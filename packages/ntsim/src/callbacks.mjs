/**
 * callbacks.mjs — invocation side of object/registry callback registrations.
 *
 * notify.mjs already fires Psp* notify routines; this module adds:
 *   - ObRegisterCallbacks pre/post operation callbacks with real
 *     _OB_PRE_OPERATION_INFORMATION / _OB_POST_OPERATION_INFORMATION bytes
 *     (pre callbacks may strip DesiredAccess, exactly like an EDR)
 *   - CmRegisterCallback(Ex) callbacks for registry value writes with a
 *     REG_SET_VALUE_KEY_INFORMATION blob (callback may block with a failure
 *     NTSTATUS — CrowdStrike-style registry protection).
 *
 * All invocations go through kernel.cpu.callFunction so JsInterpreter,
 * Hybrid and Unicorn backends behave identically.
 */

const M64 = 0xffffffffffffffffn;

/** OB_OPERATION values. */
export const OB_OPERATION = { CREATE_HANDLE: 0, OPEN_HANDLE: 1 };
/** REG_NOTIFY_CLASS: pre-notifications share the class number. */
export const REG_NOTIFY_CLASS = {
  DeleteKey: 0,
  SetValueKey: 1,
  DeleteValueKey: 2,
  SetInformationKey: 3,
  RenameKey: 4,
  EnumerateKey: 5,
  EnumerateValueKey: 6,
  QueryKey: 7,
  QueryValueKey: 8,
};

const hex = (v) => "0x" + BigInt(v).toString(16);

/**
 * Install callback invocation onto an NtKernel. Idempotent.
 */
export function installCallbackEngine(kernel) {
  if (kernel.fireObOperation) return kernel;
  kernel.obEvents = [];
  kernel.cmEvents = [];

  /**
   * Drive one handle open/create through every Ob pre/post registration.
   * @param {{operation?:bigint|number, object?:bigint, objectType?:bigint,
   *   desiredAccess?:number, handleAttributes?:number, kernelOperation?:boolean,
   *   returnStatus?:bigint}} spec
   */
  kernel.fireObOperation = function fireObOperation(spec = {}) {
    const mem = kernel.mem;
    const operation = BigInt(spec.operation ?? OB_OPERATION.OPEN_HANDLE);
    const object = BigInt.asUintN(64, BigInt(spec.object ?? 0n));
    const objectType = BigInt.asUintN(64, BigInt(spec.objectType ?? 0n));
    const kernelOperation = !!spec.kernelOperation;
    const desiredAccessIn = Number(BigInt.asUintN(32, BigInt(spec.desiredAccess ?? 0x1fffffn)));

    // _OB_PRE_OPERATION_INFORMATION (x64, 0x28)
    const preInfo = kernel.allocPool(0x28, "ObPr");
    const params = kernel.allocPool(0x10, "ObPa");
    mem.w32(preInfo, Number(operation));
    mem.w32(preInfo + 4n, kernelOperation ? 1 : 0); // Flags.KernelOperation
    mem.w64(preInfo + 8n, object);
    mem.w64(preInfo + 0x10n, objectType);
    mem.w64(preInfo + 0x18n, 0n);                    // CallContext
    mem.w64(preInfo + 0x20n, params);
    mem.w32(params, desiredAccessIn);
    mem.w32(params + 4n, Number(spec.handleAttributes ?? 0));

    const preCalls = [];
    for (const reg of kernel.obCallbacks ?? []) {
      for (const entry of reg.entries) {
        if (!entry.preOp) continue;
        const r = kernel.cpu.callFunction(entry.preOp, [reg.registration, preInfo]);
        preCalls.push({
          routine: hex(entry.preOp),
          status: r.status,
          ntstatus: r.status === "ok" ? hex(BigInt.asUintN(32, r.retval ?? 0n)) : null,
        });
        if (r.status !== "ok") {
          kernel.dbgLog.push(`[ob] preOp ${hex(entry.preOp)} faulted: ${r.error?.message ?? r.status}`);
        }
      }
    }
    const desiredAccessOut = mem.u32(params);

    // _OB_POST_OPERATION_INFORMATION
    const postInfo = kernel.allocPool(0x30, "ObPo");
    mem.w32(postInfo, Number(operation));
    mem.w32(postInfo + 4n, kernelOperation ? 1 : 0);
    mem.w64(postInfo + 8n, object);
    mem.w64(postInfo + 0x10n, objectType);
    mem.w64(postInfo + 0x18n, 0n);                                  // CallContext
    mem.w32(postInfo + 0x20n, Number(BigInt.asUintN(32, BigInt(spec.returnStatus ?? 0n)))); // ReturnStatus
    mem.w32(postInfo + 0x24n, 0);
    mem.w64(postInfo + 0x28n, preInfo);                             // PreInformation

    const postCalls = [];
    for (const reg of kernel.obCallbacks ?? []) {
      for (const entry of reg.entries) {
        if (!entry.postOp) continue;
        const r = kernel.cpu.callFunction(entry.postOp, [reg.registration, postInfo]);
        postCalls.push({
          routine: hex(entry.postOp),
          status: r.status,
          ntstatus: r.status === "ok" ? hex(BigInt.asUintN(32, r.retval ?? 0n)) : null,
        });
        if (r.status !== "ok") {
          kernel.dbgLog.push(`[ob] postOp ${hex(entry.postOp)} faulted: ${r.error?.message ?? r.status}`);
        }
      }
    }

    const record = {
      operation: Number(operation),
      operationName: Number(operation) === 0 ? "create" : "open",
      kernelOperation,
      desiredAccessIn: `0x${desiredAccessIn.toString(16)}`,
      desiredAccessOut: `0x${desiredAccessOut.toString(16)}`,
      accessStripped: desiredAccessOut !== desiredAccessIn,
      preCalls,
      postCalls,
    };
    kernel.obEvents.push(record);
    kernel.dbgLog.push(
      `[ob] ${record.operationName} object ${hex(object)} access ` +
      `0x${desiredAccessIn.toString(16)} -> 0x${desiredAccessOut.toString(16)}` +
      (record.accessStripped ? " (STRIPPED by preOp)" : ""),
    );
    return record;
  };

  /**
   * Fire CmRegisterCallback callbacks for a registry SetValueKey. A callback
   * returning a failure NTSTATUS blocks the write (returns blocked: true).
   */
  kernel.fireCmSetValueKey = function fireCmSetValueKey(spec = {}) {
    const mem = kernel.mem;
    const keyPath = String(spec.keyPath ?? "\\Registry\\Machine\\SOFTWARE\\KernelForge");
    const valueName = String(spec.valueName ?? "Selftest");
    const type = Number(spec.type ?? 4); // REG_DWORD
    const data = spec.data instanceof Uint8Array
      ? spec.data
      : Uint8Array.from([1, 0, 0, 0]);
    const dataVa = kernel.allocPool(Math.max(data.length, 1), "CmD ");
    mem.write(dataVa, data);
    // UNICODE_STRING for the value name
    const us = kernel.allocPool(0x10, "CmUs");
    const buf = kernel.allocPool((valueName.length + 1) * 2, "CmNb");
    mem.w16(us, valueName.length * 2);
    mem.w16(us + 2n, valueName.length * 2 + 2);
    mem.w64(us + 8n, buf);
    mem.writeUtf16(buf, valueName);
    const keyObj = kernel.allocPool(0x20, "CmKe");

    // REG_SET_VALUE_KEY_INFORMATION (x64, 0x40)
    const info = kernel.allocPool(0x40, "CmSv");
    mem.w64(info + 0x00n, keyObj);
    mem.w64(info + 0x08n, us);
    mem.w32(info + 0x10n, 0);          // TitleIndex
    mem.w32(info + 0x14n, type);       // Type
    mem.w64(info + 0x18n, dataVa);     // Data
    mem.w32(info + 0x20n, data.length);// DataSize
    mem.w32(info + 0x24n, 0);
    mem.w64(info + 0x28n, 0n);         // CallContext
    mem.w64(info + 0x30n, 0n);         // ObjectContext
    mem.w64(info + 0x38n, 0n);         // Reserved

    const calls = [];
    let blocked = false;
    let status = 0n;
    for (const cb of kernel.cmCallbacks ?? []) {
      const r = kernel.cpu.callFunction(cb.fn, [cb.ctx, BigInt(REG_NOTIFY_CLASS.SetValueKey), info]);
      const ntstatus = r.status === "ok" ? BigInt.asUintN(32, r.retval ?? 0n) : null;
      calls.push({
        routine: hex(cb.fn),
        status: r.status,
        ntstatus: ntstatus === null ? null : hex(ntstatus),
      });
      if (ntstatus === null) continue;
      status = ntstatus;
      if (ntstatus >= 0x80000000n) { blocked = true; break; }
    }
    const record = { keyPath, valueName, type, blocked, status: hex(status), calls };
    kernel.cmEvents.push(record);
    kernel.dbgLog.push(
      `[cm] RegNtPreSetValueKey ${keyPath}\\${valueName} -> ` +
      (blocked ? `BLOCKED (${hex(status)})` : "allowed"),
    );
    return record;
  };

  return kernel;
}

export { M64 };

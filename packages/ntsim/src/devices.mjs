/**
 * devices.mjs — DRIVER_OBJECT / DEVICE_OBJECT / IRP modeling for NtKernel.
 *
 * Fidelity contract: offsets below are the classic x64 WDK layouts that
 * compiled drivers bake in at build time (Irp->IoStatus, stack locations,
 * MajorFunction dispatch). Fields a driver actually dereferences are laid
 * out exactly; kernel-private fields are plausible filler.
 *
 * The model is dual-homed:
 *  - guest-visible bytes in SparseMemory (drivers read/write them directly)
 *  - a JS-side registry (kernel.devices / kernel.driverObject) for the host
 *    to drive IRPs without parsing guest memory back.
 */

import { M64 } from "./cpu.mjs";
import { containingModule } from "./objtypes.mjs";

export const IRP_MJ = {
  CREATE: 0x00,
  CREATE_NAMED_PIPE: 0x01,
  CLOSE: 0x02,
  READ: 0x03,
  WRITE: 0x04,
  QUERY_INFORMATION: 0x05,
  SET_INFORMATION: 0x06,
  QUERY_EA: 0x07,
  SET_EA: 0x08,
  FLUSH_BUFFERS: 0x09,
  QUERY_VOLUME_INFORMATION: 0x0a,
  SET_VOLUME_INFORMATION: 0x0b,
  DIRECTORY_CONTROL: 0x0c,
  FILE_SYSTEM_CONTROL: 0x0d,
  DEVICE_CONTROL: 0x0e,
  INTERNAL_DEVICE_CONTROL: 0x0f,
  SHUTDOWN: 0x10,
  LOCK_CONTROL: 0x11,
  CLEANUP: 0x12,
  CREATE_MAILSLOT: 0x13,
  QUERY_SECURITY: 0x14,
  SET_SECURITY: 0x15,
  POWER: 0x16,
  SYSTEM_CONTROL: 0x17,
  DEVICE_CHANGE: 0x18,
  QUERY_QUOTA: 0x19,
  SET_QUOTA: 0x1a,
  PNP: 0x1b,
};
export const IRP_MJ_COUNT = 28;
export const IRP_MJ_NAMES = Object.fromEntries(
  Object.entries(IRP_MJ).map(([k, v]) => [v, k]),
);

// --------------------------------------------------------------- x64 layouts

/** _DRIVER_OBJECT (fields compiled driver code may touch) */
export const DRIVER_OBJECT = {
  SIZE: 0x150,
  TYPE: 0x004, // u16 stored at +4 (Type field of OBJECT_HEADER-ish header)
  DEVICE_OBJECT: 0x04,
  FLAGS: 0x08,
  DRIVER_START: 0x10,
  DRIVER_SIZE: 0x18,
  DRIVER_NAME: 0x20, // UNICODE_STRING {len,max,pad,ptr}
  DRIVER_SECTION: 0x30,
  DRIVER_INIT: 0x38,
  DRIVER_STARTIO: 0x40,
  // 0x68 matches compiler-worker/include/wdm.h's teaching _DRIVER_OBJECT —
  // compiled student drivers write DriverUnload here (real x64 is 0x48).
  DRIVER_UNLOAD: 0x68,
  MAJOR_FUNCTION: 0x70, // 28 x u64 slots -> ends 0x150
};

/** _DEVICE_OBJECT (subset) */
export const DEVICE_OBJECT = {
  MIN_SIZE: 0xd0,
  TYPE: 0x00,
  SIZE: 0x02,
  REFERENCE_COUNT: 0x04,
  DRIVER_OBJECT: 0x08,
  NEXT_DEVICE: 0x10,
  ATTACHED_DEVICE: 0x18,
  CURRENT_IRP: 0x20,
  TIMER: 0x28,
  FLAGS: 0x30,
  CHARACTERISTICS: 0x34,
  VPB: 0x38,
  DEVICE_EXTENSION: 0x40,
  DEVICE_TYPE: 0x44,
  STACK_SIZE: 0x48,
  QUEUE: 0x50,
  ALIGNMENT_REQUIREMENT: 0x60,
};

/** _IRP (x64). SizeOf=0xd0; IO_STACK_LOCATIONs follow the header. */
export const IRP = {
  HEADER_SIZE: 0xd0,
  STACK_SIZE: 0x48,
  TYPE: 0x00,
  MDL_ADDRESS: 0x08,
  FLAGS: 0x10,
  SYSTEM_BUFFER: 0x18, // AssociatedIrp.SystemBuffer
  IO_STATUS_STATUS: 0x30,
  IO_STATUS_INFORMATION: 0x38,
  REQUESTOR_MODE: 0x40,
  PENDING_RETURNED: 0x41,
  STACK_COUNT: 0x42,
  CURRENT_LOCATION: 0x43,
  CANCEL: 0x44,
  USER_BUFFER: 0x70, // Tail.Overlay.UserBuffer slot used by METHOD_* direct/neo
  CURRENT_STACK_LOCATION: 0xb8, // self-pointer into trailing array
};

/** _IO_STACK_LOCATION (x64) */
export const IO_STACK_LOCATION = {
  MAJOR_FUNCTION: 0x00,
  MINOR_FUNCTION: 0x01,
  FLAGS: 0x02,
  CONTROL: 0x03,
  PARAMETERS: 0x08,
  // Parameters.DeviceIoControl within union:
  OUTPUT_BUFFER_LENGTH: 0x08,
  INPUT_BUFFER_LENGTH: 0x10,
  IO_CONTROL_CODE: 0x18,
  DEVICE_OBJECT: 0x28,
  FILE_OBJECT: 0x30,
  COMPLETION_ROUTINE: 0x38,
  CONTEXT: 0x40,
};

// ------------------------------------------------------------------ builder

/**
 * Create a DRIVER_OBJECT in emulated memory and track it host-side.
 * All 28 MajorFunction slots default to `defaultDispatchThunk` (a kernel API
 * thunk whose impl completes any IRP with STATUS_SUCCESS) so unhandled MJ
 * codes behave like a lazy real driver instead of crashing.
 *
 * Pool-backed by default: allocations go through `kernel.allocPool` (full
 * mock heap) so VAs are not suspiciously round (e.g. `0xfffff80200000000`).
 * Pass `opts.va` for a fixed placement (tests / carve-overlay worlds) or
 * `opts.usePool=false` to force the legacy base. ASLR jitter is controlled
 * by `kernel.heapConfig.aslr` (`new NtKernel({heap:{aslr:true}})`).
 *
 * @returns {{va: bigint, name: string}}
 */
export function createDriverObject(kernel, name, opts = {}) {
  const mem = kernel.mem;
  let va;
  if (opts.va !== undefined && opts.va !== null) {
    va = BigInt(opts.va);
  } else if (opts.usePool === false) {
    va = kernel.bases.driver ?? 0xfffff80200000000n;
  } else {
    // Pool-allocated DRIVER_OBJECT: non-round, heap-tracked, debuggable
    va = kernel.allocPool(DRIVER_OBJECT.SIZE, "DrvO");
    // allocPool already created backing + guard; just ensure struct zeroed
    // (it is, but keep idempotent clear for fixed-pool reuse edge cases)
    mem.write(va, new Uint8Array(DRIVER_OBJECT.SIZE));
  }
  const existing = kernel.driverObjects?.get(va);
  if (existing) {
    // If we prematurely allocated a pool slot before discovering the existing
    // fixed-VA mapping, leak is harmless but note it for diagnostics.
    if (opts.va === undefined && opts.usePool !== false) {
      // pool slot was wasted; return existing mapping instead
      // (no freePool — pool leak mirrors real kernel's object retention)
    }
    return existing;
  }

  // Fresh DRIVER_OBJECT: ensure zeroed backing for the struct itself.
  // Pool-allocated path already wrote zeros; fixed-VA path needs explicit
  // materialization (may be virgin page).
  if (opts.va !== undefined || opts.usePool === false) {
    if (!mem.hasPage(va & ~0xfffn)) mem.write(va & ~0xfffn, new Uint8Array(0x1000));
    mem.write(va, new Uint8Array(DRIVER_OBJECT.SIZE));
  }
  mem.w32(va + BigInt(DRIVER_OBJECT.TYPE), 0x00040004); // Type=DRIVER_OBJECT(4),Size
  const defaultMj = opts.defaultMajorThunk
    ?? kernel.defineApi("IopInvalidDeviceRequest", function () {
      return 0xc000000bn; // STATUS_INVALID_DEVICE_REQUEST
    });
  for (let i = 0; i < IRP_MJ_COUNT; i++) {
    mem.w64(va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + i * 8), defaultMj);
  }
  const rec = {
    va,
    name,
    deviceList: [],
    unloadRoutine: 0n,
    startIo: 0n,
    defaultMajorThunk: defaultMj,
    /** {base:bigint, bytes:Uint8Array} set by the analyzer for SEH dispatch */
    image: null,
  };
  kernel.driverObjects = kernel.driverObjects ?? new Map();
  kernel.driverObjects.set(va, rec);
  return rec;
}

/** Write DriverName UNICODE_STRING + image linkage after mapPe. */
export function initDriverObjectName(kernel, drvRec, name, imageBase, imageSize) {
  const mem = kernel.mem;
  // Prefer a dedicated pool allocation for the name buffer so we never
  // clobber the guard bytes of a pool-allocated DRIVER_OBJECT (which is
  // sized exactly DRIVER_OBJECT.SIZE). Fixed-VA drivers historically used
  // va+0x200 scratch; we keep that fast-path for non-pool objects but
  // allocate fresh for heap-backed ones to stay guard-clean.
  const isPoolDrv = kernel.poolAllocs?.some((a) => a.addr === drvRec.va && a.tag === "DrvO");
  let bufVa;
  if (isPoolDrv) {
    bufVa = kernel.allocPool((name.length + 1) * 2, "DrvN");
  } else {
    bufVa = drvRec.va + 0x200n; // legacy scratch behind fixed struct
    if (!mem.hasPage(bufVa & ~0xfffn)) mem.write(bufVa & ~0xfffn, new Uint8Array(0x1000));
  }
  const nameOff = drvRec.va + BigInt(DRIVER_OBJECT.DRIVER_NAME);
  mem.writeUtf16(bufVa, name);
  mem.w16(nameOff, name.length * 2);
  mem.w16(nameOff + 2n, (name.length + 1) * 2);
  mem.w64(nameOff + 8n, bufVa);
  mem.w64(drvRec.va + BigInt(DRIVER_OBJECT.DRIVER_START), BigInt(imageBase));
  mem.w64(drvRec.va + BigInt(DRIVER_OBJECT.DRIVER_SIZE), BigInt(imageSize));
}

/**
 * Create a DEVICE_OBJECT linked onto the driver's device list.
 * @returns {{va:bigint, extension:bigint, type:number}}
 */
export function createDeviceObject(kernel, drvRec, opts = {}) {
  const mem = kernel.mem;
  const extSize = Number(opts.extensionSize ?? 0);
  const va = kernel.allocPool(DEVICE_OBJECT.MIN_SIZE + extSize, "DevO");
  mem.write(va, new Uint8Array(DEVICE_OBJECT.MIN_SIZE + extSize));
  mem.w16(va + BigInt(DEVICE_OBJECT.TYPE), Number(opts.type ?? 0x0000002b)); // FILE_DEVICE_UNKNOWN
  mem.w16(va + BigInt(DEVICE_OBJECT.SIZE), DEVICE_OBJECT.MIN_SIZE);
  mem.w32(va + BigInt(DEVICE_OBJECT.REFERENCE_COUNT), 1);
  mem.w64(va + BigInt(DEVICE_OBJECT.DRIVER_OBJECT), drvRec.va);
  mem.w64(va + BigInt(DEVICE_OBJECT.DEVICE_EXTENSION), va + BigInt(DEVICE_OBJECT.MIN_SIZE));

  // chain onto driver object list
  const first = mem.u64(drvRec.va + BigInt(DRIVER_OBJECT.DEVICE_OBJECT));
  mem.w64(va + BigInt(DEVICE_OBJECT.NEXT_DEVICE), first);
  mem.w64(drvRec.va + BigInt(DRIVER_OBJECT.DEVICE_OBJECT), va);

  const rec = {
    va,
    extension: va + BigInt(DEVICE_OBJECT.MIN_SIZE),
    driver: drvRec,
    type: Number(opts.type ?? 0x2b),
    flags: Number(opts.deviceFlags ?? 0),
  };
  drvRec.deviceList.push(rec);
  kernel.devices = kernel.devices ?? [];
  kernel.devices.push(rec);
  return rec;
}

/**
 * Build an IRP for `device` with an IO_STACK_LOCATION configured for either
 * DeviceIoControl or plain read/write, then dispatch it to the driver's
 * MajorFunction handler through the CPU backend.
 *
 * @param {object} kernel NtKernel
 * @param {object} device record from createDeviceObject()
 * @param {object} spec
 *   {major:number, ioctl?:number|bigint, input?:Uint8Array, inputHex?:string,
 *    outputLen?:number, minor?:number}
 * @returns {Promise<object>|object} result:
 *   {status:"ok", ntstatus:bigint, information:bigint, output:Uint8Array,
 *    pending:boolean, steps}|{status:"fault"|"timeout"|..., error?}
 */
export async function sendIrp(kernel, device, spec) {
  const mem = kernel.mem;
  const major = spec.major ?? IRP_MJ.DEVICE_CONTROL;
  const drvObjVa = device.driver.va;

  // ---- buffers ----------------------------------------------------------
  let inputBuf = null;
  if (spec.input instanceof Uint8Array) inputBuf = spec.input;
  else if (spec.inputHex) {
    const hx = spec.inputHex.replace(/[^0-9a-fA-F]/g, "");
    inputBuf = new Uint8Array(hx.match(/.{2}/g)?.map((x) => parseInt(x, 16)) ?? []);
  }
  const outputLen = Number(spec.outputLen ?? 0);

  const systemBuffer = (inputBuf || outputLen)
    ? kernel.allocPool(Math.max(inputBuf?.length ?? 0, outputLen) || 1, "IrpB")
    : 0n;
  if (inputBuf && inputBuf.length) mem.write(systemBuffer, inputBuf);
  const outSnapshotBefore = outputLen ? mem.read(systemBuffer, outputLen).slice() : null;

  // ---- IRP header + stack location ---------------------------------------
  const irp = kernel.allocPool(IRP.HEADER_SIZE + IRP.STACK_SIZE, "Irp!");
  mem.write(irp, new Uint8Array(IRP.HEADER_SIZE + IRP.STACK_SIZE));
  mem.w16(irp + BigInt(IRP.TYPE), 0x0006); // IRP_TYPE
  mem.w8(irp + BigInt(IRP.STACK_COUNT), 1);
  mem.w8(irp + BigInt(IRP.CURRENT_LOCATION), 1);
  if (systemBuffer) mem.w64(irp + BigInt(IRP.SYSTEM_BUFFER), systemBuffer & M64);

  const stack = irp + BigInt(IRP.HEADER_SIZE);
  mem.w64(irp + BigInt(IRP.CURRENT_STACK_LOCATION), stack & M64);
  mem.w8(stack + BigInt(IO_STACK_LOCATION.MAJOR_FUNCTION), major & 0xff);
  mem.w8(stack + BigInt(IO_STACK_LOCATION.MINOR_FUNCTION), Number(spec.minor ?? 0));
  mem.w8(stack + BigInt(IO_STACK_LOCATION.CONTROL), 0xe0); // SL_ flags typical completion bits
  mem.w64(stack + BigInt(IO_STACK_LOCATION.DEVICE_OBJECT), device.va & M64);
  if (major === IRP_MJ.DEVICE_CONTROL || major === IRP_MJ.INTERNAL_DEVICE_CONTROL) {
    mem.w32(stack + BigInt(IO_STACK_LOCATION.OUTPUT_BUFFER_LENGTH), outputLen);
    mem.w32(stack + BigInt(IO_STACK_LOCATION.INPUT_BUFFER_LENGTH), inputBuf?.length ?? 0);
    mem.w32(stack + BigInt(IO_STACK_LOCATION.IO_CONTROL_CODE), Number(BigInt(spec.ioctl ?? 0)));
  } else {
    // Parameters.Read/Write: Length@+8, Key@+0x10, ByteOffset@+0x18
    mem.w32(stack + BigInt(IO_STACK_LOCATION.PARAMETERS), Number(spec.length ?? 0));
  }

  // ---- dispatch -----------------------------------------------------------
  const mjTable = drvObjVa + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION);
  const handler = mem.u64(mjTable + BigInt(major * 8));
  device.driver.lastIrp = irp;
  mem.w64(device.va + BigInt(DEVICE_OBJECT.CURRENT_IRP), irp & M64);

  const beforeSteps = kernel.cpu.steps ?? 0;
  const r = kernel.callFunctionSeh && device.driver.image
    ? kernel.callFunctionSeh(handler, [device.va, irp], device.driver.image)
    : kernel.cpu.callFunction(handler, [device.va, irp]);
  const steps = (kernel.cpu.steps ?? 0) - beforeSteps;

  mem.w64(device.va + BigInt(DEVICE_OBJECT.CURRENT_IRP), 0n);

  if (r.status !== "ok") return { ...r, major };

  const status = mem.u32(irp + BigInt(IRP.IO_STATUS_STATUS));
  const information = mem.u64(irp + BigInt(IRP.IO_STATUS_INFORMATION));
  const pending = (mem.u8(stack + BigInt(IO_STACK_LOCATION.CONTROL)) & 0x1) !== 0;
  const output = outSnapshotBefore
    ? mem.read(systemBuffer, outputLen)
    : new Uint8Array(0);

  return {
    status: "ok",
    ntstatus: BigInt(status),
    information,
    output,
    outputHex: [...output].map((b) => b.toString(16).padStart(2, "0")).join(""),
    pending,
    steps,
    major,
    majorName: IRP_MJ_NAMES[major] ?? `0x${major.toString(16)}`,
  };
}

/** Convenience: METHOD_BUFFERED DeviceIoControl. */
export async function sendIoctl(kernel, device, code, input, outputLen = 0) {
  return sendIrp(kernel, device, {
    major: IRP_MJ.DEVICE_CONTROL,
    ioctl: code,
    input,
    outputLen,
  });
}

// --------------------------------------------------- m24: dispatch scanning

/**
 * Snapshot a DRIVER_OBJECT's 28 MajorFunction slots as the load-time
 * baseline for later tamper diffs (the EDR "attest at load" pattern).
 * Call AFTER the driver finished its legitimate DriverEntry wiring.
 */
export function snapshotMajorBaseline(kernel, drvRec, mem = kernel.mem) {
  const bytes = mem.read(drvRec.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION),
    IRP_MJ_COUNT * 8);
  drvRec.majorBaseline = bytes.slice();
  return drvRec.majorBaseline;
}

/**
 * Install kernel.scanForeignDispatch(). Idempotent.
 *
 * A MajorFunction slot is FOREIGN when it is neither the default
 * IopInvalidDeviceRequest thunk nor inside its own driver's image range
 * ([DriverStart, DriverStart+DriverSize)). That is the classic IRP-hook
 * signature: the slot was redirected into some other module's code.
 *
 * @returns {Array<{drvRec:{name:string}, code:number, codeName:string,
 *                  handler:bigint, owner:string|null}>}
 */
export function installDispatchScan(kernel) {
  if (kernel.scanForeignDispatch) return kernel;
  kernel.scanForeignDispatch = function scanForeignDispatch() {
    const mem = kernel.mem;
    const out = [];
    for (const rec of kernel.driverObjects?.values() ?? []) {
      const start = BigInt(mem.u64(rec.va + BigInt(DRIVER_OBJECT.DRIVER_START)));
      const size = BigInt(mem.u64(rec.va + BigInt(DRIVER_OBJECT.DRIVER_SIZE)));
      const inImage = (fn) => size > 0n && fn >= start && fn < start + size;
      for (let i = 0; i < IRP_MJ_COUNT; i++) {
        const handler = mem.u64(
          rec.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + i * 8));
        if (handler === rec.defaultMajorThunk) continue;
        if (inImage(handler)) continue;
        out.push({
          drvRec: rec,
          code: i,
          codeName: IRP_MJ_NAMES[i] ?? `0x${i.toString(16)}`,
          handler,
          owner: containingModule(kernel, handler),
        });
      }
    }
    return out;
  };
  return kernel;
}

/** Invoke DriverUnload if present. */
export async function callDriverUnload(kernel, drvRec) {
  const mem = kernel.mem;
  const unload = mem.u64(drvRec.va + BigInt(DRIVER_OBJECT.DRIVER_UNLOAD));
  if (!unload || unload === kernel.apiThunks.get("IopInvalidDeviceRequest")) {
    return { status: "no-unload" };
  }
  const r = kernel.callFunctionSeh && drvRec.image
    ? kernel.callFunctionSeh(unload, [drvRec.va], drvRec.image)
    : kernel.cpu.callFunction(unload, [drvRec.va]);
  return { ...r, unload };
}

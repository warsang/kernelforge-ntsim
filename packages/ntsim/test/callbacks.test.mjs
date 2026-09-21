/**
 * callbacks.mjs — Ob pre/post operation invocation (with access stripping)
 * and Cm registry callback invocation (with write blocking).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import { OB_OPERATION, REG_NOTIFY_CLASS } from "../src/callbacks.mjs";

const PRE_STRIP = 0x3000n;
const POST_OK = 0x3100n;
const CM_DENY = 0x3200n;
const CM_ALLOW = 0x3300n;

function installStubs(kernel) {
  const mem = kernel.mem;
  // preOp: Parameters->DesiredAccess = 0x1000; return 0
  mem.write(PRE_STRIP, Uint8Array.from([
    0x48, 0x8b, 0x42, 0x20,            // mov rax, [rdx+0x20]
    0xc7, 0x00, 0x00, 0x10, 0x00, 0x00,// mov dword [rax], 0x1000
    0x31, 0xc0,                        // xor eax,eax
    0xc3,
  ]));
  // postOp: return 0
  mem.write(POST_OK, Uint8Array.from([0x31, 0xc0, 0xc3]));
  // Cm callback: return STATUS_ACCESS_DENIED / STATUS_SUCCESS
  mem.write(CM_DENY, Uint8Array.from([0xb8, 0x22, 0x00, 0x00, 0xc0, 0xc3]));
  mem.write(CM_ALLOW, Uint8Array.from([0x31, 0xc0, 0xc3]));
}

function registerOb(kernel) {
  const mem = kernel.mem;
  const cbReg = kernel.allocPool(0x40, "ObRg");
  const opsBase = kernel.allocPool(0x40, "ObOp");
  mem.w16(cbReg + 2n, 1);                    // OperationRegistrationCount
  mem.w64(cbReg + 0x20n, opsBase);           // OperationRegistration
  mem.w64(opsBase, 0n);                      // ObjectType
  mem.w32(opsBase + 8n, 3);                  // Operations (create|duplicate)
  mem.w64(opsBase + 0x10n, PRE_STRIP);       // PreOperation
  mem.w64(opsBase + 0x18n, POST_OK);         // PostOperation
  const status = kernel.apiImpls.get("ObRegisterCallbacks")(cbReg);
  assert.equal(status, 0n);
  return cbReg;
}

test("Ob pre-op runs and strips DesiredAccess; post-op sees ReturnStatus", () => {
  const kernel = new NtKernel({ arch: false });
  installStubs(kernel);
  registerOb(kernel);

  const record = kernel.fireObOperation({
    operation: OB_OPERATION.OPEN_HANDLE,
    object: 0xffffb80000000100n,
    objectType: 0xfffff80000002000n,
    desiredAccess: 0x1fffff,
    kernelOperation: false,
    returnStatus: 0n,
  });
  assert.equal(record.operation, 1);
  assert.equal(record.desiredAccessIn, "0x1fffff");
  assert.equal(record.desiredAccessOut, "0x1000");
  assert.equal(record.accessStripped, true);
  assert.equal(record.preCalls.length, 1);
  assert.equal(record.preCalls[0].status, "ok");
  assert.equal(record.postCalls.length, 1);
  assert.equal(kernel.obEvents.length, 1);
  assert.ok(kernel.dbgLog.some((l) => l.includes("STRIPPED")));
});

test("Ob pre-op receives a plausible OB_PRE_OPERATION_INFORMATION", () => {
  const kernel = new NtKernel({ arch: false });
  installStubs(kernel);
  registerOb(kernel);
  // A probe callback that verifies the struct: return 0xC0000001 when the
  // Operation field is not OPEN_HANDLE(1) or Object != 0x1234.
  const mem = kernel.mem;
  const prog = kernel.allocPool(0x40, "Prog");
  mem.write(prog, Uint8Array.from([
    0x83, 0x3a, 0x01,               // cmp dword [rdx], 1
    0x75, 0x0a,                     // jne fail
    0x48, 0x81, 0x7a, 0x08, 0x34, 0x12, 0x00, 0x00, // cmp qword [rdx+8], 0x1234
    0x75, 0x02,                     // jne fail
    0x31, 0xc0,                     // xor eax,eax
    0xc3,
    0xb8, 0x01, 0x00, 0x00, 0xc0, 0xc3,             // fail: mov eax,0xC0000001; ret
  ]));
  // Re-register with our probe on a second kernel? Simpler: re-register
  // overwriting the ops entry via a fresh registration record.
  const cbReg = kernel.allocPool(0x40, "ObR2");
  const ops = kernel.allocPool(0x40, "ObO2");
  mem.w16(cbReg + 2n, 1);
  mem.w64(cbReg + 0x20n, ops);
  mem.w64(ops + 0x10n, prog);
  kernel.apiImpls.get("ObRegisterCallbacks")(cbReg);

  const record = kernel.fireObOperation({ operation: 1, object: 0x1234n });
  assert.equal(record.preCalls.length, 2);
  assert.equal(record.preCalls[1].status, "ok");
  assert.equal(record.preCalls[1].ntstatus, "0x0");
});

test("Cm callback can block a registry write with a failure NTSTATUS", () => {
  const kernel = new NtKernel({ arch: false });
  installStubs(kernel);
  const cookieOut = kernel.allocPool(8, "CkOu");
  const st = kernel.apiImpls.get("CmRegisterCallback")(CM_DENY, 0xbeefn, cookieOut);
  assert.equal(st, 0n);
  assert.equal(kernel.cmCallbacks.length, 1);

  const record = kernel.fireCmSetValueKey({
    keyPath: "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\evil",
    valueName: "Start",
    type: 4,
    data: Uint8Array.from([1, 0, 0, 0]),
  });
  assert.equal(record.blocked, true);
  assert.equal(record.calls[0].ntstatus, "0xc0000022");
  assert.equal(record.calls[0].routine, "0x3200");
  assert.equal(kernel.cmEvents.length, 1);
  assert.ok(kernel.dbgLog.some((l) => l.includes("BLOCKED")));
});

test("Cm callback returning success allows the write", () => {
  const kernel = new NtKernel({ arch: false });
  installStubs(kernel);
  const cookieOut = kernel.allocPool(8, "CkOu");
  kernel.apiImpls.get("CmRegisterCallback")(CM_ALLOW, 0n, cookieOut);
  const record = kernel.fireCmSetValueKey({ valueName: "Allow" });
  assert.equal(record.blocked, false);
  assert.equal(record.calls[0].ntstatus, "0x0");
});

test("REG_NOTIFY_CLASS.SetValueKey matches the WDK enum value", () => {
  assert.equal(REG_NOTIFY_CLASS.SetValueKey, 1);
});

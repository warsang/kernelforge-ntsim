/**
 * INT imm8 (opcode 0xCD) handling.
 *
 * Historical bug: dispatch() had no 0xCD case, so any driver reaching an
 * `int 29h` (__fastfail / GS failure) or `int 2d` died with a raw
 * "unimplemented opcode" CpuError that classified as a generic #UD —
 * exactly what TBMKD.sys surfaced after its imports mis-resolved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "../src/memory.mjs";
import { JsInterpreter } from "../src/cpu.mjs";
import { classifyFault } from "../src/seh.mjs";

function newCpu() {
  const mem = new SparseMemory();
  return { mem, cpu: new JsInterpreter(mem) };
}

test("int 29h (__fastfail) raises a classified fastfail fault", () => {
  const { mem, cpu } = newCpu();
  mem.write(0x1000n, new Uint8Array([0xcd, 0x29]));
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(String(r.error?.message ?? r.error), /fastfail/i);
  assert.match(String(r.error?.message ?? r.error), /int 0x29/i);

  const c = classifyFault(r.error);
  assert.equal(c.kind, "#FASTFAIL");
  assert.equal(c.code, 0xc0000409n); // STATUS_STACK_BUFFER_OVERRUN
  assert.equal(c.name, "STATUS_STACK_BUFFER_OVERRUN");
});

test("int3 via CD 03 acts as a resumable breakpoint", () => {
  const { mem, cpu } = newCpu();
  // cd 03 ; inc eax ; ret
  mem.write(0x1000n, new Uint8Array([0xcd, 0x03, 0xff, 0xc0, 0xc3]));
  cpu.rip = 0x1000n;
  const reason = cpu.run();
  assert.equal(reason, "breakpoint");
  assert.equal(cpu.rip, 0x1002n); // parked after the two-byte instruction
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok"); // debugger-style continue runs to completion
});

test("int 2d (DbgBreakPointWithStatus) also breaks, not faults", () => {
  const { mem, cpu } = newCpu();
  mem.write(0x1000n, new Uint8Array([0xcd, 0x2d, 0x31, 0xc0, 0xc3]));
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
});

test("unmodeled software interrupts fault with a precise message", () => {
  const { mem, cpu } = newCpu();
  mem.write(0x1000n, new Uint8Array([0xcd, 0x20]));
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(String(r.error?.message ?? r.error), /software interrupt 0x20/i);
  assert.equal(classifyFault(r.error).kind, "#UD");
});

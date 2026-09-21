/**
 * bugcheck.mjs — code names, parameter analysis, nested (double/triple)
 * fault detection and the post-mortem renderer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import {
  bugcheckName, analyzeBugcheck, noteBugcheck, renderBugcheck, summarizeBugcheck,
  resolveAddress,
} from "../src/bugcheck.mjs";
import { BUGCHECK_TABLE } from "../src/bugcheck-table.mjs";

test("bugcheck table covers the classic codes", () => {
  assert.ok(BUGCHECK_TABLE.length > 300);
  assert.equal(bugcheckName(0x0an), "IRQL_NOT_LESS_OR_EQUAL");
  assert.equal(bugcheckName(0x50n), "PAGE_FAULT_IN_NONPAGED_AREA");
  assert.equal(bugcheckName(0xd1n), "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
  assert.equal(bugcheckName(0x139n), "KERNEL_SECURITY_CHECK_FAILURE");
  assert.equal(bugcheckName(0x7fn), "UNEXPECTED_KERNEL_MODE_TRAP");
});

test("analyzeBugcheck decodes 0xD1/0x139/0x3B/0x7F parameters", () => {
  const d1 = analyzeBugcheck(0xd1n, [0xdeadbeefn, 2n, 1n, 0xfffff80300001000n]);
  assert.equal(d1.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
  assert.ok(d1.fields.some((f) => f.label === "IRQL" && f.value.includes("DISPATCH_LEVEL")));
  assert.ok(d1.fields.some((f) => f.label === "Access Type" && f.value === "WRITE"));

  const gs = analyzeBugcheck(0x139n, [2n, 0n, 0n, 0n]);
  assert.ok(gs.fields[0].value.includes("Stack cookie mismatch"));
  assert.ok(gs.summary.includes("security check"));

  const ss = analyzeBugcheck(0x3bn, [0xc0000005n, 0xfffff80300002000n, 0n, 0n]);
  assert.ok(ss.fields[0].value.includes("STATUS_ACCESS_VIOLATION"));

  const trap = analyzeBugcheck(0x7fn, [0x8n, 0n, 0n, 0n]);
  assert.ok(trap.fields[0].value.includes("Double Fault"));

  const pg = analyzeBugcheck(0x109n, [4n, 0x1bn, 0n, 0n]);
  assert.ok(pg.fields[0].value.includes("MSR"));

  const unknown = analyzeBugcheck(0x12345678n, []);
  assert.match(unknown.name, /UNKNOWN_BUGCHECK/);
});

test("noteBugcheck detects double and triple faults, preserving the primary", () => {
  const kernel = new NtKernel({ arch: false });
  noteBugcheck(kernel, 0xd1n, [1n, 2n, 0n, 3n]);
  assert.equal(kernel.bugcheck.code, 0xd1n);
  assert.equal(kernel.bugcheck.level, 1);
  assert.equal(kernel.cpu.halted, true);

  noteBugcheck(kernel, 0x7fn, [8n, 0n, 0n, 0n]);
  assert.equal(kernel.bugcheck.level, 2);
  assert.equal(kernel.bugcheck.nested, true);
  assert.equal(kernel.doubleFault.code, 0x7fn);

  noteBugcheck(kernel, 0x50n, [0n, 0n, 0n, 0n]);
  assert.equal(kernel.bugcheck.level, 3);
  assert.equal(kernel.tripleFault.code, 0x50n);
  assert.equal(kernel.bugcheck.nestedCodes.length, 2);
});

test("summarizeBugcheck is JSON-safe and names fields", () => {
  const s = summarizeBugcheck({ code: 0xd1n, params: [0x1000n, 2n, 0n, 0x2000n], level: 1 });
  assert.equal(s.code, "0x000000D1");
  assert.equal(s.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
  assert.equal(s.level, 1);
  JSON.stringify(s); // must not throw
});

test("renderBugcheck emits STOP line, register dump and resolves addresses", () => {
  const kernel = new NtKernel({ arch: false });
  kernel.loadedDrivers.push({ name: "ntoskrnl.exe", base: 0xfffff8052b800000n, imageSize: 0x800000 });
  noteBugcheck(kernel, 0xd1n, [0xdeadbeefn, 2n, 1n, 0xfffff8052b801234n]);
  kernel.cpu.regs.rsp = 0xfffff90000001000n;
  kernel.mem.write(0xfffff90000001000n, new Uint8Array(0x40));
  kernel.mem.w64(0xfffff90000001008n, 0xfffff8052b805678n);

  const text = renderBugcheck(kernel);
  assert.match(text, /\*\*\* STOP: 0x000000D1/);
  assert.match(text, /DRIVER_IRQL_NOT_LESS_OR_EQUAL/);
  assert.match(text, /RIP=/);
  assert.match(text, /ntoskrnl\.exe\+0x1234/);
  assert.match(text, /Stack \(RSP/);
});

test("resolveAddress maps module ranges", () => {
  const modules = [{ name: "evil.sys", base: 0xfffff80300000000n, size: 0x10000 }];
  assert.equal(resolveAddress(0xfffff80300000100n, modules), "evil.sys+0x100");
  assert.equal(resolveAddress(0xdeadbeefn, modules), null);
});

test("KeBugCheckEx uses the recording path with names", () => {
  const kernel = new NtKernel({ arch: false });
  kernel.apiImpls.get("KeBugCheckEx")(0xd1n, 0x1000n, 2n, 1n, 0x2000n);
  assert.equal(kernel.bugcheck.code, 0xd1n);
  assert.equal(kernel.bugcheck.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
  assert.equal(kernel.cpu.halted, true);
});

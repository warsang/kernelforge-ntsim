/**
 * diag.mjs — probe classifier, SEH/API telemetry, self-read watchpoints.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import { SparseMemory } from "../src/memory.mjs";
import { installDiag, HVSP_BASE, KUSD_KERNEL, HYPERSPACE_BASE } from "../src/diag.mjs";

function driverKernel() {
  const k = new NtKernel({ diag: {}, arch: false });
  k.loadedDrivers.push(
    { name: "ntoskrnl.exe", base: 0xfffff8052b800000n, imageSize: 0x800000 },
    { name: "HAL.dll", base: 0xfffff8052b000000n, imageSize: 0x40000 },
  );
  k.diag.watchDriver(0xfffff80300000000n, 0x10000);
  return k;
}

test("classify() labels driver probes by target surface", () => {
  const k = driverKernel();
  k.cpu.rip = 0xfffff80300000100n; // inside the watched driver image

  k.diag.classify(KUSD_KERNEL, 4, "read");          // KUSER_SHARED_DATA
  k.diag.classify(HVSP_BASE, 4, "read");            // hypervisor page
  k.diag.classify(HYPERSPACE_BASE + 0x1234n, 8, "read");
  k.diag.classify(0xfffff8052b801234n, 4, "read");  // ntoskrnl (loadedDrivers)
  k.diag.classify(0xfffff80000000100n, 4, "read");  // kernel struct region
  k.diag.classify(0xfffff90000005000n, 4, "read");  // pool
  k.diag.classify(0xdeadbeef0000003cn, 4, "read");  // e_lfanew scan
  k.diag.classify(0xdeadbeef00000000n, 1, "read");  // MZ/page scan
  k.diag.classify(0xdeadbeef00001abcn, 4, "read");  // generic unmapped

  const s = k.diag.summary();
  assert.equal(s.probes.kusd, 1);
  assert.equal(s.probes.hvsp, 1);
  assert.equal(s.probes.hyperspace, 1);
  assert.equal(s.probes.systemModule, 1);
  assert.equal(s.probes.kernelStruct, 1);
  assert.equal(s.probes.pool, 1);
  assert.equal(s.probes.peHeaderScan, 1);
  assert.equal(s.probes.pageScan, 1);
  assert.equal(s.probes.other, 1);
  assert.equal(s.unmapped.reads, 9);
  assert.ok(s.flags.peHeaderScan);
  assert.ok(s.probes.samples.kusd[0].addr.startsWith("0xfffff780"));
});

test("probes from outside the driver image are counted but not classified", () => {
  const k = driverKernel();
  k.cpu.rip = 0xfffff80100000040n; // kernel thunk arena
  k.diag.classify(KUSD_KERNEL, 4, "read");
  const s = k.diag.summary();
  assert.equal(s.unmapped.reads, 1);
  assert.equal(s.probes.kusd, 0);
});

test("SEH and ACCESS_DENIED telemetry feed the flags", () => {
  const k = driverKernel();
  k.diag.onSeh("handled by scope", true);
  k.diag.onSeh("no scope", false);
  for (let i = 0; i < 5; i++) k.diag.onApi("ZwOpenProcess", 0xc0000022n);
  const s = k.diag.summary();
  assert.equal(s.seh.dispatched, 2);
  assert.equal(s.seh.accepted, 1);
  assert.equal(s.seh.rejected, 1);
  assert.ok(s.api.stuckAccessDenied);
  assert.equal(s.flags.stuckAccessDenied, true);
  k.diag.onApi("ZwClose", 0n);
  assert.equal(k.diag.summary().api.accessDeniedStreak, 5); // reset keeps max
});

test("SparseMemory unmapped/watch hooks drive classify()", () => {
  const k = driverKernel();
  k.cpu.rip = 0xfffff80300000200n;
  // read through SparseMemory triggers the installed hook
  k.mem.read(KUSD_KERNEL, 4);
  assert.equal(k.diag.summary().probes.kusd, 1);
  k.mem.write(0xdeadbeef00000000n, new Uint8Array([1, 2, 3, 4]));
  assert.equal(k.diag.summary().unmapped.writes, 1);
});

test("watchDriver records header/IAT self-reads", () => {
  const k = driverKernel();
  const base = 0xfffff80300000000n;
  // map the driver's header page, then read it: onWatchRead must fire
  k.mem.write(base + 0x10n, new Uint8Array([1]));
  k.mem.read(base + 0x3cn, 4);
  const s = k.diag.summary();
  assert.equal(s.selfReads.header, 1);
  assert.equal(k.diag.counts.driverHeaderReads, 1);
});

test("installDiag is idempotent and can be disabled", () => {
  const k = new NtKernel({ arch: false });
  assert.equal(k.diag, undefined);
  installDiag(k, {});
  installDiag(k, {});
  assert.ok(k.diag);
});

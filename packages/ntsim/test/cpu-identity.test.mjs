import { test } from "node:test";
import assert from "node:assert/strict";
import { virtualCpuid, installUserlandCpu } from "../src/cpu-identity.mjs";

test("virtualCpuid answers vendor, brand and feature leaves", () => {
  const zero = virtualCpuid(0, 0);
  assert.equal(zero.ebx, 0x756e6547);
  assert.equal(zero.ecx, 0x6c65746e);
  assert.equal(zero.edx, 0x49656e69);
  const one = virtualCpuid(1, 0);
  assert.ok(one.edx & (1 << 25), "SSE reported");
  assert.ok(one.ecx & (1 << 20), "SSE4.2 reported");
  const seven = virtualCpuid(7, 0);
  assert.ok(seven.ebx & (1 << 5), "AVX2 reported");
  const brand = [0x80000002, 0x80000003, 0x80000004]
    .map((l) => virtualCpuid(l, 0))
    .map((r) => [r.eax, r.ebx, r.ecx, r.edx]
      .map((w) => String.fromCharCode(w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff))
      .join(""))
    .join("")
    .replace(/\0.*$/, "");
  assert.match(brand, /KernelForge Virtual CPU/);
  assert.deepEqual(virtualCpuid(0xdead, 0), { eax: 0, ebx: 0, ecx: 0, edx: 0 });
});

test("installUserlandCpu wires the hooks without clobbering existing ones", () => {
  const cpu = { steps: 5 };
  installUserlandCpu(cpu);
  assert.equal(typeof cpu.onCpuid, "function");
  assert.equal(cpu.onRdtsc(), 500n);
  assert.equal(cpu.onRdmsr(0x10n), 0n);
  const existing = () => 42n;
  const cpu2 = { steps: 1, onRdtsc: existing };
  installUserlandCpu(cpu2);
  assert.equal(cpu2.onRdtsc, existing);
});

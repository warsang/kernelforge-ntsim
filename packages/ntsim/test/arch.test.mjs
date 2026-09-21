/**
 * arch.mjs — architectural virtualization tests: CPUID leaves, MSR file,
 * virtual TSC (incl. busy-wait termination), KUSER_SHARED_DATA dual view,
 * hypervisor shared page, port I/O and virtualized time APIs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "../src/structs.mjs";
import { JsInterpreter } from "../src/cpu.mjs";
import { SparseMemory } from "../src/memory.mjs";
import { NtKernel } from "../src/kernel.mjs";
import { HV_SHARED_PAGE, MSR } from "../src/arch.mjs";
import { CodeBuf } from "./helpers/codebuf.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

async function bootKernel(arch = {}) {
  const tables = await StructTables.loadDir(TABLES_DIR, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);
  const kernel = new NtKernel({ tables, arch });
  kernel.bootstrap();
  return kernel;
}

test("cpuid is virtualized when arch is installed", () => {
  const k = new NtKernel({ arch: {} });
  const c = new CodeBuf();
  c.bytes(0x31, 0xc0);        // xor eax,eax  (leaf 0)
  c.bytes(0x0f, 0xa2);        // cpuid
  c.bytes(0x48, 0x89, 0xd8);  // mov rax, rbx (vendor "Genu")
  c.db(0xc3);
  k.mem.write(0x1000n, c.b);
  const r = k.cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval & 0xffffffffn, 0x756e6547n);

  // leaf 1: hypervisor bit clear by default
  const c2 = new CodeBuf();
  c2.bytes(0xb8, 0x01, 0x00, 0x00, 0x00); // mov eax,1
  c2.bytes(0x0f, 0xa2);                    // cpuid
  c2.bytes(0x89, 0xc8);                    // mov eax, ecx
  c2.db(0xc3);
  k.mem.write(0x2000n, c2.b);
  const r2 = k.cpu.callFunction(0x2000n);
  assert.equal((r2.retval >> 31n) & 1n, 0n);

  const summary = k.arch.summary();
  assert.ok(summary.cpu.cpuid >= 2);
});

test("cpuid claims a hypervisor only in hypervisor mode", () => {
  const k = new NtKernel({ arch: { hypervisor: true } });
  const c = new CodeBuf();
  c.bytes(0xb8, 0x01, 0x00, 0x00, 0x00); // mov eax,1
  c.bytes(0x0f, 0xa2);                    // cpuid
  c.bytes(0x89, 0xc8);                    // mov eax, ecx
  c.db(0xc3);
  k.mem.write(0x1000n, c.b);
  const r = k.cpu.callFunction(0x1000n);
  assert.equal((r.retval >> 31n) & 1n, 1n);
  // hv leaf 0x40000001 -> Hv#1 interface id
  const cpuid = k.arch.cpuid(0x40000001n, 0n);
  assert.equal(cpuid.eax, 0x31237648n);
});

test("cpuid without arch stays an honest fault", () => {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  const c = new CodeBuf();
  c.bytes(0x0f, 0xa2);
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented 0f opcode 0xa2/);
});

test("rdmsr/wrmsr are virtualized and VMX writes are forced off", () => {
  const k = new NtKernel({ arch: {} });
  const c = new CodeBuf();
  c.bytes(0xb9, 0x3a, 0x00, 0x00, 0x00); // mov ecx, 0x3a (FEATURE_CONTROL)
  c.bytes(0x0f, 0x32);                    // rdmsr
  c.db(0xc3);
  k.mem.write(0x1000n, c.b);
  const r = k.cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 1n); // locked, VMX disabled

  // wrmsr(0x3a, 0) must re-assert the lock bit
  k.arch.wrmsr(MSR.IA32_FEATURE_CONTROL, 0n);
  assert.equal(k.arch.rdmsr(MSR.IA32_FEATURE_CONTROL), 1n);
  // VMX capability MSRs are pinned to zero
  k.arch.wrmsr(0x48bn, 0xffffn);
  assert.equal(k.arch.rdmsr(0x48bn), 0n);
  assert.ok(k.arch.summary().cpu.wrmsr >= 2);
});

test("rdmsr without arch still faults (no stream desync)", () => {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  const c = new CodeBuf();
  c.bytes(0x0f, 0x32);
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented 0f opcode 0x32/);
});

test("rdtsc hook replaces the steps*100 model and terminates busy waits", () => {
  const k = new NtKernel({ arch: {} });
  const c = new CodeBuf();
  c.bytes(0x0f, 0x31);                    // rdtsc
  c.bytes(0x48, 0x89, 0xc1);              // mov rcx, rax
  c.db(0xc3);
  k.mem.write(0x1000n, c.b);
  const r = k.cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.ok(r.retval > 0n);

  // A tight RDTSC poll: 60 reads one step apart must trigger the accelerator.
  for (let i = 0; i < 60; i++) {
    k.cpu.steps = i;
    k.arch.rdtsc();
  }
  assert.ok(k.arch.busyWaitJumps > 0, "busy-wait accelerator engaged");
  assert.ok(k.arch.summary().cpu.busyWaitJumps > 0);
});

test("KUSER_SHARED_DATA is materialized, dual-aliased and sanitized", async () => {
  const k = await bootKernel();
  const kernelAlias = 0xfffff78000000000n;
  assert.equal(k.mem.u32(kernelAlias + 0x2c4n), 10); // NtMajorVersion
  assert.equal(k.mem.u8(kernelAlias + 0x2d4n), 0);   // KdDebuggerEnabled
  assert.equal(k.mem.u8(kernelAlias + 0x2d5n), 1);   // KdDebuggerNotPresent
  // user alias sees the same values (dual view)
  assert.equal(k.mem.u32(0x7ffe0000n + 0x2c4n), 10);
  // system time is a plausible FILETIME (> 2020)
  const sysTime = k.mem.u64(kernelAlias + 0x14n);
  assert.ok(sysTime > 132_000_000_000_000_000n);
});

test("hypervisor shared page exposes QpcMultiplier", async () => {
  const k = await bootKernel();
  assert.equal(k.mem.u64(HV_SHARED_PAGE + 8n), 1n << 32n);
  assert.ok(k.arch.summary().hvSharedPage);
});

test("port I/O answers 0 (VMware backdoor) and records events", () => {
  const k = new NtKernel({ arch: {} });
  assert.equal(k.cpu.onPortRead(0x5658, 4), 0n);
  assert.equal(k.cpu.onPortRead(0x5659, 4), 0n);
  k.cpu.onPortWrite(0xe9, 0x41n, 1);
  assert.equal(k.arch.counts.portRead, 2);
  assert.equal(k.arch.counts.portWrite, 1);
});

test("virtualized time APIs are monotonic and write outputs", () => {
  const k = new NtKernel({ arch: {} });
  const qpc1 = BigInt(k.apiImpls.get("KeQueryPerformanceCounter")(0n));
  k.cpu.steps += 30; // 1 QPC tick at 3 GHz / 100 ns
  const qpc2 = BigInt(k.apiImpls.get("KeQueryPerformanceCounter")(0n));
  assert.ok(qpc2 > qpc1);
  const out = k.allocPool(8, "Time");
  k.apiImpls.get("KeQuerySystemTime")(out);
  const sysTime = k.mem.u64(out);
  assert.ok(sysTime > 132_000_000_000_000_000n);
});

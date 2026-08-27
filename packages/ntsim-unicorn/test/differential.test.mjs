/**
 * Differential harness: identical kernel scenarios run under both CPU
 * backends must produce byte-identical observable state. Any interpreter
 * coverage gap or backend divergence shows up as a concrete diff.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { createUnicornBackend } from "../src/backend.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

// Low-memory layout: unicorn cannot execute at real kernel VAs yet
// (upstream softmmu limitation, see README). Both backends run the SAME
// layout so results are directly comparable.
const BASES = {
  kva: 0x10000000n,
  pool: 0x20000000n,
  thunk: 0x30000000n,
  eproc: 0x40000000n,
};

async function booted(backend) {
  const mem = new SparseMemory();
  const cpu = backend === "unicorn" ? await createUnicornBackend(mem) : new JsInterpreter(mem);
  const k = new NtKernel({ cpu, bases: BASES });
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  // identical deterministic stack for both backends
  cpu.regs.rsp = 0x7ff00n;
  mem.write(0x70000n, new Uint8Array(0x10000));
  return k;
}

function stateSnapshot(k) {
  // Semantic kernel world only: the four synthetic VA windows. Stack scratch
  // below RSP is dead storage by definition and legitimately differs between
  // backends (different sentinel conventions).
  const wins = [
    [BASES.kva, 0x100000n],
    [BASES.pool, 0x100000n],
    [BASES.thunk, 0x10000n],
    [BASES.eproc, 0x100000n],
  ];
  const inWin = (key) => {
    const b = BigInt(parseInt(key, 16));
    return wins.some(([lo, len]) => b >= lo && b < lo + len);
  };
  const relevant = k.mem
    .dump()
    .filter(([key]) => inWin(key))
    .sort((a, b) => (BigInt(parseInt(a[0], 16)) < BigInt(parseInt(b[0], 16)) ? -1 : 1));
  return {
    dbgLog: [...k.dbgLog],
    poolAllocs: k.poolAllocs.map((p) => ({ ...p })),
    processes: k.listProcesses().map((p) => ({ pid: p.pid, name: p.name, eprocess: p.eprocess })),
    memorySha256: createHash("sha256").update(JSON.stringify(relevant)).digest("hex"),
  };
}

/** Hand-assembled DKOM unlink driver: rcx = eprocess va of target. */
function dkomDriverBytes(linksOff) {
  const off = Number(linksOff);
  const d32 = (v) => [v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255];
  return [
    0x48, 0x8b, 0x81, ...d32(off),          // mov rax, [rcx+links]      (flink)
    0x48, 0x8b, 0x91, ...d32(off + 8),      // mov rdx, [rcx+links+8]    (blink)
    0x48, 0x89, 0x50, 0x08,                 // mov [rax+8], rdx          next->blink = blink
    0x48, 0x89, 0x02,                       // mov [rdx], rax            prev->flink = flink
    0xc3,
  ];
}

test("differential: DKOM unlink driver is byte-identical across backends", async () => {
  const kernels = {};
  for (const be of ["js", "unicorn"]) {
    const k = await booted(be);
    const t = k.tables;
    const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");

    // map the driver image into the pool
    const img = k.allocPool(dkomDriverBytes(linksOff).length, "dkom");
    k.mem.write(img, Uint8Array.from(dkomDriverBytes(linksOff)));

    const target = k.processesByName.get("kftarget.exe");
    // invoke image as a plain function: rcx = eprocess va of the victim
    const r = k.cpu.callFunction(img, [BigInt(target)]);

    assert.equal(r.status, "ok", `[${be}] driver faulted: ${r.error?.message}`);

    // the emulated list walk must no longer see the target on EITHER backend
    const after = k.listProcesses();
    assert.equal(after.find((p) => p.name === "kftarget.exe"), undefined, `[${be}] not hidden`);
    assert.equal(k.findEprocessByPid(888n), null, `[${be}] pid lookup still hits`);

    kernels[be] = k;
  }

  const js = stateSnapshot(kernels.js);
  const uc = stateSnapshot(kernels.unicorn);
  assert.deepEqual(uc, js, "backend divergence in final kernel state");
});

test("differential: PsLookupProcessByProcessId thunk returns same EPROCESS", async () => {
  for (const be of ["js", "unicorn"]) {
    const k = await booted(be);
    const out = k.allocPool(8, "out");
    const status = k.apiImpls.get("PsLookupProcessByProcessId")(108n, out);
    assert.equal(status, 0n, `[${be}] lookup failed`);
    assert.equal(k.mem.u64(out), k.processesByName.get("lsass.exe"), `[${be}] wrong eprocess`);
  }
});

test("differential: DbgPrint formatting matches", async () => {
  const logs = {};
  for (const be of ["js", "unicorn"]) {
    const k = await booted(be);
    const fmt = k.allocPool(64, "fmt");
    k.mem.writeAnsi(fmt, "pid=%d name=%s\n");
    k.dbgPrint(fmt, [4242n]);
    logs[be] = k.dbgLog.join("");
  }
  assert.equal(logs.unicorn, logs.js);
  assert.match(logs.js, /pid=4242/);
});

test("differential: REAL kernel VAs (default bases) — DKOM driver", async () => {
  // No bases override: kva/pool/thunk/eproc live at true canonical
  // kernel-half addresses (0xffff…). Requires the backend's TLB-VIRTUAL
  // enablement; JsInterpreter handles these natively.
  const kernels = {};
  for (const be of ["js", "unicorn"]) {
    const mem = new SparseMemory();
    const cpu = be === "unicorn" ? await createUnicornBackend(mem) : new JsInterpreter(mem);
    const k = new NtKernel({ cpu }); // DEFAULT bases on purpose
    await k.loadTablesFromDir(tablesDir);
    k.bootstrap();
    cpu.regs.rsp = 0x7ff00n;
    mem.write(0x70000n, new Uint8Array(0x10000));

    const t = k.tables;
    const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");
    const img = k.allocPool(dkomDriverBytes(linksOff).length, "dkom");
    k.mem.write(img, Uint8Array.from(dkomDriverBytes(linksOff)));
    const target = k.processesByName.get("kftarget.exe");

    const r = k.cpu.callFunction(img, [target]);
    assert.equal(r.status, "ok", `[${be}] faulted: ${r.error?.message}`);
    assert.equal(k.listProcesses().find((p) => p.name === "kftarget.exe"), undefined, `[${be}] not hidden`);
    kernels[be] = k;
  }

  // semantic windows differ per-backend here (different BASES instances? no —
  // both used defaults), so compare directly:
  const js = stateSnapshot(kernels.js);
  const uc = stateSnapshot(kernels.unicorn);
  assert.deepEqual(uc.dbgLog, js.dbgLog);
  assert.deepEqual(uc.processes, js.processes);
});

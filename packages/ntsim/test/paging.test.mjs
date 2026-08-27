/**
 * x64 guest paging: walker, builder, permissions, demand mapping.
 * Tables live in a physically-addressed SparseMemory exactly as they would
 * in the emulated machine; every assertion reads raw PTE bytes back.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SparseMemory } from "../src/memory.mjs";
import { Mmu, TranslatedMemory, PTE, isCanonical, canonicalize } from "../src/paging.mjs";
import { JsInterpreter } from "../src/cpu.mjs";
import { NtKernel } from "../src/kernel.mjs";
import {
  PageTableSpace, splitVa, joinVa, decodePte, pteBitsString, selfMapVas,
} from "../src/paging.mjs";

function freshMmu(opts = {}) {
  const raw = new SparseMemory();
  const mmu = new Mmu(raw, { demandMap: false, ...opts });
  mmu.enablePaging(mmu.newAddressSpace());
  return { raw, mmu };
}

test("canonical VA checks", () => {
  assert.equal(isCanonical(0x00007ff000000000n), true);
  assert.equal(isCanonical(0xfffff80300000000n), true);
  assert.equal(isCanonical(0x0000800000000000n), false); // non-canonical hole
  assert.equal(canonicalize(0xffff803000000000n), 0xffff803000000000n);
});

test("walk: identity-style map translates 4KB pages", () => {
  const { raw, mmu } = freshMmu();
  const va = 0xfffff80300001000n;
  const pa = mmu.frameAlloc(1);
  raw.write(pa, new Uint8Array(4096).fill(0x5a));
  mmu.mapPage(va, pa, {});

  const t = mmu.translate(va + 0x123n, "read");
  assert.equal(t.pa, pa + 0x123n);
  assert.equal(t.level, 1);
  assert.equal(t.w, true);
  assert.equal(t.x, true);

  // data visible through translation
  assert.equal(raw.read(pa + 0x123n, 1)[0], 0x5a);
});

test("PTE bits round-trip through table memory", () => {
  const { mmu } = freshMmu();
  const va = 0xffff800012345000n;
  mmu.mapPage(va, mmu.frameAlloc(), { write: false, nx: true, user: true });
  const pte = mmu.readPte(va);
  assert.notEqual(pte, null);
  assert.equal((pte & PTE.PRESENT) !== 0n, true);
  assert.equal((pte & PTE.WRITE) === 0n, true);
  assert.equal((pte & PTE.USER) !== 0n, true);
  assert.equal((pte & PTE.NX) !== 0n, true);
  assert.equal((pte & PTE.ACCESSED) !== 0n, true); // builder sets A|D
});

test("permissions: write to read-only faults, NX fetch faults", () => {
  const { mmu } = freshMmu();
  const roVa = 0xffffc90000001000n;
  mmu.mapPage(roVa, mmu.frameAlloc(), { write: false });
  assert.throws(() => mmu.translate(roVa, "write"), /read-only/);
  assert.ok(mmu.translate(roVa, "read")); // read still fine

  const nxVa = 0xffffc90000002000n;
  mmu.mapPage(nxVa, mmu.frameAlloc(), { nx: true });
  assert.throws(() => mmu.translate(nxVa, "fetch"), /NX/);
});

test("not-present faults when demand mapping disabled", () => {
  const { mmu } = freshMmu(); // demandMap:false
  assert.throws(() => mmu.translate(0xffffd00000000000n, "read"), /not present/);
});

test("2MB large pages translate", () => {
  const { raw, mmu } = freshMmu();
  // hand-build: PML4[511]->PDPT[510]->PDE with PS
  const pml4 = mmu.cr3 & ~0xfffn;
  const pdpt = mmu.frameAlloc(); raw.write(pdpt, new Uint8Array(4096));
  const pd = mmu.frameAlloc(); raw.write(pd, new Uint8Array(4096));
  const w64at = (base, off, v) => raw.w64(base + BigInt(off), v);
  w64at(pml4, 511 * 8, pdpt | PTE.PRESENT | PTE.WRITE);
  w64at(pdpt, 510 * 8, pd | PTE.PRESENT | PTE.WRITE);
  const va = (0xffffn << 48n) | (511n << 39n) | (510n << 30n) | (7n << 21n);
  const frameBase = 0x30000000n;
  w64at(pd, 7 * 8, frameBase | PTE.PRESENT | PTE.WRITE | PTE.PS);
  const t = mmu.translate(va + 0x1fffffn, "read");
  assert.equal(t.level, 2);
  assert.equal(t.pa, frameBase + 0x1fffffn);
});

test("CR3 switch changes translation (fresh address space)", () => {
  const { raw, mmu } = freshMmu();
  const va = 0xfffff70000001000n;
  mmu.mapPage(va, mmu.frameAlloc(), {});
  assert.ok(mmu.lookup(va));

  const cr3b = mmu.newAddressSpace();
  mmu.cr3 = cr3b;
  mmu.flushTlb();
  assert.equal(mmu.lookup(va), null); // empty space: nothing mapped
});

test("TranslatedMemory: demand-zero fills unmapped VAs, identity when PG off", () => {
  const raw = new SparseMemory();
  const tm = new TranslatedMemory();
  const mmu = new Mmu(raw, { demandMap: true });
  tm.attach(mmu);
  mmu.enablePaging(mmu.newAddressSpace());

  const va = 0xffffe00000011000n;
  tm.writeUtf16(va, "hello");
  assert.equal(tm.readUtf16(va, 8), "hello");
  // landed in a real physical frame via tables
  const t = mmu.lookup(va);
  assert.ok(t && raw.hasPage(t.pa));

  // paging off -> pure identity passthrough
  mmu.cr0 &= ~0x80000000n;
  tm.write(va, [0x41]);
  assert.equal(raw.read(va, 1)[0], 0x41);
});

// ======== PageTableSpace suites (feat/internals-blog-modules) ========

/** Kernel on a low-memory layout (unicorn-safe) with tables preloaded
 *  minimally: paging only needs the KPROCESS DTB offset fallback. */
function lowKernel() {
  const cpu = new JsInterpreter(new SparseMemory());
  const k = new NtKernel({
    cpu,
    bases: {
      kva: 0x10000000n,
      pool: 0x20000000n,
      thunk: 0x30000000n,
      eproc: 0x40000000n,
      driver: 0x50000000n,
    },
  });
  return k;
}

test("splitVa/joinVa round-trip and canonical sign-extension", () => {
  const va = joinVa(0xf, 0x123, 0x45, 0x67, 0x89a, false);
  const idx = splitVa(va);
  assert.deepEqual(
    [idx.pml4Index, idx.pdPtIndex, idx.pdIndex, idx.ptIndex, idx.offset],
    [0xf, 0x123, 0x45, 0x67, 0x89a],
  );
  // high half mirrors the classic Windows self-map identity
  const hi = joinVa(0x1ed, 0, 0, 0, 0, true);
  assert.equal(hi, 0xfffff68000000000n);
});

test("decodePte + pteBitsString decode hardware bits", () => {
  // P|W|U|A|D|G + pfn 0x1f8 + NX
  const v = (1n << 63n) | (0x1f8n << 12n) | 0x167n;
  const d = decodePte(v);
  assert.equal(d.present, true);
  assert.equal(d.writable, true);
  assert.equal(d.user, true);
  assert.equal(d.dirty, true);
  assert.equal(d.global, true);
  assert.equal(d.nx, true);
  assert.equal(d.pfn & 0xffffffffffn, 0x1f8n); // PFN field is bits 12..51
  const s = pteBitsString(v);
  assert.match(s, /G/);
  assert.match(s, /D/);
  assert.match(s, /NX/);
  assert.equal(pteBitsString(0n), "-------K-- X");
});

test("PageTableSpace maps 4K pages and the walk resolves through all levels", () => {
  const k = lowKernel();
  const pts = new PageTableSpace(k, { physBase: 0x300000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "walker", pid: 42 });
  assert.equal(proc.dtb, 0x300000n);

  const va = joinVa(0x9, 0x87, 0x65, 0x43, 0x10, false);
  const m = pts.mapPage(proc, va, { writable: true });
  assert.equal(m.level, "4K");

  const w = pts.translate(va, proc);
  assert.equal(w.ok, true);
  assert.equal(w.level, "4K");
  assert.equal(w.pa & ~0xfffn, m.pa);

  // rows carry both physical entry addresses and self-map VAs; the PTE row's
  // entryPa must agree with reading the PTE THROUGH its computed self-map VA.
  const pteRow = w.rows.find((r) => r.label === "PTE");
  assert.ok(pteRow);
  assert.equal(k.mem.u64(pteRow.entryVa), pteRow.value);
  assert.ok((pteRow.entryVa >> 47n) === 0n, "low-half self-map stays canonical-user");
});

test("self-map VAs alias page-table memory for dq/eb-style access", () => {
  const k = lowKernel();
  const pts = new PageTableSpace(k, { physBase: 0x300000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "alias" });

  const va = joinVa(0x2, 0x2, 0x2, 0x11, 0, false);
  const m = pts.mapPage(proc, va, {});
  const w = pts.translate(va, proc);
  const pteRow = w.rows.at(-1);

  // dq through the self-map shows the live PTE
  assert.equal(k.mem.u64(pteRow.entryVa), pteRow.value);

  // eb-style repair through the alias: flip writable off, then a walk
  // syncs the edit back into the physical frame
  const cur = k.mem.u64(pteRow.entryVa);
  k.mem.w64(pteRow.entryVa, cur & ~0x2n);
  pts.translate(va, proc); // any walk flushes aliases back
  assert.equal(decodePte(k.mem.u64(pteRow.entryPa)).writable, false);
  void m;
});

test("large pages terminate at the PDE with PS set", () => {
  const k = lowKernel();
  const pts = new PageTableSpace(k, { physBase: 0x300000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "big" });
  // build raw so the in-2M offset (21 bits) survives joinVa's 12-bit offset
  const va = (0x3n << 39n) | (0x3n << 30n) | (0x77n << 21n) | 0x1234n;
  const m = pts.mapPage(proc, va, { size: 0x200000 });
  assert.equal(m.level, "2M");
  const w = pts.translate(va, proc);
  assert.equal(w.ok, true);
  assert.equal(w.level, "2M");
  assert.equal(w.rows.length, 3); // PML4E, PDPTE, PDE — no PTE level
  assert.equal(w.pa & 0x1fffffn, 0x1234n);
});

test("walk failure reports the exact level", () => {
  const k = lowKernel();
  const pts = new PageTableSpace(k, { physBase: 0x300000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "hole" });
  const unmapped = joinVa(0x100, 5, 5, 5, 0, false);
  const w = pts.translate(unmapped, proc);
  assert.equal(w.ok, false);
  assert.equal(w.failedAt, "PML4E");
});

test("CR3 shuffle: real DTB findable via self-ref signature scan", async () => {
  const { NtKernel: K } = await import("../src/kernel.mjs");
  void K;
  const kern = lowKernel();
  const pts = new PageTableSpace(kern, { physBase: 0x300000n, selfRefIndex: 0xf });
  const real = pts.createProcess({ name: "victim", pid: 668 });
  pts.mapPage(real, joinVa(0x8, 0x8, 0x8, 0x8, 0, false), {});

  // decoy DTB whose self-ref sits at a different index — anti-cheat-style shuffle
  const decoy = pts.createProcess({ name: "decoy", pid: 665, selfRefIndex: 0x12 });
  decoy.decoy = true;
  pts.mapPage(decoy, joinVa(0x8, 0x8, 0x8, 0x8, 0, false), {});

  const hits = pts.scanSelfRefFrames().map((h) => h.dtb);
  assert.ok(hits.includes(real.dtb));
  assert.ok(hits.includes(decoy.dtb));
  // each frame's signature index distinguishes them
  const sigs = pts.scanSelfRefFrames();
  assert.deepEqual(sigs.map((s) => s.index).sort(), [0xf, 0x12]);
});

test("self-map region is protected against accidental mapping", () => {
  const k = lowKernel();
  const pts = new PageTableSpace(k, { physBase: 0x300000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "careful" });
  assert.throws(() => pts.mapPage(proc, joinVa(0xf, 0, 0, 0, 0, false)));
});

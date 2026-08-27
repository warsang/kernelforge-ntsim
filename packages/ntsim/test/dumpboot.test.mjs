/**
 * End-to-end: synthetic dump -> carve -> ntsim boots with genuine bytes ->
 * debugger reads real data out of the emulated address space.
 *
 * Reuses the kdmp test's fixture builder by inlining a compact variant:
 * builds dump -> parses -> carves ntoskrnl "MZ" page -> loads into
 * SparseMemory via loadDumpState -> asserts the bytes are visible at the
 * same VA ntsim uses.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { KdmpParser, splitVa } from "../../ntsim-assets/scripts/kdmp.mjs";
import { loadDumpState } from "../src/dumpstate.mjs";
import { SparseMemory } from "../src/memory.mjs";

const PAGE = 0x1000;
const DTB = 0x1ab000n;
const CODE_PA_PFN = 2;
const NTOS_BASE = 0xfffff8052b800000n;
const PS_LML = 0xfffff80539001000n;

function buildSyntheticDump() {
  const pages = new Map();
  const pg = () => new Uint8Array(PAGE);
  const idx = splitVa(NTOS_BASE);
  const PT_PFN = 0x10, PD_PFN = 0x11, PDPT_PFN = 0x12, LDR_PA_PFN = 0x20;

  const pml4 = pg();
  new DataView(pml4.buffer).setBigUint64(idx.pml4Index * 8, BigInt(PDPT_PFN) << 12n | 1n, true);
  pages.set(Number(DTB >> 12n), pml4);
  const pdpt = pg();
  new DataView(pdpt.buffer).setBigUint64(idx.pdPtIndex * 8, BigInt(PD_PFN) << 12n | 1n, true);
  pages.set(PDPT_PFN, pdpt);
  const pd = pg();
  new DataView(pd.buffer).setBigUint64(idx.pdIndex * 8, BigInt(PT_PFN) << 12n | 1n, true);
  pages.set(PD_PFN, pd);
  // map both NTOS pt slot and LDR region through one PT
  new DataView(pd.buffer).setBigUint64(splitVa(PS_LML).pdIndex * 8, BigInt(PT_PFN) << 12n | 1n, true);
  const pt = pg();
  new DataView(pt.buffer).setBigUint64(idx.ptIndex * 8, BigInt(CODE_PA_PFN) << 12n | 1n, true);
  new DataView(pt.buffer).setBigUint64(splitVa(PS_LML).ptIndex * 8, BigInt(LDR_PA_PFN) << 12n | 1n, true);
  pages.set(PT_PFN, pt);

  const codePage = pg();
  codePage[0] = 0x4d; codePage[1] = 0x5a; // MZ
  codePage[2] = 0xde; codePage[3] = 0xad; // marker
  pages.set(CODE_PA_PFN, codePage);

  let ldrHead = pg();
  const dvE = new DataView(ldrHead.buffer);
  dvE.setBigUint64(0x00, PS_LML, true); // Flink -> self (single entry)
  dvE.setBigUint64(0x08, PS_LML, true);
  dvE.setBigUint64(0x10, NTOS_BASE, true); // DllBase
  dvE.setUint32(0x20, 0x800000, true);     // SizeOfImage
  dvE.setUint16(0x28, 26, true);           // FullDllName.Length (bytes)
  // name at +0x400 of this page
  const nameStr = "\\SystemRoot\\ntoskrnl.exe";
  for (let i = 0; i < nameStr.length; i++) {
    ldrHead[0x400 + i * 2] = nameStr.charCodeAt(i);
    ldrHead[0x400 + i * 2 + 1] = 0;
  }
  dvE.setBigUint64(0x30, PS_LML + 0x400n, true);
  pages.set(LDR_PA_PFN, ldrHead);

  // emit FullDump with zero-filled gaps
  const pfns = [...pages.keys()].map(Number).sort((a, b) => a - b);
  const first = pfns[0];
  const count = pfns[pfns.length - 1] - first + 1;
  const buf = new ArrayBuffer(0x2000 + count * PAGE);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  dv.setUint32(0x0000, 0x45474150, true);
  dv.setUint32(0x0004, 0x34365544, true);
  dv.setBigUint64(0x0010, DTB, true);
  dv.setBigUint64(0x0020, PS_LML, true);
  dv.setBigUint64(0x0028, PS_LML + 0x1000n, true);
  dv.setUint32(0x0088, 1, true);
  dv.setBigUint64(0x0090, BigInt(count), true);
  dv.setBigUint64(0x0098, BigInt(first), true);
  dv.setBigUint64(0x00a0, BigInt(count), true);
  dv.setUint32(0x0f98, 1, true);
  let off = 0x2000;
  for (let i = 0; i < count; i++) {
    u8.set(pages.get(first + i) ?? new Uint8Array(PAGE), off);
    off += PAGE;
  }
  return new KdmpParser(buf);
}

test("dump -> carve -> loadDumpState puts genuine bytes into ntsim memory", () => {
  const dmp = buildSyntheticDump();

  // carve: read the ntoskrnl header page VA -> base64 state blob
  const pageBytes = dmp.readVirtual(NTOS_BASE, PAGE);
  assert.ok(pageBytes, "carve read failed");
  const state = {
    keyAddresses: {
      psLoadedModuleList: PS_LML.toString(16),
      psActiveProcessHead: (PS_LML + 0x1000n).toString(16),
    },
    modules: [{ name: "\\SystemRoot\\ntoskrnl.exe", base: NTOS_BASE.toString(16), size: 0x800000 }],
    pages: [[NTOS_BASE.toString(16), Buffer.from(pageBytes).toString("base64")]],
  };

  const mem = new SparseMemory();
  const info = loadDumpState(mem, state);
  assert.equal(info.pagesLoaded, 1);
  assert.equal(info.psLoadedModuleList, PS_LML);

  // genuine bytes visible at the exact VA ntsim/driver code would touch
  const raw = mem.read(NTOS_BASE, 4);
  assert.deepEqual([...raw], [0x4d, 0x5a, 0xde, 0xad]);

  // module metadata usable for lm command
  assert.equal(info.modules[0].name.endsWith("ntoskrnl.exe"), true);
  assert.equal(info.modules[0].base, NTOS_BASE);
});

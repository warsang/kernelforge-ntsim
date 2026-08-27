/**
 * Synthetic end-to-end test for the kdmp port + carve pipeline:
 * builds a minimal FullDump-format file containing:
 *   - an identity-mapped x64 page table (PML4->PT) covering one code page
 *   - a fake ntoskrnl.exe module entry in PsLoadedModuleList
 * then parses it, translates VAs, reads the module name, and carves.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { KdmpParser, splitVa } from "../scripts/kdmp.mjs";

const PAGE = 0x1000;

/** Build a FullDump buffer from {pa -> pageBytes} + header fields.
 *  PFN gaps are filled with zero pages (a real dump contains them). */
function buildFullDump({ dtb, pages }) {
  const pfns = [...pages.keys()].map(Number).sort((a, b) => a - b);
  const first = pfns[0];
  const count = pfns[pfns.length - 1] - first + 1;
  const ZERO = new Uint8Array(PAGE);

  const total = 0x2000 + count * PAGE;
  const buf = new ArrayBuffer(total);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);

  dv.setUint32(0x0000, 0x45474150, true); // EGAP
  dv.setUint32(0x0004, 0x34365544, true); // 46UD
  dv.setUint32(0x0008, 10, true);
  dv.setUint32(0x000c, 0, true);
  dv.setBigUint64(0x0010, dtb, true);
  dv.setBigUint64(0x0020, PS_LOADED_MODULE_LIST, true);
  dv.setBigUint64(0x0028, PS_ACTIVE_PROCESS_HEAD, true);
  dv.setUint32(0x0038, 0xef, true);
  dv.setUint32(0x0088, 1, true); // NumberOfRuns
  dv.setBigUint64(0x0090, BigInt(count), true);
  dv.setBigUint64(0x0098, BigInt(first), true);
  dv.setBigUint64(0x00a0, BigInt(count), true);
  dv.setUint32(0x0f98, 1, true); // DumpType = FullDump

  let off = 0x2000;
  for (let i = 0; i < count; i++) {
    u8.set(pages.get(first + i) ?? ZERO, off);
    off += PAGE;
  }
  return buf;
}

// ---- fixture layout --------------------------------------------------------
const DTB = 0x1ab000n; // PML4 page frame
const CODE_PA_PFN = 2; // physical page 0x2000 (inside dump body)
const NTOS_BASE = 0xfffff8052b800000n;

const PS_LOADED_MODULE_LIST = 0xfffff80539001000n;
const PS_ACTIVE_PROCESS_HEAD = 0xfffff80539002000n;

test("splitVa matches x64 layout", () => {
  const s = splitVa(NTOS_BASE);
  assert.equal(s.offset, 0);
  assert.equal(s.pml4Index, Number((NTOS_BASE >> 39n) & 0x1ffn));
});

test("kdmp port parses synthetic FullDump and walks PsLoadedModuleList", () => {
  const pages = new Map(); // pfn(number) -> Uint8Array

  const getPage = () => new Uint8Array(PAGE);

  // --- identity map NTOS_BASE via 4-level tables -------------------------
  const idx = splitVa(NTOS_BASE);
  // allocate table pages at known PFNs
  const PT_PFN = 0x10, PD_PFN = 0x11, PDPT_PFN = 0x12, PML4E_TARGET = idx.pml4Index;

  // PML4 page (at DTB): entry[idx.pml4Index] -> PDPT @ PDPT_PFN
  const pml4 = getPage();
  new DataView(pml4.buffer).setBigUint64(idx.pml4Index * 8, BigInt(PDPT_PFN) << 12n | 1n, true);
  pages.set(Number(DTB >> 12n), pml4);

  // PDPT: entry[idx.pdPtIndex] -> PD @ PD_PFN
  const pdpt = getPage();
  new DataView(pdpt.buffer).setBigUint64(idx.pdPtIndex * 8, BigInt(PD_PFN) << 12n | 1n, true);
  pages.set(PDPT_PFN, pdpt);

  // PD: entry[idx.pdIndex] -> PT @ PT_PFN
  const pd = getPage();
  new DataView(pd.buffer).setBigUint64(idx.pdIndex * 8, BigInt(PT_PFN) << 12n | 1n, true);
  pages.set(PD_PFN, pd);

  // PT: entry[idx.ptIndex] -> CODE page @ CODE_PA_PFN
  const pt = getPage();
  new DataView(pt.buffer).setBigUint64(idx.ptIndex * 8, BigInt(CODE_PA_PFN) << 12n | 1n, true);
  pages.set(PT_PFN, pt);

  // code page: "MZ" + KLDR entry content
  const codePage = getPage();
  codePage[0] = 0x4d; codePage[1] = 0x5a;
  pages.set(CODE_PA_PFN, codePage);

  // --- module list page(s) -----------------------------------------------
  // The LDR structures live at PS_LOADED_MODULE_LIST (kernel VA). Map BOTH its
  // page and the name-buffer page through the SAME PT as NTOS_BASE by adding
  // PT entries pointing at dedicated physical pages.
  const LDR_PA_PFN = 0x20;   // physical page holding the LDR head+entry
  const NAME_PA_PFN = 0x21;  // physical page holding FullDllName string

  const ldrHead = getPage(); // unused content; head points at entry below
  pages.set(LDR_PA_PFN, ldrHead);

  const entryPage = getPage();
  const entryOffInPage = 0x40;
  const dvE = new DataView(entryPage.buffer);
  // InLoadOrderLinks.Flink -> self-terminating: Flink = head address is not
  // representable here, so walk stops via seen-set in carve logic. Point both
  // links at themselves.
  dvE.setBigUint64(entryOffInPage + 0x00, PS_LOADED_MODULE_LIST, true);
  dvE.setBigUint64(entryOffInPage + 0x08, PS_LOADED_MODULE_LIST, true);
  // DllBase
  dvE.setBigUint64(entryOffInPage + 0x10, NTOS_BASE, true);
  // SizeOfImage
  dvE.setUint32(entryOffInPage + 0x20, 0x800000, true);
  // FullDllName UNICODE_STRING
  const nameStr = "\\SystemRoot\\ntoskrnl.exe";
  dvE.setUint16(entryOffInPage + 0x28, nameStr.length * 2, true);
  const nameOffInPage = entryOffInPage + 0x100;
  for (let i = 0; i < nameStr.length; i++) {
    entryPage[nameOffInPage + i * 2] = nameStr.charCodeAt(i);
    entryPage[nameOffInPage + i * 2 + 1] = 0;
  }
  dvE.setBigUint64(entryOffInPage + 0x30,
    (BigInt(NAME_PA_PFN) << 12n) + BigInt(nameOffInPage), true);
  pages.set(NAME_PA_PFN, entryPage);

  // Map the name-buffer VA through the page tables: NAME_PA_PFN is physical;
  // give it a VA in the LDR region (same PD as the LDR head).
  const ptLdrEarly = pages.get(PT_PFN);
  const nameVa = PS_LOADED_MODULE_LIST + 0x1000n; // next PT slot over
  const nameIdx = splitVa(nameVa);
  new DataView(pd.buffer).setBigUint64(nameIdx.pdIndex * 8, BigInt(PT_PFN) << 12n | 1n, true);
  new DataView(ptLdrEarly.buffer).setBigUint64(nameIdx.ptIndex * 8, BigInt(NAME_PA_PFN) << 12n | 1n, true);
  // point FullDllName.Buffer at the mapped VA — and since bufPtr is
  // page-based (nameVa = NAME_PA_PFN << 12), the string must live at offset 0
  // of that page. Move it there (entry fields stay in their own region).
  dvE.setBigUint64(entryOffInPage + 0x30, nameVa, true);
  for (let i = 0; i < nameStr.length; i++) {
    entryPage[i * 2] = nameStr.charCodeAt(i);
    entryPage[i * 2 + 1] = 0;
  }

  // Map the LDR VA to LDR_PA_PFN: shares PML4/PDPT with NTOS_BASE but has a
  // DIFFERENT PD index (348 vs 456), so add a PD entry -> same PT page.
  const ptLdr = pages.get(PT_PFN);
  const ldrIdx = splitVa(PS_LOADED_MODULE_LIST);
  new DataView(pd.buffer).setBigUint64(ldrIdx.pdIndex * 8, BigInt(PT_PFN) << 12n | 1n, true);
  new DataView(ptLdr.buffer).setBigUint64(ldrIdx.ptIndex * 8, BigInt(LDR_PA_PFN) << 12n | 1n, true);
  // The entry physically lives in LDR_PA_PFN at page offset 0x40; its VA is
  // PS_LOADED_MODULE_LIST (page-aligned) + 0x40. The carve walk reads the
  // LIST_ENTRY AT the head address — so place head VA -> entry offset by
  // pointing PS_LOADED_MODULE_LIST's PT slot directly at the entry content.
  // Simplest: copy entry bytes to ldrHead at offset 0 and keep name pointer
  // into NAME_PA_PFN.
  ldrHead.set(entryPage.subarray(0x40, 0x40 + 0x60), 0);
  pages.set(LDR_PA_PFN, ldrHead);

  // second page for the entry if it straddles — keep offset 0 for simplicity by
  // placing the entry exactly at its page start (head != entry here).
  const dump = buildFullDump({ dtb: DTB, pages });

  const dmp = new KdmpParser(dump);
  assert.equal(dmp.header.dumpType, 1);
  assert.equal(dmp.physmem.size > 0, true);

  // VA translation must resolve to the code page
  const pa = dmp.virtTranslate(NTOS_BASE);
  assert.ok(pa !== null, "virtTranslate failed");
  assert.equal(pa / BigInt(PAGE), BigInt(CODE_PA_PFN));

  // read MZ through readVirtual
  const mz = dmp.readVirtual(NTOS_BASE, 2);
  assert.equal(mz[0], 0x4d);
  assert.equal(mz[1], 0x5a);

  // walk module list: read DllBase + FullDllName exactly like carve-dump does
  const linkBuf = dmp.readVirtual(PS_LOADED_MODULE_LIST, 8);
  assert.ok(linkBuf, "head LIST_ENTRY unreadable");
  const flink = new DataView(linkBuf.buffer).getBigUint64(0, true);
  assert.equal(flink, PS_LOADED_MODULE_LIST, "single-entry list points at head");

  const dllBaseBuf = dmp.readVirtual(PS_LOADED_MODULE_LIST + 0x10n, 8);
  const dllBase = new DataView(dllBaseBuf.buffer).getBigUint64(0, true);
  assert.equal(dllBase, NTOS_BASE);

  const nameLenBuf = dmp.readVirtual(PS_LOADED_MODULE_LIST + 0x28n, 2);
  const nameLen = new DataView(nameLenBuf.buffer).getUint16(0, true);
  assert.equal(nameLen, 48); // 24 chars * 2 bytes (UTF-16 byte length)

  const bufPtrBuf = dmp.readVirtual(PS_LOADED_MODULE_LIST + 0x30n, 8);
  const bufPtr = new DataView(bufPtrBuf.buffer).getBigUint64(0, true);
  const nameBytes = dmp.readVirtual(bufPtr, nameLen);
  let name = "";
  for (let i = 0; i < nameLen / 2; i++) {
    name += String.fromCharCode(nameBytes[i * 2] | (nameBytes[i * 2 + 1] << 8));
  }
  assert.equal(name, "\\SystemRoot\\ntoskrnl.exe");
});

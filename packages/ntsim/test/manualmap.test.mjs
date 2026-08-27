import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "../src/kernel.mjs";
import { PeBuilder } from "../src/pebuilder.mjs";
import { mapPe, parsePe, rvaToOffset } from "../src/pe.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

/** x64 machine code helpers (hand-assembled fixtures). */
class Asm {
  constructor() { this.b = []; }
  bytes(...x) { this.b.push(...x); return this; }
  // mov rcx, imm64 : 48 B9 <dq>
  movRcxImm(v) {
    this.bytes(0x48, 0xb9);
    let x = BigInt(v);
    for (let i = 0; i < 8; i++) { this.b.push(Number(x & 0xffn)); x >>= 8n; }
    return this;
  }
  // call qword ptr [rip+disp32] : FF 15 <dd>
  callRip(disp) {
    const d = disp | 0;
    return this.bytes(0xff, 0x15, d & 0xff, (d >> 8) & 0xff, (d >> 16) & 0xff, (d >> 24) & 0xff);
  }
  ret() { return this.bytes(0xc3); }
}

test("PE builder produces parseable image; round-trip via parsePe", () => {
  const asm = new Asm();
  asm.ret();
  const b = new PeBuilder()
    .addSection(".text", new Uint8Array(asm.b))
    .addImports([{ dll: "ntoskrnl.exe", funcs: ["DbgPrint"] }]);
  const { image } = b.build(0x1000);

  const pe = parsePe(image);
  assert.equal(pe.imageBase, 0x140000000n);
  assert.equal(pe.sections.length, 2);
  assert.ok(pe.dirs[1].rva > 0);
  assert.ok(rvaToOffset(pe, pe.dirs[1].rva) !== null);
});

test("end-to-end: build .sys -> manual map -> DriverEntry runs -> DbgPrint captured", async () => {
  const k = new NtKernel();
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();

  // code layout:
  //   0x00: mov rcx, fmtVA          (48 B9 dq)
  //   0x0a: call [rip+disp32]       (FF 15 dd)
  //   0x10: xor eax,eax             (31 C0)
  //   0x12: ret                     (C3)
  // IAT slot sits at rdata RVA + idtSize + ... — we compute it from the built
  // section table instead of hand-deriving.
  const fmtStr = "kfdemo: mapped driver says hi %d\n";
  const dataSec = new Uint8Array(64);
  for (let i = 0; i < fmtStr.length; i++) dataSec[i] = fmtStr.charCodeAt(i);
  dataSec[fmtStr.length] = 0;

  // placeholder code with correct sizes; disp patched after layout known
  const code = new Uint8Array(0x14);
  code.set([0x48, 0xb9], 0);            // mov rcx, imm64
  const fmtVaSlot = 2;                  // bytes 2..9 hold fmt VA (patched)
  code.set([0xff, 0x15], 10);           // call [rip+disp32]
  const dispSlot = 12;                  // bytes 12..15
  code.set([0x31, 0xc0], 16);
  code.set([0xc3], 18);

  const b = new PeBuilder()
    .addSection(".text", code)
    .addSection(".data", dataSec, 0xc0000040)
    .addImports([{ dll: "ntoskrnl.exe", func: [], funcs: ["DbgPrint"] }]);
  const { image, imageSize } = b.build(0x1000);

  const pe = parsePe(image);
  // find .data rva for fmt string address
  const dataSecHdr = pe.sections.find((s) => s.name === ".data");
  const fmtRva = dataSecHdr.rva;

  // find IAT slot for DbgPrint: walk import dir in the BUILT image
  // (use our own parser on raw bytes to locate hint/name then IAT entry index 0)
  const impDirRva = pe.dirs[1].rva;
  const impOff = rvaToOffset(pe, impDirRva);
  const iatRvaField = u32At(image, impOff + 16);
  void iatRvaField;

  // Map at synthetic kernel base
  const base = 0xfffff80120000000n;
  let dbgThunk = null;
  const mapping = mapPe(image, k.mem, base, (name) => {
    if (name === "ntoskrnl.exe!DbgPrint") {
      dbgThunk = k.apiThunks.get("DbgPrint");
      return dbgThunk;
    }
    return null;
  });
  assert.ok(dbgThunk);

  // patch code: fmt VA = base + fmtRva ; call disp = (iatRva - ripAfter)
  // NOTE: .text sits at its section RVA (0x1000 here), so absolute patch
  // addresses are base + textRva + insnOffset.
  const textHdr = pe.sections.find((s) => s.name === ".text");
  const textBase = base + BigInt(textHdr.rva);
  const iatRva = u32At(image, impOff + 16); // IAT RVA from descriptor
  const callEndRva = 0x10;                  // rip after 'call [rip+d]' = textRva+0x10
  const disp = Number(BigInt(iatRva) - BigInt(textHdr.rva) - BigInt(callEndRva));
  const dv = new Uint8Array(4);
  dv[0] = disp & 0xff; dv[1] = (disp >> 8) & 0xff;
  dv[2] = (disp >> 16) & 0xff; dv[3] = (disp >> 24) & 0xff;
  k.mem.write(textBase + 12n, dv);
  const fmtVa = base + BigInt(fmtRva);
  const fv = new Uint8Array(8);
  let x = fmtVa;
  for (let i = 0; i < 8; i++) { fv[i] = Number(x & 0xffn); x >>= 8n; }
  k.mem.write(textBase + 2n, fv);

  // run DriverEntry
  const r = k.callDriverEntry(mapping.entry, 0n, 0n);
  assert.equal(r.status, "ok");
  assert.deepEqual(k.dbgLog, ["kfdemo: mapped driver says hi 0\n"]);
});

// tiny LE reader used above (avoids exporting internals from pe.mjs)
function u32At(b, o) {
  return ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0);
}

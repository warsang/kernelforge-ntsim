/**
 * Regression tests for PE import-table parsing.
 *
 * Historical bug: hint/name strings were read as a fixed 64-byte window and
 * trimmed with /\0.*$/. If a 0x0A byte appears anywhere after the first NUL
 * inside that window (common when the window runs past the import-string blob
 * into other .rdata — exactly what TBMKD.sys does), the regex fails to match,
 * the trim silently doesn't happen, and the import name keeps 64 raw bytes of
 * table garbage. Model lookups then miss and generic SUCCESS stubs get
 * provisioned under mangled names.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PeBuilder } from "../src/pebuilder.mjs";
import { parsePe, mapPe, PeError } from "../src/pe.mjs";

function u32At(b, o) {
  return ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0);
}

/** Locate every hint/name string file offset via a faithful descriptor walk. */
function walkImportStrings(image) {
  const pe = parsePe(image);
  const r2o = (rva) => {
    for (const s of pe.sections) {
      if (rva >= s.rva && rva < s.rva + Math.max(s.virtualSize, s.rawSize)) {
        const d = rva - s.rva;
        if (d < s.rawSize) return s.rawPtr + d;
        break;
      }
    }
    return null;
  };
  const out = [];
  let descOff = r2o(pe.dirs[1].rva);
  for (;;) {
    const nameRva = u32At(image, descOff + 12);
    const ftRva = u32At(image, descOff + 16);
    if (!nameRva && !ftRva) break;
    const dllNo = r2o(nameRva);
    let j = dllNo;
    while (image[j] !== 0) j++;
    const dll = image.subarray(dllNo, j).toString("latin1");
    let t = ftRva;
    for (;;) {
      const tOff = r2o(t);
      const hintRva = tOff != null ? u32At(image, tOff) : 0;
      if (!hintRva) break;
      const h = r2o(hintRva & 0x7fffffff);
      out.push({ dll, strOff: h + 2 });
      t += 8;
    }
    descOff += 20;
  }
  return { pe, strings: out };
}

/** Replicate PeBuilder._impBlobSize(): total byte size of the import blob. */
function impBlobSize(imports) {
  let n = (imports.length + 1) * 20;
  let hntEntries = 0;
  for (const imp of imports) {
    n += imp.dll.length + 1;
    hntEntries += imp.funcs.length + 1;
    for (const f of imp.funcs) n += 2 + f.length + 1;
  }
  n += hntEntries * 16; // hint/name table + IAT
  return (n + 7) & ~7;
}

test("import names survive a 0x0A byte inside the 64-byte read window", () => {
  // Import list mirrors the tail of TBMKD.sys's ntoskrnl.exe imports: short
  // blob so the last name's window reaches the post-section padding.
  const funcs = ["DbgPrint", "__C_specific_handler", "RtlInitUnicodeString"];
  const asm = new Uint8Array([0xc3]); // ret
  const b = new PeBuilder()
    .addSection(".text", asm)
    .addImports([{ dll: "ntoskrnl.exe", funcs }]);
  const { image } = b.build(0x1000);

  const { pe, strings } = walkImportStrings(image);
  assert.equal(strings.length, funcs.length);

  // Plant a lone 0x0A into the alignment padding at the very end of the
  // import blob (past IDT + names + tables + strings + IAT) — within 64 bytes
  // of the last name's start, but harmless to parsing.
  const rd = pe.sections.find((s) => s.name === ".rdata");
  const padOff = rd.rawPtr + impBlobSize([{ dll: "ntoskrnl.exe", funcs }]);
  const last = strings[strings.length - 1];
  const dist = padOff - last.strOff;
  assert.ok(dist > 0 && dist < 64, `fixture broken: LF at ${dist} outside window`);
  assert.equal(image[padOff], 0);
  image[padOff] = 0x0a;

  // Self-check: the OLD parser must garble this name, proving the fixture
  // exercises the historical bug.
  const oldParserName = String.fromCharCode(
    ...image.subarray(last.strOff, last.strOff + 64)
  ).replace(/\0.*$/, "");
  assert.notEqual(
    oldParserName.replace(/[^\x20-\x7e]/g, ""),
    "RtlInitUnicodeString",
    "fixture no longer triggers the regex-trim bug; tighten offsets"
  );

  // Resolve with a recorder and require exact, clean names.
  const seen = [];
  mapPe(image, fakeMem(), 0xfffff80300000000n, (name) => {
    seen.push(name);
    return 0xfffff80100001000n;
  });
  assert.deepEqual(seen, funcs.map((f) => `ntoskrnl.exe!${f}`));
});

test("all-imports-resolve round trip on a multi-DLL image", () => {
  const b = new PeBuilder()
    .addSection(".text", new Uint8Array([0xc3]))
    .addImports([
      { dll: "ntoskrnl.exe", funcs: ["KeAcquireSpinLockRaiseToDpc", "PsCreateSystemThread", "IofCompleteRequest", "_vsnprintf"] },
      { dll: "WDFLDR.SYS", funcs: ["WdfVersionBind", "WdfVersionBindClass"] },
    ]);
  const { image } = b.build(0x1000);
  const seen = [];
  mapPe(image, fakeMem(), 0xfffff80300000000n, (name) => {
    seen.push(name);
    return 0xfffff80100001000n;
  });
  assert.deepEqual(seen, [
    "ntoskrnl.exe!KeAcquireSpinLockRaiseToDpc",
    "ntoskrnl.exe!PsCreateSystemThread",
    "ntoskrnl.exe!IofCompleteRequest",
    "ntoskrnl.exe!_vsnprintf",
    "wdfldr.sys!WdfVersionBind",
    "wdfldr.sys!WdfVersionBindClass",
  ]);
});

test("unmapped import directory RVA raises PeError instead of silent garbage", () => {
  const b = new PeBuilder()
    .addSection(".text", new Uint8Array([0xc3]))
    .addImports([{ dll: "ntoskrnl.exe", funcs: ["DbgPrint"] }]);
  const { image, imageSize } = b.build(0x1000);

  // Repoint dir[1].VirtualAddress at an RVA beyond the image.
  const pe = parsePe(image);
  void pe;
  const optOff = u32At(image, 0x3c) + 4 + 20;
  const dirBase = optOff + 112;
  const badRva = imageSize + 0x2000;
  image[dirBase + 8] = badRva & 0xff;
  image[dirBase + 9] = (badRva >> 8) & 0xff;
  image[dirBase + 10] = (badRva >> 16) & 0xff;
  image[dirBase + 11] = (badRva >> 24) & 0xff;

  assert.throws(() => {
    mapPe(image, fakeMem(), 0xfffff80300000000n, () => 0xfffff80100001000n);
  }, PeError);
});

/** Minimal SparseMemory stand-in covering just what mapPe needs. */
function fakeMem() {
  const pages = new Map();
  const key = (a) => Number(a >> 12n);
  return {
    write(addr, data) {
      const base = addr - (addr % 1n);
      for (let i = 0; i < data.length; i++) {
        const k = key(base + BigInt(i));
        if (!pages.has(k)) pages.set(k, new Uint8Array(4096));
        pages.get(k)[Number((base + BigInt(i)) & 0xfffn)] = data[i];
      }
    },
    u64(addr) {
      let v = 0n;
      for (let i = 7; i >= 0; i--) {
        const k = key(addr + BigInt(i));
        const pg = pages.get(k);
        const b = pg ? pg[Number((addr + BigInt(i)) & 0xfffn)] : 0;
        v = (v << 8n) | BigInt(b);
      }
      return v;
    },
    w64(addr, val) {
      const buf = new Uint8Array(8);
      let x = BigInt(val);
      for (let i = 0; i < 8; i++) { buf[i] = Number(x & 0xffn); x >>= 8n; }
      this.write(addr, buf);
    },
  };
}

/**
 * Minimal PE32+ image builder: wraps raw x64 code/data into a loadable .sys.
 * Produces real driver fixtures without a mingw toolchain and doubles as the
 * reference implementation students study in the manual-mapping lesson.
 *
 * Two-phase build: phase 1 computes exact section layout; phase 2 writes all
 * bytes with final RVAs (import tables need their own base RVA, so no patching).
 *
 * Import blob layout inside synthetic .rdata:
 *   [IDT (N+1)*20][dll names][hint/name tables][hint/name strings][IAT]
 */

const PAGE = 4096;
const FILE_ALIGN = 512;

export class PeBuilder {
  constructor() {
    this.sections = []; // {name, data, chars}
    this.imports = [];  // {dll:"ntoskrnl.exe", funcs:["DbgPrint",...]}
    this.imageBase = 0x140000000n;
    /** optional {rva, size} written to data directory 3 (.pdata) */
    this.exceptionDir = null;
  }

  addSection(name, data, chars = 0x60000020) {
    this.sections.push({ name, data, chars });
    return this;
  }

  addImports(imports) {
    this.imports.push(...imports);
    return this;
  }

  /** Compute import blob byte size (deterministic given imports). */
  _impBlobSize() {
    if (!this.imports.length) return 0;
    let n = (this.imports.length + 1) * 20;      // IDT
    let hntEntries = 0;
    for (const imp of this.imports) {
      n += imp.dll.length + 1;                   // dll name
      hntEntries += imp.funcs.length + 1;        // hint/name table incl terminator
      for (const f of imp.funcs) {
        n += 2 + f.length + 1;                   // hint(2)+name+nul
      }
    }
    n += hntEntries * 8;                         // hint/name table
    n += hntEntries * 8;                         // IAT
    return (n + 7) & ~7;
  }

  /** Phase 2: emit import blob bytes given its final RVA. */
  _writeImpBlob(blobRva) {
    const N = this.imports.length;
    const total = this._impBlobSize();
    const buf = new Uint8Array(total);
    const w16 = (o, v) => { buf[o] = v & 0xff; buf[o + 1] = (v >> 8) & 0xff; };
    const w32 = (o, v) => {
      buf[o] = v & 0xff; buf[o + 1] = (v >> 8) & 0xff;
      buf[o + 2] = (v >> 16) & 0xff; buf[o + 3] = (v >> 24) & 0xff;
    };

    const idtSize = (N + 1) * 20;
    let dllCursor = idtSize;
    // walk once to compute true sub-offsets
    let offHnt = dllCursor;
    for (const imp of this.imports) offHnt += imp.dll.length + 1;
    let offStr = offHnt;
    for (const imp of this.imports) offStr += (imp.funcs.length + 1) * 8;
    let offIat = offStr;
    for (const imp of this.imports)
      for (const f of imp.funcs) offIat += 2 + f.length + 1;

    // write dll names
    let dc = idtSize;
    this.imports.forEach((imp) => {
      imp._nameStart = dc;
      for (const ch of imp.dll) buf[dc++] = ch.charCodeAt(0);
      buf[dc++] = 0;
    });

    // write hint/name strings + tables + IAT
    let sc = offStr, hc = offHnt, ic = offIat;
    this.imports.forEach((imp, di) => {
      imp._hntStart = hc;
      imp._iatStart = ic;
      for (const f of imp.funcs) {
        const strStart = sc;
        w16(strStart, 0);
        for (let j = 0; j < f.length; j++) buf[strStart + 2 + j] = f.charCodeAt(j);
        buf[strStart + 2 + f.length] = 0;
        sc += 2 + f.length + 1;
        w32(hc, blobRva + strStart); // hint/rva entry (bit31=0 -> by name)
        w32(ic, blobRva + strStart); // IAT initially same
        hc += 8; ic += 8;
      }
      w32(hc, 0); w32(ic, 0); // terminators
      hc += 8; ic += 8;

      // descriptor
      const d = di * 20;
      w32(d + 0, blobRva + imp._hntStart);
      w32(d + 4, 0);
      w32(d + 8, 0);
      w32(d + 12, blobRva + imp._nameStart);
      w32(d + 16, blobRva + imp._iatStart);
    });
    // null descriptor terminator already zero

    return { bytes: buf, idtSize };
  }

  build(entryRva) {
    const hasImports = this.imports.length > 0;
    const numSections = this.sections.length + (hasImports ? 1 : 0);

    const peOff = 0x80;
    const coffOff = peOff + 4;
    const optOff = coffOff + 20;
    const optSize = 240; // PE32+: 112 fixed + 16*8 data dirs
    const sectOff = optOff + optSize;
    const headersSize = sectOff + numSections * 40;
    const hdrPages = Math.ceil(headersSize / PAGE);

    // ---- phase 1: layout ----
    let rva = hdrPages * PAGE;
    const layout = [];
    for (const s of this.sections) {
      layout.push({ ...s, rva });
      rva += Math.ceil(Math.max(s.data.length, 1) / PAGE) * PAGE;
    }
    const rdataRva = rva;
    const impBlobSize = this._impBlobSize();
    if (hasImports) {
      rva += Math.ceil(impBlobSize / PAGE) * PAGE;
    }
    const imageSize = rva;

    const impBlob = hasImports ? this._writeImpBlob(rdataRva) : null;

    // file offsets & sizes
    let fileOff = headersSize;
    for (const l of layout) {
      l.rawPtr = fileOff;
      l.rsize = Math.max(Math.ceil(l.data.length / FILE_ALIGN) * FILE_ALIGN, FILE_ALIGN);
      fileOff += l.rsize;
    }
    let rdataRawPtr = 0, rdataRsize = 0;
    if (impBlob) {
      rdataRawPtr = fileOff;
      rdataRsize = Math.max(Math.ceil(impBlob.bytes.length / FILE_ALIGN) * FILE_ALIGN, FILE_ALIGN);
      fileOff += rdataRsize;
    }
    const fileSize = fileOff;

    // ---- phase 2: emit ----
    const out = new Uint8Array(fileSize);
    const w16 = (o, v) => { out[o] = v & 0xff; out[o + 1] = (v >> 8) & 0xff; };
    const w32 = (o, v) => {
      out[o] = v & 0xff; out[o + 1] = (v >> 8) & 0xff;
      out[o + 2] = (v >> 16) & 0xff; out[o + 3] = (v >> 24) & 0xff;
    };
    const w64 = (o, v) => {
      let x = BigInt(v);
      for (let i = 0; i < 8; i++) { out[o + i] = Number(x & 0xffn); x >>= 8n; }
    };

    w16(0, 0x5a4d);
    w32(0x3c, peOff);
    w32(peOff, 0x00004550);
    w16(coffOff, 0x8664);
    w16(coffOff + 2, numSections);
    w16(coffOff + 16, optSize);
    w16(coffOff + 18, 0x2020);
    w16(optOff, 0x20b);
    w32(optOff + 16, entryRva);
    w64(optOff + 24, this.imageBase);
    w32(optOff + 32, PAGE);
    w32(optOff + 36, FILE_ALIGN);
    w32(optOff + 56, imageSize);
    w32(optOff + 60, headersSize);
    w64(optOff + 72, 0x100000n);
    w64(optOff + 80, 0x1000n);
    w64(optOff + 88, 0x100000n);
    w32(optOff + 108, 16);

    const dirBase = optOff + 112; // data dirs begin right after fixed part
    if (impBlob) {
      w32(dirBase + 8, rdataRva);          // dir[1].VirtualAddress
      w32(dirBase + 12, impBlob.idtSize);  // dir[1].Size
    }
    if (this.exceptionDir) {
      w32(dirBase + 24, this.exceptionDir.rva); // dir[3].VirtualAddress (.pdata)
      w32(dirBase + 28, this.exceptionDir.size);
    }

    const writeSection = (idx, name, vsize, srva, rsize, rawPtr, chars) => {
      const so = sectOff + idx * 40;
      for (let i = 0; i < 8 && i < name.length; i++) out[so + i] = name.charCodeAt(i);
      w32(so + 8, vsize);
      w32(so + 12, srva);
      w32(so + 16, rsize);
      w32(so + 20, rawPtr);
      w32(so + 36, chars);
    };

    layout.forEach((l, idx) => {
      writeSection(idx, l.name, l.data.length, l.rva, l.rsize, l.rawPtr, l.chars);
      out.set(l.data, l.rawPtr);
    });
    if (impBlob) {
      writeSection(
        layout.length, ".rdata", impBlob.bytes.length, rdataRva,
        rdataRsize, rdataRawPtr, 0xc0000040
      );
      out.set(impBlob.bytes, rdataRawPtr);
    }

    return { image: out, imageSize, rdataRva };
  }
}

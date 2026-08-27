/**
 * PE32+ manual mapper — parses real .sys/.dll bytes, relocates, resolves imports
 * against the kernel API thunk table. This IS the manual-mapping lesson made real:
 * students later reimplement this logic themselves; ntsim uses it to load drivers.
 *
 * All multi-byte fields little-endian. Addresses BigInt.
 */

const PAGE = 4096;

function u16(b, o) { return b[o] | (b[o + 1] << 8); }
function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

/**
 * Read a NUL-terminated byte string. A fixed-window + regex trim is NOT safe
 * here: if a 0x0A byte follows the first NUL inside the window, /\0.*$/ fails
 * to match and the whole window (embedded NULs, padding, hint bytes, adjacent
 * names) silently becomes the "name". Scan for the terminator instead.
 */
function readCString(b, off, max = 256) {
  const end = Math.min(off + max, b.length);
  let i = off;
  while (i < end && b[i] !== 0) i++;
  let s = "";
  for (let j = off; j < i; j++) s += String.fromCharCode(b[j]);
  return s;
}

export class PeError extends Error {}

export function parsePe(bytes) {
  if (u16(bytes, 0) !== 0x5a4d) throw new PeError("not an MZ executable");
  const e_lfanew = u32(bytes, 0x3c);
  if (u32(bytes, e_lfanew) !== 0x00004550) throw new PeError("PE signature missing");

  const coff = e_lfanew + 4;
  const machine = u16(bytes, coff);
  if (machine !== 0x8664) throw new PeError(`unsupported machine 0x${machine.toString(16)} (need x64)`);

  const numSections = u16(bytes, coff + 2);
  const optHeaderOff = coff + 20;
  const magic = u16(bytes, optHeaderOff);
  if (magic !== 0x20b) throw new PeError("not PE32+ (64-bit)");

  const entryRva = u32(bytes, optHeaderOff + 16);
  const sizeOfHeaders = u32(bytes, optHeaderOff + 60);
  const imageBase =
    BigInt(u32(bytes, optHeaderOff + 24)) |
    (BigInt(u32(bytes, optHeaderOff + 28)) << 32n);
  const sizeOfImage = u32(bytes, optHeaderOff + 56);
  const numDirsOff = optHeaderOff + 108;
  const numDirs = u32(bytes, numDirsOff);
  const dirs = [];
  for (let i = 0; i < numDirs; i++) {
    const dOff = numDirsOff + 4 + i * 8;
    dirs.push({ rva: u32(bytes, dOff), size: u32(bytes, dOff + 4) });
  }

  const sectionsOff = optHeaderOff + u16(bytes, coff + 16);
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = sectionsOff + i * 40;
    const name = String.fromCharCode(...bytes.subarray(s, s + 8)).replace(/\0.*$/, "");
    sections.push({
      name,
      virtualSize: u32(bytes, s + 8),
      rva: u32(bytes, s + 12),
      rawSize: u32(bytes, s + 16),
      rawPtr: u32(bytes, s + 20),
      chars: u32(bytes, s + 36),
    });
  }

  return { entryRva, imageBase, sizeOfImage, sizeOfHeaders, sections, dirs };
}

export function rvaToOffset(pe, rva) {
  for (const s of pe.sections) {
    if (rva >= s.rva && rva < s.rva + Math.max(s.virtualSize, s.rawSize)) {
      const delta = rva - s.rva;
      if (delta < s.rawSize) return s.rawPtr + delta;
      break;
    }
  }
  return null; // BSS / uninitialized
}

/**
 * Manual-map a PE into memory.
 * @param {Uint8Array} bytes raw PE file
 * @param {object} mem SparseMemory-like
 * @param {bigint} baseAddr chosen image base in emulated memory
 * @param {(name:string)=>bigint|null} resolveImport returns address for import name
 * @returns {{base: bigint, imageSize: number, entry: bigint, imports: string[], relocated: number}}
 */
export function mapPe(bytes, mem, baseAddr, resolveImport) {
  const pe = parsePe(bytes);
  const base = baseAddr;

  // 1. copy section raw data at RVA positions
  for (const s of pe.sections) {
    if (s.rawSize === 0) continue;
    mem.write(base + BigInt(s.rva), bytes.subarray(s.rawPtr, s.rawPtr + s.rawSize));
  }

  // 1a. zero-fill BSS: virtualSize > rawSize (Windows accurate 0x00 fill).
  // SparseMemory returns zeros on read-but-unmapped, but Unicorn needs real
  // pages materialized or it faults with UC_ERR 7 (write to unmapped).
  for (const s of pe.sections) {
    if (s.virtualSize > s.rawSize) {
      const gap = s.virtualSize - s.rawSize;
      const bssStart = base + BigInt(s.rva + s.rawSize);
      // SparseMemory.write on unwritten region creates pages on demand
      mem.write(bssStart, new Uint8Array(gap));
    }
  }

  // 1b. map the PE headers like a real loader: drivers legitimately read their
  // own DOS/NT headers (self-base scans for 'MZ', checksum verification,
  // export walking) and fault on unmapped header pages otherwise.
  if (pe.sizeOfHeaders > 0) {
    mem.write(base, bytes.subarray(0, Math.min(pe.sizeOfHeaders, bytes.length)));
  }

  // 2. process relocations (DIR[5])
  let relocated = 0;
  const relocDir = pe.dirs[5];
  if (relocDir.rva && relocDir.size) {
    let off = rvaToOffset(pe, relocDir.rva);
    const end = off + relocDir.size;
    while (off < end) {
      const pageRva = u32(bytes, off);
      const blockSize = u32(bytes, off + 4);
      if (blockSize === 0) break;
      const entries = (blockSize - 8) / 2;
      for (let i = 0; i < entries; i++) {
        const ent = u16(bytes, off + 8 + i * 2);
        const type = ent >> 12;
        const pos = ent & 0xfff;
        if (type === 0) continue; // padding
        if (type !== 10 && type !== 9) throw new PeError(`unsupported reloc type ${type}`);
        // DIR-based absolute addr of the field:
        const fieldVa = base + BigInt(pageRva + pos);
        const old = mem.u64(fieldVa);
        const rebased = old + (base - BigInt(pe.imageBase));
        mem.w64(fieldVa, rebased);
        relocated++;
      }
      off += blockSize;
    }
  }

  // 3. resolve imports (DIR[1])
  const imports = [];
  const impDir = pe.dirs[1];
  if (impDir.rva && impDir.size) {
    let descOff = rvaToOffset(pe, impDir.rva);
    if (descOff === null) throw new PeError(`import directory RVA 0x${impDir.rva.toString(16)} not in any raw section`);
    for (;;) {
      const nameRva = u32(bytes, descOff + 12);
      const firstThunkRva = u32(bytes, descOff + 16); // IAT
      if (!nameRva && !firstThunkRva) break;
      const dllNameOff = rvaToOffset(pe, nameRva);
      if (dllNameOff === null) throw new PeError(`import DLL name RVA 0x${nameRva.toString(16)} not in any raw section`);
      const dllName = readCString(bytes, dllNameOff).toLowerCase();

      let thunkRva = firstThunkRva;
      for (;;) {
        const oftFieldOff = rvaToOffset(pe, thunkRva);
        if (oftFieldOff === null) break; // IAT runs past raw data -> no more thunks
        const hintRva = u32(bytes, oftFieldOff);
        if (hintRva === 0) break;
        let fname;
        if (hintRva & 0x80000000) {
          fname = `ord:${hintRva & 0xffff}`;
        } else {
          const hOff = rvaToOffset(pe, hintRva & 0x7fffffff);
          if (hOff === null) throw new PeError(`hint/name RVA 0x${(hintRva & 0x7fffffff).toString(16)} not in any raw section`);
          fname = readCString(bytes, hOff + 2); // skip 2-byte hint, name is NUL-terminated
        }
        const resolved = resolveImport(`${dllName}!${fname}`);
        if (resolved === null || resolved === undefined) {
          throw new PeError(`unresolved import ${dllName}!${fname}`);
        }
        mem.w64(base + BigInt(thunkRva), typeof resolved === "bigint" ? resolved : BigInt(resolved));
        imports.push(`${dllName}!${fname}`);
        thunkRva += 8;
      }
      descOff += 20;
    }
  }

  return {
    base,
    imageSize: pe.sizeOfImage,
    entry: base + BigInt(pe.entryRva),
    imports,
    relocated,
  };
}

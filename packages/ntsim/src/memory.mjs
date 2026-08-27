/**
 * Sparse 64-bit physical/virtual address space.
 * Pages are keyed by frame number (addr >> 12) as BigInt string.
 * All addresses are BigInt — kernel VAs exceed 2^53.
 */

const PAGE_SHIFT = 12n;
const PAGE_SIZE = 4096;
const PAGE_MASK = 0xfffn;

export function pageNum(addr) {
  return (addr & ~PAGE_MASK).toString(16); // canonical page base as key
}

export class SparseMemory {
  constructor() {
    /** @type {Map<string, Uint8Array>} */
    this.pages = new Map();
    /** @type {Set<string>} pages written since last checkpoint (snapshot support) */
    this.dirty = new Set();
    this.stats = { reads: 0, writes: 0, faults: 0 };
  }

  ensurePage(baseAddr) {
    const k = baseAddr.toString(16);
    let p = this.pages.get(k);
    if (!p) {
      p = new Uint8Array(PAGE_SIZE);
      this.pages.set(k, p);
    }
    return p;
  }

  /** Read arbitrary span; missing pages read as zeros WITHOUT materializing. */
  read(addr, len) {
    const out = new Uint8Array(len);
    let done = 0;
    while (done < len) {
      const off = Number(addr & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, len - done);
      const p = this.pages.get((addr & ~PAGE_MASK).toString(16));
      if (p) out.set(p.subarray(off, off + chunk), done);
      else this.stats.faults++;
      addr += BigInt(chunk);
      done += chunk;
    }
    this.stats.reads++;
    return out;
  }

  write(addr, bytes) {
    const src = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    let done = 0;
    while (done < src.length) {
      const off = Number(addr & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, src.length - done);
      const p = this.ensurePage(addr & ~PAGE_MASK);
      p.set(src.subarray(done, done + chunk), off);
      this.dirty.add((addr & ~PAGE_MASK).toString(16));
      addr += BigInt(chunk);
      done += chunk;
    }
    this.stats.writes++;
  }

  // -- typed accessors ------------------------------------------------------
  u8(addr) { return this.read(addr, 1)[0]; }
  u16(addr) { return Number(this.read(addr, 2).reduceRight((a, b) => (a << 8n) | BigInt(b), 0n)); }
  u32(addr) { return Number(this.read(addr, 4).reduceRight((a, b) => (a << 8n) | BigInt(b), 0n)); }
  u64(addr) { return this.read(addr, 8).reduceRight((a, b) => (a << 8n) | BigInt(b), 0n); }

  w8(addr, v) { this.write(addr, [v & 0xff]); }
  w16(addr, v) { this.write(addr, [v & 0xff, (v >>> 8) & 0xff]); }
  w32(addr, v) {
    this.write(addr, [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
  }
  w64(addr, v) {
    let b = BigInt(v);
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) { out[i] = Number(b & 0xffn); b >>= 8n; }
    this.write(addr, out);
  }

  /**
   * Read a NUL-terminated UTF-16LE string (UNICODE_STRING buffer style).
   * @param {bigint} addr
   * @param {number} maxChars
   */
  readUtf16(addr, maxChars = 260) {
    const chars = [];
    for (let i = 0; i < maxChars; i++) {
      const c = this.u16(addr + BigInt(i * 2));
      if (c === 0) break;
      chars.push(c);
    }
    return String.fromCharCode(...chars);
  }

  writeUtf16(addr, s, maxChars = 260) {
    const lim = Math.min(s.length, maxChars - 1);
    for (let i = 0; i < lim; i++) this.w16(addr + BigInt(i * 2), s.charCodeAt(i));
    this.w16(addr + BigInt(lim * 2), 0);
  }

  readAnsi(addr, max = 256) {
    const bytes = [];
    for (let i = 0; i < max; i++) {
      const c = this.u8(addr + BigInt(i));
      if (c === 0) break;
      bytes.push(c);
    }
    return String.fromCharCode(...bytes);
  }

  writeAnsi(addr, s, max = 256) {
    const lim = Math.min(s.length, max - 1);
    for (let i = 0; i < lim; i++) this.w8(addr + BigInt(i), s.charCodeAt(i));
    this.w8(addr + BigInt(lim), 0);
  }

  hasPage(addr) {
    return this.pages.has((addr & ~PAGE_MASK).toString(16));
  }

  /**
   * True when every byte in [addr, addr+len) is backed by a materialized
   * page. Debugger/API layer uses this to turn silent-zero reads into
   * explicit memory faults.
   */
  canRead(addr, len = 1) {
    let cur = BigInt(addr);
    const end = cur + BigInt(len);
    while (cur < end) {
      const pageKey = (cur & ~PAGE_MASK).toString(16);
      if (!this.pages.has(pageKey)) return false;
      cur = (cur & ~PAGE_MASK) + BigInt(PAGE_SIZE);
    }
    return true;
  }

  /** Serialize only materialized pages (for snapshots / state blobs). */
  dump() {
    const out = [];
    for (const [k, p] of this.pages) out.push([k, Array.from(p)]);
    return out;
  }

  restore(dumpArr) {
    this.pages.clear();
    this.dirty.clear();
    for (const [k, arr] of dumpArr) this.pages.set(k, Uint8Array.from(arr));
  }

  clearDirty() { this.dirty.clear(); }
}

/** UNICODE_STRING writer at a fixed address (uses table offsets). */
export function writeUnicodeString(mem, usAddr, bufAddr, str, lengthField, bufferField, maxLenField) {
  const byteLen = str.length * 2;
  mem.w16(usAddr + BigInt(lengthField), byteLen);
  mem.w16(usAddr + BigInt(maxLenField ?? (lengthField + 2)), byteLen + 2);
  mem.w64(usAddr + BigInt(bufferField), bufAddr);
  mem.writeUtf16(bufAddr, str);
}

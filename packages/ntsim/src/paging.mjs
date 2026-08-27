/**
 * paging.mjs — x64 guest paging for ntsim: 4-level walker, table builder,
 * and a translating SparseMemory facade.
 *
 * Fidelity contract (Intel SDM Vol.3 ch.4):
 *   PML4E -> PDPTE -> PDE -> PTE, 4KB/2MB/1GB pages, canonical 48-bit VAs,
 *   flag bits: P(0) RW(1) US(2) PWT(3) PCD(4) A(5) D(6) PS(7) G(8) NX(63).
 *
 * Memory model:
 *   - The RAW SparseMemory is PHYSICALLY addressed when paging is enabled.
 *     Page tables live there at physical frame addresses.
 *   - `TranslatedMemory` wraps the raw store and implements the identical
 *     SparseMemory surface, translating every VA access through the Mmu
 *     (with a small TLB cache). When CR0.PG is clear it is identity.
 *   - Demand-zero mapping fills unmapped VAs with fresh RW+X supervisor
 *     frames so legacy scenarios keep running under paging; explicit
 *     mapRange() calls refine permissions (NX data, user pages, ...).
 *
 * Page faults raise CpuError whose message matches seh.classifyFault's
 * "#PF / access violation" family, so drivers' own __except handlers work.
 */

import { SparseMemory } from "./memory.mjs";
import { CpuError } from "./cpu.mjs";

const PAGE_MASK = 0xfffn;

export const PTE = {
  PRESENT: 1n << 0n,
  WRITE: 1n << 1n,
  USER: 1n << 2n,
  PWT: 1n << 3n,
  PCD: 1n << 4n,
  ACCESSED: 1n << 5n,
  DIRTY: 1n << 6n,
  PS: 1n << 7n, // PAT on PTE level
  GLOBAL: 1n << 8n,
  NX: 1n << 63n,
};

/** Canonical x64 VA check (bits 47..63 must be sign-extension). */
export function isCanonical(va) {
  const v = BigInt.asUintN(64, BigInt(va));
  const top = v >> 47n;
  return top === 0n || top === 0x1ffffn;
}

export function canonicalize(va) {
  const v = BigInt.asUintN(64, BigInt(va));
  return (v & (1n << 47n)) ? (v | 0xffff000000000000n) : (v & 0x0000ffffffffffffn);
}

/** Page fault shaped like the backend faults SEH already understands. */
export class PageFault extends CpuError {
  constructor(va, reason, access) {
    super(`page fault (${reason}) ${access} @ va=0x${BigInt.asUintN(64, va).toString(16)} — unmapped memory`, va);
    this.name = "PageFault";
    this.va = BigInt.asUintN(64, va);
    this.reason = reason; // "not present" | "write to read-only" | "supervisor-only" | "NX execute" | "non-canonical"
    this.access = access; // "read" | "write" | "fetch"
  }
}

// ------------------------------------------------------------------- Mmu

export class Mmu {
  /**
   * @param {SparseMemory} raw physically-addressed backing store
   * @param {object} [opts] {frameBase?, demandMap?:boolean}
   */
  constructor(raw, opts = {}) {
    this.raw = raw;
    this.cr0 = 0x80010031n; // PE|MP|NE|ET|WP... PG set by enablePaging()
    this.cr3 = 0n;
    this.cr4 = 0x370678n; // PAE|OSFXSR|OSXMMEXCET|...
    this.efer = 0x500n; // LME|LMA
    /** demand-zero fill for unmapped VAs (RWX supervisor) */
    this.demandMap = opts.demandMap ?? true;
    this.nextFrame = opts.frameBase ?? 0x100000n; // skip low legacy IBV
    this.framesUsed = 0;
    /** @type {{base:bigint,size:bigint}[]} VAs that map PA===VA (SMRAM/TSEG) */
    this.identityRanges = [];
    /** @type {Map<string,{pa:bigint,w:boolean,u:boolean,x:boolean}>} */
    this.tlb = new Map();
    this.tlbLimit = 4096;
    this.lastFault = null;
  }

  get pagingEnabled() {
    return (this.cr0 & 0x80000000n) !== 0n && (this.efer & 0x400n) !== 0n && (this.cr4 & 0x20n) !== 0n;
  }

  enablePaging(cr3Frame) {
    this.cr3 = BigInt(cr3Frame);
    this.cr4 |= 0x20n; // PAE
    this.cr0 |= 0x80000000n; // PG
    this.efer |= 0x500n; // LME|LMA
    this.flushTlb();
  }

  flushTlb() { this.tlb.clear(); }

  // ------------------------------------------------------------- frames

  frameAlloc(count = 1) {
    const pa = this.nextFrame;
    this.nextFrame += BigInt(count) * BigInt(PAGE_SIZE);
    this.framesUsed += count;
    return pa;
  }

  // -------------------------------------------------------------- walk

  #readTableEntry(pa, what, va) {
    const b = this.raw.read(pa, 8);
    const entry = b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
    void what; void va;
    return entry;
  }

  #writeTableEntry(pa, value) {
    const out = new Uint8Array(8);
    let v = BigInt(value);
    for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    this.raw.write(pa, out);
    this.flushTlb();
  }

  /**
   * Translate a VA. @param {"read"|"write"|"fetch"} access
   * @returns {{pa:bigint, w:boolean,u:boolean,x:boolean, level:1|2|3|4, ptePa:bigint|null}}
   * @throws {PageFault}
   */
  translate(va, access = "read") {
    const v = BigInt.asUintN(64, BigInt(va));
    if (!isCanonical(v)) {
      this.lastFault = new PageFault(v, "non-canonical", access);
      throw this.lastFault;
    }

    const key = `${v >> 12n}|${access}`;
    const hit = this.tlb.get(key);
    if (hit) {
      // cache holds the FRAME base — re-apply this access's page offset
      const offMask = hit.level === 1 ? PAGE_MASK
        : hit.level === 3 ? (1n << 30n) - 1n : (1n << 21n) - 1n;
      return { ...hit, pa: hit.paBase | (v & offMask) };
    }

    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const indexes = [
      (v >> 39n) & 0x1ffn,
      (v >> 30n) & 0x1ffn,
      (v >> 21n) & 0x1ffn,
      (v >> 12n) & 0x1ffn,
    ];

    let tablePa = pml4Base;
    let level = 4;
    let entry = 0n;
    let ptePa = null;

    for (;;) {
      const idxIdx = 4 - level;
      const entryPa = tablePa + BigInt(indexes[idxIdx]) * 8n;
      entry = this.#readTableEntry(entryPa);
      if ((entry & PTE.PRESENT) === 0n) {
        this.lastFault = new PageFault(v, "not present", access);
        throw this.lastFault;
      }
      if (level > 1 && (entry & PTE.PS) !== 0n) break; // large page here
      if (level === 1) { ptePa = entryPa; break; }     // leaf 4KB PTE
      tablePa = entry & 0x000ffffffffff000n;
      level--;
    }

    // compose physical address + effective permissions
    let paBase, offMask;
    if (level === 1) {
      paBase = entry & 0x000ffffffffff000n;
      offMask = PAGE_MASK;
    } else {
      // large page: stopped AT `level`, entry holds the frame base
      const shift = level === 3 ? 30n : 21n;
      paBase = entry & 0x000ffffffffff000n;
      offMask = (1n << shift) - 1n;
    }
    const w = (entry & PTE.WRITE) !== 0n;
    const u = (entry & PTE.USER) !== 0n;
    const x = (entry & PTE.NX) === 0n;

    const result = { pa: BigInt.asUintN(64, paBase | (v & offMask)), paBase, w, u, x, level, ptePa };
    // permission enforcement (single ring-0 subject today)
    if (access === "write" && !w) {
      this.lastFault = new PageFault(v, "write to read-only", access);
      throw this.lastFault;
    }
    if (access === "fetch" && !x) {
      this.lastFault = new PageFault(v, "NX execute", access);
      throw this.lastFault;
    }
    // SMEP: Supervisor Mode Execution Prevention (CR4 bit 20)
    // When SMEP=1 and CPL=0 (kernel mode), fetching from a user page faults
    const smep = (this.cr4 & 0x100000n) !== 0n;
    if (smep && access === "fetch" && u) {
      this.lastFault = new PageFault(v, "SMEP violation: kernel fetch from user page", access);
      throw this.lastFault;
    }

    if (this.tlb.size < this.tlbLimit) this.tlb.set(key, result);
    // set A/D bits best-effort on the leaf
    try {
      if (ptePa !== null) {
        const cur = this.#readTableEntry(ptePa);
        if ((cur & PTE.ACCESSED) === 0n) {
          this.#writeTableEntry(ptePa, cur | PTE.ACCESSED | (access === "write" ? PTE.DIRTY : 0n));
        } else if (access === "write" && (cur & PTE.DIRTY) === 0n) {
          this.#writeTableEntry(ptePa, cur | PTE.DIRTY);
        }
      }
    } catch { /* A/D bookkeeping never fatal */ }
    return result;
  }

  /**
   * Ensure [va, va+len) is mapped, demand-allocating whole pages with
   * default flags. Used by TranslatedMemory before accesses that missed.
   * VAs inside identityRanges map PA===VA (SMRAM/TSEG windows).
   */
  ensureRange(va, len, flags = { w: true, u: false, x: true }) {
    let cur = BigInt.asUintN(64, BigInt(va)) & ~PAGE_MASK;
    const end = (BigInt.asUintN(64, BigInt(va)) + BigInt(len) - 1n) & ~PAGE_MASK;
    for (; cur <= end; cur += BigInt(PAGE_SIZE)) {
      if (this.lookup(cur)) continue;
      const ident = this.#identityPaFor(cur);
      if (ident !== null) {
        this.mapPage(cur, ident, { present: true, write: flags.w ?? true, user: false, nx: !flags.x, global: false });
        if (!this.raw.hasPage(ident)) {
          this.raw.write(ident, new Uint8Array(PAGE_SIZE)); // zero-back the frame
        }
        continue;
      }
      this.mapPage(cur, this.frameAlloc(), {
        present: true, write: flags.w ?? true, user: flags.u ?? false, nx: !flags.x, global: false,
      });
    }
  }

  #identityPaFor(va) {
    const v = BigInt.asUintN(64, BigInt(va));
    for (const r of this.identityRanges) {
      if (v >= r.base && v < r.base + r.size) return v & ~PAGE_MASK;
    }
    return null;
  }

  /** Non-throwing probe: returns translation or null. */
  lookup(va) {
    try {
      const saved = this.demandMap;
      this.demandMap = false;
      try { return this.translate(va, "read"); } finally { this.demandMap = saved; }
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------- builder

  /**
   * Create a fresh page-table hierarchy rooted at a newly allocated PML4.
   * @returns {bigint} cr3 physical frame base
   */
  newAddressSpace() {
    const pml4 = this.frameAlloc();
    this.raw.write(pml4, new Uint8Array(PAGE_SIZE)); // empty = nothing mapped
    return pml4;
  }

  /**
   * Map one 4KB page. Flags: {present,write,user,nx,global}
   */
  mapPage(va, pa, flags = {}) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const idx = [
      (v >> 39n) & 0x1ffn,
      (v >> 30n) & 0x1ffn,
      (v >> 21n) & 0x1ffn,
      (v >> 12n) & 0x1ffn,
    ];
    let tablePa = pml4Base;
    for (let lvl = 4; lvl >= 2; lvl--) {
      const ePa = tablePa + BigInt(idx[4 - lvl]) * 8n;
      const e = this.#readTableEntry(ePa);
      if ((e & PTE.PRESENT) === 0n) {
        const nt = this.frameAlloc();
        this.raw.write(nt, new Uint8Array(PAGE_SIZE));
        this.#writeTableEntry(ePa, (nt & 0x000ffffffffff000n) | PTE.PRESENT | PTE.WRITE | PTE.USER);
      }
      tablePa = this.#readTableEntry(ePa) & 0x000ffffffffff000n;
    }
    let f = PTE.PRESENT | PTE.ACCESSED | PTE.DIRTY;
    if (flags.write ?? true) f |= PTE.WRITE;
    if (flags.user ?? false) f |= PTE.USER;
    if (flags.nx ?? false) f |= PTE.NX;
    if (flags.global ?? false) f |= PTE.GLOBAL;
    this.#writeTableEntry(tablePa + BigInt(idx[3]) * 8n, (BigInt(pa) & 0x000ffffffffff000n) | f);
  }

  unmap(va) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const t = this.walkToPte(v);
    if (t) this.#writeTableEntry(t, 0n);
  }

  /** Physical address of the leaf PTE slot for va, or null. */
  walkToPte(va) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const idx = [
      (v >> 39n) & 0x1ffn, (v >> 30n) & 0x1ffn, (v >> 21n) & 0x1ffn, (v >> 12n) & 0x1ffn,
    ];
    let tablePa = pml4Base;
    for (let lvl = 4; lvl >= 2; lvl--) {
      const ePa = tablePa + BigInt(idx[4 - lvl]) * 8n;
      const e = this.#readTableEntry(ePa);
      if ((e & PTE.PRESENT) === 0n) return null;
      tablePa = e & 0x000ffffffffff000n;
    }
    return tablePa + BigInt(idx[3]) * 8n;
  }

  /** Read raw PTE for va (or null). */
  readPte(va) {
    const ptePa = this.walkToPte(va);
    return ptePa === null ? null : this.#readTableEntry(ptePa);
  }

  /**
   * Identity-frame map of a VA range: allocate contiguous frames, copy
   * optional bytes in. Returns first frame pa.
   */
  allocAndMap(vaStart, pageCount, bytesIn = null, flags = {}) {
    const pa0 = this.frameAlloc(pageCount);
    for (let i = 0; i < pageCount; i++) {
      this.mapPage(BigInt(vaStart) + BigInt(i) * BigInt(PAGE_SIZE), pa0 + BigInt(i) * BigInt(PAGE_SIZE), flags);
      const off = i * PAGE_SIZE;
      if (bytesIn && off < bytesIn.length) {
        this.raw.write(pa0 + BigInt(off), bytesIn.subarray(off, Math.min(bytesIn.length, off + PAGE_SIZE)));
      }
    }
    return pa0;
  }
}

// ---------------------------------------------------- TranslatedMemory

/**
 * SparseMemory-compatible facade over the RAW store: every address-bearing
 * operation goes through the MMU when paging is enabled, else identity.
 * Subclassing keeps dump()/pages/dirty semantics working unchanged for all
 * existing consumers (cpu, kernel model, debugger, snapshots).
 */
export class TranslatedMemory extends SparseMemory {
  /** @type {Mmu|null} */
  #mmu = null;
  /** guard hook (WP5 SMRAM): (va, write) => true when access must fault */
  accessGuard = null;

  attach(mmu) {
    this.#mmu = mmu;
    mmu.flushTlb();
  }

  get mmu() { return this.#mmu; }
  get rawMem() { return this.#mmu ? this.#mmu.raw : this; }

  #xlate(addr, write) {
    const mmu = this.#mmu;
    if (this.accessGuard && this.accessGuard(BigInt(addr), write)) {
      throw new PageFault(BigInt(addr), "not present", write ? "write" : "read");
    }
    if (!mmu || !mmu.pagingEnabled) return BigInt.asUintN(64, BigInt(addr));
    try {
      return mmu.translate(BigInt(addr), write ? "write" : "read").pa;
    } catch (e) {
      if (e instanceof PageFault && mmu.demandMap && e.reason === "not present") {
        mmu.ensureRange(BigInt(addr), 1);
        return mmu.translate(BigInt(addr), write ? "write" : "read").pa;
      }
      throw e;
    }
  }

  #xlateFetch(addr) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) return BigInt.asUintN(64, BigInt(addr));
    try {
      return mmu.translate(BigInt(addr), "fetch").pa;
    } catch (e) {
      if (e instanceof PageFault && mmu.demandMap && e.reason === "not present") {
        mmu.ensureRange(BigInt(addr), 1);
        return mmu.translate(BigInt(addr), "fetch").pa;
      }
      throw e;
    }
  }

  // -- overridden span ops -------------------------------------------------

  read(addr, len) {
    const mmu = this.#mmu;
    // single source of truth: everything lands in the RAW store
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      const out = dst.read(BigInt.asUintN(64, BigInt(addr)), len);
      this.stats.reads++;
      return out;
    }
    // translate per-page so spans crossing pages each get their own PA
    const out = new Uint8Array(len);
    let done = 0;
    let a = BigInt.asUintN(64, BigInt(addr));
    while (done < len) {
      const off = Number(a & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, len - done);
      const pa = this.#xlate(a, false);
      out.set(this.rawMem.read(pa, chunk), done);
      a += BigInt(chunk); done += chunk;
    }
    this.stats.reads++;
    return out;
  }

  write(addr, bytes) {
    const src = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      dst.write(BigInt.asUintN(64, BigInt(addr)), src);
      this.stats.writes++;
      return;
    }
    let done = 0;
    let a = BigInt.asUintN(64, BigInt(addr));
    while (done < src.length) {
      const off = Number(a & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, src.length - done);
      const pa = this.#xlate(a, true);
      this.rawMem.write(pa, src.subarray(done, done + chunk));
      a += BigInt(chunk); done += chunk;
    }
    this.stats.writes++;
  }

  // fetch path used by the interpreter (execute permission enforced)
  fetchBytes(addr, len) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.read(BigInt.asUintN(64, BigInt(addr)), len);
    }
    return this.rawMem.read(this.#xlateFetch(addr), len);
  }

  hasPage(addr) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.hasPage(addr);
    }
    const t = mmu.lookup(addr);
    return !!t && this.rawMem.hasPage(t.pa);
  }

  canRead(addr, len = 1) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.canRead(addr, len);
    }
    let cur = BigInt.asUintN(64, BigInt(addr));
    const end = cur + BigInt(len);
    while (cur < end) {
      const t = mmu.lookup(cur);
      if (!t || !this.rawMem.hasPage(t.pa)) return false;
      cur = (cur & ~BigInt(PAGE_MASK)) + BigInt(PAGE_SIZE);
    }
    return true;
  }
}

// ===========================================================================
// PageTableSpace layer (feat/internals-blog-modules): table frames at LOW
// physical addresses with a configurable self-map entry, kdmp-style walker
// semantics and CR3-shuffle scanning. Independent of the Mmu/TranslatedMemory
// engine above; worlds pick the layer that matches their boot model.
// ===========================================================================

/**
 * ntsim paging model: a real x64-4-level page-table layer over SparseMemory.
 *
 * Design notes:
 * - Page-table frames live at LOW physical addresses (default base 0x300000)
 *   so worlds built on NtKernel({bases}) low-memory layouts stay under bit 47
 *   and run identically under the JsInterpreter and the Unicorn/QEMU backend
 *   (see packages/ntsim-unicorn/src/backend.mjs softmmu limitation).
 * - Every DTB installs a SELF-REFERENCING PML4 entry (index configurable,
 *   default 0xF in emulated layouts; real Windows uses 0x1ED). Through the
 *   self-map, page-table memory is readable/writable at computable VAs with
 *   plain dq/eb — exactly how Windows manages PTEs from virtual memory
 *   (coresecurity "Getting Physical", connormcgarr paging write-ups).
 * - The walker mirrors kdmp.mjs virtTranslate semantics: present-bit checks
 *   per level, PS-bit large pages (1GB at PDPT, 2MB at PD).
 * - All state is ordinary sparse pages: both CPU backends observe identical
 *   bytes; nothing here executes code, so it is backend-neutral by design.
 */

export const PAGE_SIZE = 0x1000;

/** Hardware PTE bits we model (x64 long-mode format). */
export const PTE_BIT = {
  PRESENT: 1n << 0n,
  WRITABLE: 1n << 1n,
  USER: 1n << 2n,
  WRITE_THROUGH: 1n << 3n,
  CACHE_DISABLE: 1n << 4n,
  ACCESSED: 1n << 5n,
  DIRTY: 1n << 6n,
  LARGE: 1n << 7n,
  GLOBAL: 1n << 8n,
  NX: 1n << 63n,
};

const CANON_HIGH = 0xffff000000000000n;
const CANON_LOW = 0x0000ffff00000000n;

/**
 * Split a virtual address into the 9/9/9/9/12 index fields.
 * Accepts BigInt or numeric-string input; returns Number indices + offset.
 */
export function splitVa(va) {
  const v = BigInt(va);
  return {
    offset: Number(v & 0xfffn),
    ptIndex: Number((v >> 12n) & 0x1ffn),
    pdIndex: Number((v >> 21n) & 0x1ffn),
    pdPtIndex: Number((v >> 30n) & 0x1ffn),
    pml4Index: Number((v >> 39n) & 0x1ffn),
  };
}

/**
 * Compose a VA from index fields with canonical sign-extension of bit 47.
 * joinVa(0xf,0xf,0xf,0xf,0) with high=true => 0xfffffffffffff000 style.
 */
export function joinVa(pml4Index, pdPtIndex, pdIndex, ptIndex, offset, high = true) {
  let v = (BigInt(pml4Index) << 39n) | (BigInt(pdPtIndex) << 30n) |
    (BigInt(pdIndex) << 21n) | (BigInt(ptIndex) << 12n) | (BigInt(offset) & 0xfffn);
  if (high && (v & CANON_LOW)) v |= CANON_HIGH;
  return v;
}

/** Decode a hardware PTE into named bits + frame info. */
export function decodePte(value) {
  const v = BigInt.asUintN(64, BigInt(value));
  return {
    raw: v,
    present: !!(v & PTE_BIT.PRESENT),
    writable: !!(v & PTE_BIT.WRITABLE),
    user: !!(v & PTE_BIT.USER),
    accessed: !!(v & PTE_BIT.ACCESSED),
    dirty: !!(v & PTE_BIT.DIRTY),
    large: !!((v >> 7n) & 1n),
    global: !!(v & PTE_BIT.GLOBAL),
    nx: !!(v & PTE_BIT.NX),
    pfn: v >> 12n,
    frame: (v >> 12n) << 12n,
  };
}

/** WinDbg-style letter string for the low 12 bits: "--A--KRV" ordering is
 *  C G L D A N T U W V (MS docs "!pte" table), plus explicit NX marker. */
export function pteBitsString(value) {
  const v = BigInt.asUintN(64, BigInt(value));
  const c = ["C", "G", "L", "D", "A", "N", "T", "-", "W", "V"];
  const set = [0x200n, 0x100n, 0x80n, 0x40n, 0x20n, 0x10n, 0x8n, 0n, 0x2n, 0x1n];
  let s = "";
  for (let i = 0; i < set.length; i++) {
    if (i === 7) { s += (v & 0x4n) ? "U" : "K"; continue; }
    s += (v & set[i]) ? c[i] : "-";
  }
  return s + ((v & PTE_BIT.NX) ? " NX" : " X");
}

/**
 * Self-map alias windows. Real x64 Windows materializes page-table memory
 * in virtual space through the self-referencing PML4 entry (index 0x1ED,
 * yielding the famous PTE space at 0xFFFFF68000000000 — see lesson prose).
 * Emulating that exactly would require translating EVERY memory access, so
 * ntsim exposes equivalent, computable alias WINDOWS instead: one 4K window
 * per table, addressed by its position in the tree and mirrored 1:1 onto
 * the physical frame. Index math stays a pure 9-bit exercise, and dq/eb
 * through a window touches real backing bytes.
 *
 * With selfRefIndex `s` (kept below 0x1FF; low-memory layouts keep the whole
 * range under bit 47 for unicorn parity) and reserved sentinel 0x1FF:
 *   PML4 window:            va(s, 1FF, 1FF, 1FF, 0)
 *   PDPT#a window:          va(s, a,   1FF, 1FF, 0)
 *   PD#a,b window:          va(s, a,   b,   1FF, 0)
 *   PT#a,b,c window:        va(s, a,   b,   c,   0)
 * Entry N sits at windowBase + N*8. Paths containing index 0x1FF are
 * rejected (they would fold into a parent window).
 */
export const SELF_MAP_SENTINEL = 0x1ff;

export function selfMapVas(selfRefIndex, high = false) {
  const s = BigInt(selfRefIndex);
  const T = BigInt(SELF_MAP_SENTINEL);
  const mk = (a, b, c, d) => joinVa(s, a, b, c, d, high);
  return {
    pml4Base: mk(T, T, T, 0n),
    pdptBase: (a) => mk(BigInt(a), T, T, 0n),
    pdBase: (a, b) => mk(BigInt(a), BigInt(b), T, 0n),
    ptBase: (a, b, c) => mk(BigInt(a), BigInt(b), BigInt(c), 0n),
    pml4e: (idx) => mk(T, T, T, BigInt(idx) * 8n),
    pdpte: (a, y) => mk(BigInt(a), T, T, BigInt(y) * 8n),
    pde: (a, b, z) => mk(BigInt(a), BigInt(b), T, BigInt(z) * 8n),
    pte: (a, b, c, w) => mk(BigInt(a), BigInt(b), BigInt(c), BigInt(w) * 8n),
  };
}

/**
 * A collection of per-process page tables over SparseMemory.
 * Attached to scenarios as `kernel.paging`; debugger commands (!cr3, !pte,
 * !vtop) read it when present.
 */
export class PageTableSpace {
  /**
   * @param {import("./kernel.mjs").NtKernel} kernel
   * @param {{physBase?: bigint, selfRefIndex?: number|bigint,
   *          canonicalHigh?: boolean}} opts
   */
  constructor(kernel, opts = {}) {
    this.kernel = kernel;
    this.mem = kernel.mem;
    this.nextFrame = opts.physBase ?? 0x300000n;
    this.defaultSelfRefIndex = BigInt(opts.selfRefIndex ?? 0xf);
    // Canonical half used by self-map VAs. Low-memory (unicorn-safe) worlds
    // keep false; worlds mirroring true kernel VAs may set true.
    this.canonicalHigh = opts.canonicalHigh ?? false;
    /** @type {Map<string, object>} name -> process record */
    this.processes = new Map();
    /** frames handed out (physical base addrs) — used by scans/heuristics */
    this.frames = [];
    /**
     * Structure-frame -> self-map alias page. SparseMemory is flat, so the
     * classic "PTEs live in virtual memory" identity is materialized as a
     * mirrored page: dq/eb through the alias VA touch real backing bytes,
     * and walks sync aliases back before reading physical entries.
     * @type {Map<bigint, {base: bigint}>} framePa -> alias page base
     */
    this.mirrors = new Map();
    /** scenario hook fired once a corrupted PTE is repaired correctly */
    this.onHealed = null;
  }

  /** Register a freshly allocated STRUCTURE frame together with its alias. */
  _allocStructFrame(aliasBase) {
    const f = this.allocFrame();
    const base = aliasBase & ~0xfffn;
    for (const existing of this.mirrors.values()) {
      if (existing.base === base) {
        throw new Error(
          `paging: self-map alias collision at 0x${base.toString(16)} — ` +
          `assign each process a distinct selfRefIndex`);
      }
    }
    this.mirrors.set(f, { base });
    return f;
  }

  /** Write a 64-bit table entry on BOTH the physical frame and its alias. */
  poke64(entryPa, value) {
    this.mem.w64(entryPa, value);
    const m = this.mirrors.get(entryPa & ~0xfffn);
    if (m) this.mem.w64(m.base + (entryPa & 0xfffn), value);
  }

  /** Propagate student edits made through alias VAs into physical frames. */
  _syncAliasesBack() {
    for (const [frame, m] of this.mirrors) {
      if (!this.mem.hasPage(m.base)) continue;
      const bytes = this.mem.read(m.base, 4096);
      const phys = this.mem.read(frame, 4096);
      if (bytes.some((b, i) => b !== phys[i])) this.mem.write(frame, bytes);
    }
  }

  /** Allocate one zeroed physical frame; returns its physical base. */
  allocFrame() {
    const f = this.nextFrame;
    this.nextFrame += BigInt(PAGE_SIZE);
    this.mem.write(f, new Uint8Array(PAGE_SIZE)); // zero-fill + materialize
    this.frames.push(f);
    return f;
  }

  /** Allocate the next 2MB-aligned zeroed region (large-page backing). */
  allocLarge() {
    const align = 0x200000n;
    const pa = (this.nextFrame + align - 1n) & ~(align - 1n);
    this.nextFrame = pa + BigInt(PAGE_SIZE); // only first page needs materializing
    this.mem.write(pa, new Uint8Array(PAGE_SIZE));
    this.frames.push(pa);
    return pa;
  }

  _dtbFieldOffset() {
    try {
      return this.kernel.tables.offsetOf("_KPROCESS", "DirectoryTableBase");
    } catch {
      return 0x28n;
    }
  }

  /**
   * Create page tables for a process and record them against its EPROCESS.
   * Installs the self-referencing PML4E at `selfRefIndex` (per-process
   * override enables CR3-shuffle labs).
   * @returns process record {name,pid,dtb,selfRefIndex,mapped:[]}
   */
  createProcess({ name, pid, eproc = null, selfRefIndex = null }) {
    const idx = selfRefIndex === null || selfRefIndex === undefined
      ? this.defaultSelfRefIndex
      : BigInt(selfRefIndex);
    const sm = selfMapVas(idx, this.canonicalHigh);
    const dtb = this._allocStructFrame(sm.pml4Base);
    // self-ref entry points back at the PML4 frame itself, present+writable
    // + accessed — same flag shape as the real Windows entry.
    this.poke64(dtb + idx * 8n, (((dtb >> 12n) << 12n) | 0x63n));
    const rec = {
      name,
      pid: pid ?? null,
      eproc,
      dtb,
      selfRefIndex: idx,
      mapped: [],
      decoy: false,
    };
    this.processes.set(name, rec);
    if (eproc !== null && eproc !== undefined) {
      this.mem.w64(BigInt(eproc) + this._dtbFieldOffset(), dtb);
    }
    return rec;
  }

  /**
   * Map one page (4K or 2M large) into a process's tables, materializing
   * intermediate levels on demand.
   * @param {object} proc record from createProcess()
   * @param {bigint} va virtual address to map
   * @param {{pa?: bigint, size?: 4096|0x200000, writable?: boolean,
   *          user?: boolean, nx?: boolean, present?: boolean}} opts
   */
  mapPage(proc, va, opts = {}) {
    const pml4Idx = Number((BigInt(va) >> 39n) & 0x1ffn);
    if (pml4Idx === Number(BigInt(proc.selfRefIndex))) {
      throw new Error(
        `mapPage: refusing to map inside the self-map region (PML4 index 0x${proc.selfRefIndex.toString(16)})`);
    }
    if (Number((BigInt(va) >> 21n) & 0x1ffn) === SELF_MAP_SENTINEL ||
        Number((BigInt(va) >> 30n) & 0x1ffn) === SELF_MAP_SENTINEL ||
        Number((BigInt(va) >> 12n) & 0x1ffn) === SELF_MAP_SENTINEL) {
      throw new Error("mapPage: paths containing the reserved alias-sentinel index 0x1ff are not mappable");
    }
    const size = opts.size ?? 4096;
    const pa = opts.pa !== undefined ? BigInt(opts.pa)
      : size === 0x200000 ? this.allocLarge() : this.allocFrame();
    const idx = splitVa(va);
    const dtb = proc.dtb;
    const sm = selfMapVas(proc.selfRefIndex, this.canonicalHigh);

    // alias bases for intermediate levels (per-path windows)
    const pdptAlias = sm.pdptBase(idx.pml4Index);
    const pdAlias = sm.pdBase(idx.pml4Index, idx.pdPtIndex);
    const ptAlias = sm.ptBase(idx.pml4Index, idx.pdPtIndex, idx.pdIndex);

    const pml4eAddr = dtb + BigInt(idx.pml4Index) * 8n;
    let pml4e = this.mem.u64(pml4eAddr);
    const pdptFrame = (pml4e & ~0xfffn) === 0n
      ? this._allocStructFrame(pdptAlias) : pml4e >> 12n << 12n;
    pml4e = (pdptFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n); // P+W(+U)
    this.poke64(pml4eAddr, pml4e);

    const pdpteAddr = pdptFrame + BigInt(idx.pdPtIndex) * 8n;
    let pdpte = this.mem.u64(pdpteAddr);
    const pdFrame = (pdpte & ~0xfffn) === 0n
      ? this._allocStructFrame(pdAlias) : pdpte >> 12n << 12n;
    pdpte = (pdFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n);
    this.poke64(pdpteAddr, pdpte);

    const pdeAddr = pdFrame + BigInt(idx.pdIndex) * 8n;
    let pde = this.mem.u64(pdeAddr);
    if (size === 0x200000) {
      // large page: PDE points straight at the 2MB frame, PS bit set
      const flags = 0xa3n | (opts.user ? 0x4n : 0n); // P+W+PS(+U)
      this.poke64(pdeAddr, (BigInt(pa) >> 21n) << 21n | flags);
      proc.mapped.push({ va, size, pa, pdeAddr });
      return { va, pa, level: "2M", entryAddr: pdeAddr };
    }
    const ptFrame = (pde & ~0xfffn) === 0n
      ? this._allocStructFrame(ptAlias) : pde >> 12n << 12n;
    pde = (ptFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n);
    this.poke64(pdeAddr, pde);

    const pteAddr = ptFrame + BigInt(idx.ptIndex) * 8n;
    let flags = 0x61n; // P + ACCESSED + DIRTY baseline
    if (opts.writable !== false) flags |= 0x2n;
    if (opts.user) flags |= 0x4n;
    if (opts.nx) flags |= PTE_BIT.NX;
    else flags &= ~PTE_BIT.NX;
    if (opts.present === false) flags &= ~0x1n;
    this.poke64(pteAddr, (BigInt(pa) >> 12n) << 12n | flags);
    proc.mapped.push({ va, size: 4096, pa, pteAddr });
    return { va, pa, level: "4K", entryAddr: pteAddr };
  }

  /** Physical address of the final-level entry covering `va` (PTE for 4K,
   *  PDE for 2M, PDPTE for 1G); null when the walk fails earlier.
   *  @returns {bigint|null} */
  leafEntryPa(va, dtbOrProc) {
    const w = this.translate(va, dtbOrProc);
    if (!w.ok) return null;
    return w.rows[w.rows.length - 1]?.entryPa ?? null;
  }

  /**
   * Full 4-level walk. Returns rows for every level visited so debuggers can
   * print the chain (WinDbg !pte style) and labs can grade hand-computed
   * intermediate addresses.
   * @returns {{ok:boolean, level:"4K"|"2M"|"1G"|null, pa:bigint|null,
   *            failedAt?:string, rows:Array<object>}}
   */
  translate(va, dtbOrProc) {
    this._syncAliasesBack();
    const proc = typeof dtbOrProc === "object" && dtbOrProc?.dtb !== undefined
      ? dtbOrProc
      : null;
    const dtbRaw = proc ? proc.dtb : BigInt(dtbOrProc ?? 0n);
    const dtb = dtbRaw & ~0xfffn;
    const idx = splitVa(va);
    const sm = selfMapVas(proc ? proc.selfRefIndex : this.defaultSelfRefIndex,
      this.canonicalHigh);
    const rows = [];

    const pml4ePa = dtb + BigInt(idx.pml4Index) * 8n;
    const pml4e = this.mem.u64(pml4ePa);
    rows.push({ label: "PML4E", entryPa: pml4ePa, entryVa: sm.pml4e(idx.pml4Index), value: pml4e });
    if (!(pml4e & 1n)) return { ok: false, level: null, pa: null, failedAt: "PML4E", rows };

    // PDPTE lives in the PDPT frame selected by PML4E[pml4Index]
    const pdptePa = ((pml4e >> 12n) << 12n) + BigInt(idx.pdPtIndex) * 8n;
    const pdpte = this.mem.u64(pdptePa);
    rows.push({ label: "PDPTE", entryPa: pdptePa, entryVa: sm.pdpte(idx.pml4Index, idx.pdPtIndex), value: pdpte });
    if (!(pdpte & 1n)) return { ok: false, level: null, pa: null, failedAt: "PDPTE", rows };
    if ((pdpte >> 7n) & 1n) {
      return {
        ok: true, level: "1G",
        pa: ((pdpte >> 30n) << 30n) + (va & 0x3fffffffn),
        rows,
      };
    }

    const pdBase = (pdpte >> 12n) << 12n;
    const pdePa = pdBase + BigInt(idx.pdIndex) * 8n;
    const pde = this.mem.u64(pdePa);
    rows.push({ label: "PDE", entryPa: pdePa, entryVa: sm.pde(idx.pml4Index, idx.pdPtIndex, idx.pdIndex), value: pde });
    if (!(pde & 1n)) return { ok: false, level: null, pa: null, failedAt: "PDE", rows };
    if ((pde >> 7n) & 1n) {
      return {
        ok: true, level: "2M",
        pa: ((pde >> 21n) << 21n) + (va & 0x1fffffn),
        rows,
      };
    }

    const ptBase = (pde >> 12n) << 12n;
    const ptePa = ptBase + BigInt(idx.ptIndex) * 8n;
    const pte = this.mem.u64(ptePa);
    rows.push({ label: "PTE", entryPa: ptePa, entryVa: sm.pte(idx.pml4Index, idx.pdPtIndex, idx.pdIndex, idx.ptIndex), value: pte });
    if (!(pte & 1n)) return { ok: false, level: null, pa: null, failedAt: "PTE", rows };

    return {
      ok: true,
      level: "4K",
      pa: ((pte >> 12n) << 12n) + BigInt(idx.offset),
      rows,
    };
  }

  /**
   * Scan allocated frames for a self-referencing PML4 signature — the
   * practical answer to CR3-shuffled worlds (any PML4E[i] whose PFN equals
   * the frame holding it). Returns matching DTBs sorted ascending.
   */
  scanSelfRefFrames() {
    this._syncAliasesBack();
    const hits = [];
    for (const f of this.frames) {
      for (let i = 0; i < 512; i++) {
        const e = this.mem.u64(f + BigInt(i) * 8n);
        if (e !== 0n && (e & 0x1n) && ((e >> 12n) << 12n) === f) {
          hits.push({ dtb: f, index: i, value: e });
          break;
        }
      }
    }
    return hits;
  }

  /** Look up a process record by name or PID (string or bigint). */
  findProcess(token) {
    const t = String(token).replace(/\.exe$/i, "").toLowerCase();
    if (this.processes.has(t)) return this.processes.get(t);
    for (const rec of this.processes.values()) {
      if (rec.name.toLowerCase() === t) return rec;
      if (rec.pid !== null && String(rec.pid) === t.replace(/^#/, "")) return rec;
    }
    return null;
  }
}

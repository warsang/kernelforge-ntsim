/**
 * Modeled system service dispatch table (KiServiceTable-shaped).
 *
 * The table is REAL BYTES in SparseMemory: entry i holds the u64 thunk VA
 * of service i. Hooking reuses the existing detour machinery (E9 rel32 over
 * an API thunk prologue), so scanning diffs live vs pristine prologues —
 * identical semantics under the JsInterpreter and Unicorn/QEMU backends.
 *
 * Teaching anchor: PatchGuard/HyperGuard protect this structure on real
 * systems (see Yarden Shafir's SKPG series); our labs let students both
 * commit and repair the crime in a safe sandbox.
 */

export class ServiceTable {
  /**
   * @param {import("./kernel.mjs").NtKernel} kernel
   * @param {{name?: string, base?: bigint}} opts
   */
  constructor(kernel, opts = {}) {
    this.kernel = kernel;
    this.name = opts.name ?? "KiServiceTable";
    /** @type {bigint} VA of the u64 array (real bytes in memory) */
    this.base = opts.base ?? kernel.bases.kva + 0x100000n;
    /** @type {Array<{name:string, thunk:bigint}>} */
    this.entries = [];
    this.limit = opts.limit ?? 32;
  }

  /**
   * Register a service backed by an nt!-style API thunk. Returns its index.
   * The thunk is created through kernel.defineApi so detours/pristine
   * snapshots work unchanged.
   * @param {string} apiName export name, e.g. "NtOpenProcess"
   * @param {Function} [impl] modeled implementation (defaults to traced stub)
   */
  add(apiName, impl = null) {
    if (this.entries.length >= this.limit) {
      throw new Error(`ServiceTable: limit ${this.limit} reached`);
    }
    const thunk = this.kernel.defineApi(apiName, impl ?? (() => 0n));
    const index = this.entries.length;
    this.entries.push({ name: apiName, thunk });
    // keep memory truthful: entry i = thunk VA
    this.kernel.mem.w64(this.base + BigInt(index) * 8n, thunk);
    return index;
  }

  /** Entry VA of service i inside the table image. */
  entryVa(index) {
    return this.base + BigInt(index) * 8n;
  }

  readEntry(index) {
    return this.kernel.mem.u64(this.entryVa(index));
  }

  /** True when the service's thunk carries an inline (E9) detour. */
  isHooked(index) {
    const e = this.entries[index];
    return !!e && this.kernel.isDetoured(e.name);
  }

  /** Decode an E9 rel32 at `site`; returns target VA or null. */
  static rel32Target(mem, site) {
    if (mem.u8(site) !== 0xe9) return null;
    const lo = mem.u32(site + 1n);
    const rel = BigInt.asIntN(32, BigInt(lo));
    return site + 5n + rel;
  }

  /**
   * Scan all services for inline hooks.
   * @returns {Array<{index:number, name:string, thunk:bigint, target:bigint}>}
   */
  scanHooks() {
    const out = [];
    for (let i = 0; i < this.entries.length; i++) {
      if (!this.isHooked(i)) continue;
      const thunk = this.entries[i].thunk;
      out.push({
        index: i,
        name: this.entries[i].name,
        thunk,
        target: ServiceTable.rel32Target(this.kernel.mem, thunk) ?? 0n,
      });
    }
    return out;
  }

  /** Restore pristine prologue bytes for one service (or all). */
  repair(index = null) {
    if (index === null) {
      let n = 0;
      for (let i = 0; i < this.entries.length; i++) n += this.repair(i) ? 1 : 0;
      return n;
    }
    const e = this.entries[index];
    if (!e || !this.isHooked(index)) return false;
    return this.kernel.restorePrologue(e.name);
  }
}

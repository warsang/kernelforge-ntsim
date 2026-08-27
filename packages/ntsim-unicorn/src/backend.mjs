/**
 * UnicornCpuBackend — high-fidelity CPU backend for ntsim over a WASM build of
 * the Unicorn engine (QEMU TCG). Implements the CpuBackend contract documented
 * in packages/ntsim/src/cpu.mjs; JsInterpreter remains the reference/default.
 *
 * Design notes (validated in spike, see docs/spike-unicorn.md):
 * - The upstream JS wrapper marshals 64-bit addresses through f64 ("number"),
 *   which silently corrupts values > 2^53. Every address-bearing API here goes
 *   through raw ccall with Emscripten 'i64' types instead (BigInt-safe).
 * - Registers are exposed through a Proxy so `cpu.regs.rcx = v` keeps working;
 *   only BigInt ever crosses the boundary.
 * - SparseMemory stays the source of truth: pages sync IN before execution and
 *   OUT after it. Reads of never-touched memory behave as zeros on both
 *   backends because drivers only touch mapped regions in our labs.
 * - Kernel API thunks are intercepted with range-limited UC_HOOK_CODE hooks;
 *   the handler mutates regs/RIP and stops emulation, and the outer loop
 *   resumes from the synthetic `ret` target.
 *
 * Kernel-space VAs (>= 2^63, real Windows kernel addresses) execute correctly
 * with the engine's TLB switched to UC_TLB_VIRTUAL (softmmu does a clean 1:1
 * VA mapping instead of truncating through 52-bit physical space — upstream
 * issue #2010). Hook callbacks observe architectural RIPs there.
 *
 * Guest paging ({guestPaging:true}): CR0/CR3/CR4 are programmable and QEMU
 * genuinely walks host-built page tables (EFER goes in through an emulated
 * wrmsr; spike-verified fetch/data/runs at canonical kernel VAs). CAVEAT:
 * UC_HOOK_CODE is inert while CR0.PG=1 in this build, so API-thunk
 * interception cannot work — paged ntsim sessions therefore run on
 * JsInterpreter, whose memory facade performs the same walks.
 *
 * Fallback for vendored builds whose ctl() path is unavailable: pass
 * {execAliasTruncate:true} to createUnicornBackend() — pages at or above
 * bit 52 are then mapped at their low-52-bit alias (the address executed
 * accesses resolve to when paging is off), mirroring the KUSER_SHARED_DATA
 * trick proven in speakeasy. Off by default; alias collisions throw.
 */

import { CpuError } from "@kernelforge/ntsim/src/cpu.mjs";

// Single shared wasm module instance; initialization is async and idempotent.
let modulePromise = null;
async function loadModule() {
  if (!modulePromise) {
    modulePromise = (async () => {
      // The bundle is ESM now; its emscripten glue would pick the NODE branch
      // under Node and die on require(). Hide node-ness during eval+init so
      // it always takes the browser branch (WebAssembly works everywhere).
      const procRef = globalThis.process;
      const savedVersions = procRef?.versions;
      let masked = false;
      if (typeof document === "undefined" && savedVersions) {
        Object.defineProperty(procRef, "versions", { value: {}, configurable: true });
        masked = true;
      }
      try {
        const m = await import("../vendor/unicorn_x86.mjs");
        return (m.default ?? m)();
      } finally {
        if (masked) {
          Object.defineProperty(procRef, "versions", { value: savedVersions, configurable: true });
        }
      }
    })();
  }
  return modulePromise;
}

const M64 = 0xffffffffffffffffn;
/** x86-64 guest physical address width (vendored QEMU TARGET_PHYS_ADDR_SPACE_BITS). */
const PHYS_MASK52 = (1n << 52n) - 1n;
// Low sentinel: hooks over >2^53 ranges don't fire in unicorn<=2.1 wasm
// (same softmmu limit as upstream issue #2010), so the ABI return marker
// lives at a mapped low address instead of JsInterpreter's high magic.
// must stay below 2^31: wrapper marshals hook ranges through signed i32
const RET_MARKER = 0x0badf00dn;
const CHUNK_INSTRUCTIONS = 200_000;
/** Step charge for chunks that ended on a guest-facing hook stop. */
const HOOK_STOP_STEP_COST = 256;

/** u64 <-> signed i64 helpers for the wasm ABI. */
const toI64 = (v) => BigInt.asIntN(64, BigInt(v));
const toU64 = (v) => BigInt.asUintN(64, BigInt(v));

export class UnicornCpuBackend {
  /**
   * Use createUnicornBackend(); the constructor is sync-internal.
   * @param {object} mem SparseMemory-like (read/write pages as Uint8Array ops)
   * @param {object} uc initialized unicorn module namespace
   */
  #dirty = new Set();
  /** pages that are backend-internal (ABI sentinels) — never pulled into sparse */
  #internal = new Set();
  #arenaEnd = null;
  #pendingRip = null;
  /** debugger breakpoint gate: addr -> registered hook handle */
  #debugBps = new Map();
  /** set by the bp hook when a breakpoint gate fires (rip parked on addr) */
  bpHit = null;
  /** alias base -> original base (execAliasTruncate collision detection) */
  #aliasOwner = new Map();
  /** low-52-bit truncation fallback for builds without working ctl() TLB switch */
  #execAliasTruncate = false;
  /** when true, keep QEMU's DEFAULT softmmu so guest page tables are walked */
  #guestPaging = false;
  /** host callback (va)=>void ensuring guest translation exists for internal scratch */
  guestMapHook = null;
  /** host callback (va)=>pa translating backend-internal accesses under paging */
  hostXlate = null;

  #va2pa(va) {
    if (this.#guestPaging && this.hostXlate) {
      const pa = this.hostXlate(BigInt(va));
      if (pa !== null && pa !== undefined) return BigInt(pa);
    }
    return BigInt(va);
  }

  constructor(mem, uc, opts = {}) {
    this.#execAliasTruncate = !!opts.execAliasTruncate;
    this.#guestPaging = !!opts.guestPaging;
    this.mem = mem;
    this.uc = uc;
    this.engine = new uc.Unicorn(uc.ARCH_X86, uc.MODE_64);
    this.handle = uc.getValue(this.engine.handle_ptr, "*");
    this.steps = 0;
    this.fault = null;
    this.halted = false;

    /** @type {Set<string>} page bases mapped inside unicorn (hex strings) */
    this.#mapped = new Set();
    /**
     * Flat low arena so guests can touch never-materialized memory without
     * faulting (SparseMemory reads-as-zeros semantics). Lab layouts live here;
     * real kernel VAs stay unsupported until the paging bootstrap lands.
     */
    // Full 64-bit guest VA support: unicorn's default softmmu masks physical
    // addresses to x86_64's 52-bit PA space, breaking canonical kernel-half
    // VAs when paging is off (upstream issue #2010). The VIRTUAL tlb does a
    // clean 1:1 mapping instead. MUST go through the wrapper's ctl() which
    // builds a proper va_list buffer — raw fixed-arity ccalls silently no-op.
    // Skipped under execAliasTruncate (needs physical TLB for the alias
    // space) and under guestPaging (QEMU must walk real page tables).
    if (!this.#execAliasTruncate && !this.#guestPaging) {
      const UC_CTL_TLB_TYPE = 12;
      const ctlWord = (type, nr, rw) => ((type | (nr << 26) | (rw << 30)) >>> 0);
      this.engine.ctl(ctlWord(UC_CTL_TLB_TYPE, 1, 1), [{ type: "i32", value: 1 /* UC_TLB_VIRTUAL */ }]);
    }

    const arenaSize = Number(opts?.arenaSize ?? 0x2000000);
    if (arenaSize > 0) {
      const rc = this.#rawMap(0n, BigInt(arenaSize), uc.PROT_ALL);
      if (rc === 0) {
        this.#arenaEnd = BigInt(arenaSize);
        // arena is managed wholesale: never per-page map/write it in syncIn,
        // but DO record writes inside it as dirty for pull-back.
      }
    }
    engine_hook_init(this);

    function engine_hook_init(self) {
      // dirty-page tracker: record every written page during execution.
      self.engine.hook_add(uc.HOOK_MEM_WRITE, (_h, _type, address) => {
        // page base only: syncOut pulls whole pages back into SparseMemory
        self.#dirty.add((toU64(address) & ~0xfffn).toString(16));
      }, 0, 1, 0);
    }

    this.regs = new Proxy({}, {
      get: (_t, prop) => {
        if (prop === "rip") {
          if (this.#pendingRip !== null) return this.#pendingRip;
          return toU64(this.engine.reg_read_i64(uc.X86_REG_RIP));
        }
        const id = GPR_IDS.get(prop);
        if (id === undefined) return undefined;
        return toU64(this.engine.reg_read_i64(id));
      },
      set: (_t, prop, v) => {
        if (typeof v !== "bigint") throw new TypeError("registers are BigInt-only");
        if (prop === "rip") {
          // QEMU resyncs its internal IP on emu_stop, clobbering reg writes
          // made from inside hook callbacks — remember our intent instead.
          this.#pendingRip = toU64(v);
          this.engine.reg_write_i64(uc.X86_REG_RIP, toI64(v));
          return true;
        }
        const id = GPR_IDS.get(prop);
        if (id === undefined) throw new TypeError(`unknown register ${String(prop)}`);
        this.engine.reg_write_i64(id, toI64(v));
        return true;
      },
    });
  }

  #mapped;
  /** rip lives in the proxy-friendly register file too. */
  get rip() { return this.regs.rip; }
  set rip(v) { this.regs.rip = v; }

  // ------------------------------------------------------------- raw ccalls

  /** Guard against half-initialized vendored builds surfacing as cryptic
   *  "Cannot read properties of undefined (reading 'ccall')" faults (#13). */
  #requireUc() {
    if (!this.uc || typeof this.uc.ccall !== "function") {
      throw new CpuError("unicorn: core not initialized (wasm module unavailable)", 0n);
    }
  }

  #rawMap(base, size, perms) {
    this.#requireUc();
    return this.uc.ccall("uc_mem_map", "number",
      ["pointer", "i64", "i64", "number"],
      [this.handle, toI64(base), toI64(size), perms]);
  }
  #rawWrite(addr, bytes) {
    this.#requireUc();
    const p = this.uc._malloc(bytes.length);
    this.uc.writeArrayToMemory(bytes, p);
    const r = this.uc.ccall("uc_mem_write", "number",
      ["pointer", "i64", "pointer", "i64"],
      [this.handle, toI64(addr), p, toI64(bytes.length)]);
    this.uc._free(p);
    if (r !== 0) throw new CpuError(`uc_mem_write failed (${r})`, addr);
  }
  #rawRead(addr, len) {
    this.#requireUc();
    const p = this.uc._malloc(len);
    try {
      const r = this.uc.ccall("uc_mem_read", "number",
        ["pointer", "i64", "pointer", "i64"],
        [this.handle, toI64(addr), p, toI64(len)]);
      if (r !== 0) throw new CpuError(`uc_mem_read failed (${r})`, addr);
      return this.uc.HEAPU8.slice(p, p + len);
    } finally {
      this.uc._free(p);
    }
  }
  #rawStart(begin, count) {
    return this.uc.ccall("uc_emu_start", "number",
      ["pointer", "i64", "i64", "i64", "number"],
      [this.handle, toI64(begin), 0n, 0n, count]);
  }

  // ---------------------------------------------------------- memory bridge

  PAGE = 4096;

  /**
   * Address inside unicorn's (physical) space for a guest page base.
   * Default: identity — the UC_TLB_VIRTUAL switch handles canonical VAs.
   * execAliasTruncate: fold everything at or above bit 52 down into the
   * 52-bit physical space executed accesses actually resolve to.
   */
  #ucAddrFor(base) {
    if (this.#execAliasTruncate && base >= (1n << 52n)) {
      const alias = base & PHYS_MASK52;
      const key = alias.toString(16);
      const owner = this.#aliasOwner.get(key);
      if (owner !== undefined && owner !== base) {
        throw new CpuError(
          `exec-alias collision: 0x${base.toString(16)} and 0x${owner.toString(16)} share low-52 bits`,
          base,
        );
      }
      this.#aliasOwner.set(key, base);
      return alias;
    }
    return base;
  }

  /**
   * Under guest paging, backend-internal scratch VAs (ABI return marker,
   * fallback stack) additionally need a valid GUEST translation, and their
   * VA-keyed views must be kept out of sync so translated physical frames
   * carry the truth.
   */
  #ensureGuestScratch(base) {
    if (!this.#guestPaging || !this.guestMapHook) return;
    try { this.guestMapHook(base); } catch { /* host decides fault policy */ }
    this.#internal.add(base.toString(16));
  }

  #ensurePageMapped(base) {
    base = toU64(BigInt(base)) & ~0xfffn;
    const ucBase = this.#ucAddrFor(base);
    const key = base.toString(16);
    if (!this.#mapped.has(key)) {
      if (this.#arenaEnd !== null && ucBase < this.#arenaEnd) {
        this.#mapped.add(key); // covered by the flat arena already
      } else {
        const rc = this.#rawMap(ucBase, BigInt(this.PAGE), this.uc.PROT_ALL);
        if (rc !== 0) throw new CpuError(`uc_mem_map failed (${rc}) @ ${base.toString(16)}`, base);
        this.#mapped.add(key);
      }
    }
    return base;
  }

  /** Pull every guest-visible unicorn page into SparseMemory. */
  #pullAll() {
    for (const key of this.#mapped) {
      if (this.#internal.has(key)) continue;
      const base = BigInt("0x" + key);
      this.mem.write(base, this.#rawRead(this.#ucAddrFor(base), this.PAGE));
    }
  }

  /** Push every materialized SparseMemory page into unicorn. */
  #syncIn() {
    for (const [key, page] of this.mem.pages) {
      if (this.#internal.has(key)) continue; // backend-internal VA views
      const base = BigInt("0x" + key);
      this.#ensurePageMapped(base);
      this.#rawWrite(this.#ucAddrFor(base), page);
    }
  }
  /** Pull guest-written pages (plus anything sparse tracks) into SparseMemory. */
  #syncOut() {
    for (const key of this.#dirty) {
      const base = BigInt("0x" + key);
      try {
        this.mem.write(base, this.#rawRead(this.#ucAddrFor(base), this.PAGE));
      } catch {
        // Dirtied but not resident unicorn-side (e.g. the write raced a
        // mid-run sparse mutation). SparseMemory already holds the truth.
      }
    }
    this.#dirty.clear();
  }

  /**
   * Explicitly map [base, base+size) into the unicorn address space
   * (page-wise uc_mem_map) and push any SparseMemory content in. Called by
   * NtKernel.materializeModuleRange when a module joins the `lm` list so the
   * image is readable/executable immediately instead of waiting for a run's
   * demand sync. Idempotent — already-mapped pages are skipped.
   */
  mapRange(base, size) {
    let addr = toU64(BigInt(base)) & ~0xfffn;
    const end = addr + toU64(BigInt(size));
    for (; addr < end; addr += BigInt(this.PAGE)) {
      this.#ensurePageMapped(addr);
      if (this.mem.hasPage(addr)) {
        this.#rawWrite(addr, this.mem.read(addr, this.PAGE));
      }
    }
  }

  // ----------------------------------------------------------- stack access

  #takePendingRip() {
    const v = this.#pendingRip;
    this.#pendingRip = null;
    return v;
  }

  popVal() {
    const pa = this.#va2pa(this.regs.rsp);
    const v = this.mem.u64(pa);
    this.regs.rsp = (this.regs.rsp + 8n) & M64;
    return v;
  }
  pushVal(v) {
    this.regs.rsp = (this.regs.rsp - 8n) & M64;
    this.mem.w64(this.#va2pa(this.regs.rsp), v & M64);
  }

  // ------------------------------------------------------------------ hooks

  /** Guest HLT == backend halt (mirrors JsInterpreter.halted). */
  hookHlt(rip) {
    this.engine.hook_add(this.uc.HOOK_CODE, () => {
      this.halted = true;
      this.engine.emu_stop();
    }, 0, toI64(rip), toI64(rip));
  }

  /**
   * Range-limited code hook (CpuBackend contract). Handlers return true when
   * they rewired state themselves; emulation then resumes from the new RIP.
   *
   * Uses the wrapper-managed hook path (fire → mutate state → emu_stop →
   * outer loop restarts at the rewritten RIP). Hook callbacks observe
   * architectural guest addresses even at kernel VAs (spike-verified);
   * range endpoints still marshal through f64 in the wrapper, which is why
   * callFunction keeps its return marker at a LOW sentinel address.
   * @param {(addr: bigint) => boolean|null} fn
   * @param {bigint} [begin] inclusive
   * @param {bigint} [end] inclusive
   */
  addCodeHook(fn, begin = 1n, end = 0n) {
    const engine = this.engine;
    const wrapped = (u, address) => {
      // uc holds the live state mid-run; surface it to the JS handler, then
      // push any handler writes back so the guest observes side effects.
      this.#pullAll();
      if (fn(toU64(address)) === true) {
        this.#syncIn();
        engine.emu_stop();
      }
    };
    // default open range matches JsInterpreter.addCodeHook semantics
    const b = begin === 1n && end === 0n ? 0n : toI64(begin);
    const e = begin === 1n && end === 0n ? 0n : toI64(end);
    return engine.hook_add(this.uc.HOOK_CODE, wrapped, 0, b, e);
  }

  /** Delete a previously registered hook (wrapper handle object). */
  hook_del(handle) {
    try {
      this.engine.hook_del(handle);
    } catch {
      /* already removed */
    }
  }

  // ------------------------------------------------- debugger breakpoints

  /**
   * Software-breakpoint gate (stop-before semantics; memory untouched, so no
   * SMC/TLB invalidation concerns). Mirrors JsInterpreter.debugBps: a hit
   * parks regs.rip on the address and makes run() report "breakpoint".
   */
  setDebugBp(addr) {
    const a = toU64(addr);
    if (this.#debugBps.has(a)) return;
    const handle = this.addCodeHook(() => {
      this.bpHit = a;
      return true; // stop BEFORE executing; RIP stays parked on the address
    }, a, a);
    this.#debugBps.set(a, handle);
  }

  clearDebugBp(addr) {
    const a = toU64(addr);
    const h = this.#debugBps.get(a);
    if (!h) return;
    this.#debugBps.delete(a);
    try { this.hook_del(h); } catch { /* wrapper handle absent */ }
  }

  get debugBps() { return [...this.#debugBps.keys()]; }

  reset() {
    for (const [name] of GPR_IDS) this.regs[name] = 0n;
    this.steps = 0;
    this.fault = null;
    this.halted = false;
  }

  /**
   * Late memory binding (CpuBackend contract). Only valid before execution —
   * uc-side page mappings stay put; the next sync pushes the fresh object's
   * pages over them.
   */
  attachMemory(mem) {
    this.mem = mem;
    this.#dirty.clear();
  }

  // -------------------------------------------------------------- exec loop

  /**
   * Shared execution pump. Runs until isDone() (a hook completed the mission),
   * an error, or the step budget.
   * @param {number} maxSteps
   * @param {() => boolean} isDone
   * @returns {"ok"|"fault"|"timeout"} and sets this.fault on fault
   */
  #pump(maxSteps, isDone) {
    while (!isDone() && this.steps < maxSteps && !this.fault) {
      const chunk = Math.min(CHUNK_INSTRUCTIONS, maxSteps - this.steps);
      const pending = this.#takePendingRip();
      if (pending !== null) {
        // Resuming from a guest-facing code-hook stop (API thunks, tracer,
        // breakpoints): the JS side may have mutated SparseMemory inside the
        // handler — pool allocations, IRP writes, model bookkeeping. Push
        // those pages into unicorn BEFORE execution continues, or the guest
        // reads stale/unmapped views.
        this.#syncIn();
      }
      const begin = pending ?? toU64(this.regs.rip);
      const resumedFromHook = pending !== null;
      const rc = this.#rawStart(begin, chunk);
      if (process.env.KF_DEBUG_PUMP) console.error(`[pump] iter rip=${toU64(this.regs.rip).toString(16)} rc=${rc} steps=${this.steps}`);
      // hook-stopped runs exit early: charge nothing (count is a cap, not actual)
      const stoppedByHook = rc === 0 && isDone();
      if (!stoppedByHook) {
        // A chunk that ended because ANOTHER guest-facing hook fired executed
        // an unknown (usually tiny) number of instructions — charging the
        // full 200k chunk made hook-heavy drivers (every modeled API call!)
        // blow the step budget after a few dozen calls. Natural completions
        // keep full-charge semantics for runaway-loop protection.
        this.steps += resumedFromHook ? HOOK_STOP_STEP_COST : chunk;
      }
      if (rc === 0) continue;
      // Resumable debugger breakpoints: JsInterpreter continues past
      // int3/int-2d, so Unicorn must too (engine parity).
      const resume = this.#resumePastBreak(rc);
      if (resume !== null) {
        this.regs.rip = resume;
        continue;
      }
      this.fault = this.#classify(rc);
      return this.fault ? "fault" : "ok";
    }
    return !isDone() && this.steps >= maxSteps ? "timeout" : "ok";
  }

  /**
   * On an "unhandled CPU exception", check whether RIP sits on a debugger
   * breakpoint (0xCC / 0xCD 03 / 0xCD 2D). If so, return the address AFTER
   * the instruction so the pump can resume — matching JsInterpreter, which
   * treats those as resumable pendingBreak stops. Otherwise null.
   */
  #resumePastBreak(rc) {
    if (rc !== 21 || !this.mem?.read) return null;
    const rip = toU64(this.regs.rip);
    try {
      const b = this.mem.read(rip, 2);
      if (b?.[0] === 0xcc) return rip + 1n;
      if (b?.[0] === 0xcd && (b[1] === 0x03 || b[1] === 0x2d)) return rip + 2n;
    } catch { /* unmapped — genuine fault */ }
    return null;
  }

  #classify(rc) {
    const names = {
      1: "UC_ERR_NOMEM", 2: "UC_ERR_ARCH", 3: "UC_ERR_HANDLE", 4: "UC_ERR_MODE",
      6: "read of unmapped memory", 7: "write to unmapped memory",
      8: "fetch from unmapped memory", 9: "hook error", 11: "bad mapping",
      21: "unhandled CPU exception",
    };
    const what = names[rc] ?? `unicorn error ${rc}`;
    const rip = toU64(this.regs.rip);
    return new CpuError(`${what}${this.#sniffInt(what, rip)} @ rip=0x${rip.toString(16)}`, rip);
  }

  /**
   * Unicorn reports software interrupts as a generic "unhandled CPU
   * exception" with RIP on the instruction. Sniff the opcode bytes so the
   * shared SEH classifier can tell int3/int2d breaks and int29h __fastfail
   * apart from genuine faults.
   */
  #sniffInt(what, rip) {
    if (what !== "unhandled CPU exception" || !this.mem?.read) return "";
    try {
      const b = this.mem.read(rip, 2);
      if (b?.[0] === 0xcd) {
        const vec = b[1];
        if (vec === 0x29) return " — int 0x29 fastfail (__fastfail / GS failure)";
        if (vec === 0x03 || vec === 0x2d) return ` — breakpoint (int 0x${vec.toString(16)})`;
        return ` — software interrupt 0x${vec.toString(16)}`;
      }
      if (b?.[0] === 0xcc) return " — breakpoint (int3)";
    } catch {
      /* unmapped or host-view miss — keep generic message */
    }
    return "";
  }

  /** Run until halted/budget — mirrors JsInterpreter.run() semantics. */
  run(maxSteps = 10_000_000) {
    this.#ensureDefaultStack();
    this.#syncIn();
    this.bpHit = null; // fresh run: breakpoints report per-run
    const outcome = this.#pump(maxSteps, () => this.halted || this.bpHit !== null);
    this.#syncOut();
    if (this.bpHit !== null) {
      const rip = this.bpHit;
      this.bpHit = null;
      return "breakpoint"; // regs.rip is parked ON the bp address
    }
    if (outcome === "fault") return "error";
    if (outcome === "timeout") return "timeout";
    return this.halted ? "halted" : "ok";
  }

  /**
   * Execute exactly ONE instruction (debugger single-step). The instruction
   * count cap of emu_start makes this exact; throws CpuError on fault.
   * @returns {bigint} the rip the step started at
   */
  stepInsn() {
    this.#ensureDefaultStack();
    const start = toU64(this.regs.rip);
    this.#pendingRip = null;      // fresh start: drop any stale RIP latch
    this.#syncIn();
    const rc = this.#rawStart(start, 1);
    this.#takePendingRip();       // syncIn may have re-latched; read live EIP
    this.#syncOut();
    if (rc !== 0 && rc !== undefined && rc !== null && !this.engine.emu_halted?.()) {
      this.fault = this.#classify(rc);
      throw this.fault;
    }
    this.halted = false;
    return start;
  }

  /**
   * Run until RIP reaches `stopAddr` (stop-before hook), a debugger
   * breakpoint gate fires, a fault occurs, or the budget expires.
   * Mirrors HybridCpuBackend.runUntilStop semantics.
   * @returns {"stopped"|"breakpoint"|"error"|"timeout"|"halted"}
   */
  runUntilStop(stopAddr, maxSteps = 10_000_000) {
    let stopped = false;
    const handle = this.addCodeHook(() => {
      stopped = true;
      return true; // stop BEFORE executing the stop address
    }, toU64(stopAddr), toU64(stopAddr));
    try {
      this.bpHit = null;
      this.#ensureDefaultStack();
      this.#syncIn();
      const outcome = this.#pump(maxSteps, () => this.halted || this.bpHit !== null || stopped);
      this.#syncOut();
      if (this.bpHit !== null) {
        this.bpHit = null;
        return "breakpoint";
      }
      if (stopped) return "stopped";
      if (outcome === "fault") return "error";
      if (outcome === "timeout") return "timeout";
      return this.halted ? "halted" : "timeout";
    } finally {
      try { this.hook_del(handle); } catch { /* wrapper handle absent */ }
    }
  }

  /** JsInterpreter lets the stack wrap below address 0; unicorn needs real pages. */
  #ensureDefaultStack() {
    const rsp = toU64(this.regs.rsp);
    if (rsp > 0x1000n && rsp < M64 - 0x1000n) return;
    const base = 0x70000n;
    this.#ensureGuestScratch(base);
    this.#ensurePageMapped(base);
    this.#ensurePageMapped(base + 0x1000n);
    this.regs.rsp = 0x7ff00n;
  }

  // ------------------------------------------------------ control registers

  /** Control-register surface (CpuBackend contract). Writing CR0/CR3/CR4
   *  makes QEMU update its MMU state, enabling guest-table paging. */
  #crReg(name) {
    return { cr0: this.uc.X86_REG_CR0, cr3: this.uc.X86_REG_CR3, cr4: this.uc.X86_REG_CR4, efer: this.uc.X86_REG_EFER }[name];
  }
  getCR(name) {
    const id = this.#crReg(name);
    if (id === undefined) return this.#msrMirror.get(name) ?? 0n;
    return toU64(this.engine.reg_read_i64(id));
  }
  setCR(name, value) {
    const id = this.#crReg(name);
    if (name === "efer" && id === undefined) {
      // vendored build exposes no X86_REG_EFER — program the MSR through an
      // emulated wrmsr (ECX=0xC0000080), then mirror it host-side.
      this.#msrWrite(0xc0000080n, BigInt(value));
      this.#msrMirror.set("efer", toU64(BigInt(value)));
      return;
    }
    if (id === undefined) throw new CpuError(`unsupported control register ${name}`, 0n);
    this.engine.reg_write_i64(id, toI64(value));
  }

  /**
   * In-emulation wrmsr. Runs `wrmsr` from a scratch page with ECX/EDX:EAX
   * preset; QEMU applies the MSR to live CPU state.
   */
  #msrWrite(msr, value) {
    const STUB = 0x00bad000n;
    this.#ensurePageMapped(STUB & ~0xfffn);
    // Fill both views: identity physical page (used when paging is still
    // off) and the host-translated frame (used if paging is already on).
    const stubBytes = new Uint8Array([0x0f, 0x30, 0xf4]); // wrmsr ; hlt
    const nopPage = new Uint8Array(this.PAGE).fill(0x90);
    this.#rawWrite(STUB & ~0xfffn, nopPage);
    this.#rawWrite(STUB & ~0xfffn, stubBytes);
    const xpa = this.#va2pa(STUB & ~0xfffn);
    if (xpa !== (STUB & ~0xfffn)) {
      try {
        this.#rawWrite(xpa, nopPage);
        this.#rawWrite(xpa, stubBytes);
      } catch { /* translation view unavailable yet */ }
    }
    this.engine.reg_write_i64(this.uc.X86_REG_ECX, toI64(msr));
    this.engine.reg_write_i64(this.uc.X86_REG_RAX, toI64(BigInt.asUintN(32, value)));
    this.engine.reg_write_i64(this.uc.X86_REG_RDX, toI64(BigInt.asUintN(64, value) >> 32n));
    this.engine.reg_write_i64(this.uc.X86_REG_RIP, toI64(STUB));
    const rc = this.#rawStart(STUB, 16);
    if (rc !== 0 && rc !== undefined && rc !== null) {
      // HLT-stop returns via halted flag rather than error in most builds
      if (!this.engine.emu_halted?.()) throw new CpuError(`wrmsr stub failed (${rc})`, STUB);
    }
    this.halted = false;
  }
  #msrMirror = new Map();

  /**
   * Call a function using the Windows x64 ABI — prologue byte-for-byte
   * equivalent to JsInterpreter.callFunction().
   */
  callFunction(funcAddr, args = [], shadowSpace = 32) {
    this.pausedFrame = null;
    this.#ensureDefaultStack();

    this.regs.rsp = (this.regs.rsp & ~0xfn) - 8n;
    const regsOrder = ["rcx", "rdx", "r8", "r9"];
    args.slice(0, 4).forEach((a, i) => { this.regs[regsOrder[i]] = a & M64; });
    if (args.length > 4) {
      for (let i = args.length - 1; i >= 4; i--) this.pushVal(args[i]);
    }
    for (let i = 0; i < shadowSpace; i += 8) this.pushVal(0n);
    this.pushVal(RET_MARKER);

    // native sentinel: hook fires exactly at the marker address
    let returned = false;
    const markerHook = this.addCodeHook(() => { returned = true; return true; }, RET_MARKER, RET_MARKER);
    // the marker page must be mapped/translatable for the hook to ever fire;
    // fill happens UC-side only so SparseMemory stays free of backend internals
    const markerPageBase = RET_MARKER & ~0xfffn;
    this.#ensureGuestScratch(markerPageBase);
    this.#ensurePageMapped(markerPageBase);
    this.#internal.add(markerPageBase.toString(16));
    this.#rawWrite(this.#va2pa(markerPageBase), new Uint8Array(this.PAGE).fill(0xf4));

    this.#syncIn(); // AFTER prologue so pushed frames exist inside unicorn

    // A fault left over from a previous guest call must not short-circuit
    // this one: #pump treats a set fault as an immediate stop and callFunction
    // would report a bogus "halted" for every later IRP.
    this.fault = null;

    this.rip = funcAddr & M64;
    this.bpHit = null;
    const outcome = this.#pump(10_000_000, () => returned || this.bpHit !== null);
    this.hook_del(markerHook);

    this.#syncOut();

    if (this.bpHit !== null) {
      const parkedRip = toU64(this.regs.rip);
      this.bpHit = null;
      this.pausedFrame = {
        rip: parkedRip,
        ripAfterInt3: parkedRip,
        retMarker: RET_MARKER,
      };
      return {
        status: "breakpoint",
        rip: parkedRip, // parked ON the bp address
        retMarker: RET_MARKER,
      };
    }
    if (outcome === "fault") return { status: "fault", error: this.fault };
    if (outcome === "timeout") return { status: "timeout" };
    if (!returned) return { status: "halted", rip: this.regs.rip };
    return { status: "ok", retval: this.regs.rax };
  }
}

// GPR name -> unicorn register id, resolved once per module instance.
let GPR_IDS = new Map();
const NAMES = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];
function bindRegisterIds(uc) {
  GPR_IDS = new Map(NAMES.map((n) => [n, uc[`X86_REG_${n.toUpperCase()}`]]));
}

/**
 * Async factory — wasm init + register binding.
 * @param {object} mem SparseMemory-like instance
 * @param {object} [opts] backend options ({execAliasTruncate, arenaSize})
 */
export async function createUnicornBackend(mem, opts = {}) {
  const uc = await loadModule();
  if (GPR_IDS.size === 0) bindRegisterIds(uc);
  return new UnicornCpuBackend(mem, uc, opts);
}

/** Low call-return sentinel used by callFunction (exposed for debuggers). */
export { RET_MARKER };

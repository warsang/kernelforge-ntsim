/**
 * HybridCpuBackend — JsInterpreter front end with automatic Unicorn rescue.
 *
 * Contract: identical to CpuBackend (see packages/ntsim/src/cpu.mjs). The
 * deterministic interpreter executes everything it knows; when it hits an
 * instruction it refuses (unknown opcode / bad grp forms), execution hands
 * off ONE-WAY to the Unicorn wasm engine at the exact faulting RIP with a
 * full GPR transfer. Everything after the switch runs with full x86-64 ISA
 * coverage.
 *
 * Why one-way: copying QEMU state back into the interpreter is lossy (flags,
 * partial-register latches). Forward-only handoff keeps semantics honest.
 *
 * Kernel hooks (API thunks) are registered on BOTH engines up-front so the
 * switch is invisible above the CpuBackend boundary.
 */

import { JsInterpreter, CpuError } from "@kernelforge/ntsim/src/cpu.mjs";
import { createUnicornBackend } from "./backend.mjs";

const R64 = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

const UNSUPPORTED_RE =
  /unimplemented opcode|unimplemented 0f opcode|invalid alu form|unimplemented grp/;

export class HybridCpuBackend {
  /** @type {"js"|"unicorn"} */
  active = "js";

  constructor(mem, js, uc) {
    this.js = js;
    this.uc = uc;
    // Late-binding: the analyzer builds backends with mem=null and attaches
    // the kernel's SparseMemory afterwards (NtKernel also rebinds cpu.mem).
    if (mem) this.attachMemory(mem);
    /** @type {Array<{rip:string, opcode:string}>} */
    this.handoffs = [];
  }

  /**
   * Memory lives in the child engines; the shell must forward every
   * (re)binding or JsInterpreter keeps its construction-time `null` forever.
   */
  get mem() { return this.js?.mem ?? null; }
  set mem(v) { this.attachMemory(v); }
  attachMemory(mem) {
    if (this.js) this.js.mem = mem;
    if (this.uc) this.uc.mem = mem;
  }

  static async create(mem, opts = {}) {
    return new HybridCpuBackend(
      mem,
      new JsInterpreter(mem),
      await createUnicornBackend(mem, opts),
    );
  }

  // ------------------------------------------------------------- identity

  get activeEngine() {
    return this.active === "js" ? this.js : this.uc;
  }

  /** Live proxy: reads/writes always hit the ACTIVE engine's register file. */
  get regs() {
    const self = this;
    return new Proxy({}, {
      get(_t, prop) {
        if (prop === "rip") return self.activeEngine.rip;
        return self.activeEngine.regs[prop];
      },
      set(_t, prop, v) {
        if (prop === "rip") { self.activeEngine.rip = v; return true; }
        self.activeEngine.regs[prop] = v;
        return true;
      },
      has(_t, prop) { return prop === "rip" || prop in self.activeEngine.regs; },
    });
  }

  get rip() { return this.activeEngine.rip; }
  set rip(v) { this.activeEngine.rip = v; }
  get steps() { return this.js.steps + this.uc.steps; }
  get fault() { return this.activeEngine.fault; }
  get halted() { return this.activeEngine.halted; }
  set halted(v) { this.activeEngine.halted = v; }

  /**
   * Breakpoint policy for callFunction int3 hits. Applied to BOTH engines so
   * arming before a burst survives a mid-call JS->unicorn handoff (the
   * unicorn engine ignores it today — its hit path is exception-shaped and
   * handled in the debugger layer).
   */
  get breakpointPolicy() { return this.js.breakpointPolicy; }
  set breakpointPolicy(v) {
    this.js.breakpointPolicy = v;
    if (this.uc) this.uc.breakpointPolicy = v;
  }

  // ---- debugger software breakpoints (execute-gates, memory untouched) ----

  #bpAddr(addr) {
    return BigInt.asUintN(64, BigInt(addr));
  }

  /** Arm a breakpoint gate on BOTH engines (survives JS->unicorn handoff). */
  setDebugBp(addr) {
    const a = this.#bpAddr(addr);
    this.js.debugBps.add(a);
    if (this.uc) this.uc.setDebugBp(a);
  }

  clearDebugBp(addr) {
    const a = this.#bpAddr(addr);
    this.js.debugBps.delete(a);
    if (this.uc) this.uc.clearDebugBp(a);
  }

  /** True when the given address has an armed gate on the active engine. */
  hasDebugBp(addr) {
    const a = this.#bpAddr(addr);
    if (this.active === "js") return this.js.debugBps.has(a);
    return this.uc.debugBps.some((x) => x === a);
  }

  /**
   * Execute exactly one instruction on the ACTIVE engine.
   * Returns the rip the step started at.
   */
  stepInsn() {
    if (this.active === "js") {
      const start = this.js.opcodeStart ?? this.js.rip;
      this.js.step();
      return start;
    }
    if (typeof this.uc.stepInsn === "function") return this.uc.stepInsn();
    this.uc.run(1); // legacy fallback: chunk cap == one instruction
    return null;
  }

  /**
   * Run until RIP reaches `stopAddr` (temporary, self-disarming), a
   * breakpoint/error/timeout fires, or `maxSteps` elapse.
   * @returns {"stopped"|"breakpoint"|"error"|"timeout"|"halted"}
   */
  runUntilStop(stopAddr, maxSteps = 10_000_000) {
    if (this.active === "js") {
      const saved = this.js.stopOnRip;
      this.js.stopOnRip = stopAddr;
      try {
        const reason = this.js.run(maxSteps);
        if (reason === "returned") {
          return this.js.rip === stopAddr ? "stopped" : "exited";
        }
        if (reason === "breakpoint") return "breakpoint";
        if (reason === "error") return "error";
        return reason; // halted / timeout
      } finally {
        this.js.stopOnRip = saved;
      }
    }
    // unicorn: UC_HOOK_CODE fires BEFORE the instruction executes, so a
    // true-returning hook parks RIP exactly on stopAddr (stop-before).
    let stopped = false;
    const handle = this.uc.addCodeHook(() => {
      stopped = true;
      return true;
    }, stopAddr, stopAddr);
    try {
      const reason = this.uc.run(Math.min(200_000, maxSteps));
      if (stopped && this.uc.regs.rip === stopAddr) return "stopped";
      if (reason === "error") return "error";
      if (reason === "timeout") return "timeout";
      return this.uc.halted ? "halted" : "timeout";
    } finally {
      try { this.uc.hook_del(handle); } catch { /* wrapper handle absent */ }
    }
  }

  // ----------------------------------------------------------- handoff

  #isUnsupported(error) {
    return error instanceof CpuError && UNSUPPORTED_RE.test(String(error?.message ?? ""));
  }

  #copyJsToUc() {
    // Rewind to the START of the faulting instruction: the interpreter may
    // have consumed prefixes/opcodes before refusing it.
    const startRip = this.js.opcodeStart ?? this.js.rip;
    for (const name of R64) this.uc.regs[name] = this.js.regs[name];
    // control registers ride along so a paged session stays paged in QEMU
    for (const cr of ["cr0", "cr3", "cr4", "efer"]) {
      if (this.js[cr] !== undefined) this.uc.setCR?.(cr, this.js[cr]);
    }
    this.js.rip = startRip;
    this.uc.rip = startRip;
    this.uc.halted = false;
    this.uc.fault = null;
  }

  #maybeHandoff(error) {
    if (this.active !== "js" || !this.#isUnsupported(error)) return false;
    this.#copyJsToUc();
    this.handoffs.push({
      rip: "0x" + this.js.rip.toString(16),
      opcode: String(error.message),
    });
    this.active = "uc";
    return true;
  }

  // -------------------------------------------------------------- hooks

  addCodeHook(fn, begin, end) {
    // register on BOTH engines so thunk interception survives a handoff
    this.js.addCodeHook(fn, begin, end);
    this.uc.addCodeHook(fn, begin ?? 1n, end ?? 0n);
  }

  hook_del(handle) {
    // Best-effort: forward to Unicorn backend; JsInterpreter hooks are flag-gated
    // so leaving them registered is harmless. Silently ignore missing handle.
    try { this.uc?.hook_del?.(handle); } catch { /* ignore */ }
    // For JsInterpreter, hooks are stored in codeHooks array — remove if handle is a function reference
    if (handle && typeof handle === "object" && handle.fn) {
      const idx = this.js.codeHooks.indexOf(handle);
      if (idx >= 0) this.js.codeHooks.splice(idx, 1);
    }
  }

  /** HLT parity for the unicorn side (JsInterpreter halts natively). */
  hookHlt(rip) {
    this.uc.hookHlt(rip);
  }

  // ---------------------------------------------------------- stack ops

  pushVal(v) { this.activeEngine.pushVal?.(v); }
  popVal() {
    const eng = this.activeEngine;
    if (typeof eng.popVal === "function") return eng.popVal();
    // JsInterpreter has no public popVal; emulate over shared memory
    const v = this.mem.u64(eng.regs.rsp);
    eng.regs.rsp = (eng.regs.rsp + 8n) & 0xffffffffffffffffn;
    return v;
  }

  // ------------------------------------------------------------ control

  getCR(name) {
    const eng = this.activeEngine;
    return eng.getCR ? eng.getCR(name) : eng[name];
  }
  setCR(name, v) {
    const eng = this.activeEngine;
    if (eng.setCR) eng.setCR(name, v);
    else eng[name] = v;
  }

  reset(rip) {
    this.js.reset(rip);
    this.uc.reset(rip);
    this.active = "js";
  }

  run(maxSteps = 10_000_000) {
    for (;;) {
      const budgetLeft = maxSteps - this.steps;
      const reason = this.activeEngine.run(budgetLeft > 0 ? budgetLeft : 0);
      if (reason === "error" && this.#maybeHandoff(this.activeEngine.fault)) continue;
      return reason;
    }
  }

  callFunction(funcAddr, args = [], shadowSpace = 32) {
    let r = this.activeEngine.callFunction(funcAddr, args, shadowSpace);
    if (r.status === "fault" && this.#maybeHandoff(r.error)) {
      // retry once on unicorn from the transferred state
      r = this.uc.callFunction(funcAddr, args, shadowSpace);
    }
    return r;
  }
}

export { createUnicornBackend };
export default HybridCpuBackend;

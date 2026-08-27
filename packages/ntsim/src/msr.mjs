/**
 * msr.mjs — architectural CPU state modeling for NtKernel (m25):
 * the MSR register file (LSTAR/SYSENTER_EIP/EFER), an IDT and a GDT,
 * plus the tamper scanner and syscall-probe oracle the labs use.
 *
 * Teaching anchor: on real x64 Windows these ARE PatchGuard-protected —
 * an LSTAR redirect or IDT rewrite earns CRITICAL_STRUCTURE_CORRUPTION
 * (0x109) on the next sweep, and under HVCI/VBS the write is refused
 * outright. The worlds in m25 model both regimes; the only way to keep
 * such hooks alive is to own layer two (m22/m28).
 *
 * Layouts (teaching subset):
 *   MSR file (name -> u64): IA32_LSTAR 0xC0000082, IA32_SYSENTER_EIP
 *   0x176, IA32_EFER 0xC0000081.
 *   IDT: 32 x u64 handler VAs at the KPCR's IdtBase.
 *   GDT: 8 x u64 descriptors at the KPCR's GdtBase.
 */

import { M64 } from "./cpu.mjs";

export const MSR_NAMES = {
  "0xc0000082": "IA32_LSTAR",
  "0x176": "IA32_SYSENTER_EIP",
  "0xc0000081": "IA32_EFER",
};

export const IDT_VECTOR_COUNT = 32;
export const GDT_ENTRY_COUNT = 8;

/** Install architectural state onto an NtKernel. Idempotent. */
export function installArchState(kernel, opts = {}) {
  if (kernel.msrFile) return kernel;

  const mem = kernel.mem;
  kernel.msrFile = new Map();
  kernel.msrBaseline = new Map();
  kernel.archHooks = { idt: [], gdt: [], msr: [] };

  // ---- IDT / GDT backing pages (KPCR already points here in most worlds) -
  const kpcr = kernel.bases.kva + 0x200000n;
  let idtBase = opts.idtBase ?? null;
  let gdtBase = opts.gdtBase ?? null;
  try {
    idtBase = idtBase ?? mem.u64(kpcr + kernel.tables.offsetOf("_KPCR", "IdtBase"));
    gdtBase = gdtBase ?? mem.u64(kpcr + kernel.tables.offsetOf("_KPCR", "GdtBase"));
  } catch {
    idtBase = idtBase ?? kernel.bases.kva + 0x220000n;
    gdtBase = gdtBase ?? kernel.bases.kva + 0x230000n;
  }

  // seed IDT entries with nt-range stub thunks (defineApi keeps them real)
  for (let i = 0; i < IDT_VECTOR_COUNT; i++) {
    const va = kernel.defineApi(`KiInterruptStub${i}`, () => 0n);
    mem.w64(idtBase + BigInt(i * 8), va);
  }
  for (let i = 0; i < GDT_ENTRY_COUNT; i++) {
    mem.w64(gdtBase + BigInt(i * 8), 0x00af9b000000ffffn); // plausible CS-ish descriptor
  }
  mem.ensurePage?.(idtBase);
  mem.ensurePage?.(gdtBase);

  /** Baselines for attestation. */
  const idtBaseline = [];
  for (let i = 0; i < IDT_VECTOR_COUNT; i++) {
    idtBaseline.push(mem.u64(idtBase + BigInt(i * 8)));
  }
  const gdtBaseline = [];
  for (let i = 0; i < GDT_ENTRY_COUNT; i++) {
    gdtBaseline.push(mem.u64(gdtBase + BigInt(i * 8)));
  }

  // ---- MSR register file --------------------------------------------------
  const setMsrRaw = (addr, value) => {
    kernel.msrFile.set(BigInt.asUintN(64, BigInt(addr)), BigInt(value));
  };
  const lstar = opts.lstar ?? kernel.defineApi("KiSystemCallHandler", () => 0n);
  const senter = opts.sysenterEip ?? kernel.defineApi("KiFastCallEntry", () => 0n);
  setMsrRaw(0xC0000082n, lstar);        // IA32_LSTAR
  setMsrRaw(0x176n, senter);            // IA32_SYSENTER_EIP
  setMsrRaw(0xC0000081n, 0x501n);       // IA32_EFER SCE|LMA|NXE-ish
  kernel.msrBaseline = new Map(kernel.msrFile);

  kernel.archBases = { idtBase, gdtBase, idtBaseline, gdtBaseline };

  // ---- modeled privileged writes -----------------------------------------
  /**
   * WRMSR through the model. Under the HVCI/VBS analog every write to a
   * protected MSR is refused with modeled bugcheck 0x109 (like mov cr0).
   * Under hypervisor interception (m28), the hypervisor traps via VM-exit,
   * can modify the value, and the guest never knows.
   */
  kernel.wrmsr = function wrmsr(addr, value) {
    const a = BigInt("0x" + (typeof addr === "string" ? addr.replace(/^0x/i, "") : addr.toString(16)));
    const v = BigInt.asUintN(64, BigInt(value));
    
    // Hypervisor intercept check (m28)
    const intercept = kernel.msrIntercepts.get(a);
    if (intercept) {
      const intercepted = intercept(v, true);
      kernel.vmExitLog.push({ kind: "wrmsr", msr: a, guestValue: v, hostValue: intercepted, tick: kernel.tickCount });
      kernel.dbgLog.push(`[vmexit] WRMSR 0x${a.toString(16)} intercepted: guest 0x${v.toString(16)} -> host 0x${intercepted.toString(16)}`);
      // Guest thinks write succeeded with its value; hypervisor stores intercepted value
      const old = kernel.msrFile.get(a);
      setMsrRaw(a, intercepted);
      return old;
    }
    
    if (kernel.hvciMode) {
      kernel.dbgLog.push("[hvci] WRMSR to protected MSR intercepted -> CRITICAL_STRUCTURE_CORRUPTION");
      kernel.bugcheck = { code: 0x109n, params: [4n, a, v, 0n] };
      kernel.crash = { code: "0x109" };
      kernel.cpu.halted = true;
      throw new Error("HVCI: WRMSR refused (CRITICAL_STRUCTURE_CORRUPTION)");
    }
    const old = kernel.msrFile.get(a);
    setMsrRaw(a, v);
    kernel.dbgLog.push(
      `[arch] wrmsr 0x${a.toString(16)} <- 0x${v.toString(16)} (was 0x${old?.toString(16)})`);
    return old;
  };

  kernel.rdmsr = function rdmsr(addr) {
    const a = BigInt("0x" + (typeof addr === "string" ? addr.replace(/^0x/i, "") : addr.toString(16)));
    const value = kernel.msrFile.get(a) ?? 0n;
    
    // Hypervisor intercept check (m28)
    const intercept = kernel.msrIntercepts.get(a);
    if (intercept) {
      const intercepted = intercept(value, false);
      kernel.vmExitLog.push({ kind: "rdmsr", msr: a, hostValue: value, guestValue: intercepted, tick: kernel.tickCount });
      kernel.dbgLog.push(`[vmexit] RDMSR 0x${a.toString(16)} intercepted: host 0x${value.toString(16)} -> guest 0x${intercepted.toString(16)}`);
      return intercepted;
    }
    
    return value;
  };

  // compiled-sensor shims (wdm.h maps __readmsr/__writemsr to these)
  kernel.defineApi("KfReadMsr", function (msrNum) {
    return this.rdmsr(BigInt(msrNum));
  });
  kernel.defineApi("KfWriteMsr", function (msrNum, value) {
    this.wrmsr(BigInt(msrNum), value);
    return undefined;
  });

  /** LIDT analog: rewrite one vector handler (real bytes at IdtBase). */
  kernel.setIdtHandler = (vec, va) => {
    mem.w64(idtBase + BigInt(vec * 8), BigInt(va));
  };

  // ---- attestation --------------------------------------------------------
  const moduleRange = (nameRe) => {
    for (const m of kernel.loadedModules ?? []) {
      if (!nameRe.test(m.name)) continue;
      const size = Number(m.sizeOfImage ?? m.size ?? 0);
      return { base: BigInt(m.base), size };
    }
    return null;
  };

  /**
   * Convictions across all three surfaces. MSR drift is baseline-based;
   * IDT handlers must stay inside ntoskrnl/HAL image ranges.
   */
  kernel.scanArchTamper = function scanArchTamper() {
    const out = [];
    for (const [addr, base] of kernel.msrBaseline) {
      const cur = kernel.msrFile.get(addr);
      if (cur === base) continue;
      const nm = MSR_NAMES["0x" + addr.toString(16)] ?? `MSR_0x${addr.toString(16)}`;
      out.push({ kind: "msr", name: nm, current: cur, baseline: base });
    }
    const nt = moduleRange(/^(ntoskrnl|nt)\./i) ?? moduleRange(/ntoskrnl/i);
    const hal = moduleRange(/hal\.dll/i);
    const inNtOrHal = (va) => {
      const inside = ({ base, size }) =>
        va >= base && va < base + BigInt(size);
      return (nt && inside(nt)) || (hal && inside(hal));
    };
    for (let i = 0; i < IDT_VECTOR_COUNT; i++) {
      const cur = mem.u64(idtBase + BigInt(i * 8));
      const base = idtBaseline[i];
      if (cur === base) continue;
      out.push({
        kind: "idt", name: `vector ${i}`, current: cur, baseline: base,
        foreign: !inNtOrHal(cur),
      });
    }
    for (let i = 0; i < GDT_ENTRY_COUNT; i++) {
      const cur = mem.u64(gdtBase + BigInt(i * 8));
      if (cur === gdtBaseline[i]) continue;
      out.push({ kind: "gdt", name: `gdt entry ${i}`, current: cur, baseline: gdtBaseline[i] });
    }
    return out;
  };

  /** One-line verdict used by mini-PG extraCheck. */
  kernel.archDriftLabel = function archDriftLabel() {
    const hits = kernel.scanArchTamper();
    if (!hits.length) return null;
    const h = hits[0];
    return h.kind === "msr"
      ? `${h.name} drifted from baseline`
      : `${h.name} rewritten`;
  };

  /**
   * Behavioral oracle: issue one syscall through the LIVE LSTAR target.
   * Honest path dispatches the modeled handler; a redirected LSTAR runs
   * REAL bytes at the foreign VA (rcx=syscall number, Win64-ish).
   * @returns {{honest:boolean, status:bigint, target:bigint}}
   */
  kernel.probeSyscall = function probeSyscall(num = 0x29n) {
    const target = kernel.rdmsr(0xC0000082n);
    const baseline = kernel.msrBaseline.get(0xC0000082n);
    if (target === baseline) {
      return { honest: true, status: 0n, target };
    }
    const r = kernel.cpu.callFunction(target & M64, [BigInt(num)]);
    const status = BigInt.asUintN(32, BigInt(r.retval ?? 0n));
    return { honest: false, status, target };
  };

  return kernel;
}

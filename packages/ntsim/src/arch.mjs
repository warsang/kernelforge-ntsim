/**
 * arch.mjs — architectural virtualization for anti-emulation fidelity.
 *
 * Ported from KEVLAR's environment-hardening layer: a modeled MSR file,
 * CPUID leaf tables (including the hypervisor range), a virtualized TSC with
 * busy-wait termination, KUSER_SHARED_DATA / hypervisor-shared-page refresh,
 * and port-I/O defaults (VMware backdoor ports answer 0).
 *
 * Everything here is deterministic by construction: the clock is derived from
 * the CPU step counter, jitter comes from a seeded xorshift32, and there are
 * no host APIs beyond BigInt arithmetic. Snapshot/restore works because all
 * state lives on `kernel.arch` (see ntsim-analyzer/src/snapshot.mjs).
 *
 * Install with `installArchVirtualization(kernel, opts)`; the analyzer does
 * this by default (`arch: {}`), individual labs can opt out with `arch: false`.
 */

import { M64 } from "./cpu.mjs";

/** MSR addresses referenced by the model. */
export const MSR = {
  IA32_APIC_BASE: 0x1bn,
  IA32_FEATURE_CONTROL: 0x3an,
  IA32_ARCH_CAPABILITIES: 0x10an,
  IA32_SYSENTER_CS: 0x174n,
  IA32_SYSENTER_ESP: 0x175n,
  IA32_SYSENTER_EIP: 0x176n,
  IA32_MISC_ENABLE: 0x1a0n,
  IA32_PLATFORM_ID: 0x17n,
  IA32_EFER: 0xc0000080n,
  IA32_STAR: 0xc0000081n,
  IA32_LSTAR: 0xc0000082n,
  IA32_FMASK: 0xc0000084n,
  IA32_TSC_AUX: 0xc0000103n,
  VM_CR: 0xc0010114n,
};

export const MSR_NAMES = {
  "0x1b": "IA32_APIC_BASE",
  "0x3a": "IA32_FEATURE_CONTROL",
  "0x10a": "IA32_ARCH_CAPABILITIES",
  "0x174": "IA32_SYSENTER_CS",
  "0x175": "IA32_SYSENTER_ESP",
  "0x176": "IA32_SYSENTER_EIP",
  "0x1a0": "IA32_MISC_ENABLE",
  "0xc0000080": "IA32_EFER",
  "0xc0000081": "IA32_STAR",
  "0xc0000082": "IA32_LSTAR",
  "0xc0000084": "IA32_FMASK",
  "0xc0000103": "IA32_TSC_AUX",
  "0xc0010114": "VM_CR",
};

/** 100ns units per QPC tick (Windows reports 10 MHz). */
export const QPC_FREQUENCY = 10_000_000n;
/** 1601-01-01 .. 1970-01-01 in 100ns units (FILETIME epoch offset). */
const EPOCH_DELTA_100NS = 116444736000000000n;
/** Deterministic "boot" anchor: 2026-01-01T00:00:00Z in 100ns units. */
const BOOT_ANCHOR_100NS = 133_790_000_000_000_000n;

/** KUSER_SHARED_DATA field offsets written by the refresh (x64). */
const KUSD = {
  TICK_COUNT_LOW: 0x000,
  INTERRUPT_TIME: 0x008,
  SYSTEM_TIME: 0x014,
  TIME_ZONE_BIAS: 0x020,
  NT_MAJOR_VERSION: 0x2c4,
  NT_MINOR_VERSION: 0x2c8,
  KD_DEBUGGER_ENABLED: 0x2d4,
  KD_DEBUGGER_NOT_PRESENT: 0x2d5,
  TICK_COUNT: 0x320,
  PHYS_PAGES: 0x2b8,
};

const USER_KUSD = 0x7ffe0000n;
const KERNEL_KUSD = 0xfffff78000000000n;
export const HV_SHARED_PAGE = 0xfffff78000001000n;

function leBytes(u32) {
  return Uint8Array.from([u32 & 0xff, (u32 >>> 8) & 0xff, (u32 >>> 16) & 0xff, (u32 >>> 24) & 0xff]);
}

function split32(v) {
  const b = BigInt.asUintN(64, BigInt(v));
  return { low: Number(b & 0xffffffffn), high: Number((b >> 32n) & 0xffffffffn) };
}

/** CPUID vendor string -> ebx/edx/ecx chunks (Intel order). */
function vendorChunks(s) {
  const padded = (s + "\0\0\0").slice(0, 12);
  const at = (o) => (padded.charCodeAt(o)) | (padded.charCodeAt(o + 1) << 8) |
    (padded.charCodeAt(o + 2) << 16) | (padded.charCodeAt(o + 3) << 24);
  return { ebx: BigInt(at(0) >>> 0), edx: BigInt(at(4) >>> 0), ecx: BigInt(at(8) >>> 0) };
}

const INTEL_VENDOR = { ebx: 0x756e6547n, edx: 0x49656e69n, ecx: 0x6c65746en };
const HYPERVISOR_VENDOR = vendorChunks("Kernelforge");

const INTEL_BRAND = "13th Gen Intel(R) Core(TM) i9-13900K";

function brandLeaves(brand) {
  const padded = (brand + " ".repeat(48)).slice(0, 48);
  const leaves = [];
  for (let i = 0; i < 3; i++) {
    const chunk = padded.slice(i * 16, i * 16 + 16);
    const at = (o) => (chunk.charCodeAt(o)) | (chunk.charCodeAt(o + 1) << 8) |
      (chunk.charCodeAt(o + 2) << 16) | (chunk.charCodeAt(o + 3) << 24);
    leaves.push({ eax: BigInt(at(0) >>> 0), ebx: BigInt(at(4) >>> 0), ecx: BigInt(at(8) >>> 0), edx: BigInt(at(12) >>> 0) });
  }
  return leaves;
}

/**
 * Build the deterministic CPUID model.
 * @param {{intel?: boolean, hypervisor?: boolean,
 *          features?: {leaf1Ecx?: bigint, leaf1Edx?: bigint, leaf7Ebx?: bigint,
 *                     logicalProcessors?: number, avx?: boolean}}} opts
 */
export function makeCpuid(opts = {}) {
  const logical = BigInt(opts.features?.logicalProcessors ?? 4);
  const axv = opts.features?.avx ?? false;

  // Conservative default: no AVX (the JS interpreter has no VEX decoder), no
  // VMX (bare-metal claim), RDRAND/XSAVE/OSXSAVE present, hypervisor bit set
  // only when explicitly claiming one.
  let leaf1Ecx = opts.features?.leaf1Ecx ??
    (0x7ffafbffn & ~(1n << 31n));
  if (!axv) leaf1Ecx &= ~((1n << 28n) | (1n << 29n));
  if (!opts.hypervisor) leaf1Ecx &= ~(1n << 31n);
  else leaf1Ecx |= 1n << 31n;

  let leaf1Edx = opts.features?.leaf1Edx ?? 0xbfebfbffn;
  leaf1Edx &= ~(1n << 5n); // no VMX

  const leaf1Ebx = 0x00000800n | (logical << 16n); // brand idx 0, clflush 8, logical count
  const leaf7Ebx = opts.features?.leaf7Ebx ?? 0n;
  const brand = brandLeaves(INTEL_BRAND);

  return function cpuid(leaf, subleaf) {
    const l = Number(BigInt.asUintN(32, leaf));
    const s = Number(BigInt.asUintN(32, subleaf));

    if (l === 0) return { eax: 0x16n, ...INTEL_VENDOR };
    if (l === 1) return { eax: 0x000b0671n, ebx: leaf1Ebx, ecx: leaf1Ecx, edx: leaf1Edx };
    if (l === 5) return { eax: 0x40n, ebx: 0x40n, ecx: 3n, edx: 0n }; // monitor/mwait
    if (l === 6) return { eax: 0x04n, ebx: 0n, ecx: 0n, edx: 0n };
    if (l === 7) return { eax: 0n, ebx: s === 0 ? leaf7Ebx : 0n, ecx: 0n, edx: 0n };
    if (l === 0x0b) {
      if (s === 0) return { eax: 0n, ebx: logical / 2n, ecx: 0x0100n, edx: 0n }; // SMT
      if (s === 1) return { eax: 0n, ebx: logical, ecx: 0x0201n, edx: 1n };     // core
      return { eax: 0n, ebx: 0n, ecx: 0n, edx: 0n };
    }
    if (l === 0x15) return { eax: 2n, ebx: 38_400_000n, ecx: 3_000_000_000n, edx: 0n };
    if (l === 0x16) return { eax: 3000n, ebx: 5800n, ecx: 100n, edx: 0n };
    if (l === 0x14) return { eax: 0n, ebx: 0n, ecx: 0n, edx: 0n }; // no Intel PT
    if (l >= 0x40000000 && l <= 0x4fffffff) {
      if (!opts.hypervisor) return { eax: 0n, ebx: 0n, ecx: 0n, edx: 0n };
      if (l === 0x40000000) return { eax: 0x40000001n, ...HYPERVISOR_VENDOR };
      if (l === 0x40000001) return { eax: 0x31237648n, ebx: 0n, ecx: 0n, edx: 0n }; // Hv#1
      return { eax: 0n, ebx: 0n, ecx: 0n, edx: 0n };
    }
    if (l === 0x80000000) return { eax: 0x80000008n, ebx: 0n, ecx: 0n, edx: 0n };
    if (l >= 0x80000002 && l <= 0x80000004) {
      const b = brand[l - 0x80000002];
      return { eax: b.eax, ebx: b.ebx, ecx: b.ecx, edx: b.edx };
    }
    if (l === 0x80000008) return { eax: 0x2e20n, ebx: 0n, ecx: 0n, edx: 0n }; // 46-bit phys/48 virt
    return { eax: 0n, ebx: 0n, ecx: 0n, edx: 0n };
  };
}

/** Seed the MSR file with the Kevlar-fidelity defaults (no clobber). */
function seedMsrs(file) {
  const set = (addr, v) => { if (!file.has(addr)) file.set(addr, v); };
  set(MSR.IA32_APIC_BASE, 0xfee00900n);
  set(MSR.IA32_FEATURE_CONTROL, 0x1n);         // locked, VMX disabled
  set(MSR.IA32_ARCH_CAPABILITIES, 0x1n);        // RDCL_NO
  set(MSR.IA32_MISC_ENABLE, 0x4000000001n);
  set(MSR.IA32_PLATFORM_ID, 0n);
  set(MSR.IA32_EFER, 0xd01n);
  set(MSR.IA32_STAR, 0n);
  set(MSR.IA32_FMASK, 0n);
  set(MSR.IA32_TSC_AUX, 1n);
  for (let m = 0x480n; m <= 0x48dn; m++) set(m, 0n);      // VMX capability MSRs
  set(MSR.VM_CR, 0n);                                     // SVM disabled
  set(0x560n, 0n);                                        // IA32_RTIT_CTL
  for (let m = 0x570n; m <= 0x583n; m++) set(m, 0n);      // Intel PT MSRs
  for (let m = 0xc1n; m <= 0xc4n; m++) set(m, 0n);        // perf counters
  set(0x38dn, 0n); set(0x38en, 0n); set(0x38fn, 0n);      // perf global ctl/status
  if (!file.has(0xc0000082n)) set(0xc0000082n, 0n);       // LSTAR
}

/**
 * Install architectural virtualization onto an NtKernel. Idempotent.
 * @param {object} kernel
 * @param {{intel?: boolean, hypervisor?: boolean, timing?: boolean,
 *          kusd?: boolean, hypervisorPage?: boolean, portIo?: boolean,
 *          features?: object, eventLimit?: number}} opts
 */
export function installArchVirtualization(kernel, opts = {}) {
  if (kernel.arch) return kernel;

  const state = {
    opts,
    events: [],
    eventLimit: Math.max(64, Number(opts.eventLimit ?? 4096)),
    counts: {
      cpuid: 0, rdmsr: 0, wrmsr: 0, rdtsc: 0, portRead: 0, portWrite: 0,
      kusdRefresh: 0, busyWaitJumps: 0,
    },
    cpuidLeaves: new Map(),
    msrReads: new Map(),
    msrWrites: new Map(),
    tscReads: 0,
    busyWaitJumps: 0,
    intel: !!opts.intel,
    hypervisor: !!opts.hypervisor,
    timing: opts.timing !== false,
    // virtual TSC model
    tscPerStep: 100n,
    tscBase: 0n,
    tscBias: 0n,
    lastSteps: -1n,
    streak: 0,
    lastTsc: 0n,
    prng: 0x9e3779b1,
    kusdReady: false,
    hvspReady: false,
  };
  kernel.arch = state;

  // ---- MSR file ----------------------------------------------------------
  if (!kernel.msrFile) kernel.msrFile = new Map();
  seedMsrs(kernel.msrFile);
  kernel.msrBaseline ??= new Map(kernel.msrFile);
  state.msrFile = kernel.msrFile; // shared with msr.mjs when it was installed first

  state.record = (kind, detail = {}) => {
    if (state.events.length >= state.eventLimit) state.events.shift();
    state.events.push({ kind, ...detail });
  };

  const msrName = (addr) =>
    MSR_NAMES["0x" + BigInt(addr).toString(16)] ?? `MSR_0x${BigInt(addr).toString(16)}`;

  state.rdmsr = function rdmsr(msr) {
    const a = BigInt.asUintN(64, BigInt(msr));
    state.counts.rdmsr++;
    state.msrReads.set(a, (state.msrReads.get(a) ?? 0) + 1);
    const v = kernel.msrFile.get(a) ?? 0n;
    state.record("rdmsr", { msr: a, name: msrName(a), value: v });
    return v;
  };

  state.wrmsr = function wrmsr(msr, value) {
    const a = BigInt.asUintN(64, BigInt(msr));
    let v = BigInt.asUintN(64, BigInt(value));
    let forced = null;
    // Anti-VM policy: VMX/SVM stays off no matter what the driver writes.
    if (a === MSR.IA32_FEATURE_CONTROL) { v |= 1n; forced = v; }
    if ((a >= 0x480n && a <= 0x48dn) || a === MSR.VM_CR ||
        a === 0x560n || (a >= 0x570n && a <= 0x583n)) {
      v = 0n; forced = 0n;
    }
    state.counts.wrmsr++;
    state.msrWrites.set(a, (state.msrWrites.get(a) ?? 0) + 1);
    kernel.msrFile.set(a, v);
    state.record("wrmsr", { msr: a, name: msrName(a), value: v, forced: forced !== null });
    return v;
  };

  // Bind lab-style kernel.rdmsr/wrmsr only if no other module owns them.
  if (typeof kernel.rdmsr !== "function") kernel.rdmsr = (msr) => state.rdmsr(BigInt(msr));
  if (typeof kernel.wrmsr !== "function") {
    kernel.wrmsr = (msr, value) => { state.wrmsr(BigInt(msr), BigInt(value)); };
  }

  if (!kernel.apiThunks.has("KfReadMsr")) {
    kernel.defineApi("KfReadMsr", function (msr) { return this.rdmsr(BigInt(msr)); });
  }
  if (!kernel.apiThunks.has("KfWriteMsr")) {
    kernel.defineApi("KfWriteMsr", function (msr, value) {
      this.wrmsr(BigInt(msr), BigInt(value));
      return undefined;
    });
  }

  // ---- TSC ---------------------------------------------------------------
  const nextPrng = () => {
    let x = state.prng | 0;
    x ^= x << 13; x |= 0;
    x ^= x >>> 17;
    x ^= x << 5; x |= 0;
    state.prng = x;
    return x >>> 0;
  };

  state.tscNow = function tscNow() {
    const steps = BigInt(kernel.cpu.steps ?? 0);
    const jitter = state.timing ? BigInt((nextPrng() % 31) - 15) : 0n;
    const raw = state.tscBase + steps * state.tscPerStep + state.tscBias + jitter;
    return raw & M64;
  };

  state.rdtsc = function rdtsc() {
    const steps = BigInt(kernel.cpu.steps ?? 0);
    state.counts.rdtsc++;
    state.tscReads++;
    if (state.timing && state.lastSteps >= 0n) {
      const delta = steps - state.lastSteps;
      // KEVLAR's spin detector: intervals below ~2ms emulated (here: steps)
      // count as polling. After 32 consecutive short intervals, jump the
      // clock forward with quadratic growth so multi-second deadlines fall.
      if (delta < 20000n) state.streak++;
      else state.streak = 0;
      if (state.streak >= 32) {
        const k = BigInt(state.streak - 31);
        let bonus = 5000n * k * k;
        if (bonus > 50_000_000n) bonus = 50_000_000n;
        state.tscBias += bonus;
        state.busyWaitJumps++;
        state.counts.busyWaitJumps++;
        state.record("busy-wait", { streak: state.streak, bonus: Number(bonus) });
      }
    }
    state.lastSteps = steps;
    let t = state.tscNow();
    if (t <= state.lastTsc) t = (state.lastTsc + 1n) & M64;
    state.lastTsc = t;
    return t;
  };

  // ---- CPUID -------------------------------------------------------------
  const cpuidImpl = makeCpuid({ intel: state.intel, hypervisor: state.hypervisor, features: opts.features });
  state.cpuid = function cpuid(leaf, subleaf) {
    const r = cpuidImpl(leaf, subleaf);
    state.counts.cpuid++;
    const key = BigInt.asUintN(32, BigInt(leaf));
    state.cpuidLeaves.set(key, (state.cpuidLeaves.get(key) ?? 0) + 1);
    state.record("cpuid", { leaf: key, subleaf: BigInt.asUintN(32, BigInt(subleaf)), eax: r.eax ?? 0n });
    return r;
  };

  // ---- port I/O ----------------------------------------------------------
  if (opts.portIo !== false) {
    if (!kernel.cpu.onPortRead) {
      kernel.cpu.onPortRead = (port, size) => {
        state.counts.portRead++;
        state.record("port-read", { port, size });
        // VMware backdoor magic ports: an anti-VM probe must see "nothing".
        return 0n;
      };
    }
    if (!kernel.cpu.onPortWrite) {
      kernel.cpu.onPortWrite = (port, value, size) => {
        state.counts.portWrite++;
        state.record("port-write", { port, value: BigInt(value), size });
      };
    }
  }

  // ---- KUSER_SHARED_DATA / hypervisor page --------------------------------
  const writeVa = (va, off, bytes) => {
    try {
      if (kernel.paging) {
        const pa = kernel.vtop(va);
        if (pa === null) return false;
        kernel.rawMem.write(pa + BigInt(off), bytes);
        return true;
      }
      kernel.mem.write(va + BigInt(off), bytes);
      return true;
    } catch {
      return false; // page not materializable yet (paging worlds prime lazily)
    }
  };

  const setU32 = (va, off, v) => writeVa(va, off, leBytes(Number(BigInt(v) & 0xffffffffn)));
  const setU64 = (va, off, v) => {
    const { low, high } = split32(v);
    writeVa(va, off, Uint8Array.from([...leBytes(low), ...leBytes(high)]));
  };
  const setKSYSTEMTIME = (va, off, v) => {
    const { low, high } = split32(v);
    writeVa(va, off, Uint8Array.from([...leBytes(low), ...leBytes(high), ...leBytes(high), 0, 0, 0, 0]));
  };

  const writeKusd = (off, fn) => {
    const targets = kernel.paging ? [KERNEL_KUSD] : [KERNEL_KUSD, USER_KUSD];
    for (const va of targets) fn(va, off);
  };

  state.now100ns = function now100ns() {
    return state.tscNow() / 30n; // 3 GHz TSC
  };

  state.refreshKusd = function refreshKusd() {
    if (opts.kusd === false) return;
    state.counts.kusdRefresh++;
    const elapsed = state.now100ns();
    const systemTime = BOOT_ANCHOR_100NS + elapsed;
    writeKusd(KUSD.SYSTEM_TIME, (va, off) => setKSYSTEMTIME(va, off, systemTime));
    writeKusd(KUSD.INTERRUPT_TIME, (va, off) => setKSYSTEMTIME(va, off, elapsed));
    writeKusd(KUSD.TICK_COUNT, (va, off) => setKSYSTEMTIME(va, off, (elapsed * 10n) & M64));
    writeKusd(KUSD.TICK_COUNT_LOW, (va, off) => setU32(va, off, elapsed & 0xffffffffn));
    writeKusd(KUSD.KD_DEBUGGER_ENABLED, (va, off) => writeVa(va, off, Uint8Array.from([0])));
    writeKusd(KUSD.KD_DEBUGGER_NOT_PRESENT, (va, off) => writeVa(va, off, Uint8Array.from([1])));
  };

  state.ensureKusd = function ensureKusd() {
    if (state.kusdReady || opts.kusd === false) return;
    state.kusdReady = true;
    const mem = kernel.mem;
    if (!kernel.paging) {
      // Materialize the page once (flat mode); refresh writes both aliases.
      try { mem.ensurePage?.(KERNEL_KUSD); } catch { /* facade without ensurePage */ }
      try { mem.ensurePage?.(USER_KUSD); } catch { /* facade without ensurePage */ }
    }
    kernel.kuserSharedData ??= kernel.paging ? USER_KUSD : KERNEL_KUSD;
    state.kusdBase = kernel.kuserSharedData;
    const targets = kernel.paging ? [KERNEL_KUSD] : [KERNEL_KUSD, USER_KUSD];
    for (const va of targets) {
      setU32(va, KUSD.NT_MAJOR_VERSION, 10);
      setU32(va, KUSD.NT_MINOR_VERSION, 0);
      setU32(va, KUSD.PHYS_PAGES, 0x200000); // 8 GB in 4K pages
      // debugger surface: not enabled, not present
      writeVa(va, KUSD.KD_DEBUGGER_ENABLED, Uint8Array.from([0]));
      writeVa(va, KUSD.KD_DEBUGGER_NOT_PRESENT, Uint8Array.from([1]));
    }
    state.refreshKusd();
  };

  state.ensureHvsp = function ensureHvsp() {
    if (state.hvspReady || opts.hypervisorPage === false) return;
    state.hvspReady = true;
    const write = (off, bytes) => writeVa(HV_SHARED_PAGE, off, bytes);
    write(0x00, leBytes(0));                 // lock
    setU64(HV_SHARED_PAGE, 0x08, (QPC_FREQUENCY << 32n) / QPC_FREQUENCY); // QpcMultiplier = 2^32
    setU64(HV_SHARED_PAGE, 0x10, 0n);        // QpcBias
    setU64(HV_SHARED_PAGE, 0x18, BOOT_ANCHOR_100NS); // ReferenceTime
    state.record("hvsp", { va: HV_SHARED_PAGE });
  };

  // ---- virtualized time APIs ---------------------------------------------
  const mem = () => kernel.mem;
  kernel.defineApi("KeQueryPerformanceCounter", (perfCountPtr) => {
    if (perfCountPtr) mem().w64(perfCountPtr, QPC_FREQUENCY);
    return state.now100ns();
  });
  kernel.defineApi("KeQuerySystemTime", (timePtr) => {
    const t = BOOT_ANCHOR_100NS + state.now100ns();
    if (timePtr) mem().w64(timePtr, t);
    return undefined;
  });
  kernel.defineApi("KeQuerySystemTimePrecise", (timePtr) => {
    const t = BOOT_ANCHOR_100NS + state.now100ns();
    if (timePtr) mem().w64(timePtr, t);
    return undefined;
  }, { ret: "void" });
  kernel.defineApi("KeQueryTickCount", (countPtr) => {
    if (countPtr) mem().w64(countPtr, (state.now100ns() * 10n) & M64);
    return undefined;
  }, { ret: "void" });
  kernel.defineApi("KeStallExecutionProcessor", () => undefined);

  // ---- CPU hook wiring ---------------------------------------------------
  // Note: the Unicorn backend executes these instructions natively today; the
  // hooks only bind on backends that honor them (JsInterpreter/Hybrid JS
  // phase). Reports surface cpuid/msr activity on the JS path.
  kernel.cpu.onCpuid = (leaf, subleaf) => state.cpuid(leaf, subleaf);
  kernel.cpu.onRdmsr = (msr) => state.rdmsr(BigInt(msr));
  kernel.cpu.onWrmsr = (msr, value) => { state.wrmsr(BigInt(msr), BigInt(value)); };
  kernel.cpu.onRdtsc = () => state.rdtsc();

  /** Summarize for analyzer reports (counts + hot leaves/MSRs). */
  state.summary = function summary() {
    const top = (map, n = 8) => [...map.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([k, v]) => ({ value: "0x" + BigInt(k).toString(16), count: v }));
    return {
      cpu: {
        cpuid: state.counts.cpuid,
        cpuidLeaves: top(state.cpuidLeaves),
        rdmsr: state.counts.rdmsr,
        msrReads: top(state.msrReads),
        wrmsr: state.counts.wrmsr,
        msrWrites: top(state.msrWrites),
        rdtsc: state.counts.rdtsc,
        busyWaitJumps: state.busyWaitJumps,
        portRead: state.counts.portRead,
        portWrite: state.counts.portWrite,
      },
      intelSpoof: state.intel,
      hypervisorSpoof: state.hypervisor,
      kusdRefreshes: state.counts.kusdRefresh,
      hvSharedPage: state.hvspReady ? "0x" + HV_SHARED_PAGE.toString(16) : null,
    };
  };

  return kernel;
}

/**
 * diag.mjs — analysis diagnostics: probe classification, SEH telemetry,
 * self-read watches and anti-analysis flags.
 *
 * Ported from KEVLAR's diag_center.cpp: classify the addresses a driver
 * touches (KUSER_SHARED_DATA, hypervisor shared page, candidate hyperspace,
 * system-module images, kernel structs, pool) and recognize PE-header /
 * page scans so a report can say "this driver was hunting for our mapped
 * image" instead of just "read of unmapped memory".
 *
 * Hooks are cheap and event-gated: the SparseMemory callbacks only fire on
 * page misses (or on explicitly watched pages), and the API/SEH sinks are
 * O(1) counters. Install per kernel with `installDiag(kernel, opts)`.
 */

export const KUSD_USER = 0x7ffe0000n;
export const KUSD_KERNEL = 0xfffff78000000000n;
export const HVSP_BASE = 0xfffff78000001000n;
export const HYPERSPACE_BASE = 0xfffff70000000000n;

const PAGE_MASK = 0xfffn;
const STATUS_ACCESS_DENIED = 0xc0000022n;

/**
 * Install diagnostics onto an NtKernel. Idempotent.
 * @param {object} kernel
 * @param {{eventLimit?: number, sampleLimit?: number, watchProbes?: boolean}} opts
 */
export function installDiag(kernel, opts = {}) {
  if (kernel.diag) return kernel;

  const state = {
    eventLimit: Math.max(64, Number(opts.eventLimit ?? 4096)),
    sampleLimit: Math.max(1, Number(opts.sampleLimit ?? 8)),
    events: [],
    samples: new Map(), // kind -> [{addr, rip, rva}]
    counts: {
      unmappedReads: 0, unmappedWrites: 0,
      kusd: 0, hvsp: 0, hyperspace: 0, systemModule: 0, kernelStruct: 0,
      pool: 0, pe: 0, pageScan: 0, other: 0,
      driverHeaderReads: 0, driverIatReads: 0,
      sehDispatched: 0, sehAccepted: 0, sehRejected: 0,
      accessDeniedStreak: 0, accessDeniedRun: 0,
      cpuid: 0, rdmsr: 0, wrmsr: 0, rdtsc: 0, portRead: 0, portWrite: 0,
    },
    driver: null,
    watchPages: null,
  };
  kernel.diag = state;

  const sample = (kind, addr) => {
    let arr = state.samples.get(kind);
    if (!arr) { arr = []; state.samples.set(kind, arr); }
    if (arr.length >= state.sampleLimit) return;
    const rip = BigInt(kernel.cpu.rip ?? 0n);
    const rva = state.driver && rip >= state.driver.base && rip < state.driver.base + BigInt(state.driver.size)
      ? Number(rip - state.driver.base) : null;
    arr.push({ addr: `0x${BigInt(addr).toString(16)}`, rip: `0x${rip.toString(16)}`, rva });
  };

  // Ring buffer: O(1) append even under hundreds of thousands of probe
  // events (Array.shift() at the cap made large real drivers quadratic).
  state.eventCursor = 0;
  state.record = (kind, detail = {}) => {
    if (state.events.length < state.eventLimit) {
      state.events.push({ kind, ...detail });
      return;
    }
    state.events[state.eventCursor] = { kind, ...detail };
    state.eventCursor = (state.eventCursor + 1) % state.eventLimit;
  };
  /** Chronological view of the ring (oldest first). */
  state.orderedEvents = () => {
    if (!state.eventCursor) return state.events;
    return [...state.events.slice(state.eventCursor), ...state.events.slice(0, state.eventCursor)];
  };

  const inRange = (a, base, size) => a >= base && a < base + BigInt(size);

  /** Classify one memory access that reached an unmapped page. */
  state.classify = function classify(addr, size, op) {
    const a = BigInt(addr);
    if (op === "read") state.counts.unmappedReads++;
    else state.counts.unmappedWrites++;
    const rip = BigInt(kernel.cpu.rip ?? 0n);
    const inDriver = !!state.driver && rip >= state.driver.base &&
      rip < state.driver.base + BigInt(state.driver.size);
    // Keep the ring useful: record every driver miss, and only a 1/64 sample
    // of kernel-model traffic (memory model reads dominate huge drivers).
    state.probeSeq = (state.probeSeq ?? 0) + 1;
    if (inDriver || state.probeSeq % 64 === 0) {
      state.record("probe", { addr: a, size, op, rip, inDriver });
    }
    if (!inDriver) return; // kernel-model traffic is not driver behavior

    let kind = null;
    if ((a >= KUSD_USER && a < KUSD_USER + 0x1000n) ||
        (a >= KUSD_KERNEL && a < KUSD_KERNEL + 0x1000n)) kind = "kusd";
    else if (a >= HVSP_BASE && a < HVSP_BASE + 0x1000n) kind = "hvsp";
    else if (a >= HYPERSPACE_BASE && a < HYPERSPACE_BASE + 0x100000n) kind = "hyperspace";
    else {
      for (const m of kernel.loadedDrivers ?? []) {
        const base = BigInt(m.base ?? 0n);
        const size = Number(m.imageSize ?? m.size ?? 0x1000);
        if (base > 0n && inRange(a, base, size)) { kind = "systemModule"; break; }
      }
      if (!kind) {
        const b = kernel.bases;
        if (inRange(a, b.kva, 0x1000000) || inRange(a, b.eproc, 0x1000000) ||
            inRange(a, b.kthrd, 0x1000000)) kind = "kernelStruct";
        else if (inRange(a, b.pool, 0x100000000)) kind = "pool";
      }
      if (!kind) {
        const off = Number(a & PAGE_MASK);
        // PE-header scan heuristic (KEVLAR ComputePeProbeHint): MZ at page
        // start, e_lfanew at +0x3C, DOS stub probes at +0x40/+0x80.
        if (off === 0 && size <= 1) {
          kind = "pageScan";
        } else if (off <= 1 || (off >= 0x3c && off <= 0x40) || off === 0x80) {
          kind = "pe";
        }
      }
    }
    if (!kind) kind = "other";
    state.counts[kind] = (state.counts[kind] ?? 0) + 1;
    sample(kind, a);
    const rva = state.driver && inDriver ? Number(rip - state.driver.base) : null;
    state.record("probe-" + kind, { addr: a, size, rip, rva });
  };

  /** Watch the driver's header/IAT pages for self-integrity reads. */
  state.watchDriver = function watchDriver(base, size, extraRanges = []) {
    state.driver = { base: BigInt(base), size: Number(size) };
    const pages = new Map();
    pages.set((BigInt(base) & ~PAGE_MASK).toString(16), "driverHeaderReads");
    for (const r of extraRanges) {
      const rb = BigInt(r.base);
      const rend = rb + BigInt(r.size ?? 0);
      for (let p = rb & ~PAGE_MASK; p < rend; p += 0x1000n) {
        pages.set(p.toString(16), r.kind ?? "driverIatReads");
      }
    }
    state.watchPages = pages;
    // Hand the page map to SparseMemory. The interpreter reads pages
    // directly, so this is the only interception point that catches `mov`.
    kernel.rawMem.watchPages = pages;
    kernel.rawMem.onWatchRead = (kind, addr, chunk) => {
      state.counts[kind] = (state.counts[kind] ?? 0) + 1;
      state.record(kind, { addr: BigInt(addr), size: chunk });
    };
    return state;
  };

  // ---- SEH telemetry (called from NtKernel.callFunctionSeh) --------------
  state.onSeh = function onSeh(detail, handled) {
    state.counts.sehDispatched++;
    if (handled) state.counts.sehAccepted++;
    else state.counts.sehRejected++;
    state.record("seh", { handled, detail: String(detail ?? "").slice(0, 200) });
  };

  // ---- API-return telemetry (ACCESS_DENIED loops) ------------------------
  state.onApi = function onApi(name, ret) {
    if (/^(Zw|Nt)/.test(name) && ret === STATUS_ACCESS_DENIED) {
      state.counts.accessDeniedRun++;
      state.counts.accessDeniedStreak = Math.max(state.counts.accessDeniedStreak, state.counts.accessDeniedRun);
    } else {
      state.counts.accessDeniedRun = 0;
    }
  };

  // ---- memory hooks ------------------------------------------------------
  const raw = kernel.rawMem;
  if (opts.watchProbes !== false) {
    raw.onUnmappedRead = (addr, size) => state.classify(addr, size, "read");
    raw.onUnmappedWrite = (addr, size) => state.classify(addr, size, "write");
  }

  state.summary = function summary() {
    const arch = kernel.arch;
    const sysq = kernel.sysQuery;
    const picks = (map, n = 4) =>
      Object.fromEntries([...map.entries()].slice(0, n).map(([k, v]) => [k, v]));
    const probeSamples = {};
    for (const [kind, arr] of state.samples.entries()) probeSamples[kind] = arr;
    return {
      unmapped: { reads: state.counts.unmappedReads, writes: state.counts.unmappedWrites },
      probes: {
        kusd: state.counts.kusd,
        hvsp: state.counts.hvsp,
        hyperspace: state.counts.hyperspace,
        systemModule: state.counts.systemModule,
        kernelStruct: state.counts.kernelStruct,
        pool: state.counts.pool,
        peHeaderScan: state.counts.pe,
        pageScan: state.counts.pageScan,
        other: state.counts.other,
        samples: probeSamples,
      },
      selfReads: {
        header: state.counts.driverHeaderReads,
        iat: state.counts.driverIatReads,
      },
      seh: {
        dispatched: state.counts.sehDispatched,
        accepted: state.counts.sehAccepted,
        rejected: state.counts.sehRejected,
      },
      api: {
        accessDeniedStreak: state.counts.accessDeniedStreak,
        stuckAccessDenied: state.counts.accessDeniedStreak >= 5,
      },
      cpu: arch ? {
        cpuid: arch.counts.cpuid, rdmsr: arch.counts.rdmsr, wrmsr: arch.counts.wrmsr,
        rdtsc: arch.counts.rdtsc, busyWaitJumps: arch.counts.busyWaitJumps,
        portRead: arch.counts.portRead, portWrite: arch.counts.portWrite,
      } : {
        cpuid: state.counts.cpuid, rdmsr: state.counts.rdmsr, wrmsr: state.counts.wrmsr,
        rdtsc: state.counts.rdtsc, busyWaitJumps: 0,
        portRead: state.counts.portRead, portWrite: state.counts.portWrite,
      },
      systemQueries: sysq ? sysq.summary().queries : {},
      flags: {
        timingChecks: (arch?.counts.rdtsc ?? 0) > 0,
        moduleEnumeration: sysq ? sysq.summary().queries["0xb"] !== undefined ||
          sysq.summary().queries["0x4d"] !== undefined : false,
        peHeaderScan: state.counts.pe > 0,
        msrAccess: (arch?.counts.rdmsr ?? 0) + (arch?.counts.wrmsr ?? 0) > 0,
        hypervisorProbe: state.counts.hvsp > 0,
        selfIntegrityReads: state.counts.driverHeaderReads + state.counts.driverIatReads > 0,
        stuckAccessDenied: state.counts.accessDeniedStreak >= 5,
      },
      timeline: state.orderedEvents().slice(-128).map((e) => Object.fromEntries(
        Object.entries(e).map(([k, v]) => [k, typeof v === "bigint" ? `0x${v.toString(16)}` : v]),
      )),
    };
  };

  return kernel;
}

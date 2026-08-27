/**
 * ntsim kernel model: emulated x64 Windows kernel over SparseMemory + pluggable CPU.
 *
 * Realism rules:
 * - Every struct access goes through Vergilius tables for the active build.
 * - Process list is genuine _EPROCESS chain walkable by student drivers.
 * - Kernel APIs are hooked at fixed thunk addresses; student imports resolve there.
 */

import { SparseMemory } from "./memory.mjs";
import { StructTables, StructRef } from "./structs.mjs";
import { JsInterpreter, M64 } from "./cpu.mjs";
import { installWinApi } from "./winapi.mjs";
import { installNotifyEngine } from "./notify.mjs";
import { SymbolEngine } from "./symbols.mjs";
import { tryDispatchException } from "./seh.mjs";
import { Mmu, TranslatedMemory } from "./paging.mjs";
import { API_META } from "./winapi-meta.mjs";

const DEFAULT_BASES = {
  kva: 0xfffff80000000000n,
  pool: 0xfffff90000000000n, // synthetic "NonPaged" pool region
  thunk: 0xfffff80100000000n, // kernel API thunks
  eproc: 0xffffb80000000000n, // synthesized EPROCESS blocks
  driver: 0xfffff80200000000n, // DRIVER_OBJECT / analyzer scratch
};

/** Offset between the eproc base and the synthesized KTHREAD region. Chosen
 *  well past any lab carve window over the EPROCESS array, and kept under
 *  bit 47 when eproc uses a low base (blog-lab worlds). */
const KTHRD_REGION_STRIDE = 0x4000000n;

/** Cross-process handle references seeded at boot (owner -> victim pairs).
 *  These make the classic EDR cross-check real: hide a process via DKOM and
 *  its open handles are still enumerated by other processes' handle tables. */
const SEED_HANDLE_REFS = [
  { owner: "services.exe", target: "lsass.exe", access: 0x1fffff },
  { owner: "winlogon.exe", target: "lsass.exe", access: 0x1fffff },
  { owner: "kfsample.exe", target: "kftarget.exe", access: 0x143a }, // VM_READ|VM_WRITE|VM_OPERATION-ish
];

/** Software-visible IRQL names (x64). Levels >= 3 are device/clock/IPI/high;
 *  precise sub-naming varies by platform so we label the band generically. */
export const IRQL_NAMES = {
  0: "PASSIVE_LEVEL",
  1: "APC_LEVEL",
  2: "DISPATCH_LEVEL",
};

export function irqlName(level) {
  return IRQL_NAMES[level] ?? (level > 2 ? "DEVICE_OR_HIGHER" : "?");
}

const POOL_MAGIC = 0x4b46454c52505352n; // 'RSPLRFEK'-ish sentinel (LE)
const POOL_GUARD_BYTE = 0xa5;
const POOL_GUARD_LEN = 16;

const DEFAULT_PROCESSES = [
  { pid: 4, name: "System", ppl: null },
  { pid: 84, name: "wininit.exe", ppl: null },
  { pid: 96, name: "services.exe", ppl: null },
  { pid: 108, name: "lsass.exe", ppl: { type: "Light", signer: "WinTcb" } }, // PPL!
  { pid: 116, name: "winlogon.exe", ppl: null },
  // kfsample used to be 312 — that Cid collides with an authentic svchost.exe
  // in the dump-overlay worlds (!process must never list one Cid twice), so
  // both worlds agree on 1312. kftarget moved off the taught-but-invalid 666
  // (Windows Cids are always multiples of 4) onto 888 — free in every world.
  { pid: 1312, name: "kfsample.exe", ppl: null },
  { pid: 888, name: "kftarget.exe", ppl: null },
];

export class NtKernel {
  /**
   * @param {{tables?: object, tablesDir?: string, buildName?: string,
   *          cpu?: import("./cpu.mjs").CpuBackend,
   *          bases?: {kva?: bigint, pool?: bigint, thunk?: bigint, eproc?: bigint}}} opts
   *   `cpu`: inject a pre-built backend (e.g. UnicornCpuBackend bound to the
   *   same SparseMemory). Defaults to the deterministic JsInterpreter.
   *   `bases`: override synthetic VA regions (tests use low-memory layouts;
   *   defaults mirror real Windows kernel VAs).
   */
  constructor(opts = {}) {
    // Adopt the injected backend's memory so guest, kernel model, and CPU
    // all share ONE address space (JsInterpreter default binds its own).
    const raw = opts.cpu?.mem ?? new SparseMemory();
    this.rawMem = raw;
    this.cpu = opts.cpu;

    // Guest paging: the raw store becomes physically addressed, and the
    // kernel-facing `mem` is a translating facade. Only the JS interpreter
    // executes through translation today; injected backends keep raw memory
    // and must program their own CRs (see backend contract).
    this.paging = !!opts.paging && !opts.cpu;
    if (this.paging) {
      const tm = new TranslatedMemory();
      this.mmu = new Mmu(raw, { demandMap: opts.demandMap ?? true, frameBase: opts.frameBase });
      tm.attach(this.mmu);
      this.mem = tm;
      this.cr3 = this.mmu.newAddressSpace();
      this.mmu.enablePaging(this.cr3);
    } else {
      this.mmu = null;
      this.mem = raw;
    }

    this.tables = opts.tables ?? new StructTables();
    if (!this.cpu) this.cpu = new JsInterpreter(this.mem);
    this.cpu.mem = opts.cpu ? raw : this.mem;
    // Unified register surface: expose `rip` on backends whose regfile lacks
    // it (JsInterpreter tracks RIP separately from the GPR dict).
    if (this.cpu.regs && !("rip" in this.cpu.regs)) {
      const cpuRef = this.cpu;
      Object.defineProperty(cpuRef.regs, "rip", {
        get() { return cpuRef.rip ?? 0n; },
        set(v) { cpuRef.rip = BigInt.asUintN(64, BigInt(v)); },
        configurable: true,
      });
    }
    const B = opts.bases ?? {};
    /** @type {typeof DEFAULT_BASES & {kthrd: bigint}} */
    this.bases = {
      kva: B.kva ?? DEFAULT_BASES.kva,
      pool: B.pool ?? DEFAULT_BASES.pool,
      thunk: B.thunk ?? DEFAULT_BASES.thunk,
      eproc: B.eproc ?? DEFAULT_BASES.eproc,
      driver: B.driver ?? DEFAULT_BASES.driver,
      kthrd: B.kthrd ?? ((B.eproc ?? DEFAULT_BASES.eproc) + KTHRD_REGION_STRIDE),
    };
    this.buildName = opts.buildName ?? "synthetic-22h2";

    if (this.paging) {
      // Reserve the API-thunk arena up front: defineApi stamps an hlt marker
      // per export, and lazy demand-mapping would tie the physical frame
      // layout to the number of defined exports — shifting PA-anchored lab
      // constants (e.g. KUSER_SHARED_DATA) whenever new APIs are added.
      this.mmu.ensureRange(this.bases.thunk, 0x10000);
    }

    /** @type {Map<string, bigint>} export name -> thunk VA */
    this.apiThunks = new Map();
    this.nextThunk = this.bases.thunk;
    /** @type {Map<string, Function>} export name -> js impl */
    this.apiImpls = new Map();
    /** @type {Map<string, {ret:string}>} export name -> signature meta */
    this.apiMeta = new Map();
    /** @type {Map<string, Uint8Array>} export name -> pristine prologue bytes */
    this.pristineThunks = new Map();
    /** @type {Array<{api:string, thunk:bigint, target:bigint, module:string}>} */
    this.inlineHooks = [];

    // analyzer state -----------------------------------------------------
    /** @type {Array<{name:string,args:bigint[],ret:bigint,retAddr:bigint}>} */
    this.apiTrace = [];
    this.apiTraceLimit = 8192;
    /** exports auto-provisioned as traced stubs (run-any-*.sys mode) */
    this.unmodeledExports = [];
    /** IRQL violations (Zw or Nt exports called above APC_LEVEL) */
    this.irqlViolations = [];
    /** exception dispatch log */
    this.exceptionTrace = [];
    /** queued DPCs / work items / APCs awaiting drainDpcs() */
    this.pendingDpcs = [];
    this.pendingWorkItems = [];
    this.pendingApcs = [];
    /** queued PsCreateSystemThread start routines awaiting drainDeferred() */
    this.pendingThreads = [];
    /** modeled data exports (PsProcessType & co): name -> slot VA holding ptr */
    this.dataExports = new Map();

    // module-2 extension state (IRQL/DPC attack & defense labs) ------------
    /** modeled KTIMERs: {timerVa, dueTick, period, dpcVa}; fired by
     *  advanceTicks()/fireDueTimers() — the lab's explicit clock */
    this.pendingTimers = [];
    /** directed-DPC targeting: KDPC va -> processor number (KeSetTargetProcessorDpc) */
    this.dpcTargetCpu = new Map();
    /** per-CPU IRQL side-state for cores 1..N-1 (core 0 aliases currentIrql) */
    this.cpuIrqls = [0, 0, 0];
    /** control-register model: WP = bit 16; written via KfWriteCr0 thunks */
    this.cr0 = 0x80010031n;
    /** CR0 write history: {tick, old, new} */
    this.cr0Trace = [];
    /** interrupt flag (KfCli/KfSti) */
    this.interruptsEnabled = true;
    /** HVCI/VBS analog: when true, clearing CR0.WP bugchecks 0x109 */
    this.hvciMode = false;
    /** integrity-scanned ranges: {base, size, name, pristine:Uint8Array} */
    this.protectedRanges = [];
    /** mini-PatchGuard state (installPatchguard) — null when not armed */
    this.patchguard = null;
    /** EPT shadow entries (m22): [{name, va, len, hostBytes, reads}] — the
     *  guest-visible bytes are whatever sits in flat memory; hostBytes are
     *  the "physical" view only the hypervisor (and !eptview) can see. */
    this.eptShadow = [];
    this.msrIntercepts = new Map();  // MSR address → intercept handler (m28)
    this.vmExitLog = [];             // VM-exit trap log for !vmexit inspection

    // pool — full mock heap (ExAllocatePoolWithTag family)
    // opts.heap: {aslr?: boolean, seed?: number|bigint} — ASLR disabled by
    // default for deterministic CI; enable to randomize inter-allocation
    // padding and make synthetic VAs less round (drv=0xfffff9… not 0x…00000).
    this.heapConfig = {
      aslr: !!opts.heap?.aslr,
      seed: BigInt(opts.heap?.seed ?? 0x9e3779b1n) & 0xffffffffn,
    };
    // xorshift32 state for deterministic jitter
    this._heapPrng = Number(this.heapConfig.seed & 0xffffffffn) || 0x9e3779b1;
    this.nextPool = this.bases.pool;
    /** @type {Array<{addr:bigint,size:number,tag:string,freed:boolean}>} */
    this.poolAllocs = [];

    /** interrupt state: current processor IRQL (0=PASSIVE .. 31) */
    this.currentIrql = 2; // DISPATCH_LEVEL default in our labs
    /** @type {Array<{dpcVa:bigint, routine:bigint, context:bigint, drained:boolean}>} */
    this.pendingDpcs = [];
    /** scenario hook invoked when a queued DPC finally drains */
    this.onDpcDrain = null;
    /** scenario hook invoked when pool verification passes after corruption */
    this.onPoolHealed = null;
    /** when true, double-free raises a modeled BAD_POOL_CALLER bugcheck */
    this.poolStrict = false;

    /** @type {Map<string, bigint>} name -> EPROCESS va */
    this.processesByName = new Map();

    /** @type {Array<{handle:bigint, ownerEproc:bigint, targetEproc:bigint,
     *                grantedAccess:number}>} cross-process object references
     *  (EDR handle-table cross-check source; see ZwQuerySystemInformation) */
    this.objectHandles = [];

    // ------------------------------------------------------------ debug exc (anti-trace lab)
    /** @type {Array<{name:string, fn:(info:{code:string,rip:bigint})=>boolean}>} */
    this.vectoredHandlers = [];
    this.tracer = { attached: false };
    this.traceStats = { int1Raised: 0, vehHandled: 0, swallowedByTracer: 0 };

    /** captured DbgPrint lines */
    this.dbgLog = [];

    /** chronological call-trace events (see tracer.mjs); capped ring */
    this.traceEvents = [];
    this.traceLimit = 8192;
    this.tracePhase = "run";
    this.traceSeq = 0;

    /** ETW capture (EtwRegister/EtwWrite models) */
    this.etwLog = [];

    /** optional live sink: invoked with each formatted DbgPrint line as it
     *  happens (a real kernel debugger receives debug output inline; the
     *  buffer above is the post-hoc !dbgprint view). */
    this.onDebugPrint = null;

    /** bugcheck state */
    this.crash = null;

    /** @type {Array<{driverObj:bigint, name:string}>} */
    this.loadedDrivers = [];

    // Tier 2 Micro-Symbol Service
    this.symbolEngine = new SymbolEngine();
    if (this.tables) this.symbolEngine.loadFromTables(this.tables);

    this._wireApiHooks();
    installWinApi(this);
    installNotifyEngine(this);

    // Seed a tiny demo hive (Qiling-style virtual registry)
    this.registrySeed("\\Registry\\Machine\\SOFTWARE\\KernelForge", {
      Version: "1.0.0",
    });
    this.registrySeed(
      "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\kfprobe",
      { Start: "\u0003\u0000\u0000\u0000" });

    this._installCpuHook();
    this._installDebugExceptionHook();
  }

  // ------------------------------------------------------------------ boot

  /** Wire dump-derived globals into the SymbolEngine (call after bootstrap). */
  loadDumpGlobals(headerFields = {}) {
    if (!this.symbolEngine) return;
    this.symbolEngine.loadDumpGlobals({
      psActiveProcessHead: "0x" + this.PsActiveProcessHead?.toString(16),
      ...headerFields,
    });
  }

  async loadTablesFromDir(dir) {
    const names = [
      "_EPROCESS", "_ETHREAD", "_KPROCESS", "_KTHREAD", "_LIST_ENTRY",
      "_UNICODE_STRING", "_OBJECT_TYPE", "_OBJECT_HEADER", "_HANDLE_TABLE",
      "_PS_PROTECTION", "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY",
      "_MMVAD", "_MMVAD_SHORT",
    ];
    this.tables = await StructTables.loadDir(dir, names);
  }

  /** Synthesize the process environment with real per-build offsets. */
  bootstrap() {
    const t = this.tables;
    if (!t.has("_EPROCESS")) throw new Error("EPROCESS table not loaded");

    const eprocSize = Number(t.sizeOf("_EPROCESS"));
    const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");

    // layout: [head LIST_ENTRY][eproc0][eproc1]...
    const headAddr = this.bases.eproc;
    let nextEproc = headAddr + 16n;

    const linkAddrs = [];
    for (const p of DEFAULT_PROCESSES) {
      const addr = nextEproc;
      nextEproc += BigInt(eprocSize);
      const e = new StructRef(this.mem, this.tables, addr, "_EPROCESS");
      e.w64("UniqueProcessId", BigInt(p.pid));
      e.writeAnsiField("ImageFileName", p.name, 15);
      if (p.ppl && t.has("_PS_PROTECTION")) {
        // _PS_PROTECTION bit pack: Type(4b) | Audit(2b) | Signer(4b)
        // Light type=2, WinTcb signer=6 => 0x62
        e.w8("Protection", (2 << 4) | 6);
      }
      this.processesByName.set(p.name, addr);
      linkAddrs.push(addr + linksOff);
    }

    // circular doubly-linked list through head
    this.PsActiveProcessHead = headAddr;
    for (let i = 0; i < linkAddrs.length; i++) {
      const prevLinks = i === 0 ? headAddr : linkAddrs[i - 1];
      const nextLinks = i === linkAddrs.length - 1 ? headAddr : linkAddrs[i + 1];
      this.mem.w64(linkAddrs[i], nextLinks);     // Flink
      this.mem.w64(linkAddrs[i] + 8n, prevLinks); // Blink
    }
    this.mem.w64(headAddr, linkAddrs[0]);
    this.mem.w64(headAddr + 8n, linkAddrs[linkAddrs.length - 1]);

    // ------------------------------------------------ threads & cross-refs
    // One seeded _ETHREAD per process wired into its owner's ThreadListHead
    // ring, with KTHREAD.ApcState.Process stamped back at the owner EPROCESS,
    // plus per-process _HANDLE_TABLE blobs and a few cross-process handle
    // records. Rationale: ActiveProcessLinks is only ONE of the places a
    // process exists. DKOM can unlink the list; it cannot retract the
    // ApcState pointer of every thread that ever ran in the process, nor the
    // handles other processes hold against it. These are the independent
    // sources EDRs diff the process list against (lessons m1.l2 / m1.l4).
    //
    // Skipped under guest paging: demand-mapped seed pages would consume
    // MMU frames ahead of the paging fixtures and shift every physical
    // address those labs assert on. Paging worlds (SMM/paging tracks) keep
    // their pristine layout.
    if (!this.paging) this.seedProcessThreads();

    // Wire realistic primary tokens so PsReferencePrimaryToken / SeQueryInformationToken
    // return walkable data (System = S-1-5-18). Uses kdemu dump's System token when available,
    // else synthetic. This unblocks hidden drivers that validate token before installing hooks.
    try {
      const tokenOff = this.tables.offsetOf("_EPROCESS", "Token");
      const systemEproc = this.processesByName.get("System");
      if (systemEproc != null) {
        const tokenVa = this.allocPool(0x100, "Toke");
        // Minimal _TOKEN: at offset 0x40 is UserAndGroupCount etc on 22H2, but for our
        // SeQueryInformationToken we just need a non-zero token so PsReferencePrimaryToken works.
        // Store a SID string nearby and a TOKEN_USER at tokenVa+0x80 for SeQuery.
        const sidVa = tokenVa + 0x60n;
        this.mem.write(sidVa, Uint8Array.from([0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00]));
        const tuVa = tokenVa + 0x80n;
        this.mem.w64(tuVa, sidVa);
        this.mem.w32(tuVa + 8n, 0);
        // Link EPROCESS.Token (EX_FAST_REF) — low 4 bits are refcount, store pointer | 0
        this.mem.w64(systemEproc + BigInt(tokenOff), tokenVa & ~0xfn);
        // Also wire other processes with distinct SIDs for realism (optional)
        for (const [name, eproc] of this.processesByName.entries()) {
          if (name === "System") continue;
          if (eproc === systemEproc) continue;
          try { this.mem.w64(eproc + BigInt(tokenOff), tokenVa & ~0xfn); } catch {}
        }
        this.systemTokenVa = tokenVa;
        this.dbgLog.push(`[kdemu] System token @ 0x${tokenVa.toString(16)} (S-1-5-18) for ${systemEproc.toString(16)}`);
      }
    } catch (e) { this.dbgLog.push(`[kdemu] token wiring failed: ${e.message}`); }

    // scenario modules visible via `lm` — kfbootkit.sys is the L1 flag target
    this.loadedDrivers.push(
      { name: "ntoskrnl.exe", base: 0xfffff8052b800000n, imageSize: 0x800000 },
      { name: "HAL.dll", base: 0xfffff8052b000000n, imageSize: 0x40000 },
      { name: "kfbootkit.sys", base: 0xfffff80539000000n, imageSize: 0x8000 },
    );

    // ------------------------------------------------------- guest paging
    if (this.paging) {
      // DirectoryTableBase in every EPROCESS (KPROCESS is embedded at offset 0)
      let dtbOff = 0n;
      try { dtbOff = BigInt(this.tables.offsetOf("_KPROCESS", "DirectoryTableBase")); } catch { /* best effort */ }
      if (dtbOff > 0n) {
        for (const addr of this.processesByName.values()) {
          this.mem.w64(addr + dtbOff, this.cr3 & ~0xfffn);
        }
      }

      // KUSER_SHARED_DATA: one physical frame, two VA views — the classic
      // user 0x7FFE0000 and the kernel alias 0xFFFFF780`00000000.
      const kuserFrame = this.mmu.frameAlloc();
      const kuser = new Uint8Array(4096);
      const w32at = (off, v) => {
        kuser[off] = v & 0xff; kuser[off+1] = (v>>>8)&0xff; kuser[off+2] = (v>>>16)&0xff; kuser[off+3] = (v>>>24)&0xff;
      };
      w32at(0x000, 1);            // modeled TickCountLowDeprecated
      w32at(0x2c4, 10);           // NtMajorVersion 10
      w32at(0x2c8, 0);            // NtMinorVersion 0
      w32at(0x300, 2);            // SuiteMask ~ Server
      kuser[0x304] = 1;           // KdDebuggerEnabled
      this.rawMem.write(kuserFrame, kuser);
      for (const va of [0x7ffe0000n, 0xfffff78000000000n]) {
        this.mmu.mapPage(va, kuserFrame, { write: false, nx: true });
      }
      this.kuserSharedData = 0x7ffe0000n;
    }
  }

  /** Guest-VA -> guest-PA via the MMU (null when unmapped / paging off). */
  vtop(va) {
    return this.paging ? (this.mmu.lookup(va)?.pa ?? null) : BigInt(va);
  }

  // -------------------------------------------------- threads & cross-refs

  /** KTHREAD.ApcState byte offset for the active build (null if absent). */
  apcStateOffset() {
    try { return this.tables.offsetOf("_KTHREAD", "ApcState"); } catch { return null; }
  }

  /**
   * Synthesize boot-time thread & handle state (called by bootstrap):
   *   - one _ETHREAD per DEFAULT_PROCESS: CLIENT_ID, ThreadListHead ring,
   *     ActiveThreads=1, and KTHREAD.ApcState.Process -> owner EPROCESS.
   *     This is the EDR cross-reference that survives DKOM: unlinking
   *     ActiveProcessLinks does not retract any thread's ApcState pointer.
   *   - a _HANDLE_TABLE blob per process behind EPROCESS.ObjectTable, plus
   *     SEED_HANDLE_REFS records in kernel.objectHandles so handle-table
   *     enumeration finds processes the list no longer shows.
   * Each feature degrades independently when the active build's tables lack
   * its fields (win7 KTHREAD carries ApcStatePointer, not ApcState).
   */
  seedProcessThreads() {
    const t = this.tables;
    const mem = this.mem;
    let cidOff, tleOff;
    try {
      cidOff = t.offsetOf("_ETHREAD", "Cid");
      tleOff = t.offsetOf("_ETHREAD", "ThreadListEntry");
    } catch {
      return; // build lacks basic thread fields — no seeding
    }
    let tlhOff = null, atOff = null, otOff = null;
    try { tlhOff = t.offsetOf("_EPROCESS", "ThreadListHead"); } catch { /* ring off */ }
    try { atOff = t.offsetOf("_EPROCESS", "ActiveThreads"); } catch { /* counter off */ }
    try { otOff = t.offsetOf("_EPROCESS", "ObjectTable"); } catch { /* table ptr off */ }
    let tebOff = null, w32Off = null;
    try { tebOff = BigInt(t.offsetOf("_KTHREAD", "Teb")); } catch { /* optional */ }
    try { w32Off = BigInt(t.offsetOf("_KTHREAD", "Win32Thread")); } catch { /* optional */ }
    const apcOff = this.apcStateOffset();

    const ethreadSize = t.has("_ETHREAD")
      ? BigInt(Number(t.sizeOf("_ETHREAD"))) : 0x600n;
    const htSize = t.has("_HANDLE_TABLE")
      ? BigInt(Number(t.sizeOf("_HANDLE_TABLE"))) : 0x100n;
    const align16 = (v) => (v + 15n) & ~15n;

    // deterministic kthrd-region layout: [HT per proc][ETHREAD per proc]
    let cursor = this.bases.kthrd;
    for (const p of DEFAULT_PROCESSES) {
      const eproc = this.processesByName.get(p.name);
      if (!eproc) continue;
      if (otOff !== null) mem.w64(eproc + otOff, cursor); // ObjectTable -> blob
      cursor += align16(htSize);
    }

    const threadsByPid = new Map();
    let i = 0;
    for (const p of DEFAULT_PROCESSES) {
      const eproc = this.processesByName.get(p.name);
      if (!eproc) continue;
      const thr = cursor;
      cursor += align16(ethreadSize);
      mem.w64(thr + cidOff, BigInt(p.pid));              // CLIENT_ID.UniqueProcess
      mem.w64(thr + cidOff + 8n, BigInt(0x400 + i * 4)); // CLIENT_ID.UniqueThread
      if (tlhOff !== null) {
        const head = eproc + tlhOff;
        const entry = thr + tleOff;
        mem.w64(head, entry);
        mem.w64(head + 8n, entry);
        mem.w64(entry, head);
        mem.w64(entry + 8n, head);
      }
      if (atOff !== null) mem.w32(eproc + atOff, 1);
      if (apcOff !== null) mem.w64(thr + apcOff, eproc); // ApcState.Process
      if (tebOff !== null) {
        // deterministic user-mode Teb, same formula as the dump-world seeder
        const tid = BigInt(0x400 + i * 4);
        mem.w64(thr + tebOff, 0x000000e400000000n + tid * 0x100000n);
      }
      if (w32Off !== null) mem.w64(thr + w32Off, 0n); // non-GUI seed threads
      threadsByPid.set(BigInt(p.pid), thr);
      i++;
    }
    this.threadsByPid = threadsByPid;
    if (!this.currentThread) this.currentThread = threadsByPid.get(4n) ?? null;

    this.seedHandleRefs();
  }

  /**
   * (Re)build the deterministic cross-process object references from
   * SEED_HANDLE_REFS against the CURRENT processesByName map. Called by
   * seedProcessThreads at boot and re-invoked by dump-overlay worlds after
   * populateFromDump() relocates every EPROCESS — stale owner/target
   * pointers would otherwise point at bootstrap-era blocks.
   */
  seedHandleRefs() {
    this.objectHandles.length = 0;
    let h = 0x10n;
    for (const ref of SEED_HANDLE_REFS) {
      const ownerEproc = this.processesByName.get(ref.owner);
      const targetEproc = this.processesByName.get(ref.target);
      if (!ownerEproc || !targetEproc) continue;
      this.objectHandles.push({
        handle: h,
        ownerEproc,
        targetEproc,
        grantedAccess: ref.access,
      });
      h += 4n;
    }
  }

  /**
   * Walk an EPROCESS.ThreadListHead ring; returns [{addr, tid, backed}]
   * (tid via CLIENT_ID.UniqueThread when readable). Guards against empty
   * rings, self-loops and unbacked dump pointers.
   */
  threadsOf(eproc) {
    const t = this.tables;
    const out = [];
    let tlhOff, tleOff, cidOff;
    try {
      tlhOff = t.offsetOf("_EPROCESS", "ThreadListHead");
      tleOff = t.offsetOf("_ETHREAD", "ThreadListEntry");
      cidOff = t.offsetOf("_ETHREAD", "Cid");
    } catch { return out; }
    const head = eproc + tlhOff;
    let cur = this.mem.u64(head);
    const seen = new Set();
    while (cur && cur !== head && !seen.has(cur) && out.length < 64) {
      seen.add(cur);
      const base = cur - tleOff;
      let tid = null;
      try { tid = this.mem.u64(base + cidOff + 8n); } catch { /* unreadable */ }
      out.push({ addr: base, tid });
      cur = this.mem.u64(cur);
    }
    return out;
  }

  /** Raw leaf PTE for a guest VA under paging (null otherwise). */
  readPte(va) {
    return this.paging ? this.mmu.readPte(va) : null;
  }

  // -------------------------------------------------------------- pool

  /** xorshift32 step for heap jitter (deterministic, fast). */
  _heapNextJitter() {
    let x = this._heapPrng >>> 0;
    x ^= (x << 13) >>> 0;
    x ^= x >>> 17;
    x ^= (x << 5) >>> 0;
    this._heapPrng = x >>> 0;
    // 0..255 * 16 = 0..4080, 16-byte aligned, keeps low 4 bits non-zero
    return (x & 0xff) * 16;
  }

  /**
   * Layout per allocation (32 bytes of bookkeeping around the payload):
   *   [hdr magic u64 @ addr-16][pad 8][payload size bytes @ addr][guard 16B]
   * The guard lets !poolverify catch out-of-bounds writes before they turn
   * into distant, unrelated bugchecks.
   *
   * When heapConfig.aslr is true, a small deterministic jitter (16-byte
   * steps up to 4080) is added between allocations so synthetic VAs are
   * not suspiciously round (e.g. drv != 0xfffff80200000000). Disabled by
   * default for CI determinism — enable via `new NtKernel({heap:{aslr:true}})`.
   */
  allocPool(size, tag = "ntsm") {
    const aligned = (size + 15) & ~15;
    // Insert ASLR padding before the header when enabled
    let hdr = this.nextPool;
    if (this.heapConfig?.aslr) {
      const jitter = this._heapNextJitter();
      hdr += BigInt(jitter);
    }
    const addr = hdr + 16n;
    this.nextPool = hdr + BigInt(aligned) + 32n;
    // Reserve one extra guard bump when ASLR is on so the next allocation
    // does not accidentally start on the previous guard's page tail.
    if (this.heapConfig?.aslr) this.nextPool += 16n;
    this.mem.w64(hdr, POOL_MAGIC);
    this._writeGuard(addr, size);
    // Backing discipline: an allocation implies its whole span exists.
    // SparseMemory would auto-fill on access, but CPU backends with explicit
    // page maps (Unicorn) need the pages present BEFORE guest writes race
    // through a memset-style loop over the buffer.
    const spanEnd = addr + BigInt(aligned) + 32n;
    for (let p = hdr & ~0xfffn; p < spanEnd; p += 0x1000n) {
      if (!this.mem.hasPage(p)) this.mem.write(p, new Uint8Array(0x1000));
    }
    this.poolAllocs.push({ addr, size, tag, freed: false });
    return addr;
  }

  /** Register a scenario-seeded block at a fixed VA (deterministic labs). */
  registerPoolBlock(addr, size, tag = "ntsm") {
    this.mem.w64(addr - 16n, POOL_MAGIC);
    this._writeGuard(addr, size);
    this.poolAllocs.push({ addr, size, tag, freed: false, fixed: true });
    return { addr, size, tag };
  }

  _writeGuard(addr, size) {
    this.mem.write(
      addr + BigInt(size),
      new Uint8Array(POOL_GUARD_LEN).fill(POOL_GUARD_BYTE),
    );
  }

  freePool(addr) {
    const entry = this.poolAllocs.find((a) => a.addr === BigInt(addr));
    if (!entry) {
      this.dbgLog.push(`[pool] ExFreePoolWithTag: unknown address — ignored`);
      return false;
    }
    if (entry.freed) {
      if (this.poolStrict) {
        // modeled BAD_POOL_CALLER (0xC2): P1=0x7 double free-ish, P2=addr
        this.bugcheck = { code: 0xc2n, params: [0x7n, BigInt(addr), 0n, 0n] };
        this.crash = { code: "0xc2" };
        this.cpu.halted = true;
      } else {
        this.dbgLog.push(`[pool] double free at ${addr.toString(16)} detected`);
      }
      return false;
    }
    entry.freed = true;
    return true;
  }

  /** Sweep all allocation guards. Returns the corrupted entries. */
  verifyGuards() {
    return this.poolAllocs.filter((a) => {
      if (a.freed) return false;
      for (let i = 0; i < POOL_GUARD_LEN; i++) {
        if (this.mem.u8(a.addr + BigInt(a.size) + BigInt(i)) !== POOL_GUARD_BYTE) return true;
      }
      return false;
    });
  }

  guardBytes(addr) {
    const entry = this.poolAllocs.find((a) => a.addr === BigInt(addr));
    if (!entry) return null;
    return new Uint8Array(POOL_GUARD_LEN).fill(POOL_GUARD_BYTE);
  }

  // ------------------------------------------------------------ IRQL / DPC

  raiseIrql(level) {
    if (level < this.currentIrql) {
      // real Windows: KeRaiseIrql below current = bugcheck IRQL_NOT_LESS_OR_EQUAL
      this.bugcheck = { code: 0xan, params: [BigInt(level), 0n, 0n, 0n] };
      this.crash = { code: "0xa" };
      this.cpu.halted = true;
      throw new Error(`KeRaiseIrql: cannot raise to ${level} below current ${this.currentIrql}`);
    }
    const old = this.currentIrql;
    this.currentIrql = level;
    return old;
  }

  lowerIrql(level) {
    if (level > this.currentIrql) {
      this.bugcheck = { code: 0xan, params: [BigInt(level), 1n, 0n, 0n] };
      this.crash = { code: "0xa" };
      this.cpu.halted = true;
      throw new Error(`KeLowerIrql: cannot raise IRQL ${this.currentIrql} -> ${level}`);
    }
    this.currentIrql = level;
  }

  /** IRQL of logical core i (core 0 aliases currentIrql). */
  cpuIrql(i) {
    return i === 0 ? (this.currentIrql ?? 0) : (this.cpuIrqls[i - 1] ?? 0);
  }

  /** Move a logical core to an IRQL (cores >0 are directed-DPC lab state). */
  setCpuIrql(i, level) {
    if (i === 0) this.currentIrql = level;
    else if (i >= 1 && i <= this.cpuIrqls.length) this.cpuIrqls[i - 1] = level;
  }

  /**
   * CR0 write through the KfWriteCr0 thunk. Records history; under the
   * HVCI/VBS analog a WP-clearing write is intercepted with modeled
   * CRITICAL_STRUCTURE_CORRUPTION (0x109) — matching real VBS behavior.
   */
  writeCr0(value) {
    const v = BigInt.asUintN(64, BigInt(value));
    const old = this.cr0;
    const CR0_WP = 0x10000n;
    this.cr0Trace.push({ tick: this.tickCount ?? 0n, old, new: v });
    this.dbgLog.push(
      `nt: mov cr0, 0x${v.toString(16)} (WP=${((v >> 16n) & 1n).toString()}, was ${((old >> 16n) & 1n).toString()})`);
    if ((old & CR0_WP) !== 0n && (v & CR0_WP) === 0n && this.hvciMode) {
      this.dbgLog.push("[hvci] CR0.WP-clearing write intercepted -> CRITICAL_STRUCTURE_CORRUPTION");
      this.bugcheck = { code: 0x109n, params: [3n, v, old, 0n] };
      this.crash = { code: "0x109" };
      this.cpu.halted = true;
      throw new Error("HVCI: CR0.WP-clearing write blocked (CRITICAL_STRUCTURE_CORRUPTION)");
    }
    this.cr0 = v;
    return old;
  }

  /**
   * Register a pristine-vs-live integrity range (PatchGuard/HVCI analog).
   * Snapshots current bytes for later !pgscan / scanProtectedRanges().
   */
  protectRange(base, size, name = "protected") {
    const len = Number(size);
    const range = { base, size: len, name, pristine: this.mem.read(base, len) };
    this.protectedRanges.push(range);
    return range;
  }

  /** Diff protected ranges against their pristine snapshot. */
  scanProtectedRanges() {
    const diffs = [];
    for (const r of this.protectedRanges) {
      const live = this.mem.read(r.base, r.size);
      let firstDelta = -1;
      let count = 0;
      for (let i = 0; i < r.size; i++) {
        if (live[i] !== r.pristine[i]) {
          count++;
          if (firstDelta < 0) firstDelta = i;
        }
      }
      if (firstDelta >= 0) diffs.push({ ...r, firstDelta, count, liveByte: live[firstDelta], pristineByte: r.pristine[firstDelta] });
    }
    return diffs;
  }

  // ------------------------------------------------------- mini PatchGuard

  /**
   * Arm the fake mini-PatchGuard: every `period` lab ticks a sweep re-reads
   * the protected ranges and compares them against their install-time
   * snapshot. Drift raises modeled CRITICAL_STRUCTURE_CORRUPTION (0x109) and
   * halts the CPU — the race a non-PatchGuard-compliant hook loses in the
   * m20 timing lab when it stays installed past the next sweep.
   */
  installPatchguard({ period = 4, phase = 2 } = {}) {
    if (!this.protectedRanges.length) {
      throw new Error("installPatchguard: no protectRange() targets armed");
    }
    this.patchguard = {
      period: Math.max(1, Number(period) || 4),
      // sweeps are scheduled RELATIVE to arming so worlds stay deterministic
      // regardless of the lab clock's boot value
      nextSweep: Number(this.tickCount ?? 0n) + Math.max(0, Number(phase) || 0),
      sweeps: 0,
      lastSweepTick: null,
      violatedAt: null,
    };
    this.dbgLog.push(
      `[pg] mini-PatchGuard armed: period=${this.patchguard.period} tick(s), ` +
      `${this.protectedRanges.length} protected region(s)`);
    return this.patchguard;
  }

  /** True when a sweep is due on the current lab clock. */
  _pgSweepDue() {
    const pg = this.patchguard;
    if (!pg || pg.violatedAt !== null) return false;
    return Number(this.tickCount ?? 0n) >= pg.nextSweep;
  }

  patchguardSweep() {
    const pg = this.patchguard;
    if (!pg || pg.violatedAt !== null) return false;
    pg.sweeps++;
    pg.lastSweepTick = this.tickCount ?? 0n;
    const diffs = this.scanProtectedRanges();
    // worlds can attach non-byte checks (e.g. MSR/IDT register-file drift)
    const extraLabel = !diffs.length && pg.extraCheck ? pg.extraCheck.call(this) : null;
    if (!diffs.length && !extraLabel) {
      pg.nextSweep += pg.period; // clean pass — re-arm down the clock
      return false;
    }

    if (extraLabel && !diffs.length) {
      pg.violatedAt = this.tickCount ?? 0n;
      this.dbgLog.push(
        `[pg] sweep ${pg.sweeps}: ${extraLabel} -> CRITICAL_STRUCTURE_CORRUPTION`);
      this.bugcheck = { code: 0x109n, params: [3n, 0n, 0n, 0n] };
      this.crash = { code: "0x109" };
      this.cpu.halted = true;
      return true;
    }

    const d = diffs[0];
    pg.violatedAt = this.tickCount ?? 0n;
    this.dbgLog.push(
      `[pg] sweep ${pg.sweeps}: ${d.name} @ 0x${d.base.toString(16)} modified ` +
      `(byte +0x${d.firstDelta.toString(16)}: 0x${d.pristineByte.toString(16)} -> ` +
      `0x${d.liveByte.toString(16)}) -> CRITICAL_STRUCTURE_CORRUPTION`);
    this.bugcheck = { code: 0x109n, params: [3n, d.base, BigInt(d.firstDelta), 0n] };
    this.crash = { code: "0x109" };
    this.cpu.halted = true;
    return true;
  }

  /** PG summary for !pgstatus. */
  patchguardStatus() {
    const pg = this.patchguard;
    if (!pg) return null;
    const t = Number(this.tickCount ?? 0n);
    return {
      period: pg.period,
      sweeps: pg.sweeps,
      lastSweepTick: pg.lastSweepTick,
      violatedAt: pg.violatedAt,
      regions: this.protectedRanges.length,
      clean: pg.violatedAt === null,
      nextSweepIn: pg.violatedAt === null
        ? Math.max(0, pg.nextSweep - t)
        : null,
    };
  }

  // ------------------------------------------------------- EPT shadow sim

  /**
   * Model an EPT-backed hidden page (m22): the GUEST view is whatever bytes
   * sit in flat memory — the kernel and every kd read see them. The HOST
   * view (`hostBytes`, what the physical machine / a second translation
   * would return) is kept out-of-band here, exactly the split an EPT hook
   * creates between fetches and reads. `installEptShadow` records that
   * second view; it does NOT touch guest memory.
   */
  installEptShadow({ name, va, len, hostBytes }) {
    const entry = {
      name: String(name),
      va: BigInt(va),
      len: Number(len),
      hostBytes: Uint8Array.from(hostBytes),
      reads: 0,
    };
    this.eptShadow.push(entry);
    return entry;
  }

  // ------------------------------------------------------- VM-exit MSR intercepts

  /**
   * Model hypervisor MSR interception (m28): when a guest executes RDMSR/WRMSR
   * on an intercepted MSR, the hypervisor traps via VM-exit, can modify the
   * value or fake success, and the guest never knows. This is the ONLY way
   * to hook syscall flow (LSTAR) without triggering PatchGuard.
   *
   * @param {bigint} msr - MSR address (e.g., 0xC0000082 for IA32_LSTAR)
   * @param {Function} handler - (value, isWrite) => newValue; for reads, value is ignored
   */
  installMsrIntercept(msr, handler) {
    this.msrIntercepts.set(BigInt(msr), handler);
  }

  /** All shadow entries overlapping [va, va+len). */
  eptShadowAt(va, len = 1) {
    va = BigInt(va);
    return this.eptShadow.filter((e) =>
      va < e.va + BigInt(e.len) && e.va < va + BigInt(len));
  }


  /**
   * Drain-time read of a queued DPC's DeferredRoutine/DeferredContext from
   * guest memory (real x64 layout: routine @+0x18, context @+0x20). Reading
   * live memory at drain time is what makes post-insert patches (hijack
   * labs) observable and lets !dpcs/!dpcdrain report the CURRENT pointer
   * instead of a cached snapshot (issue #16).
   * Falls back to the insert-time snapshot when memory is unmapped/zeroed.
   */
  _liveDpcField(d, byteOffset, fallback) {
    try {
      if (this.mem.canRead(d.dpcVa + byteOffset, 8)) {
        const v = this.mem.u64(d.dpcVa + byteOffset);
        if (v !== 0n) return v;
      }
    } catch { /* guarded */ }
    return fallback;
  }

  static KDPC_ROUTINE_OFF = 0x18n;
  static KDPC_CONTEXT_OFF = 0x20n;

  liveDpcRoutine(d) { return this._liveDpcField(d, NtKernel.KDPC_ROUTINE_OFF, d.routine); }
  liveDpcContext(d) { return this._liveDpcField(d, NtKernel.KDPC_CONTEXT_OFF, d.context); }

  queueDpc(dpcVa, routine, context = 0n, opts = {}) {
    if (this.pendingDpcs.some((d) => d.dpcVa === dpcVa && !d.drained)) return false;
    this.pendingDpcs.push({
      dpcVa,
      routine,
      context,
      drained: false,
      targetCpu: opts.targetCpu ?? 0,
      enqueuedAt: opts.enqueuedAt ?? (this.tickCount ?? 0n),
    });
    return true;
  }

  /** Fire every queued DPC (caller must be <= DISPATCH_LEVEL). */
  drainDpcs() {
    const fired = [];
    for (const d of this.pendingDpcs) {
      if (d.drained) continue;
      d.drained = true;
      fired.push(d);
      this.dbgLog.push(`nt: KiRetireDpcList: DPC @ ${d.dpcVa.toString(16)} fired`);
      const live = this.liveDpcRoutine(d);
      if (live !== d.routine && d.routine) {
        this.dbgLog.push(`[dpc] DeferredRoutine now 0x${live.toString(16)} (insert-time 0x${d.routine.toString(16)})`);
      }
      try { this.onDpcDrain?.(d); } catch (e) { this.dbgLog.push(`[dpc] callback threw: ${e.message}`); }
    }
    return fired;
  }

  // -------------------------------------------------------------- timers

  /**
   * Model KeSetTimer/KeSetTimerEx. `dueTick` is absolute on the lab clock
   * (kernel.tickCount); `period` > 0 re-arms after each expiration.
   * @returns {boolean} true when the timer was already pending (real contract)
   */
  setTimer(timerVa, dueTick, period = 0, dpcVa = 0n) {
    const t = this.pendingTimers.find((x) => x.timerVa === timerVa);
    if (t) {
      Object.assign(t, { dueTick, period, dpcVa });
      return true;
    }
    this.pendingTimers.push({ timerVa, dueTick, period, dpcVa, firedCount: 0 });
    return false;
  }

  cancelTimer(timerVa) {
    const idx = this.pendingTimers.findIndex((x) => x.timerVa === timerVa);
    if (idx < 0) return false;
    this.pendingTimers.splice(idx, 1);
    return true;
  }

  /** Expire due timers, executing bound KDPC routines read from memory.
   *  Nothing timer-driven fires while the executing core is pinned above
   *  DISPATCH_LEVEL — the clock interrupt itself is masked up there. */
  fireDueTimers(maxPerTimer = 64) {
    if ((this.currentIrql ?? 2) > 2) return 0;
    let fired = 0;
    for (const t of [...this.pendingTimers]) {
      let guard = 0;
      while ((this.tickCount ?? 0n) >= t.dueTick) {
        fired++;
        guard++;
        t.firedCount++;
        this.dbgLog.push(`nt: KiTimerExpiration: timer 0x${t.timerVa.toString(16)} expired (tick ${t.dueTick})`);
        let routine = null;
        let context = 0n;
        if (t.dpcVa) {
          try {
            // live reads at the real x64 offsets (routine @+0x18, ctx @+0x20)
            if (this.mem.canRead(t.dpcVa, 0x28)) {
              const r = this.mem.u64(t.dpcVa + NtKernel.KDPC_ROUTINE_OFF);
              if (r !== 0n) routine = r;
              context = this.mem.u64(t.dpcVa + NtKernel.KDPC_CONTEXT_OFF);
            }
          } catch { /* guarded */ }
          if (!routine) {
            const rec = this.pendingDpcs.find((d) => d.dpcVa === t.dpcVa);
            if (rec) { routine = rec.routine; context = rec.context; }
          }
          // the timer retires its bound record so !dpcs reflects reality
          const rec = this.pendingDpcs.find((d) => d.dpcVa === t.dpcVa && !d.drained);
          if (rec) rec.drained = true;
        }
        if (routine) {
          const r = this.cpu.callFunction(routine, [t.dpcVa ?? 0n, context, 0n, 0n]);
          this.dbgLog.push(`[timer] DPC routine 0x${routine.toString(16)} -> ${r.status}`);
          if (r.status !== "ok") this.exceptionTrace.push({ kind: "timer", detail: r.status });
        }
        if (guard >= maxPerTimer) break;
        if (t.period > 0) t.dueTick += BigInt(t.period);
        else { this.cancelTimer(t.timerVa); break; }
      }
    }
    return fired;
  }

  /**
   * Advance the lab clock by n ticks, expire timers and — when the CPU is at
   * or below DISPATCH_LEVEL — retire queued DPCs with real execution.
   * This is the debugger's KiRetireDpcList/KiTimerExpiration analog.
   */
  advanceTicks(n = 1) {
    const ticks = Math.max(0, Math.min(Number(n) || 0, 100000));
    this.tickCount = (this.tickCount ?? 0n) + BigInt(ticks);
    const firedTimers = this.fireDueTimers();
    let retired = 0;
    if ((this.currentIrql ?? 2) <= 2) retired = this.retireQueuedDpcs();
    // mini-PatchGuard rides the same lab clock: sweep when due, before the
    // caller observes anything else (integrity first — like the real thing)
    if (ticks > 0 && this._pgSweepDue()) this.patchguardSweep();
    return { ticks, firedTimers, retired };
  }

  /**
   * Retire every queued DPC like drainDpcs(), but ALSO execute each routine
   * through the CPU (drainDpcs is retirement-only for scenario hooks).
   */
  retireQueuedDpcs() {
    let n = 0;
    for (const d of this.pendingDpcs.filter((x) => !x.drained)) {
      d.drained = true;
      n++;
      this.dbgLog.push(`nt: KiRetireDpcList: DPC @ ${d.dpcVa.toString(16)} fired`);
      const routine = this.liveDpcRoutine(d) || d.routine;
      try { this.onDpcDrain?.(d); } catch (e) { this.dbgLog.push(`[dpc] callback threw: ${e.message}`); }
      if (!routine) continue;
      const r = this.cpu.callFunction(routine, [d.dpcVa ?? 0n, this.liveDpcContext(d), 0n, 0n]);
      this.dbgLog.push(`[dpc] routine 0x${routine.toString(16)} -> ${r.status}`);
      if (r.status !== "ok") this.exceptionTrace.push({ kind: "dpc", detail: r.status });
    }
    return n;
  }

  /**
   * DPC watchdog analog (KiProcessExpiredTimerList / bugcheck 0x133). Two
   * trip conditions mirror real Windows budgets: any SECONDARY core parked
   * at or above DISPATCH_LEVEL (directed-DPC lockdown), or the executing
   * core sitting above DISPATCH (the m2.l1 pinned-world). Core 0 at exactly
   * DISPATCH is the lab's healthy idle state and never trips alone.
   */
  checkDpcWatchdog() {
    const pinned = [];
    for (let i = 1; i <= this.cpuIrqls.length; i++) {
      const lvl = this.cpuIrql(i);
      if (lvl >= 2) pinned.push({ cpu: i, irql: lvl });
    }
    const core0Above = (this.currentIrql ?? 2) > 2;
    const starved = this.pendingDpcs.filter((d) => !d.drained).length;
    if (!pinned.length && !core0Above) return { ok: true, pinned, starved };
    const worst = pinned.length ? pinned[0].irql : (this.currentIrql ?? 2);
    this.bugcheck = { code: 0x133n, params: [BigInt(worst), 0n, 0n, 0n] };
    this.crash = { code: "0x133" };
    this.cpu.halted = true;
    this.dbgLog.push("nt: KiProcessExpiredTimerList: DPC_WATCHDOG_VIOLATION (0x133): core(s) pinned at/above DISPATCH_LEVEL");
    return { ok: false, pinned, starved };
  }

  // ------------------------------------------------------------ API surface

  defineApi(name, impl, meta) {
    if (!this.apiThunks.has(name)) {
      const thunk = this.nextThunk;
      this.nextThunk += 16n;
      this.mem.write(thunk, [0xf4]); // hlt marker (hook intercepts first)
      this.apiThunks.set(name, thunk);
      this.pristineThunks.set(name, this.mem.read(thunk, 8));
    }
    // store PHNT/WDM signature meta for tracer and RAX handling
    const resolvedMeta = meta ?? API_META.get(name) ?? null;
    if (resolvedMeta) this.apiMeta.set(name, resolvedMeta);
    this.apiImpls.set(name, impl.bind(this));
    return this.apiThunks.get(name);
  }

  /**
   * Auto-provision an export we have no model for. Uses PHNT meta when
   * available so VOID stubs don't clobber RAX and NTSTATUS stubs return
   * STATUS_SUCCESS visibly. Used when running arbitrary uploaded drivers.
   */
  provisionUnknownApi(name) {
    if (this.apiThunks.has(name)) return this.apiThunks.get(name);
    this.unmodeledExports.push(name);
    const meta = API_META.get(name);
    const isVoid = meta?.ret === "void";
    if (isVoid) {
      this.dbgLog.push(`[analyzer] provisioned unmodeled export ${name} -> VOID`);
      return this.defineApi(name, () => undefined, meta);
    }
    // Heuristic: Ke*InStackQueuedSpinLock etc are void in PHNT but may not be in map yet
    if (/^Ke.*SpinLock|RtlInit.*String|InitializeListHead|Insert.*List|KeInitialize|KeRelease|KeAcquire|ObReference|ObDereference|IoFree|IoComplete|IoDelete/.test(name)) {
      // best-effort void detection for unmapped WDM helpers - still log as VOID
      // but keep SUCCESS logging if meta explicitly says otherwise
    }
    this.dbgLog.push(`[analyzer] provisioned unmodeled export ${name} -> SUCCESS`);
    return this.defineApi(name, () => 0n, meta);
  }

  /** Kernel data exports drivers import by address (not called through). */
  static DATA_EXPORTS = new Set(["PsProcessType", "PsThreadType", "PsInitialSystemProcess", "PspCidTable", "PspCidTableLock", "PsActiveProcessHead"]);

  /**
   * Resolve "ntdll!Name"-style import; provisions when unknown.
   *
   * Data exports (PsProcessType & co) need real memory, not call thunks:
   * drivers load them with `mov rax, [iatSlot]` and dereference the result,
   * so each gets a qword slot holding a pointer to a small backing struct.
   */
  resolveImportProvisioned(qualified) {
    const name = qualified.includes("!") ? qualified.split("!").pop() : qualified;
    const known = this.apiThunks.get(name);
    if (known) return known;
    if (NtKernel.DATA_EXPORTS.has(name)) return this.#dataExportSlot(name);
    // WDF/FLTMGR/ndis-style prefixed names still get generic stubs
    return this.provisionUnknownApi(name);
  }

  #dataExportSlot(name) {
    if (this.dataExports.has(name)) return this.dataExports.get(name);
    let backing;
    if (name === "PsInitialSystemProcess") {
      const systemEproc = this.processesByName?.get("System") ?? this.findEprocessByPid(4n);
      if (!systemEproc) throw new Error("System EPROCESS not present — bootstrap first");
      backing = systemEproc;
    } else if (name === "PsActiveProcessHead") {
      backing = this.PsActiveProcessHead;
    } else if (name === "PspCidTable") {
      backing = this.#createPspCidTable();
    } else if (name === "PspCidTableLock") {
      backing = this.allocPool(0x10, "CidL");
      this.mem.w64(backing, 0n);
      this.mem.w64(backing + 8n, 0n);
    } else {
      // minimal OBJECT_TYPE stand-in: non-zero so "is it initialized" checks pass
      backing = this.allocPool(0x40, "ObjT");
      this.mem.write(backing, [0x4f, 0x62, 0x6a, 0x54]); // 'ObjT' marker
    }
    const slot = this.allocPool(8, "PtrS");
    this.mem.w64(slot, backing & M64);
    this.dataExports.set(name, slot);
    this.dbgLog.push(`[analyzer] modeled data export ${name} @ 0x${slot.toString(16)} -> 0x${(backing & M64).toString(16)}`);
    return slot;
  }

  #createPspCidTable() {
    // Real walkable HANDLE_TABLE from synthetic EPROCESS list (kdemu-derived pids)
    // TableCode low 2 bits = level (0 = flat). Entries are 16-byte HANDLE_TABLE_ENTRY
    // where LowValue holds Object (EPROCESS) with valid bit.
    try {
      const htSize = this.tables.has("_HANDLE_TABLE") ? Number(this.tables.sizeOf("_HANDLE_TABLE")) : 128;
      const htVa = this.allocPool(htSize, "HndT");
      // zero table
      this.mem.write(htVa, new Uint8Array(htSize));
      const entriesVa = this.allocPool(0x4000, "CidE"); // 1024 entries *16
      this.mem.write(entriesVa, new Uint8Array(0x4000));
      // TableCode at offset 8
      let tableCodeOff = 8;
      try { tableCodeOff = this.tables.offsetOf("_HANDLE_TABLE", "TableCode"); } catch {}
      this.mem.w64(htVa + BigInt(tableCodeOff), entriesVa & ~0x3n);
      // HandleTableList self-loop at offset 24
      try {
        const listOff = this.tables.offsetOf("_HANDLE_TABLE", "HandleTableList");
        this.mem.w64(htVa + BigInt(listOff), htVa + BigInt(listOff));
        this.mem.w64(htVa + BigInt(listOff) + 8n, htVa + BigInt(listOff));
      } catch {}
      // Populate entries: index = handleValue>>2 ; handle for CID is pid*4? Use pid as handle
      let pidOff = null;
      try { pidOff = this.tables.offsetOf("_EPROCESS", "UniqueProcessId"); } catch {}
      const seen = new Set();
      for (const [procName, eproc] of this.processesByName.entries()) {
        if (!eproc) continue;
        let pid = 0n;
        try { pid = this.mem.u64(eproc + BigInt(pidOff ?? 0)); } catch { continue; }
        if (pid === 0n) continue;
        const handle = pid * 4n; // CID handle
        const idx = Number(handle >> 2n);
        if (seen.has(idx)) continue;
        seen.add(idx);
        const entryVa = entriesVa + BigInt(idx * 16);
        if (entryVa + 16n > entriesVa + 0x4000n) continue;
        // LowValue: Object pointer | 0x1 valid, HighValue: granted access placeholder
        this.mem.w64(entryVa, (eproc & M64) | 1n);
        this.mem.w64(entryVa + 8n, 0x1fffffn); // GrantedAccess
      }
      // Also ensure System entry at idx 1 (pid 4 -> handle 0x10 -> idx 4) is present
      this.dbgLog.push(`[kdemu] PspCidTable HANDLE_TABLE @ 0x${htVa.toString(16)} TableCode 0x${entriesVa.toString(16)} entries for ${seen.size} processes`);
      return htVa;
    } catch (e) {
      this.dbgLog.push(`[kdemu] PspCidTable creation failed: ${e.message}`);
      const fallback = this.allocPool(0x40, "HndT");
      this.mem.w64(fallback, 0n);
      return fallback;
    }
  }

  /** Write an E9 rel32 detour over an export's prologue (hook modeling). */
  installDetour(apiName, targetVa) {
    const thunk = this.apiThunks.get(apiName);
    if (!thunk) throw new Error(`installDetour: unknown api "${apiName}"`);
    const rel = Number(BigInt.asIntN(32, targetVa - (thunk + 5n)));
    this.mem.write(thunk, [
      0xe9,
      rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff,
    ]);
  }

  isDetoured(apiName) {
    const thunk = this.apiThunks.get(apiName);
    return !!thunk && this.mem.u8(thunk) === 0xe9;
  }

  /** Restore pristine prologue bytes recorded at defineApi time. */
  restorePrologue(apiName) {
    const thunk = this.apiThunks.get(apiName);
    const orig = this.pristineThunks.get(apiName);
    if (!thunk || !orig) return false;
    this.mem.write(thunk, [...orig]);
    return true;
  }

  _wireApiHooks() {
    const k = this;
    this.defineApi("DbgPrint", function (fmtAddr, ...args) {
      k.dbgPrint(fmtAddr, args);
      return 0n;
    });
    this.defineApi("ExAllocatePoolWithTag", function (poolType, size, tag) {
      const tagStr = String.fromCharCode(
        Number(tag & 0xffn), Number((tag >> 8n) & 0xffn),
        Number((tag >> 16n) & 0xffn), Number((tag >> 24n) & 0xffn),
      );
      return k.allocPool(Number(size), tagStr);
    });
    this.defineApi("ExFreePoolWithTag", function (addr, _tag) {
      k.freePool(addr);
      return undefined;
    });
    this.defineApi("PsLookupProcessByProcessId", function (pid, outPtr) {
      const found = k.findEprocessByPid(pid);
      if (found === null) return 0xc000000bn; // STATUS_INVALID_PARAMETER-ish
      k.mem.w64(outPtr, found);
      return 0n;
    });
    this.defineApi("KeGetCurrentIrql", function () {
      return BigInt(k.currentIrql ?? 2); // DISPATCH_LEVEL default in our labs
    });
  }

  dbgPrint(fmtAddr, args) {
    const fmt = this.mem.readAnsi(fmtAddr, 512);
    let ai = 0;
    // Length modifiers are parsed so the argument is consumed exactly once:
    // %I64u (MSVC spelling), %llu/%lld and %llx all render their full 64-bit
    // value instead of printing the literal suffix and desyncing every later
    // %-conversion in the same string (issue #13).
    const out = fmt.replace(
      /%(-?\d+)?(?:\.(\d+))?(I(?:32|64)|l{1,2})?([diuxXpsZwcg])/g,
      (_m, _w, _p, mod, conv) => {
        void _p;
        const wide = !!mod;
        const v = args[ai++] ?? 0n;
        switch (conv) {
          case "d": return BigInt.asIntN(64, v).toString();
          case "u": return v.toString();
          case "x": case "X": {
            const width = wide ? 16 : 8;
            const digits = v.toString(16);
            const padded = digits.padStart(width, conv === "X" ? "F" : "0");
            return conv === "X" ? padded.slice(-width).toUpperCase() : padded.slice(-width);
          }
          case "p": return v === 0n ? "0000000000000000" : v.toString(16).padStart(16, "0");
          case "w": case "Z": {
            // %wZ = UNICODE_STRING*
            const usLen = this.mem.u16(v);
            const buf = this.mem.u64(v + 8n);
            return this.mem.readUtf16(buf, usLen / 2);
          }
          case "s": return this.mem.readAnsi(v);
          default: return `%${conv}`;
        }
      });
    this.debugPrint(out);
    return out;
  }

  /** Buffer a pre-formatted line and fire the live sink. Used by the DbgPrint
   *  API thunk and by lab fixtures that speak in a driver's voice without
   *  going through the guest's formatter. */
  debugPrint(line) {
    this.dbgLog.push(line);
    this.emitTrace({ kind: "dbgprint", text: line });
    if (this.onDebugPrint) {
      try { this.onDebugPrint(line); } catch { /* sink must not kill execution */ }
    }
  }

  /**
   * Append a chronological trace event (capped). Decoding/pretty-printing
   * lives in tracer.mjs; the kernel only records raw facts.
   * @param {{kind: string, [k: string]: any}} evt
   */
  emitTrace(evt) {
    if (this.traceEvents.length >= this.traceLimit) return;
    this.traceEvents.push({
      seq: ++this.traceSeq,
      phase: this.tracePhase,
      ...evt,
    });
  }

  findEprocessByPid(pid) {
    const t = this.tables;
    let cur = this.mem.u64(this.PsActiveProcessHead); // first LINKS
    const head = this.PsActiveProcessHead;
    while (cur !== head && cur !== 0n) {
      const eproc = cur - t.offsetOf("_EPROCESS", "ActiveProcessLinks");
      if (this.mem.u64(eproc + t.offsetOf("_EPROCESS", "UniqueProcessId")) === pid) {
        return eproc;
      }
      cur = this.mem.u64(cur);
    }
    return null;
  }

  // ------------------------------------------------------------ debug exc

  /**
   * Register a modeled vectored exception handler (VEH). Handlers run in
   * registration order; return true from fn to claim the event.
   * @param {string} name display name, e.g. "kftrace!TraceVeh"
   * @param {(info: {code: string, rip: bigint}) => boolean} fn
   */
  registerVectoredHandler(name, fn) {
    const entry = { name, fn };
    this.vectoredHandlers.push(entry);
    return entry;
  }

  /**
   * Deliver a debug exception (#DB family, e.g. EXCEPTION_SINGLE_STEP):
   * an attached tracer intercepts FIRST — the guest VEH list is starved,
   * which is precisely how Variant B anti-tracing detects analysis — and
   * only otherwise do registered vectored handlers get the event.
   * @returns {boolean} true if handled (execution continues seamlessly)
   */
  deliverDebugException(info = {}) {
    const ev = {
      code: String(info.code ?? "EXCEPTION_SINGLE_STEP"),
      rip: BigInt(info.rip ?? this.cpu.rip ?? 0n),
    };
    this.traceStats.int1Raised++;
    if (this.tracer?.attached) {
      this.traceStats.swallowedByTracer++;
      this.dbgLog.push(
        `nt: ${ev.code} @ 0x${ev.rip.toString(16)} intercepted by attached tracer`);
      return true;
    }
    for (const h of this.vectoredHandlers) {
      let handled = false;
      try { handled = h.fn(ev) === true; } catch (e) {
        this.dbgLog.push(`[veh] ${h.name} threw: ${e.message}`);
      }
      if (handled) {
        this.traceStats.vehHandled++;
        return true;
      }
    }
    this.dbgLog.push(`nt: unhandled ${ev.code} @ 0x${ev.rip.toString(16)}`);
    return false;
  }

  _installDebugExceptionHook() {
    this.cpu.onDebugException = (info) => this.deliverDebugException(info);
  }

  // ------------------------------------------------------------ driver exec

  _installCpuHook() {
    const handler = (rip) => {
      const T = this.bases.thunk;
      if (rip < T || rip >= T + 0x10000000n) return false;
      // find which api
      for (const [name, addr] of this.apiThunks) {
        if (addr === rip) {
          // windows x64 ABI: rcx rdx r8 r9, then stack args above the
          // return address + 32-byte shadow space ([rsp+0x28..]) — needed
          // for varargs (DbgPrintEx, sprintf) and >4-arg exports.
          const rsp = this.cpu.regs.rsp;
          const args = [
            this.cpu.regs.rcx, this.cpu.regs.rdx,
            this.cpu.regs.r8, this.cpu.regs.r9,
          ];
          for (let j = 0; j < 7; j++) {
            try { args.push(this.cpu.mem.u64(rsp + 0x28n + BigInt(8 * j))); } catch { args.push(0n); }
          }
          const retAddr = this.cpu.mem.u64(rsp);
          // IRQL contract: Zw*/Nt* require PASSIVE_LEVEL; log violations
          if ((name.startsWith("Zw") || name.startsWith("Nt")) && (this.currentIrql ?? 0) > 1) {
            this.irqlViolations.push({ name, irql: this.currentIrql });
            this.dbgLog.push(`[irql] ${name} called at IRQL ${this.currentIrql} (> APC_LEVEL)`);
          }
          const savedRax = this.cpu.regs.rax;
          const ret = this.apiImpls.get(name)(...args);
          // VOID: leave RAX untouched (Speakeasy & hedgehog-tools/ktrace do the same;
          // x64 ABI says caller-owned register is undefined after void call).
          const meta = this.apiMeta.get(name);
          const isVoid = meta?.ret === "void";
          if (isVoid) {
            // preserve caller RAX; ret remains undefined for trace suppression
            this.cpu.regs.rax = savedRax & M64;
          } else {
            // non-void: undefined impl is treated as 0 (STATUS_SUCCESS placeholder)
            if (ret === undefined) this.cpu.regs.rax = 0n;
            else this.cpu.regs.rax = typeof ret === "bigint" ? (ret & M64) : BigInt(ret);
          }
          this.cpu.regs.rsp = (rsp + 8n) & M64; // pop return address slot
          this.cpu.rip = retAddr;
          if (this.apiTrace.length < this.apiTraceLimit) {
            this.apiTrace.push({
              name,
              args: args.map((a) => a & M64),
              ret: isVoid ? undefined : this.cpu.regs.rax,
              retAddr,
            });
          }
          this.emitTrace({
            kind: "api",
            name,
            args: args.slice(0, 8).map((a) => a & M64),
            ret: isVoid ? undefined : this.cpu.regs.rax,
            retAddr: retAddr & M64,
            irql: this.currentIrql ?? 0,
          });
          return true;
        }
      }
      return false;
    };
    if (typeof this.cpu.addCodeHook === "function") {
      this.cpu.addCodeHook(handler, this.bases.thunk, this.bases.thunk + 0x10000000n);
    } else {
      this.cpu.onCodeHook = handler;
    }
  }

  /** Invoke DriverEntry(driverObj, registryPath) on a mapped driver image. */
  callDriverEntry(entryAddr, driverObjectAddr = 0n, regPathAddr = 0n) {
    this.currentIrql = 2;
    const r = this.callFunctionSeh
      ? this.callFunctionSeh(entryAddr, [driverObjectAddr, regPathAddr])
      : this.cpu.callFunction(entryAddr, [driverObjectAddr, regPathAddr]);
    return r;
  }

  /**
   * callFunction with table-SEH fallback: on backend fault, attempt scope-
   * table dispatch for the given image; a handled exception re-enters the
   * __except handler as its own ABI call. Requires `image` {base, bytes}.
   */
  callFunctionSeh(addr, args = [], image = null) {
    const r = this.cpu.callFunction(addr, args);
    if (r.status !== "fault" || !image) return r;
    let dispatch;
    try {
      dispatch = tryDispatchException(this, image, r.error);
    } catch {
      return r; // malformed unwind data -> report the raw fault
    }
    this.exceptionTrace.push({
      faultRip: "0x" + (r.error?.rip ?? 0n).toString(16),
      handled: !!dispatch.handled,
      detail: dispatch.detail,
    });
    this.emitTrace({
      kind: "exception",
      faultRip: r.error?.rip ?? 0n,
      message: String(r.error?.message ?? r.error ?? ""),
      handled: !!dispatch.handled,
      detail: dispatch.detail,
    });
    if (!dispatch.handled) return r;
    return {
      status: "ok",
      retval: dispatch.ntstatus ?? dispatch.result?.retval ?? 0n,
      sehHandled: true,
      sehDetail: dispatch.detail,
    };
  }

  // ------------------------------------------------------- deferred phases

  /**
   * Drain queued DPCs / work items / APCs left behind by the driver.
   * DPCs use the queueDpc record model (drained flag + onDpcDrain callback,
   * fired once per record); every routine is ALSO invoked through the CPU —
   * the analyzer needs real execution, not just retirement. Bounded:
   * at most `maxPasses` sweeps so requeueing drivers can't spin forever.
   * @returns {{dpcs:number, workItems:number, apcs:number}}
   */
  drainDeferred(maxPasses = 8) {
    const counts = { dpcs: 0, workItems: 0, apcs: 0, threads: 0 };
    for (let pass = 0; pass < maxPasses; pass++) {
      const dpcs = this.pendingDpcs.filter((d) => !d.drained);
      this.pendingDpcs.forEach((d) => { d.drained = true; });
      const work = this.pendingWorkItems.splice(0);
      const apcs = this.pendingApcs.splice(0);
      const threads = this.pendingThreads.splice(0);
      if (!dpcs.length && !work.length && !apcs.length && !threads.length) break;

      for (const d of dpcs) {
        counts.dpcs++;
        this.dbgLog.push(`nt: KiRetireDpcList: DPC @ ${d.dpcVa.toString(16)} fired`);
        this.emitTrace({ kind: "dpc", routine: d.routine ?? 0n, context: d.context ?? 0n, detail: "fired" });
        try { this.onDpcDrain?.(d); } catch (e) { this.dbgLog.push(`[dpc] callback threw: ${e.message}`); }
        const routine = this.liveDpcRoutine(d) || d.routine;
        if (!routine) continue;
        const r = this.cpu.callFunction(routine, [d.dpcVa ?? 0n, this.liveDpcContext(d), 0n, 0n]);
        this.dbgLog.push(`[dpc] routine 0x${routine.toString(16)} -> ${r.status}`);
        this.emitTrace({ kind: "dpc", routine, context: d.context ?? 0n, detail: `-> ${r.status}` });
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "dpc", detail: r.status });
      }
      for (const w of work) {
        counts.workItems++;
        this.emitTrace({ kind: "workitem", worker: w.worker, context: w.context ?? 0n });
        const r = this.cpu.callFunction(w.worker, [w.device ?? 0n, w.context ?? 0n]);
        this.dbgLog.push(`[work] worker 0x${w.worker.toString(16)} -> ${r.status}`);
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "work", detail: r.status });
      }
      for (const a of apcs) {
        counts.apcs++;
        this.emitTrace({ kind: "apc", routine: a.normalRoutine, context: a.normalContext ?? 0n });
        const r = this.cpu.callFunction(a.normalRoutine, [a.normalContext ?? 0n, a.systemArgument1 ?? 0n, a.systemArgument2 ?? 0n]);
        this.dbgLog.push(`[apc] normalRoutine 0x${a.normalRoutine.toString(16)} -> ${r.status}`);
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "apc", detail: r.status });
      }
      for (const t of threads) {
        counts.threads++;
        this.dbgLog.push(`[thread] system thread 0x${t.handle.toString(16)} start routine 0x${t.startRoutine.toString(16)}`);
        this.emitTrace({
          kind: "thread",
          handle: t.handle,
          startRoutine: t.startRoutine,
          startContext: t.startContext ?? 0n,
          detail: "start (PsCreateSystemThread)",
        });
        const prevPhase = this.tracePhase;
        this.tracePhase = `${prevPhase}:thread`;
        const r = this.cpu.callFunction(t.startRoutine, [t.startContext ?? 0n]);
        this.tracePhase = prevPhase;
        this.dbgLog.push(`[thread] start routine 0x${t.startRoutine.toString(16)} -> ${r.status}`);
        this.emitTrace({ kind: "thread", handle: t.handle, startRoutine: t.startRoutine, detail: `-> ${r.status}`, error: r.error?.message ?? null });
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "thread", detail: r.status });
      }
    }
    this.deferredDrain = counts;
    return counts;
  }

  // ------------------------------------------------------------ introspection

  /**
   * Materialize backing for the module image range [base, base+size) so
   * debugger reads (db/dq/s/!dh/u) and guest fetches see a fully mapped
   * region instead of "unmapped" holes between evidence pages.
   * Idempotent per page. When the CPU backend exposes mapRange() (Unicorn),
   * the same span is pre-mapped in the emulator's address space so
   * `lm`-listed modules are executable/readable without waiting for a run's
   * demand sync.
   *
   * Callers should invoke this whenever a module is appended to
   * loadedModules. Real dump modules are deliberately NOT materialized —
   * their non-resident ranges are pedagogically meaningful.
   * @param {bigint} base
   * @param {bigint|number} size
   * @param {{fill?: number}} [opts] fill byte for newly materialized pages (default 0xCC for debugger trap; analyzer uses 0x00 for Windows-accurate BSS/inter-section gaps)
   * @returns {number} pages materialized (0 when everything was backed)
   */
  materializeModuleRange(base, size, opts = {}) {
    const fill = opts.fill !== undefined ? (opts.fill & 0xff) : 0xcc;
    const start = BigInt(base) & ~0xfffn;
    const end = BigInt(base) + BigInt(size);
    if (end <= start) return 0;
    let fresh = 0;
    for (let p = start; p < end; p += 0x1000n) {
      if (!this.mem.hasPage(p)) {
        // Windows loader zero-fills BSS; debugger scenarios historically used
        // int3 (0xCC) so stray execution halts loudly. Caller chooses.
        this.mem.write(p, new Uint8Array(0x1000).fill(fill));
        fresh++;
      }
    }
    if (typeof this.cpu?.mapRange === "function") {
      try { this.cpu.mapRange(start, end - start); } catch { /* optional */ }
    }
    return fresh;
  }

  listProcesses() {
    const t = this.tables;
    const out = [];
    let cur = this.mem.u64(this.PsActiveProcessHead);
    const head = this.PsActiveProcessHead;
    while (cur !== head && cur !== 0n) {
      const eproc = cur - t.offsetOf("_EPROCESS", "ActiveProcessLinks");
      const pid = this.mem.u64(eproc + t.offsetOf("_EPROCESS", "UniqueProcessId"));
      const nameOff = eproc + t.offsetOf("_EPROCESS", "ImageFileName");
      const name = this.mem.readAnsi(nameOff, 15);
      out.push({ pid, name, eprocess: eproc });
      cur = this.mem.u64(cur);
    }
    return out;
  }
}

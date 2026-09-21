/**
 * sysquery.mjs — NtQuerySystemInformation virtualization.
 *
 * The analyzer answer set ported from KEVLAR's nt_query.cpp:
 *   - SystemModuleInformation (0x0B) / ...Ex (0x4D): synthesized from the
 *     emulated module lists with VM/AC-module blacklist filtering and
 *     emulated-base rewriting, plus optional fake-module injection.
 *   - SystemTimeOfDayInformation (0x03): virtual boot/current time.
 *   - SystemBootEnvironmentInformation (0x5A): UEFI identity.
 *   - SystemCodeIntegrityPolicyInformation (0x91): HVCI off.
 *   - SystemHypervisorSharedPageInformation (0xC5): HV page VA.
 *   - SystemBasicInformation (0x00), SystemKernelDebuggerInformation (0x23),
 *     SystemFirmwareTableInformation (0x4C/0x67): small static answers.
 *   - SystemHandleInformation (0x10) / ...Extended (0x40): unchanged from
 *     winapi-ext (EDR cross-reference source).
 *
 * Every response is synthesized from emulator state — no host NT calls, so
 * the same code runs in Node and browser workers.
 */

import { M64 } from "./cpu.mjs";
import { HV_SHARED_PAGE } from "./arch.mjs";

export const SYSINFO = {
  SystemBasicInformation: 0x00,
  SystemTimeOfDayInformation: 0x03,
  SystemModuleInformation: 0x0b,
  SystemHandleInformation: 0x10,
  SystemKernelDebuggerInformation: 0x23,
  SystemExtendedHandleInformation: 0x40,
  SystemFirmwareTableInformation: 0x4c,
  SystemModuleInformationEx: 0x4d,
  SystemBootEnvironmentInformation: 0x5a,
  SystemCodeIntegrityInformation: 0x67,
  SystemCodeIntegrityPolicyInformation: 0x91,
  SystemHypervisorSharedPageInformation: 0xc5,
};

export const STATUS_SUCCESS = 0x00000000n;
export const STATUS_INFO_LENGTH_MISMATCH = 0xc0000004n;
export const STATUS_INVALID_INFO_CLASS = 0xc0000003n;
export const STATUS_BUFFER_TOO_SMALL = 0xc0000023n;

/** RTL_PROCESS_MODULE_INFORMATION (x64) is 0x128 bytes; FullPathName[256]. */
export const MODULE_INFO_SIZE = 0x128;
/** RTL_PROCESS_MODULE_INFORMATION_EX prepends NextOffset/Checksum/TimeDate. */
export const MODULE_EX_SIZE = 0x130;

/** KEVLAR's VM/hypervisor/AC filter list (module-list hygiene). */
export const DEFAULT_VM_BLACKLIST =
  /(vmci|vmx86|vbox(vm|guest|mouse|srv|usb|sf|camera|video)|vm3dmp|vmusb|vmrawdsk|vmscsi|vmnet|vmwv|hgfs|vmware|virtualbox|parsecvusba|faceit_ac|vgk|vgkbootstatus|easyanticheat|easyanti|battleye|bedaisy|beservice|hypervideo)/i;

const basename = (p) => String(p ?? "").split(/[\\/]/).pop() || "";

/**
 * Collect the emulated module list in load order, deduped by basename.
 * Entries from `kernel.loadedDrivers` (boot seeds) and `kernel.loadedModules`
 * (compiled fixtures) share the {name, base, imageSize|sizeOfImage} shape.
 */
export function collectModules(kernel) {
  const out = [];
  const seen = new Set();
  const push = (m) => {
    const name = basename(m.name);
    if (!name || seen.has(name.toLowerCase())) return;
    seen.add(name.toLowerCase());
    out.push({
      name,
      full: m.full ?? `\\SystemRoot\\System32\\drivers\\${name}`,
      base: BigInt(m.base ?? 0n) & M64,
      size: Number(m.imageSize ?? m.sizeOfImage ?? m.size ?? 0x1000),
    });
  };
  for (const m of kernel.loadedDrivers ?? []) push(m);
  for (const m of kernel.loadedModules ?? []) push(m);
  return out;
}

/** Apply blacklist/keep rules + optional injection to a module list. */
export function filterModules(modules, state) {
  const keep = state.keep;
  const out = modules.filter((m) => {
    if (keep.some((re) => re.test(m.name))) return true;
    return !state.blacklist.test(m.name);
  });
  for (const m of state.extraModules ?? []) {
    if (!out.some((x) => x.name.toLowerCase() === m.name.toLowerCase())) out.push({ ...m });
  }
  if (state.inject && !out.some((m) => m.name.toLowerCase() === state.inject.name.toLowerCase())) {
    out.push({ ...state.inject });
  }
  return out;
}

function writeModuleInfo(mem, at, mod, index) {
  mem.write(at, new Uint8Array(MODULE_INFO_SIZE));
  mem.w64(at + 0x00n, 0n);                    // Section
  mem.w64(at + 0x08n, 0n);                    // MappedBase
  mem.w64(at + 0x10n, mod.base & M64);        // ImageBase
  mem.w32(at + 0x18n, mod.size >>> 0);        // ImageSize
  mem.w32(at + 0x1cn, 0);                     // Flags
  mem.w16(at + 0x20n, index);                 // LoadOrderIndex
  mem.w16(at + 0x22n, index);                 // InitOrderIndex
  mem.w16(at + 0x24n, 1);                     // LoadCount
  const off = Math.max(0, mod.full.lastIndexOf("\\") + 1);
  mem.w16(at + 0x26n, off);                   // OffsetToFileName
  mem.writeAnsi(at + 0x28n, mod.full, 256);   // FullPathName
}

function queryModuleInfo(kernel, modules, out, len, retLen) {
  const mem = kernel.mem;
  const needed = 8n + BigInt(modules.length) * BigInt(MODULE_INFO_SIZE);
  if (retLen) mem.w64(retLen, needed);
  if (!out || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
  mem.w32(out, modules.length);
  mem.w32(out + 4n, 0);
  modules.forEach((m, i) =>
    writeModuleInfo(mem, out + 8n + BigInt(i * MODULE_INFO_SIZE), m, i));
  return STATUS_SUCCESS;
}

function queryModuleInfoEx(kernel, modules, out, len, retLen) {
  const mem = kernel.mem;
  const needed = 8n + BigInt(modules.length) * BigInt(MODULE_EX_SIZE);
  if (retLen) mem.w64(retLen, needed);
  if (!out || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
  mem.w32(out, modules.length);
  mem.w32(out + 4n, 0);
  modules.forEach((m, i) => {
    const at = out + 8n + BigInt(i * MODULE_EX_SIZE);
    const next = i === modules.length - 1 ? 0 : MODULE_EX_SIZE;
    mem.w16(at, next);      // NextOffset (relative to this entry)
    mem.w16(at + 2n, 0);    // ImageChecksum
    mem.w32(at + 4n, 0);    // TimeDateStamp
    writeModuleInfo(mem, at + 8n, m, i);
  });
  return STATUS_SUCCESS;
}

function writeKSYSTEMTIME(mem, at, v) {
  const b = BigInt.asUintN(64, BigInt(v));
  mem.w32(at, Number(b & 0xffffffffn));
  mem.w32(at + 4n, Number((b >> 32n) & 0xffffffffn));
}

/**
 * Install the virtualized NtQuerySystemInformation/ZwQuerySystemInformation.
 * @param {object} kernel
 * @param {{blacklist?: RegExp, keep?: string[], injectModule?: {name, base, size}|null,
 *          rewriteBases?: boolean, bootTime?: bigint, bootIdentifier?: Uint8Array}} opts
 */
export function installSysQuery(kernel, opts = {}) {
  if (kernel.sysQuery) return kernel;

  const state = {
    blacklist: opts.blacklist ?? DEFAULT_VM_BLACKLIST,
    keep: (opts.keep ?? []).map((s) => new RegExp(
      s instanceof RegExp ? s.source : String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i")),
    inject: opts.injectModule === undefined
      ? (kernel.arch?.hypervisor
        ? { name: "hypervideo.sys", full: "\\SystemRoot\\System32\\drivers\\hypervideo.sys", base: 0xfffff80301000000n, size: 0x15000 }
        : null)
      : opts.injectModule,
    rewriteBases: opts.rewriteBases !== false,
    bootTime: BigInt(opts.bootTime ?? 133_790_000_000_000_000n),
    queries: new Map(),
    unmodeled: [],
    /** modules added at runtime (the analyzed driver's LDR entry) */
    extraModules: [],
  };
  kernel.sysQuery = state;

  /** Register an extra module (the analyzed driver) into the virtual list. */
  state.addModule = (mod) => {
    const m = {
      name: basename(mod.name),
      full: mod.full ?? `\\SystemRoot\\System32\\drivers\\${basename(mod.name)}`,
      base: BigInt(mod.base ?? 0n) & M64,
      size: Number(mod.size ?? mod.imageSize ?? 0x1000),
    };
    const existing = state.extraModules.find((x) => x.name.toLowerCase() === m.name.toLowerCase());
    if (existing) Object.assign(existing, m);
    else state.extraModules.push(m);
    return m;
  };

  const now100ns = () => kernel.arch?.now100ns() ?? (kernel.tickCount ?? 0n) * 100_000n;

  const impl = (cls, sysInfo, len, retLen) => {
    const c = Number(BigInt.asUintN(32, BigInt(cls)));
    state.queries.set(c, (state.queries.get(c) ?? 0) + 1);
    const mem = kernel.mem;

    switch (c) {
      case SYSINFO.SystemBasicInformation: {
        const needed = 0x40n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.write(sysInfo, new Uint8Array(0x40));
        mem.w32(sysInfo + 0x04n, 156250);          // TimerResolution (100ns)
        mem.w32(sysInfo + 0x08n, 4096);            // PageSize
        mem.w32(sysInfo + 0x0cn, 0x200000);        // NumberOfPhysicalPages
        mem.w32(sysInfo + 0x10n, 0x100);           // LowestPhysicalPageNumber
        mem.w32(sysInfo + 0x14n, 0x2000ff);        // HighestPhysicalPageNumber
        mem.w32(sysInfo + 0x18n, 0x10000);         // AllocationGranularity
        mem.w64(sysInfo + 0x20n, 0x10000n);        // MinimumUserModeAddress
        mem.w64(sysInfo + 0x28n, 0x7ffffffeffffn); // MaximumUserModeAddress
        mem.w64(sysInfo + 0x30n, 0xfn);            // ActiveProcessorsAffinityMask
        mem.w8(sysInfo + 0x38n, 4);                // NumberOfProcessors
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemTimeOfDayInformation: {
        const needed = 0x30n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.write(sysInfo, new Uint8Array(0x30));
        const boot = state.bootTime;
        const current = boot + now100ns();
        mem.w64(sysInfo + 0x00n, boot);    // BootTime
        mem.w64(sysInfo + 0x08n, current); // CurrentTime
        mem.w64(sysInfo + 0x10n, 0n);      // TimeZoneBias
        mem.w32(sysInfo + 0x18n, 0);       // TimeZoneId
        mem.w32(sysInfo + 0x1cn, 0);       // Reserved
        mem.w64(sysInfo + 0x20n, 0n);      // BootTimeBias
        mem.w64(sysInfo + 0x28n, 0n);      // SleepTimeBias
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemModuleInformation: {
        const modules = filterModules(collectModules(kernel), state);
        return queryModuleInfo(kernel, modules, sysInfo, len, retLen);
      }

      case SYSINFO.SystemModuleInformationEx: {
        const modules = filterModules(collectModules(kernel), state);
        return queryModuleInfoEx(kernel, modules, sysInfo, len, retLen);
      }

      case SYSINFO.SystemKernelDebuggerInformation: {
        const needed = 2n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.w8(sysInfo, 0);     // DebuggerEnabled = FALSE
        mem.w8(sysInfo + 1n, 1); // DebuggerNotPresent = TRUE
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemBootEnvironmentInformation: {
        const needed = 0x20n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.write(sysInfo, new Uint8Array(0x20));
        const guid = opts.bootIdentifier ?? Uint8Array.from([
          0x6b, 0x66, 0x62, 0x6f, 0x6f, 0x74, 0x67, 0x75,
          0x69, 0x64, 0x2d, 0x30, 0x30, 0x30, 0x31, 0x00,
        ]);
        mem.write(sysInfo, guid.subarray(0, 16));
        mem.w32(sysInfo + 0x10n, 2); // FirmwareType = Uefi
        mem.w64(sysInfo + 0x18n, 1n); // BootFlags
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemCodeIntegrityInformation: {
        const needed = 0x10n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.write(sysInfo, new Uint8Array(0x10));
        mem.w32(sysInfo + 0x00n, 1); // CodeIntegrityOptions = enabled
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemCodeIntegrityPolicyInformation: {
        const needed = 0x28n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.write(sysInfo, new Uint8Array(0x28));
        // Options = enabled-with-whql; HVCI fields all off (Kevlar's answer)
        mem.w32(sysInfo + 0x00n, 1); // Options
        mem.w32(sysInfo + 0x04n, 0); // HVCIEnabled
        mem.w32(sysInfo + 0x08n, 0); // HVCIStrictMode
        mem.w32(sysInfo + 0x0cn, 0); // HVCIProtectedProcess
        mem.w32(sysInfo + 0x10n, 0); // HVCIKernelMode
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemHypervisorSharedPageInformation: {
        const needed = 8n;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        mem.w64(sysInfo, kernel.arch?.hvspReady ? HV_SHARED_PAGE : 0n);
        return STATUS_SUCCESS;
      }

      case SYSINFO.SystemFirmwareTableInformation: {
        // SYSTEM_FIRMWARE_TABLE_INFORMATION {
        //   ULONG ProviderSignature; ULONG Action; ULONG TableID;
        //   ULONG TableBufferLength; UCHAR TableBuffer[]; }
        if (!sysInfo || BigInt(len) < 0x10n) {
          if (retLen) mem.w64(retLen, 0n);
          return STATUS_INFO_LENGTH_MISMATCH;
        }
        const action = mem.u32(sysInfo + 4n);
        const table = firmwareTable(mem.u32(sysInfo));
        if (action === 0) { // GetTableSize
          mem.w32(sysInfo + 0x0cn, table.length);
          return STATUS_SUCCESS;
        }
        if (action === 1) { // GetTable
          const capacity = mem.u32(sysInfo + 0x0cn);
          if (capacity < table.length) return STATUS_BUFFER_TOO_SMALL;
          mem.write(sysInfo + 0x10n, table);
          mem.w32(sysInfo + 0x0cn, table.length);
          return STATUS_SUCCESS;
        }
        return STATUS_INVALID_INFO_CLASS;
      }

      case SYSINFO.SystemHandleInformation:
      case SYSINFO.SystemExtendedHandleInformation: {
        const SYS_HANDLE_ENTRY_SIZE = 24n;
        const entries = kernel.objectHandles ?? [];
        const needed = 8n + BigInt(entries.length || 1) * SYS_HANDLE_ENTRY_SIZE;
        if (retLen) mem.w64(retLen, needed);
        if (!sysInfo || BigInt(len) < needed) return STATUS_INFO_LENGTH_MISMATCH;
        const pidOff = (() => {
          try { return kernel.tables.offsetOf("_EPROCESS", "UniqueProcessId"); } catch { return null; }
        })();
        const pidOf = (eproc) => pidOff === null ? 0 : Number(mem.u32(eproc + pidOff));
        mem.w32(sysInfo, entries.length);
        mem.w32(sysInfo + 4n, 0);
        let off2 = 8n;
        for (const h of entries) {
          mem.w32(sysInfo + off2, pidOf(h.ownerEproc));
          mem.w32(sysInfo + off2 + 4n, 0);                 // HandleAttributes
          mem.w32(sysInfo + off2 + 8n, h.grantedAccess >>> 0);
          mem.w16(sysInfo + off2 + 12n, Number(h.handle & 0xffffn));
          mem.w16(sysInfo + off2 + 14n, 0);                // CreatorBackTraceIndex
          mem.w64(sysInfo + off2 + 16n, h.targetEproc);    // Object
          off2 += SYS_HANDLE_ENTRY_SIZE;
        }
        kernel.dbgLog.push(`[winapi] SystemHandleInformation: ${entries.length} handle(s) enumerated`);
        return STATUS_SUCCESS;
      }

      default: {
        state.unmodeled.push(c);
        kernel.dbgLog.push(
          `[winapi] ZwQuerySystemInformation(class ${c}) unmodeled -> STATUS_INVALID_INFO_CLASS`);
        return STATUS_INVALID_INFO_CLASS;
      }
    }
  };

  kernel.defineApi("ZwQuerySystemInformation", impl);
  kernel.defineApi("NtQuerySystemInformation", impl);

  state.summary = () => ({
    queries: Object.fromEntries(
      [...state.queries.entries()].map(([c, n]) => [`0x${c.toString(16)}`, n]),
    ),
    unmodeledClasses: [...new Set(state.unmodeled)].map((c) => `0x${c.toString(16)}`),
    moduleList: filterModules(collectModules(kernel), state).map((m) => ({
      name: m.name, base: `0x${m.base.toString(16)}`, size: m.size,
    })),
    injected: state.inject ? state.inject.name : null,
  });

  return kernel;
}

/** Tiny deterministic SMBIOS entry point ("_SM_"/"_SM3_") for RSMB queries. */
function firmwareTable(signature) {
  const sig = signature >>> 0;
  if (sig === 0x52534d42) { // 'RSMB' (little-endian "BMSR")
    const t = new Uint8Array(0x1f);
    t.set([0x5f, 0x53, 0x4d, 0x5f], 0); // "_SM_"
    t[5] = 0x1f;                          // entry point length
    t[6] = 2; t[7] = 8;                   // version 2.8
    return t;
  }
  if (sig === 0x50434146) return new Uint8Array(36); // 'FACP'
  return new Uint8Array(0);
}

/**
 * integrity.mjs — post-run kernel integrity scanners (mechanism, no policy).
 *
 * These provide *verified negatives* for analysis reports: rather than asking
 * a classifier to infer "no DKOM / no SSDT hook / no IRP hook" from API
 * traces, the analyzer checks the emulated kernel state directly.
 *
 *   scanProcessList(kernel)      ActiveProcessLinks ring vs seeded EPROCESS set
 *   scanSsdt(kernel, table)      KiServiceTable entries vs their pristine thunks
 *   scanDispatchSlots(kernel)    MajorFunction slots pointing outside the driver
 *   scanIntegrity(kernel, opts)  all of the above, with availability flags
 *
 * Pure reads over SparseMemory; never mutates guest state.
 */

import { IRP_MJ_NAMES, IRP_MJ_COUNT, DRIVER_OBJECT } from "./devices.mjs";
import { installDispatchScan } from "./devices.mjs";

const MAX_PROCESS_WALK = 512;

/**
 * Walk the ActiveProcessLinks ring and compare it against the seeded process
 * set. Catches DKOM-style unlinking (a process the analyzer seeded but the
 * list no longer reaches) and broken/foreign links.
 * @param {object} kernel
 */
export function scanProcessList(kernel) {
  const mem = kernel?.mem;
  const tables = kernel?.tables;
  if (!mem || !tables?.has?.("_EPROCESS")) {
    return { available: false, reason: "no _EPROCESS tables" };
  }
  let linksOff;
  try { linksOff = BigInt(tables.offsetOf("_EPROCESS", "ActiveProcessLinks")); }
  catch { return { available: false, reason: "no ActiveProcessLinks offset" }; }
  const head = kernel.PsActiveProcessHead;
  if (!head) return { available: false, reason: "no PsActiveProcessHead" };

  // Ring entries are the ActiveProcessLinks FIELDS (head.Flink points at the
  // first process's links field), so the EPROCESS base is linksVa - linksOff.
  const reached = new Set();
  const reachedLinks = [];
  const brokenLinks = [];
  let linksVa = mem.u64(head);
  let walked = 0;
  let cycle = false;
  while (linksVa !== head && linksVa !== 0n && walked < MAX_PROCESS_WALK) {
    const eproc = linksVa - linksOff;
    reached.add(eproc);
    reachedLinks.push(linksVa);
    const flink = mem.u64(linksVa);
    const blink = mem.u64(linksVa + 8n);
    if (flink === 0n || blink === 0n) {
      brokenLinks.push({ at: `0x${eproc.toString(16)}`, reason: "null link" });
      break;
    }
    linksVa = flink;
    walked++;
    if (walked > MAX_PROCESS_WALK) { cycle = true; break; }
  }
  if (walked >= MAX_PROCESS_WALK) cycle = true;

  const seeded = [...(kernel.processesByName?.entries() ?? [])];
  const unlinked = seeded
    .filter(([, va]) => !reached.has(va))
    .map(([name]) => name);
  const seededSet = new Set(seeded.map(([, va]) => va));
  const foreign = [...reached].filter((va) => !seededSet.has(va))
    .map((va) => `0x${va.toString(16)}`);

  // Verify every reached entry's Blink points back at its predecessor's links
  // field (or at the list head for the first entry).
  for (const lv of reachedLinks) {
    const flink = mem.u64(lv);
    const back = flink === head ? mem.u64(head + 8n) : mem.u64(flink + 8n);
    if (back !== lv) {
      brokenLinks.push({
        at: `0x${(lv - linksOff).toString(16)}`,
        reason: `next.Blink=0x${back.toString(16)} != 0x${lv.toString(16)}`,
      });
    }
  }

  return {
    available: true,
    ok: unlinked.length === 0 && foreign.length === 0 && brokenLinks.length === 0 && !cycle,
    walked,
    seeded: seeded.length,
    unlinked,
    foreign,
    brokenLinks: brokenLinks.slice(0, 8),
    cycle,
  };
}

/**
 * Compare SSDT entries with the thunks the table was built from.
 * @param {object} kernel
 * @param {{entryVa:Function, entries:Array, isHooked?:Function}|null} table
 */
export function scanSsdt(kernel, table = null) {
  const mem = kernel?.mem;
  const svc = table ?? kernel?.serviceTable ?? null;
  if (!mem || !svc?.entries?.length) {
    return { available: false, reason: "no seeded service table" };
  }
  const arenaStart = kernel.bases?.thunk ?? 0n;
  const arenaEnd = arenaStart + 0x10000000n;
  const hooked = [];
  const foreignTargets = [];
  svc.entries.forEach((entry, index) => {
    let current;
    try { current = mem.u64(svc.entryVa(index)); } catch { return; }
    if (current !== entry.thunk) {
      hooked.push({
        index,
        name: entry.name,
        expected: `0x${entry.thunk.toString(16)}`,
        current: `0x${current.toString(16)}`,
      });
    } else if (current < arenaStart || current >= arenaEnd) {
      foreignTargets.push({ index, name: entry.name, target: `0x${current.toString(16)}` });
    }
  });
  return {
    available: true,
    ok: hooked.length === 0,
    total: svc.entries.length,
    hooked,
    foreignTargets,
  };
}

/**
 * MajorFunction slots pointing outside the owning driver image (IRP hooks).
 * @param {object} kernel
 */
export function scanDispatchSlots(kernel) {
  const mem = kernel?.mem;
  if (!mem) return { available: false, reason: "no memory" };
  try { installDispatchScan(kernel); } catch { /* best effort */ }
  if (typeof kernel?.scanForeignDispatch !== "function") {
    return { available: false, reason: "dispatch scan unavailable" };
  }
  const foreign = kernel.scanForeignDispatch().map((f) => ({
    driver: f.drvRec?.name ?? "?",
    major: f.code,
    majorName: f.codeName ?? IRP_MJ_NAMES[f.code] ?? `0x${f.code.toString(16)}`,
    handler: `0x${BigInt(f.handler).toString(16)}`,
    owner: f.owner ?? null,
  }));
  return {
    available: true,
    ok: foreign.length === 0,
    checked: (kernel.driverObjects?.size ?? 0) * IRP_MJ_COUNT,
    foreign,
  };
}

/**
 * Run every scanner.
 * @param {object} kernel
 * @param {{serviceTable?:object}} [opts]
 */
export function scanIntegrity(kernel, { serviceTable = null } = {}) {
  return {
    processList: scanProcessList(kernel),
    ssdt: scanSsdt(kernel, serviceTable),
    dispatch: scanDispatchSlots(kernel),
  };
}

export { DRIVER_OBJECT };

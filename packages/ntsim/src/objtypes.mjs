/**
 * objtypes.mjs — OBJECT_TYPE / OBJECT_TYPE_INITIALIZER modeling for NtKernel.
 *
 * Every kernel object type (Process, Thread, File, ...) carries a
 * _OBJECT_TYPE_INITIALIZER full of optional procedure pointers:
 * OpenProcedure, CloseProcedure, ParseProcedure, ... Drivers may register
 * these through documented APIs; rootkits overwrite them in place to filter
 * or deny object access below every handle-based check.
 *
 * Teaching anchor: these pointers live in pool memory and are NOT covered by
 * PatchGuard (PG guards SSDT/IDT/GDT/MSRs/nt code pages). Detection comes
 * from EDR kernel sensors that baseline each type's initializer at boot and
 * re-diff it, convicting any procedure pointing outside ntoskrnl/HAL/owner.
 *
 * Layouts (teaching subset, x64):
 *   _OBJECT_TYPE (0xb0):
 *     +0x00 Type/Size u32            (0x00020002, plausible header pair)
 *     +0x10 Name UNICODE_STRING      {u16 len, u16 max, pad, ptr}
 *     +0x28 TotalNumberOfObjects u32
 *     +0x40 _OBJECT_TYPE_INITIALIZER procedures (7 x u64):
 *       +0x40 OpenProcedure          (POPEN_PROCEDURE)
 *       +0x48 CloseProcedure
 *       +0x50 DeleteProcedure
 *       +0x58 ParseProcedure
 *       +0x60 SecurityProcedure
 *       +0x68 QueryNameProcedure
 *       +0x70 OkayToCloseProcedure
 */

export const OBJECT_TYPE_SIZE = 0xb0;
export const OBJ_TYPEINFO_OFFSET = 0x40;

/** Ordered initializer procedures, offset = OBJ_TYPEINFO_OFFSET + i*8. */
export const OBJ_PROCEDURES = [
  "OpenProcedure",
  "CloseProcedure",
  "DeleteProcedure",
  "ParseProcedure",
  "SecurityProcedure",
  "QueryNameProcedure",
  "OkayToCloseProcedure",
];

export function objProcVa(typeVa, procName) {
  const i = OBJ_PROCEDURES.indexOf(procName);
  if (i < 0) throw new Error(`objtypes: unknown procedure "${procName}"`);
  return typeVa + BigInt(OBJ_TYPEINFO_OFFSET + i * 8);
}

/**
 * Install the object-type registry onto an NtKernel instance. Idempotent.
 */
export function installObjectTypes(kernel) {
  if (kernel.objectTypes) return kernel;

  /** @type {Array<{name:string, va:bigint, baseline:Map<string,bigint>}>} */
  kernel.objectTypes = [];

  /**
   * Materialize an OBJECT_TYPE (+ initializer) as real bytes at a VA.
   * @returns {{name:string, va:bigint, baseline:Map<string,bigint>}}
   */
  kernel.defineObjectType = function defineObjectType(name, opts = {}) {
    const mem = kernel.mem;
    const va = opts.va ?? kernel.allocPool(OBJECT_TYPE_SIZE, "ObjT");
    mem.write(va, new Uint8Array(OBJECT_TYPE_SIZE));
    mem.w32(va, 0x00020002); // Type=2 (object type), Size pair

    // Name UNICODE_STRING embedded at +0x10, body behind the struct
    const bufVa = va + 0x90n;
    mem.writeUtf16(bufVa, name);
    mem.w16(va + 0x10n, name.length * 2);
    mem.w16(va + 0x12n, (name.length + 1) * 2);
    mem.w64(va + 0x18n, bufVa);
    mem.w32(va + 0x28n, Number(opts.objectCount ?? 12));

    const rec = { name, va, baseline: new Map() };
    for (const p of OBJ_PROCEDURES) {
      const cur = opts.procedures?.[p] ?? 0n;
      mem.w64(objProcVa(va, p), BigInt(cur));
      rec.baseline.set(p, BigInt(cur));
    }
    kernel.objectTypes.push(rec);
    return rec;
  };

  /** Overwrite one initializer procedure pointer (the hook primitive). */
  kernel.setObjectTypeProc = function setObjectTypeProc(typeRec, procName, target) {
    kernel.mem.w64(objProcVa(typeRec.va, procName), BigInt(target));
  };

  /** Restore one procedure (or all when procName omitted) from baseline. */
  kernel.restoreObjectTypeProcs = function restoreObjectTypeProcs(typeRec, procName = null) {
    let n = 0;
    for (const [p, base] of typeRec.baseline) {
      if (procName && p !== procName) continue;
      kernel.mem.w64(objProcVa(typeRec.va, p), base);
      n++;
    }
    return n;
  };

  /**
   * Diff live initializer pointers against baselines.
   * @returns {Array<{typeRec:{name:string}, procName:string, current:bigint,
   *                  baseline:bigint, owner:string|null}>}
   */
  kernel.scanObjectTypeHooks = function scanObjectTypeHooks() {
    const out = [];
    for (const t of kernel.objectTypes ?? []) {
      for (const p of OBJ_PROCEDURES) {
        const cur = kernel.mem.u64(objProcVa(t.va, p));
        const base = t.baseline.get(p) ?? 0n;
        if (cur === base) continue;
        out.push({
          typeRec: t,
          procName: p,
          current: cur,
          baseline: base,
          owner: containingModule(kernel, cur),
        });
      }
    }
    return out;
  };

  return kernel;
}

/** First loaded module whose image range contains `va`, else null. */
export function containingModule(kernel, va) {
  for (const m of kernel.loadedModules ?? []) {
    const size = Number(m.sizeOfImage ?? m.size ?? 0);
    if (!size) continue;
    const base = BigInt(m.base);
    if (va >= base && va < base + BigInt(size)) return m.name;
  }
  return null;
}

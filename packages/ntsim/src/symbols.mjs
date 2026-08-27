/**
 * symbols.mjs — Tier 2 Micro-Symbol Service for ntsim.
 *
 * Provides WinDbg-style symbol resolution without shipping a full PDB parser.
 * Three data sources, merged into one lookup surface:
 *
 *   1. Vergilius tables  → type layouts (field names/offsets/sizes per build)
 *   2. Dump header       → global symbol VAs (PsActiveProcessHead, etc.)
 *   3. PE export tables  → function addresses (from captured module images)
 *
 * All lookups accept WinDbg-style paths with optional module prefixes:
 *   nt!_EPROCESS          → type layout
 *   ntoskrnl!PsActiveProcessHead  → global VA
 *   _EPROCESS.UniqueProcessId     → single field descriptor
 */

const MODULE_PREFIX_RE = /^(?:nt|ntoskrnl|ntoskrnl\.exe|hal|hal\.dll)!/i;

/** Strip `nt!`, `ntoskrnl!`, etc. from a symbol path. */
export function stripPrefix(name) {
  return name.replace(MODULE_PREFIX_RE, "");
}

export class SymbolEngine {
  constructor() {
    /** @type {Map<string, object>} typeName → StructTables record */
    this.types = new Map();
    /** @type {Map<string, bigint>} globalName → VA */
    this.globals = new Map();
    /** @type {Map<string, Map<string, bigint>>} moduleName → (exportName → VA) */
    this.moduleExports = new Map();
    /** @type {object|null} raw dump metadata */
    this.dumpMeta = null;
  }

  // ------------------------------------------------------------- loaders

  /** Register struct types from a StructTables instance. */
  loadFromTables(tables) {
    if (!tables?.types) return;
    for (const [name, info] of tables.types) {
      this.types.set(name, info);
    }
  }

  /**
   * Register globals extracted from PAGEDU64 header + KDBG block.
   * @param {object} headerFields { psLoadedModuleList, psActiveProcessHead, dtb, … }
   */
  loadDumpGlobals(headerFields) {
    this.dumpMeta = headerFields;
    if (headerFields.psLoadedModuleList)
      this.globals.set("PsLoadedModuleList", BigInt(headerFields.psLoadedModuleList));
    if (headerFields.psActiveProcessHead)
      this.globals.set("PsActiveProcessHead", BigInt(headerFields.psActiveProcessHead));
    if (headerFields.directoryTableBase)
      this.globals.set("DirectoryTableBase", BigInt(headerFields.directoryTableBase));
    // Common KDBG-derived symbols (values filled by caller when known)
    if (headerFields.kernelBase)
      this.globals.set("KernelBase", BigInt(headerFields.kernelBase));
  }

  /**
   * Parse PE export table from guest memory for a loaded module.
   * @param {object} mem SparseMemory-like with canRead/read
   * @param {bigint} base module DllBase
   * @param {string} moduleName key for caching
   */
  loadModuleExports(mem, base, moduleName) {
    try {
      const exports = new Map();
      if (mem.u16(base) !== 0x5a4d) return; // MZ
      const e_lfanew = mem.u32(BigInt(base) + 0x3cn);
      const pe = BigInt(base) + BigInt(e_lfanew);
      if (mem.u32(pe) !== 0x00004550) return; // PE\0\0
      const opt = pe + 24n;
      const magic = mem.u16(opt);
      const numDirs = mem.u32(magic === 0x20b ? opt + 108n : opt + 92n);
      if (numDirs < 1) return;
      const exportDirRva = mem.u32((magic === 0x20b ? opt + 112n : opt + 96n));
      const exportDirSize = mem.u32((magic === 0x20b ? opt + 116n : opt + 100n));
      if (!exportDirRva || !exportDirSize) return;

      const exportBase = BigInt(base) + BigInt(exportDirRva);
      const numNames = mem.u32(exportBase + 0x20n);
      const addrOfNames = BigInt(base) + mem.u32(exportBase + 0x28n);
      const addrOfFuncs = BigInt(base) + mem.u32(exportBase + 0x1cn);

      for (let i = 0; i < Math.min(numNames, 2048); i++) {
        const nameRva = mem.u32(addrOfNames + BigInt(i * 4));
        const funcRva = mem.u32(addrOfFuncs + BigInt(i * 4));
        const va = BigInt(base) + BigInt(funcRva);
        let name = "";
        for (let j = 0; j < 256; j++) {
          const c = mem.u8(BigInt(base) + BigInt(nameRva) + BigInt(j));
          if (!c) break;
          name += String.fromCharCode(c);
        }
        if (name) exports.set(name, va);
      }
      this.moduleExports.set(moduleName.toLowerCase(), exports);
    } catch {
      /* PE parsing failed — skip */
    }
  }

  // ------------------------------------------------------------ queries

  /** Normalize: strip module prefix and leading underscore normalization. */
  _normalize(name) {
    return stripPrefix(name.trim());
  }

  /**
   * Resolve a symbol path to either a type layout or a global VA.
   * @param {string} path e.g. "nt!_EPROCESS" or "PsActiveProcessHead"
   * @returns {{kind:"type", info:object}|{kind:"global", va:bigint}|{kind:"export", va:bigint}|null}
   */
  resolve(path) {
    const clean = this._normalize(path);

    // Type lookup
    if (this.types.has(clean)) return { kind: "type", info: this.types.get(clean) };

    // Global lookup
    if (this.globals.has(clean)) {
      return { kind: "global", va: this.globals.get(clean) };
    }
    // Case-insensitive global fallback
    for (const [k, v] of this.globals) {
      if (k.toLowerCase() === clean.toLowerCase()) return { kind: "global", va: v };
    }

    // Export lookup across all modules
    for (const [modName, exports] of this.moduleExports) {
      for (const [expName, va] of exports) {
        if (expName === clean || expName.toLowerCase() === clean.toLowerCase()) {
          return { kind: "export", va, module: modName };
        }
      }
    }
    return null;
  }

  /**
   * Get a single field descriptor from a named type.
   * @param {string} typeName e.g. "_EPROCESS"
   * @param {string} fieldName e.g. "UniqueProcessId"
   * @returns {{offset:number, size:number, base:string}|null}
   */
  getField(typeName, fieldName) {
    const clean = this._normalize(typeName);
    const info = this.types.get(clean);
    if (!info?.fieldsByName?.[fieldName]) return null;
    const f = info.fieldsByName[fieldName];
    return { offset: f.offset, size: f.pointer || /VOID\*/i.test(f.base) ? 8 : 4, base: f.base, decl: f.decl };
  }

  /**
   * Get full layout (sorted field list) for a named type.
   */
  getLayout(typeName) {
    const clean = this._normalize(typeName);
    const info = this.types.get(clean);
    if (!info?.fieldsByName) return null;
    return Object.values(info.fieldsByName)
      .sort((a, b) => a.offset - b.offset)
      .map((f) => ({ name: f.name, offset: f.offset, base: f.base, pointer: f.pointer }));
  }

  listTypes() {
    return [...this.types.keys()].sort();
  }

  listGlobals() {
    return [...this.globals.entries()].sort().map(([k, v]) => `${k} = 0x${v.toString(16)}`);
  }
}

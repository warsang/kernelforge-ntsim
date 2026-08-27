/**
 * Struct table engine: loads VergiliusProject-derived JSON tables and provides
 * BigInt-safe field access against SparseMemory. Nothing about offsets is ever
 * hardcoded in ntsim logic — everything flows through the active build's tables.
 */

export class StructTables {
  constructor() {
    /** @type {Map<string, {totalSize:number, fieldsByName:object}>} */
    this.types = new Map();
  }

  /**
   * Load tables from a directory (Node/build-time convenience; browsers use
   * register() with fetched JSON instead).
   */
  static async loadDir(dirPath, names) {
    const { readFile } = await import("node:fs/promises"); // Node-only path
    const t = new StructTables();
    for (const n of names) {
      try {
        const raw = await readFile(`${dirPath}/${n}.json`, "utf8");
        t.types.set(n, JSON.parse(raw));
      } catch {
        // type absent for this build (e.g. _PS_PROTECTION on win7) — leave unset
      }
    }
    return t;
  }

  /** Register a synthetic/derived type (tests, runtime-generated structs). */
  register(name, totalSize, fields) {
    const fieldsByName = {};
    for (const f of fields) fieldsByName[f.name] = f;
    this.types.set(name, { name, totalSize, fieldsByName, fields });
  }

  has(name) { return this.types.has(name); }
  sizeOf(name) { return this.types.get(name)?.totalSize ?? null; }

  offsetOf(typeName, fieldName) {
    const t = this.types.get(typeName);
    if (!t) throw new Error(`unknown type ${typeName}`);
    const f = t.fieldsByName[fieldName];
    if (!f) throw new Error(`unknown field ${typeName}.${fieldName}`);
    return BigInt(f.offset);
  }

  baseType(typeName, fieldName) {
    return this.types.get(typeName)?.fieldsByName?.[fieldName]?.base ?? null;
  }
}

/** Reader/writer bound to (memory, tables) at a concrete address. */
export class StructRef {
  /**
   * @param {import('./memory.mjs').SparseMemory} mem
   * @param {StructTables} tables
   * @param {bigint} addr
   * @param {string} typeName e.g. "_EPROCESS"
   */
  constructor(mem, tables, addr, typeName) {
    if (!tables.has(typeName)) throw new Error(`type not loaded: ${typeName}`);
    this.mem = mem;
    this.tables = tables;
    this.addr = addr;
    this.type = typeName;
  }

  off(field) { return this.addr + this.tables.offsetOf(this.type, field); }

  u8(f) { return this.mem.u8(this.off(f)); }
  u16(f) { return this.mem.u16(this.off(f)); }
  u32(f) { return this.mem.u32(this.off(f)); }
  u64(f) { return this.mem.u64(this.off(f)); }

  w8(f, v) { this.mem.w8(this.off(f), v); }
  w16(f, v) { this.mem.w16(this.off(f), v); }
  w32(f, v) { this.mem.w32(this.off(f), v); }
  w64(f, v) { this.mem.w64(this.off(f), v); }

  /** Read a pointer-typed field; returns BigInt or null for NULL. */
  ptr(f) {
    const v = this.mem.u64(this.off(f));
    return v === 0n ? null : v;
  }

  /** ANSI char array field -> JS string */
  ansi(f, maxLen = 16) {
    return this.mem.readAnsi(this.off(f), maxLen);
  }

  writeAnsiField(f, s, maxLen = 16) {
    this.mem.writeAnsi(this.off(f), s, maxLen);
  }

  /**
   * Follow a pointer field as a struct of another type.
   * @returns {StructRef|null}
   */
  follow(field, typeName) {
    const p = this.ptr(field);
    return p === null ? null : new StructRef(this.mem, this.tables, p, typeName);
  }

  /** LIST_ENTRY walk helper: returns StructRef of list-embedded structs. */
  next(listEntryField, selfTypeName) {
    const flink = this.mem.u64(this.off(listEntryField));
    if (flink === 0n) return null;
    // caller guarantees flink points at embedded ActiveProcessLinks of next EPROCESS
    const linkOff = this.tables.offsetOf(selfTypeName, listEntryField);
    return new StructRef(this.mem, this.tables, flink - linkOff, selfTypeName);
  }
}

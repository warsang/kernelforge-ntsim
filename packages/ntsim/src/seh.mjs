/**
 * seh.mjs — x64 table-based exception dispatch for mapped images.
 *
 * Scope (KEVLAR-class):
 *  - .pdata RUNTIME_FUNCTION binary search + full UNWIND_INFO parse
 *    (unwind codes, frame register, chained info)
 *  - __C_specific_handler scope-table semantics with REAL CONTEXT /
 *    EXCEPTION_RECORD fabrication (filters can inspect registers)
 *  - multi-frame search: filter returns CONTINUE_SEARCH (0) -> unwind one
 *    frame via its unwind codes and look for a handler in the caller
 *  - CONTINUE_EXECUTION (-1) -> restore the (possibly filter-modified)
 *    CONTEXT and resume the original call through CpuBackend.resumeFromFault
 *  - __finally funclets run before propagation
 *  - frame unwinding is also exported (unwindFrame/resolveUnwindInfo) for
 *    debuggers and tests.
 *
 * Backend contract: resume needs `cpu.resumeFromFault()` (JsInterpreter/
 * Hybrid JS phase). Unicorn runs to completion per callFunction, so filters
 * returning -1 there surface as handled-with-resume-unsupported and the
 * original fault is reported (never silently swallowed).
 */

import { parsePe, rvaToOffset } from "./pe.mjs";

export const STATUS_SUCCESS = 0x00000000n;
const M64 = 0xffffffffffffffffn;

/** UNWIND_REG order used by UWOP_PUSH_NONVOL / SAVE_NONVOL. */
export const UNWIND_REG = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

const CONTEXT_SIZE = 0x4d0;
const CONTEXT_GPR_OFFSETS = {
  rax: 0x78, rcx: 0x80, rdx: 0x88, rbx: 0x90, rsp: 0x98, rbp: 0xa0,
  rsi: 0xa8, rdi: 0xb0, r8: 0xb8, r9: 0xc0, r10: 0xc8, r11: 0xd0,
  r12: 0xd8, r13: 0xe0, r14: 0xe8, r15: 0xf0, rip: 0xf8,
};

/** Fault classes we can recognize from backend errors. */
export function classifyFault(error) {
  const msg = String(error?.message ?? error ?? "");
  if (/fastfail/i.test(msg)) {
    return { code: 0xc0000409n, name: "STATUS_STACK_BUFFER_OVERRUN", kind: "#FASTFAIL" };
  }
  if (/unimplemented opcode|invalid alu form|unimplemented grp|unimplemented 0f opcode|software interrupt/.test(msg)) {
    return { code: 0xc0000005n, name: "STATUS_ILLEGAL_INSTRUCTION", kind: "#UD" };
  }
  if (/unmapped memory|fetch from unmapped|read of unmapped|write to unmapped|bad mapping/.test(msg)) {
    return { code: 0xc0000005n, name: "STATUS_ACCESS_VIOLATION", kind: "#PF" };
  }
  if (/unhandled CPU exception/.test(msg)) {
    return { code: 0xc0000005n, name: "STATUS_ACCESS_VIOLATION", kind: "#XC" };
  }
  if (/div/i.test(msg)) return { code: 0xc0000094n, name: "STATUS_INTEGER_DIVIDE_BY_ZERO", kind: "#DE" };
  return { code: 0xc0000005n, name: "STATUS_ACCESS_VIOLATION", kind: "#GP" };
}

/**
 * Parse the .pdata section into sorted RUNTIME_FUNCTION triples.
 * @returns {{begin:number,end:number,unwindRva:number}[]}
 */
export function parsePdata(imageBytes) {
  const pe = parsePe(imageBytes);
  const dir = pe.dirs[3]; // IMAGE_DIRECTORY_ENTRY_EXCEPTION
  if (!dir?.rva || !dir?.size) return [];
  const base = rvaToOffset(pe, dir.rva);
  if (base === null) return [];
  const count = Math.floor(dir.size / 12);
  const out = [];
  for (let i = 0; i < count; i++) {
    const o = base + i * 12;
    const begin = imageBytes[o] | (imageBytes[o + 1] << 8) | (imageBytes[o + 2] << 16) | (imageBytes[o + 3] << 24);
    const end = imageBytes[o + 4] | (imageBytes[o + 5] << 8) | (imageBytes[o + 6] << 16) | (imageBytes[o + 7] << 24);
    const uw = imageBytes[o + 8] | (imageBytes[o + 9] << 8) | (imageBytes[o + 10] << 16) | (imageBytes[o + 11] << 24);
    if (end > begin) out.push({ begin, end, unwindRva: uw });
  }
  out.sort((a, b) => a.begin - b.begin);
  return out;
}

export function lookupRuntimeFunction(entries, rva) {
  let lo = 0, hi = entries.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const e = entries[mid];
    if (rva < e.begin) hi = mid - 1;
    else if (rva >= e.end) lo = mid + 1;
    else return e;
  }
  return null;
}

// UNWIND_INFO byte0 = Version:3 (bits0-2) | Flags:5 (bits3-7)
const UNW_FLAG_EHANDLER = 0x01;
const UNW_FLAG_UHANDLER = 0x02;
const UNW_FLAG_CHAININFO = 0x04;
const EXTRACT_FLAGS = (b) => b >> 3;

const u16 = (b, o) => (b[o] | (b[o + 1] << 8)) >>> 0;
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const i32 = (b, o) => (u32(b, o) | 0);

/**
 * Parse one UNWIND_INFO structure at a file offset (no chain following).
 * @returns {{version:number, flags:number, sizeOfProlog:number,
 *   frameReg:number, frameOff:number, codes:Array, handlerRva:number|null,
 *   scopes:Array|null, chain:{begin,end,unwindRva}|null}}
 */
function readUnwindInfo(b, pe, unwindRva) {
  const off0 = rvaToOffset(pe, unwindRva);
  if (off0 === null) return null;
  let off = off0;
  if (off + 4 > b.length) return null;
  const version = b[off] & 0x7;
  const flags = EXTRACT_FLAGS(b[off]);
  const sizeOfProlog = b[off + 1];
  const count = b[off + 2];
  const frameInfo = b[off + 3];
  const frameReg = frameInfo & 0xf;
  const frameOff = (frameInfo >> 4) & 0xf;
  off += 4;

  const codes = [];
  let slot = 0;
  while (slot < count && off + 2 <= b.length) {
    const codeOffset = b[off];
    const op = b[off + 1] & 0xf;
    const info = (b[off + 1] >> 4) & 0xf;
    const u = { codeOffset, op, info, size: 0, offset: 0, frameOffset: 0 };
    off += 2; slot++;
    if (op === 1) { // UWOP_ALLOC_LARGE
      if (info === 0) { u.size = u16(b, off) * 8; off += 2; slot++; }
      else { u.size = u32(b, off); off += 4; slot += 2; }
    } else if (op === 4) { // UWOP_SAVE_NONVOL
      u.offset = u16(b, off) * 8; off += 2; slot++;
    } else if (op === 5) { // UWOP_SAVE_NONVOL_FAR
      u.offset = u32(b, off); off += 4; slot += 2;
    } else if (op === 8) { // UWOP_SAVE_XMM128
      off += 2; slot++;
    } else if (op === 9) { // UWOP_SAVE_XMM128_FAR
      off += 4; slot += 2;
    } else if (op === 2) { // UWOP_ALLOC_SMALL
      u.size = info * 8 + 8;
    } else if (op === 3) { // UWOP_SET_FPREG
      u.frameOffset = info * 16;
    }
    codes.push(u);
  }

  // handler / chain RUNTIME_FUNCTION area is 4-byte aligned
  if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO)) {
    if ((count & 1) === 1) off += 2;
  }

  let handlerRva = null;
  let scopes = null;
  let chain = null;
  if (flags & UNW_FLAG_CHAININFO) {
    chain = { begin: u32(b, off), end: u32(b, off + 4), unwindRva: u32(b, off + 8) };
  } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
    handlerRva = u32(b, off);
    off += 4;
    // __C_specific_handler data: scope table follows the handler RVA
    const scopeCount = i32(b, off);
    if (scopeCount > 0 && scopeCount < 4096) {
      scopes = [];
      off += 4;
      for (let i = 0; i < scopeCount; i++) {
        scopes.push({
          begin: u32(b, off), end: u32(b, off + 4),
          handler: u32(b, off + 8), jumpTarget: u32(b, off + 12),
        });
        off += 16;
      }
    }
  }
  return { version, flags, sizeOfProlog, frameReg, frameOff, codes, handlerRva, scopes, chain };
}

/**
 * Parse UNWIND_INFO for a function RVA (public API, no chain following).
 * @returns {{flags:number, handlerRva:number|null, scopes:Array|null,
 *   codes:Array, frameReg:number, frameOff:number, chain:object|null}}
 */
export function parseUnwindInfo(imageBytes, entries, funcRva) {
  const rf = lookupRuntimeFunction(entries, funcRva);
  if (!rf) return null;
  const pe = parsePe(imageBytes);
  return readUnwindInfo(imageBytes, pe, rf.unwindRva);
}

/**
 * Resolve through UNW_FLAG_CHAININFO to the root unwind info (the parent
 * owns both the unwind codes used for frame teardown and the handler).
 */
export function resolveUnwindInfo(imageBytes, entries, funcRva, pe = null) {
  const rf = lookupRuntimeFunction(entries, funcRva);
  if (!rf) return null;
  const pev = pe ?? parsePe(imageBytes);
  let ui = readUnwindInfo(imageBytes, pev, rf.unwindRva);
  let guard = 0;
  while (ui?.chain && guard++ < 8) {
    const next = readUnwindInfo(imageBytes, pev, ui.chain.unwindRva);
    if (!next) break;
    ui = { ...next, chained: true };
  }
  return ui;
}

/** Register snapshot used by the frame walker. */
export function snapshotContext(cpu, rip) {
  const regs = {};
  for (const r of UNWIND_REG) regs[r] = BigInt(cpu?.regs?.[r] ?? 0n) & M64;
  return { regs, rip: BigInt(rip) & M64 };
}

/**
 * Undo one function prologue: apply the unwind codes and pop the return
 * address. Returns the caller context {regs, rip}.
 */
export function unwindFrame(mem, ctx, ui) {
  const regs = { ...ctx.regs };
  let rsp = regs.rsp ?? 0n;
  const load = (a) => {
    try { return mem.u64(a & M64); } catch { return 0n; }
  };
  for (const u of ui.codes ?? []) {
    switch (u.op) {
      case 0: // UWOP_PUSH_NONVOL
        regs[UNWIND_REG[u.info]] = load(rsp);
        rsp = (rsp + 8n) & M64;
        break;
      case 1: // UWOP_ALLOC_LARGE
      case 2: // UWOP_ALLOC_SMALL
        rsp = (rsp + BigInt(u.size)) & M64;
        break;
      case 3: { // UWOP_SET_FPREG
        const fr = regs[UNWIND_REG[ui.frameReg]] ?? 0n;
        rsp = (fr - BigInt(u.frameOffset || ui.frameOff * 16)) & M64;
        break;
      }
      case 4: // UWOP_SAVE_NONVOL
      case 5: // UWOP_SAVE_NONVOL_FAR
        regs[UNWIND_REG[u.info]] = load(rsp + BigInt(u.offset));
        break;
      case 8: case 9: // XMM saves: not modeled
        break;
      case 10: { // UWOP_PUSH_MACHFRAME
        const base2 = rsp;
        const errCode = u.info === 1;
        const rip = load(base2 + (errCode ? 0x20n : 0x18n));
        regs.rsp = (base2 + (errCode ? 0x30n : 0x28n)) & M64;
        return { regs, rip };
      }
      default:
        break;
    }
  }
  const rip = load(rsp);
  regs.rsp = (rsp + 8n) & M64;
  return { regs, rip };
}

/**
 * Write a real x64 CONTEXT for the faulting frame.
 */
export function writeContext(mem, addr, ctx, eflags = 0x202) {
  mem.write(addr, new Uint8Array(CONTEXT_SIZE));
  mem.w32(addr + 0x30n, 0x0010001f); // ContextFlags (CONTEXT_FULL-ish)
  mem.w32(addr + 0x34n, 0x1f80);     // MxCsr reset value
  mem.w16(addr + 0x38n, 0x33);       // SegCs
  mem.w16(addr + 0x3an, 0x2b);       // SegDs
  mem.w32(addr + 0x44n, Number(BigInt(eflags) & 0xffffffffn));
  for (const [r, o] of Object.entries(CONTEXT_GPR_OFFSETS)) {
    mem.w64(addr + BigInt(o), (r === "rip" ? ctx.rip : ctx.regs[r]) ?? 0n);
  }
}

/** Read a CONTEXT back (filters may patch registers before returning -1). */
export function readContext(mem, addr) {
  const regs = {};
  for (const r of UNWIND_REG) regs[r] = mem.u64(addr + BigInt(CONTEXT_GPR_OFFSETS[r]));
  return { regs, rip: mem.u64(addr + 0xf8n) };
}

/**
 * Exception dispatch record written into emulated memory so filters can read
 * EXCEPTION_POINTERS {ExceptionRecord{Code,Flags,Record,Address}, Context}.
 */
function writeExceptionPointers(kernel, exc, faultVa, ctx, eflags) {
  const mem = kernel.mem;
  const rec = kernel.allocPool(0x30, "ExRe");
  const ptrs = kernel.allocPool(0x10, "ExPt");
  const context = kernel.allocPool(CONTEXT_SIZE, "ExCx");
  mem.w32(rec, Number(BigInt(exc.code) & 0xffffffffn));
  mem.w32(rec + 4n, 0); // flags
  mem.w64(rec + 8n, 0n); // inner record
  mem.w64(rec + 0x10n, faultVa); // ExceptionAddress
  mem.w32(rec + 0x18n, 0); // NumberParameters
  writeContext(mem, context, ctx, eflags);
  mem.w64(ptrs, rec);
  mem.w64(ptrs + 8n, context);
  return { rec, ptrs, context };
}

function eflagsOf(cpu) {
  try { return cpu?.composeFlags ? cpu.composeFlags() : 0x202; } catch { return 0x202; }
}

/**
 * Attempt SEH dispatch for a faulting call (multi-frame).
 *
 * @param {object} kernel NtKernel
 * @param {object} image {base:bigint, bytes:Uint8Array}
 * @param {Error} error backend fault (CpuError carries rip)
 * @returns {{handled:boolean, detail:string, result?:object, ntstatus?:bigint,
 *   resume?:{regs:object, rip:bigint}}}
 */
export function tryDispatchException(kernel, image, error) {
  const mem = kernel.mem;
  const exc = classifyFault(error);
  const rip = error?.rip !== undefined ? BigInt(error.rip) : kernel.cpu.rip;
  const base = BigInt(image.base);
  let rva = Number(rip - base);
  if (rva < 0 || rva > 0x10000000) {
    return { handled: false, detail: `fault outside image @ 0x${rip.toString(16)} (${exc.kind})` };
  }

  image.pdata ??= parsePdata(image.bytes);
  if (!image.pdata.length) {
    return { handled: false, detail: `no .pdata (${exc.kind} @ rva 0x${rva.toString(16)})` };
  }
  image._pe ??= parsePe(image.bytes);
  const pe = image._pe;

  const faultCtx = snapshotContext(kernel.cpu, rip);
  let ctx = faultCtx;
  const frames = [];

  for (let depth = 0; depth < 16; depth++) {
    rva = Number(ctx.rip - base);
    if (rva < 0 || rva > 0x10000000) break;
    const rf = lookupRuntimeFunction(image.pdata, rva);
    if (!rf) break;
    const ui = resolveUnwindInfo(image.bytes, image.pdata, rva, pe);
    if (!ui) break;
    const scope = ui.scopes?.find((s) => rva >= s.begin && rva < s.end);
    if (!scope) {
      const next = unwindFrame(mem, ctx, ui);
      if (!next || next.rip === 0n || next.regs.rsp <= ctx.regs.rsp) break;
      frames.push(`rva 0x${rva.toString(16)}`);
      ctx = next;
      continue;
    }

    frames.push(`rva 0x${rva.toString(16)} (handler)`);
    const { ptrs, context } = writeExceptionPointers(kernel, exc, rip, faultCtx, eflagsOf(kernel.cpu));

    // __finally scope: jumpTarget == 0, handler has terminate bit
    if (scope.jumpTarget === 0) {
      const finallyAddr = base + BigInt(scope.handler & ~1);
      const r = kernel.cpu.callFunction(finallyAddr, [ptrs]);
      return {
        handled: true,
        detail: `__finally funclet at rva 0x${scope.handler.toString(16)} -> ${r.status}`,
        result: r,
      };
    }

    // __except: optional filter funclet decides
    if (!(scope.handler & 1) && scope.handler !== 0) {
      const filterAddr = base + BigInt(scope.handler);
      const fr = kernel.cpu.callFunction(filterAddr, [ptrs]);
      if (fr.status === "ok") {
        const verdict = Number(BigInt.asIntN(32, fr.retval));
        kernel.dbgLog.push(
          `[seh] filter rva 0x${scope.handler.toString(16)} -> ${verdict} for ${exc.name}`,
        );
        if (verdict === 0 /* EXCEPTION_CONTINUE_SEARCH */) {
          const next = unwindFrame(mem, ctx, ui);
          if (!next || next.rip === 0n || next.regs.rsp <= ctx.regs.rsp) break;
          ctx = next;
          continue;
        }
        if (verdict === -1 /* EXCEPTION_CONTINUE_EXECUTION */) {
          const restored = readContext(mem, context);
          kernel.dbgLog.push(
            `[seh] filter CONTINUE_EXECUTION for ${exc.name} @ rva 0x${rva.toString(16)}`,
          );
          return {
            handled: true,
            resume: restored,
            detail: `filter rva 0x${scope.handler.toString(16)} -> CONTINUE_EXECUTION`,
          };
        }
        if (verdict !== 1) {
          return { handled: false, detail: `filter declined (${verdict})` };
        }
      }
    }

    const target = base + BigInt(scope.jumpTarget);
    const hr = kernel.cpu.callFunction(target, [ptrs]);
    kernel.dbgLog.push(
      `[seh] ${exc.kind} @ rva 0x${rva.toString(16)} dispatched to handler rva ` +
      `0x${scope.jumpTarget.toString(16)} -> ${hr.status}`,
    );
    return {
      handled: hr.status === "ok",
      detail: `except handler rva 0x${scope.jumpTarget.toString(16)} (${hr.status})`,
      result: hr,
      ntstatus: hr.status === "ok" ? hr.retval : undefined,
    };
  }

  return {
    handled: false,
    detail: `no handler (${exc.kind} @ rip 0x${rip.toString(16)}); walked ${frames.join(" <- ") || "no frame"}`,
  };
}

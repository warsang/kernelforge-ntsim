/**
 * seh.mjs — x64 table-based exception dispatch for mapped images.
 *
 * Scope (honest, speakeasy-class):
 *  - .pdata RUNTIME_FUNCTION binary search + UNWIND_INFO parse
 *  - __C_specific_handler scope-table semantics for the frame that faulted
 *    (the dominant shape for packed/armored drivers: whole-entry __try)
 *  - filter funclets are invoked through the CPU backend; when the filter
 *    returns EXCEPTION_EXECUTE_HANDLER(1) execution resumes at JumpTarget
 *  - NOT implemented: multi-frame unwind, C++ EH, collide-aware unwind state.
 *    Unhandled faults surface as bugcheck-style reports — never silent.
 *
 * Dispatch strategy keeps the CpuBackend contract untouched: a handled
 * exception re-enters the handler funclet as its own ABI call. Handlers that
 * `return` (the convention) complete normally; fall-through handlers run to
 * the step budget and are reported as such.
 */

import { parsePe, rvaToOffset } from "./pe.mjs";

export const STATUS_SUCCESS = 0x00000000n;

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

function lookupRuntimeFunction(entries, rva) {
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

/**
 * Parse UNWIND_INFO at file offset for `funcRva`.
 * @returns {{flags:number, handlerRva:number|null, scopes:
 *   [{begin:number,end:number,handler:number,jumpTarget:number}]|null}}
 */
export function parseUnwindInfo(imageBytes, entries, funcRva) {
  const rf = lookupRuntimeFunction(entries, funcRva);
  if (!rf) return null;
  const pe = parsePe(imageBytes);
  let off = rvaToOffset(pe, rf.unwindRva);
  if (off === null) return null;
  const b = imageBytes;
  const flags = EXTRACT_FLAGS(b[off]);
  const count = b[off + 2];
  off += 4;
  off += count * 2; // skip UNWIND_CODEs (each 2 bytes; no chained-info support)
  // after codes: optional unwind-code padding to 4-byte alignment happens
  // only when count is odd AND handlers follow
  if ((count & 1) === 1 && (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))) off += 2;
  let handlerRva = null;
  if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
    handlerRva =
      (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
    off += 4;
  }
  let scopes = null;
  if (handlerRva !== null) {
    // __C_specific_handler layout: u32 count then 4*u32 per scope entry
    const scopeCount =
      b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24);
    if (scopeCount > 0 && scopeCount < 4096) {
      scopes = [];
      off += 4;
      for (let i = 0; i < scopeCount; i++) {
        const rd = () => {
          const v = (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
          off += 4;
          return v;
        };
        scopes.push({ begin: rd(), end: rd(), handler: rd(), jumpTarget: rd() });
      }
    }
  }
  void UNW_FLAG_CHAININFO;
  return { flags, handlerRva, scopes };
}

/**
 * Exception dispatch record written into emulated memory so filters can read
 * EXCEPTION_POINTERS {ExceptionRecord{Code,Flags,Record,Address}, Context}.
 * Layout is our own stable one; filters in compiled drivers only receive it
 * as an opaque pointer arg to their funclets (which we invoke directly).
 */
function writeExceptionPointers(kernel, excCode, faultVa) {
  const mem = kernel.mem;
  const rec = kernel.allocPool(0x30, "ExRe");
  const ptrs = kernel.allocPool(0x10, "ExPt");
  mem.w32(rec, Number(BigInt(excCode) & 0xffffffffn));
  mem.w32(rec + 4n, 0); // flags
  mem.w64(rec + 8n, 0n); // inner record
  mem.w64(rec + 0x10n, faultVa);
  mem.w64(ptrs, rec);
  mem.w64(ptrs + 8n, kernel.allocPool(0x4d0, "ExCx")); // fake CONTEXT block
  return ptrs;
}

/**
 * Attempt SEH dispatch for a faulting call.
 *
 * @param {object} kernel NtKernel
 * @param {object} image {base:bigint, bytes:Uint8Array}
 * @param {Error} error backend fault (CpuError carries rip)
 * @returns {{handled:boolean, detail:string, result?:object}}
 */
export function tryDispatchException(kernel, image, error) {
  const mem = kernel.mem;
  const exc = classifyFault(error);
  const rip = error?.rip !== undefined ? BigInt(error.rip) : kernel.cpu.rip;
  const rva = Number(rip - BigInt(image.base));
  if (rva < 0 || rva > 0x10000000) {
    return { handled: false, detail: `fault outside image @ 0x${rip.toString(16)} (${exc.kind})` };
  }

  image.pdata ??= parsePdata(image.bytes);
  if (!image.pdata.length) {
    return { handled: false, detail: `no .pdata (${exc.kind} @ rva 0x${rva.toString(16)})` };
  }

  const ui = parseUnwindInfo(image.bytes, image.pdata, rva);
  if (!ui || ui.handlerRva === null || !ui.scopes || !ui.scopes.length) {
    return { handled: false, detail: `no scope table (${exc.kind} @ rva 0x${rva.toString(16)})` };
  }

  const scope = ui.scopes.find((s) => rva >= s.begin && rva < s.end);
  if (!scope) {
    return { handled: false, detail: `fault rva 0x${rva.toString(16)} outside all try ranges` };
  }

  const excPointers = writeExceptionPointers(kernel, exc.code, rip);

  // __finally scope: jumpTarget == 0, handler has terminate bit
  if (scope.jumpTarget === 0) {
    const finallyAddr = BigInt(image.base) + BigInt(scope.handler & ~1);
    const r = kernel.cpu.callFunction(finallyAddr, [excPointers]);
    return {
      handled: true,
      detail: `__finally funclet at rva 0x${scope.handler.toString(16)} -> ${r.status}`,
      result: r,
    };
  }

  // __except: optional filter funclet decides
  if (!(scope.handler & 1) && scope.handler !== 0) {
    const filterAddr = BigInt(image.base) + BigInt(scope.handler);
    const fr = kernel.cpu.callFunction(filterAddr, [excPointers]);
    if (fr.status === "ok") {
      const verdict = Number(BigInt.asIntN(32, fr.retval));
      kernel.dbgLog.push(
        `[seh] filter rva 0x${scope.handler.toString(16)} -> ${verdict} for ${exc.name}`,
      );
      if (verdict !== 1 /* EXCEPTION_EXECUTE_HANDLER */ && verdict !== -1) {
        return { handled: false, detail: `filter declined (${verdict})` };
      }
    }
  }

  const target = BigInt(image.base) + BigInt(scope.jumpTarget);
  const hr = kernel.cpu.callFunction(target, [excPointers]);
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

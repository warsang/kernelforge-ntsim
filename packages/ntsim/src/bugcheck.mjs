/**
 * bugcheck.mjs — BSOD emulation: code names, parameter analysis, double/
 * triple-fault detection and a KEVLAR-style post-mortem renderer.
 *
 * The name table is generated from KEVLAR's dbg_bugcheck_table.h
 * (379 entries, see bugcheck-table.mjs). Parameter analysis covers the
 * codes an analysis harness actually sees (0xA/0x50/0xD1/0x139/0x3B/0x1E/
 * 0x8E/0x7E/0xC4/0x7F/0x109/0x133) and resolves faulting IPs to module+RVA.
 */

import { BUGCHECK_NAMES } from "./bugcheck-table.mjs";

const M64 = 0xffffffffffffffffn;

const IRQL_NAMES = {
  0: "PASSIVE_LEVEL",
  1: "APC_LEVEL",
  2: "DISPATCH_LEVEL",
};

const EXCEPTION_NAMES = {
  "0xc0000005": "STATUS_ACCESS_VIOLATION",
  "0xc0000006": "STATUS_IN_PAGE_ERROR",
  "0xc000001d": "STATUS_ILLEGAL_INSTRUCTION",
  "0xc000008c": "STATUS_ARRAY_BOUNDS_EXCEEDED",
  "0xc000008d": "STATUS_FLOAT_DENORMAL_OPERAND",
  "0xc000008e": "STATUS_FLOAT_DIVIDE_BY_ZERO",
  "0xc000008f": "STATUS_FLOAT_INEXACT_RESULT",
  "0xc0000090": "STATUS_FLOAT_INVALID_OPERATION",
  "0xc0000091": "STATUS_FLOAT_OVERFLOW",
  "0xc0000092": "STATUS_FLOAT_STACK_CHECK",
  "0xc0000093": "STATUS_FLOAT_UNDERFLOW",
  "0xc0000094": "STATUS_INTEGER_DIVIDE_BY_ZERO",
  "0xc0000095": "STATUS_INTEGER_OVERFLOW",
  "0xc0000096": "STATUS_PRIVILEGED_INSTRUCTION",
  "0xc00000fd": "STATUS_STACK_OVERFLOW",
  "0xc0000409": "STATUS_STACK_BUFFER_OVERRUN",
  "0x80000003": "STATUS_BREAKPOINT",
  "0x80000004": "STATUS_SINGLE_STEP",
};

/** 0x139 (KERNEL_SECURITY_CHECK_FAILURE) subtype names — KEVLAR's mapping. */
const SECURITY_CHECK_SUBTYPES = {
  0: "Stack buffer overrun",
  1: "VTGuard check failure",
  2: "Stack cookie mismatch (/GS)",
  3: "Corrupt LIST_ENTRY",
  4: "Out-of-bounds stack variable access",
  5: "Invalid parameter passed to function",
  6: "Uninitialized stack variable used",
  8: "Illegal ICall target",
  9: "Write to read-only exception handler",
  13: "Invalid fiber context switch",
  14: "Invalid registry callback",
  18: "CFG violation",
  19: "Return flow guard violation",
  21: "CET shadow stack mismatch",
};

/** 0x7F trap numbers. */
const TRAP_NAMES = {
  0: "Divide by Zero (#DE)",
  1: "Debug (#DB)",
  2: "NMI",
  3: "Breakpoint (#BP)",
  4: "Overflow (#OF)",
  5: "Bound Check (#BR)",
  6: "Invalid Opcode (#UD)",
  7: "Device Not Available (#NM)",
  8: "Double Fault (#DF)",
  10: "Invalid TSS (#TS)",
  11: "Segment Not Present (#NP)",
  12: "Stack Fault (#SS)",
  13: "General Protection Fault (#GP)",
  14: "Page Fault (#PF)",
  16: "Floating-Point Error (#MF)",
  17: "Alignment Check (#AC)",
  18: "Machine Check (#MC)",
  19: "SIMD Floating-Point (#XM)",
  20: "Virtualization (#VE)",
  21: "Control Protection (#CP)",
};

export function bugcheckName(code) {
  return BUGCHECK_NAMES.get(Number(BigInt.asUintN(32, BigInt(code)))) ?? null;
}

const hex = (v, pad = 16) => "0x" + BigInt.asUintN(64, BigInt(v)).toString(16).padStart(pad, "0");

function accessType(v) {
  const n = Number(BigInt.asUintN(64, BigInt(v)) & 0xffn);
  if (n & 0x1) return "WRITE";
  if (n & 0x8) return "EXECUTE";
  return "READ";
}

function exceptionName(code) {
  const c = BigInt.asUintN(32, BigInt(code));
  return EXCEPTION_NAMES["0x" + c.toString(16)] ?? null;
}

/**
 * Decode a bugcheck's parameters.
 * @returns {{code:bigint, name:string, summary:string|null,
 *   fields:Array<{label:string, value:string}>}}
 */
export function analyzeBugcheck(code, params = []) {
  const c = Number(BigInt.asUintN(32, BigInt(code)));
  const p = params.map((v) => BigInt.asUintN(64, BigInt(v ?? 0n)));
  const fields = [];
  let summary = null;

  switch (c) {
    case 0x0a:
      summary = "Driver accessed pageable/incorrect memory at raised IRQL";
      fields.push(
        { label: "Faulting Address", value: hex(p[0]) },
        { label: "IRQL", value: `${p[1]} (${IRQL_NAMES[Number(p[1])] ?? "unknown"})` },
        { label: "Access Type", value: accessType(p[2]) },
        { label: "Faulting IP", value: hex(p[3]) },
      );
      break;
    case 0x50:
      summary = "Page fault in non-paged (or freed) memory";
      fields.push(
        { label: "Faulting Address", value: hex(p[0]) },
        { label: "Access Type", value: accessType(p[1]) },
        { label: "Faulting IP", value: hex(p[2]) },
      );
      break;
    case 0xd1:
      summary = "Driver touched memory it cannot access at the current IRQL";
      fields.push(
        { label: "Memory Reference", value: hex(p[0]) },
        { label: "IRQL", value: `${p[1]} (${IRQL_NAMES[Number(p[1])] ?? "unknown"})` },
        { label: "Access Type", value: accessType(p[2]) },
        { label: "Faulting IP", value: hex(p[3]) },
      );
      break;
    case 0x139:
      summary = "Kernel security check failed";
      fields.push({
        label: "Failure Type",
        value: `${p[0]} (${SECURITY_CHECK_SUBTYPES[Number(p[0])] ?? "unknown failure subtype"})`,
      });
      break;
    case 0x3b: {
      const exName = exceptionName(p[0]);
      summary = exName ? `Unhandled kernel exception: ${exName}` : "Unhandled kernel exception";
      fields.push(
        { label: "Exception Code", value: hex(p[0], 8) + (exName ? ` (${exName})` : "") },
        { label: "Faulting IP", value: hex(p[1]) },
        { label: "Exception Record", value: hex(p[2]) },
      );
      break;
    }
    case 0x1e:
    case 0x8e:
    case 0x7e: {
      const exName = exceptionName(p[0]);
      summary = exName ? `Unhandled exception in kernel mode: ${exName}` : "Unhandled exception in kernel mode";
      fields.push(
        { label: "Exception Code", value: hex(p[0], 8) + (exName ? ` (${exName})` : "") },
        { label: "Faulting IP", value: hex(p[1]) },
        { label: "Exception Param", value: hex(p[2]) },
      );
      break;
    }
    case 0x0d1:
      break;
    case 0xc4:
      summary = "Driver Verifier detected a violation";
      fields.push({ label: "Violation Type", value: hex(p[0], 8) });
      break;
    case 0x7f: {
      const trap = TRAP_NAMES[Number(p[0])];
      summary = trap ? `Unexpected kernel-mode trap: ${trap}` : "Unexpected kernel-mode trap";
      fields.push(
        { label: "Trap Number", value: `${p[0]}${trap ? ` (${trap})` : ""}` },
        { label: "Trap Param 1", value: hex(p[1]) },
        { label: "Trap Param 2", value: hex(p[2]) },
        { label: "Trap Param 3", value: hex(p[3]) },
      );
      break;
    }
    case 0x109:
      summary = "PatchGuard-style critical structure corruption";
      fields.push(
        { label: "Structure Type", value: `${p[0]}${Number(p[0]) === 4 ? " (MSR)" : ""}` },
        { label: "Address", value: hex(p[1]) },
        { label: "Value", value: hex(p[2]) },
      );
      break;
    case 0x133:
      summary = "DPC watchdog violation";
      fields.push(
        { label: "Core / DPC Time", value: `${p[0]}` },
        { label: "DPC Time Limit", value: `${p[1]}` },
      );
      break;
    case 0xc2:
      summary = "Bad pool caller (double free / corrupt header)";
      fields.push(
        { label: "Pool Type", value: `${p[0]}` },
        { label: "Address", value: hex(p[1]) },
      );
      break;
    case 0xc5:
      summary = "Memory access violation caused by driver";
      fields.push(
        { label: "Address", value: hex(p[1]) },
        { label: "Access Type", value: accessType(p[2]) },
        { label: "Faulting IP", value: hex(p[3]) },
      );
      break;
    default:
      break;
  }

  return {
    code: BigInt.asUintN(64, BigInt(code)),
    name: bugcheckName(c) ?? `UNKNOWN_BUGCHECK_0x${c.toString(16).toUpperCase()}`,
    summary,
    fields,
  };
}

/**
 * Record a bugcheck with nesting detection. Level 1 = primary, 2 = double
 * fault, 3+ = triple fault (KEVLAR's KiBugCheckActive state machine).
 */
export function noteBugcheck(kernel, code, params = []) {
  const codeBig = BigInt.asUintN(64, BigInt(code));
  const paramsBig = params.map((v) => BigInt.asUintN(64, BigInt(v ?? 0n)));
  if (!kernel.bugcheck) {
    kernel.bugcheck = {
      code: codeBig,
      params: paramsBig,
      level: 1,
      name: bugcheckName(codeBig) ?? undefined,
    };
  } else {
    const level = (kernel.bugcheck.level ?? 1) + 1;
    kernel.bugcheck.level = level;
    kernel.bugcheck.nested = true;
    kernel.bugcheck.nestedCount = (kernel.bugcheck.nestedCount ?? 0) + 1;
    (kernel.bugcheck.nestedCodes ??= []).push(codeBig);
    const nested = { code: codeBig, params: paramsBig, name: bugcheckName(codeBig) ?? undefined };
    if (level === 2) kernel.doubleFault = nested;
    if (level >= 3) kernel.tripleFault = nested;
  }
  kernel.crash = { code: "0x" + codeBig.toString(16) };
  kernel.cpu.halted = true;
  try {
    kernel.emitTrace?.({ kind: "bugcheck", code: codeBig, level: kernel.bugcheck.level });
  } catch { /* tracing is best-effort */ }
  return kernel.bugcheck;
}

/** Module ranges for address resolution (loaded drivers + target image). */
function moduleRanges(kernel, extra) {
  const out = [];
  const push = (name, base, size) => {
    const b = BigInt(base ?? 0n);
    if (b > 0n) out.push({ name: String(name), base: b, size: Number(size ?? 0x1000) });
  };
  for (const m of extra ?? []) push(m.name, m.base, m.size ?? m.imageSize ?? m.sizeOfImage);
  for (const m of kernel?.loadedDrivers ?? []) push(m.name, m.base, m.imageSize);
  for (const m of kernel?.loadedModules ?? []) push(m.name, m.base, m.sizeOfImage ?? m.size);
  return out;
}

/** "ntoskrnl.exe+0x1234" style resolution; null when unmapped. */
export function resolveAddress(addr, modules) {
  const a = BigInt.asUintN(64, BigInt(addr));
  for (const m of modules) {
    if (a >= m.base && a < m.base + BigInt(m.size)) {
      return `${m.name}+0x${(a - m.base).toString(16)}`;
    }
  }
  return null;
}

const hex32 = (v) => "0x" + BigInt.asUintN(32, BigInt(v)).toString(16).toUpperCase().padStart(8, "0");

/**
 * KEVLAR-style post-mortem text: stop code, analysis, registers, stack and
 * an RBP-chain call stack resolved against the module list.
 */
export function renderBugcheck(kernel, opts = {}) {
  const bc = kernel?.bugcheck;
  if (!bc) return null;
  const code = BigInt.asUintN(64, BigInt(bc.code));
  const analysis = analyzeBugcheck(code, bc.params ?? []);
  const cpu = kernel.cpu;
  const mem = kernel.mem;
  const modules = moduleRanges(kernel, opts.modules);

  const lines = [];
  const stopCode = "0x" + code.toString(16).toUpperCase().padStart(8, "0");
  lines.push(`*** STOP: ${stopCode}` +
    (bc.params?.length ? ` (${bc.params.map((p) => hex(p)).join(", ")})` : ""));
  lines.push(analysis.name + (analysis.summary ? ` — ${analysis.summary}` : ""));
  if (bc.level > 1) {
    lines.push(bc.level >= 3
      ? "*** TRIPLE FAULT (nested bugcheck during double-fault handling) ***"
      : "*** DOUBLE FAULT DETECTED (bugcheck raised while handling a bugcheck) ***");
  }
  if (analysis.fields.length) {
    lines.push("  Analysis:");
    for (const f of analysis.fields) {
      const resolved = /^0x[0-9a-f]{16}$/i.test(f.value)
        ? (resolveAddress(BigInt(f.value), modules) ?? "")
        : "";
      lines.push(`    ${f.label.padEnd(16)}: ${f.value}${resolved ? "  (" + resolved + ")" : ""}`);
    }
  }
  if (cpu?.regs) {
    const r = cpu.regs;
    lines.push("  Registers:");
    lines.push(`    RAX=${hex(r.rax)} RBX=${hex(r.rbx)} RCX=${hex(r.rcx)} RDX=${hex(r.rdx)}`);
    lines.push(`    RSI=${hex(r.rsi)} RDI=${hex(r.rdi)} RBP=${hex(r.rbp)} RSP=${hex(r.rsp)}`);
    lines.push(`    R8 =${hex(r.r8)} R9 =${hex(r.r9)} R10=${hex(r.r10)} R11=${hex(r.r11)}`);
    lines.push(`    R12=${hex(r.r12)} R13=${hex(r.r13)} R14=${hex(r.r14)} R15=${hex(r.r15)}`);
    lines.push(`    RIP=${hex(cpu.rip)} (${resolveAddress(cpu.rip, modules) ?? "unmapped"})`);
  }
  // stack qwords around RSP
  if (cpu?.regs && mem) {
    try {
      const rsp = BigInt.asUintN(64, BigInt(cpu.regs.rsp));
      const words = [];
      for (let i = 0; i < 8; i++) {
        const va = rsp + BigInt(i * 8);
        words.push(`${hex(va)}: ${hex(mem.u64(va))}`);
      }
      lines.push("  Stack (RSP+0x00..0x38):");
      for (const w of words) lines.push(`    ${w}`);
    } catch { /* unmapped stack */ }
  }
  // RBP chain
  if (cpu?.regs && mem) {
    try {
      let rbp = BigInt.asUintN(64, BigInt(cpu.regs.rbp));
      const frames = [];
      for (let i = 0; i < 8 && rbp > 0x1000n; i++) {
        const ret = mem.u64(rbp + 8n);
        if (ret === 0n || ret === 0xdead0000feed0000n) break;
        frames.push(`${hex(ret)} (${resolveAddress(ret, modules) ?? "unmapped"})`);
        const next = mem.u64(rbp);
        if (next <= rbp) break;
        rbp = next;
      }
      if (frames.length) {
        lines.push("  Call stack (RBP chain):");
        for (const f of frames) lines.push(`    ${f}`);
      }
    } catch { /* corrupt chain */ }
  }
  return lines.join("\n");
}

/** JSON-safe summary for analyzer reports. */
export function summarizeBugcheck(bc, opts = {}) {
  if (!bc) return null;
  const code = BigInt.asUintN(64, BigInt(bc.code));
  const analysis = analyzeBugcheck(code, bc.params ?? []);
  return {
    code: "0x" + code.toString(16).toUpperCase().padStart(8, "0"),
    name: analysis.name,
    summary: analysis.summary,
    level: bc.level ?? 1,
    nested: !!bc.nested,
    params: (bc.params ?? []).map((p) => hex(p)),
    fields: analysis.fields,
    doubleFault: bc.level === 2 ? true : undefined,
    tripleFault: bc.level >= 3 ? true : undefined,
    nestedCodes: (bc.nestedCodes ?? []).map((c) => hex(c, 8)),
  };
}

export { M64, IRQL_NAMES, EXCEPTION_NAMES };

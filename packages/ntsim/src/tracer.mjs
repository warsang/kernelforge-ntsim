/**
 * tracer.mjs — ktrace / speakeasy-style call tracing for the ntsim kernel.
 *
 * The kernel records raw facts via NtKernel.emitTrace() (API thunks, DbgPrint,
 * exceptions, deferred routines, ETW). This module turns those events into a
 * human-readable chronological log:
 *
 *   [0009] DriverEntry        TBMKD.sys+0x2e48  nt!_vsnprintf(buf=0xfffff90000000250, max=0x1ff, fmt="[%s] ...") -> 0x17
 *   [0010] DriverEntry        TBMKD.sys+0x2e69  nt!DbgPrint(fmt="[TBMKEv1] DriverEntry.\n") -> 0x0
 *
 * Argument decoding uses per-API signatures (UNICODE_STRING dereferences,
 * CTL_CODE decomposition, pool tags as 4cc, GUID formatting, ...); unknown
 * APIs degrade to raw hex arguments. Everything is computed while the guest
 * memory is still live and stored back onto the events, so reports stay
 * plain JSON.
 */

import { isVoidApi } from "./winapi-meta.mjs";

const U64MASK = (1n << 64n) - 1n;

/* ------------------------------------------------------------ value decoding */

function hex(v) {
  return "0x" + (BigInt.asUintN(64, BigInt(v ?? 0))).toString(16);
}

function ntstatusName(code) {
  const NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0xc0000005: "STATUS_ACCESS_VIOLATION",
    0xc000000b: "STATUS_INVALID_HANDLE",
    0xc000000d: "STATUS_INVALID_PARAMETER",
    0xc0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xc0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xc00000bb: "STATUS_NOT_SUPPORTED",
    0xc0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xc0000467: "STATUS_INSUFFICIENT_POWER",
  };
  return NAMES[Number(BigInt.asUintN(32, BigInt(code)))] ?? null;
}

/** Argument-value decoders, exported for tests and ad-hoc UI formatting. */
export const DEC = {
  hex: (_mem, v) => hex(v),
  dec: (_mem, v) => BigInt.asUintN(64, BigInt(v ?? 0)).toString(),
  i32: (_mem, v) => BigInt.asIntN(32, BigInt(v ?? 0)).toString(),
  bool: (_mem, v) => ((v ?? 0n) ? "TRUE" : "FALSE"),
  irql: (_mem, v) => {
    // KIRQL params are 8-bit; callers often leave garbage in high reg bytes
    const lvl = Number(BigInt.asUintN(8, BigInt(v ?? 0)));
    const NAMES = ["PASSIVE", "APC", "DISPATCH", "DIRQL"];
    return `${lvl} (${NAMES[lvl] ?? "HIGH"})`;
  },
  pid: (_mem, v) => `pid ${v}`,
  tag: (_mem, v) => {
    const x = Number(BigInt.asUintN(32, BigInt(v ?? 0)));
    const s = String.fromCharCode(
      x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff,
    );
    return `'${[...s].map((c) => (c >= " " && c <= "~" ? c : ".")).join("")}'`;
  },
  ctlcode: (_mem, v) => {
    const c = Number(BigInt.asUintN(32, BigInt(v ?? 0)));
    const device = (c >> 16) & 0xffff;
    const access = (c >> 14) & 3;
    const fn = (c >> 2) & 0xfff;
    const method = c & 3;
    const ACCESS = ["READ", "WRITE", "RW", "ANY"];
    const METHOD = ["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"];
    return `CTL_DEVICE=0x${device.toString(16)} FUNC=${fn >= 0x800 ? "0x" + fn.toString(16) : fn} ACCESS=${ACCESS[access]} METHOD=${METHOD[method]}`;
  },
  guid: (mem, v) => {
    try {
      const b = mem.read(v, 16);
      const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
      const u16 = (o) => b[o] | (b[o + 1] << 8);
      const hexs = (n) => n.toString(16).padStart(n <= 0xffff ? 4 : 8, "0");
      const d4 = [...b.slice(8, 16)].map((x) => x.toString(16).padStart(2, "0")).join("");
      return `{${hexs(u32(0))}-${hexs(u16(4))}-${hexs(u16(6))}-${d4.slice(0, 4)}-${d4.slice(4)}}`;
    } catch { return hex(v); }
  },
  wstr: (mem, v) => {
    try {
      let out = "";
      for (let i = 0; i < 128; i++) {
        const c = Number(mem.u16(v + BigInt(i * 2)));
        if (c === 0) break;
        out += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
      }
      return `L"${out}"`;
    } catch { return hex(v); }
  },
  ustr: (mem, v) => {
    // UNICODE_STRING*: Length u16, MaximumLength u16 @+4, Buffer @+8
    try {
      if (!v) return "NULL";
      const len = mem.u16(v);
      const buf = mem.u64(v + 8n);
      if (!len || !buf) return "{}";
      let out = "";
      for (let i = 0; i < Math.min(len / 2, 128); i++) {
        const c = Number(mem.u16(buf + BigInt(i * 2)));
        if (c === 0) break;
        out += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
      }
      return `L"${out}" (len=${len})`;
    } catch { return hex(v); }
  },
  ansi: (mem, v) => {
    try {
      let out = "";
      for (let i = 0; i < 160; i++) {
        const c = mem.u8(v + BigInt(i));
        if (c === 0) break;
        out += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
      }
      return `"${out}"`;
    } catch { return hex(v); }
  },
  ntstatus: (_mem, v) => {
    const name = ntstatusName(v);
    return hex(v) + (name ? ` (${name})` : "");
  },
};

DEC.handle = DEC.hex;
DEC.fnptr = DEC.hex;

/** Per-API argument decoders; index-aligned with the x64 ABI arg list. */
export const API_SIGNATURES = {
  // memory / strings
  ExAllocatePool2: [["flags", "hex"], ["size", "dec"], ["tag", "tag"]],
  ExAllocatePoolWithTag: [["type", "i32"], ["size", "dec"], ["tag", "tag"]],
  ExFreePoolWithTag: [["ptr", "hex"], ["tag", "tag"]],
  RtlInitUnicodeString: [["dest", "ustr"], ["src", "wstr"]],
  RtlCopyUnicodeString: [["dst", "ustr"], ["src", "ustr"]],
  wcslen: [["s", "wstr"]],
  _vsnprintf: [["buf", "hex"], ["max", "dec"], ["fmt", "ansi"]],
  vsprintf: [["buf", "hex"], ["fmt", "ansi"]],
  sprintf: [["buf", "hex"], ["fmt", "ansi"]],
  DbgPrint: [["fmt", "ansi"]],
  DbgPrintEx: [["comp", "hex"], ["level", "hex"], ["fmt", "ansi"]],
  MmGetSystemRoutineAddress: [["name", "ustr"]],

  // devices / IRPs
  IoCreateDevice: [["drv", "hex"], ["extSize", "dec"], ["name", "ustr"]],
  IoCreateSymbolicLink: [["link", "ustr"], ["target", "ustr"]],
  IoDeleteSymbolicLink: [["link", "ustr"]],
  IofCompleteRequest: [["irp", "hex"], ["boost", "dec"]],
  IoCompleteRequest: [["irp", "hex"], ["boost", "dec"]],
  IofCallDriver: [["dev", "hex"], ["irp", "hex"]],
  IoGetRequestorProcessId: [["irp", "hex"]],

  // sync
  KeAcquireSpinLockRaiseToDpc: [["sl", "hex"]],
  KeAcquireSpinLock: [["sl", "hex"], ["oldIrql", "hex"]],
  KeReleaseSpinLock: [["sl", "hex"], ["newIrql", "irql"]],
  KeWaitForSingleObject: [["obj", "hex"], ["reason", "dec"], ["mode", "dec"], ["alertable", "bool"], ["timeout", "hex"]],
  KeInitializeEvent: [["ev", "hex"], ["type", "dec"], ["init", "bool"]],
  KeSetEvent: [["ev", "hex"], ["increment", "dec"], ["wait", "bool"]],

  // processes / threads
  PsCreateSystemThread: [["hOut", "hex"], ["access", "hex"], ["oa", "hex"], ["proc", "hex"], ["clientId", "hex"], ["start", "hex"], ["ctx", "hex"]],
  PsTerminateSystemThread: [["status", "ntstatus"]],
  PsLookupProcessByProcessId: [["pid", "pid"], ["out", "hex"]],
  PsGetProcessId: [["eproc", "hex"]],
  ZwOpenProcess: [["hOut", "hex"], ["access", "hex"], ["oa", "hex"], ["cid", "hex"]],
  ZwTerminateProcess: [["h", "hex"], ["status", "ntstatus"]],
  ZwOpenProcess__dummy: [],

  // callbacks
  ObRegisterCallbacks: [["reg", "hex"]],
  PsSetCreateProcessNotifyRoutine: [["cb", "fnptr"], ["remove", "bool"]],
  PsSetCreateThreadNotifyRoutine: [["cb", "fnptr"]],
  PsSetLoadImageNotifyRoutine: [["cb", "fnptr"]],
  PsRemoveCreateThreadNotifyRoutine: [["cb", "fnptr"]],
  PsRemoveLoadImageNotifyRoutine: [["cb", "fnptr"]],

  // registry / files
  ZwOpenKey: [["hOut", "hex"], ["access", "hex"], ["oa", "hex"]],
  ZwClose: [["h", "handle"]],
  ZwCreateFile: [["hOut", "hex"], ["access", "hex"], ["oa", "hex"]],

  // KMDF loader
  WdfVersionBind: [["drv", "hex"], ["path", "ustr"], ["params", "hex"], ["info", "hex"]],
  WdfVersionBindClass: [["params", "hex"]],
  WdfLdrQueryInterface: [["params", "hex"]],

  // ETW
  EtwRegister: [["guid", "guid"], ["cb", "fnptr"], ["ctx", "hex"], ["hOut", "hex"]],
  EtwUnregister: [["h", "handle"]],
};

/* ------------------------------------------------------------- finalization */

function resolveModule(modules, va) {
  for (const m of modules ?? []) {
    if (va >= m.base && va < m.base + BigInt(m.size)) {
      return `${m.name}+0x${(va - m.base).toString(16)}`;
    }
  }
  return null;
}

/**
 * Decorate raw kernel.traceEvents into JSON-safe records with decoded args,
 * caller module+rva, and a formatted text line per event.
 * @returns {{events: object[], text: string}}
 */
export function finalizeTrace(kernel, modules = []) {
  const mem = kernel.mem;
  const events = [];
  for (const e of kernel.traceEvents) {
    const rec = {
      seq: e.seq,
      phase: e.phase,
      kind: e.kind,
      detail: e.detail ?? null,
    };

    if (e.kind === "api") {
      const sig = API_SIGNATURES[e.name];
      const argList = sig
        ? (e.args ?? []).slice(0, Math.min(sig.length, e.args?.length ?? 0))
        : (e.args ?? []).slice(0, 4);
      const parts = [];
      const decodedArgs = [];
      argList.forEach((v, i) => {
        const [argName, decName] = (sig?.[i]) ?? [`a${i}`, "hex"];
        const dec = DEC[decName] ?? DEC.hex;
        let text;
        try { text = dec(mem, v); } catch { text = hex(v); }
        decodedArgs.push({ name: argName, raw: hex(v), decoded: text });
        parts.push(`${argName}=${text}`);
      });
      const isVoid = e.ret === undefined || isVoidApi(e.name);
      let retText = null;
      if (!isVoid) {
        const statusName = ntstatusName(e.ret);
        retText =
          sigHasStatus(e.name) && statusName
            ? `${hex(e.ret)} (${statusName})`
            : hex(e.ret);
      }
      rec.name = e.name;
      rec.args = decodedArgs;
      rec.ret = retText;
      rec.irql = e.irql;
      rec.caller = resolveModule(modules, e.retAddr) ?? hex(e.retAddr);
      rec.text = isVoid
        ? `${e.name}(${parts.join(", ")})`
        : `${e.name}(${parts.join(", ")}) -> ${retText}`;
    } else if (e.kind === "dbgprint") {
      rec.text = `DbgPrint: ${e.text.replace(/\n$/, "")}`;
    } else if (e.kind === "exception") {
      rec.faultRip = resolveModule(modules, e.faultRip) ?? hex(e.faultRip);
      rec.message = e.message;
      rec.handled = e.handled;
      rec.text = `EXCEPTION ${e.message} @ ${rec.faultRip} -> ${e.handled ? "handled" : "UNHANDLED"} (${e.detail})`;
    } else if (e.kind === "thread") {
      rec.routine = resolveModule(modules, e.startRoutine) ?? hex(e.startRoutine);
      rec.text = `SystemThread(${rec.routine}, ctx=${hex(e.startContext)}) ${e.detail ?? ""}`;
    } else if (e.kind === "dpc") {
      rec.routine = resolveModule(modules, e.routine) ?? hex(e.routine);
      rec.text = `DPC(${rec.routine}) ${e.detail ?? ""}`;
    } else if (e.kind === "workitem") {
      rec.routine = resolveModule(modules, e.worker) ?? hex(e.worker);
      rec.text = `WorkItem(${rec.routine})`;
    } else if (e.kind === "apc") {
      rec.routine = resolveModule(modules, e.routine) ?? hex(e.routine);
      rec.text = `Apc(${rec.routine})`;
    } else if (e.kind === "etw") {
      rec.text = `ETW ${e.op ?? ""} ${e.summary ?? ""}`.trim();
      Object.assign(rec, { op: e.op, summary: e.summary });
    } else if (e.kind === "mem_write") {
      // Linux: guest memory writes (dropper path strings, struct path, etc)
      const a = e.addr !== undefined ? hex(e.addr) : "0x0";
      const sz = e.size ?? (e.data ? e.data.length : "?");
      const prev = e.preview ? ` "${e.preview}"` : (e.data ? ` "${String(e.data).slice(0,32)}"` : "");
      rec.addr = a; rec.size = sz; rec.preview = e.preview ?? e.data;
      if(e.name) rec.text = `mem_write ${e.name} addr=${a} size=${sz}${prev}`;
      else rec.text = `mem_write addr=${a} size=${sz}${prev}`;
      if(e.filename) rec.text += ` file="${e.filename}"`;
      if(e.mnt !== undefined) rec.text += ` mnt=${hex(e.mnt)} dentry=${hex(e.dentry)}`;
      if(e.exe) rec.text += ` exe="${e.exe}" argv=[${(e.argv||[]).join(",")}]`;
      if(e.pc) rec.pc = hex(e.pc);
    } else if (e.kind === "cred") {
      rec.text = `cred ${e.op} 0x${(e.cred??0n).toString(16)} uid=${e.uid??""}`;
    } else if (e.kind === "msr") {
      rec.text = `msr ${e.op} msr=0x${(e.msr??0n).toString(16)}`;
    } else if (e.kind === "ftrace" || e.kind === "kprobe" || e.kind === "bpf" || e.kind === "ebpf") {
      rec.text = `${e.kind} ${e.op||""} ${e.symbol||""} ${e.handler?hex(e.handler):""}`.trim();
    } else {
      rec.text = e.detail ?? e.kind;
    }

    events.push(rec);
  }

  // formatted block, phase-grouped headers inserted on transitions
  const lines = [];
  let lastPhase = null;
  for (const ev of events) {
    if (ev.phase !== lastPhase) {
      lines.push(`--- phase: ${ev.phase} ---`);
      lastPhase = ev.phase;
    }
    const seq = `[${String(ev.seq).padStart(4, "0")}]`;
    const where = ev.caller ?? "";
    lines.push(`${seq} ${ev.phase.padEnd(22)} ${where ? where.padEnd(20) + "  " : ""}${ev.text}`);
  }
  return { events, text: lines.join("\n") };
}

const STATUS_RETURNING = new Set([
  "ZwOpenProcess", "ZwTerminateProcess", "ZwOpenKey", "ZwClose", "ZwCreateFile",
  "ZwReadFile", "ZwWriteFile", "PsTerminateSystemThread", "ObRegisterCallbacks",
  "EtwRegister", "EtwWrite", "EtwWriteTransfer", "MmGetSystemRoutineAddress",
  "PsCreateSystemThread", "PsSetCreateProcessNotifyRoutineEx",
  "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine",
  "WdfVersionBind", "WdfVersionBindClass", "IoCreateDevice", "IoCreateSymbolicLink",
]);
function sigHasStatus(name) {
  return STATUS_RETURNING.has(name) || name?.startsWith("Zw") || name?.startsWith("Nt");
}

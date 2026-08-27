/**
 * Kernel notification-callback INVOCATION engine.
 *
 * Until now ntsim merely recorded registrations (winapi.mjs pushes callback
 * VAs into kernel.notifyRoutines.{process,thread,image}); nothing ever
 * called them. This module adds the missing dispatch side, modeled after
 * Psp*NotifyRoutine semantics and invoked exactly like deferred work:
 * through kernel.cpu.callFunction — identical under JsInterpreter and
 * Unicorn/QEMU backends because every argument (PS_CREATE_NOTIFY_INFO,
 * UNICODE_STRINGs, IMAGE_INFO) is materialized as real bytes in memory.
 *
 * Layouts (teaching subset, x64):
 *   _PS_CREATE_NOTIFY_INFO (0x48 bytes):
 *     +0x00 Size            +0x04 FileObjectUsable    +0x08 FileObject
 *     +0x10 ParentProcessId +0x18 CreatingThreadId    +0x20 CreatingProcessId
 *     +0x28 ImageFileName   (PUNICODE_STRING)         +0x30 CommandLine (PUNICODE_STRING)
 *     +0x38 FileOpenParams? (reserved 0)             +0x40 CreationStatus (NTSTATUS, writable!)
 *   A callback writing a negative NTSTATUS here BLOCKS process creation —
 *   the exact mechanism CrowdStrike-class sensors use (DbgMan teardown §1).
 *   _IMAGE_INFO (0x20): +0x00 Properties (bit8 SystemModeImage) +0x08 ImageBase +0x10 ImageSelector/Size...
 */

import { M64 } from "./cpu.mjs";

export const PS_CREATE_NOTIFY_INFO_SIZE = 0x48;
export const CREATE_INFO_CREATION_STATUS_OFFSET = 0x40n;

/** Materialize a PS_CREATE_NOTIFY_INFO (+ backing UNICODE_STRINGs) in memory. */
export function buildCreateInfo(kernel, { pid, parentPid = 4n, imageName, commandLine = null }) {
  const mem = kernel.mem;
  const base = kernel.allocPool(Number(PS_CREATE_NOTIFY_INFO_SIZE), "CrIn");
  const usName = kernel.allocPool(16, "CrUs");
  const bufName = kernel.allocPool((imageName.length + 1) * 2, "CrNb");
  // UNICODE_STRING {Len u16, Max u16, pad, Buffer ptr}
  mem.w16(usName, imageName.length * 2);
  mem.w16(usName + 2n, imageName.length * 2 + 2);
  mem.w64(usName + 8n, bufName);
  mem.writeUtf16(bufName, imageName);

  let cmdUs = 0n;
  if (commandLine) {
    cmdUs = kernel.allocPool(16, "CrUs");
    const bufCmd = kernel.allocPool((commandLine.length + 1) * 2, "CrNb");
    mem.w16(cmdUs, commandLine.length * 2);
    mem.w16(cmdUs + 2n, commandLine.length * 2 + 2);
    mem.w64(cmdUs + 8n, bufCmd);
    mem.writeUtf16(bufCmd, commandLine);
  }

  mem.w32(base, PS_CREATE_NOTIFY_INFO_SIZE);      // Size
  mem.w32(base + 4n, 0);                          // FileObjectUsable = false
  mem.w64(base + 8n, 0n);                         // FileObject = NULL (slow path)
  mem.w64(base + 0x10n, BigInt(parentPid));       // ParentProcessId
  mem.w64(base + 0x18n, 0n);                      // CreatingThreadId
  mem.w64(base + 0x20n, 0n);                      // CreatingProcessId (creator)
  mem.w64(base + 0x28n, usName);                  // ImageFileName
  mem.w64(base + 0x30n, cmdUs);                   // CommandLine
  mem.w32(base + CREATE_INFO_CREATION_STATUS_OFFSET, 0); // STATUS_SUCCESS default
  void pid;
  return base;
}

/** Materialize IMAGE_INFO + FULL_IMAGE_NAME for image-load callbacks. */
export function buildImageInfo(kernel, { imageName, pid, base, size, kernelImage = false }) {
  const mem = kernel.mem;
  const info = kernel.allocPool(0x20, "ImIn");
  mem.w32(info, kernelImage ? 0x100 : 0);          // Properties.SystemModeImage
  mem.w64(info + 8n, BigInt(base ?? 0n));
  mem.w64(info + 0x10n, BigInt(size ?? 0));
  const us = kernel.allocPool(16, "ImUs");
  const buf = kernel.allocPool((imageName.length + 1) * 2, "ImNb");
  mem.w16(us, imageName.length * 2);
  mem.w16(us + 2n, imageName.length * 2 + 2);
  mem.w64(us + 8n, buf);
  mem.writeUtf16(buf, imageName);
  void pid;
  return { info, fullName: us };
}

/**
 * Install fire* methods onto an NtKernel instance. Idempotent.
 */
export function installNotifyEngine(kernel) {
  if (kernel.fireProcessNotify) return kernel;

  kernel.notifyKinds = { processEx: new Set(), thread: new Set(), image: new Set() };

  /** Track which convention (legacy vs Ex) each process callback uses. */
  const trackProcessKind = (apiName, isEx) => {
    const orig = kernel.apiImpls.get(apiName);
    if (!orig) return;
    kernel.apiImpls.set(apiName, function (cb, ...rest) {
      const va = BigInt.asUintN(64, BigInt(cb)) & M64;
      const removing = Number(rest[0] ?? 0) === 1;
      if (removing) kernel.notifyKinds.processEx.delete(va);
      else if (isEx) kernel.notifyKinds.processEx.add(va);
      return orig.call(this, cb, ...rest);
    });
  };
  trackProcessKind("PsSetCreateProcessNotifyRoutine", false);
  trackProcessKind("PsSetCreateProcessNotifyRoutineEx", true);
  trackProcessKind("PsSetCreateProcessNotifyRoutineEx2", true);

  /**
   * Drive one process-create event through every registered callback.
   * @returns {{blocked:boolean, status:bigint, log:string[], infoAddr:bigint|null}}
   */
  kernel.fireProcessNotify = function fireProcessNotify(pid, imageName, opts = {}) {
    const log = [];
    const cbs = [...(kernel.notifyRoutines?.process ?? [])];
    let blocked = false;
    let status = 0n;
    let infoAddr = null;
    for (const cbVa of cbs) {
      const isEx = kernel.notifyKinds.processEx.has(BigInt(cbVa));
      try {
        if (isEx) {
          infoAddr = infoAddr ?? buildCreateInfo(kernel, {
            pid, imageName,
            parentPid: opts.parentPid ?? 4n,
            commandLine: opts.commandLine ?? null,
          });
          const eproc = opts.eproc ??
            (kernel.PsActiveProcessHead
              ? (kernel.findEprocessByPid(BigInt(pid)) ?? 0n)
              : 0n);
          const r = kernel.cpu.callFunction(BigInt(cbVa), [eproc, infoAddr]);
          log.push(`nt!PspProcessNotify: Ex cb ${hex(cbVa)} -> ${r.status}`);
          const cs = kernel.mem.u32(infoAddr + CREATE_INFO_CREATION_STATUS_OFFSET);
          if (cs !== 0) {
            status = BigInt.asUintN(32, BigInt(cs));
            blocked = (status & 0x80000000n) !== 0n;
            log.push(`nt!PspProcessNotify: CreationStatus=0x${cs.toString(16)} ` +
              `${blocked ? "(creation BLOCKED)" : ""}`);
            if (blocked) break;
          }
        } else {
          const r = kernel.cpu.callFunction(BigInt(cbVa),
            [opts.parentPid ?? 4n, BigInt(pid), 1n]);
          log.push(`nt!PspProcessNotify: legacy cb ${hex(cbVa)} -> ${r.status}`);
        }
      } catch (e) {
        log.push(`notify cb ${hex(cbVa)} faulted: ${e.message}`);
      }
    }
    for (const l of log) kernel.dbgLog.push(l);
    return { blocked, status, log, infoAddr };
  };

  kernel.fireThreadNotify = function fireThreadNotify(pid, tid, create = true) {
    const log = [];
    for (const cbVa of kernel.notifyRoutines?.thread ?? []) {
      const r = kernel.cpu.callFunction(BigInt(cbVa), [BigInt(pid), BigInt(tid), create ? 1n : 0n]);
      log.push(`nt!PspThreadNotify: cb ${hex(cbVa)} -> ${r.status}`);
    }
    for (const l of log) kernel.dbgLog.push(l);
    return { log };
  };

  kernel.fireImageNotify = function fireImageNotify(imageName, pid, opts = {}) {
    const log = [];
    const { info, fullName } = buildImageInfo(kernel, { imageName, pid, ...opts });
    for (const cbVa of kernel.notifyRoutines?.image ?? []) {
      const r = kernel.cpu.callFunction(BigInt(cbVa), [fullName, BigInt(pid), info]);
      log.push(`nt!PspImageNotify: cb ${hex(cbVa)} -> ${r.status}`);
    }
    for (const l of log) kernel.dbgLog.push(l);
    return { log, info, fullName };
  };
}

function hex(v) {
  return "0x" + BigInt(v).toString(16);
}

/**
 * winapi-extra.mjs — long-tail kernel exports needed by filter/security
 * drivers (SystemInformer.sys and friends): the rest of the FLTMGR surface,
 * Io/Ob/Ps/Ke/Ex/Mm/Se/Cm/Rtl helpers and the BCrypt/Ldr entry points.
 *
 * Two tiers:
 *   - hand-modeled (this file): behavior faithful enough for real flows —
 *     file objects, section mappings, SLISTs, rundown protection, queues,
 *     data exports, resource walks;
 *   - shallow stubs (kernel.defineShallowStub): meta-driven defaults tracked
 *     separately in `kernel.shallowStubs`, so reports stay honest about how
 *     deep the model actually goes.
 */

const STATUS_SUCCESS = 0x00000000n;
const STATUS_NOT_FOUND = 0xc0000034n;
const STATUS_NOT_SUPPORTED = 0xc00000bbn;
const STATUS_UNSUCCESSFUL = 0xc0000001n;
const STATUS_INVALID_PARAMETER = 0xc000000dn;

/** Exports that get meta-driven default behavior (no hand model). */
export const SHALLOW_EXPORTS = new Set([
  // Meta-driven defaults (ntstatus -> SUCCESS, void -> no-op, Is*/Are*/Does* -> FALSE).
  // Spin-lock / lookaside / minor helpers where a no-op is the correct behavior.
  "ExQueryDepthSList", "ExGetPreviousMode", "KeAreAllApcsDisabled", "KeTestAlertThread",
  "IoGetTopLevelIrp", "IoIsFileOriginRemote", "IoIsFileObjectIgnoringSharing",
  "FsRtlIsSystemPagingFile", "FsRtlIsPagingFile", "ExfUnblockPushLock", "ExEnumHandleTable",
  "IoGetOplockKeyContextEx", "MmDoesFileHaveUserWritableReferences",
  "IoGetTransactionParameterBlock", "PsGetProcessJob",
  "KeQueryActiveProcessorCountEx", "KeInitializeThreadedDpc", "KeRemoveQueueDpcEx",
  "KeAcquireSpinLockForDpc", "KeReleaseSpinLockForDpc", "ExAcquireSpinLockShared",
  "ExAcquireSpinLockSharedAtDpcLevel", "ExAcquireSpinLockExclusive", "ExReleaseSpinLockShared",
  "ExReleaseSpinLockSharedFromDpcLevel", "ExReleaseSpinLockExclusive",
  "KeAcquireSpinLockAtDpcLevel", "KeReleaseSpinLockFromDpcLevel",
  "KeAcquireInStackQueuedSpinLock", "KeAcquireInStackQueuedSpinLockAtDpcLevel",
  "KeReleaseInStackQueuedSpinLock", "KeReleaseInStackQueuedSpinLockFromDpcLevel",
  "IoAcquireVpbSpinLock", "IoReleaseVpbSpinLock",
  "ExInitializeNPagedLookasideList", "ExDeleteNPagedLookasideList",
  "ExInitializePagedLookasideList", "ExDeletePagedLookasideList",
  "ZwAlpcConnectPort", "DbgSetDebugPrintCallback",
]);

export function installWinApiExtra(kernel, ctx) {
  const { impls, k, usRead } = ctx;
  const mem = kernel.mem;
  const STATUS = STATUS_SUCCESS;

  const foOf = (fo) => kernel.fileObjects?.get(ptrSizeMaskSafe(fo)) ?? null;
  function ptrSizeMaskSafe(v) {
    try { return BigInt.asUintN(64, BigInt(v ?? 0n)); } catch { return 0n; }
  }
  const fourCc = (tag) => {
    try {
      const v = Number(BigInt.asUintN(32, BigInt(tag)));
      return String.fromCharCode(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
    } catch { return "????"; }
  };

  // ------------------------------------------------------------- FLTMGR
  const fltNameInfo = (path) => {
    // FLT_FILE_NAME_INFORMATION: Name UNICODE_STRING at +0, then
    // Volume/Share/Extension/ParentDir/Stream UNICODE_STRINGs, then
    // Format/Flags (ULONGs). 0x90 bytes is plenty.
    const info = k.alloc(0x90);
    const put = (off, str) => {
      const buf = k.alloc(Math.max(2, str.length * 2 + 2));
      mem.writeUtf16(buf, str);
      mem.w16(info + BigInt(off), str.length * 2);
      mem.w16(info + BigInt(off + 2), str.length * 2 + 2);
      mem.w64(info + BigInt(off + 8), buf);
    };
    put(0x00, path);
    put(0x10, "\\Device\\HarddiskVolume1");
    put(0x20, "\\kfsample");
    put(0x30, ".sys");
    put(0x40, "\\Device\\HarddiskVolume1\\");
    mem.w32(info + 0x50n, 0); // Format = FLT_FILE_NAME_NORMALIZED
    mem.w32(info + 0x54n, 0); // Flags
    return info;
  };
  kernel.fltNameInfos = kernel.fltNameInfos ?? new Map();

  k.define("FltGetFileNameInformation", (callbackData, nameOptions, nameInfoOut) => {
    void callbackData; void nameOptions;
    const rec = kernel.fileObjects?.values().next().value;
    const info = fltNameInfo(rec?.path ?? "\\Device\\HarddiskVolume1\\kfsample.tmp");
    if (nameInfoOut) mem.w64(ptrSizeMaskSafe(nameInfoOut), info);
    return STATUS;
  });
  k.define("FltGetFileNameInformationUnsafe", (fileObject, instance, nameOptions, nameInfoOut) => {
    void instance; void nameOptions;
    const rec = foOf(fileObject);
    const info = fltNameInfo(rec?.path ?? "\\Device\\HarddiskVolume1\\kfsample.tmp");
    if (nameInfoOut) mem.w64(ptrSizeMaskSafe(nameInfoOut), info);
    return STATUS;
  });
  k.define("FltReferenceFileNameInformation", (nameInfo) => ptrSizeMaskSafe(nameInfo));
  k.define("FltParseFileNameInformation", (nameInfo) => {
    // already parsed by fltNameInfo(); re-assert the component strings
    void nameInfo;
    return STATUS;
  });
  k.define("FltReleaseFileNameInformation", (nameInfo) => { void nameInfo; return undefined; });
  k.define("FltGetVolumeProperties", (volume, propsOut, propsLength, bytesReturned) => {
    void volume;
    const len = Number(propsLength) || 0;
    const need = 0x50;
    if (bytesReturned) mem.w64(ptrSizeMaskSafe(bytesReturned), BigInt(need));
    if (propsOut && len >= need) {
      mem.write(ptrSizeMaskSafe(propsOut), new Uint8Array(need));
      mem.w32(ptrSizeMaskSafe(propsOut) + 0x00n, 7);       // DeviceType = FILE_DEVICE_DISK
      mem.w32(ptrSizeMaskSafe(propsOut) + 0x04n, 0);       // DeviceCharacteristics
      mem.w32(ptrSizeMaskSafe(propsOut) + 0x08n, 2);       // FileSystemType = FLT_FSTYPE_NTFS
    }
    return STATUS;
  });
  k.define("FltGetVolumeName", (volume, nameOut, nameLength) => {
    void volume; void nameLength;
    const str = "\\Device\\HarddiskVolume1";
    const buf = k.alloc(str.length * 2 + 2);
    mem.writeUtf16(buf, str);
    if (nameOut) {
      mem.w16(ptrSizeMaskSafe(nameOut), str.length * 2);
      mem.w16(ptrSizeMaskSafe(nameOut) + 2n, str.length * 2 + 2);
      mem.w64(ptrSizeMaskSafe(nameOut) + 8n, buf);
    }
    return STATUS;
  });
  k.define("FltGetFileSystemType", (fileObject, fileSystemTypeOut) => {
    void fileObject;
    if (fileSystemTypeOut) mem.w32(ptrSizeMaskSafe(fileSystemTypeOut), 2); // NTFS
    return STATUS;
  });
  k.define("FltGetTunneledName", (fileObject, nameInfo, tunneledNameOut) => {
    void fileObject; void nameInfo; void tunneledNameOut;
    return STATUS_NOT_FOUND; // no tunneled name in the emulated world
  });
  k.define("FltBuildDefaultSecurityDescriptor", (sdOut, desiredAccess) => {
    void desiredAccess;
    if (sdOut) {
      const sd = k.alloc(0x40);
      mem.write(sd, [0x01, 0x00, 0x04, 0x80]); // revision 1, SE_SELF_RELATIVE
      mem.w64(ptrSizeMaskSafe(sdOut), sd);
    }
    return STATUS;
  });
  k.define("FltFreeSecurityDescriptor", (sd) => { void sd; return undefined; });
  k.define("FltObjectReference", (object) => { void object; return STATUS; });
  k.define("FltObjectDereference", (object) => { void object; return undefined; });
  k.define("FltCreateCommunicationPort", (filter, portOut, objAttr, context, connect, disconnect,
    message, maxConnections) => {
    void filter; void objAttr; void context; void connect; void disconnect; void message; void maxConnections;
    const port = k.alloc(0x60);
    mem.write(port, [0x46, 0x6c, 0x74, 0x50]); // 'FltP'
    if (portOut) mem.w64(ptrSizeMaskSafe(portOut), port);
    kernel.dbgLog.push("[flt] FltCreateCommunicationPort -> modeled port (no user-mode client attached)");
    return STATUS;
  });
  k.define("FltCloseCommunicationPort", (port) => { void port; return undefined; });
  k.define("FltCloseClientPort", (filter, clientPort) => { void filter; void clientPort; return undefined; });
  k.define("FltSendMessage", (filter, clientPort, replyPort, senderBuffer, senderBufferLength,
    replyBuffer, replyLength, timeout) => {
    void filter; void clientPort; void replyPort; void senderBuffer; void senderBufferLength;
    void replyBuffer; void timeout;
    if (replyLength) mem.w32(ptrSizeMaskSafe(replyLength), 0);
    return STATUS_UNSUCCESSFUL; // no user-mode client: drivers take their fallback path
  });

  // ------------------------------------------------------- Io / file object
  k.define("IoCreateFile", (objAttr, access, iosb, allocSize, attrs, share, disp,
    options, eaBuf, eaLen, createType, internalParams, opts2) => {
    void allocSize; void attrs; void share; void options; void eaBuf; void eaLen;
    void createType; void internalParams; void opts2;
    const hOut = k.alloc(8);
    const st = impls.ZwCreateFile(hOut, access, objAttr, iosb, 0n, 0n, 0n, disp, 0n, 0n, 0n);
    if (st === STATUS && kernel._createFileObject) {
      const path = (() => { try { return usRead(mem, mem.u64(ptrSizeMaskSafe(objAttr) + 0x10n)).str; } catch { return ""; } })();
      const fo = kernel._createFileObject(path || "<file>");
      kernel.handles.set(mem.u64(hOut), { __file: path, __fileObject: ptrSizeMaskSafe(fo) });
    }
    return st;
  });
  k.define("IoGetRelatedDeviceObject", (fileObject) => {
    const rec = foOf(fileObject);
    const dev = k.alloc(0x200);
    mem.write(dev, [0x44, 0x65, 0x76, 0x4f]); // 'DevO'
    kernel.dbgLog.push(`[io] IoGetRelatedDeviceObject(${rec ? `"${rec.path}"` : "0x0"}) -> modeled DEVICE_OBJECT`);
    return dev;
  });
  k.define("IoGetDeviceAttachmentBaseRef", (deviceObject) => deviceObject ?? 0n);
  k.define("IoGetStackLimits", (lowOut, highOut) => {
    if (lowOut) mem.w64(lowOut, kernel.bases?.kva ?? 0x10000000n);
    if (highOut) mem.w64(highOut, (kernel.bases?.kva ?? 0x10000000n) + 0x100000n);
    return undefined;
  });
  k.define("IoQueryFullDriverPath", (driverObject, fullPathOut) => {
    void driverObject;
    if (fullPathOut) {
      const s = "\\SystemRoot\\System32\\drivers\\kfsample.sys";
      const buf = k.alloc(s.length * 2 + 2);
      mem.writeUtf16(buf, s);
      mem.w16(fullPathOut, s.length * 2);
      mem.w16(fullPathOut + 2n, s.length * 2 + 2);
      mem.w64(fullPathOut + 8n, buf);
    }
    return STATUS;
  });

  // ------------------------------------------------------------- Ob
  k.define("ObOpenObjectByPointer", (object, handleAttributes, passedAccessState,
    desiredAccess, objectType, accessMode, handleOut) => {
    void handleAttributes; void passedAccessState; void desiredAccess; void objectType; void accessMode;
    const h = kernel.nextObHandle = (kernel.nextObHandle ?? 0x6000n) + 4n;
    kernel.handles.set(h, { __object: ptrSizeMaskSafe(object) });
    if (handleOut) mem.w64(handleOut, h);
    return STATUS;
  });
  k.define("ObGetObjectType", (object) => {
    void object;
    const slot = kernel.dataExports?.get("IoFileObjectType");
    return slot ? mem.u64(slot) : 0n;
  });
  k.define("ObDuplicateObject", (sourceProcess, sourceHandle, targetProcess, targetHandleOut,
    desiredAccess, handleAttributes, options) => {
    void sourceProcess; void targetProcess; void desiredAccess; void handleAttributes; void options;
    const h = ptrSizeMaskSafe(sourceHandle);
    const rec = kernel.handles.get(h) ?? { __dup: h };
    const nh = kernel.nextObHandle = (kernel.nextObHandle ?? 0x6000n) + 4n;
    kernel.handles.set(nh, rec);
    if (targetHandleOut) mem.w64(targetHandleOut, nh);
    return STATUS;
  });
  k.define("ObSetHandleAttributes", () => STATUS);

  // ------------------------------------------------------------- Ps
  k.define("PsGetThreadProcess", (thread) => {
    try {
      const off = kernel.tables.offsetOf("_ETHREAD", "ThreadsProcess");
      if (off !== null && thread) return mem.u64(ptrSizeMaskSafe(thread) + BigInt(off));
    } catch { /* fall through */ }
    return kernel.findEprocessByPid(4n) ?? 0n;
  });
  k.define("PsGetProcessSectionBaseAddress", (eproc) => {
    try {
      const off = kernel.tables.offsetOf("_EPROCESS", "SectionBaseAddress");
      if (off !== null && eproc) return mem.u64(ptrSizeMaskSafe(eproc) + BigInt(off));
    } catch { /* fall through */ }
    return 0x140000000n;
  });
  k.define("PsGetCurrentThreadTeb", () => kernel.tebVa ?? (kernel.tebVa = k.alloc(0x1000)));
  k.define("PsGetThreadTeb", () => kernel.tebVa ?? (kernel.tebVa = k.alloc(0x1000)));
  k.define("PsReferenceProcessFilePointer", (eproc, fileObjectOut) => {
    void eproc;
    const fo = kernel._createFileObject ? kernel._createFileObject("\\SystemRoot\\System32\\kfsample.exe") : 0n;
    if (fileObjectOut) mem.w64(fileObjectOut, fo);
    return STATUS;
  });
  k.define("PsLookupProcessThreadByCid", (cid, processOut, threadOut) => {
    if (!cid) return STATUS_INVALID_PARAMETER;
    const pid = mem.u64(ptrSizeMaskSafe(cid));
    const tid = mem.u64(ptrSizeMaskSafe(cid) + 8n);
    const eproc = kernel.findEprocessByPid(pid);
    if (processOut) mem.w64(processOut, eproc ?? 0n);
    if (threadOut) {
      // synthesize a thread handle-ish pointer for the pid (enough for drivers
      // that only pass it back into other modeled Ps APIs)
      const thr = kernel.findEthreadByTid?.(tid) ?? 0n;
      mem.w64(threadOut, thr);
    }
    return eproc ? STATUS : STATUS_NOT_FOUND;
  });
  k.define("PsSetCreateThreadNotifyRoutineEx", (routine) => {
    kernel.notifyRoutines.thread.push(ptrSizeMaskSafe(routine));
    kernel.dbgLog.push(`[ps] PsSetCreateThreadNotifyRoutineEx(0x${ptrSizeMaskSafe(routine).toString(16)}) registered`);
    return STATUS;
  });
  k.define("PsAcquireProcessExitSynchronization", () => STATUS);
  k.define("PsReleaseProcessExitSynchronization", () => undefined);

  // ------------------------------------------------------------- Mm
  const mapSection = (sizeHint) => {
    const size = Math.max(0x1000, Math.min(Number(sizeHint) || 0x1000, 1 << 22));
    const va = k.alloc(size);
    mem.write(va, new Uint8Array(size));
    return va;
  };
  k.define("MmCreateSection", (sectionOut, desiredAccess, objAttr, maxSize, pageProtection,
    allocationAttributes, fileHandle, parameters) => {
    void desiredAccess; void objAttr; void maxSize; void pageProtection;
    void allocationAttributes; void fileHandle; void parameters;
    const sec = k.alloc(0x40);
    mem.write(sec, [0x53, 0x65, 0x63, 0x74]); // 'Sect'
    if (sectionOut) mem.w64(sectionOut, sec);
    return STATUS;
  });
  k.define("MmMapViewOfSection", (section, process, baseOut, zeroBits, commitSize,
    sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect) => {
    void section; void process; void zeroBits; void commitSize; void sectionOffset;
    void inheritDisposition; void allocationType; void win32Protect;
    const va = mapSection(viewSize ? mem.u64(ptrSizeMaskSafe(viewSize)) : 0x1000);
    if (baseOut) mem.w64(baseOut, va);
    if (viewSize) mem.w64(ptrSizeMaskSafe(viewSize), 0x1000);
    return STATUS;
  });
  k.define("MmUnmapViewOfSection", () => STATUS);
  k.define("MmMapViewInSystemSpace", (section, mappedBaseOut, viewSize) => {
    void section;
    const va = mapSection(viewSize ? mem.u64(ptrSizeMaskSafe(viewSize)) : 0x1000);
    if (mappedBaseOut) mem.w64(mappedBaseOut, va);
    return STATUS;
  });
  k.define("MmMapViewInSystemSpaceEx", (section, mappedBaseOut, viewSize, sectionOffset, flags) => {
    void section; void sectionOffset; void flags;
    const va = mapSection(viewSize ? mem.u64(ptrSizeMaskSafe(viewSize)) : 0x1000);
    if (mappedBaseOut) mem.w64(mappedBaseOut, va);
    return STATUS;
  });
  k.define("MmUnmapViewInSystemSpace", () => STATUS);
  k.define("MmProbeAndLockProcessPages", (memoryDescriptorList, process, address, length,
    writeOperation, operation) => {
    void process; void address; void length; void writeOperation; void operation;
    void memoryDescriptorList;
    return STATUS;
  });
  k.define("MmCopyMemory", (target, source, numberOfBytes, mmFlags, numberOfBytesTransferred) => {
    const len = Math.min(Number(numberOfBytes) || 0, 1 << 20);
    try { mem.write(ptrSizeMaskSafe(target), mem.read(ptrSizeMaskSafe(source), len)); } catch { /* unreadable */ }
    if (numberOfBytesTransferred) mem.w64(ptrSizeMaskSafe(numberOfBytesTransferred), BigInt(len));
    return STATUS;
  });

  // ------------------------------------------------------------- Zw
  k.define("ZwQueryInformationProcess", (handle, cls, buf, len, retLen) => {
    void handle; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n) mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    if (retLen) mem.w32(ptrSizeMaskSafe(retLen), n);
    return STATUS;
  });
  k.define("ZwQueryInformationThread", (handle, cls, buf, len, retLen) => {
    void handle; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n) mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    if (retLen) mem.w32(ptrSizeMaskSafe(retLen), n);
    return STATUS;
  });

  // ------------------------------------------------------------- Cm
  k.define("CmCallbackGetKeyObjectIDEx", (cookie, object, objectIdOut, objectNameOut, flags) => {
    void cookie; void object; void flags;
    const id = k.alloc(0x40);
    mem.write(id, [0x4b, 0x49, 0x44, 0x00]); // 'KID'
    if (objectIdOut) mem.w64(ptrSizeMaskSafe(objectIdOut), id);
    if (objectNameOut) mem.w64(ptrSizeMaskSafe(objectNameOut), 0n);
    return STATUS;
  });
  k.define("CmCallbackReleaseKeyObjectIDEx", (objectId) => { void objectId; return undefined; });

  // ------------------------------------------------------------- misc
  k.define("DbgSetDebugPrintCallback", (callback, enable) => {
    void callback; void enable;
    return STATUS;
  });

  // ------------------------------------------------- deep long-tail models
  // Kernel queues (KQUEUE): real FIFO over a LIST_ENTRY so waiters see entries.
  kernel.kqueues = kernel.kqueues ?? new Map();
  k.define("KeInitializeQueue", (queue, count) => {
    void count;
    const q = ptrSizeMaskSafe(queue);
    mem.write(q, new Uint8Array(0x80));
    mem.write(q, [0x4b, 0x51, 0x75, 0x65]); // 'KQue'
    kernel.kqueues.set(q, []);
    return undefined;
  });
  k.define("KeInsertQueue", (queue, entry) => {
    const list = kernel.kqueues.get(ptrSizeMaskSafe(queue));
    if (!list) return 0n;
    list.push(ptrSizeMaskSafe(entry));
    return 1n; // TRUE
  });
  k.define("KeRemoveQueueEx", (queue, waitMode, timeout, alertable) => {
    void waitMode; void timeout; void alertable;
    const list = kernel.kqueues.get(ptrSizeMaskSafe(queue));
    if (!list || !list.length) return 0n; // empty -> NULL
    return list.shift();
  });
  k.define("KeRundownQueue", (queue) => {
    kernel.kqueues.set(ptrSizeMaskSafe(queue), []);
    return undefined;
  });

  // Rtl helpers with real behavior.
  k.define("RtlInitUnicodeStringEx", (dest, src) => {
    if (!dest) return STATUS_INVALID_PARAMETER;
    return impls.RtlInitUnicodeString(dest, src) === undefined ? STATUS : STATUS_INVALID_PARAMETER;
  });
  k.define("RtlInitAnsiStringEx", (dest, src) => {
    if (!dest) return STATUS_INVALID_PARAMETER;
    return impls.RtlInitAnsiString(dest, src) === undefined ? STATUS : STATUS_INVALID_PARAMETER;
  });
  k.define("RtlDuplicateUnicodeString", (flags, srcUs, destUs) => {
    void flags;
    if (!srcUs || !destUs) return STATUS_INVALID_PARAMETER;
    const src = usRead(mem, ptrSizeMaskSafe(srcUs));
    const buf = k.alloc(Math.max(2, src.length + 2));
    if (src.buffer && src.length) mem.write(buf, mem.read(src.buffer, src.length));
    mem.w16(ptrSizeMaskSafe(destUs), src.length);
    mem.w16(ptrSizeMaskSafe(destUs) + 2n, src.length + 2);
    mem.w64(ptrSizeMaskSafe(destUs) + 8n, buf);
    return STATUS;
  });
  k.define("RtlImageNtHeaderEx", (flags, base, size, ntHeaderOut) => {
    void flags; void size;
    const b = ptrSizeMaskSafe(base);
    try {
      if (mem.u16(b) !== 0x5a4d) return 0xc000007bn; // STATUS_INVALID_IMAGE_FORMAT
      const lfanew = BigInt(mem.u32(b + 0x3cn));
      if (mem.u32(b + lfanew) !== 0x00004550) return 0xc000007bn;
      if (ntHeaderOut) mem.w64(ptrSizeMaskSafe(ntHeaderOut), b + lfanew);
      return STATUS;
    } catch { return STATUS_INVALID_PARAMETER; }
  });
  k.define("RtlFindExportedRoutineByName", (base, nameVa) => {
    const b = ptrSizeMaskSafe(base);
    try {
      const lfanew = BigInt(mem.u32(b + 0x3cn));
      const opt = b + lfanew + 24n;
      const expRva = BigInt(mem.u32(opt + 112n));
      if (!expRva) return 0n;
      const exp = b + expRva;
      const numNames = BigInt(mem.u32(exp + 24n));
      const namesRva = BigInt(mem.u32(exp + 32n));
      const ordsRva = BigInt(mem.u32(exp + 36n));
      const funcsRva = BigInt(mem.u32(exp + 28n));
      const want = (() => {
        let str = "";
        for (let i = 0; i < 128; i++) { const c = mem.u8(ptrSizeMaskSafe(nameVa) + BigInt(i)); if (!c) break; str += String.fromCharCode(c); }
        return str;
      })();
      for (let i = 0n; i < numNames && i < 4096n; i++) {
        const nameRva = BigInt(mem.u32(b + namesRva + i * 4n));
        let str = "";
        for (let j = 0; j < 128; j++) { const c = mem.u8(b + nameRva + BigInt(j)); if (!c) break; str += String.fromCharCode(c); }
        if (str === want) {
          const ord = BigInt(mem.u16(b + ordsRva + i * 2n));
          const fnRva = BigInt(mem.u32(b + funcsRva + ord * 4n));
          return b + fnRva;
        }
      }
      return 0n;
    } catch { return 0n; }
  });
  kernel.rtlRandomState = 0x12345678n;
  k.define("RtlRandomEx", (seedPtr) => {
    let s = kernel.rtlRandomState;
    if (seedPtr) { try { s = mem.u32(ptrSizeMaskSafe(seedPtr)); } catch { /* keep */ } }
    s = (s * 1103515245n + 12345n) & 0x7fffffffn;
    kernel.rtlRandomState = s;
    if (seedPtr) mem.w32(ptrSizeMaskSafe(seedPtr), Number(s));
    return s;
  });
  k.define("RtlWalkFrameChain", (callers, count, flags) => {
    void flags;
    const n = Math.min(Number(count) || 0, 64);
    let written = 0;
    try {
      let rsp = kernel.cpu?.regs?.rsp ?? 0n;
      for (let i = 0; i < n; i++) {
        const ret = mem.u64(rsp + 8n + BigInt(i * 8));
        if (!ret) break;
        mem.w64(ptrSizeMaskSafe(callers) + BigInt(i * 8), ret);
        written++;
      }
      void rsp;
    } catch { /* unreadable stack */ }
    return BigInt(written);
  });

  // Security / registry / Zw out-param surface.
  k.define("SeCaptureSubjectContext", (ctx) => {
    if (ctx) mem.write(ptrSizeMaskSafe(ctx), new Uint8Array(0x20));
    return undefined;
  });
  k.define("SeCaptureSubjectContextEx", (thread, process, ctx) => {
    void thread; void process;
    if (ctx) mem.write(ptrSizeMaskSafe(ctx), new Uint8Array(0x20));
    return undefined;
  });
  k.define("SeReleaseSubjectContext", (ctx) => { void ctx; return undefined; });
  k.define("SePrivilegeCheck", (required, granted, accessMode) => {
    void required; void granted; void accessMode;
    return 1n; // TRUE: treat required privileges as present
  });
  k.define("SeGetCachedSigningLevel", (file, flagsOut, levelOut, signerOut, signerSize) => {
    void file;
    if (flagsOut) mem.w32(ptrSizeMaskSafe(flagsOut), 0);
    if (levelOut) mem.w8(ptrSizeMaskSafe(levelOut), 0); // SE_SIGNING_LEVEL_UNCHECKED
    if (signerSize) mem.w32(ptrSizeMaskSafe(signerSize), 0);
    return STATUS;
  });
  k.define("CmGetBoundTransaction", () => 0n);

  k.define("ZwQueryVirtualMemory", (handle, base, cls, buf, len, retLen) => {
    void handle; void base; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n >= 0x30) {
      mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
      mem.w64(ptrSizeMaskSafe(buf) + 24n, 0x1000n);  // RegionSize
      mem.w32(ptrSizeMaskSafe(buf) + 32n, 0x04);     // MEM_COMMIT
      mem.w32(ptrSizeMaskSafe(buf) + 36n, 0x40);     // PAGE_EXECUTE_READWRITE
    } else if (buf && n) {
      mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    }
    if (retLen) mem.w64(ptrSizeMaskSafe(retLen), BigInt(Math.min(0x30, n)));
    return STATUS;
  });
  k.define("ZwQuerySection", (handle, cls, buf, len, retLen) => {
    void handle; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n) mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    if (retLen) mem.w64(ptrSizeMaskSafe(retLen), BigInt(n));
    return STATUS;
  });
  k.define("ZwQueryObject", (handle, cls, buf, len, retLen) => {
    void handle; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n) mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    if (retLen) mem.w32(ptrSizeMaskSafe(retLen), n);
    return STATUS;
  });
  k.define("ZwQueryVolumeInformationFile", (handle, iosb, buf, len, cls) => {
    void handle; void cls;
    const n = Math.min(Number(len) || 0, 4096);
    if (buf && n) mem.write(ptrSizeMaskSafe(buf), new Uint8Array(n));
    if (iosb) { mem.w64(ptrSizeMaskSafe(iosb), STATUS); mem.w64(ptrSizeMaskSafe(iosb) + 8n, BigInt(n)); }
    return STATUS;
  });
  k.define("ZwFsControlFile", (handle, ev, apcR, apcCtx, iosb, code, inBuf, inLen, outBuf, outLen) => {
    void handle; void ev; void apcR; void apcCtx; void code; void inBuf; void inLen; void outBuf; void outLen;
    if (iosb) { mem.w64(ptrSizeMaskSafe(iosb), 0xc0000010n); mem.w64(ptrSizeMaskSafe(iosb) + 8n, 0n); } // INVALID_DEVICE_REQUEST
    return 0xc0000010n;
  });
  k.define("ZwCreateEvent", (handleOut, access, objAttr, type, state) => {
    void access; void objAttr; void type; void state;
    const h = kernel.nextObHandle = (kernel.nextObHandle ?? 0x6000n) + 4n;
    kernel.handles.set(h, { __event: true });
    if (handleOut) mem.w64(ptrSizeMaskSafe(handleOut), h);
    return STATUS;
  });
  k.define("ZwCreateSection", (handleOut, access, objAttr, maxSize, prot, attrs, fileHandle) => {
    void access; void objAttr; void maxSize; void prot; void attrs; void fileHandle;
    const sec = k.alloc(0x40);
    mem.write(sec, [0x53, 0x65, 0x63, 0x74]); // 'Sect'
    const h = kernel.nextObHandle = (kernel.nextObHandle ?? 0x6000n) + 4n;
    kernel.handles.set(h, { __section: ptrSizeMaskSafe(sec) });
    if (handleOut) mem.w64(ptrSizeMaskSafe(handleOut), h);
    return STATUS;
  });
  k.define("ZwSetInformationVirtualMemory", () => STATUS);
  k.define("ZwSetInformationThread", () => STATUS);
  k.define("ZwSetInformationProcess", () => STATUS);
  k.define("ZwAlpcConnectPort", () => STATUS_NOT_SUPPORTED); // ALPC not modeled
  k.define("IoGetOplockKeyContextEx", () => STATUS_NOT_FOUND);
  k.define("IoGetTopLevelIrp", () => 0n);
  k.define("IoIsFileOriginRemote", () => 0n);
  k.define("IoIsFileObjectIgnoringSharing", () => 1n);
  k.define("FsRtlIsPagingFile", () => 0n);
  k.define("FsRtlIsSystemPagingFile", () => 0n);
  k.define("FsRtlQueryKernelEaFile", () => STATUS_NOT_FOUND);
  k.define("FsRtlSetKernelEaFile", () => STATUS);
  k.define("FsRtlKernelFsControlFile", () => 0xc0000010n);
  k.define("FsRtlCreateSectionForDataScan", (sectionOut, fileObject, iosb, size, prot, attrs, allocationAttrs) => {
    void fileObject; void size; void prot; void attrs; void allocationAttrs;
    const sec = k.alloc(0x40);
    mem.write(sec, [0x53, 0x65, 0x63, 0x74]);
    if (sectionOut) mem.w64(ptrSizeMaskSafe(sectionOut), sec);
    if (iosb) { mem.w64(ptrSizeMaskSafe(iosb), STATUS); mem.w64(ptrSizeMaskSafe(iosb) + 8n, 0n); }
    return STATUS;
  });
  k.define("LdrFindResource_U", () => STATUS_NOT_FOUND);
  k.define("LdrAccessResource", () => STATUS_NOT_FOUND);
  k.define("ExGetPreviousMode", () => 1n); // UserMode
  k.define("ExEnumHandleTable", () => STATUS_UNSUCCESSFUL); // stop enumeration immediately
  k.define("ExfUnblockPushLock", () => undefined);
  k.define("MmDoesFileHaveUserWritableReferences", () => 0n);
  k.define("IoGetTransactionParameterBlock", () => 0n);
  k.define("PsGetProcessJob", () => 0n);
  k.define("PsGetProcessWow64Process", () => 0n);
  k.define("PsIsProcessBeingDebugged", () => 0n);
  k.define("PsIsThreadTerminating", () => 0n);
  k.define("PsIsSystemThread", () => 0n);
  k.define("PsGetProcessExitProcessCalled", () => 0n);
  k.define("PsGetProcessProtection", () => 0n);
  k.define("PsGetProcessExitStatus", () => 0x103n);  // STATUS_PENDING (still running)
  k.define("PsGetThreadExitStatus", () => 0x103n);
  k.define("KeAreAllApcsDisabled", () => 0n);
  k.define("KeTestAlertThread", () => 0n);
  k.define("KeQueryActiveProcessorCountEx", () => 1n);
  k.define("KeInitializeThreadedDpc", (dpc, routine, ctx) => impls.KeInitializeDpc(dpc, routine, ctx));
  k.define("KeRemoveQueueDpcEx", (dpc, flags) => { void flags; return impls.KeRemoveQueueDpc(dpc); });
  k.define("DbgSetDebugPrintCallback", (callback, enable) => {
    void callback; void enable;
    return STATUS;
  });

  // ---------------------------------------------- CRT + AVL + guarded mutex
  const ascii = (va, max = 1024) => {
    let out = "";
    for (let i = 0; i < max; i++) { const c = mem.u8(ptrSizeMaskSafe(va) + BigInt(i)); if (!c) break; out += String.fromCharCode(c); }
    return out;
  };
  const wide = (va, max = 1024) => {
    let out = "";
    for (let i = 0; i < max; i++) { const c = mem.u16(ptrSizeMaskSafe(va) + BigInt(i * 2)); if (!c) break; out += String.fromCharCode(c); }
    return out;
  };
  const lower = (str) => str.replace(/[A-Z]/g, (c) => c.toLowerCase());

  k.define("tolower", (c) => {
    const ch = Number(BigInt.asUintN(8, BigInt(c ?? 0n)));
    return BigInt(ch >= 65 && ch <= 90 ? ch + 32 : ch);
  });
  k.define("strchr", (sVa, ch) => {
    const str = ascii(sVa);
    const idx = str.indexOf(String.fromCharCode(Number(BigInt.asUintN(8, BigInt(ch ?? 0n)))));
    return idx < 0 ? 0n : ptrSizeMaskSafe(sVa) + BigInt(idx);
  });
  k.define("strstr", (hayVa, needleVa) => {
    const idx = ascii(hayVa).indexOf(ascii(needleVa));
    return idx < 0 ? 0n : ptrSizeMaskSafe(hayVa) + BigInt(idx);
  });
  k.define("wcsstr", (hayVa, needleVa) => {
    const idx = wide(hayVa).indexOf(wide(needleVa));
    return idx < 0 ? 0n : ptrSizeMaskSafe(hayVa) + BigInt(idx * 2);
  });
  k.define("_stricmp", (a, b) => {
    const x = lower(ascii(a)), y = lower(ascii(b));
    return BigInt(x < y ? -1 : x > y ? 1 : 0);
  });
  k.define("_strnicmp", (a, b, n) => {
    const len = Number(n) || 0;
    const x = lower(ascii(a)).slice(0, len), y = lower(ascii(b)).slice(0, len);
    return BigInt(x < y ? -1 : x > y ? 1 : 0);
  });
  k.define("_wcsnicmp", (a, b, n) => {
    const len = Number(n) || 0;
    const x = lower(wide(a)).slice(0, len), y = lower(wide(b)).slice(0, len);
    return BigInt(x < y ? -1 : x > y ? 1 : 0);
  });
  k.define("strcpy_s", (dst, size, src) => {
    const str = ascii(src);
    if (size && str.length + 1 > Number(size)) return 0x16n; // ERANGE
    for (let i = 0; i <= str.length; i++) mem.w8(ptrSizeMaskSafe(dst) + BigInt(i), str.charCodeAt(i) & 0xff);
    return 0n;
  });
  k.define("wcscpy_s", (dst, size, src) => {
    const str = wide(src);
    if (size && str.length + 1 > Number(size)) return 0x16n;
    for (let i = 0; i <= str.length; i++) mem.w16(ptrSizeMaskSafe(dst) + BigInt(i * 2), str.charCodeAt(i) & 0xffff);
    return 0n;
  });
  k.define("sprintf_s", (dst, size, fmtVa, ...rest) => {
    const fmt = ascii(fmtVa);
    let out = ""; let ai = 0;
    for (let i = 0; i < fmt.length; i++) {
      if (fmt[i] !== "%") { out += fmt[i]; continue; }
      const spec = fmt[++i];
      if (spec === "%") out += "%";
      else if (spec === "s") out += ascii(rest[ai++] ?? 0n, 128);
      else if (spec === "S" || spec === "ls") out += wide(rest[ai++] ?? 0n, 128);
      else if (spec === "d" || spec === "i") out += String(BigInt.asIntN(32, BigInt(rest[ai++] ?? 0n)));
      else if (spec === "u") out += String(BigInt.asUintN(32, BigInt(rest[ai++] ?? 0n)));
      else if (spec === "x") out += BigInt.asUintN(32, BigInt(rest[ai++] ?? 0n)).toString(16);
      else if (spec === "p") out += `0x${BigInt.asUintN(64, BigInt(rest[ai++] ?? 0n)).toString(16)}`;
      else out += `%${spec}`;
    }
    const limit = size ? Math.max(0, Number(size) - 1) : out.length;
    out = out.slice(0, limit);
    for (let i = 0; i < out.length; i++) mem.w8(ptrSizeMaskSafe(dst) + BigInt(i), out.charCodeAt(i) & 0xff);
    mem.w8(ptrSizeMaskSafe(dst) + BigInt(out.length), 0);
    return 0n;
  });
  k.define("_vsnwprintf", (dst, count, fmtVa, argList) => {
    // argList is a va_list (pointer to a u64 array on x64)
    const args = [];
    for (let i = 0; i < 12; i++) { try { args.push(mem.u64(ptrSizeMaskSafe(argList) + BigInt(i * 8))); } catch { break; } }
    const fmt = wide(fmtVa);
    let out = ""; let ai = 0;
    for (let i = 0; i < fmt.length; i++) {
      if (fmt[i] !== "%") { out += fmt[i]; continue; }
      const spec = fmt[++i];
      if (spec === "%") out += "%";
      else if (spec === "s" || spec === "S") out += wide(args[ai++] ?? 0n, 128);
      else if (spec === "d" || spec === "i") out += String(BigInt.asIntN(32, BigInt(args[ai++] ?? 0n)));
      else if (spec === "u") out += String(BigInt.asUintN(32, BigInt(args[ai++] ?? 0n)));
      else if (spec === "x") out += BigInt.asUintN(32, BigInt(args[ai++] ?? 0n)).toString(16);
      else if (spec === "p") out += `0x${BigInt.asUintN(64, BigInt(args[ai++] ?? 0n)).toString(16)}`;
      else out += `%${spec}`;
    }
    const limit = count ? Math.max(0, Number(count) - 1) : out.length;
    out = out.slice(0, limit);
    for (let i = 0; i < out.length; i++) mem.w16(ptrSizeMaskSafe(dst) + BigInt(i * 2), out.charCodeAt(i) & 0xffff);
    mem.w16(ptrSizeMaskSafe(dst) + BigInt(out.length * 2), 0);
    return BigInt(out.length);
  });
  k.define("_local_unwind", () => undefined);

  k.define("RtlUnicodeStringToAnsiString", (destAs, srcUs, allocate) => {
    void allocate;
    const src = usRead(mem, ptrSizeMaskSafe(srcUs));
    const buf = k.alloc(Math.max(2, src.length + 2));
    for (let i = 0; i < src.length; i++) {
      try { mem.w8(buf + BigInt(i), mem.u8(src.buffer + BigInt(i * 2))); } catch { break; }
    }
    mem.w8(buf + BigInt(src.length), 0);
    mem.w16(ptrSizeMaskSafe(destAs), src.length);
    mem.w16(ptrSizeMaskSafe(destAs) + 2n, src.length + 1);
    mem.w64(ptrSizeMaskSafe(destAs) + 8n, buf);
    return STATUS;
  });
  k.define("RtlFreeAnsiString", (as) => { void as; return undefined; });
  k.define("RtlFreeUnicodeString", (us) => { void us; return undefined; });
  k.define("MmProtectMdlSystemAddress", () => STATUS);
  k.define("IoSetTopLevelIrp", () => undefined);
  k.define("SeTokenIsAdmin", () => 0n); // FALSE: do not unlock admin-only paths
  k.define("ZwAllocateVirtualMemory", (handle, basePtr, zeroBits, sizePtr, allocationType, protect) => {
    void handle; void zeroBits; void allocationType; void protect;
    const size = Math.min(Number(sizePtr ? mem.u32(ptrSizeMaskSafe(sizePtr)) : 0x1000) || 0x1000, 1 << 24);
    const va = k.alloc(size);
    mem.write(va, new Uint8Array(size));
    if (basePtr) mem.w64(ptrSizeMaskSafe(basePtr), va);
    if (sizePtr) mem.w32(ptrSizeMaskSafe(sizePtr), size);
    return STATUS;
  });
  k.define("PsGetProcessPeb", (eproc) => {
    void eproc;
    kernel.pebVa = kernel.pebVa ?? (() => { const va = k.alloc(0x1000); mem.write(va, new Uint8Array(0x1000)); return va; })();
    return kernel.pebVa;
  });

  // Guarded mutexes: no-op acquire/release (single-threaded emulation).
  k.define("KeInitializeGuardedMutex", (mutex) => { if (mutex) mem.write(ptrSizeMaskSafe(mutex), new Uint8Array(0x40)); return undefined; });
  k.define("KeAcquireGuardedMutex", () => undefined);
  k.define("KeReleaseGuardedMutex", () => undefined);

  // Generic tables (AVL flavor): host-side arrays + guest memory elements.
  kernel.genericTables = kernel.genericTables ?? new Map();
  k.define("RtlInitializeGenericTableAvl", (table, compare, allocRoutine, freeRoutine, ctx) => {
    const t2 = ptrSizeMaskSafe(table);
    mem.write(t2, new Uint8Array(0x50));
    kernel.genericTables.set(t2, { compare: ptrSizeMaskSafe(compare), alloc: ptrSizeMaskSafe(allocRoutine), free: ptrSizeMaskSafe(freeRoutine), ctx: ptrSizeMaskSafe(ctx), elements: [] });
    return undefined;
  });
  k.define("RtlInsertElementGenericTableAvl", (table, buffer, bufferSize, newElementOut) => {
    const rec = kernel.genericTables.get(ptrSizeMaskSafe(table));
    if (!rec) return 0n;
    const size = Math.min(Number(bufferSize) || 0, 0x1000);
    const el = k.alloc(size);
    try { mem.write(el, mem.read(ptrSizeMaskSafe(buffer), size)); } catch { /* unreadable */ }
    rec.elements.push(el);
    if (newElementOut) mem.w8(ptrSizeMaskSafe(newElementOut), 1);
    return el;
  });
  k.define("RtlLookupElementGenericTableAvl", (table, buffer) => {
    const rec = kernel.genericTables.get(ptrSizeMaskSafe(table));
    if (!rec) return 0n;
    const key = (() => { try { return mem.u64(ptrSizeMaskSafe(buffer)); } catch { return 0n; } })();
    return rec.elements.find((el) => { try { return mem.u64(el) === key; } catch { return false; } }) ?? 0n;
  });
  k.define("RtlDeleteElementGenericTableAvl", (table, buffer) => {
    const rec = kernel.genericTables.get(ptrSizeMaskSafe(table));
    if (!rec) return 0n;
    const key = (() => { try { return mem.u64(ptrSizeMaskSafe(buffer)); } catch { return 0n; } })();
    const idx = rec.elements.findIndex((el) => { try { return mem.u64(el) === key; } catch { return false; } });
    if (idx < 0) return 0n;
    rec.elements.splice(idx, 1);
    return 1n; // TRUE
  });
  k.define("RtlEnumerateGenericTableWithoutSplayingAvl", (table, restartPtr) => {
    const rec = kernel.genericTables.get(ptrSizeMaskSafe(table));
    if (!rec) return 0n;
    let idx = 0;
    if (restartPtr) { try { idx = Number(mem.u32(ptrSizeMaskSafe(restartPtr))) || 0; } catch { idx = 0; } }
    const el = rec.elements[idx] ?? 0n;
    if (restartPtr) mem.w32(ptrSizeMaskSafe(restartPtr), el ? idx + 1 : 0);
    return el;
  });
  k.define("CmCallbackGetKeyObjectID", (cookie, object, objectIdOut, objectNameOut) =>
    impls.CmCallbackGetKeyObjectIDEx(cookie, object, objectIdOut, objectNameOut, 0n));
  k.define("ExAllocatePoolWithQuotaTag", (poolType, size, tag) => impls.ExAllocatePoolWithTag(poolType, size, tag));

  // ------------------------------------------------------- SLIST / BCrypt
  k.define("InitializeSListHead", (head) => {
    if (head) mem.write(ptrSizeMaskSafe(head), new Uint8Array(16));
    return undefined;
  });
  k.define("ExpInterlockedPushEntrySList", (head, entry) => {
    const h = ptrSizeMaskSafe(head);
    const prev = mem.u64(h);
    mem.w64(ptrSizeMaskSafe(entry), prev);
    mem.w64(h, ptrSizeMaskSafe(entry));
    return prev;
  });
  k.define("ExpInterlockedPopEntrySList", (head) => {
    const h = ptrSizeMaskSafe(head);
    const first = mem.u64(h);
    if (first) mem.w64(h, mem.u64(first));
    return first;
  });
  k.define("ExpInterlockedFlushSList", (head) => {
    const h = ptrSizeMaskSafe(head);
    const first = mem.u64(h);
    mem.w64(h, 0n);
    return first;
  });

  // BCrypt: hash/random/verify primitives with real object bookkeeping.
  kernel.bcryptObjects = kernel.bcryptObjects ?? new Map();
  k.define("BCryptGenRandom", (algo, buffer, len, flags) => {
    void algo; void flags;
    const n = Math.min(Number(len) || 0, 4096);
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = (i * 37 + 11) & 0xff; // deterministic
    if (buffer) mem.write(ptrSizeMaskSafe(buffer), bytes);
    return STATUS;
  });
  k.define("BCryptCreateHash", (algo, hashOut, hashObject, hashObjectSize, secret, secretSize, flags) => {
    void algo; void hashObject; void hashObjectSize; void secret; void secretSize; void flags;
    const h = k.alloc(0x40);
    mem.write(h, [0x42, 0x48, 0x61, 0x73]); // 'BHas'
    kernel.bcryptObjects.set(ptrSizeMaskSafe(h), { data: [] });
    if (hashOut) mem.w64(ptrSizeMaskSafe(hashOut), h);
    return STATUS;
  });
  k.define("BCryptHashData", (hash, input, len, flags) => {
    void flags;
    const rec = kernel.bcryptObjects.get(ptrSizeMaskSafe(hash));
    if (rec) {
      const n = Math.min(Number(len) || 0, 1 << 16);
      try { rec.data.push(...mem.read(ptrSizeMaskSafe(input), n)); } catch { /* unreadable */ }
    }
    return STATUS;
  });
  k.define("BCryptFinishHash", (hash, output, len, flags) => {
    void flags;
    const rec = kernel.bcryptObjects.get(ptrSizeMaskSafe(hash));
    const n = Math.min(Number(len) || 0, 64);
    const bytes = new Uint8Array(n);
    const src = rec?.data ?? [];
    for (let i = 0; i < n; i++) bytes[i] = (src[i % Math.max(1, src.length)] ?? 0x5a) ^ (i * 31);
    if (output) mem.write(ptrSizeMaskSafe(output), bytes);
    return STATUS;
  });
  k.define("BCryptDestroyHash", (hash) => {
    kernel.bcryptObjects.delete(ptrSizeMaskSafe(hash));
    return STATUS;
  });
  k.define("BCryptImportKeyPair", (algo, keyOut, blobType, blob, blobSize, flags) => {
    void algo; void blobType; void blob; void blobSize; void flags;
    const key = k.alloc(0x40);
    mem.write(key, [0x42, 0x4b, 0x65, 0x79]); // 'BKey'
    if (keyOut) mem.w64(ptrSizeMaskSafe(keyOut), key);
    return STATUS;
  });
  k.define("BCryptVerifySignature", (key, padding, hash, hashSize, signature, signatureSize, flags) => {
    void key; void padding; void hash; void hashSize; void signature; void signatureSize; void flags;
    // The emulated machine has no real key material: report "valid" and log,
    // so self-signature checks do not abort analysis.
    kernel.dbgLog.push("[bcrypt] BCryptVerifySignature -> STATUS_SUCCESS (signature check not really evaluated)");
    return STATUS;
  });

  // Rundown protection: reference count over an emulated counter.
  kernel.rundownCounters = kernel.rundownCounters ?? new Map();
  k.define("ExInitializeRundownProtection", (runRef) => {
    kernel.rundownCounters.set(ptrSizeMaskSafe(runRef), 1);
    return undefined;
  });
  k.define("ExAcquireRundownProtection", (runRef) => {
    const key = ptrSizeMaskSafe(runRef);
    kernel.rundownCounters.set(key, (kernel.rundownCounters.get(key) ?? 0) + 1);
    return 1n; // TRUE
  });
  k.define("ExReleaseRundownProtection", (runRef) => {
    const key = ptrSizeMaskSafe(runRef);
    kernel.rundownCounters.set(key, Math.max(0, (kernel.rundownCounters.get(key) ?? 1) - 1));
    return undefined;
  });
  k.define("ExWaitForRundownProtectionRelease", (runRef) => {
    kernel.rundownCounters.set(ptrSizeMaskSafe(runRef), 0);
    return undefined;
  });

  // Shallow stubs are registered lazily in resolveImportProvisioned() so a
  // driver only reports the ones it actually imports.
}

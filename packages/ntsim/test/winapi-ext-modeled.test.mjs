/**
 * Kernel APIs added for filter / anti-cheat drivers: Ob*WithTag, ObCloseHandle,
 * IoCreateFileEx, MmFlushImageSection, the Flt* minifilter surface, the Ksi*
 * vendor shim and the IoFileObjectType data export.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "../src/structs.mjs";
import { NtKernel } from "../src/kernel.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

const MODELED = [
  "ObReferenceObjectByHandleWithTag", "ObCloseHandle", "IoCreateFileEx", "MmFlushImageSection",
  "FltGetVolumeFromFileObject", "FltAllocateContext", "FltAcquirePushLockExclusiveEx",
  "FltInitializePushLock", "FltDeletePushLock", "FltSupportsStreamHandleContexts",
  "FltGetStreamHandleContext", "FltSetStreamHandleContext", "FltReleaseContext",
  "FltGetDestinationFileNameInformation", "FltCancelFileOpen", "FltReleasePushLockEx",
  "FltAcquirePushLockSharedEx",
  "KsiRemoveQueueApc", "KsiQueueWorkItem", "KsiInitializeWorkItem", "KsiInsertQueueDpc",
  "KsiInitializeDpc", "KsiSystemProcess", "KsiInitializeSystemProcess", "KsiUninitialize",
  "KsiInitializeApc", "KsiInitialize", "KsiInsertQueueApc",
];

async function lowKernel() {
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING", "_KDPC"]) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  const kernel = new NtKernel({
    tables,
    bases: { kva: 0x10000000n, pool: 0x20000000n, thunk: 0x30000000n, eproc: 0x40000000n, driver: 0x50000000n },
  });
  kernel.bootstrap();
  return kernel;
}

test("all requested exports resolve as modeled (no provisioned stubs)", async () => {
  const kernel = await lowKernel();
  for (const name of MODELED) {
    kernel.resolveImportProvisioned(`ntoskrnl!${name}`);
  }
  kernel.resolveImportProvisioned("ntoskrnl!IoFileObjectType");
  const unmodeled = new Set(kernel.unmodeledExports);
  const missing = MODELED.filter((n) => unmodeled.has(n));
  assert.deepEqual(missing, [], `unmodeled: ${missing.join(", ")}`);
  assert.ok(!unmodeled.has("IoFileObjectType"), "IoFileObjectType must be a data export");
});

/** OBJECT_ATTRIBUTES + UNICODE_STRING for a path (x64 layout). */
function makeObjAttr(kernel, str) {
  const mem = kernel.mem;
  const buf = kernel.allocPool(str.length * 2 + 2, "PthB");
  mem.writeUtf16(buf, str);
  const us = kernel.allocPool(0x10, "UsSt");
  mem.w16(us, str.length * 2);
  mem.w16(us + 2n, str.length * 2 + 2);
  mem.w64(us + 8n, buf);
  const oa = kernel.allocPool(0x30, "ObAt");
  mem.w32(oa, 0x30);          // Length
  mem.w64(oa + 0x10n, us);    // ObjectName
  return oa;
}

test("ObCloseHandle closes modeled handles and rejects unknown ones", async () => {
  const kernel = await lowKernel();
  const mem = kernel.mem;
  const hOut = kernel.allocPool(8, "HndO");
  const oa = makeObjAttr(kernel, "\\??\\C:\\kfsample.txt");
  const impls = kernel.apiImpls;
  const st = impls.get("ZwCreateFile")(hOut, 0x40100000n, oa, 0n, 0n, 0n, 0n, 5n, 0n, 0n, 0n);
  assert.equal(st, 0n, "ZwCreateFile succeeds");
  const handle = mem.u64(hOut);
  assert.ok(handle > 0n);
  const obClose = impls.get("ObCloseHandle");
  assert.equal(obClose(handle, 0n), 0n, "close succeeds");
  assert.equal(obClose(handle, 0n), 0xc000000bn, "second close is INVALID_HANDLE");
});

test("IoCreateFileEx produces a FILE_OBJECT with a UNICODE_STRING name", async () => {
  const kernel = await lowKernel();
  const mem = kernel.mem;
  const name = "\\Device\\HarddiskVolume1\\sample.sys";
  const oa = makeObjAttr(kernel, name);
  const iosb = kernel.allocPool(0x10, "IoSb");
  const foOut = kernel.allocPool(8, "FoOu");
  const impls = kernel.apiImpls;
  const st = impls.get("IoCreateFileEx")(oa, 0x120089n, iosb, 0n, 0n, 7n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, foOut);
  assert.equal(st, 0n);
  assert.equal(mem.u64(iosb), 0n, "IO_STATUS_BLOCK.Status = SUCCESS");
  const fo = mem.u64(foOut);
  assert.ok(fo > 0n);
  assert.equal(mem.u16(fo), 5, "FILE_OBJECT.Type = IO_TYPE_FILE");
  const len = mem.u16(fo + 0x30n);
  const buf = mem.u64(fo + 0x38n);
  assert.equal(len, name.length * 2);
  assert.equal(mem.readUtf16(buf, name.length), name);
});

test("Flt* and Ksi* surface behaves plausibly", async () => {
  const kernel = await lowKernel();
  const mem = kernel.mem;
  const impls = kernel.apiImpls;
  const filter = 0x777n;

  // volume + context
  const volOut = kernel.allocPool(8, "VolO");
  assert.equal(impls.get("FltGetVolumeFromFileObject")(filter, 0n, volOut), 0n);
  const vol = mem.u64(volOut);
  assert.ok(vol > 0n);
  const ctxOut = kernel.allocPool(8, "CtxO");
  assert.equal(impls.get("FltAllocateContext")(filter, 1n, 0x80n, 0n, ctxOut), 0n);
  const ctx = mem.u64(ctxOut);
  assert.ok(ctx > 0n);

  // stream-handle contexts
  assert.equal(impls.get("FltSupportsStreamHandleContexts")(0n), 1n);
  const fo = kernel.allocPool(0x100, "FoBk");
  const gotOut = kernel.allocPool(8, "GotO");
  assert.equal(impls.get("FltGetStreamHandleContext")(0n, fo, gotOut), 0xc0000034n, "NOT_FOUND before set");
  assert.equal(impls.get("FltSetStreamHandleContext")(0n, fo, 0n, ctx), 0n);
  assert.equal(impls.get("FltGetStreamHandleContext")(0n, fo, gotOut), 0n);
  assert.equal(mem.u64(gotOut), ctx);
  impls.get("FltReleaseContext")(ctx);
  impls.get("FltCancelFileOpen")(0n, fo);

  // push locks are void
  const pl = kernel.allocPool(8, "PshL");
  assert.equal(impls.get("FltInitializePushLock")(pl), undefined);
  assert.equal(impls.get("FltAcquirePushLockExclusiveEx")(pl, 0n), undefined);
  assert.equal(impls.get("FltReleasePushLockEx")(pl, 0n), undefined);

  // destination name info
  const destOut = kernel.allocPool(0x10, "DstN");
  assert.equal(impls.get("FltGetDestinationFileNameInformation")(0n, fo, 0n, 0n, 0n, 0n, destOut, 0n), 0n);
  assert.ok(mem.u16(destOut) > 0, "destination UNICODE_STRING has a length");

  // Ksi shim: DPC init/queue and system process
  const dpc = kernel.allocPool(0x40, "KDPC");
  const routine = 0x1234n;
  const dctx = 0x5678n;
  assert.equal(impls.get("KsiInitializeDpc")(dpc, routine, dctx), undefined);
  assert.equal(mem.u64(dpc + 0x18n), routine);
  assert.equal(mem.u64(dpc + 0x20n), dctx);
  impls.get("KsiInsertQueueDpc")(dpc, 0n, 0n);
  assert.ok(kernel.pendingDpcs.some((d) => d.dpcVa === dpc), "Ksi DPC queued");
  const sysProc = impls.get("KsiSystemProcess")();
  assert.equal(sysProc, kernel.findEprocessByPid(4n));
  assert.equal(impls.get("KsiInitialize")(), 0n);
  assert.equal(impls.get("KsiRemoveQueueApc")(), 1n);
});

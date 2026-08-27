/**
 * Regression tests for the issue #21 / #13 compile-and-runtime batch:
 *   - __readgsqword modeled GS/PRCB walk returns live DPC queue depth
 *   - PsGetProcessImageFileName / KeGetCurrentThread resolve
 *   - DbgPrint consumes %I64u/%llu/%llx exactly once (no literal suffix,
 *     no argument desync)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "../src/kernel.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

async function booted() {
  const k = new NtKernel();
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  return k;
}

test("__readgsqword(0x20) yields a PRCB whose KDPC_DATA depth is live", async () => {
  const k = await booted();
  const gs = k.apiImpls.get("__readgsqword");
  assert.ok(gs, "__readgsqword must be modeled");

  const prcb = gs(0x20);
  assert.ok(prcb !== 0n, "PRCB pointer must be non-zero");

  // no DPCs queued yet — the driver derefs PRCB+0x3000 directly
  const dpcData = prcb + 0x3000n;
  assert.equal(k.mem.u32(dpcData + 0x18n), 0); // _KDPC_DATA.DpcQueueDepth @ +0x18

  // queue one DPC through the modeled APIs; a fresh GS sample must observe it
  const dpc = k.allocPool(64);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0x50101000n, 0n);
  k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n);
  assert.equal(gs(0x20), prcb); // resample refreshes the live fields
  assert.equal(k.mem.u32(dpcData + 0x18n), 1);
  assert.equal(k.apiImpls.get("KeQueryDpcQueueDepth")(), 1n);
});

test("PsGetProcessImageFileName points at readable ANSI bytes", async () => {
  const k = await booted();
  const eproc = k.processesByName.get("kftarget.exe");
  const namePtr = k.apiImpls.get("PsGetProcessImageFileName")(eproc);
  const off = k.tables.offsetOf("_EPROCESS", "ImageFileName");
  assert.equal(namePtr, eproc + off);
  assert.match(k.mem.readAnsi(namePtr, 15), /^kftarget/);
  const pid = k.apiImpls.get("PsGetProcessId")(eproc);
  assert.equal(pid, 888n);
});

test("DbgPrint %I64u renders the value and keeps later args aligned", async () => {
  const k = await booted();
  const fmtAddr = k.allocPool(128);
  k.mem.writeAnsi(fmtAddr, "[EPROCESS: %p] PID: %I64u | Name: %s\n");
  const eproc = k.processesByName.get("kftarget.exe");
  k.dbgPrint(fmtAddr, [eproc, 888n, eproc + k.tables.offsetOf("_EPROCESS", "ImageFileName")]);
  assert.match(k.dbgLog.at(-1), /PID: 888 \| Name: kftarget\.exe/);
  assert.doesNotMatch(k.dbgLog.at(-1), /%I64u|%I\b/);
});

test("DbgPrint %llu and %llx render full-width values", async () => {
  const k = await booted();
  const fmtAddr = k.allocPool(128);
  k.mem.writeAnsi(fmtAddr, "pid=%llu cr0=%llx\n");
  k.dbgPrint(fmtAddr, [4n, 0x80010031n]);
  const line = k.dbgLog.at(-1);
  assert.match(line, /pid=4 /);
  assert.match(line, /cr0=0*80010031/);
});

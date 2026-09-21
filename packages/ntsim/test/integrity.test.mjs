/**
 * integrity.mjs — verified negatives: DKOM, SSDT hooks, foreign IRP slots.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "../src/structs.mjs";
import { NtKernel } from "../src/kernel.mjs";
import { ServiceTable } from "../src/ssdt.mjs";
import {
  createDriverObject,
  initDriverObjectName,
  DRIVER_OBJECT,
} from "../src/devices.mjs";
import {
  scanProcessList, scanSsdt, scanDispatchSlots, scanIntegrity,
} from "../src/integrity.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

async function booted() {
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING"]) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  const kernel = new NtKernel({ tables });
  kernel.bootstrap();
  return kernel;
}

test("scanProcessList reports a healthy ring", async () => {
  const k = await booted();
  const scan = scanProcessList(k);
  assert.equal(scan.available, true);
  assert.equal(scan.ok, true, JSON.stringify(scan));
  assert.ok(scan.walked >= 7);
  assert.deepEqual(scan.unlinked, []);
  assert.deepEqual(scan.foreign, []);
});

test("scanProcessList detects a DKOM-unlinked process", async () => {
  const k = await booted();
  const t = k.tables;
  const target = k.processesByName.get("kftarget.exe");
  const links = target + BigInt(t.offsetOf("_EPROCESS", "ActiveProcessLinks"));
  const flink = k.mem.u64(links);
  const blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);
  k.mem.w64(flink + 8n, blink);

  const scan = scanProcessList(k);
  assert.equal(scan.ok, false);
  assert.deepEqual(scan.unlinked, ["kftarget.exe"]);
});

test("scanSsdt detects a patched service entry", async () => {
  const k = await booted();
  const table = new ServiceTable(k, { limit: 4 });
  table.add("NtOpenProcess");
  table.add("NtWriteVirtualMemory");
  k.serviceTable = table;

  const clean = scanSsdt(k);
  assert.equal(clean.available, true);
  assert.equal(clean.ok, true);
  assert.equal(clean.total, 2);

  k.mem.w64(table.entryVa(1), 0xdeadbeefn);
  const dirty = scanSsdt(k);
  assert.equal(dirty.ok, false);
  assert.equal(dirty.hooked.length, 1);
  assert.equal(dirty.hooked[0].name, "NtWriteVirtualMemory");
  assert.equal(dirty.hooked[0].current, "0xdeadbeef");
});

test("scanSsdt is unavailable without a seeded table", async () => {
  const k = await booted();
  const scan = scanSsdt(k);
  assert.equal(scan.available, false);
});

test("scanDispatchSlots detects a foreign MajorFunction", async () => {
  const k = await booted();
  const drv = createDriverObject(k, "clean.sys");
  initDriverObjectName(k, drv, "clean.sys", 0xfffff80300000000n, 0x10000);

  const clean = scanDispatchSlots(k);
  assert.equal(clean.available, true);
  assert.equal(clean.ok, true, JSON.stringify(clean.foreign));

  // IRP hook: MJ[14] (DEVICE_CONTROL) redirected outside the driver image
  k.mem.w64(
    drv.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + 14 * 8),
    0xfffff8052b801234n,
  );
  const dirty = scanDispatchSlots(k);
  assert.equal(dirty.ok, false);
  assert.equal(dirty.foreign.length, 1);
  assert.equal(dirty.foreign[0].majorName, "DEVICE_CONTROL");
  assert.equal(dirty.foreign[0].handler, "0xfffff8052b801234");
});

test("scanIntegrity aggregates all three scanners", async () => {
  const k = await booted();
  const table = new ServiceTable(k, { limit: 2 });
  table.add("NtOpenProcess");
  k.serviceTable = table;
  const out = scanIntegrity(k);
  assert.equal(out.processList.available, true);
  assert.equal(out.ssdt.available, true);
  assert.equal(out.dispatch.available, true);
  assert.equal(out.processList.ok, true);
  assert.equal(out.ssdt.ok, true);
});

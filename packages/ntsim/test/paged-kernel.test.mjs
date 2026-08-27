/**
 * Kernel under guest paging: KUSER dual-map, EPROCESS DTB, and a real
 * driver image whose DriverEntry reads through translated memory.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "../src/kernel.mjs";
import { StructTables } from "../src/structs.mjs";
import { PeBuilder } from "../src/pebuilder.mjs";
import { parsePe } from "../src/pe.mjs";
import { mapPe } from "../src/pe.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);
const loadTables = async () => StructTables.loadDir(tablesDir, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY", "_KPROCESS"]);

async function pagedKernel() {
  const k = new NtKernel({ tables: await loadTables(), paging: true });
  k.bootstrap();
  return k;
}

test("paged boot: KUSER_SHARED_DATA is dual-mapped to one frame", async () => {
  const k = await pagedKernel();
  const userPa = k.vtop(0x7ffe0000n);
  const kernPa = k.vtop(0xfffff78000000000n);
  assert.ok(userPa && kernPa, "both aliases must translate");
  assert.equal(userPa & ~0xfffn, kernPa & ~0xfffn, "same physical frame");

  // identical contents through both views
  assert.equal(k.mem.u32(0x7ffe0000n), k.mem.u32(0xfffff78000000000n));
  assert.equal(k.mem.u32(0x7ffe0000n + 0x2c4n), 10); // NtMajorVersion=10
});

test("paged boot: every EPROCESS carries the kernel DTB", async () => {
  const k = await pagedKernel();
  const dtbOff = BigInt(k.tables.offsetOf("_KPROCESS", "DirectoryTableBase"));
  for (const addr of k.processesByName.values()) {
    assert.equal(k.mem.u64(addr + dtbOff) & ~0xfffn, k.cr3 & ~0xfffn);
  }
});

test("paged exec: DriverEntry runs and reads KUSER through translation", async () => {
  const k = await pagedKernel();

  // driver: movabs rax, kernel KUSER alias ; mov eax,[rax] ; ret
  const textLen = 0x40;
  const text = new Uint8Array(textLen);
  text.set([
    0x48, 0xb8, ...(() => { const o = []; let x = 0xfffff78000000000n; for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; })(), // movabs rax
    0x8b, 0x00,                                 // mov eax, [rax]
    0xc3,
  ], 0x10);

  const probe = new PeBuilder().addSection(".text", new Uint8Array(textLen), 0x60000020);
  const tRva = parsePe(probe.build(0).image).sections[0].rva;

  const bb = new PeBuilder();
  bb.addSection(".text", text, 0x60000020);
  const img = bb.build(tRva + 0x10).image;

  const BASE = 0xfffff80300000000n;
  const mapped = mapPe(img, k.mem, BASE, (q) => k.resolveImportProvisioned(q));

  const drvObj = k.allocPool(0x150);
  const regPath = k.allocPool(0x100);
  const r = k.callFunctionSeh(mapped.entry, [drvObj, regPath], { base: mapped.base, bytes: img });
  assert.equal(r.status, "ok", JSON.stringify(r, (k2,v2)=>typeof v2==="bigint"?v2.toString():v2));
  assert.equal(r.retval, 1n); // modeled TickCountLowDeprecated seeded to 1
});

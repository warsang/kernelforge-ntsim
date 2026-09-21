/**
 * Physical-memory model + MDL PFN arrays + \Device\PhysicalMemory sections +
 * BCD hive virtualization.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import { MDL } from "../src/devices.mjs";
import { BCD_ELEMENTS, bcdValueForElement } from "../src/bcd.mjs";

function buildObjAttr(kernel, path) {
  const mem = kernel.mem;
  const objAttr = kernel.allocPool(0x30, "ObjA");
  const us = kernel.allocPool(0x10, "Us  ");
  const buf = kernel.allocPool((path.length + 1) * 2, "UsB ");
  mem.writeUtf16(buf, path);
  mem.w16(us, path.length * 2);
  mem.w16(us + 2n, path.length * 2 + 2);
  mem.w64(us + 8n, buf);
  mem.w64(objAttr + 0x10n, us);
  return objAttr;
}

function openKey(kernel, path) {
  const mem = kernel.mem;
  const out = kernel.allocPool(8, "Hnd ");
  const status = kernel.apiImpls.get("ZwOpenKey")(out, 0n, buildObjAttr(kernel, path));
  return { status, handle: mem.u64(out) };
}

function queryValue(kernel, handle, name) {
  const mem = kernel.mem;
  const us = kernel.allocPool(0x10, "QVUs");
  const buf = kernel.allocPool((name.length + 1) * 2, "QVB ");
  mem.writeUtf16(buf, name);
  mem.w16(us, name.length * 2);
  mem.w16(us + 2n, name.length * 2 + 2);
  mem.w64(us + 8n, buf);
  const info = kernel.allocPool(0x200, "QVI ");
  const retLen = kernel.allocPool(8, "QVL ");
  const status = kernel.apiImpls.get("ZwQueryValueKey")(handle, us, 0n, info, 0x200n, retLen);
  const len = mem.u32(info + 4n);
  return { status, type: mem.u32(info), len, data: mem.read(info + 8n, len) };
}

test("VA<->PA identity model round-trips deterministically", () => {
  const k = new NtKernel({ arch: false });
  const va = 0xfffff90000001234n;
  assert.equal(k.vaToPa(va), va >> 12n);
  assert.equal(k.paToVa(k.vaToPa(va)), va & ~0xfffn);
  assert.equal(k.apiImpls.get("MmGetPhysicalAddress")(va), va >> 12n);
  assert.equal(k.apiImpls.get("MmGetVirtualForPhysical")(va >> 12n), va & ~0xfffn);
});

test("MmGetPhysicalMemoryRanges returns a terminated range table", () => {
  const k = new NtKernel({ arch: false });
  const table = k.apiImpls.get("MmGetPhysicalMemoryRanges")();
  assert.ok(table);
  assert.ok(k.mem.u64(table) > 0n);
  assert.ok(k.mem.u64(table + 8n) > 0n);
  assert.equal(k.mem.u64(table + 0x20n), 0n); // terminator BaseAddress
  assert.equal(k.mem.u64(table + 0x28n), 0n); // terminator Length
});

test("MmMapIoSpace maps through the physical model; APIC page fails", () => {
  const k = new NtKernel({ arch: false });
  assert.equal(k.apiImpls.get("MmMapIoSpace")(0x1000n, 0x1000n), k.paToVa(0x1000n));
  assert.equal(k.apiImpls.get("MmMapIoSpace")(0xfee00000n, 0x1000n), 0n);
  assert.equal(k.apiImpls.get("MmMapIoSpaceEx")(0x2000n, 0x1000n, 0n), k.paToVa(0x2000n));
});

test("MDL PFN array uses the shared physical model", () => {
  const k = new NtKernel({ arch: false });
  const buf = k.allocPool(0x3000, "Buf ");
  const mdl = k.apiImpls.get("IoAllocateMdl")(buf, 0x3000, 0, 0, 0n);
  k.apiImpls.get("MmBuildMdlForNonPagedPool")(mdl);
  assert.equal(k.mem.u16(mdl + BigInt(MDL.FLAGS)) & MDL.FLAG_SOURCE_IS_NONPAGED_POOL,
    MDL.FLAG_SOURCE_IS_NONPAGED_POOL);
  const pfnArray = k.apiImpls.get("MmGetMdlPfnArray")(mdl);
  assert.equal(pfnArray, mdl + BigInt(MDL.PFN_ARRAY));
  assert.equal(k.mem.u64(pfnArray), k.vaToPa(buf));
  assert.equal(k.mem.u64(pfnArray + 8n), k.vaToPa(buf) + 1n);
  assert.equal(k.apiImpls.get("MmGetMdlVirtualAddress")(mdl), buf);
});

test("\\Device\\PhysicalMemory opens and maps a tracked view", () => {
  const k = new NtKernel({ arch: false });
  const mem = k.mem;
  const out = k.allocPool(8, "SecH");
  const st = k.apiImpls.get("ZwOpenSection")(out, 0n, buildObjAttr(k, "\\Device\\PhysicalMemory"));
  assert.equal(st, 0n);
  const handle = mem.u64(out);
  assert.ok(handle);

  const baseOut = k.allocPool(8, "SecB");
  const viewSize = k.allocPool(8, "SecS");
  mem.w64(viewSize, 0x2000n);
  const ms = k.apiImpls.get("ZwMapViewOfSection")(
    handle, 0n, baseOut, 0n, 0x2000n, 0n, viewSize, 0n, 0n, 0n);
  assert.equal(ms, 0n);
  const base = mem.u64(baseOut);
  assert.ok(base > 0n);
  assert.equal(mem.u64(viewSize), 0x2000n);
  assert.ok(k.sectionViews.has(base));
  assert.equal(k.apiImpls.get("ZwUnmapViewOfSection")(0n, base), 0n);
  assert.ok(!k.sectionViews.has(base));
});

test("BCD hive is seeded with typed element keys", () => {
  const k = new NtKernel({ arch: false });
  assert.ok(k.registry.has("\\Registry\\Machine\\BCD"));
  const objectPath = "\\Registry\\Machine\\BCD\\00000000\\Objects\\{00000000-0000-0000-0000-000000000000}";
  const { status, handle } = openKey(k, `${objectPath}\\Elements\\12000004`);
  assert.equal(status, 0n);
  const value = queryValue(k, handle, "Value");
  assert.equal(value.status, 0n);
  assert.equal(value.type, 1); // REG_SZ per element-ID nibble
  assert.ok(value.len > 0);
});

test("queried-but-missing BCD elements synthesize by format nibble", () => {
  const k = new NtKernel({ arch: false });
  const base = "\\Registry\\Machine\\BCD\\00000000\\Objects\\{00000000-0000-0000-0000-000000000000}\\Elements";
  const cases = [
    ["12000099", 1], // string
    ["22000099", 4], // integer
    ["32000099", 4], // boolean (DWORD)
    ["52000099", 3], // object list (binary)
    ["72000099", 3], // device (binary)
  ];
  for (const [name, expectedType] of cases) {
    const { handle } = openKey(k, `${base}\\${name}`);
    const v = queryValue(k, handle, "Value");
    assert.equal(v.status, 0n, `element ${name}`);
    assert.equal(v.type, expectedType, `element ${name} type`);
  }
  assert.ok(k.dbgLog.some((l) => l.includes("[bcd] synthesized")));
});

test("bcdValueForElement rejects non-element names", () => {
  assert.equal(bcdValueForElement("Value"), null);
  assert.equal(bcdValueForElement(0), null);
  assert.equal(bcdValueForElement(BCD_ELEMENTS[0x12000004] ? 0x12000004 : 0).type, 1);
});

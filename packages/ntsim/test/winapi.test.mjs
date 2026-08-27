/**
 * Kernel API emulation layer tests — direct impl invocation over SparseMemory.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";

async function booted() {
  const k = new NtKernel();
  return k;
}

test("pool + copy/zero/fill operate over guest memory", async (t) => {
  const k = await booted();
  const a = k.apiImpls.get("ExAllocatePoolWithTag")(0, 64n, 0x6e6f6cn);
  assert.ok(a > 0n);
  k.apiImpls.get("RtlFillMemory")(a, 8n, 0x41);
  assert.equal(k.mem.u8(a), 0x41);
  assert.equal(k.mem.u8(a + 7n), 0x41);
  const b = k.apiImpls.get("ExAllocatePool")(0, 32n);
  k.apiImpls.get("memcpy")(b, a, 4n);
  assert.equal(k.mem.u8(b), 0x41);
  k.apiImpls.get("RtlZeroMemory")(a, 8n);
  assert.equal(k.mem.u8(a), 0);
});

test("LIST_ENTRY ops maintain a real linked list in memory", async () => {
  const k = await booted();
  const head = k.allocPool(16);
  const e1 = k.allocPool(16), e2 = k.allocPool(16);
  const api = k.apiImpls;
  api.get("InitializeListHead")(head);
  assert.equal(api.get("IsListEmpty")(head), 1n);
  api.get("InsertTailList")(head, e1);
  api.get("InsertTailList")(head, e2);
  assert.equal(api.get("IsListEmpty")(head), 0n);
  // walk: head.Flink -> e1 -> e2 -> head
  const walk = [];
  let cur = k.mem.u64(head);
  while (cur !== head && walk.length < 8) {
    walk.push(cur);
    cur = k.mem.u64(cur);
  }
  assert.deepEqual(walk, [e1, e2], "list walk " + walk.map((v) => v.toString(16)).join(" -> "));
  assert.equal(api.get("RemoveHeadList")(head), e1);
  assert.equal(api.get("RemoveHeadList")(head), e2);
  assert.equal(api.get("IsListEmpty")(head), 1n);
});

test("interlocked RMW on guest memory", async () => {
  const k = await booted();
  const v = k.allocPool(4);
  k.mem.w32(v, 10);
  assert.equal(k.apiImpls.get("InterlockedIncrement")(v), 11n);
  assert.equal(k.apiImpls.get("InterlockedCompareExchange")(v, 50n, 11n), 11n);
  assert.equal(k.mem.u32(v), 50);
});

test("registry: seeded key opens and queries REG_SZ", async () => {
  const k = await booted();
  const oa = k.allocPool(64);       // OBJECT_ATTRIBUTES with ObjectName @+0x10
  const us = k.allocPool(24);
  const buf = k.allocPool(128);
  const path = "\\Registry\\Machine\\SOFTWARE\\KernelForge";
  memWriteAnsi(k, buf, "");         // keep buffer allocated
  writeUs(k, us, buf, path);
  k.mem.w64(oa + 0x10n, us);

  const h = k.allocPool(8);
  assert.equal(k.apiImpls.get("ZwOpenKey")(h, 0n, oa), 0n);
  const handle = k.mem.u64(h);

  const valueName = k.allocPool(24);
  writeUs(k, valueName, k.allocPool(64), "Version");
  const info = k.allocPool(64);
  const resLen = k.allocPool(4);
  const st = k.apiImpls.get("ZwQueryValueKey")(
    handle, valueName, 2n /* KeyValuePartialInformation */, info, 64n, resLen);
  assert.equal(st, 0n);
  assert.equal(k.mem.u32(info), 1);                   // REG_SZ
  const dataLen = k.mem.u32(info + 4n);               // DataLength
  const data = k.mem.read(info + 8n, Number(dataLen));
  assert.deepEqual([...data], [...Buffer.from("1.0.0\0", "utf8")]);
});

function memWriteAnsi() { /* reserved for future use */ }
function writeUs(kernel, usVa, bufVa, str) {
  kernel.mem.w16(usVa, str.length * 2);
  kernel.mem.w16(usVa + 2n, str.length * 2 + 2);
  kernel.mem.w64(usVa + 8n, bufVa);
  kernel.mem.writeUtf16(bufVa, str);
}

test("MmGetSystemRoutineAddress resolves known exports and records unknowns", async () => {
  const k = await booted();
  const us = k.allocPool(24);
  const buf = k.allocPool(128);
  const call = (name) => {
    writeUs(k, us, buf, name);
    return k.apiImpls.get("MmGetSystemRoutineAddress")(us);
  };
  const dbgThunk = call("DbgPrint");
  assert.ok(dbgThunk > 0n);
  assert.equal(dbgThunk, k.apiThunks.get("DbgPrint"));
  const missing = call("NtTotallyFakeRoutine");
  assert.equal(missing, 0n);
  assert.ok(k.unsupportedExports.includes("NtTotallyFakeRoutine"));
});

test("RtlGetVersion reports 22H2 build fields", async () => {
  const k = await booted();
  const info = k.allocPool(0x120);
  k.apiImpls.get("RtlGetVersion")(info);
  assert.equal(k.mem.u32(info + 4n), 10);
  assert.equal(k.mem.u32(info + 8n), 0);
  assert.equal(k.mem.u32(info + 12n), 19045);
  assert.equal(k.mem.u32(info + 16n), 2);
});

test("KeBugCheckEx records the crash and halts the CPU", async () => {
  const k = await booted();
  k.cpu.reset(0x1000n);
  k.apiImpls.get("KeBugCheckEx")(0x139n, 3n, 0n, 0n, 0n);
  assert.ok(k.bugcheck);
  assert.equal(k.bugcheck.code, 0x139n);
  assert.equal(k.cpu.halted, true);
});

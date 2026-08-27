/**
 * m24 engine primitives: MajorFunction baseline/containment scanning and
 * OBJECT_TYPE_INITIALIZER modeling (objtypes.mjs + devices.mjs additions).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { createDriverObject, createDeviceObject, sendIrp,
  snapshotMajorBaseline, installDispatchScan, DRIVER_OBJECT,
  IRP_MJ } from "@kernelforge/ntsim/src/devices.mjs";
import { installObjectTypes, OBJ_PROCEDURES, objProcVa } from "@kernelforge/ntsim/src/objtypes.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2");

async function lowKernel() {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING"]) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  const kernel = new NtKernel({
    cpu, tables,
    bases: {
      kva: 0x10000000n, pool: 0x20000000n,
      thunk: 0x30000000n, eproc: 0x40000000n, driver: 0x50000000n,
    },
  });
  kernel.bootstrap();
  kernel.loadedModules ??= [];
  return kernel;
}

/** mov dword [rdx+0x30], status ; xor eax,eax ; ret */
function irpStatusStub(status) {
  return new Uint8Array([
    0xc7, 0x42, 0x30,
    status & 0xff, (status >> 8) & 0xff, (status >> 16) & 0xff, (status >> 24) & 0xff,
    0x31, 0xc0, 0xc3,
  ]);
}

test("scanForeignDispatch convicts only out-of-image wired slots", async () => {
  const k = await lowKernel();
  installDispatchScan(k);
  const VICTIM = 0x5100000n, SNOOP = 0x5200000n;

  const drv = createDriverObject(k, "kfser", { va: VICTIM });
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.DRIVER_START), VICTIM);
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.DRIVER_SIZE), 0x4000n);
  // honest in-image handler for DEVICE_CONTROL
  k.mem.write(VICTIM + 0x800n, irpStatusStub(0));
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + IRP_MJ.DEVICE_CONTROL * 8),
    VICTIM + 0x800n);
  createDeviceObject(k, drv, {});
  snapshotMajorBaseline(k, drv);

  assert.deepEqual(k.scanForeignDispatch(), [], "clean table scans empty");

  // foreign rewrite into a "kfsnoop.sys" module range
  k.loadedModules.push({ base: SNOOP, sizeOfImage: 0x4000, name: "kfsnoop.sys" });
  k.mem.write(SNOOP + 0x800n, irpStatusStub(0xdead0001));
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + IRP_MJ.DEVICE_CONTROL * 8),
    SNOOP + 0x800n);

  const hits = k.scanForeignDispatch();
  assert.equal(hits.length, 1);
  assert.equal(hits[0].codeName, "DEVICE_CONTROL");
  assert.equal(hits[0].handler, SNOOP + 0x800n);
  assert.equal(hits[0].owner, "kfsnoop.sys");
});

test("hooked slot changes the behavioral completion via sendIrp", async () => {
  const k = await lowKernel();
  installDispatchScan(k);
  const VICTIM = 0x5100000n, SNOOP = 0x5200000n;
  const drv = createDriverObject(k, "kfser", { va: VICTIM });
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.DRIVER_START), VICTIM);
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.DRIVER_SIZE), 0x4000n);
  k.mem.write(VICTIM + 0x800n, new Uint8Array([
    0xc7, 0x42, 0x38, 4, 0, 0, 0, // mov dword [rdx+0x38], 4 (Information)
    0x31, 0xc0, 0xc3,
  ]));
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + IRP_MJ.DEVICE_CONTROL * 8),
    VICTIM + 0x800n);
  const dev = createDeviceObject(k, drv, {});

  const honest = await sendIrp(k, dev, { major: IRP_MJ.DEVICE_CONTROL, ioctl: 0x222000 });
  assert.equal(honest.ntstatus, 0n);
  assert.equal(honest.information, 4n);

  k.mem.write(SNOOP + 0x800n, irpStatusStub(0xdead0001));
  k.mem.w64(VICTIM + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + IRP_MJ.DEVICE_CONTROL * 8),
    SNOOP + 0x800n);
  const hijacked = await sendIrp(k, dev, { major: IRP_MJ.DEVICE_CONTROL, ioctl: 0x222000 });
  assert.equal(hijacked.ntstatus, 0xdead0001n);
  assert.equal(BigInt(hijacked.information), 0n);
});

test("object types: define, hook, scan, restore", async () => {
  const k = await lowKernel();
  installObjectTypes(k);
  const OT = 0x5300000n;
  const t = k.defineObjectType("Process", { va: OT });
  assert.equal(OBJ_PROCEDURES[0], "OpenProcedure");
  assert.equal(k.mem.u64(objProcVa(OT, "OpenProcedure")), 0n);

  k.setObjectTypeProc(t, "OpenProcedure", 0x5400900n);
  const hooks = k.scanObjectTypeHooks();
  assert.equal(hooks.length, 1);
  assert.equal(hooks[0].procName, "OpenProcedure");

  k.restoreObjectTypeProcs(t, "OpenProcedure");
  assert.deepEqual(k.scanObjectTypeHooks(), []);
});

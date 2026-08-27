/**
 * m26 kernel-side ETW logger model (etwkernel.mjs): baseline, blindfolding
 * gate, tamper scan.
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
import { installEtwKernelModel, WMI_LOGGER_FLAGS_OFFSET } from "@kernelforge/ntsim/src/etwkernel.mjs";

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
  return kernel;
}

test("logger model: pump passes healthy, zeroed EnableFlags suppress silently", async () => {
  const k = await lowKernel();
  installEtwKernelModel(k);
  const rec = k.defineEtwLogger({
    name: "CKCL", va: 0x5600000n, loggerId: 0x1a, enableFlags: 0xff, getCpuClock: 1,
  });

  assert.deepEqual(k.pumpKernelEvents(8), { delivered: 8, suppressed: 0 });
  assert.deepEqual(k.scanEtwTamper(), []);

  k.mem.w32(rec.va + BigInt(WMI_LOGGER_FLAGS_OFFSET), 0);
  assert.deepEqual(k.pumpKernelEvents(8), { delivered: 0, suppressed: 8 });

  const hits = k.scanEtwTamper();
  assert.equal(hits.length, 1);
  assert.equal(hits[0].baseline, 0xff);
  assert.equal(hits[0].current, 0);

  // nonzero-but-drifted masks pass events yet still convict on diff
  k.mem.w32(rec.va + BigInt(WMI_LOGGER_FLAGS_OFFSET), 0x80);
  assert.deepEqual(k.pumpKernelEvents(2), { delivered: 2, suppressed: 0 });
  assert.equal(k.scanEtwTamper().length, 1);
});

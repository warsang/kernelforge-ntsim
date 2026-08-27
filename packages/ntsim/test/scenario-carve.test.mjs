/**
 * Scenario-boot integration: carved dump pages + static JSON world must
 * coexist — genuine ntoskrnl bytes underneath, process/KPCR overlay on top,
 * and no double-writes of module headers when the carve already provided them.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, tryLoadCarvedState } from "../../../apps/web/src/scenarios.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const tablesDir = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");

test("tryLoadCarvedState returns null when no carve file is deployed", async () => {
  // default fetch against file:// fails / 404 -> null (labs fall back cleanly)
  const r = await tryLoadCarvedState(async () => ({ ok: false }));
  assert.equal(r, null);
});

test("bootDefault accepts carvedState: pages land, overlay wins, headers dedup", async () => {
  const NTOS_BASE = "fffff8052b800000";

  const carvedState = {
    build: "synthetic",
    keyAddresses: {
      psLoadedModuleList: "fffff80539001000",
      psActiveProcessHead: "fffff80539002000",
    },
    modules: [
      { name: "\\SystemRoot\\system32\\ntoskrnl.exe", base: NTOS_BASE, size: 0x800000 },
    ],
    pages: [
      // one recognizable "genuine" page at the ntos base
      [NTOS_BASE, Buffer.from([0x4d, 0x5a, 0xde, 0xad]).toString("base64")],
    ],
  };

  const dumpWorld = {
    meta: { processCount: 1, moduleCount: 1, source: "KDemu mem.dmp", directoryTableBase: "0x6d4000" },
    processes: [{
      pid: 48, name: "wininit.exe", eprocess: "0xffffb8053fe9c080",
      eprocessHex: "", protectionByte: null, token: null,
    }],
    modules: [{
      base: "0x" + NTOS_BASE, sizeOfImage: 0x800000,
      baseDllName: "ntoskrnl.exe", fullDllName: "\\SystemRoot\\system32\\ntoskrnl.exe",
      // stale header that must NOT overwrite the carved page
      headerHex: "ff".repeat(16),
    }],
    kpcr: null, context: null, threads: [],
  };

  const scenario = getScenario("boot-default");
  const session = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables: async () => {
      const { StructTables } = await import("@kernelforge/ntsim/src/structs.mjs");
      return StructTables.loadDir(tablesDir, ["_EPROCESS", "_KLDR_DATA_TABLE_ENTRY", "_KPCR", "_KPRCB", "_ETHREAD"]);
    },
    dumpWorld,
    carvedState,
  });

  const { kernel, dumpPagesLoaded } = session;
  assert.equal(dumpPagesLoaded, 1);
  assert.equal(kernel.dumpSource, "carved");
  assert.equal(kernel.carvedModules.length, 1);

  // genuine bytes survive at ntos base
  const raw = kernel.mem.read(BigInt("0x" + NTOS_BASE), 4);
  assert.deepEqual([...raw], [0x4d, 0x5a, 0xde, 0xad]);

  // overlay world still functional: process list walks
  const procs = kernel.listProcesses();
  assert.ok(procs.length >= 2); // defaults + fixtures

  // kftarget fixture appended by populateFromDump
  assert.ok(kernel.processesByName.has("kftarget.exe"));
});

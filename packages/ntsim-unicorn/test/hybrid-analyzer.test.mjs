/**
 * HybridCpuBackend × analyzer regression battery.
 *
 * Covers the late-memory-binding contract: the browser analyzer builds
 * backends with mem=null (HybridCpuBackend.create(null)) and attaches the
 * kernel's SparseMemory afterwards. Any backend that drops that rebinding
 * faults with "Cannot read properties of null (reading 'write')" on the
 * first guest access — exactly what shipped users hit on the hybrid engine.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";
import { parsePe, rvaToOffset } from "@kernelforge/ntsim/src/pe.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { HybridCpuBackend } from "../src/hybrid.mjs";
import { analyzeDriver } from "@kernelforge/ntsim-analyzer/src/index.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);
const loadTables = () =>
  StructTables.loadDir(tablesDir, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);

const u32le = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

test("[hybrid] late memory binding reaches BOTH child engines", async () => {
  const hyb = await HybridCpuBackend.create(null);
  assert.equal(hyb.js.mem, null);
  assert.equal(hyb.uc.mem, null);

  // NtKernel-style: plain `.mem =` reassignment must propagate…
  const mem = new SparseMemory();
  hyb.mem = mem;
  assert.equal(hyb.js.mem, mem);
  assert.equal(hyb.uc.mem, mem);

  // …and so must the analyzer's optional attachMemory() hook.
  const mem2 = new SparseMemory();
  hyb.attachMemory(mem2);
  assert.equal(hyb.js.mem, mem2);
  assert.equal(hyb.uc.mem, mem2);
});

/** DriverEntry body bytes placed at .text+0x10 of a fresh image. */
function imageWithText(textLen, at10, opts = {}) {
  const probe = new PeBuilder().addSection(".text", new Uint8Array(textLen), 0x60000020);
  const t = parsePe(probe.build(0).image).sections[0].rva;
  const text = new Uint8Array(textLen);
  text.set(at10, 0x10);
  const b = new PeBuilder();
  b.addSection(".text", text, 0x60000020);
  if (opts.imports) b.addImports(opts.imports);
  return { img: b.build(t + 0x10).image, t };
}

const hybridOpts = async (extra = {}) => ({
  name: "hybrid-repro.sys",
  backendName: "hybrid",
  tables: await loadTables(),
  runUnload: false,
  ...extra,
  makeBackend: async () => HybridCpuBackend.create(null),
});

test("[hybrid] analyzeDriver end-to-end: modeled import + SSE handoff rescue", async () => {
  // entry @ t+0x10:
  //   xor ecx,ecx ; mov edx,0x10 ; mov r8d,'tset'
  //   call qword [rip+disp32]      -> ExAllocatePoolWithTag (modeled)
  //   psrldq xmm0,2                -> JsInterpreter refuses (unimplemented 0F 73), Unicorn rescues
  //   ret                          -> rax = pool allocation
  const at10 = [
    0x48, 0x31, 0xc9,
    0xba, 0x10, 0x00, 0x00, 0x00,
    0x41, 0xb8, 0x74, 0x65, 0x73, 0x74,
    0xff, 0x15, 0, 0, 0, 0, // disp32 patched below against the built IAT
    0x0f, 0x73, 0xd0, 0x02,
    0xc3,
  ];
  const CALL_OFF = 0x10 + 3 + 5 + 6; // offset of ff 15 within .text
  let { img, t } = imageWithText(0x100, at10, {
    imports: [{ dll: "ntoskrnl.exe", funcs: ["ExAllocatePoolWithTag"] }],
  });

  // locate FirstThunk RVA from the finished image's import directory
  const pe = parsePe(img);
  const descOff = rvaToOffset(pe, pe.dirs[1].rva);
  const iatRva =
    img[descOff + 16] | (img[descOff + 17] << 8) | (img[descOff + 18] << 16) | (img[descOff + 19] << 24);
  const disp = iatRva - (t + CALL_OFF + 6);
  img.set(u32le(disp), /* file off of disp32 */ rvaToOffset(pe, t + CALL_OFF) + 2);

  const r = await analyzeDriver(img, await hybridOpts());
  assert.equal(r.entry.status, "ok", JSON.stringify(r.entry));
  assert.notEqual(r.entry.retval, "0x00000000"); // live pool pointer came back

  const cpu = r.__session.kernel.cpu;
  assert.ok(cpu instanceof HybridCpuBackend);
  assert.equal(cpu.handoffs.length, 1, JSON.stringify(cpu.handoffs));
  assert.match(cpu.handoffs[0].opcode, /unimplemented 0f opcode 0x73/i);
  assert.ok(r.__session.kernel.apiTrace.some((e) => e.name === "ExAllocatePoolWithTag"));
});

test("[hybrid] unsupported int imm8 degrades to a clean fault (no TypeError)", async () => {
  // TBMKD-shaped: cd 29 (int 29h) — interpreter refuses the fetch, unicorn
  // raises it as an unhandled CPU exception. Either way the analyzer must
  // surface a proper fault report, not a JS null-dereference crash. The
  // backend sniffs opcode bytes at RIP so the message names the fastfail.
  const { img } = imageWithText(0x20, [0xcd, 0x29, 0x31, 0xc0, 0xc3]);
  const r = await analyzeDriver(img, await hybridOpts());
  assert.equal(r.entry.status, "fault");
  assert.match(String(r.entry.error), /int 0x29 fastfail/i);
});

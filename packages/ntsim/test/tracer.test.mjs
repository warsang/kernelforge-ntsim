/**
 * tracer.mjs — chronological call-trace finalization.
 *
 * Covers argument decoders, module+rva resolution, phase grouping, and the
 * kernel-side emitTrace hooks (api / dbgprint / thread / etw).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import { SparseMemory } from "../src/memory.mjs";
import { finalizeTrace, DEC } from "../src/tracer.mjs";

const BASE = 0xfffff80300000000n;

/** Minimal kernel stand-in: finalizeTrace only touches .mem. */
function fakeKernel() {
  const mem = new SparseMemory();
  return { mem, traceEvents: [] };
}

test("ctl-code / pool-tag / guid / unicode-string decoders", () => {
  const k = fakeKernel();
  const { mem } = k;
  // UNICODE_STRING{len=18, max=20, buf->L"\Device\X"} at 0x1000
  mem.w16(0x1000n, 18);
  mem.w16(0x1002n, 20);
  mem.w64(0x1008n, 0x1100n);
  const s = "\\Device\\X";
  for (let i = 0; i < s.length; i++) mem.w16(0x1100n + BigInt(i * 2), s.charCodeAt(i));

  // GUID {33a1b2c3-0000-1111-aaaa-bbbbccccdddd} at 0x1200
  const guidBytes = [
    0xc3, 0xb2, 0xa1, 0x33, 0x00, 0x00, 0x11, 0x11,
    0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd,
  ];
  mem.write(0x1200n, new Uint8Array(guidBytes));

  k.traceEvents = [
    { seq: 1, phase: "p", kind: "api", name: "FakeIoctl", args: [0x222007n], ret: 0n, retAddr: BASE + 0x1234n },
    { seq: 2, phase: "p", kind: "api", name: "ExAllocatePool2", args: [0x40n, 0x48ben, 0x4b4d5348n], ret: 0n, retAddr: BASE + 0x10n },
    { seq: 3, phase: "p", kind: "api", name: "EtwRegister", args: [0x1200n, 0n, 0n, 0x2000n], ret: 0n, retAddr: BASE + 0x10n },
    { seq: 4, phase: "p", kind: "api", name: "IoCreateSymbolicLink", args: [0x1000n, 0x1000n], ret: 0n, retAddr: BASE + 0x10n },
    { seq: 5, phase: "p", kind: "api", name: "UnknownApi", args: [1n, 2n], ret: 0n, retAddr: BASE + 0x10n },
  ];
  const { events, text } = finalizeTrace(k, [{ name: "sample.sys", base: BASE, size: 0x10000 }]);

  // raw decoders
  assert.equal(DEC.ctlcode(mem, 0x222007n), "CTL_DEVICE=0x22 FUNC=0x801 ACCESS=READ METHOD=NEITHER");
  assert.match(DEC.tag(mem, 0x4b4d5348n), /'HSMK'/);
  assert.match(DEC.guid(mem, 0x1200n), /\{33a1b2c3-0000-1111-aaaa-bbbbccccdddd\}/);
  assert.match(DEC.ustr(mem, 0x1000n), /L"\\Device\\X"/);

  // event-level behavior
  assert.match(events[1].args[1].decoded, /^18622$/); // size decoded as decimal
  assert.match(events[3].text, /IoCreateSymbolicLink\(link=L"\\Device\\X"/);
  assert.match(events[4].text, /UnknownApi\(a0=0x1, a1=0x2\)/); // unknown -> raw hex

  // module+rva resolution for callers
  assert.match(events[0].caller ?? "", /sample\.sys\+0x1234/) ;
  assert.ok(events[0].caller.startsWith("sample.sys+0x1234"));
  // phase grouping header appears
  assert.match(text, /--- phase: p ---/);
});

test("kernel emitTrace records api/dbgprint/thread/etw events chronologically", async () => {
  const k = new NtKernel();
  await k.loadTablesFromDir(
    new URL("../../ntsim-assets/data/vergilius/windows-10/22h2/", import.meta.url).pathname,
    ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"],
  );
  k.bootstrap();

  const mem = k.mem;
  // routine: mov eax,0x42 ; ret
  mem.write(0x501000n, new Uint8Array([0xb8, 0x42, 0x00, 0x00, 0x00, 0xc3]));

  k.dbgPrint(0n, []); // empty format -> still logs an event

  k.pendingThreads.push({ handle: 0x3100n, startRoutine: 0x501000n, startContext: 0x7n });
  const counts = k.drainDeferred();
  assert.equal(counts.threads, 1);

  // ETW through the modeled impl directly (thunk ABI capture is covered elsewhere)
  mem.write(0x6000n, new Uint8Array([
    0x78, 0x56, 0x34, 0x12, 0x21, 0x07, 0x00, 0x62,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ])); // GUID {12345678-0721-6200-0100-000000000000}
  mem.w64(0x6100n, 0n); // handle out
  k.apiImpls.get("EtwRegister")(0x6000n, 0n, 0n, 0x6100n);

  const kinds = k.traceEvents.map((e) => e.kind);
  assert.ok(kinds.includes("dbgprint"));
  assert.ok(kinds.includes("thread"));
  assert.ok(kinds.includes("etw"));

  const { text } = finalizeTrace(k, []);
  assert.match(text, /SystemThread\(0x501000, ctx=0x7\)/);
  assert.match(text, /ETW register provider \{12345678-0721-6200-0100-000000000000\}/);
});

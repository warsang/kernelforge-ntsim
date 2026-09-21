/**
 * seh.mjs — full x64 unwind: scope dispatch, multi-frame search,
 * chained unwind info, unwind-code execution, CONTINUE_EXECUTION resume.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "../src/memory.mjs";
import { NtKernel } from "../src/kernel.mjs";
import { PeBuilder } from "../src/pebuilder.mjs";
import { parsePe, mapPe, rvaToOffset } from "../src/pe.mjs";
import {
  parseUnwindInfo, resolveUnwindInfo, unwindFrame, snapshotContext,
  tryDispatchException,
} from "../src/seh.mjs";

const u32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const BASE = 0xfffff80300000000n;

/** Map a PE image into a fresh kernel's memory (sections at their RVAs). */
function mapImage(kernel, image) {
  mapPe(image, kernel.mem, BASE, () => 0n);
  return { base: BASE, bytes: image };
}

/** UNWIND_INFO with EHANDLER + one scope entry. */
function writeScopeTable(text, at, { handlerRva, scope }) {
  text.set([0x09, 0x00, 0x00, 0x00], at);          // version 1 | EHANDLER<<3
  text.set(u32(handlerRva), at + 4);               // handler RVA (points at table)
  text.set(u32(1), at + 8);                        // scope count
  text.set(u32(scope.begin), at + 12);
  text.set(u32(scope.end), at + 16);
  text.set(u32(scope.filter), at + 20);
  text.set(u32(scope.jumpTarget), at + 24);
}

test("parseUnwindInfo decodes unwind codes (direct)", () => {
  const len = 0x100;
  const probe = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  const t = parsePe(probe.build(0).image).sections[0].rva;
  const text = new Uint8Array(len);
  text.set([0x01, 0x08, 0x02, 0x05], 0x80); // 2 slots, frameReg rbp
  text.set([0x08, 0x42], 0x84);             // ALLOC_SMALL 0x28 at codeOffset 8
  text.set([0x04, 0x30], 0x86);             // PUSH_NONVOL rbx at codeOffset 4
  const b = new PeBuilder().addSection(".text", text, 0x60000020);
  const image = b.build(t + 0x10).image;
  const entries = [{ begin: t, end: t + 0x40, unwindRva: t + 0x80 }];
  const ui = parseUnwindInfo(image, entries, t + 0x10);
  assert.ok(ui);
  assert.equal(ui.version, 1);
  assert.equal(ui.frameReg, 5);
  assert.equal(ui.codes.length, 2);
  assert.equal(ui.codes[0].op, 2);
  assert.equal(ui.codes[0].size, 40);
  assert.equal(ui.codes[1].op, 0);
  assert.equal(ui.codes[1].info, 3);
});

test("unwindFrame undoes pushes/allocations and pops the return address", () => {
  const mem = new SparseMemory();
  // prologue: push rbx (rsp 0x4ff8), sub rsp,0x20 (rsp 0x4fd8)
  mem.w64(0x4ff8n, 0xaaaabbbbn);
  mem.w64(0x5000n, 0xfffff80300000abcn); // return address
  const ctx = { regs: { rsp: 0x4fd8n, rbx: 0n }, rip: 0xfffff80300000010n };
  const ui = {
    frameReg: 0, frameOff: 0,
    codes: [
      { op: 1, info: 0, size: 0x20, offset: 0 }, // alloc large 0x20
      { op: 0, info: 3, size: 0, offset: 0 },    // push rbx
    ],
  };
  const next = unwindFrame(mem, ctx, ui);
  assert.equal(next.regs.rbx, 0xaaaabbbbn);
  assert.equal(next.rip, 0xfffff80300000abcn);
  assert.equal(next.regs.rsp, 0x5008n);
});

test("snapshotContext captures registers and rip", () => {
  const cpu = { regs: { rsp: 0x1234n, rbp: 0x5678n, rax: 1n } };
  const ctx = snapshotContext(cpu, 0xdeadbeefn);
  assert.equal(ctx.regs.rsp, 0x1234n);
  assert.equal(ctx.regs.rbp, 0x5678n);
  assert.equal(ctx.rip, 0xdeadbeefn);
});

// --------------------------------------------------------------------------
// End-to-end dispatches through a real image
// --------------------------------------------------------------------------

function buildMultiFrameImage() {
  const entrySub = 0x10;
  const innerSub = 0x40;
  const len = 0x100;
  const b0 = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  const t = parsePe(b0.build(0).image).sections[0].rva;
  const text = new Uint8Array(len);

  // entry: call inner (rel32) ; ret
  const callOff = entrySub;
  text.set([0xe8, ...u32(0)], entrySub);
  const innerVa = t + innerSub;
  const callNext = t + callOff + 5;
  const rel = innerVa - callNext;
  text.set(u32(rel >>> 0), entrySub + 1);
  text.set([0xc3], entrySub + 5);
  // inner: ud2 ; mov eax,0x1234 ; ret
  text.set([0x0f, 0x0b], innerSub);
  text.set([0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3], innerSub + 2);
  // filters/handlers
  text.set([0xb8, 1, 0, 0, 0, 0xc3], 0x20);                 // filter -> 1
  text.set([0xb8, 0xde, 0xc0, 0xad, 0xde, 0xc3], 0x30);     // except body

  // entry UNWIND_INFO @t+0x80 with scope over the call
  writeScopeTable(text, 0x80, {
    handlerRva: t + 0x88,
    scope: { begin: t + entrySub, end: t + entrySub + 6, filter: t + 0x20, jumpTarget: t + 0x30 },
  });
  // inner UNWIND_INFO @t+0xA0: no handlers, no codes (leaf-ish)
  text.set([0x01, 0x00, 0x00, 0x00], 0xa0);

  // .pdata: two consecutive 12-byte RUNTIME_FUNCTIONs, sorted by begin
  text.set(u32(t + entrySub), 0xc0);
  text.set(u32(t + entrySub + 6), 0xc4);
  text.set(u32(t + 0x80), 0xc8);
  text.set(u32(t + innerSub), 0xcc);
  text.set(u32(t + innerSub + 2), 0xd0);
  text.set(u32(t + 0xa0), 0xd4);

  const b = new PeBuilder().addSection(".text", text, 0x60000020);
  b.exceptionDir = { rva: t + 0xc0, size: 24 };
  const image = b.build(t + entrySub).image;
  return { image, entrySub, innerSub, t };
}

test("multi-frame walk finds the caller's __except handler", () => {
  const { image, entrySub, t } = buildMultiFrameImage();
  const kernel = new NtKernel({ arch: false });
  const mapped = mapImage(kernel, image);
  const r = kernel.callFunctionSeh(BASE + BigInt(t + entrySub), [], mapped);
  assert.equal(r.status, "ok", `status=${r.status} err=${r.error?.message ?? ""} detail=${r.sehDetail ?? ""}`);
  assert.equal(r.sehHandled, true);
  assert.equal(r.retval, 0xdeadc0den);
  assert.match(r.sehDetail, /except handler/);
});

test("filter CONTINUE_SEARCH unwinds to the caller", () => {
  const { image, t } = buildMultiFrameImage();
  // Patch the filter to return 0 (continue search) - no handler anywhere.
  const patched = new Uint8Array(image);
  const off = rvaToOffset(parsePe(image), t + 0x20);
  assert.deepEqual([...image.slice(off, off + 6)], [0xb8, 1, 0, 0, 0, 0xc3]);
  patched.set([0xb8, 0, 0, 0, 0, 0xc3], off); // filter -> 0
  const kernel = new NtKernel({ arch: false });
  mapImage(kernel, patched);
  const r = tryDispatchException(kernel, { base: BASE, bytes: patched }, {
    rip: BASE + BigInt(t + 0x40), message: "unimplemented 0f opcode 0x0b",
  });
  assert.equal(r.handled, false);
  assert.match(r.detail, /no handler/);
});

function buildContinueExecutionImage() {
  const entrySub = 0x10;
  const innerSub = 0x40;
  const len = 0x100;
  const b0 = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  const t = parsePe(b0.build(0).image).sections[0].rva;
  const text = new Uint8Array(len);

  // entry: call inner ; ret
  text.set([0xe8, ...u32(0)], entrySub);
  const rel = (t + innerSub) - (t + entrySub + 5);
  text.set(u32(rel >>> 0), entrySub + 1);
  text.set([0xc3], entrySub + 5);
  // inner: ud2 ; mov eax,0x1234 ; ret
  text.set([0x0f, 0x0b], innerSub);
  text.set([0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3], innerSub + 2);
  // filter: patch Context->Rip += 2, return -1
  //   mov rax,[rcx+8]         48 8B 41 08
  //   add qword [rax+0xF8], 2 48 83 80 F8 00 00 00 02
  //   mov eax,-1              B8 FF FF FF FF
  //   ret                     C3
  text.set([
    0x48, 0x8b, 0x41, 0x08,
    0x48, 0x83, 0x80, 0xf8, 0x00, 0x00, 0x00, 0x02,
    0xb8, 0xff, 0xff, 0xff, 0xff,
    0xc3,
  ], 0x20);
  // scope on the inner function so its frame owns the filter
  writeScopeTable(text, 0x80, {
    handlerRva: t + 0x88,
    scope: { begin: t + innerSub, end: t + innerSub + 2, filter: t + 0x20, jumpTarget: t + 0x30 },
  });
  text.set([0x01, 0x00, 0x00, 0x00], 0xa0); // entry leaf unwind info
  // .pdata: inner @0xc0, entry @0xcc
  text.set(u32(t + innerSub), 0xc0);
  text.set(u32(t + innerSub + 2), 0xc4);
  text.set(u32(t + 0x80), 0xc8);
  text.set(u32(t + entrySub), 0xcc);
  text.set(u32(t + entrySub + 6), 0xd0);
  text.set(u32(t + 0xa0), 0xd4);

  const b = new PeBuilder().addSection(".text", text, 0x60000020);
  b.exceptionDir = { rva: t + 0xc0, size: 24 };
  const image = b.build(t + entrySub).image;
  return { image, entrySub, innerSub, t };
}

test("filter CONTINUE_EXECUTION resumes after a patched CONTEXT.Rip", () => {
  const { image, entrySub, t } = buildContinueExecutionImage();
  const kernel = new NtKernel({ arch: false });
  const mapped = mapImage(kernel, image);
  const r = kernel.callFunctionSeh(BASE + BigInt(t + entrySub), [], mapped);
  assert.equal(r.status, "ok", `status=${r.status} err=${r.error?.message ?? ""} detail=${r.sehDetail ?? ""}`);
  assert.equal(r.sehHandled, true);
  assert.equal(r.retval, 0x1234n); // resumed after UD2, took the mov eax path
  assert.match(r.sehDetail, /CONTINUE_EXECUTION/);
});

test("chained UNWIND_INFO inherits the parent's handler scopes", () => {
  const len = 0x100;
  const b0 = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  const t = parsePe(b0.build(0).image).sections[0].rva;
  const text = new Uint8Array(len);
  const childSub = 0x40;
  text.set([0x0f, 0x0b], childSub);                          // ud2
  text.set([0xb8, 1, 0, 0, 0, 0xc3], 0x20);                  // filter -> 1
  text.set([0xb8, 0xde, 0xc0, 0xad, 0xde, 0xc3], 0x30);      // handler

  // parent UNWIND_INFO @t+0x80 with a scope covering the child
  writeScopeTable(text, 0x80, {
    handlerRva: t + 0x88,
    scope: { begin: t + childSub, end: t + childSub + 2, filter: t + 0x20, jumpTarget: t + 0x30 },
  });
  // child UNWIND_INFO @t+0xA0: version 1, flags CHAININFO (0x04<<3) -> parent @t+0x80
  text.set([0x21, 0x00, 0x00, 0x00], 0xa0);
  text.set(u32(t + childSub), 0xa4);
  text.set(u32(t + childSub + 2), 0xa8);
  text.set(u32(t + 0x80), 0xac);
  // .pdata: only the child function (parent's entry is not required)
  text.set(u32(t + childSub), 0xc0);
  text.set(u32(t + childSub + 2), 0xc4);
  text.set(u32(t + 0xa0), 0xc8);

  const b = new PeBuilder().addSection(".text", text, 0x60000020);
  b.exceptionDir = { rva: t + 0xc0, size: 12 };
  const image = b.build(t + childSub).image;

  const entries = [{ begin: t + childSub, end: t + childSub + 2, unwindRva: t + 0xa0 }];
  const ui = resolveUnwindInfo(image, entries, t + childSub);
  assert.ok(ui.chained);
  assert.equal(ui.scopes.length, 1);

  const kernel = new NtKernel({ arch: false });
  const mapped = mapImage(kernel, image);
  const r = kernel.callFunctionSeh(BASE + BigInt(t + childSub), [], mapped);
  assert.equal(r.status, "ok", `status=${r.status} err=${r.error?.message ?? ""} detail=${r.sehDetail ?? ""}`);
  assert.equal(r.sehHandled, true);
  assert.equal(r.retval, 0xdeadc0den);
});

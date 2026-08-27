/**
 * Conformance suite: the same driver-level CPU behaviors must hold on both
 * backends. JsInterpreter is the reference; UnicornCpuBackend must match.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { createUnicornBackend } from "../src/backend.mjs";
import { CodeBuf, REX_W } from "../../ntsim/test/helpers/codebuf.mjs";

const backends = {
  js: async (mem) => new JsInterpreter(mem),
  unicorn: async (mem) => await createUnicornBackend(mem),
};

for (const [name, make] of Object.entries(backends)) {
  const newCpu = async () => {
    const mem = new SparseMemory();
    return { mem, cpu: await make(mem) };
  };

  test(`[${name}] mov r64 imm64 + ret`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.db(0x48).db(0xb8).dq(0x4142434445464748n);
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    const r = cpu.callFunction(0x1000n);
    assert.equal(r.status, "ok");
    assert.equal(r.retval, 0x4142434445464748n);
  });

  test(`[${name}] windows x64 ABI args`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.db(0x48).db(0x89).db(0xc8);
    c.db(0x48).db(0x01).db(0xd0);
    c.db(0x4c).db(0x01).db(0xc0);
    c.db(0x4c).db(0x01).db(0xc8);
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    const r = cpu.callFunction(0x1000n, [10n, 20n, 30n, 40n]);
    assert.equal(r.retval, 100n);
  });

  test(`[${name}] memory operand + rip-relative`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.db(0x48).db(0x8b).db(0x01); // mov rax,[rcx]
    c.db(REX_W).db(0x8b).db(0x05).dd(9); // mov rax,[rip+9]
    c.db(0xc3);
    mem.w64(0x2000n, 0xcafe1234n);
    cpu.regs.rcx = 0x2000n;
    mem.write(0x1000n, c.b);
    mem.w64(0x1013n, 0x11223344n);
    const r = cpu.callFunction(0x1000n);
    assert.equal(r.retval, 0x11223344n);
  });

  test(`[${name}] stack ops and call/ret chains`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.db(0x55);
    c.db(REX_W).db(0x89).db(0xe5);
    c.db(REX_W).db(0x83).db(0xec).db(0x10);
    c.db(REX_W).db(0x89).db(0x4d).db(0x00);
    c.db(REX_W).db(0x8b).db(0x45).db(0x00);
    c.db(0xc9);
    c.db(0xc3);
    mem.write(0x3000n, c.b);
    // give unicorn an explicit low stack like real usage
    if (cpu.regs.rsp === 0n) cpu.regs.rsp = 0x7ff00n;
    mem.write(0x7f000n, new Uint8Array(0x100));
    const r = cpu.callFunction(0x3000n, [0x777n]);
    assert.equal(r.status, "ok");
    assert.equal(r.retval, 0x777n);
  });

  test(`[${name}] flags jcc + loop sum`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.bytes(0x31, 0xc0);
    c.db(REX_W).bytes(0x01, 0xc8);
    c.db(0xff).db(0xc9);
    c.bytes(0x75, 0xf9);
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    const r = cpu.callFunction(0x1000n, [10n]);
    assert.equal(r.retval, 55n);
  });

  test(`[${name}] rep movsb copies memory`, async () => {
    const { mem, cpu } = await newCpu();
    mem.writeAnsi(0x5000n, "HOOK");
    const c = new CodeBuf();
    c.db(0xfc);
    c.db(0x48).db(0xbe).dq(0x5000n);
    c.db(0x48).db(0xbf).dq(0x6000n);
    c.db(0x48).db(0xb9).dq(8n);
    c.bytes(0xf3, 0xa4);
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    if (cpu.regs.rsp === 0n) cpu.regs.rsp = 0x7ff00n;
    mem.write(0x7f000n, new Uint8Array(0x100));
    const r = cpu.callFunction(0x1000n);
    assert.equal(r.status, "ok");
    assert.equal(mem.readAnsi(0x6000n, 8), "HOOK");
  });

  test(`[${name}] timeout guard stops infinite loops`, async () => {
    const { mem, cpu } = await newCpu();
    const c = new CodeBuf();
    c.bytes(0xeb, 0xfe); // jmp $
    mem.write(0x1000n, c.b);
    const t0 = Date.now();
    const reason = cpu.run(10_000);
    assert.equal(reason, name === "unicorn" ? "timeout" : "timeout");
    assert.ok(Date.now() - t0 < 2000);
  });

  test(`[${name}] kernel VAs survive register round-trip (API level)`, async () => {
    const { mem, cpu } = await newCpu();
    const va = 0xffffb80000001000n;
    cpu.regs.rax = va;
    assert.equal(cpu.regs.rax, va); // no Number round-trip anywhere
    cpu.regs.rdx = va;
    cpu.regs.rcx = 0x4142n;
    void mem;
  });

  test(`[${name}] addCodeHook intercepts thunk with side effect`, async () => {
  const { mem, cpu } = await newCpu();
  const SCRATCH = 0x9000n;
  const c = new CodeBuf();
  // 0x1000: call 0x5000 (rel32 = 0x5000 - 0x1005)
  // 0x1005: mov rax, [0x9000]  -> movabs rcx,SCRATCH ; mov rax,[rcx]
  // then ret
  c.db(0xe8).dd(Number((0x5000n - 0x1005n) & 0xffffffffn));
  c.db(REX_W).db(0xb8 ^ 1 ? 0xb9 : 0xb9).dq(SCRATCH); // movabs rcx, SCRATCH
  c.db(REX_W).db(0x8b).db(0x01);                      // mov rax,[rcx]
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  mem.write(0x5000n, [0xf4]);
  if (cpu.regs.rsp === 0n) cpu.regs.rsp = 0x7ff00n;
  mem.write(0x7f000n, new Uint8Array(0x100));

  cpu.addCodeHook((addr) => {
    if (addr !== 0x5000n) return false;
    mem.w64(SCRATCH, 0xc0ffee11n); // thunk side effect in memory
    cpu.regs.rax = 0x99n;
    cpu.rip = cpu.popVal();        // synthetic ret
    return true;
  }, 0x5000n, 0x5fffn);

  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(mem.u64(SCRATCH), 0xc0ffee11n);   // side effect landed
  assert.equal(r.retval, 0xc0ffee11n);           // guest observed it via [SCRATCH]
});

// JS-interpreter-specific: fail-loud on truly unknown opcode (UD2)
test("[js] unimplemented opcode raises CpuError", async () => {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  const c = new CodeBuf();
  c.bytes(0x0f, 0x0b); // UD2
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented|opcode/i);
});

// Unicorn-specific: full ISA executes what the interpreter refuses (UD2 still faults on both, so use extended SSE that Unicorn handles but JS now also handles — demonstrate parity)
test("[unicorn] extended SSE still executes on Unicorn (parity check)", async () => {
  const mem = new SparseMemory();
  const cpu = await createUnicornBackend(mem);
  const c = new CodeBuf();
  c.bytes(0x48, 0x31, 0xc0);   // xor rax,rax
  c.bytes(0x0f, 0x28, 0xc1);   // movaps xmm0,xmm1 — now supported on both, but Unicorn proves WASM path
  c.bytes(0x48, 0xff, 0xc0);   // inc rax
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  cpu.regs.rsp = 0x7ff00n;
  mem.write(0x7f000n, new Uint8Array(0x100));
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 1n);
});
}

// JS-interpreter-specific: fail-loud on UD2
test("[js] unimplemented opcode raises CpuError", async () => {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  const c = new CodeBuf();
  c.bytes(0x0f, 0x0b); // UD2
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented|opcode/i);
});

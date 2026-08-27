import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "../src/memory.mjs";
import { JsInterpreter, M64 } from "../src/cpu.mjs";
import { CodeBuf, REX_W } from "./helpers/codebuf.mjs";

function newCpu() {
  const mem = new SparseMemory();
  return { mem, cpu: new JsInterpreter(mem) };
}

test("mov r64 imm64 + ret", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // movabs rax, 0x4142434445464748
  c.db(0x48).db(0xb8).dq(0x4142434445464748n);
  c.db(0xc3); // ret
  const base = 0x1000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x4142434445464748n);
});

test("windows x64 ABI: args in rcx/rdx/r8/r9", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // mov rax, rcx ; add rax, rdx ; add rax, r8 ; add rax, r9
  c.db(0x48).db(0x89).db(0xc8);
  c.db(0x48).db(0x01).db(0xd0);
  c.db(0x4c).db(0x01).db(0xc0);
  c.db(0x4c).db(0x01).db(0xc8);
  c.db(0xc3);
  const base = 0x1000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base, [10n, 20n, 30n, 40n]);
  assert.equal(r.retval, 100n);
});

test("memory operand: mov rax, [rcx]", () => {
  const { mem, cpu } = Sestup();
  function Sestup() { return newCpu(); }
  const c = new CodeBuf();
  c.db(0x48).db(0x8b).db(0x01); // mov rax,[rcx]
  c.db(0xc3);
  const dataAddr = 0x2000n;
  mem.w64(dataAddr, 0xcafe1234n);
  cpu.regs.rcx = dataAddr;
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.retval, 0xcafe1234n);
});

test("RIP-relative addressing", () => {
  const { mem, cpu } = newCpu();
  const base = 0x1000n;
  const c = new CodeBuf();
  // mov rax, [rip+disp32] ; instruction is 7 bytes at base
  // rip after = base+7 ; want target base+16 => disp = 9
  c.db(REX_W).db(0x8b).db(0x05).dd(9);
  c.db(0xc3);
  c.bytes(0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90); // pad base+8..base+14
  mem.write(base, c.b);
  mem.w64(base + 16n, 0x11223344n);
  const r = cpu.callFunction(base);
  assert.equal(r.retval, 0x11223344n);
});

test("stack ops and call/ret chains", () => {
  const { mem, cpu } = newCpu();
  // func B: mov rax, [rsp+8] ... actually test push/pop correctness
  const c = new CodeBuf();
  c.db(0x55);                         // push rbp
  c.db(REX_W).db(0x89).db(0xe5);      // mov rbp, rsp
  c.db(REX_W).db(0x83).db(0xec).db(0x10); // sub rsp, 0x10
  c.db(REX_W).db(0x89).db(0x4d).db(0x00); // mov [rbp], rcx  (no -8 offset for simplicity)
  c.db(REX_W).db(0x8b).db(0x45).db(0x00); // mov rax, [rbp]
  c.db(0xc9);                         // leave
  c.db(0xc3);                         // ret
  const base = 0x3000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base, [0x777n]);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x777n);
});

test("flags: jcc taken/not-taken", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // cmp rcx, rdx ; sete al -> return rcx==rdx
  // mov eax, 0
  c.db(0xb8).dd(0);
  // cmp rcx, rdx
  c.db(REX_W).db(0x39).db(0xd1);
  // sete al
  c.bytes(0x0f, 0x94, 0xc0);
  c.db(0xc3);
  mem.write(0x1000n, c.b);

  let r = cpu.callFunction(0x1000n, [5n, 5n]);
  assert.equal(r.retval, 1n);
  r = cpu.callFunction(0x1000n, [5n, 6n]);
  assert.equal(r.retval, 0n);
});

test("loop: sum 1..N with jne", () => {
  const { mem, cpu } = newCpu();
  // xor eax,eax ; L: add rax,rcx ; dec rcx ; jnz L ; ret
  const c = new CodeBuf();
  c.bytes(0x31, 0xc0);                    // 1000: xor eax, eax
  c.db(REX_W).bytes(0x01, 0xc8);          // 1002: L: add rax, rcx
  c.db(0xff).db(0xc9);                    // 1005: dec rcx
  c.bytes(0x75, 0xf9);                    // 1007: jnz -> end=1009, 1009-7=1002 => f9
  c.db(0xc3);                             // 1009: ret
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n, [10n]);
  assert.equal(r.retval, 55n);
});

test("rep movsb copies memory", () => {
  const { mem, cpu } = newCpu();
  mem.writeAnsi(0x5000n, "HOOK");
  const c = new CodeBuf();
  // cld; mov rsi, 0x5000; mov rdi, 0x6000; mov rcx, 8; rep movsb
  c.db(0xfc);                              // cld
  c.db(0x48).db(0xbe).dq(0x5000n);         // movabs rsi
  c.db(0x48).db(0xbf).dq(0x6000n);         // movabs rdi
  c.db(0x48).db(0xb9).dq(8n);              // movabs rcx
  c.bytes(0xf3, 0xa4);                     // rep movsb
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(mem.readAnsi(0x6000n, 8), "HOOK");
});

test("unimplemented opcode raises CpuError with rip", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.bytes(0x0f, 0x0b); // UD2 — always #UD, classified as unimplemented
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented/);
});

test("timeout guard stops infinite loops", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.bytes(0xeb, 0xfe); // jmp $
  mem.write(0x1000n, c.b);
  const t0 = Date.now();
  const reason = cpu.run(10_000);
  assert.equal(reason, "timeout");
  assert.ok(Date.now() - t0 < 2000);
});

test("kernel VAs (>2^53) survive register round-trip", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.db(REX_W).db(0x89).db(0xc8); // mov rax, rcx
  c.db(0xc3);                    // ret
  mem.write(0x1000n, c.b);
  const va = 0xffffb80000001000n;
  const r = cpu.callFunction(0x1000n, [va]);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, va); // truncated under the old 40-bit M64 mask
});

test("addCodeHook intercepts within range only", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // 0x1000: mov rax, 42        (overwrites rax if the hook failed to fire)
  // 0x1007: call 0x5000        (rel32 = 0x5000 - 0x100c = 0x3ff4)
  // 0x100c: ret
  c.db(REX_W).db(0xc7).db(0xc0).dd(42);
  c.db(0xe8).dd(0x3ff4);
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  mem.write(0x5000n, [0xf4]); // hlt marker, never executed when hook fires

  cpu.addCodeHook(() => {
    cpu.regs.rax = 0x99n;
    cpu.rip = cpu.popVal(); // emulate ret
    return true;
  }, 0x5000n, 0x5fffn);
  // decoy: wrong range must never fire
  cpu.addCodeHook(() => {
    cpu.regs.rax = 0x77n;
    return true;
  }, 0x9000n, 0x9fffn);

  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x99n);
});

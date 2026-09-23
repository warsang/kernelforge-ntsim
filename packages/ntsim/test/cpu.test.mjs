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

test("addCodeHook intercepts within range only", () => {  const { mem, cpu } = newCpu();
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

test("bswap r32/r64 byte-reverses without touching flags", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // xor eax,eax (zf=1) ; mov eax,0x12345678 ; bswap eax ; ret
  c.bytes(0x31, 0xc0);
  c.db(0xb8).dd(0x12345678);
  c.bytes(0x0f, 0xc8); // bswap eax
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x78563412n);
  assert.equal(cpu.zf, true); // bswap preserves flags

  // 64-bit: bswap rax ; REX.B form: bswap r10d
  const c2 = new CodeBuf();
  c2.db(REX_W).db(0xb8).dq(0x0123456789abcdefn);
  c2.bytes(0x48, 0x0f, 0xc8); // bswap rax
  c2.db(0x49).db(0xba).dq(0x1122334455667788n); // movabs r10
  c2.bytes(0x66, 0x41, 0x0f, 0xca); // bswap r10d (0x66 ignored)
  c2.bytes(0x4c, 0x89, 0xd0); // mov rax, r10
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  const r2 = cpu.callFunction(0x2000n);
  assert.equal(r2.status, "ok");
  assert.equal(cpu.regs.rax & 0xffffffffn, 0x88776655n); // low32 swapped, zero-extended
  assert.equal(cpu.regs.r10, 0x88776655n);
});

test("mov r/m16,Sreg (0x8c) reads selectors; 0x8e round-trips", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  // mov ax,0x1234 ; mov ds,ax ; xor eax,eax ; mov ax,ds ; ret
  c.bytes(0x66, 0xb8, 0x34, 0x12);
  c.bytes(0x8e, 0xd8); // mov ds, ax
  c.bytes(0x31, 0xc0);
  c.bytes(0x8c, 0xd8); // mov ax, ds
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x1234n);

  // default selectors: CS=0x10 stored to memory via modrm
  const c2 = new CodeBuf();
  c2.db(0x48).db(0xb9).dq(0x4000n); // movabs rcx, data
  c2.bytes(0x8c, 0x09); // mov [rcx], cs
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  const r2 = cpu.callFunction(0x2000n);
  assert.equal(r2.status, "ok");
  assert.deepEqual(mem.read(0x4000n, 2), Uint8Array.from([0x10, 0x00]));
});

test("jrcxz/jecxz jumps on zero rcx/ecx", () => {
  const { mem, cpu } = newCpu();
  const mk = () => {
    const c = new CodeBuf();
    c.bytes(0x31, 0xc9); // xor ecx, ecx
    c.bytes(0xe3, 0x06); // jrcxz +6 -> mov eax, 2
    c.db(0xb8).dd(1);    // mov eax, 1
    c.db(0xc3);
    c.db(0xb8).dd(2);    // mov eax, 2
    c.db(0xc3);
    return c;
  };
  mem.write(0x1000n, mk().b);
  // rcx=0 via xor -> taken
  assert.equal(cpu.callFunction(0x1000n, [0xdeadn]).retval, 2n);
  // 0x67 form tests ECX, not RCX: high bits set but low32 zero -> taken
  const c2 = new CodeBuf();
  c2.bytes(0x67, 0xe3, 0x06); // jecxz +6
  c2.db(0xb8).dd(1);
  c2.db(0xc3);
  c2.db(0xb8).dd(2);
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  assert.equal(cpu.callFunction(0x2000n, [0x100000000n]).retval, 2n);
  assert.equal(cpu.callFunction(0x2000n, [5n]).retval, 1n);
});

test("shld/shrd double shifts with flags", () => {
  const { mem, cpu } = newCpu();
  // shrd eax, ebx, 8 : eax=0x12345678 ebx=0xabcdef01 -> 0x01123456, cf=0
  const c = new CodeBuf();
  c.db(0xb8).dd(0x12345678);
  c.db(0xbb).dd(0xabcdef01);
  c.bytes(0x0f, 0xac, 0xd8, 0x08);
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x01123456n);
  assert.equal(cpu.cf, false);

  // shld eax, ebx, cl=4 : (0x12345678<<4)|(0xabcdef01>>28) = 0x2345678a, cf=1
  const c2 = new CodeBuf();
  c2.db(0xb8).dd(0x12345678);
  c2.db(0xbb).dd(0xabcdef01);
  c2.db(0xb9).dd(4);
  c2.bytes(0x0f, 0xa5, 0xd8); // shld eax, ebx, cl
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  const r2 = cpu.callFunction(0x2000n);
  assert.equal(r2.status, "ok");
  assert.equal(r2.retval, 0x2345678an);
  assert.equal(cpu.cf, true);

  // count 0: no-op, flags preserved
  const c3 = new CodeBuf();
  c3.db(0xb8).dd(0x11);
  c3.bytes(0x31, 0xdb); // xor ebx,ebx -> zf=1
  c3.bytes(0x0f, 0xac, 0xd8, 0x00);
  c3.db(0xc3);
  mem.write(0x3000n, c3.b);
  const r3 = cpu.callFunction(0x3000n);
  assert.equal(r3.status, "ok");
  assert.equal(r3.retval, 0x11n);
  assert.equal(cpu.zf, true);
});

test("xadd exchanges and adds with ADD flags", () => {
  const { mem, cpu } = newCpu();
  // xadd eax, ebx : eax=5 ebx=7 -> eax=12 ebx=5
  const c = new CodeBuf();
  c.db(0xb8).dd(5);
  c.db(0xbb).dd(7);
  c.bytes(0x0f, 0xc1, 0xd8);
  c.bytes(0x89, 0xd8); // mov eax, ebx -> observe exchanged value
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 5n);

  // mem form + carry: [0x4000]=0xffffffff xadd eax -> mem=0, eax=old, cf=1 zf=1
  mem.w32(0x4000n, 0xffffffff);
  const c2 = new CodeBuf();
  c2.db(0x48).db(0xb9).dq(0x4000n);
  c2.db(0xb8).dd(1);
  c2.bytes(0x0f, 0xc1, 0x01); // xadd [rcx], eax
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  const r2 = cpu.callFunction(0x2000n);
  assert.equal(r2.status, "ok");
  assert.equal(r2.retval, 0xffffffffn);
  assert.equal(mem.u32(0x4000n), 0);
  assert.equal(cpu.cf, true);
  assert.equal(cpu.zf, true);
});

test("bsf/bsr scan with ZF on zero source", () => {
  const { mem, cpu } = newCpu();
  const run = (blob, ebx) => {
    const c = new CodeBuf();
    c.db(0xbb).dd(ebx);
    c.db(0xb8).dd(0xaa);
    c.bytes(...blob);
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    return cpu.callFunction(0x1000n);
  };
  assert.equal(run([0x0f, 0xbc, 0xc3], 0x00100000).retval, 20n); // bsf
  assert.equal(cpu.zf, false);
  assert.equal(run([0x0f, 0xbd, 0xc3], 0x80000001).retval, 31n); // bsr
  assert.equal(run([0x0f, 0xbd, 0xc3], 0).retval, 0xaan); // zero: dest kept
  assert.equal(cpu.zf, true);
  // 64-bit: bsr rax, rbx with bit 32 -> 32
  const c = new CodeBuf();
  c.db(0x48).db(0xbb).dq(0x100000000n);
  c.bytes(0x48, 0x0f, 0xbd, 0xc3);
  c.db(0xc3);
  mem.write(0x2000n, c.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 32n);
});

test("0f ba bt/bts/btr/btc by imm8", () => {
  const { mem, cpu } = newCpu();
  const run = (sub, eax) => {
    const c = new CodeBuf();
    c.db(0xb8).dd(eax);
    c.bytes(0x0f, 0xba, 0xe0 | sub, 0x05);
    c.bytes(0x0f, 0x92, 0xc0); // setc al
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    return cpu.callFunction(0x1000n);
  };
  assert.equal(run(4, 0xdf).retval, 0n); // bt, bit5 clear -> cf=0
  assert.equal(run(4, 0xff).retval, 1n); // bt, bit5 set -> cf=1
  // bts sets the bit (0 -> 0x20), btr clears it back (0x20 -> 0)
  const c = new CodeBuf();
  c.db(0xb8).dd(0);
  c.bytes(0x0f, 0xba, 0xe8, 0x05); // bts eax, 5
  c.bytes(0x0f, 0xba, 0xf0, 0x05); // btr eax, 5
  c.db(0xc3);
  mem.write(0x2000n, c.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0n);
  assert.equal(cpu.cf, true); // btr observed the bit set by bts
});

test("rol/ror rotate values, keep ZF/SF, set CF", () => {
  const { mem, cpu } = newCpu();
  // rol eax,4 : 0x12345678 -> 0x23456781, cf = bit28 = 1, zf preserved
  const c = new CodeBuf();
  c.bytes(0x31, 0xc0); // zf=1
  c.db(0xb8).dd(0x12345678);
  c.bytes(0xc1, 0xc0, 0x04);
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const r = cpu.callFunction(0x1000n);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x23456781n);
  assert.equal(cpu.cf, true);
  assert.equal(cpu.zf, true); // rol must not touch ZF/SF
  assert.equal(cpu.sf, false);

  // ror eax,4 : 0x12345678 -> 0x81234567
  const c2 = new CodeBuf();
  c2.db(0xb8).dd(0x12345678);
  c2.bytes(0xc1, 0xc8, 0x04);
  c2.db(0xc3);
  mem.write(0x2000n, c2.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0x81234567n);

  // 8-bit: rol al,3 : 0x81 -> 0x0c
  const c3 = new CodeBuf();
  c3.bytes(0xb0, 0x81);
  c3.bytes(0xc0, 0xc0, 0x03);
  c3.bytes(0x0f, 0xb6, 0xc0); // movzx eax, al
  c3.db(0xc3);
  mem.write(0x3000n, c3.b);
  assert.equal(cpu.callFunction(0x3000n).retval, 0x0cn);
});

test("rdtsc is deterministic and monotonic", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.bytes(0x0f, 0x31); // rdtsc
  c.db(0x50);          // push rax
  c.bytes(0x0f, 0x31); // rdtsc
  c.db(0x5b);          // pop rbx
  c.bytes(0x48, 0x29, 0xd8); // sub rax, rbx
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  const once = cpu.callFunction(0x1000n);
  const twice = cpu.callFunction(0x1000n);
  assert.equal(once.status, "ok");
  assert.ok(once.retval > 0n); // tick advanced between the two reads
  assert.equal(once.retval, twice.retval); // deterministic

  // system opcodes without ModRM stay honest errors (no stream desync)
  const d = new CodeBuf();
  d.bytes(0x0f, 0x32); // rdmsr
  d.db(0xc3);
  mem.write(0x2000n, d.b);
  const r = cpu.callFunction(0x2000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented 0f opcode/);
});

test("parity flag: jp/jnp follow low-byte popcount", () => {
  const run = (bytes, addr) => {
    const { mem, cpu } = newCpu();
    const c = new CodeBuf();
    c.bytes(...bytes);
    c.db(0xc3);
    mem.write(BigInt(addr), c.b);
    return cpu.callFunction(BigInt(addr)).retval;
  };
  // xor eax,eax -> PF=1: jp taken (skips mov al,7), jnp falls through
  assert.equal(run([0x31, 0xc0, 0x7a, 0x02, 0xb0, 0x07], 0x1000), 0n);
  assert.equal(run([0x31, 0xc0, 0x7b, 0x02, 0xb0, 0x07], 0x2000), 7n);
  // al=3 (two bits set... 0b11 -> even -> PF=1); al=1 (one bit -> PF=0)
  assert.equal(run([0xb0, 0x03, 0x84, 0xc0, 0x7b, 0x02, 0xb0, 0x07], 0x3000), 7n);
  assert.equal(run([0xb0, 0x01, 0x84, 0xc0, 0x7b, 0x02, 0xb0, 0x07], 0x4000), 1n);
  assert.equal(run([0xb0, 0x01, 0x84, 0xc0, 0x7a, 0x02, 0xb0, 0x07], 0x5000), 7n);
});

test("debug registers: mov dr round-trips, dr4/5 alias, mem form faults", () => {
  const { mem, cpu } = newCpu();
  // movabs rax, <val> ; mov dr0, rax ; mov rbx, dr0 ; ret -> val
  const c = new CodeBuf();
  c.db(0x48).db(0xb8).dq(0xdeadbeef12345678n);
  c.bytes(0x0f, 0x23, 0xc0); // mov dr0, rax
  c.bytes(0x0f, 0x21, 0xc3); // mov rbx, dr0
  c.bytes(0x48, 0x89, 0xd8); // mov rax, rbx
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  assert.equal(cpu.callFunction(0x1000n).retval, 0xdeadbeef12345678n);

  // dr4 aliases dr6
  const d = new CodeBuf();
  d.db(0x48).db(0xb8).dq(0x55n);
  d.bytes(0x0f, 0x23, 0xe0); // mov dr4, rax
  d.bytes(0x0f, 0x21, 0xf3); // mov rbx, dr6 (/6 = 110_011)
  d.bytes(0x48, 0x89, 0xd8);
  d.db(0xc3);
  mem.write(0x2000n, d.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0x55n);

  // mem form is invalid -> honest fault
  const m = new CodeBuf();
  m.bytes(0x0f, 0x23, 0x00); // mov [rax], dr? (mod=0)
  m.db(0xc3);
  mem.write(0x3000n, m.b);
  const r = cpu.callFunction(0x3000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented 0f 23/);
});

test("0f ae fences are no-ops preserving flags", () => {
  for (const modrm of [0xe8, 0xf0, 0xf8]) { // lfence / mfence / sfence
    const { mem, cpu } = newCpu();
    const c = new CodeBuf();
    c.bytes(0x38, 0xc0);       // cmp al, al -> ZF=1
    c.bytes(0x0f, 0xae, modrm); // fence
    c.bytes(0x0f, 0x94, 0xc0); // setz al -> 1 iff ZF survived
    c.bytes(0x0f, 0xb6, 0xc0); // movzx eax, al
    c.db(0xc3);
    mem.write(0x1000n, c.b);
    const r = cpu.callFunction(0x1000n);
    assert.equal(r.status, "ok");
    assert.equal(r.retval, 1n);
  }
});

test("0f ae clflush + mxcsr + fxsave area stubs", () => {
  const { mem, cpu } = newCpu();
  const data = 0x4000n;
  // clflush [rax] must not fault and must leave memory alone
  mem.w64(data, 0x1122334455667788n);
  const c = new CodeBuf();
  c.db(0x48).db(0xb8).dq(data); // movabs rax, data
  c.bytes(0x0f, 0xae, 0x38);    // clflush [rax]
  c.bytes(0x48, 0x8b, 0x00);    // mov rax, [rax]
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  assert.equal(cpu.callFunction(0x1000n).retval, 0x1122334455667788n);

  // stmxcsr default -> 0x1f80; ldmxcsr round-trips a new value
  const s = new CodeBuf();
  s.db(0x48).db(0xb8).dq(data);
  s.bytes(0x0f, 0xae, 0x18);    // stmxcsr [rax]
  s.bytes(0x8b, 0x00);          // mov eax, [rax]
  s.db(0xc3);
  mem.write(0x2000n, s.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0x1f80n);
  const l = new CodeBuf();
  l.db(0x48).db(0xb8).dq(data);
  l.bytes(0xc7, 0x00).dd(0x5f5f); // mov dword [rax], 0x5f5f
  l.bytes(0x0f, 0xae, 0x10);      // ldmxcsr [rax]
  l.bytes(0x0f, 0xae, 0x18);      // stmxcsr [rax]
  l.bytes(0x8b, 0x00);            // mov eax, [rax]
  l.db(0xc3);
  mem.write(0x3000n, l.b);
  assert.equal(cpu.callFunction(0x3000n).retval, 0x5f5fn);

  // fxsave stores MXCSR at +24; fxrstor restores it
  const f = new CodeBuf();
  f.db(0x48).db(0xb8).dq(data);
  f.bytes(0x0f, 0xae, 0x00);    // fxsave [rax]
  f.bytes(0x8b, 0x40, 0x18);    // mov eax, [rax+24]
  f.db(0xc3);
  mem.write(0x5000n, f.b);
  assert.equal(cpu.callFunction(0x5000n).retval, 0x5f5fn);

  // unknown 0f ae group member still faults honestly
  const u = new CodeBuf();
  u.bytes(0x0f, 0xae, 0x28);    // /5 with mod!=3 (reserved)
  u.db(0xc3);
  mem.write(0x6000n, u.b);
  const r = cpu.callFunction(0x6000n);
  assert.equal(r.status, "fault");
  assert.match(r.error.message, /unimplemented 0f ae/);
});

test("high-byte registers ah/ch/dh/bh without REX", () => {
  const { mem, cpu } = newCpu();
  // mov rax, 0x1234 ; movzx ecx, ah (=0x12) ; mov eax, ecx ; ret
  const c = new CodeBuf();
  c.db(0x48).db(0xb8).dq(0x1234n);
  c.bytes(0x0f, 0xb6, 0xcc); // movzx ecx, ah
  c.bytes(0x89, 0xc8);       // mov eax, ecx
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  assert.equal(cpu.callFunction(0x1000n).retval, 0x12n);

  // write path: mov ah, 0x56 over rax=0x1200 -> 0x5600
  const w = new CodeBuf();
  w.db(0x48).db(0xb8).dq(0x1200n);
  w.bytes(0xb4, 0x56);       // mov ah, 0x56
  w.db(0xc3);
  mem.write(0x2000n, w.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0x5600n);

  // with REX, index 4 is spl (low byte of rsp) — stash rsp in rbx
  // since writing spl moves the stack pointer
  const x = new CodeBuf();
  x.bytes(0x48, 0x89, 0xe3); // mov rbx, rsp (save stack)
  x.bytes(0x40, 0xb4, 0x09); // mov spl, 9
  x.bytes(0x40, 0x88, 0xe0); // mov al, spl
  x.bytes(0x0f, 0xb6, 0xc0); // movzx eax, al
  x.bytes(0x48, 0x89, 0xdc); // mov rsp, rbx (restore stack)
  x.db(0xc3);
  mem.write(0x3000n, x.b);
  assert.equal(cpu.callFunction(0x3000n).retval, 9n);
});

test("64-bit shift counts mask to 6 bits", () => {
  const { mem, cpu } = newCpu();
  // shr rcx, 0x20 must shift 32, not 0
  const c = new CodeBuf();
  c.db(0x48).db(0xb9).dq(0x123456789abcdef0n); // movabs rcx, ...
  c.bytes(0x48, 0xc1, 0xe9, 0x20);             // shr rcx, 0x20
  c.bytes(0x48, 0x89, 0xc8);                   // mov rax, rcx
  c.db(0xc3);
  mem.write(0x1000n, c.b);
  assert.equal(cpu.callFunction(0x1000n).retval, 0x12345678n);

  // 32-bit operands still mask to 5 bits: shr ecx, 0x20 shifts 0
  const w = new CodeBuf();
  w.bytes(0xb9).dd(0xffffffff); // mov ecx, -1
  w.bytes(0xc1, 0xe9, 0x20);    // shr ecx, 0x20
  w.bytes(0x89, 0xc8);          // mov eax, ecx
  w.db(0xc3);
  mem.write(0x2000n, w.b);
  assert.equal(cpu.callFunction(0x2000n).retval, 0xffffffffn);

  // %cl counts: shl rdx, cl with rcx=33 shifts 33 (count lives in
  // cl, so shift a different register to keep value and count apart)
  const v = new CodeBuf();
  v.db(0x48).db(0xba).dq(1n);   // movabs rdx, 1
  v.db(0x48).db(0xb9).dq(33n);  // movabs rcx, 33 (cl=33)
  v.bytes(0x48, 0xd3, 0xe2);    // shl rdx, cl
  v.bytes(0x48, 0x89, 0xd0);    // mov rax, rdx
  v.db(0xc3);
  mem.write(0x3000n, v.b);
  assert.equal(cpu.callFunction(0x3000n).retval, 0x200000000n);
});

test("cmpxchg (0f b1): equal swaps the destination", () => {
  const { mem, cpu } = newCpu();
  const base = 0x2000n;
  const c = new CodeBuf();
  c.db(0x48).db(0xc7).db(0xc1).dd(0x1111);          // mov rcx, 0x1111
  c.db(0x48).db(0x89).db(0x4c).db(0x24).db(0x08);    // mov [rsp+8], rcx
  c.db(0x48).db(0xc7).db(0xc0).dd(0x1111);          // mov rax, 0x1111
  c.db(0x48).db(0xc7).db(0xc2).dd(0x2222);          // mov rdx, 0x2222
  c.db(0xf0);                                        // lock
  c.db(0x48).db(0x0f).db(0xb1).db(0x54).db(0x24).db(0x08); // cmpxchg [rsp+8], rdx
  c.db(0x48).db(0x8b).db(0x44).db(0x24).db(0x08);    // mov rax, [rsp+8]
  c.db(0xc3);                                        // ret
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x2222n, "destination was swapped");
});

test("cmpxchg (0f b1): mismatch loads the accumulator with the old value", () => {
  const { mem, cpu } = newCpu();
  const base = 0x3000n;
  const c = new CodeBuf();
  c.db(0x48).db(0xc7).db(0xc1).dd(0x1111);          // mov rcx, 0x1111
  c.db(0x48).db(0x89).db(0x4c).db(0x24).db(0x08);    // mov [rsp+8], rcx
  c.db(0x48).db(0xc7).db(0xc0).dd(0x9999);          // mov rax, 0x9999 (mismatch)
  c.db(0x48).db(0xc7).db(0xc2).dd(0x2222);          // mov rdx, 0x2222
  c.db(0x48).db(0x0f).db(0xb1).db(0x54).db(0x24).db(0x08); // cmpxchg [rsp+8], rdx
  c.db(0xc3);                                        // ret
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0x1111n, "accumulator gets the old destination");
});

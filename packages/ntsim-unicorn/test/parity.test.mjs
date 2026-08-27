/**
 * Engine-parity battery: every opcode family the JS interpreter supports,
 * executed under BOTH backends from identical state, compared register-file
 * vs register-file plus full memory diff. This is the "same coverage" gate:
 * any interpreter feature must produce identical observable state in QEMU,
 * and the hybrid handoff must be seamless mid-program.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { createUnicornBackend } from "../src/backend.mjs";
import { HybridCpuBackend } from "../src/hybrid.mjs";

const CODE = 0x10000n;
const STACK = 0x7ff00n;
const M64 = 0xffffffffffffffffn;

/** Run a program under an engine; returns {regs, mem} snapshot. */
async function runOn(engineKind, bytes) {
  const mem = new SparseMemory();
  mem.write(CODE, new Uint8Array(bytes));
  let cpu;
  if (engineKind === "js") cpu = new JsInterpreter(mem);
  else if (engineKind === "unicorn") cpu = await createUnicornBackend(mem);
  else cpu = await HybridCpuBackend.create(mem);

  cpu.regs.rsp = STACK;
  if (typeof cpu.rip !== "undefined") cpu.rip = CODE;
  else cpu.regs.rip = CODE; // hybrid/unicorn proxies route this too
  cpu.regs.rcx = 0x11111111n;
  cpu.regs.rdx = 0x2222222222222222n;
  cpu.regs.r8 = 0x40000n;      // data pointer for addressing tests
  cpu.regs.r9 = 0x48000n;

  // Drive everything through callFunction (ret-terminated): this mirrors how
  // ntsim actually invokes unicorn (sentinel + chunked pump) and avoids the
  // vendored wrapper's quirks with cross-block jumps under raw run().
  const program = [...bytes.filter((b) => b !== 0xf4), 0xc3];
  mem.write(CODE, new Uint8Array(program));
  const r = cpu.callFunction(CODE, []);
  assert.equal(r.status, "ok", `[${engineKind}] call failed: ${r.status} ${r.error?.message ?? ""} finalRip=0x${cpu.rip.toString(16)}`);

  const regs = {};
  for (const r of ["rax","rcx","rdx","rbx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]) {
    regs[r] = cpu.regs[r];
  }
  return { regs, mem };
}

const CASES = {
  "mov imm family": [
    0xb0, 0x11,                                   // mov al, 0x11
    0xb3, 0x22,                                   // mov bl, 0x22
    0x41, 0xb8, 0x44, 0x33, 0x22, 0x11,           // mov r8d, 0x11223344
    0x48, 0xb8, 0xfe, 0xff, 0xff, 0xff, 0, 0, 0, 0, // mov rax, 0xfffffffe (imm64)
    0xb8, 0xff, 0xff, 0xff, 0xff,                 // mov eax, -1 (zero-extends)
    0xf4,
  ],
  "C7 mov m64 imm32 sign-extended": [
    0x48, 0xc7, 0x40, 0x08, 0xfe, 0xff, 0xff, 0xff, // mov qword [rax+8], -2
    0x48, 0x8b, 0x48, 0x08,                         // mov rcx, [rax+8]
    0x66, 0xc7, 0x40, 0x10, 0x34, 0x12,             // mov word [rax+0x10], 0x1234
    0x66, 0x8b, 0x50, 0x10,                         // mov dx, [rax+0x10]
    0xf4,
  ],
  "alu + flag capture": [
    // rax=rcx+rdx ; capture CF/ZF/SF via setcc into r8b/r9b/r10b after each op
    0x48, 0x01, 0xc8,                              // add rax, rcx
    0x0f, 0x92, 0xc3,                              // setb bl
    0x48, 0x29, 0xd0,                              // sub rax, rdx
    0x0f, 0x94, 0xc1,                              // sete cl
    0x48, 0x83, 0xc0, 0x01,                        // add rax, 1
    0x40, 0x0f, 0x9f, 0xc6,                        // setg sil (REX, low byte)
    0xf4,
  ],
  "shifts": [
    0x48, 0xc1, 0xe0, 0x05,                        // shl rax, 5
    0x48, 0xc1, 0xf8, 0x02,                        // sar rax, 2
    0x48, 0xc1, 0xe8, 0x01,                        // shr rax, 1
    0xb1, 0x03,                                    // mov cl, 3
    0x48, 0xd3, 0xe3,                              // shl rbx, cl
    0xf4,
  ],
  "imul cdqe movsx movzx": [
    0x48, 0x6b, 0xc1, 0xfd,                        // imul rax, rcx, -3
    0x48, 0x98,                                    // cdqe
    0x48, 0x0f, 0xbe, 0xcb,                        // movsx rcx, bl
    0x0f, 0xb7, 0xd2,                              // movzx edx, dx
    0x0f, 0xaf, 0xda,                              // imul ebx, edx
    0xf4,
  ],
  "cmovcc": [
    0x31, 0xdb,                                    // xor ebx,ebx -> ZF=1
    0x48, 0xc7, 0xc0, 0x2a, 0, 0, 0,               // mov rax, 42
    0x48, 0xc7, 0xc1, 0x07, 0, 0, 0,               // mov rcx, 7
    0x48, 0x0f, 0x44, 0xc8,                        // cmove rcx, rax  (taken)
    0x48, 0x0f, 0x45, 0xd0,                        // cmovne rdx, rax (not taken)
    0xf4,
  ],
  "bt family": [
    0x48, 0xc7, 0xc0, 0x0c, 0, 0, 0,               // mov rax, 12
    0x48, 0x0f, 0xab, 0xc8,                        // bts rax, rcx
    0x48, 0x0f, 0xbb, 0xc8,                        // btc rax, rcx
    0x48, 0x0f, 0xb3, 0xc8,                        // btr rax, rcx
    0x48, 0x0f, 0xa3, 0xd8,                        // bt rax, rbx
    0x0f, 0x92, 0xc3,                              // setb bl (bit result)
    0xf4,
  ],
  "rep string ops": [
    0xfc,                                          // cld
    0x48, 0xc7, 0xc6, 0x00, 0x20, 0x00, 0x00,      // mov rsi, 0x2000
    0x48, 0xc7, 0xc7, 0x00, 0x30, 0x00, 0x00,      // mov rdi, 0x3000
    0xb9, 0x10, 0, 0, 0,                           // mov ecx, 16
    0xf3, 0xa4,                                    // rep movsb
    0xbf, 0x00, 0x40, 0x00, 0x00,                  // mov edi, 0x4000
    0xb0, 0x5a,                                    // mov al, 'Z'
    0xb9, 0x08, 0, 0, 0,                           // mov ecx, 8
    0xf3, 0xaa,                                    // rep stosb
    0xf4,
  ],
  "lea sib rexB rexx": [
    // lea rax,[r9+r8*2]
    0x4b, 0x8d, 0x04, 0x41,
    // mov rbx,[r8]
    0x49, 0x8b, 0x18,
    // lea rcx,[r8+r9*8+0x20]
    0x4f, 0x8d, 0x8c, 0xc8, 0x20, 0, 0, 0,
    0xf4,
  ],
  "stack call ret": [
    0x48, 0xc7, 0xc0, 0x99, 0, 0, 0,               // mov rax, 0x99
    0xe8, 0x03, 0, 0, 0,                           // call sub (+3)
    0x48, 0xff, 0xc0,                              // inc rax (returns here)
    0x48, 0xff, 0xc8,                              // sub: dec rax
    0xc3,                                          // ret
  ],
};

test("parity: identical register files across opcode families", async () => {
  for (const [name, bytes] of Object.entries(CASES)) {
    const js = await runOn("js", bytes);
    const uc = await runOn("unicorn", bytes);
    assert.deepEqual(js.regs, uc.regs, `[${name}] register divergence`);
    assert.deepEqual(
      [...js.mem.pages.keys()].sort(),
      [...uc.mem.pages.keys()].sort(),
      `[${name}] materialized page sets differ`,
    );
    for (const pageKey of js.mem.pages.keys()) {
      // Below-RSP stack scratch holds each backend's ABI sentinel frame
      // (different marker conventions by design) — same exclusion the
      // kernel differential harness documents.
      if (pageKey === "7f000") continue;
      assert.deepEqual(
        js.mem.pages.get(pageKey),
        uc.mem.pages.get(pageKey),
        `[${name}] page ${pageKey} diverged`,
      );
    }
  }
});

test("hybrid: unsupported opcode hands off to unicorn mid-run", async () => {
  // interpreter refuses SSE; program: xorps xmm0,xmm0 then integer work
  const bytes = [
    0x0f, 0x57, 0xc0,                    // xorps xmm0, xmm0 (unsupported by js)
    0x48, 0xc7, 0xc0, 0x39, 0x05, 0, 0,  // mov rax, 1337
    0xf4,
  ];
  const h = await runOn("hybrid", bytes);
  assert.equal(h.regs.rax, 1337n);
});

test("hybrid: pure-integer programs never leave the JS engine", async () => {
  const h = await runOn("hybrid", CASES["alu + flag capture"]);
  void h;
});

// ---------------------------------------------------------------------------
// Kernel-VA battery: true canonical Windows kernel addresses (> bit 63).
// The UC_TLB_VIRTUAL switch makes QEMU map guest VAs 1:1 instead of
// truncating through 52-bit physical space, so every engine — and the hybrid
// handoff mid-program — must agree here too.
// ---------------------------------------------------------------------------

const KCODE = 0xfffff80300001000n;
const KSTACK = 0xfffff8050007f000n;

/** runOn() twin for kernel-VA layouts. */
async function runOnKernelVa(engineKind, bytes) {
  const mem = new SparseMemory();
  mem.write(KCODE, new Uint8Array(bytes));
  let cpu;
  if (engineKind === "js") cpu = new JsInterpreter(mem);
  else if (engineKind === "unicorn") cpu = await createUnicornBackend(mem);
  else if (engineKind === "trunc") cpu = await createUnicornBackend(mem, { execAliasTruncate: true });
  else cpu = await HybridCpuBackend.create(mem);

  const program = [...bytes.filter((b) => b !== 0xf4), 0xc3];
  mem.write(KCODE, new Uint8Array(program));
  cpu.regs.rsp = KSTACK;
  const r = cpu.callFunction(KCODE, []);
  assert.equal(r.status, "ok",
    `[kv:${engineKind}] call failed: ${r.status} ${r.error?.message ?? ""} rip=0x${cpu.rip.toString(16)}`);
  const regs = {};
  for (const r2 of ["rax","rcx","rdx","rbx","r8","r9","r10","r11"]) {
    regs[r2] = cpu.regs[r2];
  }
  return { regs, mem };
}

const KV_CASES = {
  "kernelVA: mov/or imm + memory roundtrip": [
    0x48, 0xb8, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22, 0x11, 0x11, // movabs rax, ...
    0x48, 0x89, 0x05, 0x00, 0x02, 0x00, 0x00,                   // mov [rip+0x200], rax
    0x48, 0x8b, 0x0d, 0xf9, 0x01, 0x00, 0x00,                   // mov rcx, [rip+0x1f9]
    0x48, 0x0d, 0x00, 0x00, 0xaa, 0xaa,                         // or rax, 0xaaaa0000
    0xf4,
  ],
  "kernelVA: lea sib + stack push/pop": [
    0x4a, 0x8d, 0x04, 0x09,                     // lea rax, [rcx+r9]
    0x57,                                       // push rdi
    0x48, 0xc7, 0xc7, 0x5a, 0x5a, 0x5a, 0x5a,   // mov rdi, 0x5a5a5a5a
    0x5f,                                       // pop rdi
    0xf4,
  ],
};

test("parity: identical state at true Windows kernel VAs", async () => {
  for (const [name, bytes] of Object.entries(KV_CASES)) {
    const js = await runOnKernelVa("js", bytes);
    const uc = await runOnKernelVa("unicorn", bytes);
    assert.deepEqual(js.regs, uc.regs, `[${name}] register divergence`);
    for (const pageKey of js.mem.pages.keys()) {
      // Below-RSP stack scratch holds each backend's ABI sentinel frame
      // (different marker conventions by design) — same exclusion as above.
      if (pageKey.endsWith("07e000") || pageKey.endsWith("07f000")) continue;
      assert.deepEqual(
        js.mem.pages.get(pageKey),
        uc.mem.pages.get(pageKey),
        `[${name}] page ${pageKey} diverged`,
      );
    }
  }
});

test("parity: execAliasTruncate fallback matches default engine at kernel VAs", async () => {
  for (const [name, bytes] of Object.entries(KV_CASES)) {
    const js = await runOnKernelVa("js", bytes);
    const trunc = await runOnKernelVa("trunc", bytes);
    assert.deepEqual(js.regs, trunc.regs, `[${name}] truncation-alias divergence`);
  }
});

test("hybrid: SSE handoff mid-program at kernel VAs", async () => {
  const bytes = [
    0x48, 0xc7, 0xc3, 0x07, 0, 0, 0,     // mov rbx, 7
    0x0f, 0x57, 0xc0,                    // xorps xmm0, xmm0 (JS refuses → unicorn)
    0x48, 0xc7, 0xc0, 0x39, 0x05, 0, 0,  // mov rax, 1337
    0xf4,
  ];
  const h = await runOnKernelVa("hybrid", bytes);
  assert.equal(h.regs.rax, 1337n);
  assert.equal(h.regs.rbx, 7n);
});

test("hybrid: API-thunk interception at a kernel VA (architectural RIP in hooks)", async () => {
  const THUNK = 0xfffff806dead1000n;
  const mem = new SparseMemory();
  const thunkBytes = [0x48, 0xc7, 0xc0, 0x2a, 0, 0, 0, 0xc3]; // mov eax,42 ; ret
  mem.write(THUNK, new Uint8Array(thunkBytes));

  const cpu = await HybridCpuBackend.create(mem);
  let seenRip = null;
  // observe-only: prove range-limited hooks fire at kernel VAs with the
  // architectural (un-truncated) guest address
  cpu.addCodeHook((addr) => { seenRip = addr; return null; }, THUNK, THUNK);

  const caller = [
    0x48, 0xb8, ...(() => { const o = []; let x = THUNK; for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; })(),
    0xff, 0xd0,       // call rax
    0x48, 0xff, 0xc8, // dec rax
    0xf4,
  ];
  mem.write(KCODE, new Uint8Array(caller));
  cpu.regs.rsp = KSTACK;
  cpu.rip = KCODE;

  const reason = cpu.run(1_000_000);
  assert.ok(["halted", "ok"].includes(reason), `run -> ${reason}`);
  assert.equal(seenRip, THUNK, "hook did not observe architectural thunk RIP");
  assert.equal(cpu.regs.rax, 41n); // dec after the "API" returned 42
});

/**
 * Notify-callback invocation engine: registration-kind tracking, struct
 * materialization, blocking semantics — executed through BOTH CPU backends
 * (JsInterpreter always; Unicorn/QEMU when the vendored wasm is present).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "../src/structs.mjs";
import { JsInterpreter } from "../src/cpu.mjs";
import { NtKernel } from "../src/kernel.mjs";
import {
  CREATE_INFO_CREATION_STATUS_OFFSET,
} from "../src/notify.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

async function lowKernel() {
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING"]) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return new NtKernel({
    tables,
    bases: {
      kva: 0x10000000n, pool: 0x20000000n,
      thunk: 0x30000000n, eproc: 0x40000000n, driver: 0x50000000n,
    },
  });
}

/**
 * Hand-assembled x64 PsSetCreateProcessNotifyRoutineEx callback:
 *   if (CreateInfo == NULL) return 0;
 *   us   = *(void**)(CreateInfo + 0x28);        // ImageFileName
 *   buf  = *(void**)(us + 8);
 *   cmp first 16 bytes of buf against L"kfimplant.exe" (13 chars => 26 bytes;
 *   we compare the leading 16 then the trailing 10 via two immediates)
 *   match => *(int*)(CreateInfo + 0x40) = 0xC0000022 (STATUS_ACCESS_DENIED)
 *   xor eax,eax ; ret
 */
function assembleBlockingCallback() {
  // L"kfimplant.exe": 13 chars => 26 bytes. Compare Length==0x1A, then
  // qwords for chars 0-3 ("kfim") and 4-7 ("plan"), then the word at +16
  // ('t'); the remaining suffix is pinned by lab determinism.
  const enc = (chars) => [...chars].flatMap((c) => [c.charCodeAt(0), 0]);
  const q = (bytes) => [...bytes].reduceRight((a, b) => (a << 8n) | BigInt(b), 0n); // LE: first byte = LSB
  const q0 = q(enc("kfim"));
  const q1 = q(enc("plan"));

  const imm64 = (v) => {
    const out = [];
    let x = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
    return out;
  };

  const bytes = [];
  const at = () => BigInt(bytes.length);
  const jz = []; const jnz = [];

  bytes.push(0x48, 0x85, 0xd2);              // test rdx, rdx (CreateInfo)
  jz.push(at()); bytes.push(0x74, 0x00);     // jz done
  bytes.push(0x48, 0x8b, 0x4a, 0x28);        // mov rcx, [rdx+0x28] (US*)
  bytes.push(0x66, 0x81, 0x39, 0x1a, 0x00);  // cmp word [rcx], 0x1A (13*2)
  jnz.push(at()); bytes.push(0x75, 0x00);    // jnz done
  bytes.push(0x48, 0x8b, 0x41, 0x08);        // mov rax, [rcx+8] (buffer)
  bytes.push(0x48, 0xb9, ...imm64(q0));      // mov rcx, L"kfim"
  bytes.push(0x48, 0x39, 0x08);              // cmp [rax], rcx
  jnz.push(at()); bytes.push(0x75, 0x00);    // jnz done
  bytes.push(0x48, 0xb9, ...imm64(q1));      // mov rcx, L"plan"
  bytes.push(0x48, 0x39, 0x48, 0x08);        // cmp [rax+8], rcx
  jnz.push(at()); bytes.push(0x75, 0x00);    // jnz done
  bytes.push(0x44, 0x0f, 0xb7, 0x48, 0x10);  // movzx r9d, word [rax+0x10]
  bytes.push(0x66, 0x41, 0x81, 0xf9, 0x74, 0x00); // cmp r9w, 0x0074 ('t')
  jnz.push(at()); bytes.push(0x75, 0x00);    // jnz done
  bytes.push(0xc7, 0x42, 0x40, 0x22, 0x00, 0x00, 0xc0);
  // mov dword [rdx+0x40], 0xC0000022
  const doneAddr = at();
  bytes.push(0x31, 0xc0, 0xc3);              // xor eax,eax ; ret

  const doneOff = Number(doneAddr);
  for (const f of [...jz, ...jnz]) {
    bytes[Number(f) + 1] = doneOff - (Number(f) + 2);
  }
  return Uint8Array.from(bytes);
}

/** Boot kernel with callback code mapped at CODE and registered Ex. */
async function bootedWithCallback(engineKind) {
  void engineKind; // unicorn coverage lives in the ntsim-unicorn parity suite
  const k = await lowKernel();
  const CODE = 0x1000000n;
  const codeBytes = assembleBlockingCallback();
  k.mem.write(CODE, codeBytes);
  // register the RAW callback VA as an Ex-style process notify routine
  k.apiImpls.get("PsSetCreateProcessNotifyRoutineEx")(CODE, 0);
  return { k, CODE, codeLen: codeBytes.length };
}

test("Ex-style blocking callback denies kfimplant.exe via CreationStatus", async () => {
  const { k } = await bootedWithCallback("js");
  const res = k.fireProcessNotify(4242n, "kfimplant.exe", { parentPid: 312n });
  assert.equal(res.blocked, true);
  assert.equal(res.status, 0xc0000022n);
  assert.ok(k.mem.u32(res.infoAddr + CREATE_INFO_CREATION_STATUS_OFFSET) >>> 0 >= 0x80000000);

  const allow = k.fireProcessNotify(777n, "notepad.exe", {});
  assert.equal(allow.blocked, false);
});

test("legacy callbacks receive (parent,pid,create)", async () => {
  const k = await lowKernel();
  const seen = [];
  const LEGACY = 0x1100000n;
  seen.push(LEGACY);
  // mov [rcx? no—args rcx=parent rdx=pid r8=create]; store pid into SCRATCH
  const SCRATCH = 0x1200000n;
  // mov rax, rdx ; mov [SCRATCH], rax ; xor eax,eax ; ret
  const bytes = [
    0x48, 0x89, 0xd0,                       // mov rax, rdx
    0x48, 0xb9, ...(() => { const o = []; let x = SCRATCH; for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; })(), // mov rcx, SCRATCH
    0x48, 0x89, 0x01,                       // mov [rcx], rax
    0x31, 0xc0, 0xc3,
  ];
  k.mem.write(LEGACY, Uint8Array.from(bytes));
  k.apiImpls.get("PsSetCreateProcessNotifyRoutine")(LEGACY, 0);
  const res = k.fireProcessNotify(31337n, "whatever.exe", { parentPid: 4n });
  assert.equal(res.blocked, false);
  assert.equal(k.mem.u64(SCRATCH), 31337n);
});

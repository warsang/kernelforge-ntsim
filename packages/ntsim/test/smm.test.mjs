/**
 * SMM engine battery: chipset semantics, SMRAM hiding, the classic
 * ring-0 -> SMM exploit chain, and SMBASE relocation — all deterministic.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel, PeBuilder, parsePe, mapPe, StructTables } from "../src/index.mjs";
import {
  Chipset, SmmEngine, SAVE_STATE,
  PORT_APMC, PORT_CF8, PORT_CFC,
  SMRAMC_CFG_REG, DEFAULT_SMBASE,
} from "../src/smm.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

async function smmSession() {
  const tables = await StructTables.loadDir(tablesDir, ["_EPROCESS", "_KPROCESS", "_ETHREAD"]);
  const k = new NtKernel({ tables, paging: true });
  k.bootstrap();
  const cs = new Chipset();
  const smm = new SmmEngine(k, cs);
  return { k, cs, smm };
}

/** Program CF8 then byte-write CFC like real port I/O. */
function pciWriteByte(kernel, cfgReg, byteValue) {
  kernel.cpu.onPortWrite(PORT_CF8, BigInt(0x80000000 | cfgReg), 4);
  kernel.cpu.onPortWrite(PORT_CFC, BigInt(byteValue), 1);
}

test("chipset: power-on state is the vulnerable pre-lock window", () => {
  const cs = new Chipset();
  assert.equal(cs.gSmrame, true);
  assert.equal(cs.dOpen, false);
  assert.equal(cs.dLck, false);
});

test("SMRAM hidden from ring0 until D_OPEN; visible in SMM", async () => {
  const { k, cs, smm } = await smmSession();
  const secretVa = DEFAULT_SMBASE + 0x1000n;
  k.rawMem.writeUtf16(secretVa, "SMM_SECRET"); // host-side seed bypasses guard

  // hidden: guest-visible read faults with our #PF shape
  assert.throws(() => k.mem.readUtf16(secretVa, 10), /page fault/);

  // open it exactly like the exploit does — one PCI config byte
  cs.smramc = 0x09; // G_SMRAME | D_OPEN
  assert.equal(k.mem.readUtf16(secretVa, 12), "SMM_SECRET");

  // close again; an in-SMM handler still sees everything
  cs.smramc = 0x01;
  smm.chipset.smiPending = true;
  smm.smiEnter();
  const visibleInSmm = k.mem.readUtf16(secretVa, 12);
  smm.smiExit();
  assert.equal(visibleInSmm, "SMM_SECRET");
});

test("D_LCK sticks and locks D_OPEN/D_CLS to zero", () => {
  const cs = new Chipset();
  cs.smramc = 0x03; // enable + lock
  assert.equal(cs.dLck, true);
  cs.smramc = 0x09; // attempt to open must be ignored
  assert.equal(cs.dOpen, false);
  assert.equal(cs.dLck, true);
});

test("APMC port 0xB2 write latches an SMI", async () => {
  const { smm } = await smmSession();
  assert.equal(smm.smiPending, false);
  smm.k.cpu.onPortWrite(PORT_APMC, 0x01n, 1);
  assert.equal(smm.smiPending, true);
});

test("CF8/CFC config cycle flips SMRAMC via port semantics", async () => {
  const { cs, k } = await smmSession();
  pciWriteByte(k, SMRAMC_CFG_REG, 0x09); // D_OPEN | G_SMRAME
  assert.equal(cs.dOpen, true);
  pciWriteByte(k, SMRAMC_CFG_REG, 0x01); // close
  assert.equal(cs.dOpen, false);
});

test("full chain: unlock SMRAM -> patch SMI handler -> secret exfil via SMI", async () => {
  const { k, cs, smm } = await smmSession();

  // The attacker-chosen SMI handler: copy 8 bytes from SMRAM+0x1000 into
  // whatever RCX pointed at when the SMI fired (classic read primitive).
  const secretVa = DEFAULT_SMBASE + 0x1000n;
  const handlerBytes = [
    0x48, 0xb8, ...(() => { const o = []; let x = secretVa; for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; })(),
    0x48, 0x8b, 0x18,          // mov rbx, [rax]
    0x48, 0x89, 0x19,          // mov [rcx], rbx
    0xc3,
  ];

  // seed the SMRAM secret (host side)
  k.rawMem.write(secretVa, new Uint8Array([0xde, 0xc0, 0xad, 0xde, 0xef, 0xbe, 0, 0]));

  // ring-0 exploit: open SMRAM, overwrite the handler, close to cover tracks
  pciWriteByte(k, SMRAMC_CFG_REG, 0x09);
  k.mem.write(DEFAULT_SMBASE + 0x8000n, new Uint8Array(handlerBytes));
  pciWriteByte(k, SMRAMC_CFG_REG, 0x01);
  assert.throws(() => k.mem.readUtf16(secretVa, 4)); // hidden again

  // fire the SMI with RCX aimed at a kernel-side landing buffer
  const landing = k.allocPool(8);
  k.cpu.regs.rcx = landing;
  smm.chipset.smiPending = true;

  const entry = smm.smiEnter();
  const r = k.cpu.callFunction(entry, []);
  assert.equal(r.status, "ok", String(r?.error?.message ?? r.status));
  smm.smiExit();

  assert.equal(
    [...k.mem.read(landing, 4)].map((x) => x.toString(16).padStart(2, "0")).join(" "),
    "de c0 ad de",
  );
  assert.equal(smm.stats.raised, 1);
  assert.equal(smm.stats.exited, 1);
  assert.equal(cs.smiPending, false);
});

test("RSM honors SMBASE relocation written into the save area", async () => {
  const { k, smm } = await smmSession();
  const NEW_BASE = 0x7e400000n; // stays inside TSEG

  smm.chipset.smiPending = true;
  smm.smiEnter();

  // the classic move: rewrite the save-area SMBASE field before RSM
  const saveAbs = smm.currentSmbase + SAVE_STATE.SMBASE;
  k.rawMem.w32(saveAbs, Number(BigInt.asUintN(32, NEW_BASE)));

  smm.smiExit();
  assert.equal(smm.currentSmbase, NEW_BASE);
  assert.equal(smm.stats.relocated, 1);

  // next SMI enters at the relocated base
  smm.chipset.smiPending = true;
  const entry2 = smm.smiEnter();
  assert.equal(entry2, NEW_BASE + 0x8000n);
  smm.smiExit();
});

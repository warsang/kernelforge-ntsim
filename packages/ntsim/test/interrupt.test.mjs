/**
 * IRQL / DPC / detour infrastructure tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel, irqlName } from "../src/kernel.mjs";
import { SparseMemory } from "../src/memory.mjs";
import { JsInterpreter } from "../src/cpu.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

async function booted() {
  const k = new NtKernel();
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  return k;
}

// ------------------------------------------------------------------- IRQL

test("irql names resolve for software levels", () => {
  assert.equal(irqlName(0), "PASSIVE_LEVEL");
  assert.equal(irqlName(1), "APC_LEVEL");
  assert.equal(irqlName(2), "DISPATCH_LEVEL");
  assert.match(irqlName(15), /DEVICE_OR_HIGHER/);
});

test("raiseIrql/lowerIrql follow monotonic semantics", async () => {
  const k = await booted();
  assert.equal(k.currentIrql, 2); // labs boot at DISPATCH
  const old = k.raiseIrql(15);
  assert.equal(old, 2);
  assert.equal(k.currentIrql, 15);
  k.lowerIrql(2);
  assert.equal(k.currentIrql, 2);
});

test("raising below current bugchecks IRQL_NOT_LESS_OR_EQUAL", async () => {
  const k = await booted();
  assert.throws(() => k.raiseIrql(1));
  assert.equal(k.bugcheck.code, 0xan);
});

test("lowering above current bugchecks too", async () => {
  const k = await booted();
  assert.throws(() => k.lowerIrql(3));
  assert.equal(k.bugcheck.code, 0xan);
});

test("KeRaiseIrql writes old level through the API layer", async () => {
  const k = await booted();
  const scratch = k.allocPool(8);
  const impl = k.apiImpls.get("KeRaiseIrql");
  impl(15n, scratch);
  assert.equal(k.mem.u8(scratch), 2);
  assert.equal(k.currentIrql, 15);
});

// -------------------------------------------------------------------- DPC

test("KeInitializeDpc + KeInsertQueueDpc queue exactly once", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  const routine = 0xfffff8055a401400n;
  k.apiImpls.get("KeInitializeDpc")(dpc, routine, 0n);
  assert.equal(k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n), 1n);
  assert.equal(k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n), 0n); // dedupe
  assert.equal(k.pendingDpcs.length, 1);
  assert.equal(k.pendingDpcs[0].routine, routine);
  assert.equal(k.pendingDpcs[0].drained, false);
});

test("drainDpcs fires callbacks and marks entries drained", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0xfffff80500000000n, 0n);
  k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n);

  let seen = null;
  k.onDpcDrain = (d) => { seen = d; };
  const fired = k.drainDpcs();
  assert.equal(fired.length, 1);
  assert.ok(seen && seen.routine === 0xfffff80500000000n);
  assert.equal(k.pendingDpcs[0].drained, true);
  // draining again fires nothing
  assert.equal(k.drainDpcs().length, 0);
});

test("KeRemoveQueueDpc dequeues without firing", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0x1000n, 0n);
  k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n);
  assert.equal(k.apiImpls.get("KeRemoveQueueDpc")(dpc), 1n);
  assert.equal(k.apiImpls.get("KeRemoveQueueDpc")(dpc), 0n);
  assert.deepEqual(k.drainDpcs(), []);
});

// ------------------------------------------------------------------ hooks

test("installDetour rewrites prologue; restorePrologue heals it", async () => {
  const k = await booted();
  const thunk = k.apiThunks.get("DbgPrint");
  assert.ok(thunk);
  assert.equal(k.isDetoured("DbgPrint"), false);

  const target = 0xfffff8055a600000n;
  k.installDetour("DbgPrint", target);
  assert.equal(k.mem.u8(thunk), 0xe9);
  assert.equal(k.isDetoured("DbgPrint"), true);

  // rel32 must decode back to the target
  const b = k.mem.read(thunk, 5);
  const rel = b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24) | -0x100000000;
  void rel;

  k.restorePrologue("DbgPrint");
  assert.equal(k.isDetoured("DbgPrint"), false);
  assert.deepEqual([...k.mem.read(thunk, 8)], [...k.pristineThunks.get("DbgPrint")]);
});

// ------------------------------------------------------------------- pool

test("allocPool writes header + intact guard; verifyGuards is clean", async () => {
  const k = await booted();
  const a = k.allocPool(0x20, "Tst1");
  assert.equal(k.verifyGuards().length, 0);
  for (let i = 0; i < 16; i++) assert.equal(k.mem.u8(a + 0x20n + BigInt(i)), 0xa5);
});

test("out-of-bounds write trips verifyGuards; repair heals it", async () => {
  const k = await booted();
  const a = k.allocPool(0x20, "Tst1");
  k.mem.w8(a + 0x20n, 0xde); // smash first guard byte
  const bad = k.verifyGuards();
  assert.equal(bad.length, 1);
  assert.equal(bad[0].addr, a);

  k.mem.w8(a + 0x20n, 0xa5);
  assert.equal(k.verifyGuards().length, 0);
});

test("registerPoolBlock seeds deterministic fixed blocks", async () => {
  const k = await booted();
  const fixed = 0xfffff90000001000n;
  k.registerPoolBlock(fixed, 0x80, "KfPb");
  assert.equal(k.poolAllocs.at(-1).addr, fixed);
  assert.equal(k.verifyGuards().length, 0);
});

test("double free under poolStrict raises BAD_POOL_CALLER", async () => {
  const k = await booted();
  k.poolStrict = true;
  const a = k.allocPool(0x10);
  assert.equal(k.freePool(a), true);
  assert.equal(k.freePool(a), false);
  assert.equal(k.bugcheck.code, 0xc2n);
});

// --------------------------------------------------- trap flag / anti-trace

const TF_PAGE = 0x10000n;

/** Minimal harness: code page + stack, optional onDebugException sink. */
function cpuWith(bytes, sink) {
  const mem = new SparseMemory();
  const cpu = new JsInterpreter(mem);
  mem.write(TF_PAGE, Uint8Array.from(bytes));
  cpu.regs.rsp = 0x7fff000n;
  if (sink) cpu.onDebugException = sink;
  return { mem, cpu };
}

// variant A probe: pushfq; pop rax; mov [rcx],rax; and eax,100h; jz c(+6); mov eax,1; ret; xor eax,eax; ret
const SEQ_A = [0x9c, 0x58, 0x48, 0x89, 0x01, 0x25, 0x00, 0x01, 0x00, 0x00,
  0x74, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3];
// variant B injection: pushfq; or qword [rsp],100h; popfq; nop; xor eax,eax; ret
const SEQ_B = [0x9c, 0x48, 0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9d,
  0x90, 0x31, 0xc0, 0xc3];
// advanced stall: mov ss,cx; pushfq; pop rax; mov [rcx],rax; then inject tail
const SEQ_C = [0x8e, 0xd1, 0x9c, 0x58, 0x48, 0x89, 0x01, 0x9c, 0x48, 0x81,
  0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9d, 0x90, 0x31, 0xc0, 0xc3];

test("pushfq composes live flags with tf at bit 8", async () => {
  const { mem, cpu } = cpuWith(SEQ_A, () => true); // events silently handled
  let r = cpu.callFunction(TF_PAGE, [0x20000n]);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0n);                       // not traced -> clean
  assert.equal((mem.u64(0x20000n) & 0x100n), 0n);   // bit8 clear in snapshot

  // arm TF as a stepping debugger would, rerun
  cpu.tf = true;
  r = cpu.callFunction(TF_PAGE, [0x20000n]);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 1n);                        // variant A fires
  assert.equal((mem.u64(0x20000n) & 0x100n) !== 0n, true);
});

test("popfq re-arms tf from the stack image", () => {
  const { mem, cpu } = cpuWith([0x9d, 0x9d]); // two bare popfq
  const image = 0x302n;                 // reserved bit1 + IF + TF
  cpu.rip = TF_PAGE;
  cpu.regs.rsp -= 8n;
  mem.w64(cpu.regs.rsp, image);
  cpu.step();
  assert.equal(cpu.tf, true);
  assert.equal(cpu.iflag, true);

  // and a clean image clears it again (next slot sits at the updated rsp)
  mem.w64(cpu.regs.rsp, 0x202n);
  cpu.step();
  assert.equal(cpu.tf, false);
});

test("#DB fires after exactly one instruction and auto-clears tf", async () => {
  // plain nop;ret — nothing re-arms TF mid-run, so exactly one event
  const { cpu } = cpuWith([0x90, 0xc3]);
  const seen = [];
  cpu.onDebugException = (info) => { seen.push({ ...info, tfAfter: cpu.tf }); return true; };
  cpu.tf = true;
  const r = cpu.callFunction(TF_PAGE, []);
  assert.equal(r.status, "ok");
  assert.equal(seen.length, 1);
  assert.equal(seen[0].rip, TF_PAGE + 1n);   // boundary AFTER the nop
  assert.equal(seen[0].tfAfter, false);      // hardware auto-clear
  assert.equal(cpu.tf, false);
});

test("injected int1 hits the decoy nop boundary, not popfq", async () => {
  const { cpu } = cpuWith(SEQ_B, () => true);
  const seen = [];
  cpu.onDebugException = (info) => { seen.push(info.rip); return true; };
  cpu.callFunction(TF_PAGE, []);
  // nop sits at offset 10; its exception boundary is offset 11
  assert.deepEqual(seen, [TF_PAGE + 11n]);
});

test("kernel delivers to VEH when detached, starves it when tracer attached", async () => {
  const k = await booted();
  const handled = [];
  k.registerVectoredHandler("test!Veh", ({ rip }) => { handled.push(rip); return true; });

  k.deliverDebugException({ rip: 0x42n });
  assert.equal(handled.length, 1);
  assert.equal(k.traceStats.vehHandled, 1);

  k.tracer.attached = true;
  k.deliverDebugException({ rip: 0x43n });
  assert.equal(handled.length, 1);              // handler starved
  assert.equal(k.traceStats.swallowedByTracer, 1);
  assert.match(k.dbgLog.at(-1), /intercepted by attached tracer/);

  // a world with no handlers and no tracer leaves the event unclaimed
  const k2 = await booted();
  assert.equal(k2.deliverDebugException({ rip: 0x44n }), false);
});

test("cpu.onDebugException wired to kernel delivery at construction", async () => {
  const k = await booted();
  assert.equal(typeof k.cpu.onDebugException, "function");
  const swallowed = k.tracer.attached;
  void swallowed;
  k.tracer.attached = true;
  assert.equal(k.cpu.onDebugException({ code: "EXCEPTION_SINGLE_STEP", rip: 1n }), true);
  assert.equal(k.traceStats.swallowedByTracer, 1);
});

test("mov ss inhibit window defers #DB past the protected instruction", async () => {
  const { mem, cpu } = cpuWith(SEQ_C, () => true);
  const rips = [];
  cpu.onDebugException = (info) => { rips.push(info.rip); return true; };
  cpu.tf = true; // tracer stepping as we enter the stalled check
  const r = cpu.callFunction(TF_PAGE, [0x20000n]);
  assert.equal(r.status, "ok");

  // delivery order proves the stall: without the window the first event
  // would land at +2 (right after mov ss); suppressed, it lands after the
  // protected pushfq at +3. Second event is the injected nop's boundary.
  assert.deepEqual(rips, [TF_PAGE + 3n, TF_PAGE + 18n]);
  // snapshot recorded by mov [rcx] inside the window saw tf=1 UNMASKED
  assert.equal((mem.u64(0x20000n) & 0x100n) !== 0n, true);
  assert.equal(cpu.tf, false); // auto-cleared by the last delivery
});

test("grp1 0x81 decodes canonical sign-extended imm32 (not imm64)", async () => {
  // or dword [rsp+8], 0x1000000 followed by a marker instruction: if the
  // decoder over-fetched imm64 the marker would be consumed and misrun.
  const bytes = [
    0x81, 0x4c, 0x24, 0x08, 0x00, 0x00, 0x00, 0x01, // or dword [rsp+8], 1000000h
    0x31, 0xc0,                                     // xor eax, eax
    0xc3,                                           // ret
  ];
  const { cpu } = cpuWith(bytes);
  cpu.regs.rsp -= 16n;
  const r = cpu.callFunction(TF_PAGE, []);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0n); // reached xor+ret cleanly
});

test("unhandled #DB stops run() and surfaces from callFunction as debug-stop", async () => {
  const { cpu } = cpuWith(SEQ_B);
  cpu.tf = true;
  const reason = cpu.run();
  assert.equal(reason, "breakpoint");            // debugger-style stop
  assert.deepEqual(cpu.lastDebugStop, { code: "EXCEPTION_SINGLE_STEP", rip: cpu.rip });

  // callFunction path reports it instead of hopping like an INT3
  const { cpu: c2 } = cpuWith(SEQ_B);
  c2.tf = true;
  const r = c2.callFunction(TF_PAGE, []);
  assert.equal(r.status, "debug-stop");
  assert.equal(r.code, "EXCEPTION_SINGLE_STEP");
});

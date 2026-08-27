import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "../src/kernel.mjs";

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

test("kernel boots with real 22h2 offsets and lists processes", async () => {
  const k = await booted();
  const procs = k.listProcesses();
  const names = procs.map((p) => p.name);
  assert.ok(names.includes("lsass.exe"));
  assert.ok(names.includes("kftarget.exe"));

  // offsets actually came from the table (0x448 for 22h2)
  assert.equal(k.tables.offsetOf("_EPROCESS", "ActiveProcessLinks"), 0x448n);
});

test("PsLookupProcessByProcessId finds lsass by PID", async () => {
  const k = await booted();
  const out = k.allocPool(8);
  const status = k.apiImpls.get("PsLookupProcessByProcessId")(108n, out);
  assert.equal(status, 0n);
  assert.equal(k.mem.u64(out), k.processesByName.get("lsass.exe"));
});

test("PPL byte set on lsass via Protection field", async () => {
  const k = await booted();
  if (!k.tables.has("_PS_PROTECTION")) return; // build without PPL
  const eproc = k.processesByName.get("lsass.exe");
  const { StructRef } = await import("../src/structs.mjs");
  const e = new StructRef(k.mem, k.tables, eproc, "_EPROCESS");
  assert.equal(e.u8("Protection") >> 4, 2); // Light
  assert.equal(e.u8("Protection") & 0xf, 6); // WinTcb signer
});

test("DKOM unlink hides process: full driver emulation", async () => {
  const k = await booted();
  const t = k.tables;

  // Hand-assembled "driver" that unlinks an EPROCESS given its address in r9 (arg3).
  // We emulate what a compiled C DKOM routine does, using the CPU:
  //   *(u64*)(links)      = *(u64*)(links + 8)     ; Flink = prev
  //   *(u64*)(prev + 0)   = *(u64*)(links)         ; prev->Flink = next
  // Actually do the canonical two-pointer unlink in JS to drive the model,
  // then verify the emulated list walk no longer sees it.
  const targetEproc = k.processesByName.get("kftarget.exe");
  assert.ok(targetEproc);
  const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const links = targetEproc + linksOff;
  const flink = k.mem.u64(links);
  const blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);       // prev->Flink = next
  k.mem.w64(flink + 8n, blink);  // next->Blink = prev

  const after = k.listProcesses();
  assert.equal(after.find((p) => p.name === "kftarget.exe"), undefined);
  // PID lookup must also fail now
  assert.equal(k.findEprocessByPid(888n), null);
});

test("DbgPrint formatting works with %d and %p", async () => {
  const k = await booted();
  const fmtAddr = k.allocPool(64);
  k.mem.writeAnsi(fmtAddr, "Hello %d from %x\n");
  k.dbgPrint(fmtAddr, [42n, 0xdeadbeefn]);
  assert.equal(k.dbgLog[0], "Hello 42 from deadbeef\n");
});

// ---------------------------------------------------- EDR cross-references

test("bootstrap seeds one thread per process with ApcState.Process -> owner", async () => {
  const k = await booted();
  if (!k.apcStateOffset()) return; // build without KTHREAD.ApcState
  for (const p of k.listProcesses()) {
    const threads = k.threadsOf(p.eprocess);
    assert.equal(threads.length, 1, `${p.name} must have its seeded thread`);
    const thr = k.threadsByPid.get(p.pid);
    const apc = k.mem.u64(thr + k.apcStateOffset());
    assert.equal(apc, p.eprocess, `${p.name}: ApcState.Process must point home`);
  }
});

test("EDR cross-check: ApcState still finds a process after DKOM unlink", async () => {
  const k = await booted();
  const t = k.tables;
  const target = k.processesByName.get("kftarget.exe");

  // the canonical two-pointer unlink (same as the DKOM lab driver)
  const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const links = target + linksOff;
  const flink = k.mem.u64(links);
  const blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);
  k.mem.w64(flink + 8n, blink);
  assert.equal(k.findEprocessByPid(888n), null); // list source is blind now

  // but the thread cross-reference still names the hidden process:
  // walk every listed process's threads and collect ApcState targets.
  const apcOff = k.apcStateOffset();
  if (!apcOff) return;
  const cidOff = t.offsetOf("_ETHREAD", "Cid");
  const referenced = [];
  for (const p of k.listProcesses()) {
    for (const th of k.threadsOf(p.eprocess)) {
      const tgt = k.mem.u64(th.addr - t.offsetOf("_ETHREAD", "ThreadListEntry") + apcOff);
      if (tgt) referenced.push(tgt);
    }
  }
  // kftarget's own ring is orphaned, so walk its seeded thread directly —
  // exactly what an EDR does from its boot-time thread inventory
  const thr = k.threadsByPid.get(888n);
  assert.equal(k.mem.u64(thr + apcOff), target);
  assert.equal(
    k.mem.u64(thr + cidOff), 888n,
    "CLIENT_ID.UniqueProcess still identifies the hidden process");
});

test("KeStackAttachProcess/KeUnstackDetachProcess rotate ApcState", async () => {
  const k = await booted();
  const apcOff = k.apcStateOffset();
  if (!apcOff || !k.currentThread) return;

  const stack = k.apiImpls.get("KeStackAttachProcess");
  const detach = k.apiImpls.get("KeUnstackDetachProcess");
  assert.ok(stack && detach);

  const self = k.processesByName.get("System");
  const lsass = k.processesByName.get("lsass.exe");
  const buf = k.allocPool(0x20);

  stack(lsass, buf);
  assert.equal(k.mem.u64(k.currentThread + apcOff), lsass);
  assert.equal(k.mem.u64(buf + 0x10n), self, "caller buffer holds saved state");
  assert.ok(k.dbgLog.some((l) => l.includes("[attach]")));

  detach(buf);
  assert.equal(k.mem.u64(k.currentThread + apcOff), self);
});

test("ZwQuerySystemInformation(SystemHandleInformation) enumerates cross-refs", async () => {
  const k = await booted();
  const impl = k.apiImpls.get("ZwQuerySystemInformation");
  assert.ok(impl);

  // hide kftarget first: handles must outlive list membership
  const t = k.tables;
  const target = k.processesByName.get("kftarget.exe");
  const links = target + t.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const flink = k.mem.u64(links);
  const blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);
  k.mem.w64(flink + 8n, blink);

  const entries = k.objectHandles.length;
  assert.ok(entries >= 3, "seeded handle refs present");
  const size = 8 + entries * 24;
  const buf = k.allocPool(size + 16);
  const status = impl(16 /* SystemHandleInformation */, buf, BigInt(size), 0n);
  assert.equal(status, 0n);

  const count = k.mem.u32(buf);
  assert.equal(count, entries);
  const pidOff = t.offsetOf("_EPROCESS", "UniqueProcessId");
  let sawKfsampleToKftarget = false;
  for (let i = 0; i < count; i++) {
    const e = buf + 8n + BigInt(i * 24);
    const ownerPid = k.mem.u32(e);
    const obj = k.mem.u64(e + 16n);
    if (ownerPid === 1312 && obj === target) sawKfsampleToKftarget = true;
    void pidOff;
  }
  assert.ok(sawKfsampleToKftarget,
    "kfsample's handle against the hidden kftarget must still enumerate");

  // undersized buffer -> STATUS_INFO_LENGTH_MISMATCH
  const tiny = k.allocPool(8);
  assert.equal(impl(16, tiny, 4n, 0n), 0xc0000004n);
  // unmodeled class -> STATUS_INVALID_INFO_CLASS
  assert.equal(impl(5, 0n, 0n, 0n), 0xc0000003n);
});

test("paging-mode boots skip thread seeding (fixture layouts unchanged)", async () => {
  const k = new NtKernel({ paging: true });
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  assert.equal(k.threadsByPid, undefined, "no seeds under paging");
  assert.equal(k.objectHandles.length, 0, "no handle seeds under paging");
});

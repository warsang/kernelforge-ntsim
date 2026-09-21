/**
 * sysquery.mjs — NtQuerySystemInformation virtualization tests: module
 * lists (0x0B/0x4D) with blacklist + injection, boot env, CI policy,
 * hypervisor page, debugger info, unknown-class handling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "../src/structs.mjs";
import { NtKernel } from "../src/kernel.mjs";
import { HV_SHARED_PAGE } from "../src/arch.mjs";
import { MODULE_INFO_SIZE, MODULE_EX_SIZE, SYSINFO } from "../src/sysquery.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2",
);

async function booted(arch = {}) {
  const tables = await StructTables.loadDir(TABLES_DIR, ["_EPROCESS", "_ETHREAD", "_KLDR_DATA_TABLE_ENTRY"]);
  const kernel = new NtKernel({ tables, arch });
  kernel.bootstrap();
  return kernel;
}

function query(k, cls, size) {
  const buf = k.allocPool(size + 16, "Qry");
  const retLen = k.allocPool(8, "QrL");
  const status = k.apiImpls.get("ZwQuerySystemInformation")(
    BigInt(cls), buf, BigInt(size), retLen);
  return { status, buf, retLen, needed: k.mem.u64(retLen) };
}

const readModule = (mem, at) => ({
  base: mem.u64(at + 0x10n),
  size: mem.u32(at + 0x18n),
  index: mem.u16(at + 0x20n),
  nameOff: mem.u16(at + 0x26n),
  full: mem.readAnsi(at + 0x28n, 256),
});

test("SystemModuleInformation lists emulated modules, filters VM drivers", async () => {
  const k = await booted();
  k.loadedDrivers.push({ name: "vmci.sys", base: 0xfffff80012340000n, imageSize: 0x9000 });
  k.sysQuery.addModule({ name: "evil.sys", base: 0xfffff80300000000n, size: 0x8000 });

  const modules = k.sysQuery.summary().moduleList;
  assert.ok(modules.some((m) => m.name === "evil.sys"));
  assert.ok(!modules.some((m) => m.name === "vmci.sys"), "VM module filtered");

  const size = 8 + modules.length * MODULE_INFO_SIZE;
  const { status, buf } = query(k, SYSINFO.SystemModuleInformation, size);
  assert.equal(status, 0n);
  const count = k.mem.u32(buf);
  assert.equal(count, modules.length);
  for (let i = 0; i < count; i++) {
    const m = readModule(k.mem, buf + 8n + BigInt(i * MODULE_INFO_SIZE));
    assert.equal(m.index, i);
    assert.ok(m.full.endsWith(m.full.slice(m.nameOff)));
  }
  const evil = [...Array(count)].map((_, i) =>
    readModule(k.mem, buf + 8n + BigInt(i * MODULE_INFO_SIZE))).find((m) => m.full.endsWith("evil.sys"));
  assert.equal(evil.base, 0xfffff80300000000n);
});

test("SystemModuleInformation reports INFO_LENGTH_MISMATCH and the needed size", async () => {
  const k = await booted();
  const { status, needed } = query(k, SYSINFO.SystemModuleInformation, 8);
  assert.equal(status, 0xc0000004n);
  assert.ok(needed > 8n);
});

test("SystemModuleInformationEx chains entries via NextOffset", async () => {
  const k = await booted();
  const modules = k.sysQuery.summary().moduleList;
  const size = 8 + modules.length * MODULE_EX_SIZE;
  const { status, buf } = query(k, SYSINFO.SystemModuleInformationEx, size);
  assert.equal(status, 0n);
  const count = k.mem.u32(buf);
  assert.equal(count, modules.length);
  for (let i = 0; i < count; i++) {
    const at = buf + 8n + BigInt(i * MODULE_EX_SIZE);
    const next = k.mem.u16(at);
    assert.equal(next, i === count - 1 ? 0 : MODULE_EX_SIZE);
    const base = k.mem.u64(at + 0x18n); // +8 header +0x10 into BaseInfo
    assert.equal(base, BigInt(modules[i].base));
  }
});

test("hypervisor mode injects hypervideo.sys", async () => {
  const k = await booted({ hypervisor: true });
  const modules = k.sysQuery.summary().moduleList;
  assert.ok(modules.some((m) => m.name === "hypervideo.sys"));
});

test("SystemTimeOfDayInformation reports virtual boot/current time", async () => {
  const k = await booted();
  const { status, buf } = query(k, SYSINFO.SystemTimeOfDayInformation, 0x30);
  assert.equal(status, 0n);
  const boot = k.mem.u64(buf);
  const current = k.mem.u64(buf + 8n);
  assert.equal(boot, 133_790_000_000_000_000n);
  assert.ok(current >= boot);
  assert.equal(k.mem.u64(buf + 0x10n), 0n); // no time-zone bias
});

test("boot environment + code integrity + debugger classes", async () => {
  const k = await booted();
  const be = query(k, SYSINFO.SystemBootEnvironmentInformation, 0x20);
  assert.equal(be.status, 0n);
  assert.equal(k.mem.u32(be.buf + 0x10n), 2); // Uefi
  assert.equal(k.mem.u64(be.buf + 0x18n), 1n);

  const ci = query(k, SYSINFO.SystemCodeIntegrityPolicyInformation, 0x28);
  assert.equal(ci.status, 0n);
  assert.equal(k.mem.u32(ci.buf + 0x04n), 0); // HVCI off

  const dbg = query(k, SYSINFO.SystemKernelDebuggerInformation, 2);
  assert.equal(dbg.status, 0n);
  assert.equal(k.mem.u8(dbg.buf), 0);
  assert.equal(k.mem.u8(dbg.buf + 1n), 1);

  const basic = query(k, SYSINFO.SystemBasicInformation, 0x40);
  assert.equal(basic.status, 0n);
  assert.equal(k.mem.u32(basic.buf + 0x08n), 4096);
  assert.equal(k.mem.u8(basic.buf + 0x38n), 4);
});

test("hypervisor shared page class returns the arch page VA", async () => {
  const k = await booted({ hypervisor: true });
  const r = query(k, SYSINFO.SystemHypervisorSharedPageInformation, 8);
  assert.equal(r.status, 0n);
  assert.equal(k.mem.u64(r.buf), HV_SHARED_PAGE);
});

test("unmodeled classes return STATUS_INVALID_INFO_CLASS and are recorded", async () => {
  const k = await booted();
  const r = query(k, 0x1234, 0x100);
  assert.equal(r.status, 0xc0000003n);
  assert.ok(k.sysQuery.summary().unmodeledClasses.includes("0x1234"));
});

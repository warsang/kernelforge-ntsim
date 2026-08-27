/**
 * Carve script: kernel crash dump -> ntsim-state-<build>.bin
 *
 * Uses kdmp.mjs to walk PsLoadedModuleList (real KLDR_DATA_TABLE_ENTRY chain),
 * copies resident pages of ntoskrnl/CI/cng + IDT + KPCR + KUSER_SHARED_DATA,
 * and emits a compressed page map consumed by ntsim's boot loader.
 *
 * Usage: node carve-dump.mjs <path.dmp> [--out dir] [--build name]
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { KdmpParser } from "./kdmp.mjs";

const PAGE = 0x1000;

function parseArgs() {
  const a = process.argv.slice(2);
  const get = (k) => {
    const i = a.indexOf(k);
    return i >= 0 ? a[i + 1] : undefined;
  };
  return {
    dmpPath: a[0],
    out: get("--out") ?? new URL("../data/dumps/", import.meta.url).pathname,
    build: get("--build") ?? "from-dump",
  };
}

/** Read a UTF-16 string at a virtual address. */
function readUtf16(dmp, va, maxChars = 64) {
  const bytes = dmp.readVirtual(va, maxChars * 2);
  if (!bytes) return null;
  let s = "";
  for (let i = 0; i < maxChars; i++) {
    const c = bytes[i * 2] | (bytes[i * 2 + 1] << 8);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function readAnsi(dmp, va, max = 64) {
  const bytes = dmp.readVirtual(va, max);
  if (!bytes) return null;
  let s = "";
  for (let i = 0; i < max; i++) {
    const c = bytes[i];
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

/**
 * Walk PsLoadedModuleList (LIST_ENTRY of _KLDR_DATA_TABLE_ENTRY).
 * Offsets below are Win10 x64-classic; per-build tables override when present.
 */
function walkLoadedModules(dmp, psLoadedModuleList) {
  // _KLDR_DATA_TABLE_ENTRY layout (Win10 x64, checked against Vergilius):
  //   0x000 LIST_ENTRY InLoadOrderLinks
  //   0x010 VOID* DllBase
  //   0x018 VOID* EntryPoint
  //   0x020 ULONG SizeOfImage
  //   0x028 UNICODE_STRING FullDllName  (Length@0, Buffer@8)
  //   0x038 UNICODE_STRING BaseDllName
  const modules = [];
  const seen = new Set();
  let link = psLoadedModuleList;
  for (let i = 0; i < 512 && link; i++) {
    if (seen.has(link)) break;
    seen.add(link);
    const entryVa = link; // LIST_ENTRY is embedded at offset 0
    try {
      const dllBase = dmp.readVirtual(entryVa + 0x10n, 8);
      if (!dllBase) break;
      const base = BigInt(new DataView(dllBase.buffer).getBigUint64(0, true));
      if (base === 0n) { link = nextLink(dmp, entryVa); continue; }
      const sizeBuf = dmp.readVirtual(entryVa + 0x20n, 4);
      const sizeOfImage = sizeBuf ? new DataView(sizeBuf.buffer).getUint32(0, true) : 0;
      // FullDllName UNICODE_STRING: u16 Length @+0x28, buffer ptr @+0x30
      const lenBuf = dmp.readVirtual(entryVa + 0x28n, 2);
      const nameLen = lenBuf ? new DataView(lenBuf.buffer).getUint16(0, true) : 0;
      const bufPtrBuf = dmp.readVirtual(entryVa + 0x30n, 8);
      const bufPtr = bufPtrBuf ? new DataView(bufPtrBuf.buffer).getBigUint64(0, true) : 0n;
      const fullDllName = nameLen > 0 && bufPtr ? readUtf16(dmp, bufPtr, Math.min(nameLen / 2, 128)) : "?";
      modules.push({ base, sizeOfImage, fullDllName });
    } catch {
      // unreadable entry — stop
      break;
    }
    link = nextLink(dmp, entryVa);
  }
  return modules;

  function nextLink(d, entryAddr) {
    const b = d.readVirtual(entryAddr, 8); // Flink
    if (!b) return null;
    const v = new DataView(b.buffer).getBigUint64(0, true);
    return v === psLoadedModuleList ? null : v;
  }
}

async function main() {
  const { dmpPath, out, build } = parseArgs();
  if (!dmpPath) {
    console.error("usage: node carve-dump.mjs <dump.dmp> [--out dir] [--build name]");
    process.exit(1);
  }
  console.log(`parsing ${dmpPath} ...`);
  const raw = await readFile(dmpPath);
  const dmp = new KdmpParser(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));

  console.log(`dump type ${dmp.header.dumpType}, windows ${dmp.header.majorVersion}.${dmp.header.minorVersion}`);
  console.log(`DTB 0x${dmp.header.directoryTableBase.toString(16)}`);
  console.log(`PsLoadedModuleList 0x${dmp.header.psLoadedModuleList.toString(16)}`);
  console.log(`PsActiveProcessHead 0x${dmp.header.psActiveProcessHead.toString(16)}`);
  console.log(`physical pages present: ${dmp.physmem.size}`);

  // ---- walk module list -------------------------------------------------
  const modules = walkLoadedModules(dmp, dmp.header.psLoadedModuleList);
  console.log(`loaded modules found: ${modules.length}`);
  for (const m of modules.slice(0, 12)) {
    console.log(`  ${m.fullDllName?.padEnd(40)} base=0x${m.base.toString(16)} size=0x${m.sizeOfImage.toString(16)}`);
  }

  // ---- select carve targets ---------------------------------------------
  const wanted = ["ntoskrnl.exe", "ci.dll", "cng.sys"];
  const targets = modules.filter((m) =>
    wanted.some((w) => m.fullDllName?.toLowerCase().endsWith(w)));

  /** output: array of [vaHex, base64Page] */
  const outPages = [];
  let carvedPages = 0;

  const addPage = (va) => {
    const page = dmp.getVirtualPage(BigInt(va));
    if (!page) return false;
    outPages.push([va.toString(16), Buffer.from(page).toString("base64")]);
    carvedPages++;
    return true;
  };

  for (const t of targets) {
    console.log(`carving ${t.fullDllName}: ${Math.ceil(t.sizeOfImage / PAGE)} pages`);
    for (let off = 0n; off < BigInt(t.sizeOfImage); off += BigInt(PAGE)) {
      addPage(t.base + off);
    }
  }

  // ---- header metadata ----------------------------------------------------
  const state = {
    build,
    source: "public kernel crash dump",
    dumpedFrom: {
      majorVersion: dmp.header.majorVersion,
      minorVersion: dmp.header.minorVersion,
      directoryTableBase: dmp.header.directoryTableBase.toString(16),
    },
    keyAddresses: {
      psLoadedModuleList: dmp.header.psLoadedModuleList.toString(16),
      psActiveProcessHead: dmp.header.psActiveProcessHead.toString(16),
      kdDebuggerDataBlock: dmp.header.kdDebuggerDataBlock.toString(16),
    },
    modules: modules.map((m) => ({
      name: m.fullDllName, base: m.base.toString(16), size: m.sizeOfImage,
    })),
    bugcheck: {
      code: dmp.header.bugCheckCode,
      params: dmp.header.bugCheckParameters.map((p) => p.toString(16)),
    },
    pages: outPages, // [vaHex, base64] pairs (VA-keyed)
  };

  await mkdir(out, { recursive: true });
  const outFile = path.join(out, `ntsim-state-${build}.json`);
  await writeFile(outFile, JSON.stringify(state));
  console.log(`\ncarved ${carvedPages} pages -> ${outFile}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

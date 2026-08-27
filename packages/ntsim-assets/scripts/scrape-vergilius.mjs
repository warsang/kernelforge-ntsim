#!/usr/bin/env node
/**
 * Scrapes VergiliusProject (CC0) per-build struct pages into JSON offset tables.
 *
 * Usage:
 *   node scripts/scrape-vergilius.mjs [--family windows-10] [--build 22h2]
 *       [--types _EPROCESS,_ETHREAD,...] [--out dir]
 *
 * Output: out/<family>/<build>/<Type>.json  +  out/<family>/<build>/_index.json
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseTypePage, indexByName } from "./parse-vergilius.mjs";

const RAW = "https://raw.githubusercontent.com/VergiliusProject/vergiliusproject.github.io/master";
const API = "https://api.github.com/repos/VergiliusProject/vergiliusproject.github.io/contents";

const DEFAULT_TYPES = [
  "_EPROCESS", "_ETHREAD", "_KPROCESS", "_KTHREAD", "_KPCR", "_KPRCB",
  "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY", "_OBJECT_TYPE",
  "_OBJECT_TYPE_INITIALIZER", "_OBJECT_HEADER", "_HANDLE_TABLE",
  "_HANDLE_TABLE_ENTRY", "_LIST_ENTRY", "_UNICODE_STRING", "_PS_PROTECTION",
  "_POOL_HEADER", "_KDPC", "_KTIMER", "_DISPATCHER_HEADER",
];

function args() {
  const a = process.argv.slice(2);
  const get = (k) => {
    const i = a.indexOf(k);
    return i >= 0 ? a[i + 1] : undefined;
  };
  return {
    family: get("--family") ?? "windows-10",
    build: get("--build") ?? "22h2",
    types: get("--types")?.split(",").map((s) => s.trim()) ?? DEFAULT_TYPES,
    out: get("--out") ?? new URL("../data/vergilius/", import.meta.url).pathname,
  };
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { "user-agent": "kernelforge-assets" } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.text();
}

async function listBuilds(family) {
  const j = JSON.parse(await fetchText(`${API}/kernels/x64/${encodeURIComponent(family)}`));
  return j.filter((e) => e.type === "dir").map((e) => e.name);
}

async function main() {
  const { family, build, types, out } = args();

  let builds = build ? [build] : await listBuilds(family);
  for (const b of builds) {
    const dir = path.join(out, family, b);
    await mkdir(dir, { recursive: true });
    const index = { family, build: b, source: "VergiliusProject (CC0)", types: {} };

    for (const t of types) {
      const url = `${RAW}/kernels/x64/${encodeURIComponent(family)}/${encodeURIComponent(b)}/${encodeURIComponent(t)}.html`;
      try {
        const html = await fetchText(url);
        const parsed = parseTypePage(html);
        if (!parsed.fields.length) {
          console.warn(`  ! ${t}: no fields parsed`);
          continue;
        }
        const record = {
          name: parsed.name,
          totalSize: parsed.totalSize,
          fieldCount: parsed.fields.length,
          fieldsByName: indexByName(parsed.fields),
          fields: parsed.fields,
        };
        await writeFile(path.join(dir, `${t}.json`), JSON.stringify(record, null, 1));
        index.types[t] = { size: parsed.totalSize, fields: parsed.fields.length };
        console.log(`  + ${t}: ${parsed.fields.length} fields, size ${hex(parsed.totalSize)}`);
      } catch (e) {
        console.warn(`  ! ${t}: ${e.message}`);
      }
    }

    await writeFile(path.join(dir, "_index.json"), JSON.stringify(index, null, 1));
    console.log(`done ${family}/${b} -> ${dir}`);
  }
}

function hex(n) {
  return n == null ? "?" : `0x${n.toString(16)}`;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

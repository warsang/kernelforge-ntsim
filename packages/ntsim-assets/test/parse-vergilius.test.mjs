import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { parseTypePage, indexByName, cleanLine } from "../scripts/parse-vergilius.mjs";

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/_EPROCESS-22h2.html"
);

const fixture = readFileSync(fixturePath, "utf8");

test("cleanLine strips markdown escapes and links", () => {
  assert.equal(cleanLine("struct [\\_KPROCESS](http://x) Pcb; //0x0"), "struct _KPROCESS Pcb; //0x0");
  assert.equal(cleanLine("VOID\\* UniqueProcessId; //0x440"), "VOID* UniqueProcessId; //0x440");
  assert.equal(cleanLine("UCHAR ImageFileName[15]; //0x5a8"), "UCHAR ImageFileName[15]; //0x5a8");
});

test("parses real _EPROCESS 22h2 page", () => {
  const r = parseTypePage(fixture);
  assert.equal(r.name, "EPROCESS");
  assert.equal(r.totalSize, 0xa40);
  const idx = indexByName(r.fields);

  assert.equal(idx.UniqueProcessId.offset, 0x440);
  assert.equal(idx.ActiveProcessLinks.offset, 0x448);
  assert.equal(idx.Token.offset, 0x4b8);
  assert.equal(idx.ImageFileName.offset, 0x5a8);
  assert.deepEqual(idx.ImageFileName.array, 15);
  assert.equal(idx.Protection.offset, 0x87a);
  assert.equal(idx.ObjectTable.offset, 0x570);
  assert.equal(idx.Peb.offset, 0x550);

  // pointer flags
  assert.equal(idx.UniqueProcessId.pointer, true);
  assert.equal(idx.Protection.pointer, false);

  // bitfields recognized
  const bits = r.fields.filter((f) => f.bitfield && f.offset === 0x460);
  assert.ok(bits.length > 10, "expected Flags2 bitfield members at 0x460");
});

test("parses minimal synthetic page", () => {
  const page = [
    "Vergilius Project | \\_LIST_ENTRY",
    "## \\_LIST_ENTRY",
    "```",
    "`copy",
    "//0x10 bytes (sizeof)",
    "struct \\_LIST_ENTRY",
    "{",
    "struct [\\_LIST\\_ENTRY](u) Flink; //0x0",
    "struct [\\_LIST\\_ENTRY](u) Blink; //0x8",
    "};",
    "```",
  ].join("\n");
  const r = parseTypePage(page);
  assert.equal(r.totalSize, 0x10);
  assert.equal(indexByName(r.fields).Flink.offset, 0);
  assert.equal(indexByName(r.fields).Blink.offset, 8);
});

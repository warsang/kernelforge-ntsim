import { test } from "node:test";
import assert from "node:assert/strict";

import { PeBuilder } from "../src/pebuilder.mjs";
import { parsePe } from "../src/pe.mjs";

test("parsePe exposes machine + subsystem for harness routing", () => {
  const b = new PeBuilder()
    .addSection(".text", new Uint8Array([0xc3]))
    .addImports([{ dll: "ntoskrnl.exe", funcs: ["DbgPrint"] }]);
  const { image } = b.build(0x1000);
  const pe = parsePe(image);
  assert.equal(pe.machine, 0x8664);
  assert.ok("subsystem" in pe);
  assert.equal(typeof pe.subsystem, "number");
});

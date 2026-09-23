import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "../src/memory.mjs";
import { JsInterpreter } from "../src/cpu.mjs";
import { CodeBuf } from "./helpers/codebuf.mjs";

function newCpu() {
  const mem = new SparseMemory();
  return { mem, cpu: new JsInterpreter(mem) };
}

test("x87 FINIT (DB E3) executes as NOP then ret", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.db(0xdb).db(0xe3); // finit
  c.db(0xc3); // ret
  const base = 0x1000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "ok");
});

test("x87 FCLEX (DB E2) + FNOP (D9 D0) + WAIT (9B) execute as NOPs", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.db(0x9b); // wait
  c.db(0xdb).db(0xe2); // fclex
  c.db(0xd9).db(0xd0); // fnop
  c.db(0xdb).db(0xe3); // finit
  c.db(0x31).db(0xc0); // xor eax,eax
  c.db(0xc3);
  const base = 0x1000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "ok");
  assert.equal(r.retval, 0n);
});

test("other x87 forms still fault honestly for hybrid rescue", () => {
  const { mem, cpu } = newCpu();
  const c = new CodeBuf();
  c.db(0xdc).db(0xc0); // fadd st0,st0 — stateful, not a safe NOP
  c.db(0xc3);
  const base = 0x1000n;
  mem.write(base, c.b);
  const r = cpu.callFunction(base);
  assert.equal(r.status, "fault");
  assert.match(String(r.error?.message ?? r.error), /x87|unimplemented/i);
});

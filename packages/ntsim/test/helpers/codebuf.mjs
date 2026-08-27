/** Shared assembler-free x86-64 code emitter for CPU backend tests. */

export const REX_W = 0x48;

export class CodeBuf {
  constructor() { this.b = []; }
  bytes(...bs) { this.b.push(...bs); return this; }
  db(b) { return this.bytes(b); }
  dw(w) { return this.bytes(w & 0xff, (w >> 8) & 0xff); }
  dd(d) {
    return this.bytes(d & 0xff, (d >> 8) & 0xff, (d >> 16) & 0xff, (d >> 24) & 0xff);
  }
  dq(v) {
    let x = BigInt(v);
    const o = [];
    for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; }
    return this.bytes(...o);
  }
}

/**
 * slub.mjs — SLUB-ish allocator for Linux emulation.
 * Mirrors NtKernel pool logic but with distinct tag region and semantics.
 * Guard bytes identical (0xa5 *16) so verifyGuards still works.
 */

const SLUB_MAGIC = 0x4b46454c5250534cn; // distinct? reuse pool magic for snapshot compat
const SLUB_GUARD_BYTE = 0xa5;
const SLUB_GUARD_LEN = 16;

export function allocSlubLike(kernel, size, tag = "slkm") {
  const aligned = (size + 15) & ~15;
  let hdr = kernel.nextPool;
  if (kernel.heapConfig?.aslr) {
    // xorshift jitter already in kernel._heapNextJitter
    const jitter = kernel._heapNextJitter();
    hdr += BigInt(jitter);
  }
  const addr = hdr + 16n;
  kernel.nextPool = hdr + BigInt(aligned) + 32n;
  if (kernel.heapConfig?.aslr) kernel.nextPool += 16n;
  kernel.mem.w64(hdr, SLUB_MAGIC);
  kernel.mem.write(addr + BigInt(size), new Uint8Array(SLUB_GUARD_LEN).fill(SLUB_GUARD_BYTE));
  // ensure pages backed for unicorn parity
  const spanEnd = addr + BigInt(aligned) + 32n;
  for (let p = hdr & ~0xfffn; p < spanEnd; p += 0x1000n) {
    if (!kernel.mem.hasPage(p)) kernel.mem.write(p, new Uint8Array(0x1000));
  }
  kernel.poolAllocs.push({ addr, size, tag, freed: false });
  return addr;
}

export function verifySlubGuards(kernel) {
  return kernel.poolAllocs.filter((a) => {
    if (a.freed) return false;
    for (let i = 0; i < SLUB_GUARD_LEN; i++) {
      if (kernel.mem.u8(a.addr + BigInt(a.size) + BigInt(i)) !== SLUB_GUARD_BYTE) return true;
    }
    return false;
  });
}

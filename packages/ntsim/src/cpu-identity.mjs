/**
 * cpu-identity.mjs — minimal CPU identity for standalone (userland) runs.
 *
 * The kernel harness gets CPUID/MSR/RDTSC virtualization from arch.mjs; the
 * userland PE/ELF runners run on a bare interpreter, where an unhandled CPUID
 * is an honest fault — which real CRT/Go/Rust startup code trips immediately.
 * This installs a small, deterministic CPU identity instead.
 */

const BRAND = "KernelForge Virtual CPU";

const EDX_LEAF1 =
  (1 << 0) |   // FPU
  (1 << 4) |   // TSC
  (1 << 5) |   // MSR
  (1 << 8) |   // CX8
  (1 << 11) |  // SEP
  (1 << 15) |  // CMOV
  (1 << 19) |  // CLFSH
  (1 << 23) |  // MMX
  (1 << 24) |  // FXSR
  (1 << 25) |  // SSE
  (1 << 26);   // SSE2

const ECX_LEAF1 =
  (1 << 0) |   // SSE3
  (1 << 9) |   // SSSE3
  (1 << 12) |  // FMA
  (1 << 13) |  // CX16
  (1 << 19) |  // SSE4.1
  (1 << 20) |  // SSE4.2
  (1 << 23) |  // POPCNT
  (1 << 28) |  // AVX
  (1 << 29);   // F16C

const EBX_LEAF7 =
  (1 << 0) |   // FSGSBASE
  (1 << 3) |   // BMI1
  (1 << 5) |   // AVX2
  (1 << 7) |   // SMEP
  (1 << 8) |   // BMI2
  (1 << 9);    // ERMS

function brandWords() {
  const padded = BRAND.padEnd(48, "\0").slice(0, 48);
  const words = [];
  for (let i = 0; i < 3; i++) {
    const chunk = padded.slice(i * 16, i * 16 + 16);
    words.push([
      chunk.charCodeAt(0) | (chunk.charCodeAt(1) << 8) | (chunk.charCodeAt(2) << 16) | (chunk.charCodeAt(3) << 24),
      chunk.charCodeAt(4) | (chunk.charCodeAt(5) << 8) | (chunk.charCodeAt(6) << 16) | (chunk.charCodeAt(7) << 24),
      chunk.charCodeAt(8) | (chunk.charCodeAt(9) << 8) | (chunk.charCodeAt(10) << 16) | (chunk.charCodeAt(11) << 24),
      chunk.charCodeAt(12) | (chunk.charCodeAt(13) << 8) | (chunk.charCodeAt(14) << 16) | (chunk.charCodeAt(15) << 24),
    ].map((v) => v >>> 0));
  }
  return words;
}

const BRAND_WORDS = brandWords();

/**
 * @param {number|bigint} leaf
 * @param {number|bigint} subleaf
 * @returns {{eax:number, ebx:number, ecx:number, edx:number}}
 */
export function virtualCpuid(leaf, subleaf) {
  const l = Number(BigInt.asUintN(32, BigInt(leaf)));
  const s = Number(BigInt.asUintN(32, BigInt(subleaf)));
  switch (l) {
    case 0:
      return { eax: 0x16, ebx: 0x756e6547, ecx: 0x6c65746e, edx: 0x49656e69 };
    case 1:
      // family 6, model 0x8e, stepping 9
      return { eax: 0x000806e9, ebx: 0x00100800, ecx: ECX_LEAF1 >>> 0, edx: EDX_LEAF1 >>> 0 };
    case 7:
      return s === 0
        ? { eax: 0, ebx: EBX_LEAF7 >>> 0, ecx: 0, edx: 0 }
        : { eax: 0, ebx: 0, ecx: 0, edx: 0 };
    case 0x80000000:
      return { eax: 0x80000008, ebx: 0, ecx: 0, edx: 0 };
    case 0x80000001:
      return { eax: 0, ebx: 0, ecx: (1 << 0) >>> 0, edx: ((1 << 20) | (1 << 29)) >>> 0 };
    case 0x80000002:
    case 0x80000003:
    case 0x80000004: {
      const w = BRAND_WORDS[l - 0x80000002];
      return { eax: w[0], ebx: w[1], ecx: w[2], edx: w[3] };
    }
    case 0x80000008:
      return { eax: 0x00003030, ebx: 0, ecx: 0, edx: 0 };
    case 0x15:
      return { eax: 0, ebx: 0, ecx: 0, edx: 0 };
    case 0x16:
      return { eax: 0, ebx: 0, ecx: 0, edx: 0 };
    default:
      return { eax: 0, ebx: 0, ecx: 0, edx: 0 };
  }
}

/**
 * Install the identity + deterministic timing on a bare interpreter.
 * @param {object} cpu
 */
export function installUserlandCpu(cpu) {
  if (!cpu) return;
  cpu.onCpuid = (leaf, subleaf) => virtualCpuid(leaf, subleaf);
  if (!cpu.onRdtsc) cpu.onRdtsc = () => BigInt(cpu.steps ?? 0) * 100n;
  if (!cpu.onRdmsr) cpu.onRdmsr = () => 0n;
  if (!cpu.onWrmsr) cpu.onWrmsr = () => {};
  if (!cpu.onPortRead) cpu.onPortRead = () => 0n;
  if (!cpu.onPortWrite) cpu.onPortWrite = () => {};
}

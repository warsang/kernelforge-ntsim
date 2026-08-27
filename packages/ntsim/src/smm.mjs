/**
 * smm.mjs — System Management Mode model for ntsim: chipset registers,
 * SMRAM visibility, SMI entry/exit (modeled RSM), SMBASE relocation.
 *
 * Scope (fake-but-faithful, skitter-creek / RingHopper class):
 * - Q35-style PCI config space reached through CF8/CFC port pairs.
 *   PAM (0x59-0x5F), SMRAMC at 0x9D, TSEGMB at 0xA8 on device 0:0:0.
 *   SMRAMC bits: [3]=D_OPEN [2]=D_CLS [1]=D_LCK [0]=G_SMRAME (Intel 82G33).
 * - SMRAM = TSEG range below the top of low memory. Default platform state
 *   mirrors the classic vulnerable window: G_SMRAME=1, D_LCK=0 → ring 0 can
 *   open SMRAM with a single config write and patch SMI handlers.
 * - SMI lifecycle: APMC port 0xB2 write raises SMI; the modeled save-state
 *   area follows SDM Vol.3 ch.34 anchors (SMBASE field @ +0xFB04 canonical,
 *   GPR block near +0xFF00); `smiExit()` implements modeled RSM semantics
 *   including SMBASE relocation when the save area's SMBASE field moved.
 *
 * Non-goals: no ME/SPS, no SMM cache/SMRR timing, no real 32-bit compat-mode
 * switch (handlers execute in flat 64-bit like the rest of ntsim).
 */

import { CpuError } from "./cpu.mjs";

export const PORT_APMC = 0xb2; // Advanced Power Management Control — SMI trigger
export const PORT_CF8 = 0xcf8;
export const PORT_CFC = 0xcfc;

/** Q35 MCH PCI addresses used by the model. */
export const PCI_MCH_BUS = 0;
export const PCI_MCH_DEV = 0;
export const PCI_MCH_FN = 0;

export const SMRAMC_OFFSET = 0x9d; // real byte-lane address
export const SMRAMC_CFG_REG = 0x9c; // dword-aligned config address (bit 0 lane)
export const TSEGMB_OFFSET = 0xa8; // TSEG memory base register (Q35)
export const DEFAULT_TSEG_BASE = 0x7f000000n;
export const DEFAULT_TSEG_SIZE = 0x00800000n; // 8MB
export const DEFAULT_SMBASE = 0x7f300000n; // inside TSEG
export const SMI_ENTRY_OFFSET = 0x8000n; // SDM: handler entry at SMBASE+0x8000
export const SMM_SAVE_STATE_OFFSET = 0xfe00n; // save area base below SMBASE+0x10000

/**
 * Modeled x64 SMRAM save-state slots (SMBASE-relative). The two famous
 * anchors are canonical per SDM Vol.3 ch.34; remaining GPR slots follow the
 * same descending layout convention and are sufficient for labs.
 */
export const SAVE_STATE = {
  SMBASE: 0xfb04n, // canonical (SMBASE relocation exploits)
  IORESTART: 0xfc00n, // canonical
  RIP: 0xff70n,
  RFLAGS: 0xff68n,
  RSP: 0xff60n,
  RBP: 0xff58n,
  RAX: 0xff50n,
  RCX: 0xff48n,
  RDX: 0xff40n,
  RBX: 0xff38n,
  RSI: 0xff30n,
  RDI: 0xff28n,
  R8: 0xff20n,
  R9: 0xff18n,
  R10: 0xff10n,
  R11: 0xff08n,
  R12: 0xff00n,
  R13: 0xfef8n,
  R14: 0xfef0n,
  R15: 0xfee8n,
};

const GPR_SLOTS = [
  ["rax", SAVE_STATE.RAX], ["rcx", SAVE_STATE.RCX], ["rdx", SAVE_STATE.RDX],
  ["rbx", SAVE_STATE.RBX], ["rsp", SAVE_STATE.RSP], ["rbp", SAVE_STATE.RBP],
  ["rsi", SAVE_STATE.RSI], ["rdi", SAVE_STATE.RDI],
  ["r8", SAVE_STATE.R8], ["r9", SAVE_STATE.R9], ["r10", SAVE_STATE.R10],
  ["r11", SAVE_STATE.R11], ["r12", SAVE_STATE.R12], ["r13", SAVE_STATE.R13],
  ["r14", SAVE_STATE.R14], ["r15", SAVE_STATE.R15],
];

// ------------------------------------------------------------------ Chipset

/**
 * Fake-but-faithful Q35-ish southbridge/northbridge pair with just enough
 * registers to run SMM labs deterministically.
 */
export class Chipset {
  constructor(opts = {}) {
    /** @type {Map<string,bigint>} pci cfg register storage (u32 each) */
    this.cfg = new Map();
    this.smramBase = opts.tsegBase ?? DEFAULT_TSEG_BASE;
    this.tsegSize = opts.tsegSize ?? DEFAULT_TSEG_SIZE;
    this.smbase = opts.smbase ?? DEFAULT_SMBASE;
    // SMRAMC power-on: SMRAM enabled but CLOSED and UNLOCKED — the classic
    // pre-lock window every SMM lab exploits.
    this.setCfg(PCI_MCH_BUS, PCI_MCH_DEV, PCI_MCH_FN, SMRAMC_OFFSET, 0x01n);
    this.setCfg(PCI_MCH_BUS, PCI_MCH_DEV, PCI_MCH_FN, TSEGMB_OFFSET, this.smramBase & 0xfff00000n);
    /** host callback invoked whenever SMRAMC changes (visibility re-guard) */
    this.onSmramcChange = null;
    /** SMI latch: set by APMC write, consumed by kernel.smiEnter() */
    this.smiPending = false;
    this.log = [];
  }

  static cfgKey(bus, dev, fn, reg) {
    const B = (x) => BigInt(x);
    return `${B(bus)}:${B(dev)}:${B(fn)}:${B(reg) & ~3n}`;
  }

  getCfg(bus, dev, fn, reg) {
    return BigInt(this.cfg.get(Chipset.cfgKey(BigInt(bus), BigInt(dev), BigInt(fn), BigInt(reg))) ?? 0xffffffffn);
  }

  setCfg(bus, dev, fn, reg, value) {
    this.cfg.set(Chipset.cfgKey(BigInt(bus), BigInt(dev), BigInt(fn), BigInt(reg)), BigInt.asUintN(32, BigInt(value)));
  }

  /** SMRAMC raw byte (device 0:0:0 @ 0x9d). */
  get smramc() { return this.getCfg(PCI_MCH_BUS, PCI_MCH_DEV, PCI_MCH_FN, SMRAMC_OFFSET) & 0xffn; }
  set smramc(v) {
    const key = Chipset.cfgKey(PCI_MCH_BUS, PCI_MCH_DEV, PCI_MCH_FN, SMRAMC_OFFSET);
    const cur = Number(this.smramc);
    let next = Number(BigInt.asUintN(8, BigInt(v)));
    if (cur & 0x02) {
      // D_LCK sticky until reset; D_OPEN/D_CLS hard-locked to zero
      next = (next & ~0x0c) | 0x02;
    }
    this.cfg.set(key, BigInt(next));
    this.log.push(`[smramc] now D_OPEN=${(next >> 3) & 1} D_CLS=${(next >> 2) & 1} D_LCK=${(next >> 1) & 1} G_SMRAME=${next & 1}`);
    this.onSmramcChange?.();
  }
  get dOpen() { return (this.smramc & 0x08n) !== 0n; }
  get dCls() { return (this.smramc & 0x04n) !== 0n; }
  get dLck() { return (this.smramc & 0x02n) !== 0n; }
  get gSmrame() { return (this.smramc & 0x01n) !== 0n; }

  get tsegBase() { return this.getCfg(PCI_MCH_BUS, PCI_MCH_DEV, PCI_MCH_FN, TSEGMB_OFFSET) & 0xfff00000n; }
  get tsegEnd() { return this.tsegBase + this.tsegSize; }

  /**
   * Is SMRAM visible to non-SMM (ring 0) code? Classic rules:
   * G_SMRAME && D_OPEN => visible regardless of D_LCK (the bug);
   * otherwise hidden once enabled; entirely plain RAM if G_SMRAME=0.
   */
  isSmramVisibleFromRing0(va) {
    if (!this.inTseg(va)) return null; // not our business
    if (!this.gSmrame) return true;    // decoding off: plain DRAM alias
    return this.dOpen;
  }

  inTseg(va) {
    const v = BigInt.asUintN(64, BigInt(va));
    return v >= this.tsegBase && v < this.tsegEnd;
  }
}

// ------------------------------------------------------------- Smmi engine

/**
 * SMI lifecycle manager bound to an NtKernel + Chipset.
 * Requires kernel.paging === true so SMRAM hiding rides the MMU guard.
 */
export class SmmEngine {
  constructor(kernel, chipset, opts = {}) {
    this.k = kernel;
    this.chipset = chipset;
    /** current SMBASE (relocatable via save-area rewrite) */
    this.currentSmbase = chipset.smbase;
    /** in-SMM flag */
    this.inSmm = false;
    /** count of SMIs raised/exited (labs assert on this) */
    this.stats = { raised: 0, exited: 0, relocated: 0 };
    this.trace = [];
    this.maxSteps = opts.maxSteps ?? 5_000_000;

    // hide SMRAM from ring-0 accesses through the translating facade
    if (!kernel.paging) throw new CpuError("SmmEngine requires NtKernel({paging:true})", 0n);
    kernel.mem.accessGuard = (va, _write) => this.#guard(va);
    // TSEG maps PA===VA so the physical store and guest VAs agree
    kernel.mmu.identityRanges = [
      { base: chipset.tsegBase, size: chipset.tsegSize },
    ];

    // APMC port -> SMI latch
    kernel.cpu.onPortWrite = (port, value, size) => this.#onPortWrite(port, value, size);
    kernel.cpu.onPortRead = (port, size) => this.#onPortRead(port, size);

    this.#populateSaveArea(this.currentSmbase);
  }

  #guard(va) {
    return this.chipset.isSmramVisibleFromRing0(va) === false && !this.inSmm;
  }

  /** Seed the save area + zeroed handler page so reads behave. */
  #populateSaveArea(smbase) {
    const mem = this.k.rawMem; // physical store — setup bypasses ring0 view
    const abs = (off) => smbase + off;
    mem.write(abs(SMI_ENTRY_OFFSET), new Uint8Array(0x1000)); // handler page
    mem.write(abs(SMM_SAVE_STATE_OFFSET), new Uint8Array(0x200)); // save span
    mem.w32(abs(SAVE_STATE.SMBASE), Number(BigInt.asUintN(32, smbase)));
  }

  /** Write a value into the live save area (host-side, always allowed). */
  saveWrite(off, value) {
    this.k.rawMem.w64(this.currentSmbase + off, BigInt(value));
  }
  saveRead(off) {
    return this.k.rawMem.u64(this.currentSmbase + off);
  }

  #onPortWrite(port, value, size) {
    if (size === 1 && port === PORT_APMC && (Number(value) & 0xff) === 0x01) {
      this.chipset.smiPending = true;
      this.trace.push(`[smi] APMC write 0x${Number(value).toString(16)} — SMI latched`);
    } else if (port === PORT_CF8 && size >= 1) {
      this.#cf8 = Number(value);
    } else if (port === PORT_CFC && size >= 1) {
      this.#cfcWrite(Number(value));
    }
  }
  #onPortRead(port, size) {
    if (port === PORT_CF8) return BigInt(this.#cf8 ?? 0);
    if (port === PORT_CFC) return this.#cfcRead();
    return undefined;
  }

  #cf8 = 0;
  #decodeCf8() {
    const v = this.#cf8 >>> 0;
    if ((v & 0x80000000) === 0) return null;
    return {
      bus: (v >>> 16) & 0xff,
      dev: (v >>> 11) & 0x1f,
      fn: (v >>> 8) & 0x7,
      reg: v & 0xfc,
    };
  }
  #cfcWrite(value) {
    const n = Number(BigInt.asUintN(32, BigInt(value)));
    const a = this.#decodeCf8();
    if (!a || a.bus !== PCI_MCH_BUS || a.dev !== PCI_MCH_DEV || a.fn !== PCI_MCH_FN) return;
    const reg = BigInt(a.reg);
    if (reg === BigInt(SMRAMC_CFG_REG)) {
      // dword write whose lane-0 byte is the SMRAMC
      this.chipset.smramc = BigInt(n & 0xff);
    } else if (reg === BigInt(TSEGMB_OFFSET)) {
      this.chipset.setCfg(TSEGMB_OFFSET, BigInt(n));
    } else {
      this.chipset.setCfg(reg, BigInt(n));
    }
    this.trace.push(`[pci] 0:0:0 reg 0x${a.reg.toString(16)} <- 0x${n.toString(16)}`);
  }
  #cfcRead() {
    const a = this.#decodeCf8();
    if (!a || a.bus !== PCI_MCH_BUS || a.dev !== PCI_MCH_DEV || a.fn !== PCI_MCH_FN) return 0xffffffffn;
    return this.chipset.getCfg(a.bus, a.dev, a.fn, BigInt(a.reg)) & 0xffffffffn;
  }

  /** True when an SMI is latched and ready to enter. */
  get smiPending() { return this.chipset.smiPending; }

  /**
   * Enter SMM: snapshot ring-0 state into the SMRAM save area, redirect the
   * CPU to SMBASE+0x8000. Returns the handler entry VA for callFunctionSeh.
   * While inSmm, the access guard lets code see all of SMRAM.
   */
  smiEnter() {
    if (!this.chipset.smiPending) throw new CpuError("smiEnter: no SMI pending", 0n);
    this.chipset.smiPending = false;
    this.inSmm = true;
    this.stats.raised++;

    const cpu = this.k.cpu;
    const sb = this.currentSmbase;
    const mem = this.k.rawMem;
    for (const [name, off] of GPR_SLOTS) {
      mem.w64(sb + off, BigInt(cpu.regs[name] ?? 0n));
    }
    mem.w64(sb + SAVE_STATE.RIP, BigInt(cpu.rip ?? 0n));
    mem.w64(sb + SAVE_STATE.SMBASE, BigInt.asUintN(32, sb));
    this.trace.push(`[smi] enter: saved context, handler @ ${sb + SMI_ENTRY_OFFSET}`);
    return sb + SMI_ENTRY_OFFSET;
  }

  /**
   * Modeled RSM: restore ring-0 state from the save area. If the guest moved
   * the SMBASE field first, the relocation sticks (stats.relocated++).
   */
  smiExit() {
    const sbOld = this.currentSmbase;
    const mem = this.k.rawMem;
    const savedSmbase = BigInt.asUintN(32, BigInt(mem.u32(sbOld + SAVE_STATE.SMBASE)));
    const cpu = this.k.cpu;
    for (const [name, off] of GPR_SLOTS) {
      cpu.regs[name] = mem.u64(sbOld + off);
    }
    cpu.rip = mem.u64(sbOld + SAVE_STATE.RIP);
    this.inSmm = false;
    this.stats.exited++;
    if (savedSmbase !== BigInt.asUintN(32, sbOld)) {
      this.currentSmbase = BigInt(savedSmbase);
      this.stats.relocated++;
      this.#populateSaveArea(this.currentSmbase);
      this.trace.push(`[smi] RSM: SMBASE relocated 0x${sbOld.toString(16)} -> 0x${this.currentSmbase.toString(16)}`);
    } else {
      this.trace.push(`[smi] RSM: resume at 0x${cpu.rip.toString(16)}`);
    }
    return cpu.rip;
  }

  /**
   * Convenience: raise+enter+execute handler via SEH path+exit. The handler
   * runs with the SAME arg registers it was interrupted with (real SMM) and
   * RSM restores the pre-SMI context afterwards.
   * @returns {{status:string, retval?:bigint, error?:object}}
   */
  smiDispatch(image = null) {
    const entry = this.smiEnter();
    let r;
    try {
      r = image
        ? this.k.callFunctionSeh(entry, [], image)
        : this.k.cpu.callFunction(entry, []);
    } catch (e) {
      this.inSmm = false;
      throw e;
    }
    // handler `ret` lands on our call sentinel — model RSM now
    this.smiExit();
    return r;
  }
}

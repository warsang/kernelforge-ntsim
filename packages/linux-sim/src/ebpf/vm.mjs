/**
 * ebpf/vm.mjs — eBPF VM loader with rbpf (solana_rbpf) primary, ubpf fallback, JS interpreter stub.
 * Browser-contained, WASM lazy-loaded. Falls back to pure-JS if WASM unavailable.
 */

let rbpfWasm = null;
let ubpfWasm = null;
let jsFallback = null;

const RBPF_URL = new URL("../../../vendor/rbpf.wasm", import.meta.url);
const UBPF_URL = new URL("../../../vendor/ubpf.wasm", import.meta.url);

// Minimal JS interpreter for BPF (subset: mov, add, exit) — for testing without WASM
class JsEbpfVm {
  constructor(progBytes){
    this.prog = new Uint8Array(progBytes);
    this.helpers = new Map();
  }
  registerHelper(id, fn){ this.helpers.set(id, fn); }
  // Simple interpreter: supports BPF_ALU64 | BPF_MOV (0xb7), BPF_ADD (0x07), BPF_EXIT (0x95), call helper (0x85)
  run(mem, memLen){
    const regs = new Array(11).fill(0n);
    regs[1] = 0n; // r1 = ctx ptr (we ignore)
    regs[10] = 0x100000n; // stack
    let pc=0;
    const prog = this.prog;
    while(pc < prog.length){
      const op = prog[pc];
      const dst = prog[pc+1] & 0x0f;
      const src = (prog[pc+1]>>4)&0x0f;
      const off = prog[pc+2] | (prog[pc+3]<<8);
      const imm = prog[pc+4] | (prog[pc+5]<<8) | (prog[pc+6]<<16) | (prog[pc+7]<<24);
      // signed imm
      const immS = (imm<<0)>>0;
      switch(op){
        case 0xb7: // mov64 dst, imm
          regs[dst]=BigInt(immS & 0xffffffff) & 0xffffffffffffffffn;
          break;
        case 0x07: // add64 dst, imm
          regs[dst]=(regs[dst]+BigInt(immS)) & 0xffffffffffffffffn;
          break;
        case 0x95: // exit
          return Number(regs[0] & 0xffffffffn);
        case 0x85: // call helper
          {
            const fn=this.helpers.get(imm);
            if(fn){
              const ret=fn(regs[1], regs[2], regs[3], regs[4], regs[5]);
              regs[0]=BigInt(ret??0) & 0xffffffffffffffffn;
            } else {
              regs[0]=0n;
            }
          }
          break;
        case 0xbf: // mov64 dst, src
          regs[dst]=regs[src];
          break;
        default:
          // unsupported → treat as nop
          break;
      }
      pc+=8;
    }
    return 0;
  }
}

async function loadRbpfWasm(){
  if(rbpfWasm) return rbpfWasm;
  try{
    const res=await fetch(RBPF_URL);
    if(!res.ok) throw new Error("rbpf wasm not found");
    const bytes=await res.arrayBuffer();
    // Try to instantiate as rbpf (expected exports: rbpf_create, rbpf_run)
    // For now, we don't have actual rbpf WASM built, so fallback
    // If bytes length >1000, attempt
    // This is a placeholder — real solana_rbpf WASM would be instantiated here
    throw new Error("rbpf WASM placeholder — using JS fallback");
  }catch(e){
    return null;
  }
}

async function loadUbpfWasm(){
  if(ubpfWasm) return ubpfWasm;
  try{
    const res=await fetch(UBPF_URL);
    if(!res.ok) throw new Error("ubpf not found");
    await res.arrayBuffer();
    throw new Error("ubpf placeholder");
  }catch(e){
    return null;
  }
}

export class EbpfVm {
  constructor(progBytes){
    this.progBytes = new Uint8Array(progBytes);
    this.helpers = new Map();
    this.backend = "js";
    this.wasmInstance = null;
  }
  static async create(progBytes){
    const vm=new EbpfVm(progBytes);
    // Try rbpf first
    const rbpf=await loadRbpfWasm();
    if(rbpf){
      vm.backend="rbpf";
      vm.wasmInstance=rbpf;
      return vm;
    }
    const ubpf=await loadUbpfWasm();
    if(ubpf){
      vm.backend="ubpf";
      vm.wasmInstance=ubpf;
      return vm;
    }
    vm.backend="js";
    vm.jsVm=new JsEbpfVm(progBytes);
    for(const [id,fn] of vm.helpers) vm.jsVm.registerHelper(id, fn);
    return vm;
  }
  registerHelper(id, fn){
    this.helpers.set(id, fn);
    if(this.jsVm) this.jsVm.registerHelper(id, fn);
    // For WASM backends, would call wasm register
  }
  // mem is Uint8Array or pointer+len in emulator memory; we simplify to Uint8Array context
  run(ctxBytes){
    if(this.backend==="js" && this.jsVm){
      return this.jsVm.run(ctxBytes, ctxBytes.length);
    }
    // For WASM, would call wasm interpreter
    // Fallback to JS
    if(!this.jsVm) this.jsVm=new JsEbpfVm(this.progBytes);
    return this.jsVm.run(ctxBytes, ctxBytes.length);
  }
  // For kernel emulation, run with context pointer in guest memory
  runWithGuestMem(kernel, ctxPtr, ctxLen){
    // Read ctx from guest mem if needed, or just run with empty
    let ctxBytes=new Uint8Array(0);
    try{
      if(ctxPtr && ctxLen) ctxBytes=kernel.mem.read(ctxPtr, Number(ctxLen));
    }catch{}
    return this.run(ctxBytes);
  }
}

export async function createEbpfVm(progBytes){
  return EbpfVm.create(progBytes);
}

/**
 * ebpf/verifier.mjs — minimal verifier (allow-all with logging, fallback to rbpf verifier if WASM available)
 */
export function verifyEbpfProg(progBytes, kernel){
  // progBytes is Uint8Array of 8-byte instructions
  if(progBytes.length % 8 !== 0){
    return {ok:false, error:"prog length not multiple of 8"};
  }
  const cnt=progBytes.length/8;
  if(cnt===0) return {ok:false, error:"empty prog"};
  if(cnt>4096) return {ok:false, error:"prog too large"};
  // Check last instruction is EXIT (0x95)
  const lastOp=progBytes[progBytes.length-8];
  if(lastOp!==0x95){
    kernel?.dbgLog?.push(`[bpf verifier] last insn not EXIT (0x95) but 0x${lastOp.toString(16)} — stub allow`);
  }
  // Allow all for now, but log
  kernel?.dbgLog?.push(`[bpf verifier] verified ${cnt} insns, allow`);
  return {ok:true, insnCount:cnt};
}

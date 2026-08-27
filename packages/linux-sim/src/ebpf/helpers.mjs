/**
 * ebpf/helpers.mjs — helper IDs for eBPF programs
 */
export const BPF_HELPERS = {
  map_lookup_elem: 1,
  map_update_elem: 2,
  map_delete_elem: 3,
  probe_read: 4,
  ktime_get_ns: 5,
  trace_printk: 6,
  get_current_pid_tgid: 14,
  get_current_uid_gid: 15,
  get_current_comm: 16,
};

export function installEbpfHelpers(vm, kernel){
  vm.registerHelper(BPF_HELPERS.trace_printk, (fmtPtr, fmtSize, ...args)=>{
    try{
      const msg=kernel.mem.readAnsi(fmtPtr, Number(fmtSize));
      kernel.dbgLog.push(`[bpf trace_printk] ${msg} args ${args.join(",")}`);
      kernel.emitTrace({kind:"bpf", helper:"trace_printk", msg});
    }catch(e){
      kernel.dbgLog.push(`[bpf trace_printk] (failed)`);
    }
    return 0;
  });
  vm.registerHelper(BPF_HELPERS.map_lookup_elem, (mapPtr, keyPtr)=>{
    // Stub: look up in kernel.ebpfMaps
    try{
      const map=kernel.ebpfMaps?.get(Number(mapPtr & 0xffffffffn));
      if(!map) return 0n;
      // Simplified: return value ptr if exists
      const keyBytes=kernel.mem.read(keyPtr, 8);
      const keyHex=[...keyBytes].map(b=>b.toString(16).padStart(2,"0")).join("");
      const val=map.get(keyHex);
      if(val) return BigInt(val);
    }catch{}
    return 0n;
  });
  vm.registerHelper(BPF_HELPERS.get_current_pid_tgid, ()=>{
    return 0x123400005678n;
  });
}

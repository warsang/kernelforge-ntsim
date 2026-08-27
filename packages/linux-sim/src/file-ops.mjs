/**
 * file-ops.mjs — device registry helpers + sendFileOp dispatch
 * Mirrors NtKernel devices.mjs sendIrp but for Linux file_operations.
 */

// 6.6.18 teaching layout (pinned). Must match linux-api's expectation and the shim header we ship to wasm clang.
// We'll expose this as constant so test helpers can use same offsets.
export const FILE_OPS_OFF = {
  owner: 0x0,
  llseek: 0x8,
  read: 0x10,
  write: 0x18,
  read_iter: 0x20,
  write_iter: 0x28,
  unlocked_ioctl: 0x30,
  compat_ioctl: 0x38,
  mmap: 0x40,
  open: 0x48,
  flush: 0x50,
  release: 0x58,
  fsync: 0x60,
  poll: 0x68,
  // size for scanning heuristic
  SIZE: 0x80,
};

// helper to read a fops struct and return ops map
export function readFileOps(kernel, fopsVa){
  const ops={};
  const base=BigInt(fopsVa);
  if(base===0n) return ops;
  const get=(off)=> {
    try{ return kernel.mem.u64(base + BigInt(off)); } catch{ return 0n; }
  };
  ops.read = get(FILE_OPS_OFF.read);
  ops.write = get(FILE_OPS_OFF.write);
  ops.unlocked_ioctl = get(FILE_OPS_OFF.unlocked_ioctl);
  ops.compat_ioctl = get(FILE_OPS_OFF.compat_ioctl);
  ops.mmap = get(FILE_OPS_OFF.mmap);
  ops.open = get(FILE_OPS_OFF.open);
  ops.release = get(FILE_OPS_OFF.release);
  ops.poll = get(FILE_OPS_OFF.poll);
  ops.llseek = get(FILE_OPS_OFF.llseek);
  // keep raw
  ops._raw = {
    read: ops.read, write: ops.write, unlocked_ioctl: ops.unlocked_ioctl,
    compat_ioctl: ops.compat_ioctl, mmap: ops.mmap, open: ops.open, release: ops.release
  };
  return ops;
}

// Convert _IO macros for harvesting? For now just keep cmd value as ioctl.
export function getHarvestedOps(kernel){
  const out=[];
  for(const dev of kernel.deviceRegistry){
    if(!dev.fops) continue;
    const ops=readFileOps(kernel, dev.fops);
    for(const [opName, va] of Object.entries(ops._raw)){
      if(va!==0n){
        out.push({ device: dev.name||`dev-${dev.major}`, op: opName, va, dev, fops: dev.fops, subsystem:"file" });
      }
    }
  }
  // also include generic opsRegistry (ftrace/kprobe/tracepoint/ebpf/io_uring)
  if(kernel.opsRegistry){
    for(const e of kernel.opsRegistry){
      if(e.handlerVa && e.handlerVa!==0n){
        let fops=e.opsVa;
        if(e.subsystem==="ebpf" && e.fd!==undefined) fops=BigInt(e.fd);
        if(e.subsystem==="io_uring" && e.fd!==undefined) fops=BigInt(e.fd);
        const key=`${e.subsystem}:${e.opsVa.toString(16)}:${e.handlerVa.toString(16)}`;
        if(!out.some(o=>o.fops===fops && o.va===e.handlerVa && o.subsystem===e.subsystem)){
          out.push({ device: e.device||e.subsystem, op: e.subsystem, va:e.handlerVa, fops, subsystem:e.subsystem, entry:e, addr:e.addr });
        }
      }
    }
  }
  return out;
}

export function getAllHarvestedOps(kernel){
  const base=getHarvestedOps(kernel);
  // ftrace
  for(const h of kernel.ftraceHooks||[]){
    if(h.func && h.func!==0n){
      const key=`ftrace:${h.func.toString(16)}`;
      if(!base.some(o=>o.va===h.func)) base.push({device:`ftrace:${h.addr?.toString(16)??"unknown"}`, op:"ftrace", va:h.func, fops:h.opsPtr, subsystem:"ftrace", entry:h});
    }
  }
  for(const k of kernel.kprobes||[]){
    if(k.pre_handler && k.pre_handler!==0n) base.push({device:`kprobe:${k.symbol||k.kpPtr.toString(16)}`, op:"kprobe_pre", va:k.pre_handler, fops:k.kpPtr, subsystem:"kprobe", entry:k});
    if(k.post_handler && k.post_handler!==0n) base.push({device:`kprobe:${k.symbol}`, op:"kprobe_post", va:k.post_handler, fops:k.kpPtr, subsystem:"kprobe", entry:k});
  }
  for(const tp of kernel.tracepoints||[]){
    base.push({device:`tracepoint`, op:"tracepoint", va:tp.probe, fops:tp.tpPtr, subsystem:"tracepoint", entry:tp});
  }
  for(const [fd, prog] of kernel.ebpfProgs||[]){
    // ebpf prog handler is VM, not direct VA — represent as ebpf prog fd
    base.push({device:`ebpf:${fd}`, op:"ebpf", va: BigInt(fd), fops:BigInt(fd), subsystem:"ebpf", prog});
  }
  for(const [fd, ring] of kernel.ioUringRings||[]){
    base.push({device:`io_uring:${fd}`, op:"io_uring", va:ring.sqRing, fops:BigInt(fd), subsystem:"io_uring", ring});
  }
  // dedup by fops+va+op (ftrace shares func but different ops)
  const seen=new Set();
  const dedup=[];
  for(const e of base){
    const k=`${e.subsystem||e.op}:${e.fops?.toString(16)??""}:${e.va.toString(16)}`;
    if(!seen.has(k)){ seen.add(k); dedup.push(e); }
  }
  return dedup;
}

// Synthetic file struct layout: 0x00: f_op, 0x08: private_data, 0x10: f_pos
const FILE_OFF = { f_op: 0x0, private_data: 0x8, f_pos: 0x10 };
const INODE_OFF = { i_mode: 0x0 };

/**
 * Dispatch a file operation.
 * @param {LinuxKernel} kernel
 * @param {object} device device entry from registry (or synthetic)
 * @param {{op:string, cmd?:bigint|number|string, input?:Uint8Array, inputHex?:string, outputLen?:number, offset?:bigint}} spec
 *  op: unlocked_ioctl | read | write | mmap | open | release | proc_show | proc_store | netlink
 */
export async function sendFileOp(kernel, device, spec){
  const op = spec.op || "unlocked_ioctl";
  let fopsVa = device?.fops;
  if(!fopsVa){
    // try first device
    const first = kernel.deviceRegistry[0];
    if(first) fopsVa = first.fops;
  }
  if(!fopsVa) return { status:"no_device", error: new Error("no fops registered") };
  const ops=readFileOps(kernel, fopsVa);
  let target=null;
  let majorName=op;
  // map
  switch(op){
    case "unlocked_ioctl":
    case "ioctl":
      target=ops.unlocked_ioctl;
      majorName="UNLOCKED_IOCTL";
      break;
    case "compat_ioctl":
      target=ops.compat_ioctl;
      majorName="COMPAT_IOCTL";
      break;
    case "read":
      target=ops.read;
      majorName="READ";
      break;
    case "write":
      target=ops.write;
      majorName="WRITE";
      break;
    case "mmap":
      target=ops.mmap;
      majorName="MMAP";
      break;
    case "open":
      target=ops.open;
      majorName="OPEN";
      break;
    case "release":
      target=ops.release;
      majorName="RELEASE";
      break;
    case "proc_show":
    case "proc_read":
      target=ops.read || ops.llseek;
      majorName="PROC_SHOW";
      break;
    case "proc_store":
    case "proc_write":
      target=ops.write;
      majorName="PROC_STORE";
      break;
    case "netlink":
      target= fopsVa;
      majorName="NETLINK";
      break;
    case "ftrace":
      target=device?.va ?? fopsVa ?? ops.unlocked_ioctl;
      // ftrace hook is stored in opsRegistry, device.va is handler
      if(device?.va) target=device.va;
      majorName="FTRACE";
      break;
    case "kprobe":
    case "kprobe_pre":
    case "kprobe_post":
      target=device?.va ?? fopsVa;
      majorName="KPROBE";
      break;
    case "tracepoint":
      target=device?.va ?? fopsVa;
      majorName="TRACEPOINT";
      break;
    case "ebpf":
      target=null; // handled specially
      majorName="EBPF";
      break;
    case "io_uring":
      target=null;
      majorName="IO_URING";
      break;
    default:
      target=ops[op] ?? null;
      majorName=op.toUpperCase();
  }
// Prepare buffers
  let inputBytes;
  if(spec.input instanceof Uint8Array) inputBytes=spec.input;
  else if(typeof spec.inputHex==="string" && spec.inputHex.length){
    const hx=spec.inputHex.replace(/[^0-9a-fA-F]/g,"");
    const pairs=hx.match(/.{2}/g)??[];
    inputBytes=new Uint8Array(pairs.map(x=>parseInt(x,16)));
  } else if(typeof spec.input==="string" && spec.input.length){
    const hx=spec.input.replace(/[^0-9a-fA-F]/g,"");
    const pairs=hx.match(/.{2}/g)??[];
    inputBytes=new Uint8Array(pairs.map(x=>parseInt(x,16)));
  } else if(spec.input && typeof spec.input.length==="number"){
    inputBytes=Uint8Array.from(spec.input);
  } else {
    inputBytes=new Uint8Array(0);
  }
  const outputLen = spec.outputLen ?? 64;
  const cmd = spec.cmd!==undefined ? BigInt(spec.cmd) : (spec.ioctl!==undefined ? BigInt(spec.ioctl) : 0n);
  // EBPF and IO_URING are handled specially without a direct target VA
  if(majorName==="EBPF"){
    const fd=Number(device?.fops ?? device?.prog?.fd ?? 0);
    const prog=kernel.ebpfProgs.get(fd) || device?.prog;
    if(!prog){
      return { status:"no_handler", majorName, error: new Error(`no ebpf prog for fd ${fd}`), ntstatus: 0xC0000001n };
    }
    const stepsBefore=kernel.cpu.steps;
    let res;
    let outputHex="";
    try{
      // Lazy import EbpfVm
      const {EbpfVm}=await import("./ebpf/vm.mjs");
      const {installEbpfHelpers}=await import("./ebpf/helpers.mjs");
      const vm=await EbpfVm.create(prog.progBytes);
      installEbpfHelpers(vm, kernel);
      // Context: use inputBytes as ctx
      const ctxVa=kernel.allocSlub(Math.max(inputBytes.length, 64), "ebpf_ctx");
      if(inputBytes.length) kernel.mem.write(ctxVa, inputBytes);
      const ret=vm.runWithGuestMem(kernel, ctxVa, BigInt(inputBytes.length));
      res={status:"ok", retval: BigInt(ret)};
      kernel.dbgLog.push(`[ebpf] prog fd ${fd} ret ${ret} backend ${vm.backend}`);
      kernel.emitTrace({kind:"ebpf", prog:fd, ret});
      // output is ctx after run
      try{
        const out=kernel.mem.read(ctxVa, Math.min(outputLen, 64));
        outputHex=[...out].map(b=>b.toString(16).padStart(2,"0")).join("");
      }catch{}
    }catch(e){
      res={status:"fault", error:e};
    }
    const steps=kernel.cpu.steps-stepsBefore;
    return {
      status: res.status||"ok",
      majorName, op, ntstatus: res.retval??0n, retval: res.retval??0n,
      outputHex, steps, inputHex:[...inputBytes].map(b=>b.toString(16).padStart(2,"0")).join(""),
      device: device?.name, target:`ebpf:${fd}`, error: res.error?String(res.error):undefined,
      userVa:`0x${(prog.progBytes?0n:0n).toString(16)}`,
    };
  }
  if(majorName==="IO_URING"){
    const fd=Number(device?.fops ?? device?.ring?.fd ?? 0);
    const ring=kernel.ioUringRings.get(fd) || device?.ring;
    if(!ring){
      return { status:"no_handler", majorName, error: new Error(`no io_uring ring fd ${fd}`), ntstatus: 0xC0000001n };
    }
    const stepsBefore=kernel.cpu.steps;
    let res={status:"ok", retval:0n};
    let outputHex="";
    try{
      // For auto-drive, synthesize SQEs from inputBytes if provided, else use ring's pending
      // If input provided, write SQEs into sqRing and set sqTail
      if(inputBytes.length>=64){
        // input contains raw SQEs
        const sqes=Math.floor(inputBytes.length/64);
        for(let i=0;i<sqes;i++) kernel.mem.write(ring.sqRing+BigInt(i*64), inputBytes.subarray(i*64,(i+1)*64));
        kernel.mem.w32(ring.sqTail, sqes);
      } else if(inputBytes.length>0){
        // single SQE from input
        const sqeBase=ring.sqRing;
        // clear and write simple SQE
        kernel.mem.write(sqeBase, new Uint8Array(64));
        kernel.mem.w32(sqeBase+24n, inputBytes.length);
        kernel.mem.w64(sqeBase+32n, BigInt(inputBytes.length));
        kernel.mem.w32(ring.sqTail, 1);
      }
      // Now call io_uring_enter logic
      const {dispatchSqe, writeCqe}=await import("./io_uring.mjs");
      const sqHead=Number(kernel.mem.u32(ring.sqHead));
      const sqTail=Number(kernel.mem.u32(ring.sqTail));
      const toSubmit=sqTail - sqHead;
      let cqTail=Number(kernel.mem.u32(ring.cqTail));
      const mode=kernel.ioUringScheduler?.mode || "fifo";
      const pending=[];
      for(let i=0;i<toSubmit;i++){
        const idx=(sqHead+i)%ring.sqEntries;
        const sqeBase=ring.sqRing+BigInt(idx*64);
        const buf=kernel.mem.read(sqeBase,64);
        const dv=new DataView(buf.buffer, buf.byteOffset);
        const sqe={opcode:dv.getUint8(0), fd:dv.getInt32(4,true), addr:dv.getBigUint64(16,true), len:dv.getUint32(24,true), user_data:dv.getBigUint64(32,true)};
        const implRes=dispatchSqe(kernel, sqe);
        if(mode==="reorder") pending.push({sqe, res:implRes});
        else {
          const cqeBase=ring.cqRing+BigInt((cqTail%ring.cqEntries)*16);
          kernel.mem.w64(cqeBase, sqe.user_data);
          kernel.mem.w32(cqeBase+8n, implRes);
          cqTail++;
        }
      }
      if(mode==="reorder" && pending.length){
        let s=0x9e3779b1 ^ toSubmit;
        const xorshift=()=>{ s^=s<<13; s^=s>>>17; s^=s<<5; return s>>>0; };
        for(let i=pending.length-1;i>0;i--){ const j=xorshift()%(i+1); const t=pending[i]; pending[i]=pending[j]; pending[j]=t; }
        for(const {sqe,res:rr} of pending){
          const cqeBase=ring.cqRing+BigInt((cqTail%ring.cqEntries)*16);
          kernel.mem.w64(cqeBase, sqe.user_data);
          kernel.mem.w32(cqeBase+8n, rr);
          cqTail++;
        }
        kernel.dbgLog.push(`[io_uring] reordered ${pending.length} completions`);
      }
      kernel.mem.w32(ring.cqTail, cqTail);
      kernel.mem.w32(ring.sqHead, sqTail);
      res={status:"ok", retval: BigInt(toSubmit)};
      try{
        const cqBytes=kernel.mem.read(ring.cqRing, Math.min(cqTail*16, 64));
        outputHex=[...cqBytes].map(b=>b.toString(16).padStart(2,"0")).join("");
      }catch{}
      kernel.dbgLog.push(`[io_uring] fd ${fd} submit ${toSubmit} completions ${cqTail} mode ${mode}`);
    }catch(e){ res={status:"fault", error:e}; }
    const steps=kernel.cpu.steps-stepsBefore;
    return {
      status: res.status||"ok",
      majorName, op, ntstatus: res.retval??0n, retval: res.retval??0n,
      outputHex, steps, inputHex:[...inputBytes].map(b=>b.toString(16).padStart(2,"0")).join(""),
      device: device?.name, target:`io_uring:${fd}`, error: res.error?String(res.error):undefined,
      userVa:`0x${ring.sqRing.toString(16)}`,
    };
  }
  if(!target || target===0n){
    return { status:"no_handler", majorName, error: new Error(`no handler for ${op}`), ntstatus: 0xC0000001n };
  }

  
  // Allocate file + inode + user arg buffer
  const fileVa = kernel.allocSlub(64, "file");
  const inodeVa = kernel.allocSlub(32, "inode");
  try{ kernel.mem.w64(fileVa + BigInt(FILE_OFF.f_op), fopsVa); }catch{}
  try{ kernel.mem.w64(fileVa + BigInt(FILE_OFF.private_data), 0n); }catch{}
  try{ kernel.mem.w64(fileVa + BigInt(FILE_OFF.f_pos), BigInt(spec.offset ?? 0n)); }catch{}

  const userLen = Math.max(inputBytes.length, outputLen, 16);
  const userVa = kernel.allocSlub(userLen, "UArg");
  if(inputBytes.length) kernel.mem.write(userVa, inputBytes);

  // Build args per op
  let args=[];
  let stepsBefore=kernel.cpu.steps;
  let res;
  kernel.tracePhase = `fileop ${majorName} 0x${target.toString(16)}`;
  try {
    switch(majorName){
      case "UNLOCKED_IOCTL":
      case "COMPAT_IOCTL":
        // long (*unlocked_ioctl)(struct file *filp, unsigned int cmd, unsigned long arg);
        args=[fileVa, cmd, userVa];
        res=kernel.callLinuxFunction(target, args);
        break;
      case "READ":
      case "PROC_SHOW":
        // ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
        {
          const ppos = kernel.allocSlub(8,"ppos");
          kernel.mem.w64(ppos, BigInt(spec.offset ?? 0n));
          args=[fileVa, userVa, BigInt(inputBytes.length || outputLen), ppos];
          res=kernel.callLinuxFunction(target, args);
          // for read, output is data written to userVa via copy_to_user OR direct write to buf? In our model driver writes via copy_to_user so userVa already updated.
          // We'll read back userVa
        }
        break;
      case "WRITE":
      case "PROC_STORE":
        {
          const ppos = kernel.allocSlub(8,"ppos");
          kernel.mem.w64(ppos, BigInt(spec.offset ?? 0n));
          args=[fileVa, userVa, BigInt(inputBytes.length), ppos];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      case "MMAP":
        {
          const vma = kernel.allocSlub(64,"vma");
          // vma->vm_start / vm_end etc minimal
          kernel.mem.w64(vma, 0x7f000000n); // vm_start
          kernel.mem.w64(vma+8n, 0x7f000000n + BigInt(outputLen));
          args=[fileVa, vma];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      case "OPEN":
      case "RELEASE":
        args=[kernel.allocSlub(32,"inode_dummy"), fileVa];
        // actually open takes inode*, file*; inode is allocated above as inodeVa
        args=[inodeVa, fileVa];
        res=kernel.callLinuxFunction(target, args);
        break;
      case "NETLINK":
        // int (*input)(struct sk_buff *skb) — we fake skb with data ptr+len
        {
          const skb = kernel.allocSlub(64,"skb");
          kernel.mem.w64(skb, userVa); // data
          kernel.mem.w32(skb+8n, inputBytes.length);
          args=[skb];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      case "FTRACE":
        {
          const regs=kernel.allocSlub(128,"pt_regs");
          // ip, parent_ip, ops, regs
          args=[0xdeadbeefn, 0n, fopsVa, regs];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      case "KPROBE":
        {
          const regs=kernel.allocSlub(128,"pt_regs");
          args=[fopsVa, regs];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      case "TRACEPOINT":
        {
          const child=kernel.allocSlub(64,"task");
          const parent=kernel.allocSlub(64,"task");
          args=[parent, child];
          res=kernel.callLinuxFunction(target, args);
        }
        break;
      default:
        args=[fileVa, cmd, userVa];
        res=kernel.callLinuxFunction(target, args);
    }
  } catch(e){
    res={status:"fault", error:e};
  }
  const steps = kernel.cpu.steps - stepsBefore;
  let outputHex="";
  try{
    const outBytes = kernel.mem.read(userVa, Math.min(outputLen, 256));
    outputHex=[...outBytes].map(b=>b.toString(16).padStart(2,"0")).join("");
  } catch{}
  let retVal=0n;
  if(res && res.status==="ok") retVal=res.retval ?? 0n;
  else if(res && res.retval!==undefined) retVal=res.retval;

  return {
    status: res?.status === "ok" ? "ok" : (res?.status || "fault"),
    majorName,
    op,
    ntstatus: retVal, // linux retval (0 ok, negative errno)
    information: BigInt(inputBytes.length),
    retval: retVal,
    outputHex,
    steps,
    inputHex: [...inputBytes].map(b=>b.toString(16).padStart(2,"0")).join(""),
    device: device?.name,
    target: `0x${target.toString(16)}`,
    error: res?.error ? String(res.error.message??res.error) : undefined,
    userVa: `0x${userVa.toString(16)}`,
  };
}

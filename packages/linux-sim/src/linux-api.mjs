/**
 * linux-api.mjs — Linux kernel shim implementations for emulation.
 * Covers kmalloc, copy_from_user, printk, chardev registration etc.
 */

export function installLinuxApi(kernel){
  // Version-dispatch table keyed by vermagic (from .modinfo), not hardcoded buildName.
  // Each entry is consulted at call time via kernel.vermagic.
  const API_VERSIONS = {
    notify_change: [
      { until: "5.12", sig: ["dentry","attr","delegated"], ret:"long", args:3 },
      { from: "5.12", sig: ["mnt_idmap","dentry","attr","delegated"], ret:"long", args:4 },
    ],
  };
  function parseVersion(v){
    const m = String(v||"").match(/(\d+)\.(\d+)(?:\.(\d+))?/);
    if(!m) return null;
    return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]||0) };
  }
  function cmpVer(a,b){
    if(a.major!==b.major) return a.major-b.major;
    if(a.minor!==b.minor) return a.minor-b.minor;
    return a.patch-b.patch;
  }
  function pickRow(table, vermagic){
    const v = parseVersion(vermagic);
    if(!v) return table[table.length-1];
    for(const row of table){
      if(row.until){
        const u = parseVersion(row.until);
        if(u && cmpVer(v,u) < 0) return row;
      } else if(row.from){
        const f = parseVersion(row.from);
        if(f && cmpVer(v,f) >= 0) return row;
      } else return row;
    }
    return table[table.length-1];
  }
  // __fentry__ and tracing nops — must be void preserving (BUG-1)
  for(const n of ["__fentry__","mcount","__tracepoint_iter","__traceiter","trace_printk"]){
    kernel.defineApi(n, function(){ return undefined; }, {ret:"void"});
  }
  // printk family
  kernel.defineApi("printk", function(fmt,...args){
    // fmt is first arg (rdi)
    return this.dbgPrint(fmt, args);
  }, {ret:"long"});
  kernel.defineApi("_printk", function(fmt,...args){ return this.dbgPrint(fmt, args); }, {ret:"long"});
  kernel.defineApi("pr_info", function(fmt,...args){ return this.dbgPrint(fmt, args); }, {ret:"long"});
  kernel.defineApi("pr_err", function(fmt,...args){ return this.dbgPrint(fmt, args); }, {ret:"long"});
  kernel.defineApi("pr_warn", function(fmt,...args){ return this.dbgPrint(fmt, args); }, {ret:"long"});

  // memory
  kernel.defineApi("kmalloc", function(size, flags){
    return this.allocSlub(Number(size), "kmalloc");
  }, {ret:"pvoid"});
  kernel.defineApi("kzalloc", function(size, flags){
    const addr=this.allocSlub(Number(size),"kzalloc");
    this.mem.write(addr, new Uint8Array(Number(size)));
    return addr;
  }, {ret:"pvoid"});
  kernel.defineApi("__kmalloc", function(size, flags){ return this.allocSlub(Number(size),"kmalloc"); }, {ret:"pvoid"});
  kernel.defineApi("kfree", function(ptr){ if(ptr) this.freePool(ptr); return undefined; }, {ret:"void"});
  kernel.defineApi("krealloc", function(ptr,size,flags){
    if(!ptr) return this.allocSlub(Number(size),"krealloc");
    if(Number(size)===0){ this.freePool(ptr); return 0n; }
    const n=this.allocSlub(Number(size),"krealloc");
    // copy old size? approximate copy min
    try { const old=this.mem.read(ptr, Number(size)); this.mem.write(n, old); } catch{}
    this.freePool(ptr);
    return n;
  }, {ret:"pvoid"});
  kernel.defineApi("vmalloc", function(size){ return this.allocSlub(Number(size),"vmalloc"); }, {ret:"pvoid"});
  kernel.defineApi("vzalloc", function(size){
    const a=this.allocSlub(Number(size),"vzalloc");
    this.mem.write(a, new Uint8Array(Number(size)));
    return a;
  }, {ret:"pvoid"});
  kernel.defineApi("vfree", function(ptr){ if(ptr) this.freePool(ptr); }, {ret:"void"});

  // user copy
  const TASK_SIZE_MAX = 0x7ffffffff000n;
  kernel.defineApi("access_ok", function(addr,size){
    const a=BigInt(addr), s=BigInt(size);
    return (a + s <= TASK_SIZE_MAX && a >= 0x1000n) ? 1n : 0n;
  }, {ret:"long"});
  kernel.defineApi("__access_ok", function(addr,size){ const a=BigInt(addr), s=BigInt(size); return (a+s <= TASK_SIZE_MAX)?1n:0n; }, {ret:"long"});

  function doCopyFrom(k, to, from, n){
    const t=BigInt(to), f=BigInt(from), len=Number(n);
    // For emulation, treat any address as user-allowed if mem has it; only fail if not mapped
    try{
      const data=k.mem.read(f, len);
      k.mem.write(t, data);
      return 0n;
    } catch(e){
      k.dbgLog.push(`[copy_from_user] fault at 0x${f.toString(16)} len ${len} ${e.message}`);
      return BigInt(len);
    }
  }
  function doCopyTo(k, to, from, n){
    const t=BigInt(to), f=BigInt(from), len=Number(n);
    try{
      const data=k.mem.read(f, len);
      k.mem.write(t, data);
      return 0n;
    } catch(e){
      k.dbgLog.push(`[copy_to_user] fault at 0x${t.toString(16)} len ${len} ${e.message}`);
      return BigInt(len);
    }
  }
  kernel.defineApi("copy_from_user", function(to,from,n){ return doCopyFrom(this,to,from,n); }, {ret:"ulong"});
  kernel.defineApi("_copy_from_user", function(to,from,n){ return doCopyFrom(this,to,from,n); }, {ret:"ulong"});
  kernel.defineApi("__copy_from_user", function(to,from,n){ return doCopyFrom(this,to,from,n); }, {ret:"ulong"});
  kernel.defineApi("copy_to_user", function(to,from,n){ return doCopyTo(this,to,from,n); }, {ret:"ulong"});
  kernel.defineApi("_copy_to_user", function(to,from,n){ return doCopyTo(this,to,from,n); }, {ret:"ulong"});
  kernel.defineApi("__copy_to_user", function(to,from,n){ return doCopyTo(this,to,from,n); }, {ret:"ulong"});

  kernel.defineApi("get_user", function(valPtr, from){
    // get_user(x, ptr) -> copy 4 or 8 bytes?
    // We'll copy 8
    const f=BigInt(from), t=BigInt(valPtr);
    if(f + 8n > TASK_SIZE_MAX) return 1n;
    try{
      const v=this.mem.u64(f);
      this.mem.w64(t, v);
      return 0n;
    } catch{ return 1n; }
  }, {ret:"long"});

  kernel.defineApi("put_user", function(val, to){
    const t=BigInt(to);
    if(t+8n > TASK_SIZE_MAX) return 1n;
    try{ this.mem.w64(t, BigInt(val)); return 0n; } catch{ return 1n; }
  }, {ret:"long"});

  // char devices
  kernel.defineApi("register_chrdev", function(major, namePtr, fops){
    const name = this.mem.readAnsi(namePtr, 64);
    this.deviceRegistry.push({ major: Number(major), name, fops: BigInt(fops), type:"chrdev" });
    this.dbgLog.push(`[register_chrdev] major ${major} name ${name} fops 0x${BigInt(fops).toString(16)}`);
    // return major if 0 allocate dynamic
    if(Number(major)===0) return 240n;
    return BigInt(major);
  }, {ret:"long"});
  kernel.defineApi("__register_chrdev", function(major, minor, count, namePtr, fops){
    const name=this.mem.readAnsi(namePtr,64);
    this.deviceRegistry.push({ major: Number(major), minor: Number(minor), count: Number(count), name, fops: BigInt(fops), type:"chrdev" });
    this.dbgLog.push(`[__register_chrdev] ${name} fops 0x${BigInt(fops).toString(16)}`);
    return Number(major)===0 ? 240n : BigInt(major);
  }, {ret:"long"});
  kernel.defineApi("unregister_chrdev", function(major,namePtr){
    const idx=this.deviceRegistry.findIndex(d=>d.major===Number(major));
    if(idx>=0) this.deviceRegistry.splice(idx,1);
    return 0n;
  }, {ret:"void"});
  kernel.defineApi("alloc_chrdev_region", function(devPtr, baseminor, count, namePtr){
    const name=this.mem.readAnsi(namePtr,64);
    const dev= 0x01000000n | BigInt(baseminor);
    try{ this.mem.w64(devPtr, dev); }catch{}
    this.deviceRegistry.push({ major:1, baseminor:Number(baseminor), count:Number(count), name, type:"alloc_region" });
    return 0n;
  }, {ret:"long"});

  kernel.defineApi("cdev_init", function(cdev, fops){
    // store fops at cdev+0x10 (ish)
    try{ this.mem.w64(cdev+0x8n, BigInt(fops)); }catch{}
    this.cdevs.push({cdev:BigInt(cdev), fops:BigInt(fops)});
    return undefined;
  }, {ret:"void"});
  kernel.defineApi("cdev_add", function(cdev, dev, count){
    this.dbgLog.push(`[cdev_add] cdev 0x${cdev.toString(16)} dev 0x${dev.toString(16)}`);
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("cdev_del", function(cdev){ return undefined; }, {ret:"void"});

  // misc
  kernel.defineApi("misc_register", function(miscPtr){
    // miscdevice layout: 0:int minor, 8:char* name, 16:file_operations* fops
    let minor=0, name="", fops=0n;
    try{
      minor=this.mem.u32(miscPtr);
      const namePtr=this.mem.u64(miscPtr+8n);
      name=this.mem.readAnsi(namePtr,64);
      fops=this.mem.u64(miscPtr+16n);
    } catch(e){ }
    this.miscDevices.push({miscPtr:BigInt(miscPtr), minor, name, fops});
    this.deviceRegistry.push({major:10, minor, name, fops, type:"misc"});
    this.dbgLog.push(`[misc_register] ${name} minor ${minor} fops 0x${fops.toString(16)}`);
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("misc_deregister", function(miscPtr){
    const idx=this.miscDevices.findIndex(m=>m.miscPtr===BigInt(miscPtr));
    if(idx>=0) this.miscDevices.splice(idx,1);
    return 0n;
  }, {ret:"long"});

  // class/device create (no-op)
  kernel.defineApi("class_create", function(owner,namePtr){
    return this.allocSlub(64,"class");
  }, {ret:"pvoid"});
  kernel.defineApi("device_create", function(cls,parent,dev,drvdata,fmt){
    return this.allocSlub(64,"device");
  }, {ret:"pvoid"});

  // proc
  kernel.defineApi("proc_create", function(namePtr, mode, parent, proc_ops){
    const name=this.mem.readAnsi(namePtr,64);
    // proc_ops vs file_operations: treat as file_operations
    let fops=proc_ops;
    // In newer kernels proc_ops has different layout, but we treat passed pointer as fops struct
    // Try to read if proc_ops is pointer to struct with read/write etc at known offsets; we just store as is
    this.procEntries.push({name, proc_ops: BigInt(proc_ops), fops: BigInt(fops), parent: BigInt(parent)});
    // also register as device for driving
    this.deviceRegistry.push({name:`/proc/${name}`, fops: BigInt(fops), type:"proc"});
    this.dbgLog.push(`[proc_create] ${name} ops 0x${BigInt(proc_ops).toString(16)}`);
    return this.allocSlub(32,"proc_entry");
  }, {ret:"pvoid"});
  kernel.defineApi("proc_create_data", function(namePtr,mode,parent,proc_ops,data){
    return this.apiImpls.get("proc_create").call(this, namePtr, mode, parent, proc_ops);
  }, {ret:"pvoid"});
  kernel.defineApi("remove_proc_entry", function(namePtr,parent){ return undefined; }, {ret:"void"});
  kernel.defineApi("proc_remove", function(entry){ return undefined; }, {ret:"void"});

  // netlink
  kernel.defineApi("netlink_kernel_create", function(net, unit, cfgPtr){
    // cfg: groups etc, input at offset maybe 8
    let input=0n;
    try{
      if(cfgPtr) input=this.mem.u64(cfgPtr+8n);
    } catch{}
    this.netlinkHandlers.set(Number(unit), input);
    this.deviceRegistry.push({name:`netlink-${unit}`, fops: input, type:"netlink", unit: Number(unit)});
    this.dbgLog.push(`[netlink_kernel_create] unit ${unit} input 0x${input.toString(16)}`);
    return this.allocSlub(64,"netlink_sock");
  }, {ret:"pvoid"});
  kernel.defineApi("netlink_kernel_release", function(sock){ return undefined; }, {ret:"void"});

  // creds
  kernel.defineApi("prepare_kernel_cred", function(daemon){
    const cred=this.allocSlub(32,"cred");
    this.mem.w32(cred, 0); // uid 0
    this.mem.w32(cred+4n,0);
    return cred;
  }, {ret:"pvoid"});
  kernel.defineApi("commit_creds", function(newCred){
    const cred=BigInt(newCred);
    this.currentCred = { uid: Number(this.mem.u32(cred)), gid: Number(this.mem.u32(cred+4n)) };
    this.credHistory.push({cred, uid: this.currentCred.uid, at: this.traceSeq});
    this.dbgLog.push(`[commit_creds] cred 0x${cred.toString(16)} uid ${this.currentCred.uid}`);
    this.emitTrace({kind:"cred", op:"commit", cred});
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("revert_creds", function(old){ return undefined; }, {ret:"void"});
  kernel.defineApi("get_current_cred", function(){ return this.allocSlub(32,"cred"); }, {ret:"pvoid"});

  // msr / cr
  kernel.defineApi("native_write_msr", function(msr, low, high){
    this.dbgLog.push(`[wrmsr] msr 0x${BigInt(msr).toString(16)} val 0x${BigInt(high).toString(16)}:${BigInt(low).toString(16)}`);
    this.emitTrace({kind:"msr", op:"wrmsr", msr: BigInt(msr)});
    return undefined;
  }, {ret:"void"});
  kernel.defineApi("wrmsr", function(msr,low,high){ return this.apiImpls.get("native_write_msr").call(this,msr,low,high); }, {ret:"void"});

  kernel.defineApi("write_cr0", function(val){
    this.dbgLog.push(`[write_cr0] 0x${BigInt(val).toString(16)}`);
    return undefined;
  }, {ret:"void"});

  // kallsyms — always succeed (allocate dummy thunk) to keep hook install from early-returning
  kernel.defineApi("kallsyms_lookup_name", function(namePtr){
    const name=this.mem.readAnsi(namePtr,128);
    let va=this.kallsyms.get(name) || this.apiThunks.get(name);
    if(!va){
      // Create a dummy thunk for any unknown symbol so callers don't get NULL
      try{
        va=this.defineApi(name, ()=>0n, {ret:"long"});
        this.dbgLog.push(`[kallsyms_lookup_name] ${name} -> synthetic 0x${va.toString(16)}`);
      }catch{ va=0n; }
    } else {
      this.dbgLog.push(`[kallsyms_lookup_name] ${name} -> 0x${va.toString(16)}`);
    }
    return va;
  }, {ret:"pvoid"});

  // VFS helpers — success-by-default, fuzz-configurable via stubPolicy (BUG-3/4)
  // BUG-5: emit full addr/size/data + string preview for forensics
  kernel.defineApi("filp_open", function(filenamePtr, flags, mode){
    const filename = this.mem.readAnsi(filenamePtr,128);
    const pol=this.stubPolicy.get("filp_open");
    if(pol?.mode==="err"){
      const code=BigInt(pol.errCode ?? -2);
      const errPtr = (code & 0xffffffffffffffffn);
      this.dbgLog.push(`[filp_open] ${filename} -> ERR_PTR ${errPtr.toString(16)}`);
      this.emitTrace({kind:"mem_write", addr:filenamePtr, size: filename.length, data: filename, name:"filp_open", filename, ret:errPtr});
      return errPtr;
    }
    const f=this.allocSlub(96,"file");
    this.mem.w64(f, 0n);
    this.dbgLog.push(`[filp_open] ${filename} -> file 0x${f.toString(16)}`);
    this.emitTrace({kind:"mem_write", addr:f, size:96, data:`file for ${filename}`, name:"filp_open", filename, ret:f});
    return f;
  }, {ret:"pvoid"});

  kernel.defineApi("kern_path", function(namePtr, flags, pathPtr){
    const pol=this.stubPolicy.get("kern_path");
    if(pol?.mode==="err") return (-2n & 0xffffffffffffffffn);
    const name=this.mem.readAnsi(namePtr,128);
    const d=this.allocSlub(64,"dentry");
    const m=this.allocSlub(64,"vfsmount");
    // struct path { mnt @0, dentry @8 } — use typed offsets (generic for all kernels, LP64)
    const PATH_MNT_OFF = 0n, PATH_DENTRY_OFF = 8n;
    try{ this.mem.w64(pathPtr + PATH_MNT_OFF, m); this.mem.w64(pathPtr + PATH_DENTRY_OFF, d); }catch{}
    this.dbgLog.push(`[kern_path] ${name} -> path 0x${pathPtr.toString(16)} {mnt 0x${m.toString(16)} dentry 0x${d.toString(16)}}`);
    this.emitTrace({kind:"mem_write", addr:pathPtr, size:16, data:`{mnt:0x${m.toString(16)},dentry:0x${d.toString(16)}}`, name:"kern_path", filename:name, mnt:m, dentry:d, ret:0n});
    return 0n;
  }, {ret:"long"});

  kernel.defineApi("path_put", function(pathPtr){
    this.dbgLog.push(`[path_put] 0x${pathPtr.toString(16)}`);
    return undefined;
  }, {ret:"void"});

  kernel.defineApi("notify_change", function(a,b,c,d){
    const pol=this.stubPolicy.get("notify_change");
    if(pol?.mode==="err") return (-1n & 0xffffffffffffffffn);
    const row = pickRow(API_VERSIONS.notify_change, this.vermagic || this.buildName);
    let mnt_idmap, dentry, attrPtr, delegatedPtr;
    if(row.args===4){
      mnt_idmap=a; dentry=b; attrPtr=c; delegatedPtr=d;
      this.dbgLog.push(`[notify_change] idmap 0x${mnt_idmap.toString(16)} dentry 0x${dentry.toString(16)} attr 0x${attrPtr.toString(16)} delegated 0x${delegatedPtr?delegatedPtr.toString(16):"0"}`);
    } else {
      dentry=a; attrPtr=b; delegatedPtr=c; mnt_idmap=0n;
      this.dbgLog.push(`[notify_change] dentry 0x${dentry.toString(16)} attr 0x${attrPtr.toString(16)} delegated 0x${delegatedPtr?delegatedPtr.toString(16):"0"} (legacy)`);
    }
    try{ if(delegatedPtr) this.mem.w64(delegatedPtr, 0n); }catch{}
    this.emitTrace({kind:"api", name:"notify_change", args: row.args===4? [mnt_idmap,dentry,attrPtr] : [dentry,attrPtr], ret:0n, vermagic: this.vermagic});
    return 0n;
  }, {ret:"long"});

  kernel.defineApi("call_usermodehelper", function(pathPtr, argvPtr, envpPtr, wait){
    const exe = this.mem.readAnsi(pathPtr,128);
    // Decode argv array (null-terminated array of char* at argvPtr)
    const argv = [];
    try{
      for(let i=0;i<8;i++){
        const ptr = this.mem.u64(argvPtr + BigInt(i*8));
        if(ptr===0n) break;
        argv.push(this.mem.readAnsi(ptr,64));
      }
    }catch{}
    // Similarly envp
    const envp = [];
    try{
      if(envpPtr){
        for(let i=0;i<8;i++){
          const ptr=this.mem.u64(envpPtr + BigInt(i*8));
          if(ptr===0n) break;
          envp.push(this.mem.readAnsi(ptr,64));
        }
      }
    }catch{}
    this.dbgLog.push(`[call_usermodehelper] ${exe} argv [${argv.join(",")}] envp [${envp.join(",")}]`);
    this.emitTrace({kind:"mem_write", addr:pathPtr, size: exe.length, data: exe, name:"call_usermodehelper", exe, argv, envp, ret:0n});
    const pol=this.stubPolicy.get("call_usermodehelper");
    if(pol?.mode==="err") return 1n;
    return 0n;
  }, {ret:"long"});

  // ---- ftrace (generic hook harvest, success-by-default) ----
  const FTRACE_OPS_FUNC_OFF = 0x0; // `func` is first field in 6.12 ftrace_ops
  kernel.defineApi("register_ftrace_function", function(opsPtr){
    try{
      const pol=this.stubPolicy.get("register_ftrace_function");
      if(pol?.mode==="err") return (-22n & 0xffffffffffffffffn);
      const func=this.mem.u64(opsPtr + BigInt(FTRACE_OPS_FUNC_OFF));
      this.ftraceHooks.push({opsPtr:BigInt(opsPtr), func});
      this.opsRegistry.push({subsystem:"ftrace", api:"register_ftrace_function", opsVa:BigInt(opsPtr), handlerVa:func, symbol:"ftrace", layout:"ftrace_ops"});
      this.dbgLog.push(`[register_ftrace_function] ops 0x${opsPtr.toString(16)} func 0x${func.toString(16)}`);
      this.emitTrace({kind:"ftrace", op:"register", ops:opsPtr, func});
    }catch(e){ this.dbgLog.push(`[register_ftrace_function] err ${e.message}`); }
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("unregister_ftrace_function", function(opsPtr){
    this.ftraceHooks=this.ftraceHooks.filter(h=>h.opsPtr!==BigInt(opsPtr));
    this.opsRegistry=this.opsRegistry.filter(o=>!(o.subsystem==="ftrace" && o.opsVa===BigInt(opsPtr)));
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("ftrace_set_filter_ip", function(opsPtr, ip, remove, reset){
    this.dbgLog.push(`[ftrace_set_filter_ip] ops 0x${opsPtr.toString(16)} ip 0x${ip.toString(16)}`);
    const h=this.ftraceHooks.find(x=>x.opsPtr===BigInt(opsPtr));
    if(h) h.addr=BigInt(ip);
    const e=this.opsRegistry.find(x=>x.opsVa===BigInt(opsPtr));
    if(e) e.addr=BigInt(ip);
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("ftrace_set_filter", function(opsPtr, bufPtr, len, reset){
    return 0n;
  }, {ret:"long"});

  // ---- kprobe ---- (BUG-7: offsets must be BigInt, kp must be coerced)
  const KPROBE_SYMBOL_OFF = 0x10n;
  const KPROBE_PRE_OFF = 0x28n;
  const KPROBE_POST_OFF = 0x30n;
  const KPROBE_ADDR_OFF = 0x20n;
  kernel.defineApi("register_kprobe", function(kpPtr){
    try{
      const kp = BigInt(kpPtr);
      const pol=this.stubPolicy.get("register_kprobe");
      if(pol?.mode==="err") return (-22n & 0xffffffffffffffffn);
      const symPtr=this.mem.u64(kp + KPROBE_SYMBOL_OFF);
      const sym=symPtr? this.mem.readAnsi(symPtr,64) : "";
      const pre=this.mem.u64(kp + KPROBE_PRE_OFF);
      const post=this.mem.u64(kp + KPROBE_POST_OFF);
      const addr=sym? (this.kallsyms.get(sym) || this.apiThunks.get(sym) || 0n) : this.mem.u64(kp+KPROBE_ADDR_OFF);
      this.kprobes.push({kpPtr:BigInt(kpPtr), symbol:sym, addr, pre_handler:pre, post_handler:post});
      this.opsRegistry.push({subsystem:"kprobe", api:"register_kprobe", opsVa:BigInt(kpPtr), handlerVa:pre||post, symbol, layout:"kprobe"});
      this.dbgLog.push(`[register_kprobe] ${sym || "addr 0x"+addr.toString(16)} pre 0x${pre.toString(16)}`);
      if(pre) this.emitTrace({kind:"kprobe", op:"register", symbol:sym, handler:pre});
    }catch(e){ this.dbgLog.push(`[register_kprobe] err ${e.message}`);}
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("unregister_kprobe", function(kpPtr){
    this.kprobes=this.kprobes.filter(k=>k.kpPtr!==BigInt(kpPtr));
    this.opsRegistry=this.opsRegistry.filter(o=>!(o.subsystem==="kprobe" && o.opsVa===BigInt(kpPtr)));
    return undefined;
  }, {ret:"void"});
  kernel.defineApi("register_kretprobe", function(kpPtr){ return this.apiImpls.get("register_kprobe").call(this,kpPtr); }, {ret:"long"});

  // ---- tracepoint ----
  kernel.defineApi("tracepoint_probe_register", function(tpPtr, probe, data){
    this.tracepoints.push({tpPtr:BigInt(tpPtr), probe:BigInt(probe)});
    this.opsRegistry.push({subsystem:"tracepoint", api:"tracepoint_probe_register", opsVa:BigInt(tpPtr), handlerVa:BigInt(probe), layout:"tracepoint"});
    this.dbgLog.push(`[tracepoint_probe_register] probe 0x${probe.toString(16)}`);
    return 0n;
  }, {ret:"long"});
  kernel.defineApi("tracepoint_probe_unregister", function(tpPtr, probe, data){ return 0n; }, {ret:"long"});

  // ---- bpf (eBPF VM) ----
  kernel.defineApi("bpf", function(cmd, attrPtr, size){
    const pol=this.stubPolicy.get("bpf");
    if(pol?.mode==="err") return (-1n & 0xffffffffffffffffn);
    try{
      const c=Number(cmd);
      if(c===5){ // BPF_PROG_LOAD
        const prog_type=this.mem.u32(attrPtr);
        const insn_cnt=this.mem.u32(attrPtr+4n);
        const insnsPtr=this.mem.u64(attrPtr+8n);
        const progBytes=this.mem.read(insnsPtr, Number(insn_cnt)*8);
        // Store prog for later drive — try to create VM (lazy)
        const fd=100 + this.ebpfProgs.size;
        this.ebpfProgs.set(fd, {prog_type, insn_cnt, progBytes: new Uint8Array(progBytes), attrPtr:BigInt(attrPtr)});
        this.opsRegistry.push({subsystem:"ebpf", api:"bpf", opsVa:BigInt(attrPtr), handlerVa: insnsPtr, progType:prog_type, fd});
        this.dbgLog.push(`[bpf] PROG_LOAD type ${prog_type} cnt ${insn_cnt} -> fd ${fd}`);
        // also try to verify via ebpf verifier if available
        try{ const {verifyEbpfProg}=globalThis.__ebpfVerifier || {}; }catch{}
        return BigInt(fd);
      } else if(c===9){ // BPF_MAP_CREATE
        const fd=200 + this.ebpfMaps.size;
        this.ebpfMaps.set(fd, new Map());
        this.dbgLog.push(`[bpf] MAP_CREATE -> fd ${fd}`);
        return BigInt(fd);
      } else if(c===7){ // BPF_PROG_ATTACH etc
        this.dbgLog.push(`[bpf] cmd ${c} stub success`);
        return 0n;
      }
      this.dbgLog.push(`[bpf] cmd ${c} stub 0`);
      return 0n;
    }catch(e){ this.dbgLog.push(`[bpf] err ${e.message}`); return 0n; }
  }, {ret:"long"});

  // ---- io_uring (two rings) ----
  kernel.defineApi("io_uring_setup", function(entries, paramsPtr){
    const pol=this.stubPolicy.get("io_uring_setup");
    if(pol?.mode==="err") return (-22n & 0xffffffffffffffffn);
    try{
      const n=Number(entries);
      // reuse io_uring.mjs alloc helper if available, else inline
      const sqEntries=(() => { let p=1; while(p<n) p<<=1; return p; })();
      const cqEntries=sqEntries*2;
      const sqRing=this.allocSlub(sqEntries*64, "io_sq");
      const cqRing=this.allocSlub(cqEntries*16, "io_cq");
      const sqHead=this.allocSlub(4, "io_sq_head");
      const sqTail=this.allocSlub(4, "io_sq_tail");
      const cqHead=this.allocSlub(4, "io_cq_head");
      const cqTail=this.allocSlub(4, "io_cq_tail");
      this.mem.w32(sqHead,0); this.mem.w32(sqTail,0); this.mem.w32(cqHead,0); this.mem.w32(cqTail,0);
      if(paramsPtr){
        try{ this.mem.w32(paramsPtr, sqEntries); this.mem.w32(paramsPtr+4n, cqEntries); }catch{}
      }
      const fd=300 + this.ioUringRings.size;
      const ring={sqEntries,cqEntries,sqRing,cqRing,sqHead,sqTail,cqHead,cqTail,fd};
      this.ioUringRings.set(fd, ring);
      this.opsRegistry.push({subsystem:"io_uring", api:"io_uring_setup", opsVa:BigInt(paramsPtr||0n), handlerVa: sqRing, fd, ring});
      this.dbgLog.push(`[io_uring_setup] entries ${entries} -> fd ${fd} sq 0x${sqRing.toString(16)} cq 0x${cqRing.toString(16)}`);
      return BigInt(fd);
    }catch(e){ this.dbgLog.push(`[io_uring_setup] err ${e.message}`); return 0n; }
  }, {ret:"long"});
  kernel.defineApi("io_uring_enter", function(fd, to_submit, min_complete, flags, sig){
    const ring=this.ioUringRings.get(Number(fd));
    if(!ring){ this.dbgLog.push(`[io_uring_enter] no ring fd ${fd}`); return (-9n & 0xffffffffffffffffn); }
    const pol=this.stubPolicy.get("io_uring_enter");
    const toSubmit=Number(to_submit);
    let cqTail=Number(this.mem.u32(ring.cqTail));
    // scheduler mode from stubPolicy or fuzz
    const mode=this.ioUringScheduler?.mode || "fifo";
    const pending=[];
    for(let i=0;i<toSubmit;i++){
      const sqIdx=(Number(this.mem.u32(ring.sqHead)) + i) % ring.sqEntries;
      const sqeBase=ring.sqRing + BigInt(sqIdx*64);
      let sqe;
      try{
        const buf=this.mem.read(sqeBase,64);
        const dv=new DataView(buf.buffer, buf.byteOffset);
        sqe={opcode:dv.getUint8(0), fd:dv.getInt32(4,true), off:dv.getBigUint64(8,true), addr:dv.getBigUint64(16,true), len:dv.getUint32(24,true), user_data:dv.getBigUint64(32,true)};
      }catch{ sqe={opcode:0, user_data:0n}; }
      // dispatch reuse: map to existing stubs
      let res=0;
      // Simple dispatch: WRITE/READ/OPENAT etc via existing apiImpls
      try{
        if(sqe.opcode===23 || sqe.opcode===2){ // WRITE/WRITEV
          const impl=this.apiImpls.get("kernel_write");
          if(impl) res=0; else res=sqe.len;
        } else if(sqe.opcode===18){ // OPENAT
          const impl=this.apiImpls.get("filp_open");
          if(impl) res=3;
        } else if(sqe.opcode===0){ res=0; }
        else res=0;
      }catch{ res=-1; }
      if(mode==="reorder"){
        pending.push({sqe, res});
      } else {
        // FIFO
        const cqeBase=ring.cqRing + BigInt((cqTail % ring.cqEntries)*16);
        this.mem.w64(cqeBase, sqe.user_data);
        this.mem.w32(cqeBase+8n, res);
        this.mem.w32(cqeBase+12n, 0);
        cqTail++;
      }
    }
    if(mode==="reorder" && pending.length){
      // shuffle via simple xorshift seeded by to_submit
      let s=0x9e3779b1 ^ toSubmit;
      const xorshift=()=>{ s^=s<<13; s^=s>>>17; s^=s<<5; return s>>>0; };
      for(let i=pending.length-1;i>0;i--){ const j=xorshift()%(i+1); const t=pending[i]; pending[i]=pending[j]; pending[j]=t; }
      for(const {sqe,res} of pending){
        const cqeBase=ring.cqRing + BigInt((cqTail % ring.cqEntries)*16);
        this.mem.w64(cqeBase, sqe.user_data);
        this.mem.w32(cqeBase+8n, res);
        this.mem.w32(cqeBase+12n, 0);
        cqTail++;
      }
      this.dbgLog.push(`[io_uring_enter] reordered ${pending.length} completions`);
    }
    this.mem.w32(ring.cqTail, cqTail);
    this.dbgLog.push(`[io_uring_enter] fd ${fd} submit ${toSubmit} -> ${cqTail} completions mode ${mode}`);
    return BigInt(toSubmit);
  }, {ret:"long"});
  kernel.defineApi("io_uring_register", function(fd, opcode, arg, nr_args){ return 0n; }, {ret:"long"});

  // kernel file ops helpers
  kernel.defineApi("kernel_write", function(file, buf, len, pos){
    this.dbgLog.push(`[kernel_write] file 0x${file.toString(16)} len ${len}`);
    return BigInt(len);
  }, {ret:"long"});
  kernel.defineApi("kernel_read", function(file, buf, len, pos){
    const b=new Uint8Array(Number(len)).fill(0x41);
    try{ this.mem.write(buf, b); }catch{}
    return BigInt(len);
  }, {ret:"long"});
  kernel.defineApi("filp_close", function(filp, id){ this.dbgLog.push(`[filp_close] 0x${filp.toString(16)}`); return 0n; }, {ret:"long"});
  kernel.defineApi("vfs_read", function(file, buf, len, pos){ return BigInt(len); }, {ret:"long"});
  kernel.defineApi("vfs_write", function(file, buf, len, pos){ return BigInt(len); }, {ret:"long"});

  // mutex etc stubs — thunks are void (no args, no ret) to avoid misleading trace
  for(const nm of ["mutex_lock","mutex_unlock","mutex_init","spin_lock","spin_unlock","spin_lock_init","try_module_get","module_put","nonseekable_open","single_open","single_release","seq_read","seq_lseek","seq_release","__mutex_init"]){
    kernel.defineApi(nm, function(){ return 0n; }, {ret:"long"});
  }
  for(const nm of ["__x86_return_thunk","__x86_indirect_thunk_rax","__x86_indirect_thunk_rbp","__x86_indirect_thunk_r12"]){
    kernel.defineApi(nm, function(){ return undefined; }, {ret:"void"});
  }
  // copy helpers for put_user etc already done

  // add_taint style?
  kernel.defineApi("add_taint", function(t, lockdep){ this.dbgLog.push(`[taint] ${t}`); }, {ret:"void"});

  // capability
  kernel.defineApi("capable", function(cap){ return 1n; }, {ret:"long"});
}

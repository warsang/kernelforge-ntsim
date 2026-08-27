import { test } from "node:test";
import assert from "node:assert/strict";
import { LinuxKernel } from "../src/linux-kernel.mjs";
import { parseElfKo, mapModule } from "../src/module-loader.mjs";
import { sendFileOp, getHarvestedOps, FILE_OPS_OFF } from "../src/file-ops.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function compileKo(source){
  const dir=mkdtempSync(path.join(tmpdir(),"kf-ko-"));
  try{
    const cFile=path.join(dir,"mod.c");
    const oFile=path.join(dir,"mod.o");
    writeFileSync(cFile, source);
    const includeDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../compiler-worker/include");
    execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", includeDir,"-D__KERNEL__","-DMODULE","-c",cFile,"-o",oFile], {timeout:15000});
    return new Uint8Array(readFileSync(oFile));
  } finally { try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
}

test("file-ops: register_chrdev + unlocked_ioctl dispatch", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){ return (cmd==0x1234)?0:-1; }
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"mydev",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const k=new LinuxKernel({});
  const p=parseElfKo(bytes);
  const m=mapModule(k,p,0xffffffffc0000000n,(n)=>k.resolveImportProvisioned(n));
  k.callFunctionSeh(m.init,[],{});
  assert.equal(k.deviceRegistry.length,1);
  const ops=getHarvestedOps(k);
  assert.ok(ops.some(o=>o.op==="unlocked_ioctl"));
  const r=await sendFileOp(k, k.deviceRegistry[0], {op:"unlocked_ioctl", cmd:0x1234, input: new Uint8Array([1]), outputLen:8});
  assert.equal(r.status,"ok");
  assert.equal(r.retval,0n);
  const r2=await sendFileOp(k, k.deviceRegistry[0], {op:"unlocked_ioctl", cmd:0x9999, input: new Uint8Array([1]), outputLen:8});
  assert.equal(r2.retval, 0xffffffffffffffffn); // -1
});

test("file-ops: read/write/mmap/proc/netlink", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/netlink.h>
#include <linux/uaccess.h>
MODULE_LICENSE("GPL");
static ssize_t my_read(struct file *f, char __user *buf, size_t len, loff_t *off){ char k[]="readok"; copy_to_user(buf,k,6); return 6; }
static ssize_t my_write(struct file *f, const char __user *buf, size_t len, loff_t *off){ return len; }
static int my_mmap(struct file *f, void *vma){ return 0; }
static ssize_t proc_show(struct file *f, char __user *buf, size_t len, loff_t *off){ char k[]="proc"; copy_to_user(buf,k,4); return 4; }
static void nl_input(void *skb){ }
static struct file_operations fops={ .read=my_read, .write=my_write, .mmap=my_mmap };
static struct proc_ops pops={ .proc_read=proc_show };
static struct netlink_kernel_cfg cfg={ .input=nl_input };
static int __init myinit(void){
  register_chrdev(240,"rwdev",&fops);
  proc_create("myproc",0,0,&pops);
  netlink_kernel_create(&init_net, 31, &cfg);
  return 0;
}
module_init(myinit);
`;
  const bytes=compileKo(src);
  const k=new LinuxKernel({});
  const p=parseElfKo(bytes);
  const m=mapModule(k,p,0xffffffffc0000000n,(n)=>k.resolveImportProvisioned(n));
  k.callFunctionSeh(m.init,[],{});
  assert.ok(k.deviceRegistry.length>=3); // chrdev + proc + netlink
  // harvest should have read,write,mmap,proc
  const ops=getHarvestedOps(k);
  assert.ok(ops.some(o=>o.op==="read"));
  assert.ok(ops.some(o=>o.op==="write"));
  assert.ok(ops.some(o=>o.op==="mmap"));
  // drive each
  const dev=k.deviceRegistry.find(d=>d.name==="rwdev");
  const r=await sendFileOp(k, dev, {op:"read", input: new Uint8Array(0), outputLen:16});
  assert.equal(r.status,"ok");
  assert.ok(r.outputHex.includes("726561646f6b")); // "readok"
  const w=await sendFileOp(k, dev, {op:"write", input: new Uint8Array([1,2,3]), outputLen:4});
  assert.equal(w.status,"ok");
  const mm=await sendFileOp(k, dev, {op:"mmap", outputLen:8});
  assert.equal(mm.status,"ok");
  // proc
  const procDev=k.deviceRegistry.find(d=>d.name.includes("myproc"));
  assert.ok(procDev);
  const pr=await sendFileOp(k, procDev, {op:"proc_show", input: new Uint8Array(0), outputLen:16});
  assert.equal(pr.status,"ok");
  // netlink
  const nlDev=k.deviceRegistry.find(d=>d.type==="netlink");
  assert.ok(nlDev);
  const nl=await sendFileOp(k, nlDev, {op:"netlink", input: new Uint8Array([1,2,3,4]), outputLen:8});
  assert.equal(nl.status,"ok");
});

test("FILE_OPS_OFF matches 6.6.18 pinned layout", ()=>{
  assert.equal(FILE_OPS_OFF.unlocked_ioctl, 0x30);
  assert.equal(FILE_OPS_OFF.read, 0x10);
  assert.equal(FILE_OPS_OFF.write, 0x18);
  assert.equal(FILE_OPS_OFF.SIZE, 0x80);
});

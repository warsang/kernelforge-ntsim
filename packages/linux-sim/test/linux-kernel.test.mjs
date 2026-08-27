import { test } from "node:test";
import assert from "node:assert/strict";
import { LinuxKernel } from "../src/linux-kernel.mjs";
import { parseElfKo, mapModule } from "../src/module-loader.mjs";
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

test("LinuxKernel: allocSlub and verifyGuards", ()=>{
  const k=new LinuxKernel({});
  const a=k.allocSlub(32,"test");
  assert.ok(a!==0n);
  assert.equal(k.verifyGuards().length,0);
  // corrupt guard
  k.mem.write(a+32n, new Uint8Array([0xff]));
  assert.equal(k.verifyGuards().length,1);
});

test("LinuxKernel: provisionUnknownApi and resolve", ()=>{
  const k=new LinuxKernel({});
  const va=k.resolveImportProvisioned("copy_from_user");
  assert.ok(va!==0n);
  const va2=k.resolveImportProvisioned("nonexistent_foo");
  assert.ok(va2!==0n);
  assert.ok(k.unmodeledExports.includes("nonexistent_foo"));
});

test("LinuxKernel: mapModule and init_module execution", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static struct file_operations fops;
static int __init myinit(void){ register_chrdev(240,"test", &fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const parsed=parseElfKo(bytes);
  const k=new LinuxKernel({});
  const mapped=mapModule(k, parsed, 0xffffffffc0000000n, (n)=>k.resolveImportProvisioned(n));
  assert.ok(mapped.init);
  const res=k.callFunctionSeh(mapped.init, [], {});
  assert.equal(res.status,"ok");
  assert.equal(k.deviceRegistry.length,1);
  assert.equal(k.deviceRegistry[0].name,"test");
});

test("LinuxKernel: copy_from_user emulation", async ()=>{
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
MODULE_LICENSE("GPL");
static long myread(struct file *f, char __user *buf, size_t len, loff_t *off){
  char kbuf[8]="hello";
  if(copy_to_user(buf, kbuf, 5)) return -1;
  return 5;
}
static struct file_operations fops={ .read=myread };
static int __init myinit(void){ register_chrdev(240,"rtest",&fops); return 0;}
module_init(myinit);
`;
  const bytes=compileKo(src);
  const parsed=parseElfKo(bytes);
  const k=new LinuxKernel({});
  const mapped=mapModule(k, parsed, 0xffffffffc0000000n, (n)=>k.resolveImportProvisioned(n));
  k.callFunctionSeh(mapped.init,[],{});
  const { sendFileOp } = await import("../src/file-ops.mjs");
  const dev=k.deviceRegistry[0];
  const r=await sendFileOp(k, dev, {op:"read", input: new Uint8Array(0), outputLen:16});
  assert.equal(r.status,"ok");
  assert.ok(r.outputHex.startsWith("68656c6c6f")); // "hello"
});

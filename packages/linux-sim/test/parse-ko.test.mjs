import { test } from "node:test";
import assert from "node:assert/strict";
import { parseElfKo, validateKo, ElfError } from "../src/module-loader.mjs";
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
    const bytes=readFileSync(oFile);
    return new Uint8Array(bytes);
  } finally { try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
}

test("parseElfKo: valid 64-bit ET_REL", ()=>{
  const src=`
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init myinit(void){return 0;}
module_init(myinit);
`;
  const bytes=compileKo(src);
  const parsed=parseElfKo(bytes);
  assert.equal(parsed.eiClass, 2);
  assert.equal(parsed.eType, 1);
  assert.equal(parsed.eMachine, 62);
  assert.ok(parsed.sections.some(s=>s.name===".text"));
  assert.ok(parsed.symbols.some(s=>s.name==="init_module"));
});

test("parseElfKo: rejects non-ELF", ()=>{
  assert.throws(()=> parseElfKo(new Uint8Array([0,1,2,3])), ElfError);
});

test("parseElfKo: rejects 32-bit", async ()=>{
  // use 32-bit object if available? skip
  const bytes=new Uint8Array(64);
  bytes[0]=0x7f; bytes[1]=0x45; bytes[2]=0x4c; bytes[3]=0x46;
  bytes[4]=1; // 32-bit
  bytes[5]=1;
  // need minimal header to trigger not 64-bit check
  bytes[16]=1; bytes[17]=0; // e_type
  bytes[18]=3; bytes[19]=0; // EM_386
  assert.throws(()=> parseElfKo(bytes), /not 64-bit/);
});

test("validateKo: detects .text", ()=>{
  const src=`
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init myinit(void){return 0;}
module_init(myinit);
`;
  const bytes=compileKo(src);
  const elf=validateKo(bytes);
  assert.ok(elf);
});

/**
 * module-loader.mjs — ELF64 ET_REL parsing + relocation + mapping for .ko
 * Target: x86_64 ELF64 ET_REL (EM_X86_64) for kernel 6.6.18
 * Browser-contained, no fs, pure Uint8Array.
 */

export class ElfError extends Error {}

const ELF_MAGIC = 0x464c457f; // \x7fELF LE
const EI_CLASS_64 = 2;
const ET_REL = 1;
const EM_X86_64 = 62;

const SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_NOBITS = 8;
const SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4;

const R_X86_64_NONE = 0, R_X86_64_64 = 1, R_X86_64_PC32 = 2, R_X86_64_GOT32 = 3, R_X86_64_PLT32 = 4, R_X86_64_32 = 10, R_X86_64_32S = 11;

function u16(b,o){ return b[o] | (b[o+1]<<8); }
function u32(b,o){ return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0; }
function u64(b,o){
  const lo = BigInt(u32(b,o));
  const hi = BigInt(u32(b,o+4));
  return (hi<<32n)|lo;
}
function i32(v){ return (v<<0)>>0; }

export function parseElfKo(bytes){
  if(!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  if(bytes.length < 64) throw new ElfError("truncated: shorter than ELF64 header");
  if(u32(bytes,0)!==ELF_MAGIC) throw new ElfError("bad magic: not ELF");
  const eiClass = bytes[4];
  const eiData = bytes[5];
  if(eiData!==1) throw new ElfError("only little-endian ELF supported");
  const eType = u16(bytes,16);
  const eMachine = u16(bytes,18);
  const eVersion = u32(bytes,20);
  const eEntry = u64(bytes,24);
  const ePhoff = u64(bytes,32);
  const eShoff = u64(bytes,40);
  const eFlags = u32(bytes,48);
  const eEhsize = u16(bytes,52);
  const ePhentsize = u16(bytes,54);
  const ePhnum = u16(bytes,56);
  const eShentsize = u16(bytes,58);
  const eShnum = u16(bytes,60);
  const eShstrndx = u16(bytes,62);

  if(eiClass!==EI_CLASS_64) throw new ElfError(`not 64-bit ELF (EI_CLASS=${eiClass}) — expected x86_64`);
  if(eMachine!==EM_X86_64) throw new ElfError(`wrong machine 0x${eMachine.toString(16)} — expected EM_X86_64`);
  if(eType!==ET_REL) throw new ElfError(`not relocatable (e_type=${eType}) — .ko must be ET_REL`);
  if(Number(eShoff)===0 || eShnum===0 || eShentsize===0) throw new ElfError("no section headers");

  const shoff = Number(eShoff);
  const shnum = eShnum;
  const shentsize = eShentsize;
  const headers=[];
  for(let i=0;i<shnum;i++){
    const off=shoff+i*shentsize;
    if(off+64>bytes.length) throw new ElfError("section header truncated");
    headers.push({
      sh_name: u32(bytes,off),
      sh_type: u32(bytes,off+4),
      sh_flags: u64(bytes,off+8),
      sh_addr: u64(bytes,off+16),
      sh_offset: u64(bytes,off+24),
      sh_size: u64(bytes,off+32),
      sh_link: u32(bytes,off+40),
      sh_info: u32(bytes,off+44),
      sh_addralign: u64(bytes,off+48),
      sh_entsize: u64(bytes,off+56),
    });
  }
  const strTabHdr = headers[eShstrndx];
  if(!strTabHdr) throw new ElfError("missing shstrtab");
  const strTabBase = Number(strTabHdr.sh_offset);
  const cstr=(base,off)=>{
    let end=off;
    while(base+end < bytes.length && bytes[base+end]!==0) end++;
    let s="";
    for(let i=off;i<end;i++) s+=String.fromCharCode(bytes[base+i]);
    return s;
  };
  const secName=(h)=>cstr(strTabBase, h.sh_name);
  const sections = headers.map((h,i)=>({
    idx:i,
    name: secName(h),
    type: h.sh_type,
    flags: h.sh_flags,
    addr: h.sh_addr,
    offset: h.sh_offset,
    size: h.sh_size,
    link: h.sh_link,
    info: h.sh_info,
    addralign: h.sh_addralign,
    entsize: h.sh_entsize,
    hdr: h,
    data: (h.sh_type===SHT_NOBITS) ? null : bytes.slice(Number(h.sh_offset), Number(h.sh_offset+h.sh_size)),
  }));

  // symbols
  let symbols=[];
  const symIdx = headers.findIndex(h=>h.sh_type===SHT_SYMTAB);
  if(symIdx>=0){
    const symHdr=headers[symIdx];
    const strHdr=headers[symHdr.sh_link];
    if(!strHdr) throw new ElfError("symtab without linked strtab");
    const strBase=Number(strHdr.sh_offset);
    const count = Number(symHdr.sh_size / 24n); // Elf64_Sym 24
    for(let i=0;i<count;i++){
      const off=Number(symHdr.sh_offset)+i*24;
      const st_name=u32(bytes,off);
      const st_info=bytes[off+4];
      const st_other=bytes[off+5];
      const st_shndx=u16(bytes,off+6);
      const st_value=u64(bytes,off+8);
      const st_size=u64(bytes,off+16);
      const bind = st_info>>4, type=st_info&0xf;
      const name=cstr(strBase, st_name);
      symbols.push({ idx:i, name, value: st_value, size: st_size, shndx: st_shndx, bind, type, info: st_info, other: st_other });
    }
  }

  // relas: collect per section
  const relas=[];
  for(const sec of sections){
    if(sec.type===SHT_RELA){
      const cnt = Number(sec.size / 24n);
      for(let i=0;i<cnt;i++){
        const off=Number(sec.offset)+i*24;
        const r_offset=u64(bytes,off);
        const r_info=u64(bytes,off+8);
        const r_addend = (()=>{ const v=u64(bytes,off+16); // signed? treat as signed 64
          return BigInt.asIntN(64, v);
        })();
        const r_sym = Number(r_info >> 32n);
        const r_type = Number(r_info & 0xffffffffn);
        relas.push({ section: sec, targetSecIdx: sec.info, r_offset, r_info, r_addend, r_sym, r_type, sym: symbols[r_sym] || null });
      }
    }
  }

  // .modinfo parsing
  let modinfo=null;
  const modSec=sections.find(s=>s.name===".modinfo");
  if(modSec && modSec.data){
    const txt = new TextDecoder().decode(modSec.data);
    const entries={};
    for(const part of txt.split("\x00")){
      if(!part) continue;
      const eq=part.indexOf("=");
      if(eq>0) entries[part.slice(0,eq)]=part.slice(eq+1);
    }
    modinfo=entries;
  }

  return {
    eiClass, eType, eMachine, eEntry,
    ePhoff, eShoff, eFlags, eEhsize, ePhentsize, ePhnum, eShentsize, eShnum, eShstrndx,
    headers, sections, symbols, relas, modinfo,
    bytes,
  };
}

export function validateKo(bytes){
  const elf=parseElfKo(bytes);
  const hasText = elf.sections.some(s=>s.name===".text" && s.size>0n);
  if(!hasText) throw new ElfError("no .text section — not a kernel module object?");
  // vermagic check (warn not fail) caller can inspect elf.modinfo?.vermagic
  return elf;
}

/**
 * Apply relocations to already-copied sections in memory.
 * @param {object} kernel LinuxKernel with mem
 * @param {bigint} base load base
 * @param {object} parsed parseElfKo result
 * @param {Map<string,bigint>} sectionAddrs map section idx -> runtime VA (base+sh_addr calculated)
 * @param {(name:string)=>bigint|null} resolveExternal
 * @returns {{applied:number, unresolved:string[]}}
 */
export function applyRelocs(kernel, base, parsed, sectionAddrs, resolveExternal){
  let applied=0;
  const unresolved=[];
  for(const rela of parsed.relas){
    const targetSecIdx = rela.targetSecIdx;
    const targetSecAddr = sectionAddrs.get(targetSecIdx);
    if(targetSecAddr===undefined) continue;
    const patchAddr = targetSecAddr + rela.r_offset;
    const sym = rela.sym;
    let symVal=null;
    let symName=null;
    if(sym){
      symName = sym.name;
      if(sym.shndx===0){ // SHN_UNDEF
        const ext = resolveExternal(sym.name);
        if(ext!==null && ext!==undefined) symVal = BigInt(ext);
        else {
          unresolved.push(sym.name);
          continue;
        }
      } else if(sym.shndx===0xfff1){ // SHN_ABS?
        symVal = sym.value;
      } else {
        // defined within module: section relative
        const secAddr = sectionAddrs.get(sym.shndx);
        if(secAddr===undefined){
          // maybe absolute? use value as is
          symVal = base + sym.value;
        } else {
          symVal = secAddr + (sym.value - parsed.sections[sym.shndx].addr); // if sh_addr not zero? Typically relocatable has sh_addr 0, so value is offset within section
          // But for ET_REL with sh_addr 0, sym.value is offset within its section file. So add secAddr.
          // If sh_addr was non-zero in input, adjust: sym.value already includes sec addr? For ET_REL usually 0. So this formula works if we approximate.
          // Simpler: secAddr + sym.value
          symVal = secAddr + sym.value;
          // However if parsed section had sh_addr !=0, double counts; but ET_REL usually 0.
          // We'll use secAddr + sym.value without subtract.
          // Correction: Actually sym.value for ET_REL is offset within section, so secAddr + sym.value is correct.
          // Let's keep that.
          symVal = sectionAddrs.get(sym.shndx) + sym.value;
        }
      }
    } else {
      // reloc against no sym? should not happen
      continue;
    }
    const addend = rela.r_addend;
    const A = addend;
    const P = patchAddr;
    let result;
    switch(rela.r_type){
      case R_X86_64_64:
        result = symVal + A;
        kernel.mem.w64(P, result);
        applied++;
        break;
      case R_X86_64_PC32:
      case R_X86_64_PLT32:
        result = symVal + A - P;
        // i32 check
        if(result < -0x80000000n || result > 0x7fffffff) {
          // For emulator we still write low 32, but warn via dbglog
          kernel.dbgLog.push(`[loader] PC32 reloc out of range at 0x${P.toString(16)} sym ${symName} delta ${result.toString(16)}`);
        }
        kernel.mem.w32(P, Number(result & 0xffffffffn));
        applied++;
        break;
      case R_X86_64_32:
        result = symVal + A;
        if(result < 0n || result > 0xffffffffn) kernel.dbgLog.push(`[loader] 32 reloc trunc at 0x${P.toString(16)} sym ${symName} val 0x${result.toString(16)}`);
        kernel.mem.w32(P, Number(result & 0xffffffffn));
        applied++;
        break;
      case R_X86_64_32S:
        result = symVal + A;
        // check if fits in signed 32 after truncation (sign-extended)
        if(BigInt.asIntN(64, BigInt.asIntN(32, result)) !== BigInt.asIntN(64, result)){
          kernel.dbgLog.push(`[loader] 32S reloc trunc at 0x${P.toString(16)} sym ${symName} val 0x${result.toString(16)}`);
        }
        kernel.mem.w32(P, Number(result & 0xffffffffn));
        applied++;
        break;
      case R_X86_64_NONE:
        break;
      default:
        kernel.dbgLog.push(`[loader] unhandled rela type ${rela.r_type} for ${symName} at 0x${P.toString(16)}`);
        break;
    }
  }
  return { applied, unresolved };
}

/**
 * Map module sections into kernel memory at base, apply relocs.
 * Returns {base, size, sectionsMapped, applied, entry: init_module VA, cleanup: cleanup_module VA}
 */
export function mapModule(kernel, parsed, base, resolveExternal){
  base = BigInt(base);
  // Use explicit vermagic from .modinfo as source of truth for version dispatch (not hardcoded buildName)
  if(parsed.modinfo?.vermagic){
    kernel.vermagic = parsed.modinfo.vermagic;
    kernel.buildName = kernel.vermagic; // for display
  }
  // Determine overall size: max (sh_addr+sh_size) among SHF_ALLOC
  let maxEnd=0n;
  for(const s of parsed.sections){
    if((s.flags & BigInt(SHF_ALLOC))!==0n){
      const end = s.addr + s.size;
      if(end > maxEnd) maxEnd = end;
    }
  }
  // If sh_addr are 0 for relocatable, we need to layout sequentially page-aligned like linkdriver
  // Detect: if any SHF_ALLOC section has sh_addr==0, layout needed.
  const needsLayout = parsed.sections.some(s=> (s.flags & BigInt(SHF_ALLOC))!==0n && s.addr===0n);
  const sectionAddrs = new Map();
  let imageSize;
  if(needsLayout){
    // Sequential layout: sort by addralign, place 16-aligned, like coff linkSections
    let cur = base;
    const alignUp=(v,a)=>{ const m=v % a; return m===0n ? v : v + (a - m); };
    for(const s of parsed.sections){
      if((s.flags & BigInt(SHF_ALLOC))===0n) continue;
      const align = s.addralign ? s.addralign : 16n;
      cur = alignUp(cur, align);
      sectionAddrs.set(s.idx, cur);
      const sz = s.size;
      if(s.type!==SHT_NOBITS && s.data){
        kernel.mem.write(cur, s.data);
      } else if(s.type===SHT_NOBITS){
        // BSS zero fill: ensure pages exist with zeros
        // SparseMemory read-as-zero so just ensure backing for writes that assume presence
        // Ensure pages exist
        const end = cur + sz;
        for(let p=cur & ~0xfffn; p < end; p+=0x1000n){
          if(!kernel.mem.hasPage(p)) kernel.mem.write(p, new Uint8Array(0x1000));
        }
      }
      // zero pad to aligned?
      cur += sz;
      // align next to 16
      cur = alignUp(cur, 16n);
    }
    imageSize = Number(cur - base);
  } else {
    // Use sh_addr as RVA (already linked .ko with absolute addrs)
    for(const s of parsed.sections){
      if((s.flags & BigInt(SHF_ALLOC))===0n) continue;
      const va = base + s.addr;
      sectionAddrs.set(s.idx, va);
      if(s.type!==SHT_NOBITS && s.data){
        kernel.mem.write(va, s.data);
      } else if(s.type===SHT_NOBITS){
        const end = va + s.size;
        for(let p=va & ~0xfffn; p < end; p+=0x1000n){
          if(!kernel.mem.hasPage(p)) kernel.mem.write(p, new Uint8Array(0x1000));
        }
      }
    }
    imageSize = Number(maxEnd);
  }
  // materialize gaps for unicorn parity
  try { kernel.materializeModuleRange?.(base, imageSize, {fill:0}); } catch{}
  const apply = applyRelocs(kernel, base, parsed, sectionAddrs, resolveExternal);
  // Find init/cleanup
  const initSym = parsed.symbols.find(s=>s.name==="init_module");
  const cleanupSym = parsed.symbols.find(s=>s.name==="cleanup_module");
  let initVA=null, cleanupVA=null;
  if(initSym){
    const secAddr = sectionAddrs.get(initSym.shndx);
    if(secAddr!==undefined) initVA = secAddr + initSym.value;
    else initVA = base + initSym.value;
  }
  if(cleanupSym){
    const secAddr = sectionAddrs.get(cleanupSym.shndx);
    if(secAddr!==undefined) cleanupVA = secAddr + cleanupSym.value;
    else cleanupVA = base + cleanupSym.value;
  }
  return {
    base, imageSize, sectionAddrs, applied: apply.applied, unresolved: apply.unresolved,
    init: initVA, cleanup: cleanupVA,
    sections: parsed.sections.filter(s=> (s.flags & BigInt(SHF_ALLOC))!==0n).map(s=>({name:s.name, va: sectionAddrs.get(s.idx)?.toString(16), size: Number(s.size)})),
    modinfo: parsed.modinfo,
  };
}

/**
 * kdmp-parser JS port (from 0vercl0k/kdmp-parser, MIT) — parses Windows
 * kernel crash dumps (full / BMP / kernel-memory / complete types) and
 * exposes physical + virtual page access. Used to carve genuine ntoskrnl
 * bytes into ntsim and, later, for live dump analysis in the browser.
 *
 * All offsets per the C++ HEADER64 layout; DataView little-endian.
 */

const PAGE_SIZE = 0x1000;

export const DumpType = {
  FullDump: 1,
  KernelDump: 2,
  BMPDump: 4,
  MiniDump: 5,
  LiveKernelBitmapDump: 6,
  KernelMemoryDump: 8,
  KernelAndUserMemoryDump: 9,
  CompleteMemoryDump: 10,
};

/** x64 VA split (bits identical to kdmpparser::VIRTUAL_ADDRESS). */
export function splitVa(va) {
  return {
    offset: Number(va & 0xfffn),
    ptIndex: Number((va >> 12n) & 0x1ffn),
    pdIndex: Number((va >> 21n) & 0x1ffn),
    pdPtIndex: Number((va >> 30n) & 0x1ffn),
    pml4Index: Number((va >> 39n) & 0x1ffn),
  };
}

export class KdmpParser {
  /** @param {ArrayBuffer} buf raw .dmp bytes */
  constructor(buf) {
    this.u8 = new Uint8Array(buf);
    this.dv = new DataView(buf);

    if (this.dv.getUint32(0x0000, true) !== 0x45474150 /* EGAP */) {
      throw new Error("bad dump signature");
    }
    if (this.dv.getUint32(0x0004, true) !== 0x34365544 /* 46UD */) {
      throw new Error("bad ValidDump");
    }

    this.header = {
      majorVersion: this.dv.getUint32(0x0008, true),
      minorVersion: this.dv.getUint32(0x000c, true),
      directoryTableBase: this.dv.getBigUint64(0x0010, true),
      pfnDatabase: this.dv.getBigUint64(0x0018, true),
      psLoadedModuleList: this.dv.getBigUint64(0x0020, true),
      psActiveProcessHead: this.dv.getBigUint64(0x0028, true),
      machineImageType: this.dv.getUint32(0x0030, true),
      numberProcessors: this.dv.getUint32(0x0034, true),
      bugCheckCode: this.dv.getUint32(0x0038, true),
      bugCheckParameters: [
        this.dv.getBigUint64(0x0040, true),
        this.dv.getBigUint64(0x0048, true),
        this.dv.getBigUint64(0x0050, true),
        this.dv.getBigUint64(0x0058, true),
      ],
      kdDebuggerDataBlock: this.dv.getBigUint64(0x0080, true),
      // CONTEXT record lives at 0x0348 (3000 bytes)
      contextOffset: 0x0348,
      dumpType: this.dv.getUint32(0x0f98, true),
    };

    /** @type {Map<string, number>} PA hex string -> file offset */
    this.physmem = new Map();
    this._buildPhysmem();
  }

  _buildPhysmem() {
    const t = this.header.dumpType;
    if (t === DumpType.FullDump) {
      this._buildFull();
    } else if (t === DumpType.LiveKernelBitmapDump || t === DumpType.BMPDump) {
      this._buildBmp();
    } else if (
      t === DumpType.KernelMemoryDump ||
      t === DumpType.KernelAndUserMemoryDump ||
      t === DumpType.CompleteMemoryDump
    ) {
      this._buildRdmp(t);
    } else {
      throw new Error(`unsupported dump type ${t}`);
    }
  }

  // FullDump: runs describe PFN ranges; pages follow the header directly.
  _buildFull() {
    // PHYSMEM_DESC at u1 = 0x0088:
    //   { uint32 NumberOfRuns (0x88); uint64 NumberOfPages (0x90);
    //     runs start 0x98: { uint64 BasePage; uint64 PageCount } each 16B }
    const numberOfRuns = this.dv.getUint32(0x0088, true);
    let runOff = 0x0098;
    let runBase = 0x2000; // pages follow the 0x2000-byte header
    for (let i = 0; i < numberOfRuns; i++) {
      const basePage = this.dv.getBigUint64(runOff, true);
      const pageCount = this.dv.getBigUint64(runOff + 8, true);
      for (let p = 0n; p < pageCount; p++) {
        const pfn = basePage + p;
        const pa = pfn * BigInt(PAGE_SIZE);
        this.physmem.set(pa.toString(16), runBase + Number(p) * PAGE_SIZE);
      }
      runBase += Number(pageCount) * PAGE_SIZE;
      runOff += 16;
    }
  }

  // BMP/LiveKernel: bitmap of PFNs; FirstPage points at first page blob.
  _buildBmp() {
    // BMP_HEADER64 at 0x2000 (exact layout from kdmp-parser-structs.h):
    //   u32 Signature@0x00  u32 ValidDump@0x04  pad[24] @0x08
    //   u64 FirstPage@0x20  u64 TotalPresentPages@0x28  u64 Pages@0x30
    //   u8 Bitmap[]@0x38   (bit i => PFN i; pages packed sequentially)
    const bmpBase = 0x2000;
    const sig = this.dv.getUint32(bmpBase, true);
    if (sig !== 0x5344504d /* SDPM */ && sig !== 0x4644504d /* FDMP */) {
      throw new Error("bad BMP header signature");
    }
    if (this.dv.getUint32(bmpBase + 4, true) !== 0x55444d50 /* PMUD */) {
      throw new Error("bad BMP ValidDump");
    }
    const firstPage = this.dv.getBigUint64(bmpBase + 0x20, true);
    const totalBitmapPages = this.dv.getBigUint64(bmpBase + 0x30, true);
    const bitmapOff = bmpBase + 0x38;
    const bitmapSize = Number(totalBitmapPages / 8n);

    let pageFileOff = Number(firstPage);
    for (let byteIdx = 0; byteIdx < bitmapSize && byteIdx * 8 < this.u8.length - bitmapOff; byteIdx++) {
      const byte = this.u8[bitmapOff + byteIdx];
      for (let bit = 0; bit < 8; bit++) {
        if (((byte >> bit) & 1) !== 1) continue;
        const pfn = byteIdx * 8 + bit;
        const pa = pfn * PAGE_SIZE;
        if (pageFileOff + PAGE_SIZE > this.u8.length) return;
        this.physmem.set(pa.toString(16), pageFileOff);
        pageFileOff += PAGE_SIZE;
      }
    }
  }


  // RDMP ('new' dumps): metadata is PfnRange[] {PageFileNumber, NumberOfPages},
  // bitmap area holds the ranges, pages follow FirstPageOffset.
  _buildRdmp(type) {
    const isComplete = type === DumpType.CompleteMemoryDump;
    const hdrBase = 0x2000;
    const firstPageOffset = isComplete
      ? this.dv.getBigUint64(hdrBase + 0x28, true) // FullRdmpHeader.Hdr.FirstPageOffset
      : this.dv.getBigUint64(hdrBase + 0x20, true);
    const metadataSize = this.dv.getBigUint64(
      isComplete ? hdrBase + 0x40 : hdrBase + 0x38, true);
    void metadataSize;
    // RDMP layouts vary across builds; fall back to a linear scan heuristic:
    // treat [firstPageOffset, EOF) as sequential present pages with unknown
    // PFNs is WRONG, so we instead require an explicit range table which we
    // locate via the documented fields when possible.
    //
    // NOTE: full RDMP support lands with the real sample dump (carve script
    // validates against known EPROCESS chain); see carve-dump.mjs.
    throw new Error("RDMP dump support requires validation sample — see carve script");
  }

  /** Physical page -> Uint8Array view (length PAGE_SIZE) or null. */
  getPhysicalPage(physicalAddress) {
    const pa = BigInt(physicalAddress);
    const aligned = pa - (pa % BigInt(PAGE_SIZE));
    const off = this.physmem.get(aligned.toString(16));
    if (off === undefined) return null;
    return this.u8.subarray(off, off + PAGE_SIZE);
  }

  phyRead8(physicalAddress) {
    const pa = BigInt(physicalAddress);
    const page = this.getPhysicalPage(pa);
    if (!page) return null;
    const off = Number(pa % BigInt(PAGE_SIZE));
    return this.dv.getBigUint64(page.byteOffset + off, true);
  }

  /**
   * 4-level x64 page walk (mirrors VirtTranslate). Handles 1GB/2MB large pages.
   * @returns {bigint|null} physical address or null when not present
   */
  virtTranslate(virtualAddress, directoryTableBase = 0n) {
    const dtb = (directoryTableBase || this.header.directoryTableBase) &
      ~0xfffn;
    const idx = splitVa(virtualAddress);

    const pml4Base = dtb; // reference treats DTB as PTE: PFN = dtb >> 12 == aligned dtb
    const pml4e = this.phyRead8(pml4Base + BigInt(idx.pml4Index) * 8n);
    if (pml4e === null || !(pml4e & 1n)) return null;

    const pdptBase = (pml4e >> 12n) << 12n;
    const pdpte = this.phyRead8(pdptBase + BigInt(idx.pdPtIndex) * 8n);
    if (pdpte === null || !(pdpte & 1n)) return null;
    if ((pdpte >> 7n) & 1n) {
      // 1GB page
      return ((pdpte >> 12n) << 12n) + (virtualAddress & 0x3fffffffn);
    }

    const pdBase = (pdpte >> 12n) << 12n;
    const pde = this.phyRead8(pdBase + BigInt(idx.pdIndex) * 8n);
    if (pde === null || !(pde & 1n)) return null;
    if ((pde >> 7n) & 1n) {
      // 2MB page
      return ((pde >> 12n) << 12n) + (virtualAddress & 0x1fffffn);
    }

    const ptBase = (pde >> 12n) << 12n;
    const pte = this.phyRead8(ptBase + BigInt(idx.ptIndex) * 8n);
    if (pte === null || !(pte & 1n)) return null;

    return ((pte >> 12n) << 12n) + BigInt(idx.offset);
  }

  /** Virtual address -> page bytes, or null. */
  getVirtualPage(virtualAddress, dtb = 0n) {
    const pa = this.virtTranslate(virtualAddress, dtb);
    if (pa === null) return null;
    return this.getPhysicalPage(Number(pa));
  }

  /** Read len bytes at a virtual address (may span pages). */
  readVirtual(virtualAddress, len, dtb = 0n) {
    const out = new Uint8Array(len);
    let done = 0n;
    while (done < BigInt(len)) {
      const va = virtualAddress + done;
      const page = this.getVirtualPage(va, dtb);
      if (!page) return null;
      const off = Number(va & 0xfffn);
      const chunk = Math.min(PAGE_SIZE - off, len - Number(done));
      out.set(page.subarray(off, off + chunk), Number(done));
      done += BigInt(chunk);
    }
    return out;
  }
}

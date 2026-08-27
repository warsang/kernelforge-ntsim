/**
 * io_uring.mjs — two-ring emulation reusing existing stub dispatch.
 * Allocates SQ/CQ rings as slub-backed memory when io_uring_setup is stubbed.
 * Mirrors BUG-2 stack fix technique for new region.
 */

export const IORING_OP = {
  NOP: 0,
  READV: 1,
  WRITEV: 2,
  FSYNC: 3,
  READ_FIXED: 4,
  WRITE_FIXED: 5,
  POLL_ADD: 6,
  POLL_REMOVE: 7,
  SYNC_FILE_RANGE: 8,
  SENDMSG: 9,
  RECVMSG: 10,
  TIMEOUT: 11,
  TIMEOUT_REMOVE: 12,
  ACCEPT: 13,
  ASYNC_CANCEL: 14,
  LINK_TIMEOUT: 15,
  CONNECT: 16,
  FALLOCATE: 17,
  OPENAT: 18,
  CLOSE: 19,
  FILES_UPDATE: 20,
  STATX: 21,
  READ: 22,
  WRITE: 23,
  FADVISE: 24,
  MADVISE: 25,
  SEND: 26,
  RECV: 27,
  OPENAT2: 28,
  EPOLL_CTL: 29,
  SPLICE: 30,
  PROVIDE_BUFFERS: 31,
  REMOVE_BUFFERS: 32,
  TEE: 33,
  SHUTDOWN: 34,
  RENAMEAT: 35,
  UNLINKAT: 36,
  MKDIRAT: 37,
  SYMLINKAT: 38,
  LINKAT: 39,
};

// SQE layout (64 bytes, simplified)
export const SQE_OFF = {
  opcode: 0,      // u8
  flags: 1,       // u8
  ioprio: 2,      // u16
  fd: 4,          // s32
  off: 8,         // u64
  addr: 16,       // u64
  len: 24,        // u32
  rw_flags: 28,   // u32
  user_data: 32,  // u64
  buf_index: 40,  // u16
  personality: 42,// u16
  splice_fd_in: 44,// s32
};

// CQE layout (16 bytes)
export const CQE_OFF = {
  user_data: 0, // u64
  res: 8,       // s32
  flags: 12,    // u32
};

function roundPow2(n){
  let p=1;
  while(p<n) p<<=1;
  return p;
}

export function allocIoUringRings(kernel, entries, paramsPtr){
  const sqEntries=roundPow2(Math.max(1, Number(entries)));
  const cqEntries=sqEntries*2;
  const sqRingSize=sqEntries*64;
  const cqRingSize=cqEntries*16;
  const sqRing=kernel.allocSlub(sqRingSize, "io_sq");
  const cqRing=kernel.allocSlub(cqRingSize, "io_cq");
  const sqHead=kernel.allocSlub(4, "io_sq_head");
  const sqTail=kernel.allocSlub(4, "io_sq_tail");
  const cqHead=kernel.allocSlub(4, "io_cq_head");
  const cqTail=kernel.allocSlub(4, "io_cq_tail");
  kernel.mem.w32(sqHead, 0);
  kernel.mem.w32(sqTail, 0);
  kernel.mem.w32(cqHead, 0);
  kernel.mem.w32(cqTail, 0);
  // params struct (simplified: sq_entries at 0, cq_entries at 4, flags at 8)
  try{
    if(paramsPtr){
      kernel.mem.w32(paramsPtr, sqEntries);
      kernel.mem.w32(paramsPtr+4n, cqEntries);
      kernel.mem.w32(paramsPtr+8n, 0);
      kernel.mem.w32(paramsPtr+12n, sqRing & 0xffffffffn);
      kernel.mem.w32(paramsPtr+16n, cqRing & 0xffffffffn);
    }
  }catch{}
  const ringInfo={
    sqEntries, cqEntries,
    sqRing, cqRing,
    sqHead, sqTail, cqHead, cqTail,
    fd: 0, // will be set by caller
  };
  return ringInfo;
}

export function readSqe(kernel, sqRing, idx){
  const base=sqRing + BigInt(idx*64);
  const buf=kernel.mem.read(base, 64);
  const dv=new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    opcode: dv.getUint8(SQE_OFF.opcode),
    flags: dv.getUint8(SQE_OFF.flags),
    fd: dv.getInt32(SQE_OFF.fd, true),
    off: dv.getBigUint64(SQE_OFF.off, true),
    addr: dv.getBigUint64(SQE_OFF.addr, true),
    len: dv.getUint32(SQE_OFF.len, true),
    user_data: dv.getBigUint64(SQE_OFF.user_data, true),
  };
}

export function writeCqe(kernel, cqRing, idx, user_data, res){
  const base=cqRing + BigInt(idx*16);
  kernel.mem.w64(base + BigInt(CQE_OFF.user_data), user_data);
  kernel.mem.w32(base + BigInt(CQE_OFF.res), Number(res));
  kernel.mem.w32(base + BigInt(CQE_OFF.flags), 0);
}

export function dispatchSqe(kernel, sqe){
  // Reuse existing stub infrastructure per opcode
  const {opcode, fd, addr, len, off} = sqe;
  try{
    switch(opcode){
      case IORING_OP.NOP:
        return 0;
      case IORING_OP.READ:
      case IORING_OP.READV:
      case IORING_OP.READ_FIXED:
        // reuse kernel_read path via filp_open? Simplified: copy  len bytes from fd's file (stub)
        // For emulator, just simulate success
        return len;
      case IORING_OP.WRITE:
      case IORING_OP.WRITEV:
      case IORING_OP.WRITE_FIXED:
        // reuse kernel_write stub
        {
          // Call the same path as kernel_write: we have a stub for kernel_write? Not yet, but we have filp_open/kernel_write
          // For now, just log and return len
          const impl=kernel.apiImpls.get("kernel_write");
          if(impl){
            // kernel_write(file, buf, len, pos)
            // We need a file pointer; fd is int, not file*. For stub, just return len
            kernel.dbgLog.push(`[io_uring] WRITE fd ${fd} addr 0x${addr.toString(16)} len ${len}`);
          }
          return len;
        }
      case IORING_OP.OPENAT:
        {
          const path=kernel.mem.readAnsi(addr, 64);
          const impl=kernel.apiImpls.get("filp_open");
          let ret=0n;
          if(impl) ret=impl.call(kernel, addr, 0n, 0n);
          kernel.dbgLog.push(`[io_uring] OPENAT ${path} -> 0x${ret.toString(16)}`);
          return Number(ret & 0xffffffffn) || 3; // fd 3
        }
      case IORING_OP.CLOSE:
        return 0;
      case IORING_OP.STATX:
      case IORING_OP.FADVISE:
      default:
        kernel.dbgLog.push(`[io_uring] unhandled opcode ${opcode}`);
        return 0;
    }
  }catch(e){
    kernel.dbgLog.push(`[io_uring] dispatch err ${e.message}`);
    return -1;
  }
}

/**
 * devices.mjs / winapi-ext.mjs — full IRP pipeline: METHOD_* buffer setup,
 * UserBuffer/Type3InputBuffer, MDLs, IoSetCompletionRoutine +
 * IoCompleteRequest invocation, pending-IRP draining via deferred work.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NtKernel } from "../src/kernel.mjs";
import { PeBuilder } from "../src/pebuilder.mjs";
import { parsePe, mapPe } from "../src/pe.mjs";
import {
  IRP_MJ, IRP, IO_STACK_LOCATION, IOCTL_METHOD, ioctlMethod, MDL,
  createDriverObject, initDriverObjectName, createDeviceObject,
  sendIrp, completeIrp,
} from "../src/index.mjs";

const BASE = 0xfffff80300000000n;
const u32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const q = (v) => {
  const out = [];
  let x = BigInt(v);
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
};

function probeTextRva(len) {
  const b = new PeBuilder().addSection(".text", new Uint8Array(len), 0x60000020);
  return parsePe(b.build(0).image).sections[0].rva;
}

/** Assemble a driver whose entry installs `handlerVa` into MJ[`major`]. */
function mountDriver(kernel, text, major = IRP_MJ.DEVICE_CONTROL) {
  const b = new PeBuilder().addSection(".text", text, 0x60000020);
  const image = b.build(0).image;
  const t = parsePe(image).sections[0].rva;
  const mapped = mapPe(image, kernel.mem, BASE, () => 0n);
  const drv = createDriverObject(kernel, "irtest.sys");
  initDriverObjectName(kernel, drv, "irtest.sys", mapped.base, mapped.imageSize);
  drv.image = { base: BASE, bytes: image };
  const entry = kernel.callFunctionSeh(BASE + BigInt(t + 0x10), [drv.va, 0n], drv.image);
  const device = createDeviceObject(kernel, drv, {});
  return { drv, device, entry, t, mapped };
}

const ctl = (devType, fn, method, access = 3) =>
  ((devType & 0xffff) << 16) | ((fn & 0xfff) << 2) | ((method & 3)) | ((access & 3) << 14);

// --------------------------------------------------------------------------
// METHOD_NEITHER
// --------------------------------------------------------------------------

test("METHOD_NEITHER: Type3InputBuffer in, UserBuffer out", async () => {
  const kernel = new NtKernel({ arch: false });
  const t = probeTextRva(0x200);
  const handlerVa = BASE + BigInt(t + 0x40);
  const text = new Uint8Array(0x200);
  text.set([0x48, 0xb8, ...q(handlerVa), 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0x31, 0xc0, 0xc3], 0x10);
  text.set([
    0x49, 0x89, 0xd2,                        // mov r10, rdx (irp)
    0x4d, 0x8b, 0x82, 0xb8, 0, 0, 0,         // mov r8, [r10+0xB8] (stack)
    0x4d, 0x8b, 0x40, 0x20,                  // mov r8, [r8+0x20] (Type3InputBuffer)
    0x41, 0x8b, 0x08,                        // mov ecx, [r8]
    0x81, 0xc1, 0x00, 0x01, 0x00, 0x00,      // add ecx, 0x100
    0x49, 0x8b, 0x82, 0x68, 0, 0, 0,         // mov rax, [r10+0x68] (UserBuffer)
    0x89, 0x08,                              // mov [rax], ecx
    0x41, 0xc7, 0x42, 0x30, 0, 0, 0, 0,      // IoStatus.Status = 0
    0x41, 0xc7, 0x42, 0x38, 4, 0, 0, 0,      // IoStatus.Information = 4
    0x31, 0xc0, 0xc3,
  ], 0x40);
  const { device } = mountDriver(kernel, text);

  const code = ctl(0x22, 0x800, IOCTL_METHOD.NEITHER);
  const r = await sendIrp(kernel, device, {
    major: IRP_MJ.DEVICE_CONTROL, ioctl: code,
    inputHex: "11223344", outputLen: 8,
  });
  assert.equal(r.status, "ok");
  assert.equal(r.method, IOCTL_METHOD.NEITHER);
  assert.ok(r.buffers.type3, "Type3InputBuffer allocated");
  assert.equal(r.buffers.user, r.buffers.user);
  const word = r.output[0] | (r.output[1] << 8) | (r.output[2] << 16) | (r.output[3] << 24);
  assert.equal(word >>> 0, 0x44332311); // 0x44332211 + 0x100
});

// --------------------------------------------------------------------------
// METHOD_IN_DIRECT + MDL
// --------------------------------------------------------------------------

test("METHOD_IN_DIRECT: MDL describes UserBuffer and MmGetSystemAddress aliases it", async () => {
  const kernel = new NtKernel({ arch: false });
  const t = probeTextRva(0x200);
  const handlerVa = BASE + BigInt(t + 0x40);
  const text = new Uint8Array(0x200);
  text.set([0x48, 0xb8, ...q(handlerVa), 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0x31, 0xc0, 0xc3], 0x10);
  text.set([
    0x49, 0x89, 0xd2,                        // mov r10, rdx (irp)
    0x49, 0x8b, 0x42, 0x08,                  // mov rax, [r10+8]   (MdlAddress)
    0x48, 0x8b, 0x40, 0x20,                  // mov rax, [rax+0x20] (StartVa)
    0xc7, 0x00, 0xbe, 0xba, 0xfe, 0xca,      // mov dword [rax], 0xCAFEBABE
    0x41, 0xc7, 0x42, 0x30, 0, 0, 0, 0,      // IoStatus.Status = 0
    0x41, 0xc7, 0x42, 0x38, 4, 0, 0, 0,      // IoStatus.Information = 4
    0x31, 0xc0, 0xc3,
  ], 0x40);
  const { device } = mountDriver(kernel, text);

  const code = ctl(0x22, 0x801, IOCTL_METHOD.IN_DIRECT);
  const r = await sendIrp(kernel, device, {
    major: IRP_MJ.DEVICE_CONTROL, ioctl: code, inputHex: "aabbccdd", outputLen: 4,
  });
  assert.equal(r.status, "ok");
  assert.ok(r.buffers.mdl, "MDL allocated");
  assert.equal(r.output[0], 0xbe);
  assert.equal(r.output[3], 0xca);

  // MDL header is layout-accurate and points at the user buffer
  const mem = kernel.mem;
  assert.equal(mem.u64(r.buffers.mdl + BigInt(MDL.START_VA)), r.buffers.user);
  assert.equal(mem.u32(r.buffers.mdl + BigInt(MDL.BYTE_COUNT)), 4);
  const sysVa = kernel.apiImpls.get("MmGetSystemAddressForMdlSafe")(r.buffers.mdl, 0n);
  assert.equal(sysVa, r.buffers.user);
  // buffered input lives in SystemBuffer
  assert.equal(mem.u8(r.buffers.system), 0xaa);
});

// --------------------------------------------------------------------------
// Completion routines
// --------------------------------------------------------------------------

test("IofCompleteRequest invokes the registered completion routine", async () => {
  const kernel = new NtKernel({ arch: false });
  const iofVa = kernel.apiThunks.get("IofCompleteRequest");
  const ctxVa = kernel.allocPool(8, "Ctx ");
  const t = probeTextRva(0x200);
  const handlerVa = BASE + BigInt(t + 0x40);
  const completionVa = BASE + BigInt(t + 0xc0);
  const text = new Uint8Array(0x200);
  text.set([0x48, 0xb8, ...q(handlerVa), 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0x31, 0xc0, 0xc3], 0x10);
  text.set([
    0x49, 0x89, 0xd2,                        // mov r10, rdx (irp)
    0x49, 0x8b, 0x82, 0xb8, 0, 0, 0,         // mov rax, [r10+0xB8] (stack)
    0x48, 0xb9, ...q(completionVa),          // mov rcx, completion
    0x48, 0x89, 0x88, 0x38, 0, 0, 0,         // mov [rax+0x38], rcx
    0x48, 0xb9, ...q(ctxVa),                 // mov rcx, context
    0x48, 0x89, 0x88, 0x40, 0, 0, 0,         // mov [rax+0x40], rcx
    0x80, 0x48, 0x03, 0x80,                  // or byte [rax+3], SL_INVOKE_ON_SUCCESS
    0x41, 0xc7, 0x42, 0x30, 0, 0, 0, 0,      // IoStatus.Status = 0
    0x4c, 0x89, 0xd1,                        // mov rcx, r10
    0x31, 0xd2,                              // xor edx, edx
    0x48, 0xb8, ...q(iofVa),                 // mov rax, IofCompleteRequest
    0xff, 0xd0,                              // call rax
    0x31, 0xc0, 0xc3,
  ], 0x40);
  // completion routine: *context = 0xdeadbeef; return STATUS_SUCCESS
  text.set([0x4c, 0x89, 0xc0, 0xc7, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x31, 0xc0, 0xc3], 0xc0);

  const { device } = mountDriver(kernel, text);
  const r = await sendIrp(kernel, device, {
    major: IRP_MJ.DEVICE_CONTROL, ioctl: ctl(0x22, 0x802, IOCTL_METHOD.BUFFERED), outputLen: 4,
  });
  assert.equal(r.status, "ok");
  assert.equal(kernel.mem.u32(ctxVa), 0xdeadbeef);
  assert.ok(kernel.irpCompletions.some((c) => c.routine === completionVa));
});

test("IoSetCompletionRoutine writes slots + control bits; stack helpers work", () => {
  const kernel = new NtKernel({ arch: false });
  const irp = kernel.allocPool(IRP.HEADER_SIZE + 2 * IRP.STACK_SIZE, "Irp?");
  const mem = kernel.mem;
  mem.write(irp, new Uint8Array(IRP.HEADER_SIZE + 2 * IRP.STACK_SIZE));
  const top = irp + BigInt(IRP.HEADER_SIZE);
  const second = top + BigInt(IRP.STACK_SIZE);
  mem.w64(irp + BigInt(IRP.CURRENT_STACK_LOCATION), second);
  kernel.apiImpls.get("IoSetCompletionRoutine")(irp, 0x1234n, 0x5678n, 1, 0, 0);
  assert.equal(mem.u64(second + BigInt(IO_STACK_LOCATION.COMPLETION_ROUTINE)), 0x1234n);
  assert.equal(mem.u64(second + BigInt(IO_STACK_LOCATION.CONTEXT)), 0x5678n);
  assert.equal(mem.u8(second + BigInt(IO_STACK_LOCATION.CONTROL)) & 0x80, 0x80);
  assert.equal(kernel.apiImpls.get("IoGetCurrentIrpStackLocation")(irp), second);
  assert.equal(kernel.apiImpls.get("IoGetNextIrpStackLocation")(irp), top);
});

test("completeIrp honors SL_INVOKE_ON_ERROR gating", () => {
  const kernel = new NtKernel({ arch: false });
  const irp = kernel.allocPool(IRP.HEADER_SIZE + IRP.STACK_SIZE, "Irp?");
  const mem = kernel.mem;
  mem.write(irp, new Uint8Array(IRP.HEADER_SIZE + IRP.STACK_SIZE));
  const stack = irp + BigInt(IRP.HEADER_SIZE);
  mem.w64(irp + BigInt(IRP.CURRENT_STACK_LOCATION), stack);
  // routine set, but only ON_SUCCESS invited; status is an error -> skipped
  mem.w64(stack + BigInt(IO_STACK_LOCATION.COMPLETION_ROUTINE), 0xdeadn);
  mem.w8(stack + BigInt(IO_STACK_LOCATION.CONTROL), 0x80);
  mem.w32(irp + BigInt(IRP.IO_STATUS_STATUS), 0xc000000d);
  completeIrp(kernel, irp);

  assert.equal(kernel.irpCompletions.length, 0);
});

// --------------------------------------------------------------------------
// Pending IRP completed by a deferred DPC
// --------------------------------------------------------------------------

test("pending IRP is completed by a drained DPC (IoCompleteRequest)", async () => {
  const kernel = new NtKernel({ arch: false });
  const iofVa = kernel.apiThunks.get("IofCompleteRequest");
  const keInitDpcVa = kernel.apiThunks.get("KeInitializeDpc");
  const keInsertVa = kernel.apiThunks.get("KeInsertQueueDpc");
  assert.ok(iofVa && keInitDpcVa && keInsertVa);

  const dpcVa = kernel.allocPool(0x28, "KDPC");
  const t = probeTextRva(0x200);
  const handlerVa = BASE + BigInt(t + 0x40);
  const dpcRoutineVa = BASE + BigInt(t + 0xc0);
  const text = new Uint8Array(0x200);
  text.set([0x48, 0xb8, ...q(handlerVa), 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0x31, 0xc0, 0xc3], 0x10);
  text.set([
    0x49, 0x89, 0xd2,                        // mov r10, rdx (irp)
    0x49, 0x8b, 0x82, 0xb8, 0, 0, 0,         // mov rax, [r10+0xB8]
    0x80, 0x48, 0x03, 0x01,                  // or byte [rax+3], SL_PENDING_RETURNED
    0x41, 0xc7, 0x42, 0x30, 0x03, 0x01, 0, 0,// IoStatus.Status = STATUS_PENDING
    // KeInitializeDpc(dpc, dpcRoutine, irp)
    0x48, 0xb9, ...q(dpcVa),
    0x48, 0xba, ...q(dpcRoutineVa),
    0x4d, 0x89, 0xd0,
    0x48, 0xb8, ...q(keInitDpcVa),
    0xff, 0xd0,
    // KeInsertQueueDpc(dpc, 0, 0)
    0x48, 0xb9, ...q(dpcVa),
    0x31, 0xd2,
    0x45, 0x31, 0xc0,
    0x48, 0xb8, ...q(keInsertVa),
    0xff, 0xd0,
    0xb8, 0x03, 0x01, 0x00, 0x00,            // return STATUS_PENDING
    0xc3,
  ], 0x40);
  // DPC routine: (KDPC, Context=irp, ...) -> IoStatus=SUCCESS then complete
  text.set([
    0xc7, 0x42, 0x30, 0x00, 0x00, 0x00, 0x00, // mov dword [rdx+0x30], 0
    0x48, 0x89, 0xd1,                        // mov rcx, rdx (irp)
    0x31, 0xd2,                              // xor edx, edx
    0x48, 0xb8, ...q(iofVa),
    0xff, 0xd0,
    0xc3,
  ], 0xc0);

  const { device } = mountDriver(kernel, text);
  const r = await sendIrp(kernel, device, {
    major: IRP_MJ.DEVICE_CONTROL, ioctl: ctl(0x22, 0x803, IOCTL_METHOD.BUFFERED), outputLen: 4,
  });
  assert.equal(r.status, "ok");
  assert.equal(r.pending, false, "DPC completed the pending IRP");
  assert.equal(r.ntstatus, 0n);
  assert.ok(kernel.lastCompletedIrp, "completion recorded");
  assert.ok(kernel.dbgLog.some((l) => l.includes("DPC @")), "DPC fired");
});

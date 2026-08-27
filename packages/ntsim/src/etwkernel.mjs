/**
 * etwkernel.mjs — kernel ETW logger-context modeling for NtKernel (m26).
 *
 * Kernel ETW sessions (Autologger/CKCL-class) live in pool as
 * _WMI_LOGGER_CONTEXT structures. Their EnableFlags bitmask decides which
 * event classes the kernel even bothers to build; zero it and every
 * provider keeps "succeeding" while nothing reaches the trace buffers.
 *
 * Teaching anchor: logger contexts are NOT PatchGuard-protected state.
 * What watches them in the real world: EDR/Sysmon agents checksumming
 * their own sessions, Windows 11 tamper protection for secured loggers,
 * and consumer-side gap alarms when an expected stream goes quiet.
 *
 * Teaching layout (_WMI_LOGGER_CONTEXT subset):
 *   +0x00 LoggerId      u32
 *   +0x10 EnableFlags   u32   <- the blindfolding knob
 *   +0x14 GetCpuClock   u32
 */

export const WMI_LOGGER_FLAGS_OFFSET = 0x10;
export const WMI_LOGGER_CPUCLOCK_OFFSET = 0x14;

/** Install the logger registry + event pump onto an NtKernel. Idempotent. */
export function installEtwKernelModel(kernel) {
  if (kernel.etwLoggers) return kernel;

  /** @type {Array<{name:string, va:bigint, baseline:{flags:number, clock:number}}> } */
  kernel.etwLoggers = [];

  /**
   * Materialize a _WMI_LOGGER_CONTEXT-shaped struct at a fixed VA.
   */
  kernel.defineEtwLogger = function defineEtwLogger(opts) {
    const mem = kernel.mem;
    const va = opts.va ?? kernel.allocPool(0x20, "WmiL");
    mem.w32(va, opts.loggerId ?? 1);            // LoggerId
    mem.w32(va + BigInt(WMI_LOGGER_FLAGS_OFFSET), opts.enableFlags ?? 0xff);
    mem.w32(va + BigInt(WMI_LOGGER_CPUCLOCK_OFFSET), opts.getCpuClock ?? 1);
    const rec = {
      name: opts.name,
      va,
      baseline: {
        flags: Number(opts.enableFlags ?? 0xff),
        clock: Number(opts.getCpuClock ?? 1),
      },
    };
    kernel.etwLoggers.push(rec);
    return rec;
  };

  /** Live EnableFlags of a logger record. */
  kernel.loggerFlags = function loggerFlags(rec) {
    return kernel.mem.u32(rec.va + BigInt(WMI_LOGGER_FLAGS_OFFSET));
  };

  /**
   * Diff every logger against its boot baseline.
   * @returns {Array<{rec, current:number, baseline:number}>}
   */
  kernel.scanEtwTamper = function scanEtwTamper() {
    return (kernel.etwLoggers ?? [])
      .map((rec) => ({
        rec,
        current: kernel.loggerFlags(rec),
        baseline: rec.baseline.flags,
      }))
      .filter((x) => x.current !== x.baseline);
  };

  /**
   * Modeled CKCL emission: n kernel events attempt to flow through the
   * named logger's gate. Zeroed EnableFlags => silently suppressed.
   * @returns {{delivered:number, suppressed:number}}
   */
  kernel.pumpKernelEvents = function pumpKernelEvents(n, loggerName = "CKCL") {
    const rec = (kernel.etwLoggers ?? []).find((l) => l.name === loggerName);
    if (!rec) return { delivered: n, suppressed: 0 };
    const flags = kernel.loggerFlags(rec);
    if (flags === 0) return { delivered: 0, suppressed: n };
    // teaching model: any nonzero mask passes everything
    return { delivered: n, suppressed: 0 };
  };

  return kernel;
}

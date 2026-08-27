/**
 * Load a carved dump state (carve-dump.mjs output) into a SparseMemory,
 * keyed by VA. Used by NtKernel.bootFromDump for genuine-bytes mode.
 */

const PAGE = 0x1000;

/**
 * @param {import('./memory.mjs').SparseMemory} mem
 * @param {{pages: [string, string][], keyAddresses: Record<string,string>, modules: {name:string,base:string,size:number}[]}} state
 */
export function loadDumpState(mem, state) {
  let loaded = 0;
  for (const [vaHex, b64] of state.pages) {
    const buf = Buffer.from(b64, "base64");
    mem.write(BigInt("0x" + vaHex), buf);
    loaded++;
  }
  return {
    pagesLoaded: loaded,
    psLoadedModuleList: BigInt("0x" + state.keyAddresses.psLoadedModuleList),
    psActiveProcessHead: BigInt("0x" + state.keyAddresses.psActiveProcessHead),
    modules: state.modules.map((m) => ({
      name: m.name,
      base: BigInt("0x" + m.base),
      size: m.size,
    })),
  };
}

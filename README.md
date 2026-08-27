# kernelforge-ntsim
Browser-native emulated x64 Windows kernel (ntsim) + Unicorn hybrid backend + Linux sim.

Standalone packages:
- `@kernelforge/ntsim` - sparse memory, CPU interpreter, kernel, PE mapper, paging, SMM, winapi (249 exports) - MIT
- `@kernelforge/ntsim-assets` - Vergilius CC0 struct tables + kdmp parser - CC0-1.0
- `@kernelforge/ntsim-unicorn` - Unicorn/QEMU wasm backend + HybridCpuBackend - GPL-2.0
- `@kernelforge/linux-sim` - Linux kernel sim over ntsim memory - MIT

```bash
npm install @kernelforge/ntsim
npm test
```

Provenance: VergiliusProject CC0, Unicorn GPL-2.0, v86 BSD. See LEGAL.md.
Rebuild: `npm run vendor:ghidra` etc per package README.

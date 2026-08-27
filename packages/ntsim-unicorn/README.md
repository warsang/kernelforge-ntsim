# @kernelforge/ntsim-unicorn

High-fidelity CPU backend for [ntsim](../ntsim) built on the Unicorn engine
(QEMU TCG) compiled to WebAssembly.

**JsInterpreter remains the default backend for every lab and test.** This
package is opt-in infrastructure: a ~1 MB GPLv2 wasm bundle that only loads
when a scenario explicitly asks for it.

## When to use which backend

| | JsInterpreter (default) | UnicornCpuBackend |
|---|---|---|
| Determinism / grading | pinned semantics, byte-stable forever | tied to vendored binary version |
| ISA coverage | integer subset clang emits for kernel C; unknown opcodes **fail loudly** | full x86-64 (SSE, lock cmpxchg, …) |
| Debug tooling | plain JS state, trivial snapshots/replay | state behind wasm boundary |
| Bundle cost | zero | ~1 MB wasm, lazy-loaded |

Rule of thumb: grade and teach on `js`; use `unicorn` when a scenario needs
instructions the interpreter refuses, or as a differential oracle.

## Real kernel VAs — supported (TLB-VIRTUAL)

Unicorn ≥ 2.1's default softmmu masks physical addresses to x86_64's 52-bit PA
space, which breaks canonical kernel-half VAs when paging is off
([upstream #2010](https://github.com/unicorn-engine/unicorn/issues/2010)).
The backend therefore enables **`UC_TLB_VIRTUAL`** at construction via
`uc_ctl(UC_CTL_TLB_TYPE)`, which maps guest VA→PA 1:1 across the full 64-bit
space. With it, ntsim's default synthetic bases (`0xffff_f800…`) execute and
are exercised by the differential suite (`differential.test.mjs`, "REAL kernel
VAs" case).

Implementation notes learned the hard way:
- `uc_ctl` is variadic. The only reliable invocation from JS is the wrapper's
  `engine.ctl(controlWord, [{type:'i32', value}])`, which materializes a
  va_list buffer — raw fixed-arity ccalls read garbage varargs and silently
  no-op (mode defaults to CPU = no fix).
- Code-hook ranges must be registered through raw `'i64'` ccalls: the
  wrapper's `hook_add` marshals begin/end through f64, corrupting any range
  containing addresses above 2^53 — exactly where kernel API thunks live.

Low-memory layouts (`new NtKernel({ bases })`) remain supported for scenarios
that want small address spaces.

## Versioning & provenance

- `vendor/unicorn_x86.cjs` is built from the **exact upstream source** at the
  pinned commit (AlexAltea/unicorn.js, unicorn core 2.1.x), emscripten 3.1.74.
- The npm dist of `@alexaltea/unicorn-js@2.1.4` is **not** used: it is stale
  (missing `_uc_ctl`) *and* marshals address parameters through f64, silently
  corrupting anything above 2^53. All address-bearing calls in this backend go
  through raw `ccall(..., 'i64', ...)` shims instead.
- Rebuild recipe lives in the repo spike notes; bump the vendored file only
  with the differential suite green.

## License

The vendored bundle embeds Unicorn/QEMU, licensed **GPLv2**. Fine for
private/internal course use; distributing the platform publicly triggers GPL
obligations on the combined work.

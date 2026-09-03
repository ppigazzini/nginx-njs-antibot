# Design

This page explains why the solver is shaped the way it is. For the module
contract and its constants, see [configuration](configuration.md).

## The algorithm

The server issues a challenge and accepts a nonce N such that
`SHA-256(challenge || ":" || decimal(N))` begins with `POW_BITS` zero bits.

The challenge is an HMAC-SHA256 hex digest, so it is always exactly 64
characters, which is exactly one SHA-256 block. Four consequences follow.

**A midstate.** The first block does not change within a challenge. Its
compression is done once, and each candidate nonce compresses only the second
block. This halves the work per attempt and applies to both solvers.

**Only h0 is computed.** `POW_BITS_MAX` is 32, so the difficulty test never
inspects past the first output word. The remaining seven are not computed on
the search path.

**A schedule specialised on the nonce's decimal width.** Only the digit bytes
differ between candidates, so the message schedule words past them stay
constant until the width changes. Both solvers build those words once and keep
them. Widths change only at powers of ten.

**No division in the hot loop.** Consecutive nonces differ by one decimal
digit almost always, so the nonce is incremented in place in the block rather
than re-derived. wasm32 has no 64-bit divide instruction and would otherwise
call a software routine on every attempt.

## The wasm solver

`src/pow_solver.c` is compiled with `-msimd128`.
[Security model](security.md) carries the measured rates, and
`test/solver.test.mjs` prints them for the machine it runs on.

**Four-way SIMD.** Four independent nonces are hashed in the lanes of `i32x4`
vectors, so one set of 64 rounds retires four candidates. This is the
multi-buffer technique from Gueron and Krasnov, IACR 2012/371.

## The JS fallback

A module containing SIMD instructions fails validation as a whole on an engine
without SIMD, even when the SIMD functions are never called, so the fallback
is a second implementation in JavaScript. It also serves engines with no
WebAssembly.

The JS solver generates its compression function at run time and passes it to
`new Function`. Three properties follow from generating it:

- all 64 rounds are unrolled with the K constants as literals, so no round
  performs a table load;
- the message schedule lives in 16 local variables rather than a typed array,
  so the hot loop touches no memory;
- working variables are rotated by name, so a round assigns two variables
  instead of eight.

The width specialisation is applied by generating one compressor per width,
with the constant schedule words as literals. The generated functions are
cached.

The generated source is about 19.8KB, built inside the worker; the shipped
generator is about 2KB.

JavaScript has no portable SIMD, so the remaining gap to the wasm solver
cannot be closed from JavaScript.

The page, the worker and this solver are ES5. The fallback exists for engines
too old or too limited for WebAssembly, and syntax those engines reject would
fail before the fallback could run.

## The worker pool

Workers are spawned at `navigator.hardwareConcurrency / 2`, clamped to 1..8.
Each worker owns every n-th block of 262,144 nonces, so the ranges never
overlap and their union covers the whole space below the cap.

The workers share nothing: each scans its own stride of the nonce space, so
the search needs no shared memory and the site needs no
`Cross-Origin-Opener-Policy` or `Cross-Origin-Embedder-Policy` headers.

The module is compiled once on the main thread and the compiled
`WebAssembly.Module` is posted to each worker, which is structured cloneable.
That gives one compile, one SIMD feature test, and no per-worker copy of the
payload.

Scaling on 4 physical and 8 logical cores: 1.91x at two workers, 3.07x at
four, 3.94x at eight. Logical cores share execution units, so it is sublinear
past two; per-worker balance is 97% at four. Half the cores leaves the machine
usable, and all of them yield 31% more.

## The progress readout

The counter shows `1 - exp(-tried / expected)`, the probability that a solve
would have finished by this point. The search is memoryless, so this is the
completion figure that exists: its median is 50%, and it flattens where the
slow tail is.

## Cost model

At any difficulty a visitor tolerates, an attacker's compute cost is small.
The gap is hardware, not code: a core with SHA-256 instructions computes the
same hash without the rounds this solver spends, and WebAssembly cannot reach
those instructions. [Security model](security.md) carries the measured rates.

The solver closes most of the gap that is closable from a browser, which is
what makes a difficulty in the twenties usable at all.

Proof-of-work stops scrapers that do not execute JavaScript. Against an
operator already paying for a large residential IP pool, the compute cost is a
rounding error. Rate limiting on a key that is not per-IP bounds a widely
distributed fleet.

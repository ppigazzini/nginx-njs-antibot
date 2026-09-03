/*
 * Portable stand-in for clang's <wasm_simd128.h>, for building
 * src/pow_solver.c natively under sanitizers, valgrind and libFuzzer.
 *
 * Only the intrinsics the solver uses are defined. Lanes are held as
 * uint32_t and arithmetic is unsigned, so lane overflow wraps as it does in
 * wasm instead of being signed overflow. Shift counts are taken modulo 32,
 * which is what i32x4.shl and i32x4.shr_u do.
 */

#ifndef POW_SOLVER_WASM_SIMD128_SHIM_H
#define POW_SOLVER_WASM_SIMD128_SHIM_H

#include <stdint.h>

typedef struct { uint32_t u[4]; } v128_t;

#define POW_LANES(expr)                                                       \
    do {                                                                      \
        v128_t r;                                                             \
        for (unsigned i_ = 0; i_ < 4u; i_++) { r.u[i_] = (expr); }            \
        return r;                                                             \
    } while (0)

static inline v128_t wasm_i32x4_splat(int32_t x) { POW_LANES((uint32_t)x); }

static inline v128_t wasm_i32x4_make(int32_t a, int32_t b, int32_t c, int32_t d) {
    v128_t r;
    r.u[0] = (uint32_t)a; r.u[1] = (uint32_t)b;
    r.u[2] = (uint32_t)c; r.u[3] = (uint32_t)d;
    return r;
}

static inline v128_t wasm_i32x4_add(v128_t a, v128_t b) { POW_LANES(a.u[i_] + b.u[i_]); }
static inline v128_t wasm_v128_and(v128_t a, v128_t b) { POW_LANES(a.u[i_] & b.u[i_]); }
static inline v128_t wasm_v128_or (v128_t a, v128_t b) { POW_LANES(a.u[i_] | b.u[i_]); }
static inline v128_t wasm_v128_xor(v128_t a, v128_t b) { POW_LANES(a.u[i_] ^ b.u[i_]); }

static inline v128_t wasm_i32x4_shl(v128_t a, uint32_t n) { POW_LANES(a.u[i_] << (n & 31u)); }
static inline v128_t wasm_u32x4_shr(v128_t a, uint32_t n) { POW_LANES(a.u[i_] >> (n & 31u)); }

static inline int32_t wasm_i32x4_extract_lane_impl(v128_t a, unsigned lane) {
    return (int32_t)a.u[lane & 3u];
}
#define wasm_i32x4_extract_lane(a, lane) wasm_i32x4_extract_lane_impl((a), (lane))

#undef POW_LANES
#endif

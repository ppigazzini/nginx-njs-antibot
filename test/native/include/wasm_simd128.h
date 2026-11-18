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

/* Byte k of a vector is byte k % 4 of lane k / 4, least significant first,
 * which is wasm's little-endian layout whatever the host's byte order. */
static inline uint8_t pow_v128_byte(v128_t a, unsigned k) {
    return (uint8_t)(a.u[(k / 4u) & 3u] >> (8u * (k % 4u)));
}

static inline uint32_t pow_load_le32(const void *mem) {
    const uint8_t *p = (const uint8_t *)mem;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline v128_t wasm_v128_load32_zero(const void *mem) {
    v128_t r = {{0u, 0u, 0u, 0u}};
    r.u[0] = pow_load_le32(mem);
    return r;
}

static inline v128_t wasm_v128_load32_lane_impl(const void *mem, v128_t v,
                                                unsigned lane) {
    v.u[lane & 3u] = pow_load_le32(mem);
    return v;
}
#define wasm_v128_load32_lane(mem, v, lane) \
    wasm_v128_load32_lane_impl((mem), (v), (lane))

/* Byte k of the result is byte c[k] of a, or byte c[k] - 16 of b. */
static inline v128_t wasm_i8x16_shuffle_impl(v128_t a, v128_t b,
                                             const unsigned char c[16]) {
    v128_t r = {{0u, 0u, 0u, 0u}};
    for (unsigned k = 0; k < 16u; k++) {
        uint8_t byte = c[k] < 16u ? pow_v128_byte(a, c[k])
                                  : pow_v128_byte(b, (unsigned)(c[k] - 16u) & 15u);
        r.u[k / 4u] |= (uint32_t)byte << (8u * (k % 4u));
    }
    return r;
}
#define wasm_i8x16_shuffle(a, b, ...) \
    wasm_i8x16_shuffle_impl((a), (b), (const unsigned char[16]){__VA_ARGS__})

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

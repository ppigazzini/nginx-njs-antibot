/* SPDX-License-Identifier: BlueOak-1.0.0 OR Apache-2.0 */

/*
 * SHA-256 proof-of-work solver for the nginx-njs-antibot challenge.
 *
 * Protocol
 * --------
 * The server issues a challenge and accepts a nonce N such that
 *
 *     SHA-256(challenge || ":" || decimal(N))
 *
 * begins with `bits` zero bits.
 *
 * test/solver.test.mjs prints the rate for the machine it runs on. Four
 * things account for it, in descending order of effect.
 *
 * 1. Four-way SIMD. Four independent nonces are hashed in the lanes of
 *    i32x4 vectors, so one set of 64 rounds retires four candidates. This is
 *    the multi-buffer technique from Gueron and Krasnov, IACR 2012/371.
 *
 * 2. A midstate. The challenge is an HMAC-SHA256 hex digest, so it is always
 *    exactly 64 characters -- exactly one SHA-256 block. Its compression is
 *    done once in pow_init(), and each candidate compresses only the second
 *    block. That halves the work per attempt.
 *
 * 3. No division in the hot loop. Consecutive nonces differ by one decimal
 *    digit almost always, so the nonce is incremented in place in the block
 *    instead of being re-derived. wasm32 has no 64-bit divide instruction and
 *    would otherwise call a software routine for every attempt.
 *
 * 4. A message schedule specialised on the nonce's decimal width. Only the
 *    digit bytes differ between groups, so the schedule words past them are
 *    identical in all four lanes and constant until the width changes. They
 *    are loaded once and kept, which leaves three words to rebuild per group
 *    instead of sixteen.
 *
 * The difficulty test only inspects the first output word: the caller clamps
 * bits to 32, so h1..h7 are never computed on the search path.
 *
 * Build
 * -----
 *   ./build.sh
 *
 * which runs:
 *
 *   clang --target=wasm32 -O3 -msimd128 -nostdlib -ffreestanding -std=c11 \
 *     -Wl,--no-entry -Wl,--strip-all -Wl,--initial-memory=131072 \
 *     -o dist/pow_solver.wasm src/pow_solver.c
 *
 * SIMD is required. A module containing SIMD instructions fails validation as
 * a whole on an engine without SIMD, even if the SIMD functions are never
 * called, so this file cannot serve as its own fallback. Engines without SIMD
 * run the pure-JS solver in src/antibot.js, which implements the same
 * algorithm.
 *
 * Freestanding: no libc, no imports, no traps. The only mutable state is the
 * challenge buffer and the midstate derived from it.
 *
 * Exports
 * -------
 *   set_byte(index, value)     write one challenge byte
 *   init()                     fold the challenge into the midstate
 *   solve(start, count, bits)  offset of the first solution, or 0xFFFFFFFF
 *   digest_word(nonce, index)  one word of a full digest, for self-test
 */

#ifndef __wasm_simd128__
#error "build with -msimd128 (see build.sh); engines without SIMD \
run the pure-JS solver in src/antibot.js"
#endif

#include <stdint.h>
#include <wasm_simd128.h>

/* Exported entry points. Declared up front so the definitions below are
 * checked against a prototype rather than being implicit externals. */
void     pow_set_byte(uint32_t index, uint32_t value);
uint32_t pow_init(void);
uint32_t pow_solve(double start, uint32_t count, uint32_t bits);
uint32_t pow_digest_word(double nonce, uint32_t index);

#define SHA256_BLOCK_BYTES   64u
#define SHA256_STATE_WORDS    8u
#define SHA256_ROUNDS        64u

/* The challenge is one full block; the midstate shortcut depends on it. */
#define CHALLENGE_BYTES      SHA256_BLOCK_BYTES

/* Offset in the final block where the 64-bit message length begins. */
#define LENGTH_FIELD_OFFSET  56u

/* A uint64 is at most 20 decimal digits. The block holds that comfortably:
 * the colon, the digits, the 0x80 terminator and the 8-byte length come to
 * 30 bytes of the 64. */
#define MAX_NONCE_DIGITS     20u

_Static_assert(1u + MAX_NONCE_DIGITS + 1u + 8u <= SHA256_BLOCK_BYTES,
               "the colon, digits, terminator and length must fit one block");

/* Returned by pow_solve() when the scanned range held no solution. */
#define POW_NOT_FOUND        0xFFFFFFFFu

_Static_assert(CHALLENGE_BYTES == SHA256_BLOCK_BYTES,
               "the midstate shortcut requires a single-block challenge");

static const uint32_t SHA256_K[SHA256_ROUNDS] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t SHA256_IV[SHA256_STATE_WORDS] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

/* Rotation by 0 would shift by 32, which is undefined. Every call site passes
 * a SHA-256 constant between 2 and 25. */
static inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}
static inline uint32_t big_sigma0(uint32_t x)   { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static inline uint32_t big_sigma1(uint32_t x)   { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static inline uint32_t small_sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static inline uint32_t small_sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

/* Ch and Maj in their branch-free two-operation forms. */
static inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g)   { return g ^ (e & (f ^ g)); }
static inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) | (c & (a | b)); }

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/*
 * Expand a block into the full 64-word message schedule.
 */
static void sha256_schedule(const uint8_t block[SHA256_BLOCK_BYTES],
                            uint32_t w[SHA256_ROUNDS]) {
    for (unsigned i = 0; i < 16u; i++) {
        w[i] = load_be32(block + 4u * i);
    }
    for (unsigned i = 16u; i < SHA256_ROUNDS; i++) {
        w[i] = small_sigma1(w[i - 2u]) + w[i - 7u] + small_sigma0(w[i - 15u]) + w[i - 16u];
    }
}

#define SHA256_ROUND(a, b, c, d, e, f, g, h, i)                               \
    do {                                                                      \
        const uint32_t t1 = (h) + big_sigma1(e) + choose(e, f, g)             \
                          + SHA256_K[i] + w[i];                               \
        const uint32_t t2 = big_sigma0(a) + majority(a, b, c);                \
        (d) += t1;                                                            \
        (h) = t1 + t2;                                                        \
    } while (0)

/* Eight rounds with the working variables rotated by name, so the loop body
 * carries no register shuffling of its own. */
#define SHA256_OCTET(i)                                                       \
    SHA256_ROUND(a, b, c, d, e, f, g, h, (i) + 0u);                           \
    SHA256_ROUND(h, a, b, c, d, e, f, g, (i) + 1u);                           \
    SHA256_ROUND(g, h, a, b, c, d, e, f, (i) + 2u);                           \
    SHA256_ROUND(f, g, h, a, b, c, d, e, (i) + 3u);                           \
    SHA256_ROUND(e, f, g, h, a, b, c, d, (i) + 4u);                           \
    SHA256_ROUND(d, e, f, g, h, a, b, c, (i) + 5u);                           \
    SHA256_ROUND(c, d, e, f, g, h, a, b, (i) + 6u);                           \
    SHA256_ROUND(b, c, d, e, f, g, h, a, (i) + 7u)

/*
 * The 64 rounds, leaving the working variables in `out`. What the caller does
 * with them is what separates a full compression from the first word alone.
 *
 * Neither wrapper is on the search path: pow_init() runs one, and the scan's
 * tail runs the other for the last few candidates in a range.
 */
static void sha256_rounds(const uint32_t state[SHA256_STATE_WORDS],
                          const uint8_t block[SHA256_BLOCK_BYTES],
                          uint32_t out[SHA256_STATE_WORDS]) {
    uint32_t w[SHA256_ROUNDS];
    sha256_schedule(block, w);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned i = 0; i < SHA256_ROUNDS; i += 8u) {
        SHA256_OCTET(i);
    }

    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
    out[4] = e; out[5] = f; out[6] = g; out[7] = h;
}

static void sha256_compress(uint32_t state[SHA256_STATE_WORDS],
                            const uint8_t block[SHA256_BLOCK_BYTES]) {
    uint32_t out[SHA256_STATE_WORDS];
    sha256_rounds(state, block, out);
    for (unsigned i = 0; i < SHA256_STATE_WORDS; i++) {
        state[i] += out[i];
    }
}

static uint32_t sha256_compress_h0(const uint32_t state[SHA256_STATE_WORDS],
                                   const uint8_t block[SHA256_BLOCK_BYTES]) {
    uint32_t out[SHA256_STATE_WORDS];
    sha256_rounds(state, block, out);
    return state[0] + out[0];
}

/* Module state: the challenge, and the midstate after compressing it. */
static uint8_t  challenge[CHALLENGE_BYTES];
static uint32_t midstate[SHA256_STATE_WORDS];

/* One bit per challenge byte written, so init can refuse a partial challenge
 * instead of hashing whatever the buffer happens to hold. `initialised` says
 * the midstate matches the bytes now in the buffer, not merely that a
 * challenge was complete at some point. */
static uint64_t challenge_written;
static _Bool    initialised;

/*
 * Lay out the second and final block: ":" + decimal nonce + 0x80 + zero
 * padding + the 64-bit big-endian message length. Returns the digit count.
 *
 * All 64 bytes are written on every call, so a block buffer may be reused
 * across nonces of differing digit counts without being cleared first.
 */
static unsigned build_final_block(uint64_t nonce, uint8_t block[SHA256_BLOCK_BYTES]) {
    uint8_t digits[MAX_NONCE_DIGITS];
    unsigned count = 0;

    do {
        digits[count++] = (uint8_t)('0' + (unsigned)(nonce % 10u));
        nonce /= 10u;
    } while (nonce != 0u);

    block[0] = ':';
    for (unsigned i = 0; i < count; i++) {
        block[1u + i] = digits[count - 1u - i];
    }

    const unsigned used = 1u + count;
    block[used] = 0x80u;
    for (unsigned i = used + 1u; i < LENGTH_FIELD_OFFSET; i++) {
        block[i] = 0u;
    }

    const uint64_t bit_length = (uint64_t)(CHALLENGE_BYTES + used) * 8u;
    for (unsigned i = 0; i < 8u; i++) {
        block[SHA256_BLOCK_BYTES - 1u - i] = (uint8_t)(bit_length >> (8u * i));
    }
    return count;
}

/*
 * Add one to the decimal nonce already laid out in `block`, in place.
 * Returns true when the carry ran off the leading digit, which is the only
 * case that changes the block layout and needs a full rebuild.
 */
static inline _Bool increment_decimal(uint8_t *block, unsigned count) {
    for (unsigned i = count; i >= 1u; i--) {
        if (block[i] != (uint8_t)'9') {
            block[i]++;
            return 0;
        }
        block[i] = (uint8_t)'0';
    }
    return 1;
}

/*
 * Write one byte of the challenge. Out-of-range indices are ignored.
 *
 * A write invalidates the midstate: it was folded from the bytes as they
 * were, so solve() must not run against it again until init() rebuilds it.
 */
__attribute__((export_name("set_byte")))
void pow_set_byte(uint32_t index, uint32_t value) {
    if (index < CHALLENGE_BYTES) {
        challenge[index] = (uint8_t)value;
        challenge_written |= (uint64_t)1 << index;
        initialised = 0;
    }
}

/*
 * Fold the challenge block into the midstate. Returns 1 on success, and 0
 * when any challenge byte is still unwritten, in which case solve() reports
 * no solution rather than searching against a midstate over stale bytes.
 */
__attribute__((export_name("init")))
uint32_t pow_init(void) {
    if (challenge_written != ~(uint64_t)0) {
        initialised = 0;
        return 0;
    }
    for (unsigned i = 0; i < SHA256_STATE_WORDS; i++) {
        midstate[i] = SHA256_IV[i];
    }
    sha256_compress(midstate, challenge);
    initialised = 1;
    return 1;
}

#define SIMD_LANES 4u

static inline v128_t v_rotr(v128_t x, unsigned n) {
    return wasm_v128_or(wasm_u32x4_shr(x, n), wasm_i32x4_shl(x, 32u - n));
}
static inline v128_t v_big_sigma0(v128_t x) {
    return wasm_v128_xor(wasm_v128_xor(v_rotr(x, 2), v_rotr(x, 13)), v_rotr(x, 22));
}
static inline v128_t v_big_sigma1(v128_t x) {
    return wasm_v128_xor(wasm_v128_xor(v_rotr(x, 6), v_rotr(x, 11)), v_rotr(x, 25));
}
static inline v128_t v_small_sigma0(v128_t x) {
    return wasm_v128_xor(wasm_v128_xor(v_rotr(x, 7), v_rotr(x, 18)), wasm_u32x4_shr(x, 3));
}
static inline v128_t v_small_sigma1(v128_t x) {
    return wasm_v128_xor(wasm_v128_xor(v_rotr(x, 17), v_rotr(x, 19)), wasm_u32x4_shr(x, 10));
}
static inline v128_t v_choose(v128_t e, v128_t f, v128_t g) {
    return wasm_v128_xor(g, wasm_v128_and(e, wasm_v128_xor(f, g)));
}
static inline v128_t v_majority(v128_t a, v128_t b, v128_t c) {
    return wasm_v128_or(wasm_v128_and(a, b), wasm_v128_and(c, wasm_v128_or(a, b)));
}

#define V_ROUND(a, b, c, d, e, f, g, h, i)                                    \
    do {                                                                      \
        const v128_t t1 = wasm_i32x4_add(                                     \
            wasm_i32x4_add(wasm_i32x4_add((h), v_big_sigma1(e)),              \
                           wasm_i32x4_add(v_choose(e, f, g),                  \
                                          wasm_i32x4_splat((int32_t)SHA256_K[i]))), \
            w[i]);                                                            \
        const v128_t t2 = wasm_i32x4_add(v_big_sigma0(a), v_majority(a, b, c));\
        (d) = wasm_i32x4_add((d), t1);                                        \
        (h) = wasm_i32x4_add(t1, t2);                                         \
    } while (0)

#define V_OCTET(i)                                                            \
    V_ROUND(a, b, c, d, e, f, g, h, (i) + 0u);                                \
    V_ROUND(h, a, b, c, d, e, f, g, (i) + 1u);                                \
    V_ROUND(g, h, a, b, c, d, e, f, (i) + 2u);                                \
    V_ROUND(f, g, h, a, b, c, d, e, (i) + 3u);                                \
    V_ROUND(e, f, g, h, a, b, c, d, (i) + 4u);                                \
    V_ROUND(d, e, f, g, h, a, b, c, (i) + 5u);                                \
    V_ROUND(c, d, e, f, g, h, a, b, (i) + 6u);                                \
    V_ROUND(b, c, d, e, f, g, h, a, (i) + 7u)

/*
 * Compress four blocks against the shared midstate; return each lane's h0.
 *
 * The four messages differ only in their nonce digits, so they share the
 * midstate and every round constant, and only the schedule is per-lane.
 */
/*
 * The message schedule, together with the number of leading words that change
 * from group to group. Words at and past `varying` are filled when the nonce's
 * decimal width changes and are kept until it changes again, so the schedule
 * and that count must stay together.
 */
typedef struct {
    v128_t   w[SHA256_ROUNDS];
    unsigned varying;
    unsigned width;         /* the `used` value w[varying..15] was built for */
} schedule_t;

static v128_t sha256x4_compress_h0(const uint32_t state[SHA256_STATE_WORDS],
                                   const uint8_t blocks[SIMD_LANES][SHA256_BLOCK_BYTES],
                                   schedule_t *sched) {
    v128_t *const w = sched->w;
    for (unsigned i = 0; i < sched->varying; i++) {
        w[i] = wasm_i32x4_make((int32_t)load_be32(blocks[0] + 4u * i),
                               (int32_t)load_be32(blocks[1] + 4u * i),
                               (int32_t)load_be32(blocks[2] + 4u * i),
                               (int32_t)load_be32(blocks[3] + 4u * i));
    }
    for (unsigned i = 16u; i < SHA256_ROUNDS; i++) {
        w[i] = wasm_i32x4_add(
                   wasm_i32x4_add(v_small_sigma1(w[i - 2u]), w[i - 7u]),
                   wasm_i32x4_add(v_small_sigma0(w[i - 15u]), w[i - 16u]));
    }

    v128_t a = wasm_i32x4_splat((int32_t)state[0]);
    v128_t b = wasm_i32x4_splat((int32_t)state[1]);
    v128_t c = wasm_i32x4_splat((int32_t)state[2]);
    v128_t d = wasm_i32x4_splat((int32_t)state[3]);
    v128_t e = wasm_i32x4_splat((int32_t)state[4]);
    v128_t f = wasm_i32x4_splat((int32_t)state[5]);
    v128_t g = wasm_i32x4_splat((int32_t)state[6]);
    v128_t h = wasm_i32x4_splat((int32_t)state[7]);

    for (unsigned i = 0; i < SHA256_ROUNDS; i += 8u) {
        V_OCTET(i);
    }

    return wasm_i32x4_add(a, wasm_i32x4_splat((int32_t)state[0]));
}

/* Advance every lane by SIMD_LANES, rebuilding any lane whose carry ran off
 * the leading digit. The wasted increments after such a carry are discarded
 * by the rebuild; carries happen only at powers of ten. */
static void advance_lanes(uint64_t next_base,
                          uint8_t blocks[SIMD_LANES][SHA256_BLOCK_BYTES],
                          unsigned digits[SIMD_LANES]) {
    for (unsigned lane = 0; lane < SIMD_LANES; lane++) {
        _Bool carried = 0;
        for (unsigned step = 0; step < SIMD_LANES && !carried; step++) {
            carried = increment_decimal(blocks[lane], digits[lane]);
        }
        if (carried) {
            digits[lane] = build_final_block(next_base + lane, blocks[lane]);
        }
    }
}

__attribute__((export_name("solve")))
uint32_t pow_solve(double start, uint32_t count, uint32_t bits) {
    if (bits == 0u || bits > 32u || !initialised) {
        return POW_NOT_FOUND;
    }

    const unsigned shift = 32u - bits;
    const uint64_t base = (uint64_t)start;
    uint8_t blocks[SIMD_LANES][SHA256_BLOCK_BYTES];
    unsigned digits[SIMD_LANES];
    schedule_t sched;
    sched.varying = 16u;
    sched.width = 0u;

    for (unsigned lane = 0; lane < SIMD_LANES; lane++) {
        digits[lane] = build_final_block(base + lane, blocks[lane]);
    }

    uint32_t i = 0;
    for (; count - i >= SIMD_LANES; i += SIMD_LANES) {
        /* Only the nonce digits differ between groups. When every lane holds
         * the same digit count, the words past them are identical in all four
         * blocks and constant until the count changes, so they are loaded once
         * and the schedule keeps them. */
        const unsigned used = digits[0] + 1u;
        _Bool uniform = 1;
        for (unsigned lane = 1; lane < SIMD_LANES; lane++) {
            if (digits[lane] != digits[0]) { uniform = 0; break; }
        }
        if (uniform) {
            if (used != sched.width) {
                sched.varying = (used + 3u) / 4u;
                for (unsigned k = sched.varying; k < 16u; k++) {
                    sched.w[k] = wasm_i32x4_splat((int32_t)load_be32(blocks[0] + 4u * k));
                }
                sched.width = used;
            }
        } else {
            sched.varying = 16u;
            sched.width = 0u;
        }

        const v128_t h0 = sha256x4_compress_h0(midstate, blocks, &sched);

        /* Lane order matches nonce order, so the lowest hit wins. */
        if (((uint32_t)wasm_i32x4_extract_lane(h0, 0) >> shift) == 0u) return i;
        if (((uint32_t)wasm_i32x4_extract_lane(h0, 1) >> shift) == 0u) return i + 1u;
        if (((uint32_t)wasm_i32x4_extract_lane(h0, 2) >> shift) == 0u) return i + 2u;
        if (((uint32_t)wasm_i32x4_extract_lane(h0, 3) >> shift) == 0u) return i + 3u;

        advance_lanes(base + i + SIMD_LANES, blocks, digits);
    }

    /* Tail: fewer than SIMD_LANES candidates left in the range. */
    for (; i < count; i++) {
        uint8_t block[SHA256_BLOCK_BYTES];
        build_final_block(base + i, block);
        if ((sha256_compress_h0(midstate, block) >> shift) == 0u) {
            return i;
        }
    }
    return POW_NOT_FOUND;
}


/*
 * Word `index` of the full digest for `nonce`, under the current challenge.
 * Not used by the solver; it exists so a caller can check this module against
 * a known-good SHA-256 without reimplementing the block layout.
 */
__attribute__((export_name("digest_word")))
uint32_t pow_digest_word(double nonce, uint32_t index) {
    uint8_t block[SHA256_BLOCK_BYTES];
    if (!initialised) {
        return 0;
    }
    uint32_t state[SHA256_STATE_WORDS];

    for (unsigned i = 0; i < SHA256_STATE_WORDS; i++) {
        state[i] = midstate[i];
    }
    build_final_block((uint64_t)nonce, block);
    sha256_compress(state, block);
    return state[index & 7u];
}

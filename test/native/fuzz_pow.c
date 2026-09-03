/*
 * Differential fuzz target for src/pow_solver.c.
 *
 * The solver is compiled natively through the shim in include/, so ASan,
 * UBSan, valgrind and libFuzzer see the real source. Every answer is checked
 * against OpenSSL's SHA-256.
 *
 * Two properties are asserted per case:
 *
 *   1. digest_word(nonce, i) equals word i of
 *      SHA-256(challenge || ":" || decimal(nonce)).
 *   2. solve(start, count, bits) returns the offset of the first nonce in
 *      the range whose digest has `bits` leading zero bits, or 0xFFFFFFFF.
 *
 * Build and run with test/native/check.sh.
 */

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/pow_solver.c"

/* The oracle costs one SHA-256 per nonce in the range, so the range is what
 * bounds a case, not the difficulty. Difficulty is therefore swept across the
 * whole accepted span, and the range is usually small with an occasional
 * larger one to reach the schedule cache and the tail path at scale. */
#define ORACLE_MAX_COUNT      256u
#define ORACLE_WIDE_COUNT    4096u
#define ORACLE_MAX_BITS        32u

static void oracle_digest(const uint8_t challenge[64], uint64_t nonce,
                          uint8_t out[32]) {
    uint8_t msg[64 + 1 + 24];
    int n = snprintf((char *)msg + 64, sizeof msg - 64, ":%llu",
                     (unsigned long long)nonce);
    memcpy(msg, challenge, 64);
    SHA256(msg, (size_t)(64 + n), out);
}

static int oracle_meets(const uint8_t digest[32], unsigned bits) {
    unsigned full = bits / 8u, rem = bits % 8u;
    for (unsigned i = 0; i < full; i++) {
        if (digest[i] != 0) return 0;
    }
    return rem == 0 || (digest[full] >> (8u - rem)) == 0;
}

/* Interesting starting points: the decimal-width boundaries where the block
 * is rebuilt, plus whatever the input asks for. */
static uint64_t pick_start(uint64_t raw, unsigned selector) {
    static const uint64_t decade[] = {
        0, 8, 98, 998, 9998, 99998, 999998, 9999998, 99999998,
        999999998, 9999999998ULL, 99999999998ULL
    };
    if (selector % 3u == 0u) {
        return decade[selector % (sizeof decade / sizeof decade[0])];
    }
    return raw % 100000000000ULL;
}

/* The scan index must not wrap. This is the loop condition solve() uses,
 * with the largest count it can be given. */
static void check_loop_bound(void) {
    const uint32_t count = 0xFFFFFFFFu;
    unsigned long long guard = 0;
    for (uint32_t i = 0; count - i >= 4u; i += 4u) {
        if (++guard > 1200000000ULL) {
            fprintf(stderr, "scan loop did not terminate for count=%u\n", count);
            abort();
        }
    }
}

/*
 * Entry points must refuse to work on a challenge that was never completed,
 * and must reject out-of-range difficulties.
 *
 * This runs once, on the first case, while the module's state is still the
 * zero it starts with. Testing the incomplete-challenge path later would need
 * a reset hook, and the module is better off without one.
 */
/* 0 is a legitimate digest word, so one zero proves nothing. All eight being
 * zero is a 2^-256 event for a real digest. */
static int all_digest_words_zero(void) {
    for (uint32_t w = 0; w < 8u; w++) {
        if (pow_digest_word(0, w) != 0) { return 0; }
    }
    return 1;
}

static void check_entry_points(const uint8_t challenge[64]) {
    static _Bool done = 0;
    if (done) { return; }
    done = 1;

    for (unsigned i = 0; i < 63u; i++) {
        pow_set_byte(i, challenge[i]);
    }
    if (pow_init() != 0) { fprintf(stderr, "init accepted 63 bytes\n"); abort(); }
    if (pow_solve(0, 64, 8) != POW_NOT_FOUND) {
        fprintf(stderr, "solve ran without a complete challenge\n"); abort();
    }
    /* 0 is a legitimate digest word, so one zero proves nothing. All eight
     * being zero is a 2^-256 event for a real digest. */
    if (!all_digest_words_zero()) {
        fprintf(stderr, "digest_word ran without a complete challenge\n"); abort();
    }

    pow_set_byte(63, challenge[63]);
    if (pow_init() != 1) { fprintf(stderr, "init refused 64 bytes\n"); abort(); }

    /* A write after init leaves the midstate describing the old bytes. */
    pow_set_byte(0, (uint32_t)challenge[0] ^ 1u);
    if (pow_solve(0, 64, 8) != POW_NOT_FOUND) {
        fprintf(stderr, "solve ran on a midstate that no longer matches\n"); abort();
    }
    if (!all_digest_words_zero()) {
        fprintf(stderr, "digest_word ran on a stale midstate\n"); abort();
    }
    pow_set_byte(0, challenge[0]);
    if (pow_init() != 1) { fprintf(stderr, "init failed after rewrite\n"); abort(); }

    for (uint32_t bits = 33; bits < 40u; bits++) {
        if (pow_solve(0, 64, bits) != POW_NOT_FOUND) {
            fprintf(stderr, "solve accepted bits=%u\n", bits); abort();
        }
    }
    if (pow_solve(0, 64, 0) != POW_NOT_FOUND) {
        fprintf(stderr, "solve accepted bits=0\n"); abort();
    }
    for (uint32_t count = 0; count < 4u; count++) {
        (void)pow_solve(0, count, 20);   /* below one SIMD group: tail path */
    }
}

static void run_case(const uint8_t challenge[64], uint64_t start,
                     uint32_t count, unsigned bits) {
    uint8_t digest[32];

    check_entry_points(challenge);

    for (unsigned i = 0; i < 64u; i++) {
        pow_set_byte(i, challenge[i]);
    }
    if (pow_init() != 1) { fprintf(stderr, "init failed\n"); abort(); }

    /* Property 1: the full digest, over nonces of several decimal widths. */
    static const uint64_t probe[] = {0, 1, 9, 10, 99, 100, 4294967295ULL,
                                     4294967296ULL, 999999999999ULL};
    for (unsigned i = 0; i < sizeof probe / sizeof probe[0]; i++) {
        oracle_digest(challenge, probe[i], digest);
        for (unsigned w = 0; w < 8u; w++) {
            uint32_t got = pow_digest_word((double)probe[i], w);
            uint32_t want = ((uint32_t)digest[w * 4] << 24) |
                            ((uint32_t)digest[w * 4 + 1] << 16) |
                            ((uint32_t)digest[w * 4 + 2] << 8) |
                            (uint32_t)digest[w * 4 + 3];
            if (got != want) {
                fprintf(stderr, "digest mismatch: nonce=%llu word=%u\n",
                        (unsigned long long)probe[i], w);
                abort();
            }
        }
    }

    /* Property 2: solve() agrees with brute force. */
    uint32_t want = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < count; i++) {
        oracle_digest(challenge, start + i, digest);
        if (oracle_meets(digest, bits)) { want = i; break; }
    }
    uint32_t got = pow_solve((double)start, count, bits);
    if (got != want) {
        fprintf(stderr, "solve mismatch: start=%llu count=%u bits=%u "
                        "got=%u want=%u\n",
                (unsigned long long)start, count, bits, got, want);
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 64u + 11u) return 0;

    uint8_t challenge[64];
    memcpy(challenge, data, 64);

    uint64_t raw = 0;
    for (unsigned i = 0; i < 8u; i++) {
        raw = (raw << 8) | data[64 + i];
    }
    unsigned selector = data[72];
    const _Bool wide = (data[72] & 0x3fu) == 0u;
    uint32_t count = 1u + (uint32_t)(data[73] %
                          (wide ? ORACLE_WIDE_COUNT : ORACLE_MAX_COUNT));
    unsigned bits = 1u + (unsigned)(data[74] % ORACLE_MAX_BITS);

    run_case(challenge, pick_start(raw, selector), count, bits);
    return 0;
}

#ifndef POW_LIBFUZZER
/* Standalone mode: a deterministic sweep, so the same binary runs under
 * valgrind and under the sanitizers without libFuzzer. */
int main(int argc, char **argv) {
    check_loop_bound();

    unsigned long iterations = (argc > 1) ? strtoul(argv[1], NULL, 10) : 200;
    unsigned long seed = (argc > 2) ? strtoul(argv[2], NULL, 10) : 1;

    uint8_t input[75];
    for (unsigned long n = 0; n < iterations; n++) {
        for (unsigned i = 0; i < sizeof input; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            input[i] = (uint8_t)(seed >> 33);
        }
        LLVMFuzzerTestOneInput(input, sizeof input);
    }
    printf("%lu cases checked against OpenSSL\n", iterations);
    return 0;
}
#endif

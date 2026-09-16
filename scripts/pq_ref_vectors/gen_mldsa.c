/*
 * gen_mldsa.c — known-answer-vector generator for ML-DSA (FIPS 204).
 *
 * This harness is original code. It treats the pq-crystals/dilithium
 * reference implementation purely as an oracle: it links against the
 * reference objects and calls only the public entry points declared in
 * sign.h (crypto_sign_keypair, crypto_sign_signature_internal,
 * crypto_sign_verify). Nothing from the reference sources is reproduced
 * here, and nothing here is meant to be reproduced in src/.
 *
 * Build once per parameter set with -DDILITHIUM_MODE=2|3|5 (ML-DSA-44/65/87);
 * see scripts/gen_pq_ref_vectors.sh. Output goes to stdout as KEY=HEX lines.
 *
 * Determinism:
 *   - The reference's key generation obtains its 32-byte seed xi through the
 *     randombytes() hook. We supply that hook from a SplitMix64 stream seeded
 *     with a fixed constant, and we record every seed handed out so the
 *     vector file is self-contained (a consumer never needs this PRNG).
 *   - Signatures use the FIPS 204 deterministic variant: rnd = 0^32. The
 *     reference's config.h hard-wires DILITHIUM_RANDOMIZED_SIGNING, so rather
 *     than patching the reference we call crypto_sign_signature_internal with
 *     an explicit all-zero rnd and the empty-context prefix pre = 0x00 || 0x00,
 *     which is exactly what crypto_sign_signature computes in a build without
 *     that macro. Every signature is then checked with crypto_sign_verify
 *     (context = empty) before it is written out.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "randombytes.h"
#include "sign.h"

#if DILITHIUM_MODE == 2
#define PREFIX "MLDSA44"
#elif DILITHIUM_MODE == 3
#define PREFIX "MLDSA65"
#elif DILITHIUM_MODE == 5
#define PREFIX "MLDSA87"
#else
#error "DILITHIUM_MODE must be 2, 3, or 5"
#endif

#define XI_BYTES 32
#define RND_BYTES_ 32
#define MSG_COUNT 3

static const size_t MSG_LENS[MSG_COUNT] = {0, 33, 200};

/* SplitMix64: a fixed-seed stream; nothing about it is secret or standard-
 * relevant, since every byte it produces that matters is recorded. */
static uint64_t prng_state = 0x4d4c2d4453412d00ULL + DILITHIUM_MODE;

static uint64_t prng_next(void) {
    uint64_t z = (prng_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void prng_fill(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if ((i & 7) == 0) {
            uint64_t w = prng_next();
            for (size_t j = 0; j < 8 && i + j < n; j++) {
                out[i + j] = (uint8_t)(w >> (8 * j));
            }
        }
    }
}

/* Record of the most recent randombytes() request, so the keygen seed xi
 * can be written next to the keys it produced. */
static uint8_t last_random[64];
static size_t last_random_len;

void randombytes(uint8_t *out, size_t outlen) {
    prng_fill(out, outlen);
    if (outlen > sizeof last_random) {
        fprintf(stderr, "randombytes: unexpected request of %zu bytes\n", outlen);
        exit(1);
    }
    memcpy(last_random, out, outlen);
    last_random_len = outlen;
}

static void emit(const char *key, const uint8_t *data, size_t len) {
    printf("%s_%s=", PREFIX, key);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t xi[XI_BYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (last_random_len != XI_BYTES) {
        fprintf(stderr, "keypair drew %zu random bytes, expected %d\n", last_random_len, XI_BYTES);
        return 1;
    }
    memcpy(xi, last_random, XI_BYTES);

    emit("XI", xi, XI_BYTES);
    emit("PK", pk, CRYPTO_PUBLICKEYBYTES);
    emit("SK", sk, CRYPTO_SECRETKEYBYTES);

    static const uint8_t rnd[RND_BYTES_] = {0};
    static const uint8_t pre_empty_ctx[2] = {0x00, 0x00}; /* 0x00 || ctxlen=0 */

    for (int i = 0; i < MSG_COUNT; i++) {
        uint8_t msg[256];
        uint8_t sig[CRYPTO_BYTES];
        size_t mlen = MSG_LENS[i];
        size_t siglen = 0;
        char key[16];

        prng_fill(msg, mlen);
        if (crypto_sign_signature_internal(sig, &siglen, msg, mlen, pre_empty_ctx,
                                           sizeof pre_empty_ctx, rnd, sk) != 0
            || siglen != CRYPTO_BYTES) {
            fprintf(stderr, "signing message %d failed\n", i);
            return 1;
        }
        if (crypto_sign_verify(sig, siglen, msg, mlen, NULL, 0, pk) != 0) {
            fprintf(stderr, "reference rejected its own signature on message %d\n", i);
            return 1;
        }

        snprintf(key, sizeof key, "MSG%d", i);
        emit(key, msg, mlen);
        snprintf(key, sizeof key, "SIG%d", i);
        emit(key, sig, siglen);
    }
    return 0;
}

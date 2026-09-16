/*
 * gen_mlkem.c — known-answer-vector generator for ML-KEM (FIPS 203).
 *
 * This harness is original code. It treats the pq-crystals/kyber reference
 * implementation purely as an oracle: it links against the reference objects
 * and calls only the public entry points declared in kem.h
 * (crypto_kem_keypair_derand, crypto_kem_enc_derand, crypto_kem_dec).
 * Nothing from the reference sources is reproduced here, and nothing here is
 * meant to be reproduced in src/.
 *
 * Build once per parameter set with -DKYBER_K=2|3|4 (ML-KEM-512/768/1024);
 * see scripts/gen_pq_ref_vectors.sh. Output goes to stdout as KEY=HEX lines.
 *
 * Determinism: the "derand" entry points take their randomness as arguments
 * (d || z for key generation, m for encapsulation), which we draw from a
 * SplitMix64 stream seeded with a fixed constant and record verbatim, so the
 * vector file is self-contained. A randombytes() hook is still provided
 * because the reference's randomized entry points reference the symbol, but
 * this program never lets it be reached.
 *
 * Per parameter set the output is one key pair, one honest encapsulation
 * (ct, ss), and one implicit-rejection case: a single byte of ct is XORed
 * with a fixed mask and the reference's decapsulation output ss' for that
 * corrupted ciphertext is recorded. FIPS 203 §7.3 fixes ss' = J(z || ct'),
 * so this pins the rejection path of decapsulation, not merely "some other
 * key comes out".
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kem.h"
#include "params.h"
#include "randombytes.h"

#if KYBER_K == 2
#define PREFIX "MLKEM512"
#elif KYBER_K == 3
#define PREFIX "MLKEM768"
#elif KYBER_K == 4
#define PREFIX "MLKEM1024"
#else
#error "KYBER_K must be 2, 3, or 4"
#endif

#define SEED_BYTES 32
#define BAD_CT_INDEX 0
#define BAD_CT_XOR 0x01

static uint64_t prng_state = 0x4d4c2d4b454d2d00ULL + KYBER_K;

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

void randombytes(uint8_t *out, size_t outlen) {
    (void)out;
    (void)outlen;
    fprintf(stderr, "randombytes() must not be reached: only derand entry points are used\n");
    exit(1);
}

static void emit(const char *key, const uint8_t *data, size_t len) {
    printf("%s_%s=", PREFIX, key);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t keygen_coins[2 * SEED_BYTES]; /* d || z */
    uint8_t m[SEED_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];
    uint8_t ss_bad[CRYPTO_BYTES];
    uint8_t idx = BAD_CT_INDEX;
    uint8_t mask = BAD_CT_XOR;

    prng_fill(keygen_coins, sizeof keygen_coins);
    prng_fill(m, sizeof m);

    if (crypto_kem_keypair_derand(pk, sk, keygen_coins) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    if (crypto_kem_enc_derand(ct, ss, pk, m) != 0) {
        fprintf(stderr, "encaps failed\n");
        return 1;
    }
    if (crypto_kem_dec(ss_dec, ct, sk) != 0 || memcmp(ss, ss_dec, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "reference decapsulation disagrees with its own encapsulation\n");
        return 1;
    }

    emit("D", keygen_coins, SEED_BYTES);
    emit("Z", keygen_coins + SEED_BYTES, SEED_BYTES);
    emit("PK", pk, CRYPTO_PUBLICKEYBYTES);
    emit("SK", sk, CRYPTO_SECRETKEYBYTES);
    emit("M", m, SEED_BYTES);
    emit("CT", ct, CRYPTO_CIPHERTEXTBYTES);
    emit("SS", ss, CRYPTO_BYTES);

    ct[BAD_CT_INDEX] ^= BAD_CT_XOR;
    if (crypto_kem_dec(ss_bad, ct, sk) != 0) {
        fprintf(stderr, "decaps of corrupted ciphertext failed\n");
        return 1;
    }
    if (memcmp(ss, ss_bad, CRYPTO_BYTES) == 0) {
        fprintf(stderr, "corrupted ciphertext did not trigger implicit rejection\n");
        return 1;
    }
    emit("CTBAD_INDEX", &idx, 1);
    emit("CTBAD_XOR", &mask, 1);
    emit("SSBAD", ss_bad, CRYPTO_BYTES);
    return 0;
}

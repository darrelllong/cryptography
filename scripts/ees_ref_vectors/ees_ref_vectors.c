/*
 * Interoperability harness for the crate's IEEE Std 1363.1-2008 / X9.98
 * NTRUEncrypt (SVES-3) implementation.
 *
 * This program links against Security Innovation's reference implementation
 * of the standard (libntruencrypt / ntru-crypto, CC0) and uses it purely as a
 * behavioural oracle:
 *
 *   gen   <out.txt>  For each of the nine parameter sets the crate ships,
 *                    generate a key pair from a recorded deterministic byte
 *                    stream, export the public / private key blobs, then
 *                    encrypt messages of
 *                    length 0, 1, max-1 and max with a recorded byte stream
 *                    and check the oracle decrypts its own output. The bytes
 *                    the oracle drew while encrypting are written next to
 *                    each ciphertext, so an implementation that draws the
 *                    random component the same way can replay it exactly.
 *
 *   check <in.txt>   Read SET / PK / SK / MSG / CT records produced by some
 *                    other implementation. For each record the oracle must
 *                    (1) decrypt CT under SK back to MSG, and (2) accept PK,
 *                    encrypt MSG under it and decrypt that under SK. Prints
 *                    one line per record; exits non-zero if any fails.
 *
 * Nothing here is derived from the oracle's sources; it only calls its
 * public API (ntru_crypto.h).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntru_crypto.h"

/* ---- parameter sets under test --------------------------------------- */

struct set_entry {
    const char *name;
    NTRU_ENCRYPT_PARAM_SET_ID id;
};

static const struct set_entry SETS[] = {
    {"ees401ep1", NTRU_EES401EP1},   {"ees449ep1", NTRU_EES449EP1},
    {"ees677ep1", NTRU_EES677EP1},   {"ees1087ep2", NTRU_EES1087EP2},
    {"ees541ep1", NTRU_EES541EP1},   {"ees1171ep1", NTRU_EES1171EP1},
    {"ees1087ep1", NTRU_EES1087EP1}, {"ees1499ep1", NTRU_EES1499EP1},
    {"ees443ep1", NTRU_EES443EP1},
};
#define NUM_SETS (sizeof SETS / sizeof SETS[0])

/* ---- recorded deterministic byte source ------------------------------ */

/* xorshift64* keyed per operation; the bytes are recorded verbatim into the
 * vector file, so the generator only needs to be reproducible, not strong. */
static uint64_t g_state;
static uint8_t g_record[1 << 16];
static uint32_t g_record_len;

static void rng_reset(uint64_t key)
{
    g_state = key ^ 0x9E3779B97F4A7C15ULL;
    if (g_state == 0)
        g_state = 1;
    g_record_len = 0;
}

static uint32_t rng_fn(uint8_t *out, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        uint64_t x = g_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        g_state = x;
        out[i] = (uint8_t)((x * 0x2545F4914F6CDD1DULL) >> 56);
        if (g_record_len < sizeof g_record)
            g_record[g_record_len++] = out[i];
    }
    return DRBG_OK;
}

/* ---- hex helpers ----------------------------------------------------- */

static void put_hex(FILE *f, const char *key, const uint8_t *p, size_t n)
{
    size_t i;
    fprintf(f, "%s=", key);
    for (i = 0; i < n; i++)
        fprintf(f, "%02X", p[i]);
    fputc('\n', f);
}

static int hex_val(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (s[0] && s[1] && s[0] != '\n' && s[0] != '\r') {
        int hi = hex_val(s[0]), lo = hex_val(s[1]);
        if (hi < 0 || lo < 0 || n >= cap)
            return (size_t)-1;
        out[n++] = (uint8_t)(hi << 4 | lo);
        s += 2;
    }
    return n;
}

/* ---- gen mode -------------------------------------------------------- */

static int gen_set(FILE *out, const struct set_entry *set, unsigned set_idx)
{
    DRBG_HANDLE drbg;
    uint16_t pk_len = 0, sk_len = 0, max_len = 0;
    uint8_t *pk, *sk;
    uint32_t rc;
    size_t lens[4];
    unsigned li;

    if (ntru_crypto_drbg_external_instantiate(rng_fn, &drbg) != DRBG_OK) {
        fprintf(stderr, "%s: drbg instantiate failed\n", set->name);
        return 1;
    }

    rc = ntru_crypto_ntru_encrypt_keygen(drbg, set->id, &pk_len, NULL, &sk_len, NULL);
    if (rc != NTRU_OK) {
        fprintf(stderr, "%s: keygen size query failed (%u)\n", set->name, rc);
        return 1;
    }
    pk = malloc(pk_len);
    sk = malloc(sk_len);
    rng_reset(0x4B4559ULL << 8 | set_idx); /* "KEY" */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, set->id, &pk_len, pk, &sk_len, sk);
    if (rc != NTRU_OK) {
        fprintf(stderr, "%s: keygen failed (%u)\n", set->name, rc);
        return 1;
    }
    fprintf(out, "\nSET=%s\nORIGIN=reference\n", set->name);
    put_hex(out, "PK", pk, pk_len);
    put_hex(out, "SK", sk, sk_len);


    /* max plaintext length: decrypt with a NULL output buffer reports it */
    rc = ntru_crypto_ntru_decrypt(sk_len, sk, 0, NULL, &max_len, NULL);
    if (rc != NTRU_OK) {
        fprintf(stderr, "%s: max length query failed (%u)\n", set->name, rc);
        return 1;
    }
    fprintf(out, "MAX_MSG=%u\n", max_len);

    lens[0] = 0;
    lens[1] = 1;
    lens[2] = max_len - 1;
    lens[3] = max_len;
    for (li = 0; li < 4; li++) {
        size_t mlen = lens[li], i;
        uint8_t msg[512], dec[512], *ct;
        uint16_t ct_len = 0, dec_len;
        for (i = 0; i < mlen; i++)
            msg[i] = (uint8_t)(0x5A ^ (i * 0x31 + mlen));
        rc = ntru_crypto_ntru_encrypt(drbg, pk_len, pk, (uint16_t)mlen, msg, &ct_len, NULL);
        if (rc != NTRU_OK) {
            fprintf(stderr, "%s: ct size query failed (%u)\n", set->name, rc);
            return 1;
        }
        ct = malloc(ct_len);
        rng_reset(0x454E43ULL << 16 | set_idx << 8 | li); /* "ENC" */
        rc = ntru_crypto_ntru_encrypt(drbg, pk_len, pk, (uint16_t)mlen, msg, &ct_len, ct);
        if (rc != NTRU_OK) {
            fprintf(stderr, "%s: encrypt len=%zu failed (%u)\n", set->name, mlen, rc);
            return 1;
        }
        dec_len = sizeof dec;
        rc = ntru_crypto_ntru_decrypt(sk_len, sk, ct_len, ct, &dec_len, dec);
        if (rc != NTRU_OK || dec_len != mlen || memcmp(dec, msg, mlen) != 0) {
            fprintf(stderr, "%s: oracle self-decrypt len=%zu failed (%u)\n", set->name, mlen, rc);
            return 1;
        }
        put_hex(out, "MSG", msg, mlen);
        put_hex(out, "ENC_RNG", g_record, g_record_len);
        put_hex(out, "CT", ct, ct_len);
        free(ct);
    }

    ntru_crypto_drbg_uninstantiate(drbg);
    free(pk);
    free(sk);
    return 0;
}

static int do_gen(const char *path)
{
    FILE *out = fopen(path, "w");
    unsigned i;
    if (!out) {
        perror(path);
        return 1;
    }
    fprintf(out, "# NTRUEncrypt SVES-3 (IEEE Std 1363.1-2008 / ANSI X9.98) interoperability vectors.\n");
    fprintf(out, "# Produced by scripts/ees_ref_vectors/ees_ref_vectors.c driving Security Innovation's\n");
    fprintf(out, "# reference implementation (libntruencrypt 1.1.0, CC0, github.com/jschanck-si/NTRUEncrypt\n# commit 3d36004274308feef0701bf9473e5b0775e1bf6f) purely as a behavioural oracle.\n");
    fprintf(out, "# ENC_RNG is the exact byte string the oracle drew from its RNG while encrypting (the\n");
    fprintf(out, "# random component b, bLen octets per attempt, repeated when the dm0 check rejected).\n");
    fprintf(out, "# PK / SK are the oracle's tagged key blobs.\n");
    fprintf(out, "# CT is the packed ciphertext ring element. The oracle decrypted every CT back to MSG.\n");
    for (i = 0; i < NUM_SETS; i++)
        if (gen_set(out, &SETS[i], i))
            return 1;
    fclose(out);
    return 0;
}

/* ---- check mode ------------------------------------------------------ */

static int do_check(const char *path)
{
    FILE *in = fopen(path, "r");
    static char line[1 << 16];
    static uint8_t pk[4096], sk[8192], msg[512], ct[4096];
    char set[32] = "";
    size_t pk_len = 0, sk_len = 0, msg_len = 0, ct_len = 0;
    int failures = 0, records = 0;

    if (!in) {
        perror(path);
        return 1;
    }
    while (fgets(line, sizeof line, in)) {
        if (!strncmp(line, "SET=", 4)) {
            sscanf(line + 4, "%31s", set);
        } else if (!strncmp(line, "PK=", 3)) {
            pk_len = parse_hex(line + 3, pk, sizeof pk);
        } else if (!strncmp(line, "SK=", 3)) {
            sk_len = parse_hex(line + 3, sk, sizeof sk);
        } else if (!strncmp(line, "MSG=", 4)) {
            msg_len = parse_hex(line + 4, msg, sizeof msg);
        } else if (!strncmp(line, "CT=", 3)) {
            uint8_t dec[512];
            uint16_t dec_len = sizeof dec;
            uint32_t rc;
            int ok;
            ct_len = parse_hex(line + 3, ct, sizeof ct);
            rc = ntru_crypto_ntru_decrypt((uint16_t)sk_len, sk, (uint16_t)ct_len, ct, &dec_len, dec);
            ok = rc == NTRU_OK && dec_len == msg_len && memcmp(dec, msg, msg_len) == 0;
            if (ok) {
                /* second leg: the oracle accepts PK and SK as a matching pair */
                DRBG_HANDLE drbg;
                uint8_t ct2[4096];
                uint16_t ct2_len = sizeof ct2;
                rng_reset((uint64_t)records << 20 | msg_len);
                ok = ntru_crypto_drbg_external_instantiate(rng_fn, &drbg) == DRBG_OK &&
                     ntru_crypto_ntru_encrypt(drbg, (uint16_t)pk_len, pk, (uint16_t)msg_len, msg,
                                              &ct2_len, ct2) == NTRU_OK;
                if (ok) {
                    dec_len = sizeof dec;
                    rc = ntru_crypto_ntru_decrypt((uint16_t)sk_len, sk, ct2_len, ct2, &dec_len, dec);
                    ok = rc == NTRU_OK && dec_len == msg_len && memcmp(dec, msg, msg_len) == 0;
                }
                ntru_crypto_drbg_uninstantiate(drbg);
                printf("%s len=%zu %s\n", set, msg_len,
                       ok ? "PASS" : "FAIL (oracle rejected PK, or PK/SK mismatch)");
            } else {
                printf("%s len=%zu FAIL (oracle decrypt rejected CT or mismatched MSG)\n", set, msg_len);
            }
            records++;
            if (!ok)
                failures++;
        }
    }
    fclose(in);
    printf("%d records, %d failures\n", records, failures);
    return failures != 0 || records == 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "gen"))
        return do_gen(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "check"))
        return do_check(argv[2]);
    fprintf(stderr, "usage: %s gen <out.txt> | check <in.txt>\n", argv[0]);
    return 2;
}

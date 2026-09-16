/*
 * Cross-check: does tbuktu/libntru interoperate with the reference vectors?
 *
 * libntru describes itself as "following the IEEE P1363.1 standard". This
 * program takes the SET / PK / SK / MSG / ENC_RNG / CT records written by
 * ees_ref_vectors (Security Innovation's reference implementation of the
 * standard, run as an oracle), converts the keys and ciphertexts into
 * libntru's in-memory structures, and asks libntru three questions per
 * record:
 *
 *   own     libntru encrypts MSG under the converted key and decrypts its own
 *           output. This must pass; it shows the key conversion is faithful.
 *   decrypt libntru decrypts the reference CT. Passing means libntru accepts
 *           standard ciphertexts.
 *   encrypt libntru encrypts MSG with the reference's random component b
 *           (replayed from ENC_RNG). Passing means libntru produces the same
 *           ciphertext ring element as the reference.
 *
 * Only libntru's public entry points (ntru.h) and data types (types.h) are
 * used; all packing and unpacking below is written from the EESS #1
 * conversion primitives (RE2BSP/BS2OSP) and from libntru's documented array
 * format (least-significant bit first).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntru.h"

struct set_entry {
    const char *name;
    const NtruEncParams *params;
};

static const struct set_entry SETS[] = {
    {"ees401ep1", &EES401EP1},   {"ees449ep1", &EES449EP1},   {"ees677ep1", &EES677EP1},
    {"ees1087ep2", &EES1087EP2}, {"ees541ep1", &EES541EP1},   {"ees1171ep1", &EES1171EP1},
    {"ees1087ep1", &EES1087EP1}, {"ees1499ep1", &EES1499EP1}, {"ees443ep1", &EES443EP1},
};
#define NUM_SETS (sizeof SETS / sizeof SETS[0])

/* ---- replayed random bytes ------------------------------------------- */

static uint8_t g_replay[4096];
static size_t g_replay_len, g_replay_pos;

static uint8_t replay_init(NtruRandContext *ctx, struct NtruRandGen *gen)
{
    (void)ctx;
    (void)gen;
    return 1;
}

static uint8_t replay_generate(uint8_t out[], uint16_t len, NtruRandContext *ctx)
{
    (void)ctx;
    if (g_replay_pos + len > g_replay_len)
        return 0;
    memcpy(out, g_replay + g_replay_pos, len);
    g_replay_pos += len;
    return 1;
}

static uint8_t replay_release(NtruRandContext *ctx)
{
    (void)ctx;
    return 1;
}

/* ---- hex and bit helpers --------------------------------------------- */

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

/* read `width` bits, most significant first, starting at bit offset *pos */
static unsigned read_msb(const uint8_t *in, size_t *pos, unsigned width)
{
    unsigned v = 0, k;
    for (k = 0; k < width; k++, (*pos)++)
        v = v << 1 | ((in[*pos / 8] >> (7 - *pos % 8)) & 1);
    return v;
}

/* write `width` bits, least significant first, at bit offset *pos */
static void write_lsb(uint8_t *out, size_t *pos, unsigned v, unsigned width)
{
    unsigned k;
    for (k = 0; k < width; k++, (*pos)++)
        if ((v >> k) & 1)
            out[*pos / 8] |= (uint8_t)(1 << (*pos % 8));
}

static unsigned bit_length(unsigned x)
{
    unsigned b = 0;
    while (x) {
        b++;
        x >>= 1;
    }
    return b;
}

/* ---- conversions from the reference blobs ---------------------------- */

static void unpack_ring(const uint8_t *packed, uint16_t n, NtruIntPoly *p)
{
    size_t pos = 0;
    uint16_t i;
    p->N = n;
    for (i = 0; i < n; i++)
        p->coeffs[i] = (int16_t)read_msb(packed, &pos, 11);
}

static void read_index_list(const uint8_t *packed, size_t *pos, unsigned bits, uint16_t n,
                            uint16_t d, NtruTernPoly *t)
{
    uint16_t k;
    t->N = n;
    t->num_ones = d;
    t->num_neg_ones = d;
    for (k = 0; k < d; k++)
        t->ones[k] = (uint16_t)read_msb(packed, pos, bits);
    for (k = 0; k < d; k++)
        t->neg_ones[k] = (uint16_t)read_msb(packed, pos, bits);
}

static void read_trits(const uint8_t *packed, uint16_t n, NtruTernPoly *t)
{
    uint16_t i;
    t->N = n;
    t->num_ones = 0;
    t->num_neg_ones = 0;
    for (i = 0; i < n; i++) {
        unsigned v = packed[i / 5], j;
        for (j = 0; j < i % 5; j++)
            v /= 3;
        if (v % 3 == 1)
            t->ones[t->num_ones++] = i;
        else if (v % 3 == 2)
            t->neg_ones[t->num_neg_ones++] = i;
    }
}

static int load_keypair(const struct set_entry *set, const uint8_t *sk, size_t sk_len,
                        NtruEncKeyPair *kp)
{
    const NtruEncParams *p = set->params;
    uint16_t n = p->N;
    size_t ring = (n * 11u + 7) / 8, pos = 0;
    unsigned bits = bit_length(n - 1u);
    const uint8_t *priv = sk + 5 + ring;
    size_t priv_len = sk_len - 5 - ring;

    unpack_ring(sk + 5, n, &kp->pub.h);
    kp->pub.q = p->q;
    kp->priv.q = p->q;
    if (p->prod_flag) {
        kp->priv.t.prod_flag = 1;
        kp->priv.t.poly.prod.N = n;
        read_index_list(priv, &pos, bits, n, p->df1, &kp->priv.t.poly.prod.f1);
        read_index_list(priv, &pos, bits, n, p->df2, &kp->priv.t.poly.prod.f2);
        read_index_list(priv, &pos, bits, n, p->df3, &kp->priv.t.poly.prod.f3);
    } else {
        kp->priv.t.prod_flag = 0;
        if (priv_len == (n + 4u) / 5)
            read_trits(priv, n, &kp->priv.t.poly.tern);
        else
            read_index_list(priv, &pos, bits, n, p->df1, &kp->priv.t.poly.tern);
    }
    return 1;
}

/* reference packed ring element (MSB first) -> libntru array (LSB first) */
static void repack_ct(const uint8_t *ct, uint16_t n, uint8_t *out, size_t out_len)
{
    size_t rpos = 0, wpos = 0;
    uint16_t i;
    memset(out, 0, out_len);
    for (i = 0; i < n; i++)
        write_lsb(out, &wpos, read_msb(ct, &rpos, 11), 11);
}

static int same_ring_element(const uint8_t *ref_ct, const uint8_t *lib_ct, uint16_t n)
{
    size_t rpos = 0, lpos = 0;
    uint16_t i;
    for (i = 0; i < n; i++) {
        unsigned a = read_msb(ref_ct, &rpos, 11), b = 0, k;
        for (k = 0; k < 11; k++, lpos++)
            b |= ((lib_ct[lpos / 8] >> (lpos % 8)) & 1u) << k;
        if (a != b)
            return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    static char line[1 << 16];
    static uint8_t sk[8192], msg[512], rng[4096], ct[4096];
    static NtruEncKeyPair kp;
    const struct set_entry *set = NULL;
    size_t sk_len = 0, msg_len = 0, rng_len = 0;
    unsigned per_set[NUM_SETS][4]; /* records, own, decrypt, encrypt */
    unsigned i;
    FILE *in;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <reference-vectors.txt>\n", argv[0]);
        return 2;
    }
    in = fopen(argv[1], "r");
    if (!in) {
        perror(argv[1]);
        return 2;
    }
    memset(per_set, 0, sizeof per_set);
    while (fgets(line, sizeof line, in)) {
        if (!strncmp(line, "SET=", 4)) {
            char name[32];
            set = NULL;
            sscanf(line + 4, "%31s", name);
            for (i = 0; i < NUM_SETS; i++)
                if (!strcmp(name, SETS[i].name))
                    set = &SETS[i];
        } else if (!strncmp(line, "ORIGIN=", 7)) {
            if (strncmp(line + 7, "reference", 9))
                set = NULL; /* only the oracle's own records are cross-checked */
        } else if (set && !strncmp(line, "SK=", 3)) {
            sk_len = parse_hex(line + 3, sk, sizeof sk);
            load_keypair(set, sk, sk_len, &kp);
        } else if (set && !strncmp(line, "MSG=", 4)) {
            msg_len = parse_hex(line + 4, msg, sizeof msg);
        } else if (set && !strncmp(line, "ENC_RNG=", 8)) {
            rng_len = parse_hex(line + 8, rng, sizeof rng);
        } else if (set && !strncmp(line, "CT=", 3)) {
            const NtruEncParams *p = set->params;
            unsigned idx = (unsigned)(set - SETS);
            uint16_t enc_len = ntru_enc_len(p), dec_len;
            uint8_t lib_ct[4096], own_ct[4096], dec[512];
            NtruRandGen gen = {replay_init, replay_generate, replay_release};
            NtruRandContext ctx;
            size_t ct_len = parse_hex(line + 3, ct, sizeof ct);
            int own_ok, dec_ok, enc_ok;

            (void)ct_len;
            per_set[idx][0]++;

            /* own: libntru round trip under the converted key */
            memcpy(g_replay, rng, rng_len);
            g_replay_len = rng_len;
            g_replay_pos = 0;
            ntru_rand_init(&ctx, &gen);
            enc_ok = ntru_encrypt(msg, (uint16_t)msg_len, &kp.pub, p, &ctx, own_ct) == NTRU_SUCCESS;
            dec_len = 0;
            own_ok = enc_ok && ntru_decrypt(own_ct, &kp, p, dec, &dec_len) == NTRU_SUCCESS &&
                     dec_len == msg_len && !memcmp(dec, msg, msg_len);
            /* encrypt: same b, same ring element as the reference? */
            enc_ok = enc_ok && same_ring_element(ct, own_ct, p->N);
            /* decrypt: libntru on the reference ciphertext */
            repack_ct(ct, p->N, lib_ct, enc_len);
            dec_len = 0;
            dec_ok = ntru_decrypt(lib_ct, &kp, p, dec, &dec_len) == NTRU_SUCCESS &&
                     dec_len == msg_len && !memcmp(dec, msg, msg_len);

            per_set[idx][1] += (unsigned)own_ok;
            per_set[idx][2] += (unsigned)dec_ok;
            per_set[idx][3] += (unsigned)enc_ok;
        }
    }
    fclose(in);

    printf("%-11s %7s %13s %15s %15s\n", "set", "records", "libntru-own", "decrypts-ref-ct",
           "matches-ref-ct");
    for (i = 0; i < NUM_SETS; i++)
        printf("%-11s %7u %13u %15u %15u\n", SETS[i].name, per_set[i][0], per_set[i][1],
               per_set[i][2], per_set[i][3]);
    return 0;
}

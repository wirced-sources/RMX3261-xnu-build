/* SPDX-License-Identifier: MIT. Uses the unmodified pinned BearSSL HMAC_DRBG. */
#include "ums512_rng.h"
#include <string.h>
#define RNG_READY UINT64_C(0x554d53524e473031)
#define RNG_LIMIT (UINT64_C(1) << 48)

void ums512_crypto_clear(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--) { *v++ = 0; }
}

int ums512_rng_init(struct ums512_rng *r, const void *seed, size_t n)
{
    if (!r || !seed || n < 32) { return -1; }
    br_hmac_drbg_init(&r->drbg, &br_sha256_vtable, seed, n);
    r->requests = 0;
    r->initialized = RNG_READY;
    return 0;
}

int ums512_rng_generate(struct ums512_rng *r, void *out, size_t n)
{
    if (!r || r->initialized != RNG_READY || (!out && n)) { return -1; }
    /* BearSSL deliberately leaves request limits to its caller. Enforce them. */
    uint64_t count = n / 65536 + (n % 65536 != 0);
    if (r->requests > RNG_LIMIT || count > RNG_LIMIT-r->requests) { return -2; }
    unsigned char *p = out;
    while (n) {
        size_t chunk = n > 65536 ? 65536 : n;
        br_hmac_drbg_generate(&r->drbg, p, chunk);
        r->requests++;
        p += chunk;
        n -= chunk;
    }
    return 0;
}

int ums512_rng_mix(struct ums512_rng *r, const void *seed, size_t n)
{
    if (!r || r->initialized != RNG_READY || !seed || !n) { return -1; }
    /* Mixing caller input never resets the entropy/reseed limit. */
    br_hmac_drbg_update(&r->drbg, seed, n);
    return 0;
}

int ums512_rng_uniform(struct ums512_rng *r, uint64_t bound, uint64_t *out)
{
    if (!bound || !out) { return -1; }
    uint64_t value, threshold = -bound % bound;
    int error;
    do {
        error = ums512_rng_generate(r, &value, sizeof(value));
        if (error) { return error; }
    } while (value < threshold);
    *out = value % bound;
    return 0;
}

int ums512_rng_selftest(void)
{
    /* NIST HMAC_DRBG worked example SHA-256, PDF pp147-153, no reseed.
     * Public test inputs; NEVER used to initialize a live generator. */
    static const unsigned char expected[64] = {
        0xd6,0x7b,0x8c,0x17,0x34,0xf4,0x6f,0xa3,0xf7,0x63,0xcf,0x57,0xc6,0xf9,0xf4,0xf2,
        0xdc,0x10,0x89,0xbd,0x8b,0xc1,0xf6,0xf0,0x23,0x95,0x0b,0xfc,0x56,0x17,0x63,0x52,
        0x08,0xc8,0x50,0x12,0x38,0xad,0x7a,0x44,0x00,0xde,0xfe,0xe4,0x6c,0x64,0x0b,0x61,
        0xaf,0x77,0xc2,0xd1,0xa3,0xbf,0xaa,0x90,0xed,0xe5,0xd2,0x07,0x40,0x6e,0x54,0x03
    };
    struct ums512_rng r;
    unsigned char seed[63], out[64];
    for (size_t i=0; i<55; i++) { seed[i] = (unsigned char)i; }
    for (size_t i=0; i<8; i++) { seed[55+i] = (unsigned char)(32+i); }
    int error = ums512_rng_init(&r, seed, sizeof(seed));
    if (!error) { error = ums512_rng_generate(&r, out, sizeof(out)); }
    if (!error && memcmp(out, expected, sizeof(out))) { error = -3; }
    ums512_crypto_clear(&r, sizeof(r));
    ums512_crypto_clear(seed, sizeof(seed));
    ums512_crypto_clear(out, sizeof(out));
    return error;
}

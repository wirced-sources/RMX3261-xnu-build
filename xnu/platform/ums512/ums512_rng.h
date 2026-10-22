/* SPDX-License-Identifier: MIT; platform-owned adapter, no Apple implementation. */
#pragma once
#include "bearssl.h"
struct ums512_rng {
    br_hmac_drbg_context drbg;
    uint64_t requests;
    uint64_t initialized;
};
void ums512_crypto_clear(void *p, size_t n);
int ums512_rng_init(struct ums512_rng *r, const void *seed, size_t n);
int ums512_rng_generate(struct ums512_rng *r, void *out, size_t n);
int ums512_rng_mix(struct ums512_rng *r, const void *seed, size_t n);
int ums512_rng_uniform(struct ums512_rng *r, uint64_t bound, uint64_t *out);
int ums512_rng_selftest(void);

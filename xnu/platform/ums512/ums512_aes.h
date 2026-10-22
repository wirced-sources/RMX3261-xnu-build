/* SPDX-License-Identifier: MIT. Portable AES-CBC; no authentication claim. */
#pragma once
#include "bearssl_block.h"
struct ums512_aes {
    union {
        br_aes_ct64_cbcenc_keys encrypt;
        br_aes_ct64_cbcdec_keys decrypt;
    } key;
    uint32_t ready;
    uint32_t decrypt;
};
int ums512_aes_init(struct ums512_aes *, const void *, size_t, unsigned);
int ums512_aes_cbc(const struct ums512_aes *, void *, size_t, const void *, void *, unsigned);
int ums512_aes_selftest(void);

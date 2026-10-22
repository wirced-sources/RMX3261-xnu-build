/* SPDX-License-Identifier: MIT. Real BearSSL 0.6 bitsliced constant-time AES.
 * CBC only: does not authenticate ciphertext, signatures or executable pages.
 * Contexts own their key schedule; calls do not allocate or obtain entropy.
 */
#include "ums512_aes.h"
#include "ums512_rng.h"
#include <string.h>

#define AES_READY UINT32_C(0x41455331)
static int span(const void *p, size_t n)
{
    return p && (uintptr_t)p <= UINTPTR_MAX - n;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    if (!an || !bn) return 0;
    return (uintptr_t)a < (uintptr_t)b + bn && (uintptr_t)b < (uintptr_t)a + an;
}
int ums512_aes_init(struct ums512_aes *ctx, const void *key, size_t n, unsigned decrypt)
{
    unsigned char copy[32];
    if (!span(ctx,sizeof(*ctx))) return -1;
    if (!span(key,n) || (n != 16 && n != 24 && n != 32) || decrypt > 1) {
        ums512_crypto_clear(ctx,sizeof(*ctx));
        return -1;
    }
    /* Copy before clearing permits a caller's key to overlap its old context. */
    memcpy(copy,key,n);
    ums512_crypto_clear(ctx,sizeof(*ctx));
    if (decrypt) br_aes_ct64_cbcdec_init(&ctx->key.decrypt,copy,n);
    else br_aes_ct64_cbcenc_init(&ctx->key.encrypt,copy,n);
    ums512_crypto_clear(copy,sizeof(copy));
    ctx->decrypt=decrypt;
    ctx->ready=AES_READY;
    return 0;
}
int ums512_aes_cbc(const struct ums512_aes *ctx, void *iv, size_t blocks,
    const void *in, void *out, unsigned decrypt)
{
    size_t n;
    if (!span(ctx,sizeof(*ctx)) || ctx->ready != AES_READY || decrypt > 1 ||
        ctx->decrypt != decrypt || blocks > SIZE_MAX/16 || !span(iv,16)) return -1;
    if (decrypt) {
        if (ctx->key.decrypt.vtable != &br_aes_ct64_cbcdec_vtable ||
            (ctx->key.decrypt.num_rounds != 10 && ctx->key.decrypt.num_rounds != 12 &&
             ctx->key.decrypt.num_rounds != 14)) return -1;
    } else {
        if (ctx->key.encrypt.vtable != &br_aes_ct64_cbcenc_vtable ||
            (ctx->key.encrypt.num_rounds != 10 && ctx->key.encrypt.num_rounds != 12 &&
             ctx->key.encrypt.num_rounds != 14)) return -1;
    }
    n=blocks*16;
    if (overlap(ctx,sizeof(*ctx),iv,16) || (n &&
        (!span(in,n) || !span(out,n) || overlap(ctx,sizeof(*ctx),in,n) ||
         overlap(ctx,sizeof(*ctx),out,n) || overlap(iv,16,in,n) || overlap(iv,16,out,n) ||
         (in != out && overlap(in,n,out,n))))) return -1;
    if (!n) return 0;
    if (in != out) memcpy(out,in,n);
    if (decrypt) br_aes_ct64_cbcdec_run(&ctx->key.decrypt,iv,out,n);
    else br_aes_ct64_cbcenc_run(&ctx->key.encrypt,iv,out,n);
    return 0;
}

static int unhex(const char *s, unsigned char *out, size_t n)
{
    for (size_t i=0;i<n;i++) {
        unsigned v=0;
        for (unsigned j=0;j<2;j++) {
            unsigned c=(unsigned char)s[2*i+j];
            if (c >= '0' && c <= '9') c-='0';
            else if (c >= 'a' && c <= 'f') c=c-'a'+10;
            else return -1;
            v=16*v+c;
        }
        out[i]=(unsigned char)v;
    }
    return s[2*n] ? -1 : 0;
}
int ums512_aes_selftest(void)
{
    /* NIST SP800-38A F.2.1/F.2.3/F.2.5 (four CBC blocks), and FIPS197 C.1-3.
     * Public KAT keys are never used by the kernel RNG or TCP key generation. */
    static const char *keys[]={
        "2b7e151628aed2a6abf7158809cf4f3c",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
    static const char *cipher[]={
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"};
    static const char *single[]={"69c4e0d86a7b0430d8cdb78070b4c55a",
        "dda97ca4864cdfe06eaf70a0ec0d7191","8ea2b7ca516745bfeafc49904b496089"};
    unsigned char key[32],plain[64],want[64],out[80],iv[16],initial[16],block[16];
    struct ums512_aes enc,dec;
    if (unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",plain,64)) return 1;
    for (unsigned a=0;a<3;a++) {
        size_t kn=16+8*a;
        for (unsigned i=0;i<16;i++) initial[i]=(unsigned char)i;
        if (unhex(keys[a],key,kn) || unhex(cipher[a],want,64) ||
            ums512_aes_init(&enc,key,kn,0) || ums512_aes_init(&dec,key,kn,1)) return 2;
        memcpy(iv,initial,16);
        if (ums512_aes_cbc(&enc,iv,4,plain,out,0) || memcmp(out,want,64) || memcmp(iv,want+48,16)) return 3;
        memcpy(iv,initial,16);
        if (ums512_aes_cbc(&dec,iv,4,out,out,1) || memcmp(out,plain,64) || memcmp(iv,want+48,16)) return 4;
        memcpy(iv,initial,16);memcpy(out,plain,64);
        for (unsigned i=0;i<4;i++) if (ums512_aes_cbc(&enc,iv,1,out+16*i,out+16*i,0)) return 5;
        if (memcmp(out,want,64)) return 6;
        memcpy(iv,initial,16);
        for (unsigned i=0;i<4;i++) if (ums512_aes_cbc(&dec,iv,1,out+16*i,out+16*i,1)) return 7;
        if (memcmp(out,plain,64)) return 8;
        for (unsigned i=0;i<kn;i++) key[i]=(unsigned char)i;
        for (unsigned i=0;i<16;i++) block[i]=(unsigned char)(17*i);
        if (unhex(single[a],want,16) || ums512_aes_init(&enc,key,kn,0) || ums512_aes_init(&dec,key,kn,1)) return 9;
        memset(iv,0,16);
        if (ums512_aes_cbc(&enc,iv,1,block,out,0) || memcmp(out,want,16)) return 10;
        memset(iv,0,16);
        if (ums512_aes_cbc(&dec,iv,1,out,out,1) || memcmp(out,block,16)) return 11;
    }
    memset(out,0xa5,sizeof(out));memset(iv,0x3c,sizeof(iv));
    if (!ums512_aes_cbc(&enc,iv,SIZE_MAX/16+1,plain,out,0) ||
        !ums512_aes_cbc(&enc,iv,1,NULL,out,0) || !ums512_aes_cbc(&enc,iv,1,plain,NULL,0) ||
        !ums512_aes_cbc(&enc,iv,1,out,out+1,0) || !ums512_aes_cbc(&enc,out,1,out,out,0) ||
        !ums512_aes_cbc(&enc,iv,1,plain,&enc,0) || !ums512_aes_cbc(&enc,iv,1,plain,out,1) ||
        !ums512_aes_cbc(&enc,NULL,1,plain,out,0)) return 12;
    for (unsigned i=0;i<sizeof(out);i++) if (out[i] != 0xa5) return 13;
    for (unsigned i=0;i<sizeof(iv);i++) if (iv[i] != 0x3c) return 14;
    if (ums512_aes_cbc(&enc,iv,0,NULL,NULL,0)) return 15;
    if (!ums512_aes_init(&enc,key,17,0) || !ums512_aes_cbc(&enc,iv,1,plain,out,0) ||
        !ums512_aes_init(&enc,NULL,16,0) || !ums512_aes_init(&enc,key,16,2) ||
        !ums512_aes_init(NULL,key,16,0)) return 16;
    ums512_crypto_clear(&enc,sizeof(enc));ums512_crypto_clear(&dec,sizeof(dec));
    ums512_crypto_clear(key,sizeof(key));ums512_crypto_clear(out,sizeof(out));
    return 0;
}

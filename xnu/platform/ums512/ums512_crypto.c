/* SPDX-License-Identifier: MIT. XNU8796 adapter for a real portable crypto backend.
 * RNG, digest and HMAC capabilities only. Cipher/AEAD/RSA are NOT supplied.
 * No success stubs or signature-policy changes. Bootstrap CPU only (MAX_CPUS=1).
 */
#include <libkern/libkern.h>
#include <libkern/crypto/register_crypto.h>
#include <libkern/crypto/rand.h>
#include <libkern/section_keywords.h>
#include <kern/startup.h>
#include <kern/locks.h>
#include <kern/lock_group.h>
#include <prng/random.h>
#include <corecrypto/cckprng.h>
#include <sys/random.h>
#include "ums512_rng.h"

_Static_assert(MAX_CPUS == 1, "PRNG CPU integration requires explicit SMP support");
_Static_assert(sizeof(struct ums512_rng) <= CRYPTO_RANDOM_MAX_CTX_SIZE, "KMEM context too large");
static struct ums512_rng master_rng;
static struct cckprng_ctx prng_handle;
static SECURITY_READ_ONLY_LATE(cckprng_getentropy) entropy_source;
static SECURITY_READ_ONLY_LATE(void *) entropy_arg;
static SECURITY_READ_ONLY_LATE(bool) generator_ready;
static uint64_t fresh_samples;
LCK_GRP_DECLARE(ums512_crypto_group, "ums512 crypto");
LCK_MTX_DECLARE(ums512_crypto_mutex, &ums512_crypto_group);

static void require_ok(int error)
{
    if (error) { panic("UMS512 crypto failure %d", error); }
}

static void prng_init(struct cckprng_ctx *ctx, unsigned ngens, size_t seed_size,
    const void *seed, size_t nonce_size, const void *nonce,
    cckprng_getentropy source, void *arg)
{
    if (ctx != &prng_handle || ngens != 1 || seed_size < 32 || !source || !nonce_size) {
        panic("UMS512 PRNG invalid initialization contract");
    }
    /* XNU passes the SHA256-conditioned bootloader entropy, not a timestamp seed. */
    require_ok(ums512_rng_init(&master_rng, seed, seed_size));
    require_ok(ums512_rng_mix(&master_rng, nonce, nonce_size));
    static const char domain[] = "UMS512 XNU master HMAC_DRBG v1";
    require_ok(ums512_rng_mix(&master_rng, domain, sizeof(domain)-1));
    entropy_source = source;
    entropy_arg = arg;
}

static void prng_init_legacy(struct cckprng_ctx *ctx, size_t ns, const void *s,
    size_t nn, const void *n, cckprng_getentropy f, void *arg)
{
    prng_init(ctx, 1, ns, s, nn, n, f, arg);
}

static void prng_initgen(struct cckprng_ctx *ctx, unsigned cpu)
{
    if (ctx != &prng_handle || cpu || generator_ready) { panic("UMS512 PRNG CPU initialization mismatch"); }
    generator_ready = true;
}

static void prng_generate(struct cckprng_ctx *ctx, unsigned cpu, size_t n, void *out)
{
    if (ctx != &prng_handle || cpu || !generator_ready || n > CCKPRNG_GENERATE_MAX_NBYTES) {
        panic("UMS512 PRNG invalid generation contract");
    }
    lck_mtx_lock(&ums512_crypto_mutex);
    require_ok(ums512_rng_generate(&master_rng, out, n));
    lck_mtx_unlock(&ums512_crypto_mutex);
}

static void prng_reseed(struct cckprng_ctx *ctx, size_t n, const void *seed)
{
    if (ctx != &prng_handle || !generator_ready || !n) { panic("UMS512 PRNG invalid mix contract"); }
    lck_mtx_lock(&ums512_crypto_mutex);
    require_ok(ums512_rng_mix(&master_rng, seed, n));
    lck_mtx_unlock(&ums512_crypto_mutex);
}

static void prng_refresh(struct cckprng_ctx *ctx)
{
    unsigned char entropy[64];
    size_t n = sizeof(entropy);
    if (ctx != &prng_handle || !generator_ready) { panic("UMS512 PRNG refresh before initialization"); }
    lck_mtx_lock(&ums512_crypto_mutex);
    int32_t samples = entropy_source(&n, entropy, entropy_arg);
    if (samples < 0 || n > sizeof(entropy)) { panic("UMS512 entropy health test failed"); }
    if (samples > 0 && n) {
        require_ok(ums512_rng_mix(&master_rng, entropy, n));
        /* Only health-tested fresh entropy can reset the generation limit. */
        fresh_samples += (uint32_t)samples;
        if (fresh_samples >= 1024 && n >= 32) {
            master_rng.requests = 0;
            fresh_samples = 0;
        }
    }
    ums512_crypto_clear(entropy, sizeof(entropy));
    lck_mtx_unlock(&ums512_crypto_mutex);
}

static int root_generate(struct ccrng_state *ctx, size_t n, void *out)
{
    (void)ctx;
    while (n) {
        unsigned chunk = n > 65536 ? 65536 : (unsigned)n;
        read_random(out, chunk);
        out = (unsigned char *)out + chunk;
        n -= chunk;
    }
    return 0;
}

static SECURITY_READ_ONLY_LATE(struct ccrng_state) root_rng = { .generate = root_generate };
static struct ccrng_state *root_context(int *error)
{
    if (!generator_ready) { panic("UMS512 root RNG before seed"); }
    if (error) { *error = 0; }
    return &root_rng;
}
static size_t kmem_size(void) { return sizeof(struct ums512_rng); }
static void kmem_init(crypto_random_ctx_t ctx)
{
    unsigned char seed[48];
    root_generate(&root_rng, sizeof(seed), seed);
    require_ok(ums512_rng_init(ctx, seed, sizeof(seed)));
    ums512_crypto_clear(seed, sizeof(seed));
}
static void random_generate(crypto_random_ctx_t ctx, void *out, size_t n)
{
    /* Per-CPU caller-owned state: no mutex, allocation or global RNG call. */
    require_ok(ums512_rng_generate(ctx, out, n));
}
static void random_uniform(crypto_random_ctx_t ctx, uint64_t bound, uint64_t *out)
{
    require_ok(ums512_rng_uniform(ctx, bound, out));
}

/* Preserve the original ccdigest/cchmac context ABI, including direct di->final. */
static SECURITY_READ_ONLY_LATE(uint32_t) md5_iv[4], sha1_iv[5], sha256_iv[8];
static SECURITY_READ_ONLY_LATE(uint64_t) sha384_iv[8], sha512_iv[8];
#define COMPRESS(name, type, init, update, bytes) \
static void name(ccdigest_state_t state, size_t blocks, const void *data) { \
    type c; init(&c); memcpy(c.val, state, sizeof(c.val)); \
    update(&c, data, blocks*(bytes)); memcpy(state, c.val, sizeof(c.val)); \
    ums512_crypto_clear(&c, sizeof(c)); \
}
COMPRESS(md5_compress, br_md5_context, br_md5_init, br_md5_update, 64)
COMPRESS(sha1_compress, br_sha1_context, br_sha1_init, br_sha1_update, 64)
COMPRESS(sha256_compress, br_sha256_context, br_sha256_init, br_sha256_update, 64)
COMPRESS(sha512_compress, br_sha512_context, br_sha512_init, br_sha512_update, 128)

static void hash_final(const struct ccdigest_info *di, ccdigest_ctx_t original, unsigned char *out)
{
    /* corecrypto final is non-destructive; callers may finalize repeatedly. */
    ccdigest_di_decl(di, ctx);
    memcpy(ctx,original,ccdigest_di_size(di));
    unsigned used;
    memcpy(&used,ccdigest_data(di,ctx)+di->block_size,sizeof(used));
    if (used >= di->block_size) { panic("UMS512 invalid digest buffer length"); }
    uint64_t bits = ccdigest_nbits(di, ctx) + 8*used;
    bool little = di->output_size == 16;
    size_t len_size = di->block_size == 128 ? 16 : 8;
    unsigned char padding[256] = {0x80};
    size_t pad = di->block_size - used;
    if (pad <= len_size) { pad += di->block_size; }
    for (size_t i=0; i<8; i++) {
        padding[pad-8+(little ? i : 7-i)] = (unsigned char)(bits >> (8*i));
    }
    ccdigest_update(di, ctx, pad, padding);
    size_t word_size = di->state_size == 64 ? 8 : 4;
    for (size_t i=0; i<di->output_size; i++) {
        size_t w = i / word_size, b = i % word_size;
        uint64_t value = word_size == 8 ? ccdigest_state_u64(di,ctx)[w] : ccdigest_state_u32(di,ctx)[w];
        out[i] = (unsigned char)(value >> (8*(little ? b : word_size-1-b)));
    }
    ums512_crypto_clear(padding, sizeof(padding));
    ccdigest_di_clear(di, ctx);
}
#define DI(name, output, state, block, iv, compress_fn, oid_value) \
static const struct ccdigest_info name = { .output_size=output, .state_size=state, .block_size=block, \
    .oid_size=sizeof(oid_value)-1, .oid=OID_DEF(oid_value), .initial_state=iv, \
    .compress=compress_fn, .final=hash_final }
DI(md5_di,16,16,64,md5_iv,md5_compress,"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05");
DI(sha1_di,20,20,64,sha1_iv,sha1_compress,"\x06\x05\x2b\x0e\x03\x02\x1a");
DI(sha256_di,32,32,64,sha256_iv,sha256_compress,"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01");
DI(sha384_di,48,64,128,sha384_iv,sha512_compress,"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02");
DI(sha512_di,64,64,128,sha512_iv,sha512_compress,"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03");

static const struct ccdigest_info *digest_info(crypto_digest_alg_t alg)
{
    switch (alg) {
    case CRYPTO_DIGEST_ALG_MD5: return &md5_di;
    case CRYPTO_DIGEST_ALG_SHA1: return &sha1_di;
    case CRYPTO_DIGEST_ALG_SHA256: return &sha256_di;
    case CRYPTO_DIGEST_ALG_SHA384: return &sha384_di;
    case CRYPTO_DIGEST_ALG_SHA512: return &sha512_di;
    default: panic("UMS512 invalid digest algorithm %u", alg);
    }
}
static void digest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *out)
{ ccdigest_final(di, ctx, out); }
static void digest_once(const struct ccdigest_info *di, unsigned long n, const void *data, void *out)
{
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx); ccdigest_update(di, ctx, n, data); ccdigest_final(di, ctx, out);
    ccdigest_di_clear(di, ctx);
}
static size_t digest_size(crypto_digest_alg_t alg) { return ccdigest_di_size(digest_info(alg)); }
static size_t hmac_size(crypto_digest_alg_t alg) { return cchmac_di_size(digest_info(alg)); }
static void check_size(size_t have, size_t need)
{ if (have < need) { panic("UMS512 crypto context/output too small"); } }
static void digest_init(crypto_digest_alg_t a, void *c, size_t n)
{ check_size(n,digest_size(a)); ccdigest_init(digest_info(a), c); }
static void digest_update(crypto_digest_alg_t a, void *c, size_t n, const void *d, size_t z)
{ check_size(n,digest_size(a)); ccdigest_update(digest_info(a),c,z,d); }
static void digest_finish(crypto_digest_alg_t a, void *c, size_t n, void *d, size_t z)
{ check_size(n,digest_size(a)); check_size(z,digest_info(a)->output_size); ccdigest_final(digest_info(a),c,d); }
static void digest_generate(crypto_digest_alg_t a, const void *d, size_t n, void *o, size_t z)
{ check_size(z,digest_info(a)->output_size); digest_once(digest_info(a),n,d,o); }
static void hmac_init(crypto_digest_alg_t a, void *c, size_t n, const void *k, size_t z)
{ check_size(n,hmac_size(a)); cchmac_init(digest_info(a),c,z,k); }
static void hmac_update(crypto_digest_alg_t a, void *c, size_t n, const void *d, size_t z)
{ check_size(n,hmac_size(a)); cchmac_update(digest_info(a),c,z,d); }
static void hmac_finish(crypto_digest_alg_t a, void *c, size_t n, void *out, size_t z)
{
    unsigned char tag[64]; const struct ccdigest_info *di=digest_info(a);
    check_size(n,hmac_size(a));
    if (!z || z > di->output_size) { panic("UMS512 invalid HMAC tag length"); }
    cchmac_final(di,c,tag); memcpy(out,tag,z); ums512_crypto_clear(tag,sizeof(tag));
}
static bool hmac_verify_final(crypto_digest_alg_t a, void *c, size_t n, const void *tag, size_t z)
{
    unsigned char actual[64], diff=0;
    hmac_finish(a,c,n,actual,z);
    for (size_t i=0; i<z; i++) { diff |= actual[i] ^ ((const unsigned char *)tag)[i]; }
    ums512_crypto_clear(actual,sizeof(actual)); return diff == 0;
}
static void hmac_generate(crypto_digest_alg_t a, const void *k, size_t kn, const void *d, size_t dn, void *t, size_t tn)
{
    const struct ccdigest_info *di=digest_info(a); cchmac_di_decl(di,c);
    hmac_init(a,c,cchmac_di_size(di),k,kn); hmac_update(a,c,cchmac_di_size(di),d,dn);
    hmac_finish(a,c,cchmac_di_size(di),t,tn); cchmac_di_clear(di,c);
}
static bool hmac_verify(crypto_digest_alg_t a, const void *k, size_t kn, const void *d, size_t dn, const void *t, size_t tn)
{
    const struct ccdigest_info *di=digest_info(a); cchmac_di_decl(di,c);
    hmac_init(a,c,cchmac_di_size(di),k,kn); hmac_update(a,c,cchmac_di_size(di),d,dn);
    bool valid=hmac_verify_final(a,c,cchmac_di_size(di),t,tn); cchmac_di_clear(di,c); return valid;
}

static const struct cckprng_funcs prng_callbacks = {
    .init=prng_init_legacy,.initgen=prng_initgen,.reseed=prng_reseed,
    .refresh=prng_refresh,.generate=prng_generate,.init_with_getentropy=prng_init
};

static void crypto_selftest(void)
{
    static const char *expected[] = {
        "900150983cd24fb0d6963f7d28e17f72",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    };
    static const char hex[] = "0123456789abcdef";
    unsigned char out[64], again[64], key[20];
    for (unsigned a=1; a<=5; a++) {
        const struct ccdigest_info *di=digest_info(a);
        ccdigest_di_decl(di,ctx);
        ccdigest_init(di,ctx); ccdigest_update(di,ctx,1,"a"); ccdigest_update(di,ctx,2,"bc");
        ccdigest_final(di,ctx,out); ccdigest_final(di,ctx,again);
        if (memcmp(out,again,di->output_size)) { panic("UMS512 destructive digest final"); }
        for (size_t i=0; i<di->output_size; i++) {
            if (hex[out[i]>>4] != expected[a-1][2*i] || hex[out[i]&15] != expected[a-1][2*i+1]) {
                panic("UMS512 digest KAT failure %u",a);
            }
        }
        ccdigest_di_clear(di,ctx);
    }
    /* RFC4231 test case1 and an actual negative authentication check. */
    static const unsigned char tag[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    memset(key,0x0b,sizeof(key));
    hmac_generate(CRYPTO_DIGEST_ALG_SHA256,key,sizeof(key),"Hi There",8,out,32);
    if (memcmp(out,tag,32) || !hmac_verify(CRYPTO_DIGEST_ALG_SHA256,key,sizeof(key),"Hi There",8,tag,32)) {
        panic("UMS512 HMAC KAT failure");
    }
    out[0] ^= 1;
    if (hmac_verify(CRYPTO_DIGEST_ALG_SHA256,key,sizeof(key),"Hi There",8,out,32)) {
        panic("UMS512 HMAC accepted invalid tag");
    }
    ums512_crypto_clear(out,sizeof(out)); ums512_crypto_clear(again,sizeof(again));
    ums512_crypto_clear(key,sizeof(key));
}
SECURITY_READ_ONLY_LATE(struct crypto_functions) ums512_crypto_callbacks = {
    .ccdigest_init_fn=ccdigest_init,.ccdigest_update_fn=ccdigest_update,
    .ccdigest_final_fn=digest_final,.ccdigest_fn=digest_once,
    .ccmd5_di=&md5_di,.ccsha1_di=&sha1_di,.ccsha256_di=&sha256_di,
    .ccsha384_di=&sha384_di,.ccsha512_di=&sha512_di,
    .cchmac_init_fn=cchmac_init,.cchmac_update_fn=cchmac_update,
    .cchmac_final_fn=cchmac_final,.cchmac_fn=cchmac,
    .ccrng_fn=root_context,.random_generate_fn=random_generate,
    .random_uniform_fn=random_uniform,.random_kmem_ctx_size_fn=kmem_size,
    .random_kmem_init_fn=kmem_init,
    .digest_ctx_size_fn=digest_size,.digest_init_fn=digest_init,
    .digest_update_fn=digest_update,.digest_final_fn=digest_finish,.digest_fn=digest_generate,
    .hmac_ctx_size_fn=hmac_size,.hmac_init_fn=hmac_init,.hmac_update_fn=hmac_update,
    .hmac_final_generate_fn=hmac_finish,.hmac_final_verify_fn=hmac_verify_final,
    .hmac_generate_fn=hmac_generate,.hmac_verify_fn=hmac_verify
};

static void ums512_crypto_startup(void)
{
    require_ok(ums512_rng_selftest());
    br_md5_context m; br_md5_init(&m); memcpy(md5_iv,m.val,sizeof(md5_iv));
    br_sha1_context s1; br_sha1_init(&s1); memcpy(sha1_iv,s1.val,sizeof(sha1_iv));
    br_sha256_context s2; br_sha256_init(&s2); memcpy(sha256_iv,s2.val,sizeof(sha256_iv));
    br_sha384_context s3; br_sha384_init(&s3); memcpy(sha384_iv,s3.val,sizeof(sha384_iv));
    br_sha512_context s5; br_sha512_init(&s5); memcpy(sha512_iv,s5.val,sizeof(sha512_iv));
    crypto_selftest();
    register_and_init_prng(&prng_handle,&prng_callbacks);
    if (register_crypto_functions(&ums512_crypto_callbacks)) { panic("UMS512 duplicate crypto provider registration"); }
}
STARTUP(EARLY_BOOT, STARTUP_RANK_FIRST, ums512_crypto_startup);

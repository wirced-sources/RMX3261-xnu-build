#include "ums512_rng.h"
#include "ums512_aes.h"
#include "bearssl_hmac.h"
#include <stdio.h>
#include <string.h>
static int hmac_vtable_kats(void) {
    /* RFC2202/RFC4231 case1 exercises every typed hash vtable operation
     * (including HMAC's state/set_state). These are public test keys. */
    const br_hash_class *hashes[]={&br_md5_vtable,&br_sha1_vtable,&br_sha224_vtable,
        &br_sha256_vtable,&br_sha384_vtable,&br_sha512_vtable};
    const char *tags[]={"9294727a3638bb1c13f48ef8158bfc9d",
        "b617318655057264e28bc0b6fb378c8ef146be00",
        "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"};
    const char hex[]="0123456789abcdef";
    unsigned char key[20],out[64];memset(key,0x0b,sizeof(key));
    for (unsigned a=0;a<6;a++) {
        br_hmac_key_context kc;br_hmac_context hc;
        br_hmac_key_init(&kc,hashes[a],key,a ? 20 : 16);
        br_hmac_init(&hc,&kc,0);br_hmac_update(&hc,"Hi ",3);br_hmac_update(&hc,"There",5);
        size_t n=br_hmac_out(&hc,out);
        if (2*n!=strlen(tags[a])) return 1;
        for (size_t i=0;i<n;i++) if (hex[out[i]>>4]!=tags[a][2*i] || hex[out[i]&15]!=tags[a][2*i+1]) return 2;
        ums512_crypto_clear(&kc,sizeof(kc));ums512_crypto_clear(&hc,sizeof(hc));
    }
    ums512_crypto_clear(key,sizeof(key));ums512_crypto_clear(out,sizeof(out));
    puts("PASS: RFC2202/4231 MD5/SHA1/SHA224/SHA256/SHA384/SHA512 HMAC typed-vtable dispatch");
    return 0;
}
int main(void) {
    if (hmac_vtable_kats()) return 40;
    int aes=ums512_aes_selftest();
    if (aes) { fprintf(stderr,"AES CBC KAT/contract failure %d\n",aes); return 10+aes; }
    printf("PASS: AES128/192/256 CBC/zero-IV KAT, streaming/in-place/IV update, invalid-contract rejection\n");
    struct ums512_rng r={0}; unsigned char seed[48]={1}, out[16]; uint64_t value;
    if (ums512_rng_selftest()) return 1;
    if (!ums512_rng_generate(&r,out,sizeof(out))) return 2;
    if (!ums512_rng_init(&r,seed,31)) return 3;
    if (ums512_rng_init(&r,seed,sizeof(seed))) return 4;
    if (!ums512_rng_uniform(&r,0,&value)) return 5;
    if (ums512_rng_uniform(&r,1,&value) || value) return 6;
    r.requests=UINT64_C(1)<<48;
    if (!ums512_rng_generate(&r,out,sizeof(out))) return 7;
    if (ums512_rng_mix(&r,seed,sizeof(seed))) return 8;
    if (!ums512_rng_generate(&r,out,sizeof(out))) return 9;
    printf("PASS: NIST HMAC_DRBG SHA256 KAT; unseeded/short seed/zero bound/limit rejection; context %zu bytes\n",sizeof(r));
    return 0;
}

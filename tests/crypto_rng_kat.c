#include "ums512_rng.h"
#include "ums512_aes.h"
#include <stdio.h>
#include <string.h>
int main(void) {
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

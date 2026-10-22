/* SPDX-License-Identifier: MIT.
 * Real IM4M certificate/role/RSA verification, isolated from XNU policy.
 * Fixed public test root and pinned test chain. No Image4/AMFI registration.
 */
#include "ums512_img4.h"
#include "ums512_img4_vectors.h"
#include "bearssl_hash.h"
#include "bearssl_rsa.h"
#include "libDER/DER_Decode.h"
#include "libDER/asn1Types.h"
#include "libDER/oids.h"
#include "libDERImg4/libDERImg4.h"
#include "libDERImg4/DER_Img4Manifest.h"
#include "libDERImg4/Img4oids.h"
static const size_t root_size=sizeof(ums_img4_root);
#ifdef KERNEL
#include <kern/debug.h>
#include <libkern/section_keywords.h>
SECURITY_READ_ONLY_LATE(const uint8_t *) DERImg4RootCertificate=ums_img4_root;
SECURITY_READ_ONLY_LATE(const size_t *) DERImg4RootCertificateSize=&root_size;
#else
const uint8_t *DERImg4RootCertificate=ums_img4_root;
const size_t *DERImg4RootCertificateSize=&root_size;
#endif

static int equal(const uint8_t *a,const uint8_t *b,size_t n)
{
    unsigned difference=0;
    for (size_t i=0;i<n;i++) { difference |= (unsigned)(a[i]^b[i]); }
    return difference==0;
}
static void hash256(const void *p,size_t n,uint8_t out[32])
{
    br_sha256_context context;
    br_sha256_init(&context); br_sha256_update(&context,p,n); br_sha256_out(&context,out);
}

bool DERImg4VerifySignature(const DERByte *modulus,DERSize size,uint32_t exponent,
    const uint8_t *sig,size_t sig_size,const uint8_t *data,size_t data_size,const DERItem *oid)
{
    /* This reviewed test profile intentionally supports only RSA2048/SHA256.
     * Unknown algorithms, short/even moduli and other exponents are rejected.
     */
    uint8_t digest[32],recovered[32],e[]={1,0,1};
    while (size && *modulus==0) { modulus++; size--; }
    if (size!=256 || !(modulus[0]&0x80) || !(modulus[255]&1) ||
        exponent!=65537 || sig_size!=256 || !DEROidCompare(oid,&oidSha256Rsa)) { return false; }
    uint8_t public_modulus[256];memcpy(public_modulus,modulus,sizeof(public_modulus));
    br_rsa_public_key key={public_modulus,size,e,sizeof(e)};
    static const uint8_t sha256_oid[]={9,0x60,0x86,0x48,1,0x65,3,4,2,1};
    hash256(data,data_size,digest);
    return br_rsa_i31_pkcs1_vrfy(sig,sig_size,sha256_oid,32,&key,recovered)==1 &&
           equal(digest,recovered,sizeof(digest));
}

/* libDER is BER tolerant. Reject non-minimal tags/lengths, indefinite lengths,
 * malformed INTEGER/BOOLEAN and excessive recursion before entering it.
 */
static int canonical(const uint8_t *p,size_t n,unsigned depth,int sorted)
{
    if (depth>16) { return 0; }
    const uint8_t *previous=NULL;
    size_t previous_size=0;
    while (n) {
        size_t h=1,len=0;
        uint8_t tag=p[0];
        if (n<2) { return 0; }
        if ((tag&31)==31) {
            uint64_t number=0;
            if (p[h]==0x80) { return 0; }
            do {
                if (h>=n-1 || h>9 || number>(UINT64_MAX>>7)) { return 0; }
                number=(number<<7)|(p[h]&127);
            } while (p[h++]&128);
            if (number<31) { return 0; }
        }
        if (h>=n) { return 0; }
        uint8_t first=p[h++];
        if (first&128) {
            unsigned count=first&127;
            if (!count || count>sizeof(size_t) || count>n-h || p[h]==0) { return 0; }
            for (unsigned i=0;i<count;i++) { len=(len<<8)|p[h++]; }
            if (len<128) { return 0; }
        } else { len=first; }
        if (len>n-h) { return 0; }
        if (sorted && previous) {
            size_t common=previous_size<h+len?previous_size:h+len;
            int order=memcmp(previous,p,common);
            if (order>0 || (order==0 && previous_size>=h+len)) { return 0; }
        }
        if (tag==2 && (!len || (len>1 &&
            ((p[h]==0 && !(p[h+1]&128)) || (p[h]==255 && (p[h+1]&128)))))) { return 0; }
        if (tag==1 && (len!=1 || (p[h]!=0 && p[h]!=255))) { return 0; }
        if (tag==5 && len) { return 0; }
        if (tag==3 && (!len || p[h]>7 || (len==1 && p[h]) ||
            (len>1 && (p[h+len-1]&((1u<<p[h])-1))))) { return 0; }
        if ((tag&32) && !canonical(p+h,len,depth+1,tag==0x31)) { return 0; }
        previous=p;previous_size=h+len;
        p+=h+len; n-=h+len;
    }
    return 1;
}

extern DERReturn DERImg4FindDecodeProperty(const DERItem *,DERTag,DERTag,DERImg4Property *);
extern DERReturn DERImg4DecodeProperty(const DERItem *,DERTag,DERImg4Property *);
static int properties(const DERItem *set,const char *const *names,size_t count)
{
    DERSequence sequence;
    DERDecodedInfo item;
    uint32_t seen=0;
    if (count>31 || DERDecodeSeqContentInit(set,&sequence)) { return 0; }
    DERReturn status;
    while ((status=DERDecodeSeqNext(&sequence,&item))==DR_Success) {
        DERImg4Property property;
        if (DERImg4DecodeProperty(&item.content,item.tag,&property) || property.nameItem.length!=4) { return 0; }
        size_t i;
        for (i=0;i<count;i++) { if (!memcmp(property.nameItem.data,names[i],4)) { break; } }
        if (i==count || (seen&(1u<<i))) { return 0; }
        seen|=1u<<i;
    }
    return status==DR_EndOfSequence && seen==((1u<<count)-1);
}

static int manifest_profile(const uint8_t *p,size_t n)
{
    DERItem input={p,n};
    DERImg4Manifest manifest;
    DERDecodedInfo body;
    DERImg4Property manb,manp,object;
    DERTag top_tag;
    DERSequence top_sequence;
    DERDecodedInfo child;
    static const DERTag tags[]={ASN1_IA5_STRING,ASN1_INTEGER,ASN1_CONSTR_SET,ASN1_OCTET_STRING,ASN1_CONSTR_SEQUENCE};
    if (DERDecodeSeqInit(&input,&top_tag,&top_sequence) || top_tag!=ASN1_CONSTR_SEQUENCE) { return 0; }
    for (unsigned i=0;i<5;i++) {
        if (DERDecodeSeqNext(&top_sequence,&child) || child.tag!=tags[i]) { return 0; }
    }
    if (DERDecodeSeqNext(&top_sequence,&child)!=DR_EndOfSequence) { return 0; }
    if (DERParseSequence(&input,DERNumImg4ManifestItemSpecs,DERImg4ManifestItemSpecs,&manifest,sizeof(manifest)) ||
        DERDecodeItem(&manifest.body,&body)) { return 0; }
    static const char *const top[]={"MANB"},*const sets[]={"MANP","trst"};
    static const char *const global[]={"BORD","CEPO","CHIP","ECID","SDOM","mpro","msec"};
    static const char *const local[]={"DGST","EPRO","ESEC"};
    if (!properties(&body.content,top,1) ||
        DERImg4FindDecodeProperty(&body.content,DER_IMG4_ENCODE_PROPERTY_NAME(0x4d414e42),ASN1_CONSTR_SET,&manb) ||
        !properties(&manb.valueItem,sets,2) ||
        DERImg4FindDecodeProperty(&manb.valueItem,DER_IMG4_ENCODE_PROPERTY_NAME(0x4d414e50),ASN1_CONSTR_SET,&manp) ||
        DERImg4FindDecodeProperty(&manb.valueItem,DER_IMG4_ENCODE_PROPERTY_NAME(0x74727374),ASN1_CONSTR_SET,&object) ||
        !properties(&manp.valueItem,global,7) || !properties(&object.valueItem,local,3)) { return 0; }
    /* Pin the two approved public test certificates as well as the root.
     * This is a closed lab profile, not a general X.509 policy engine: no
     * unreviewed issuer, key usage, extension or certificate validity interval
     * is silently accepted. Early boot has no trusted wall clock.
     */
    DERSequence chain;
    if (DERDecodeSeqContentInit(&manifest.certificates,&chain)) { return 0; }
    for (unsigned i=0;i<2;i++) {
        const uint8_t *start=chain.nextItem;
        uint8_t digest[32];
        DERDecodedInfo cert;
        if (DERDecodeSeqNext(&chain,&cert)) { return 0; }
        hash256(start,(size_t)(chain.nextItem-start),digest);
        if (!equal(digest,ums_img4_chain_hash[i],32)) { return 0; }
    }
    return chain.nextItem==chain.end;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static int module_valid(const uint8_t *p,size_t n)
{
    if (n<24 || le32(p)!=2) { return 0; }
    uint32_t count=le32(p+20);
    if (!count || count>1024 || n!=24+(size_t)count*24) { return 0; }
    unsigned uuid=0;
    for (unsigned i=4;i<20;i++) { uuid|=p[i]; }
    if (!uuid) { return 0; }
    for (uint32_t i=0;i<count;i++) {
        const uint8_t *entry=p+24+(size_t)i*24;
        /* SHA256, no AMFID/ANE grants, no unsupported constraints/reserved data. */
        if (entry[20]!=2 || entry[21] || entry[22] || entry[23] ||
            (i && memcmp(entry-24,entry,20)>=0)) { return 0; }
    }
    return 1;
}

enum ums512_img4_result ums512_img4_verify(const uint8_t *payload,size_t bytes,const uint8_t *manifest,size_t len)
{
    if (!payload || !manifest || !bytes || bytes>24600 || !len || len>65536) { return UMS_IMG4_ARGUMENT; }
    if (!canonical(manifest,len,0,0)) { return UMS_IMG4_ENCODING; }
    if (!manifest_profile(manifest,len)) { return UMS_IMG4_POLICY; }
    DERImg4ManifestInfo info;
    if (DERImg4ParseManifest(&info,manifest,len,0x74727374)!=DR_Success) { return UMS_IMG4_SIGNATURE; }
    /* Synthetic lab identity only; never an ECID/CHIP/BORD for RMX3261 or Apple.
     * Epoch is exact, not a persisted anti-rollback implementation. Nonce-based
     * personalized/cyptex manifests and all extra/unknown properties fail closed.
     */
    if (!info.hasEcid || info.environment.ecid!=UINT64_C(0x51564d5445535431) ||
        info.environment.chipId!=0x51564d || info.environment.boardId!=1 ||
        info.environment.certificateEpoch!=1 || info.environment.securityDomain!=1 ||
        !info.environment.productionStatus || !info.environment.securityMode ||
        !info.hasEffectiveProductionStatus || !info.environment.effectiveProductionStatus ||
        !info.hasEffectiveSecurityMode || !info.environment.effectiveSecurityMode ||
        info.hasXugs || info.environment.allowMixNMatch || info.environment.enableKeys ||
        info.environment.internalUseOnlyUnit || info.imageDigestSize!=32) { return UMS_IMG4_POLICY; }
    uint8_t digest[32]; hash256(payload,bytes,digest);
    if (!equal(digest,info.imageDigest,32)) { return UMS_IMG4_DIGEST; }
    if (!module_valid(payload,bytes)) { return UMS_IMG4_MODULE; }
    return UMS_IMG4_OK;
}

unsigned ums512_img4_selftest(void)
{
    unsigned count=0;
    for (size_t i=0;i<sizeof(ums_img4_cases)/sizeof(ums_img4_cases[0]);i++) {
        const struct ums_img4_case *test=&ums_img4_cases[i];
        int accepted=ums512_img4_verify(test->payload,test->payload_size,test->manifest,test->manifest_size)==UMS_IMG4_OK;
        if (accepted!=test->accepted) {
#ifdef KERNEL
            panic("UMS512 Image4 test failed at public vector %u",(unsigned)i);
#else
            return 0;
#endif
        }
        count++;
    }
    return count;
}

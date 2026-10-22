/* SPDX-License-Identifier: MIT
 * XNU 8796 TrustCache v3 ABI, restricted to private lab type 0x80.
 * This type confers no Apple platform category or entitlements. Raw static,
 * engineering, legacy and all nonce-personalized Apple cache types are denied.
 * Callers own ABI object storage. Authenticated module snapshots remain owned
 * by this non-unloadable provider. Registry access is serialized independently
 * of the stock XNU per-runtime lock. No external pointer is a valid token.
 */
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <libkern/amfi/amfi.h>
#include "ums512_img4.h"
#include "ums512_security.h"

extern const img4_interface_t ums512_image4_interface;
LCK_GRP_DECLARE(ums512_tc_group,"QEMU laboratory TrustCache");
LCK_MTX_DECLARE(ums512_tc_lock,&ums512_tc_group);
#define TC_MAX 8u
struct record {
    TrustCacheRuntime_t *runtime;
    TrustCache_t *cache;
    const uint8_t *module;
    size_t size;
    uint8_t digest[32];
};
static struct record records[TC_MAX];
static unsigned loaded;
static TCReturn_t ret(uint8_t component,uint8_t error) { return buildTCRet(component,error,0); }
static uint32_t count_entries(const uint8_t *p)
{ return (uint32_t)p[20]|((uint32_t)p[21]<<8)|((uint32_t)p[22]<<16)|((uint32_t)p[23]<<24); }
static struct record *find(const TrustCache_t *cache)
{
    for (unsigned i=0;i<loaded;i++) { if (records[i].cache==cache) { return &records[i]; } }
    return NULL;
}
static bool intact(const struct record *r)
{
    if (!r || r->cache->type!=UMS512_TC_LAB_TYPE || r->cache->moduleSize!=r->size ||
        (const void *)r->cache->module!=r->module) { return false; }
    uint8_t digest[32]; ums512_img4_sha256(r->module,r->size,digest);
    return !memcmp(digest,r->digest,32) && ums512_img4_module_valid(r->module,r->size);
}
static TCReturn_t construct(TrustCache_t *cache,const uint8_t *data,size_t n)
{
    if (!cache || !data) { return ret(kTCComponentConstructInvalid,kTCReturnInvalidArguments); }
    if (!ums512_img4_module_valid(data,n)) { return ret(kTCComponentConstructInvalid,kTCReturnInvalidModule); }
    lck_mtx_lock(&ums512_tc_lock);
    if (find(cache)) { lck_mtx_unlock(&ums512_tc_lock); return ret(kTCComponentConstructInvalid,kTCReturnDuplicate); }
    memset(cache,0,sizeof(*cache)); cache->type=kTCTypeInvalid;
    cache->module=(const void *)data; cache->moduleSize=n;
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentConstructInvalid,kTCReturnSuccess); /* Explicitly INVALID, not a trusted member. */
}
static TCReturn_t load_module(TrustCacheRuntime_t *runtime,TCType_t type,TrustCache_t *cache,uintptr_t data,size_t n)
{
    (void)runtime; (void)type; (void)cache; (void)data; (void)n;
    return ret(kTCComponentLoadModule,kTCReturnNotPermitted); /* No external boot-authentication oracle. */
}
static TCReturn_t load(TrustCacheRuntime_t *runtime,TCType_t type,TrustCache_t *cache,
    uintptr_t payload,size_t size,uintptr_t manifest,size_t length)
{
    if (!runtime || !runtime->mutableRT || !cache || !payload || !manifest ||
        !size || size>24600 || !length || length>65536) { return ret(kTCComponentLoad,kTCReturnInvalidArguments); }
    if (type!=UMS512_TC_LAB_TYPE || runtime->image4RT!=ums512_image4_interface.i4if_v7.runtime_default) {
        return ret(kTCComponentLoad,kTCReturnNotPermitted);
    }
    /* Snapshot payload and manifest before authentication to prevent TOCTOU. */
    uint8_t *bytes=kalloc_data(size,Z_WAITOK);
    memcpy(bytes,(const void *)payload,size);
    img4_buff_t buffer=IMG4_BUFF_INIT;
    buffer.i4b_bytes=bytes; buffer.i4b_len=size;
    img4_firmware_execution_context_t exec={.i4fex_version=IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION};
    img4_firmware_t fw=ums512_image4_interface.i4if_v7.firmware_new(runtime->image4RT,&exec,0x74727374,&buffer,IMG4_FIRMWARE_FLAG_BARE);
    if (!fw) { kfree_data(bytes,size); return ret(kTCComponentLoad,kTCReturnError); }
    buffer=IMG4_BUFF_INIT; buffer.i4b_bytes=(void *)manifest; buffer.i4b_len=length;
    ums512_image4_interface.i4if_v7.firmware_attach_manifest(fw,&buffer);
    errno_t status=ums512_image4_interface.i4if_v9.firmware_evaluate(fw,
        ums512_image4_interface.i4if_v7.chip_select_personalized_ap(),NULL);
    ums512_image4_interface.i4if_v7.firmware_destroy(&fw);
    if (status) {
        uint8_t error;
        switch (status) {
        case EINVAL: error=kTCReturnInvalidArguments; break;
        case ENOTSUP: error=kTCReturnUnsupported; break;
        case EFTYPE: error=kTCReturnImage4DecodeError; break;
        case EAUTH: error=kTCReturnImage4WrongCrypto; break;
        case EACCES: error=kTCReturnImage4ManifestViolation; break;
        case ENOEXEC: error=kTCReturnImage4PayloadViolation; break;
        default: error=kTCReturnImage4UnknownError; break;
        }
        kfree_data(bytes,size); return ret(kTCComponentImage4Validate,error);
    }
    lck_mtx_lock(&ums512_tc_lock);
    uint8_t error=kTCReturnSuccess;
    if (loaded==TC_MAX) { error=kTCReturnNotPermitted; }
    if (runtime->mutableRT->loadableTCHead && !find(runtime->mutableRT->loadableTCHead)) {
        error=kTCReturnLinkedListCorrupted;
    }
    for (unsigned i=0;i<loaded;i++) {
        if (records[i].cache==cache || (records[i].runtime==runtime && !memcmp(records[i].module+4,bytes+4,16))) {
            error=kTCReturnDuplicate;
        }
    }
    if (error==kTCReturnSuccess) {
        struct record *r=&records[loaded++];
        r->runtime=runtime; r->cache=cache; r->module=bytes; r->size=size;
        ums512_img4_sha256(bytes,size,r->digest);
        memset(cache,0,sizeof(*cache)); cache->type=type; cache->module=(const void *)bytes; cache->moduleSize=size;
        cache->next=runtime->mutableRT->loadableTCHead;
        if (cache->next) { cache->next->prev=cache; }
        runtime->mutableRT->loadableTCHead=cache;
    }
    lck_mtx_unlock(&ums512_tc_lock);
    if (error!=kTCReturnSuccess) { kfree_data(bytes,size); }
    return ret(kTCComponentLoad,error);
}
static TCReturn_t check_uuid(const TrustCacheRuntime_t *runtime,const uint8_t uuid[16],const TrustCache_t **found)
{
    if (found) { *found=NULL; }
    if (!runtime || !uuid) { return ret(kTCComponentCheckRuntimeForUUID,kTCReturnInvalidArguments); }
    uint8_t error=kTCReturnNotFound;
    lck_mtx_lock(&ums512_tc_lock);
    for (unsigned i=0;i<loaded;i++) {
        if (records[i].runtime==runtime && intact(&records[i]) && !memcmp(records[i].module+4,uuid,16)) {
            if (found) { *found=records[i].cache; } error=kTCReturnSuccess; break;
        }
    }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentCheckRuntimeForUUID,error);
}
static TCReturn_t query(const TrustCacheRuntime_t *runtime,TCQueryType_t type,const uint8_t hash[20],TrustCacheQueryToken_t *token)
{
    if (token) { memset(token,0,sizeof(*token)); }
    if (!runtime || !hash || type>=kTCQueryTypeTotal) { return ret(kTCComponentQuery,kTCReturnInvalidArguments); }
    uint8_t error=kTCReturnNotFound;
    lck_mtx_lock(&ums512_tc_lock);
    for (unsigned i=0;type!=kTCQueryTypeStatic && i<loaded;i++) {
        struct record *r=&records[i];
        if (r->runtime!=runtime) { continue; }
        if (!intact(r)) { error=kTCReturnInvalidModule; break; }
        size_t low=0,high=count_entries(r->module);
        while (low<high) {
            size_t middle=low+(high-low)/2;
            const uint8_t *entry=r->module+24+middle*24;
            int order=memcmp(entry,hash,20);
            if (!order) {
                if (token) { token->trustCache=r->cache; token->trustCacheEntry=entry; }
                error=kTCReturnSuccess; break;
            }
            if (order<0) { low=middle+1; } else { high=middle; }
        }
        if (error==kTCReturnSuccess) { break; }
    }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentQuery,error);
}
static bool valid_token(const TrustCacheQueryToken_t *token)
{
    if (!token) { return false; }
    struct record *r=find(token->trustCache);
    if (!intact(r)) { return false; }
    uintptr_t address=(uintptr_t)token->trustCacheEntry,base=(uintptr_t)r->module+24;
    return address>=base && address<base+r->size-24 && (address-base)%24==0;
}
static TCReturn_t capabilities(const TrustCache_t *cache,TCCapabilities_t *value)
{
    if (!value) { return ret(kTCComponentModuleCapabilities,kTCReturnInvalidArguments); }
    *value=0; lck_mtx_lock(&ums512_tc_lock); bool ok=intact(find(cache));
    if (ok) { *value=kTCCapabilityHashType|kTCCapabilityFlags|kTCCapabilityConstraintsCategory; }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentModuleCapabilities,ok?kTCReturnSuccess:kTCReturnNotFound);
}
static TCReturn_t token_value(const TrustCacheQueryToken_t *token,void *out,unsigned which)
{
    if (!out) { return ret(kTCComponentQuery,kTCReturnInvalidArguments); }
    lck_mtx_lock(&ums512_tc_lock); bool ok=valid_token(token);
    if (ok) {
        const uint8_t *entry=token->trustCacheEntry;
        switch (which) {
        case 0: *(TCType_t *)out=UMS512_TC_LAB_TYPE; break;
        case 1: *(TCCapabilities_t *)out=kTCCapabilityHashType|kTCCapabilityFlags|kTCCapabilityConstraintsCategory; break;
        case 2: *(uint8_t *)out=entry[20]; break;
        case 3: *(uint64_t *)out=entry[21]; break;
        case 4: *(uint8_t *)out=entry[22]; break;
        default: ok=false; break;
        }
    }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentQuery,ok?kTCReturnSuccess:kTCReturnNotFound);
}
static TCReturn_t token_type(const TrustCacheQueryToken_t *t,TCType_t *p) { return token_value(t,p,0); }
static TCReturn_t token_caps(const TrustCacheQueryToken_t *t,TCCapabilities_t *p) { return token_value(t,p,1); }
static TCReturn_t token_hash(const TrustCacheQueryToken_t *t,uint8_t *p) { return token_value(t,p,2); }
static TCReturn_t token_flags(const TrustCacheQueryToken_t *t,uint64_t *p) { return token_value(t,p,3); }
static TCReturn_t token_category(const TrustCacheQueryToken_t *t,uint8_t *p) { return token_value(t,p,4); }
static TCReturn_t extract(TrustCache_t *cache,const uint8_t *data,size_t n)
{ return construct(cache,data,n); /* Extraction never adds to authenticated registry. */ }
static TCReturn_t get_module(const TrustCache_t *cache,const uint8_t **address,size_t *n)
{
    if (!address || !n) { return ret(kTCComponentGetModule,kTCReturnInvalidArguments); }
    *address=NULL; *n=0;
    lck_mtx_lock(&ums512_tc_lock); struct record *r=find(cache); bool ok=intact(r);
    if (ok) { *address=r->module; *n=r->size; }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentGetModule,ok?kTCReturnSuccess:kTCReturnNotFound);
}
static TCReturn_t get_uuid(const TrustCache_t *cache,uint8_t uuid[16])
{
    if (!uuid) { return ret(kTCComponentGetUUID,kTCReturnInvalidArguments); }
    memset(uuid,0,16);
    lck_mtx_lock(&ums512_tc_lock); struct record *r=find(cache); bool ok=intact(r);
    if (ok) { memcpy(uuid,r->module+4,16); }
    lck_mtx_unlock(&ums512_tc_lock);
    return ret(kTCComponentGetUUID,ok?kTCReturnSuccess:kTCReturnNotFound);
}

const TrustCacheInterface_t ums512_trustcache_interface={
    .version=3,.loadModule=load_module,.load=load,.query=query,.getCapabilities=capabilities,
    .queryGetTCType=token_type,.queryGetCapabilities=token_caps,.queryGetHashType=token_hash,
    .queryGetFlags=token_flags,.queryGetConstraintCategory=token_category,.constructInvalid=construct,
    .checkRuntimeForUUID=check_uuid,.extractModule=extract,.getModule=get_module,.getUUID=get_uuid,
};

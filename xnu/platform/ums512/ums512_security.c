/* SPDX-License-Identifier: MIT
 * Explicit QEMU laboratory security profile. Signature verification is real;
 * userspace execution is quarantined until CodeDirectory/page/CMS integration
 * has execution tests. No Apple entitlements, platform trust or invalid-code
 * exceptions are granted. This is intentionally stricter than a usable OS.
 */
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/codesign.h>
#include <sys/trust_caches.h>
#include <mach/vm_prot.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <libkern/amfi/amfi.h>
struct flock;
struct componentname;
struct knote;
struct auditinfo_addr;
struct vnode_attr;
struct timespec;
#include <security/mac_policy.h>
#include <pexpert/device_tree.h>
#include "ums512_img4.h"
#include "ums512_security.h"
#if CODE_SIGNING_MONITOR || PMAP_CS_PPL_MONITOR
#error Laboratory provider requires the explicit non-monitor QEMU profile
#endif
#if !CONFIG_MACF
#error Laboratory provider requires mandatory MAC execution quarantine
#endif

extern const img4_interface_t ums512_image4_interface;
extern const TrustCacheInterface_t ums512_trustcache_interface;
extern TrustCacheRuntime_t *trust_cache_rt;
struct ums512_security_proof {
    uint64_t registered,firmware_cases,cache_cases,query_cases;
    uint64_t policy_cases,stock_runtime_ready,complete,execution_quarantined;
};
SECURITY_READ_ONLY_LATE(volatile struct ums512_security_proof) ums512_security_proof;
SECURITY_READ_ONLY_LATE(static amfi_t) lab_amfi;
static mac_policy_handle_t policy_handle;

static int deny_invalid(struct proc *p __unused) { return EPERM; }
static int deny_exec(kauth_cred_t cred __unused,struct vnode *vp __unused,struct vnode *script __unused,
    struct label *vl __unused,struct label *sl __unused,struct label *el __unused,
    struct componentname *cn __unused,u_int *flags __unused,void *attr __unused,size_t n __unused)
{ return EAUTH; }
static int deny_signature(struct vnode *vp __unused,struct label *label __unused,cpu_type_t cpu __unused,
    struct cs_blob *blob __unused,unsigned *flags __unused,unsigned *signer __unused,
    int mode __unused,unsigned platform __unused,char **desc __unused,size_t *length __unused)
{ return EAUTH; }
static int deny_supplement(struct vnode *vp __unused,struct label *label __unused,struct cs_blob *blob __unused,
    struct vnode *linked __unused,struct cs_blob *lb __unused,unsigned *signer __unused)
{ return EAUTH; }
static int check_anon(struct proc *proc __unused,kauth_cred_t cred __unused,user_addr_t address __unused,
    user_size_t size __unused,int prot,int flags __unused,int *maxprot)
{
    if (maxprot) { *maxprot &= ~VM_PROT_EXECUTE; }
    return (prot&VM_PROT_EXECUTE)?EPERM:0;
}
static int check_mmap(kauth_cred_t cred __unused,struct fileglob *fg __unused,struct label *label __unused,
    int prot,int flags __unused,uint64_t offset __unused,int *maxprot)
{
    if (maxprot) { *maxprot &= ~VM_PROT_EXECUTE; }
    return (prot&VM_PROT_EXECUTE)?EPERM:0;
}
static int check_mprotect(kauth_cred_t cred __unused,struct proc *p __unused,user_addr_t addr __unused,
    user_size_t size __unused,int prot)
{ return (prot&VM_PROT_EXECUTE)?EPERM:0; }
static int deny_cs_info(kauth_cred_t cred __unused,struct proc *p __unused,unsigned int op __unused)
{ return EPERM; }
static const struct mac_policy_ops policy_ops={
    .mpo_proc_check_run_cs_invalid=deny_invalid,.mpo_vnode_check_exec=deny_exec,
    .mpo_vnode_check_signature=deny_signature,.mpo_vnode_check_supplemental_signature=deny_supplement,
    .mpo_proc_check_map_anon=check_anon,.mpo_file_check_mmap=check_mmap,
    .mpo_proc_check_mprotect=check_mprotect,.mpo_proc_check_set_cs_info=deny_cs_info,
};
static struct mac_policy_conf policy_conf={
    .mpc_name="qemu_lab_quarantine",.mpc_fullname="QEMU laboratory execution quarantine",
    .mpc_ops=&policy_ops,.mpc_loadtime_flags=MPC_LOADTIME_FLAG_NOTLATE,
};
void ums512_mac_register(void)
{
    if (mac_policy_register(&policy_conf,&policy_handle,NULL)) { panic("QEMU lab MAC registration failed"); }
}
unsigned ums512_mac_selftest(void)
{
    int maxprot=VM_PROT_ALL;
    if (!deny_invalid(NULL) || !deny_exec(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0) ||
        !deny_signature(NULL,NULL,0,NULL,NULL,NULL,0,0,NULL,NULL) ||
        !check_anon(NULL,NULL,0,0,VM_PROT_EXECUTE,0,&maxprot) || (maxprot&VM_PROT_EXECUTE) ||
        !check_mprotect(NULL,NULL,0,0,VM_PROT_EXECUTE)) { panic("QEMU lab execution quarantine failed"); }
    maxprot=VM_PROT_ALL;
    if (check_anon(NULL,NULL,0,0,VM_PROT_READ|VM_PROT_WRITE,0,&maxprot) ||
        (maxprot&VM_PROT_EXECUTE) || check_mprotect(NULL,NULL,0,0,VM_PROT_READ)) { panic("QEMU lab data policy failed"); }
    return 7;
}
static void invalidate(void *entitlements)
{ if (entitlements) { panic("QEMU lab: unexpected entitlement object"); } }
static void *as_dict(void *object __unused) { return NULL; }
struct CEError { const char *description; };
static const struct CEError no_entitlement_error={"QEMU laboratory profile grants no entitlements"};
static CEError_t no_entitlement_query(void *object __unused,uint8_t cdhash[CS_CDHASH_LEN] __unused,
    CEQuery_t query __unused,size_t length __unused)
{ return &no_entitlement_error; }
static bool transmuted(void *object __unused,const CS_GenericBlob **blob)
{ if (blob) { *blob=NULL; } return false; }
static bool xml(void *object __unused,CS_GenericBlob **blob)
{ if (blob) { *blob=NULL; } return false; }
static bool no_bytes(const uint8_t **bytes,size_t *length)
{ if (bytes) { *bytes=NULL; } if (length) { *length=0; } return false; }
static void *context_object(CEQueryContext_t context __unused) { return NULL; }
static kern_return_t no_boolean(const void *object __unused,const char *name __unused) { return KERN_NO_ACCESS; }
static kern_return_t no_proc_boolean(proc_t p __unused,const char *name __unused) { return KERN_NO_ACCESS; }
static kern_return_t no_string(const void *object __unused,const char *name __unused,const char *value __unused)
{ return KERN_NO_ACCESS; }
static kern_return_t no_proc_string(proc_t p __unused,const char *name __unused,const char *value __unused)
{ return KERN_NO_ACCESS; }
static kern_return_t no_object(const void *object __unused,const char *name __unused,void **out)
{ if (out) { *out=NULL; } return KERN_NO_ACCESS; }
static kern_return_t no_proc_object(proc_t p __unused,const char *name __unused,void **out)
{ if (out) { *out=NULL; } return KERN_NO_ACCESS; }
static kern_return_t no_monitor(void *object __unused,const CEQueryContext_t context __unused,
    const void *signature __unused,const char *identity __unused,uint32_t flags __unused)
{ return KERN_NOT_SUPPORTED; }
static kern_return_t no_adjust(void *object __unused,struct cs_blob *blob __unused)
{ return KERN_NO_ACCESS; /* No signature/entitlement object can be published. */ }

void ums512_security_init(void)
{
    DTEntry root;
    const void *model=NULL; unsigned length=0;
    static const char expected[]="qemu,virt";
    if (SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&model,&length)!=kSuccess ||
        length!=sizeof(expected) || memcmp(model,expected,sizeof(expected))) {
        panic("Laboratory security runtime requires exact QEMU model");
    }
    if (img4if || amfi || ums512_security_proof.registered) { panic("Security provider already registered"); }
    ums512_mac_register();
    lab_amfi.TrustCache=ums512_trustcache_interface;
    lab_amfi.OSEntitlements_invalidate=invalidate; lab_amfi.OSEntitlements_asdict=as_dict;
    lab_amfi.OSEntitlements_query=no_entitlement_query;
    lab_amfi.OSEntitlements_get_transmuted=transmuted; lab_amfi.OSEntitlements_get_xml=xml;
    lab_amfi.get_legacy_profile_exemptions=no_bytes; lab_amfi.get_udid=no_bytes;
    lab_amfi.query_context_to_object=context_object;
    /* CE version 0 explicitly advertises no DER entitlement interpreter. This
     * non-PPL profile rejects signatures/exec before an entitlement object can
     * exist. OSEntitlements queries below deny every privilege. */
    lab_amfi.CoreEntitlements.version=0;
    lab_amfi.OSEntitlements=(OSEntitlementsInterface_t){.version=1,
        .adjustContextWithMonitor=no_monitor,.adjustContextWithoutMonitor=no_adjust,
        .queryEntitlementBoolean=no_boolean,.queryEntitlementBooleanWithProc=no_proc_boolean,
        .queryEntitlementString=no_string,.queryEntitlementStringWithProc=no_proc_string,
        .copyEntitlementAsOSObject=no_object,.copyEntitlementAsOSObjectWithProc=no_proc_object};
    ums512_security_proof.policy_cases=ums512_mac_selftest();
    img4_interface_register(&ums512_image4_interface);
    amfi_interface_register(&lab_amfi);
    ums512_security_proof.registered=1;
    ums512_security_proof.execution_quarantined=1;
}

static void require(bool test,const char *message)
{ if (!test) { panic("QEMU lab security runtime test: %s",message); } }
static TrustCache_t test_cache;
void ums512_security_runtime_test(void)
{
    require(img4if==&ums512_image4_interface && amfi==&lab_amfi,"registered interfaces");
    require(trust_cache_rt && trust_cache_rt->mutableRT && trust_cache_rt->image4RT==IMG4_RUNTIME_DEFAULT,"stock runtime initializer");
    ums512_security_proof.stock_runtime_ready=1;
    ums512_security_proof.firmware_cases=ums512_image4_runtime_selftest();
    const uint8_t *good=NULL,*manifest=NULL; size_t size=0,length=0; int accepted=0;
    require(ums512_img4_vector(0,&good,&size,&manifest,&length,&accepted) && accepted,"public fixture");
    TrustCache_t invalid={0};
    for (unsigned i=0;;i++) {
        const uint8_t *p,*m; size_t n,l; int expected;
        if (!ums512_img4_vector(i,&p,&n,&m,&l,&expected)) { break; }
        TrustCache_t *cache=expected?&test_cache:&invalid;
        TCReturn_t status=amfi->TrustCache.load(trust_cache_rt,UMS512_TC_LAB_TYPE,cache,(uintptr_t)p,n,(uintptr_t)m,l);
        require((status.error==kTCReturnSuccess)==(expected!=0),"authenticated cache load");
        ums512_security_proof.cache_cases++; ums512_security_proof.firmware_cases++;
    }
    TrustCacheQueryToken_t token={0};
    uint8_t unknown[20]={0},hash_type=0,category=255; uint64_t flags=1; TCType_t type=0;
    TCCapabilities_t caps=0; const TrustCache_t *found=NULL;
    const uint8_t *module=NULL; size_t module_size=0; uint8_t uuid[16];
    require(amfi->TrustCache.query(trust_cache_rt,kTCQueryTypeAll,good+24,&token).error==kTCReturnSuccess,"known hash");
    require(amfi->TrustCache.queryGetTCType(&token,&type).error==kTCReturnSuccess && type==UMS512_TC_LAB_TYPE,"private trust type");
    require(amfi->TrustCache.queryGetHashType(&token,&hash_type).error==kTCReturnSuccess && hash_type==2,"SHA256 type");
    require(amfi->TrustCache.queryGetFlags(&token,&flags).error==kTCReturnSuccess && !flags,"no privilege flags");
    require(amfi->TrustCache.queryGetConstraintCategory(&token,&category).error==kTCReturnSuccess && !category,"no constraint category");
    require(amfi->TrustCache.getCapabilities(&test_cache,&caps).error==kTCReturnSuccess && caps==7,"capabilities");
    require(amfi->TrustCache.queryGetCapabilities(&token,&caps).error==kTCReturnSuccess && caps==7,"token capabilities");
    require(amfi->TrustCache.getUUID(&test_cache,uuid).error==kTCReturnSuccess && !memcmp(uuid,good+4,16),"UUID");
    require(amfi->TrustCache.checkRuntimeForUUID(trust_cache_rt,uuid,&found).error==kTCReturnSuccess && found==&test_cache,"runtime UUID");
    require(amfi->TrustCache.getModule(&test_cache,&module,&module_size).error==kTCReturnSuccess && module_size==size && !memcmp(module,good,size),"owned module snapshot");
    require(amfi->TrustCache.query(trust_cache_rt,kTCQueryTypeAll,unknown,&token).error==kTCReturnNotFound && !token.trustCache,"unknown hash rejected");
    require(amfi->TrustCache.query(trust_cache_rt,kTCQueryTypeStatic,good+24,&token).error==kTCReturnNotFound,"no Apple static privilege");
    require(amfi->TrustCache.queryGetFlags(&token,&flags).error!=kTCReturnSuccess,"empty token rejected");
    require(amfi->TrustCache.load(trust_cache_rt,UMS512_TC_LAB_TYPE,&invalid,(uintptr_t)good,size,(uintptr_t)manifest,length).error==kTCReturnDuplicate,"duplicate UUID rejected");
    require(amfi->TrustCache.loadModule(trust_cache_rt,kTCTypeStatic,&invalid,(uintptr_t)good,size).error!=kTCReturnSuccess,"unauthenticated static rejected");
    require(amfi->TrustCache.load(trust_cache_rt,kTCTypeLTRS,&invalid,(uintptr_t)good,size,(uintptr_t)manifest,length).error!=kTCReturnSuccess,"nonce type rejected");
    require(amfi->TrustCache.load(trust_cache_rt,UMS512_TC_LAB_TYPE,&invalid,(uintptr_t)good,size,0,0).error!=kTCReturnSuccess,"unsigned cache rejected");
    require(amfi->TrustCache.constructInvalid(&invalid,good,size).error==kTCReturnSuccess && invalid.type==kTCTypeInvalid,"invalid construction");
    token.trustCache=&invalid; token.trustCacheEntry=good+24;
    require(amfi->TrustCache.queryGetFlags(&token,&flags).error!=kTCReturnSuccess,"forged token rejected");
    require(query_trust_cache(kTCQueryTypeAll,good+24,&token)==KERN_SUCCESS,"stock XNU locked query");
    require(query_trust_cache(kTCQueryTypeAll,unknown,&token)==KERN_NOT_FOUND,"stock XNU unknown query");
    require(query_trust_cache(kTCQueryTypeAll,good+24,&token)==KERN_SUCCESS,"snapshot query before corruption");
    /* Fault injection into our own publicly known test module. The stored
     * authentication digest is never changed or bypassed. */
    uint8_t *test_module=(void *)(uintptr_t)module;
    test_module[24]^=1;
    require(amfi->TrustCache.queryGetFlags(&token,&flags).error!=kTCReturnSuccess,"corrupted token rejected");
    require(amfi->TrustCache.query(trust_cache_rt,kTCQueryTypeAll,good+24,NULL).error==kTCReturnInvalidModule,"corrupted module rejected");
    test_module[24]^=1;
    require(query_trust_cache(kTCQueryTypeAll,good+24,&token)==KERN_SUCCESS,"authentic snapshot restored");
    ums512_security_proof.query_cases=25;
    require(amfi->OSEntitlements.queryEntitlementBoolean(NULL,"com.apple.private.skip-library-validation")!=KERN_SUCCESS,"no entitlement grants");
    require(ums512_security_proof.cache_cases==30,"all signed vectors checked");
    ums512_security_proof.complete=1;
}

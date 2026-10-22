/* SPDX-License-Identifier: MIT
 * Experimental Image4 v9 ABI provider, NOT Apple's production trust chain.
 * Only a bare `trst` payload with the pinned laboratory IM4M profile is
 * supported. Unsupported environments, nonces and flags are authentication
 * failures. Firmware owns private snapshots and releases caller buffers once.
 */
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#if MACH_KERNEL_PRIVATE
#include <kern/misc_protos.h>
#else
#include <libkern/libkern.h>
#endif
#include <libkern/img4/interface.h>
#include "ums512_img4.h"
#include "ums512_security.h"

struct _img4_chip { uint64_t identity; };
struct _img4_object_spec { size_t size; };
struct _img4_image { img4_buff_t bytes; };
struct _img4_firmware {
    uint64_t magic;
    bool allocated;
    errno_t error;
    img4_4cc_t object;
    img4_firmware_flags_t flags;
    img4_firmware_execution_context_t exec;
    img4_buff_t original_payload,original_manifest;
    uint8_t *payload,*manifest;
    size_t payload_size,manifest_size;
};
static const struct _img4_chip lab_chip={UINT64_C(0x51564d5445535431)};
static const struct _img4_object_spec firmware_spec={sizeof(struct _img4_firmware)};
static const struct _img4_object_spec chip_spec={sizeof(struct _img4_chip)};
static const img4_runtime_t lab_runtime;
#define FW_MAGIC UINT64_C(0x494d3452544c4142)
_Static_assert(sizeof(struct _img4_firmware)<=IMG4_FIRMWARE_SIZE_RECOMMENDED,"firmware storage");

static void *rt_alloc(const img4_runtime_t *rt,size_t n)
{
    if (rt!=&lab_runtime || !n || n>65536) { return NULL; }
    return kalloc_data(n,Z_WAITOK|Z_ZERO);
}
static void rt_free(const img4_runtime_t *rt,void *p,size_t n)
{
    (void)rt;
    if (p) { kfree_data(p,n); }
}
static void rt_log(const img4_runtime_t *rt,void *handle,img4_log_level_t level,const char *fmt,...) __printflike(4,5);
static void rt_log(const img4_runtime_t *rt,void *handle,img4_log_level_t level,const char *fmt,...)
{
    (void)rt; (void)handle; (void)level;
    va_list args;
    va_start(args,fmt); vprintf(fmt,args); va_end(args);
}
static void *rt_log_handle(const img4_runtime_t *rt) { (void)rt; return NULL; }
static errno_t rt_bool(const img4_runtime_t *rt,const img4_chip_t *chip,img4_identifier_t id,bool *value)
{
    if (rt!=&lab_runtime || chip!=&lab_chip || !value) { return EINVAL; }
    switch (id) {
    case IMG4_IDENTIFIER_CPRO: case IMG4_IDENTIFIER_CSEC:
    case IMG4_IDENTIFIER_EPRO: case IMG4_IDENTIFIER_ESEC: *value=true; return 0;
    default: return ENOTSUP;
    }
}
static errno_t rt_u32(const img4_runtime_t *rt,const img4_chip_t *chip,img4_identifier_t id,uint32_t *value)
{
    if (rt!=&lab_runtime || chip!=&lab_chip || !value) { return EINVAL; }
    switch (id) {
    case IMG4_IDENTIFIER_CEPO: case IMG4_IDENTIFIER_BORD: case IMG4_IDENTIFIER_SDOM: *value=1; return 0;
    case IMG4_IDENTIFIER_CHIP: *value=0x51564d; return 0;
    default: return ENOTSUP;
    }
}
static errno_t rt_u64(const img4_runtime_t *rt,const img4_chip_t *chip,img4_identifier_t id,uint64_t *value)
{
    if (rt!=&lab_runtime || chip!=&lab_chip || !value) { return EINVAL; }
    if (id!=IMG4_IDENTIFIER_ECID) { return ENOTSUP; }
    *value=lab_chip.identity; return 0;
}
static errno_t rt_digest(const img4_runtime_t *rt,const img4_chip_t *chip,img4_identifier_t id,img4_dgst_t *value)
{
    (void)rt; (void)chip; (void)id; (void)value;
    return ENOTSUP; /* No hardware identifier digest/nonce oracle exists. */
}
static const img4_runtime_t lab_runtime={
    .i4rt_version=0,.i4rt_name="QEMU laboratory trst / pinned public test root",
    .i4rt_alloc=rt_alloc,.i4rt_dealloc=rt_free,.i4rt_log=rt_log,.i4rt_log_handle=rt_log_handle,
    .i4rt_get_identifier_bool=rt_bool,.i4rt_get_identifier_uint32=rt_u32,
    .i4rt_get_identifier_uint64=rt_u64,.i4rt_get_identifier_digest=rt_digest,
};
static const img4_chip_t *chip_select(void) { return &lab_chip; }
static img4_chip_t *chip_init(void *buffer,size_t n)
{
    if (!buffer || n<sizeof(struct _img4_chip) || (uintptr_t)buffer%_Alignof(struct _img4_chip)) {
        panic("Image4 lab: invalid chip storage");
    }
    memset(buffer,0,sizeof(struct _img4_chip));
    return buffer;
}
static errno_t chip_instantiate(const img4_chip_t *chip,img4_chip_instance_t *instance)
{
    if (chip!=&lab_chip || !instance || instance->chid_version!=IMG4_CHIP_INSTANCE_STRUCT_VERSION) { return ENOTSUP; }
    *instance=IMG4_CHIP_INSTANCE_INIT(&lab_chip);
    instance->chid_omit=IMG4_CHIP_INSTANCE_OMIT_IUOU|IMG4_CHIP_INSTANCE_OMIT_RSCH|
        IMG4_CHIP_INSTANCE_OMIT_EUOU|IMG4_CHIP_INSTANCE_OMIT_ESDM|IMG4_CHIP_INSTANCE_OMIT_FPGT|
        IMG4_CHIP_INSTANCE_OMIT_UDID|IMG4_CHIP_INSTANCE_OMIT_FCHP|IMG4_CHIP_INSTANCE_OMIT_TYPE|
        IMG4_CHIP_INSTANCE_OMIT_STYP|IMG4_CHIP_INSTANCE_OMIT_CLAS;
    instance->chid_cepo=1; instance->chid_bord=1; instance->chid_chip=0x51564d;
    instance->chid_sdom=1; instance->chid_ecid=lab_chip.identity;
    instance->chid_cpro=true; instance->chid_csec=true;
    instance->chid_epro=true; instance->chid_esec=true;
    return 0;
}
static const img4_chip_t *chip_custom(const img4_chip_instance_t *instance,img4_chip_t *storage)
{
    (void)storage;
    /* Customizing trust/environment constraints is unsupported, never relaxed. */
    (void)instance; return NULL;
}
static img4_firmware_t fw_storage(void *buffer,size_t n)
{
    if (!buffer || n<sizeof(struct _img4_firmware) || (uintptr_t)buffer%_Alignof(struct _img4_firmware)) {
        panic("Image4 lab: invalid firmware storage");
    }
    memset(buffer,0,sizeof(struct _img4_firmware));
    return buffer;
}
static void buff_dealloc(img4_buff_t *buff)
{
    if (!buff) { return; }
    img4_buff_t owned=*buff;
    *buff=IMG4_BUFF_INIT;
    if (owned.i4b_dealloc && owned.i4b_bytes) {
        owned.i4b_dealloc(&lab_runtime,owned.i4b_bytes,owned.i4b_len);
    }
}
static void fw_init(img4_firmware_t fw,const img4_runtime_t *rt,
    const img4_firmware_execution_context_t *exec,img4_4cc_t object,img4_buff_t *buff,img4_firmware_flags_t flags)
{
    if (!fw || !exec || !buff) { panic("Image4 lab: invalid firmware initialization"); }
    fw->magic=FW_MAGIC; fw->exec=*exec; fw->object=object; fw->flags=flags;
    fw->original_payload=*buff; *buff=IMG4_BUFF_INIT;
    if (rt!=&lab_runtime || exec->i4fex_version>IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION ||
        object!=0x74727374 || flags!=IMG4_FIRMWARE_FLAG_BARE) { fw->error=ENOTSUP; return; }
    if (fw->original_payload.i4b_version || !fw->original_payload.i4b_bytes ||
        !fw->original_payload.i4b_len || fw->original_payload.i4b_len>24600) { fw->error=EINVAL; return; }
    fw->payload_size=fw->original_payload.i4b_len;
    fw->payload=rt_alloc(rt,fw->payload_size);
    if (!fw->payload) { fw->error=ENOMEM; return; }
    memcpy(fw->payload,fw->original_payload.i4b_bytes,fw->payload_size);
}
static img4_firmware_t fw_new(const img4_runtime_t *rt,const img4_firmware_execution_context_t *exec,
    img4_4cc_t object,img4_buff_t *buff,img4_firmware_flags_t flags)
{
    img4_firmware_t fw=kalloc_type(struct _img4_firmware,Z_WAITOK|Z_ZERO);
    if (!fw) { return NULL; }
    fw_init(fw,rt,exec,object,buff,flags); fw->allocated=true;
    return fw;
}
static img4_firmware_t fw_vnode(const img4_runtime_t *rt,const img4_firmware_execution_context_t *exec,
    img4_4cc_t object,vnode_t vnode,img4_firmware_flags_t flags)
{
    (void)vnode;
    img4_buff_t absent=IMG4_BUFF_INIT;
    img4_firmware_t fw=fw_new(rt,exec,object,&absent,flags);
    if (fw) { fw->error=ENOTSUP; }
    return fw; /* Honest unsupported evaluation; never authenticates a vnode. */
}
static void fw_manifest(img4_firmware_t fw,img4_buff_t *buff)
{
    if (!fw || fw->magic!=FW_MAGIC || !buff) { panic("Image4 lab: invalid manifest attachment"); }
    if (fw->original_manifest.i4b_bytes) { fw->error=EINVAL; buff_dealloc(buff); return; }
    fw->original_manifest=*buff; *buff=IMG4_BUFF_INIT;
    if (fw->error) { return; }
    if (fw->original_manifest.i4b_version || !fw->original_manifest.i4b_bytes ||
        !fw->original_manifest.i4b_len || fw->original_manifest.i4b_len>65536) { fw->error=EINVAL; return; }
    fw->manifest_size=fw->original_manifest.i4b_len;
    fw->manifest=rt_alloc(&lab_runtime,fw->manifest_size);
    if (!fw->manifest) { fw->error=ENOMEM; return; }
    memcpy(fw->manifest,fw->original_manifest.i4b_bytes,fw->manifest_size);
}
static errno_t fw_evaluate(img4_firmware_t fw,const img4_chip_t *chip,const img4_nonce_t *nonce)
{
    if (!fw || fw->magic!=FW_MAGIC) { return EINVAL; }
    if (fw->error) { return fw->error; }
    if (chip!=&lab_chip || nonce) { return ENOTSUP; }
    switch (ums512_img4_verify(fw->payload,fw->payload_size,fw->manifest,fw->manifest_size)) {
    case UMS_IMG4_OK: return 0;
    case UMS_IMG4_ARGUMENT: return EINVAL;
    case UMS_IMG4_ENCODING: return EFTYPE;
    case UMS_IMG4_SIGNATURE: return EAUTH;
    case UMS_IMG4_POLICY: return EACCES;
    case UMS_IMG4_DIGEST: case UMS_IMG4_MODULE: return ENOEXEC;
    default: return EAUTH;
    }
}
static void fw_execute(img4_firmware_t fw,const img4_chip_t *chip,const img4_nonce_t *nonce)
{
    errno_t error=fw_evaluate(fw,chip,nonce);
    if (!fw || fw->magic!=FW_MAGIC || !fw->exec.i4fex_execute) { panic("Image4 lab: missing execution callback"); }
    struct _img4_image image={.bytes=IMG4_BUFF_INIT};
    image.bytes.i4b_bytes=fw->payload; image.bytes.i4b_len=fw->payload_size;
    fw->exec.i4fex_execute(fw,error?NULL:&image,error,fw->exec.i4fex_context);
}
static void fw_destroy(img4_firmware_t *ptr)
{
    if (!ptr || !*ptr) { return; }
    img4_firmware_t fw=*ptr; *ptr=NULL;
    if (fw->magic!=FW_MAGIC) { panic("Image4 lab: invalid firmware destruction"); }
    bool allocated=fw->allocated;
    rt_free(&lab_runtime,fw->payload,fw->payload_size);
    rt_free(&lab_runtime,fw->manifest,fw->manifest_size);
    buff_dealloc(&fw->original_payload); buff_dealloc(&fw->original_manifest);
    memset(fw,0,sizeof(*fw));
    if (allocated) { kfree_type(struct _img4_firmware,fw); }
}
static const img4_buff_t *image_bytes(img4_image_t image) { return image?&image->bytes:NULL; }
static const bool *image_bool(img4_image_t image,img4_4cc_t cc,bool *value)
{
    if (!image || !value || (cc!=0x4550524f && cc!=0x45534543)) { return NULL; }
    *value=true; return value; /* Only authenticated lab images can exist. */
}
static const uint32_t *image_u32(img4_image_t image,img4_4cc_t cc,uint32_t *value)
{ (void)image; (void)cc; (void)value; return NULL; }
static const uint64_t *image_u64(img4_image_t image,img4_4cc_t cc,uint64_t *value)
{ (void)image; (void)cc; (void)value; return NULL; }
static const img4_buff_t *image_data(img4_image_t image,img4_4cc_t cc,img4_buff_t *value)
{ (void)image; (void)cc; (void)value; return NULL; }
static errno_t nonce_copy(const img4_nonce_domain_t *domain,img4_nonce_t *nonce)
{ (void)domain; (void)nonce; return ENOTSUP; }
static errno_t nonce_roll(const img4_nonce_domain_t *domain)
{ (void)domain; return ENOTSUP; }

const img4_interface_t ums512_image4_interface={
    .i4if_version=9,
    .i4if_v1={.nonce_domain_copy_nonce=nonce_copy,.nonce_domain_roll_nonce=nonce_roll},
    .i4if_v7={.chip_init_from_buff=chip_init,.chip_select_personalized_ap=chip_select,
        .chip_select_effective_ap=chip_select,.chip_instantiate=chip_instantiate,.chip_custom=chip_custom,
        .firmware_new=fw_new,.firmware_new_from_vnode_4xnu=fw_vnode,
        .firmware_init_from_buff=fw_storage,.firmware_init=fw_init,.firmware_attach_manifest=fw_manifest,
        .firmware_execute=fw_execute,.firmware_destroy=fw_destroy,.image_get_bytes=image_bytes,
        .image_get_property_bool=image_bool,.image_get_property_uint32=image_u32,
        .image_get_property_uint64=image_u64,.image_get_property_data=image_data,
        .firmware_spec=&firmware_spec,.chip_spec=&chip_spec,.runtime_default=&lab_runtime,.buff_dealloc=buff_dealloc},
    .i4if_v9={.firmware_evaluate=fw_evaluate},
};

struct execution_test {
    const uint8_t *payload;
    size_t size;
    bool expect_error;
    unsigned calls;
};
static unsigned buffer_releases;
static void release_test_buffer(const img4_runtime_t *rt,void *p,size_t n)
{ buffer_releases++; rt_free(rt,p,n); }
static void execution_test_callback(const img4_firmware_t fw,img4_image_t image,errno_t error,void *context)
{
    (void)fw;
    struct execution_test *test=context;
    test->calls++;
    if (test->expect_error) {
        if (!error || image) { panic("Image4 lab: unauthenticated execution callback"); }
    } else {
        if (error || !image) { panic("Image4 lab: valid execution callback missing"); }
        const img4_buff_t *bytes=img4_image_get_bytes(image);
        if (!bytes || bytes->i4b_len!=test->size || memcmp(bytes->i4b_bytes,test->payload,test->size)) {
            panic("Image4 lab: authenticated image mismatch");
        }
    }
}
unsigned ums512_image4_runtime_selftest(void)
{
    const uint8_t *payload,*manifest; size_t n,len; int accepted;
    buffer_releases=0;
    for (unsigned index=0;index<2;index++) {
        if (!ums512_img4_vector(index,&payload,&n,&manifest,&len,&accepted)) { panic("Image4 lab: missing lifecycle fixture"); }
        struct execution_test test={.payload=payload,.size=n,.expect_error=!accepted};
        img4_firmware_execution_context_t exec={.i4fex_version=IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION,
            .i4fex_execute=execution_test_callback,.i4fex_context=&test};
        img4_buff_t buff=IMG4_BUFF_INIT;
        uint8_t *original_payload=rt_alloc(&lab_runtime,n),*original_manifest=rt_alloc(&lab_runtime,len);
        if (!original_payload || !original_manifest) { panic("Image4 lab: lifecycle allocation"); }
        memcpy(original_payload,payload,n); memcpy(original_manifest,manifest,len);
        buff.i4b_bytes=original_payload; buff.i4b_len=n; buff.i4b_dealloc=release_test_buffer;
        img4_firmware_t fw=img4_firmware_new(IMG4_RUNTIME_DEFAULT,&exec,0x74727374,&buff,IMG4_FIRMWARE_FLAG_BARE);
        if (!fw || buff.i4b_bytes) { panic("Image4 lab: payload ownership"); }
        buff=IMG4_BUFF_INIT; buff.i4b_bytes=original_manifest; buff.i4b_len=len; buff.i4b_dealloc=release_test_buffer;
        img4_firmware_attach_manifest(fw,&buff);
        if (buff.i4b_bytes) { panic("Image4 lab: manifest ownership"); }
        /* Caller storage can change after the snapshots, without changing the
         * authenticated bytes delivered to the callback. */
        original_payload[0]^=1; original_manifest[0]^=1;
        if ((img4_firmware_evaluate(fw,chip_select(),NULL)==0)!=(accepted!=0)) { panic("Image4 lab: snapshot evaluation"); }
        img4_firmware_execute(fw,chip_select(),NULL);
        if (test.calls!=1) { panic("Image4 lab: callback count"); }
        img4_nonce_t nonce={0};
        if (img4_firmware_evaluate(fw,chip_select(),&nonce)==0) { panic("Image4 lab: unsupported nonce accepted"); }
        img4_firmware_destroy(&fw);
        if (fw || buffer_releases!=(index+1)*2) { panic("Image4 lab: owned buffer release"); }
    }
    /* Stack-backed firmware is destroyed without freeing caller object storage. */
    _Alignas(16) uint8_t storage[IMG4_FIRMWARE_SIZE_RECOMMENDED];
    img4_firmware_t fw=img4_firmware_init_from_buff(storage,sizeof(storage));
    img4_firmware_execution_context_t exec={.i4fex_version=IMG4_FIRMWARE_EXECUTION_CONTEXT_STRUCT_VERSION};
    img4_buff_t buff=IMG4_BUFF_INIT;
    buff.i4b_bytes=(void *)(uintptr_t)payload; buff.i4b_len=n;
    img4_firmware_init(fw,IMG4_RUNTIME_DEFAULT,&exec,0x74727374,&buff,IMG4_FIRMWARE_FLAG_INIT);
    if (img4_firmware_evaluate(fw,chip_select(),NULL)!=ENOTSUP) { panic("Image4 lab: unsupported flags accepted"); }
    img4_firmware_destroy(&fw);
    if (fw || buffer_releases!=4) { panic("Image4 lab: stack object destruction"); }
    return 12; /* Two snapshot/callback/nonce/ownership cycles plus stack/flag checks. */
}

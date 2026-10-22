/* Exact public-interface layout compiled with the pinned XNU private headers. */
#include <stddef.h>
#include <libkern/img4/interface.h>
#include <libkern/amfi/amfi.h>
_Static_assert(IMG4_INTERFACE_VERSION==18,"Image4 source version");
_Static_assert(KERN_AMFI_INTERFACE_VERSION==6,"AMFI source version");
_Static_assert(TRUST_CACHE_INTERFACE_VERSION==3,"TrustCache table version");
_Static_assert(sizeof(TrustCacheModule2_t)==24,"packed module header");
_Static_assert(sizeof(TrustCacheEntry2_t)==24,"packed module entry");
const unsigned long ums512_security_abi[]={
    sizeof(img4_interface_t),offsetof(img4_interface_t,i4if_v7.runtime_default),
    offsetof(img4_interface_t,i4if_v9.firmware_evaluate),
    sizeof(amfi_t),offsetof(amfi_t,CoreEntitlements),offsetof(amfi_t,TrustCache),
    sizeof(TrustCacheInterface_t),offsetof(TrustCacheInterface_t,load),
    sizeof(TrustCacheRuntime_t),sizeof(TrustCacheMutableRuntime_t),
    sizeof(TrustCache_t),sizeof(TrustCacheQueryToken_t),sizeof(TCReturn_t)
};

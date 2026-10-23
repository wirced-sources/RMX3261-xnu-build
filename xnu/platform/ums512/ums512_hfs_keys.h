/* SPDX-License-Identifier: MIT
 * Internal requests for the QEMU HFS port. This is NOT an AppleKeyStore ABI.
 * Native XNU key buffer types are reused; no Apple service table is invented.
 * There is no file-key provider: protected operations must fail ENXIO.
 */
#ifndef UMS512_HFS_KEYS_H
#define UMS512_HFS_KEYS_H
#include <sys/cprotect.h>
#include <uuid/uuid.h>
typedef struct rmx_hfs_key_cred {
    cp_cred_s context;
    uuid_t volume_uuid;
} *rmx_hfs_key_cred_t;
#endif

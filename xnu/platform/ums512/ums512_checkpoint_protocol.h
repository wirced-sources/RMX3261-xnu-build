/* SPDX-License-Identifier: MIT
 * M2.1 one-shot diagnostic checkpoint record. Non-secret, not an attestation.
 * The ARM64 XNU checkpoint writes EL and stage; courier validates before USB.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#define UMS512_CKPT_NAME "xnu_ckpt="
#define UMS512_CKPT_PENDING "0000000000000000"
#define UMS512_CKPT_EL1_ARMI "0000000441524d49"

/* Returns offset of 16-byte checkpoint value or n on error/duplication. */
static inline size_t ums512_ckpt_locate(const char *cmd, size_t n)
{
    const char prefix[] = UMS512_CKPT_NAME;
    size_t off=n, count=0, i=0;
    if (!cmd || !n) return n;
    while (i<n && cmd[i]) {
        size_t start=i;
        while (i<n && cmd[i] && cmd[i]!=' ') ++i;
        size_t len=i-start, k=0;
        while (k<sizeof(prefix)-1 && k<len && cmd[start+k]==prefix[k]) ++k;
        if (k==sizeof(prefix)-1) {
            if (++count!=1 || len!=(sizeof(prefix)-1)+16) return n;
            off=start+sizeof(prefix)-1;
        }
        if (i==n) return n; /* Require a NUL-terminated command line. */
        if (cmd[i]==' ') ++i;
    }
    return count==1 ? off : n;
}

static inline int ums512_ckpt_write(char *cmd, size_t n, uint64_t el, uint32_t stage)
{
    static const char digits[]="0123456789abcdef";
    size_t off=ums512_ckpt_locate(cmd,n);
    if (off==n) return 1;
    for (size_t j=0;j<16;j++)
        if (cmd[off+j]!=UMS512_CKPT_PENDING[j]) return 1;
    uint64_t value=(el<<32)|stage;
    for (size_t j=0;j<16;j++)
        cmd[off+j]=digits[(value>>(60-4*j))&15];
    return 0;
}

static inline int ums512_ckpt_is_el1_armi(const char *cmd, size_t n)
{
    size_t off=ums512_ckpt_locate(cmd,n);
    if (off==n) return 0;
    for (size_t j=0;j<16;j++)
        if (cmd[off+j]!=UMS512_CKPT_EL1_ARMI[j]) return 0;
    return 1;
}

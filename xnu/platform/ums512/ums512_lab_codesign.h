/* SPDX-License-Identifier: MIT */
#ifndef UMS512_LAB_CODESIGN_H
#define UMS512_LAB_CODESIGN_H
#include <stdint.h>
#include <stddef.h>
/* Strict per-build laboratory certificate pins, detached CMS/RSA2048/SHA256,
 * SHA256 CodeDirectory and every signed page. No Apple/platform entitlements. */
int ums512_lab_verify_file(const uint8_t *,size_t,uint64_t,uint8_t [32]);
int ums512_lab_verify_superblob(const uint8_t *,size_t,uint64_t,uint8_t [32]);
#ifdef KERNEL
struct vnode;
struct cs_blob;
int ums512_lab_authorize_vnode(struct vnode *,struct cs_blob *);
int ums512_lab_adjust_empty_entitlements(struct cs_blob *);
void ums512_lab_vnode_negative_tests(void);
extern volatile struct ums512_lab_exec_proof {
    uint64_t exec_allowed,signature_allowed,files_verified,denials;
    uint64_t vnode_negative_tests,reserved0,reserved1,reserved2;
} ums512_lab_exec_proof;
#endif
#endif

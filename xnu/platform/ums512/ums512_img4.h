/* SPDX-License-Identifier: MIT. Experimental QEMU trust profile, not Apple trust. */
#pragma once
#include <stdint.h>
#include <stddef.h>
enum ums512_img4_result {
    UMS_IMG4_OK=0, UMS_IMG4_ARGUMENT=1, UMS_IMG4_ENCODING=2,
    UMS_IMG4_SIGNATURE=3, UMS_IMG4_POLICY=4, UMS_IMG4_DIGEST=5,
    UMS_IMG4_MODULE=6
};
/* Caller owns immutable buffers throughout verification and subsequent use.
 * Accepted modules are bounded v2 SHA256 CDHash caches with no privilege flags.
 * Success does not register a cache, authorize execution, or grant entitlements.
 */
enum ums512_img4_result ums512_img4_verify(const uint8_t *,size_t,const uint8_t *,size_t);
unsigned ums512_img4_selftest(void);

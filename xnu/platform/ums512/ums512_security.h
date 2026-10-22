/* SPDX-License-Identifier: MIT */
#ifndef UMS512_SECURITY_H
#define UMS512_SECURITY_H
#include <stdint.h>
#include <stddef.h>
#define UMS512_TC_LAB_TYPE 0x80u /* Private type; never an Apple trust category. */
void ums512_security_init(void);
void ums512_security_runtime_test(void);
void ums512_mac_register(void);
unsigned ums512_mac_selftest(void);
unsigned ums512_image4_runtime_selftest(void);
#endif

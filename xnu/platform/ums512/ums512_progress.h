/* SPDX-License-Identifier: MIT. RAM record is NOT an observable USB proof. */
#pragma once
#include <stdint.h>
#include <stddef.h>
struct ums512_xnu_progress {
    uint64_t version, stage, current_el, counter;
    unsigned char nonce[16];
    char state; /* P until genuine arm_init checkpoint publishes D */
};
extern volatile struct ums512_xnu_progress ums512_xnu_progress;
int ums512_xnu_progress_parse(volatile struct ums512_xnu_progress *, const char *, size_t);
void ums512_xnu_arm_init_checkpoint(void *);

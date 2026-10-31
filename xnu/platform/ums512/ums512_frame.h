/* SPDX-License-Identifier: MIT. Caller-owned CPU RAM only, NOT DPU scanout. */
#pragma once
#include <stdint.h>
#include <stddef.h>
int ums512_frame_bars(uint32_t *, size_t, unsigned, unsigned, unsigned);
int ums512_frame_mask(uint32_t *, size_t, unsigned, unsigned, unsigned,
                      const unsigned char *, size_t, unsigned, unsigned);

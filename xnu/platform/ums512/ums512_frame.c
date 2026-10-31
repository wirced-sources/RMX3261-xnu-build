/* SPDX-License-Identifier: MIT. XRGB8888; no guessed framebuffer PA or MMIO. */
#include "ums512_frame.h"
static int valid(uint32_t *p, size_t bytes, unsigned w, unsigned h, unsigned stride)
{
    return p && !((uintptr_t)p&3) && w && h && w<=4096 && h<=4096 &&
        !(stride&3) && stride>=w*4 && stride<=65536 && (uint64_t)stride*h<=bytes;
}
int ums512_frame_bars(uint32_t *p, size_t bytes, unsigned w, unsigned h, unsigned stride)
{
    static const uint32_t colors[]={0x00ffffff,0x00ffff00,0x0000ffff,0x0000ff00,
                                   0x00ff00ff,0x00ff0000,0x000000ff,0};
    if (!valid(p,bytes,w,h,stride)) return 1;
    for (unsigned y=0;y<h;y++) for (unsigned x=0;x<w;x++) p[y*(stride/4)+x]=colors[(uint64_t)x*8/w];
    return 0;
}
int ums512_frame_mask(uint32_t *p, size_t bytes, unsigned w, unsigned h, unsigned stride,
                      const unsigned char *mask, size_t mask_bytes, unsigned mw, unsigned mh)
{
    if (!valid(p,bytes,w,h,stride) || !mask || !mw || !mh || mw>w || mh>h ||
        (uint64_t)mw*mh>mask_bytes) return 1;
    unsigned left=(w-mw)/2,top=(h-mh)/2;
    for (unsigned y=0;y<h;y++) for (unsigned x=0;x<w;x++) {
        unsigned on=x>=left && x-left<mw && y>=top && y-top<mh && mask[(y-top)*mw+x-left];
        p[y*(stride/4)+x]=on?0x00ffffff:0;
    }
    return 0;
}

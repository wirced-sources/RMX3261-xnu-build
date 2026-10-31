/* SPDX-License-Identifier: MIT. No fake transport: USB publisher still absent.
 * Called ONLY from genuine arm_init before PE_init_platform may reject hardware.
 */
#include "ums512_progress.h"
#include "xnu_boot.h"
volatile struct ums512_xnu_progress ums512_xnu_progress;
static int hex(char c)
{ return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1; }
int ums512_xnu_progress_parse(volatile struct ums512_xnu_progress *out, const char *cmd, size_t n)
{
    static const char prefix[]="xnu_probe=";
    unsigned char tag[16];
    size_t found=0;
    if (!out || !cmd || n>608) return 1;
    out->state='P';out->stage=0;
    for (size_t i=0;i<n && cmd[i];) {
        size_t end=i;
        while (end<n && cmd[end] && cmd[end]!=' ') end++;
        size_t k=0;
        while (k<sizeof(prefix)-1 && i+k<end && cmd[i+k]==prefix[k]) k++;
        if (k==sizeof(prefix)-1) {
            if (++found!=1 || end-i!=sizeof(prefix)-1+34 || cmd[end-2]!='-' || cmd[end-1]!='P') return 1;
            for (size_t j=0;j<16;j++) {
                int a=hex(cmd[i+k+j*2]),b=hex(cmd[i+k+j*2+1]);
                if (a<0 || b<0) return 1;
                tag[j]=(unsigned char)(a*16+b);
            }
        }
        i=end+(end<n && cmd[end]==' ');
    }
    if (found!=1) return 1;
    for (size_t i=0;i<16;i++) out->nonce[i]=tag[i];
    out->version=1;
    return 0;
}
#ifndef UMS512_PROGRESS_HOST_TEST
/* Explicit one-shot diagnostic return, before PE/IRQ/clock initialization.
 * Linux is a courier only: this genuine arm_init hook is the sole D writer.
 * No caller outside this function may turn a pending nonce into a result.
 */
static uint64_t return_address(const char *s, size_t n)
{
    static const char prefix[]="xnu_return=";
    uint64_t value=0;
    unsigned found=0;
    for (size_t i=0;i<n && s[i];) {
        size_t end=i,k=0;
        while (end<n && s[end] && s[end]!=' ') end++;
        while (k<sizeof(prefix)-1 && i+k<end && s[i+k]==prefix[k]) k++;
        if (k==sizeof(prefix)-1) {
            if (++found!=1 || end-i!=k+16) return 0;
            for (size_t j=0;j<16;j++) {
                int h=hex(s[i+k+j]);
                if (h<0) return 0;
                value=(value<<4)|(unsigned)h;
            }
        }
        i=end+(end<n && s[end]==' ');
    }
    return found==1 && value>=0x80080000 && value<0x81f00000 && !(value&3) ? value : 0;
}
__attribute__((noinline)) void ums512_xnu_arm_init_checkpoint(void *opaque)
{
    struct xnu_boot_args *args=opaque;
    if (!args || ums512_xnu_progress_parse(&ums512_xnu_progress,args->command_line,sizeof(args->command_line))) return;
    uint64_t el;
    __asm__ volatile("mrs %0, CurrentEL":"=r"(el));
    /* Do not touch the timer before its higher-EL access contract is checked. */
    ums512_xnu_progress.current_el=el;ums512_xnu_progress.counter=0;
    ums512_xnu_progress.stage=0x41524d49; /* ARMI, genuine C checkpoint only */
    __asm__ volatile("dmb sy":::"memory");
    ums512_xnu_progress.state='D';
    uint64_t target=return_address(args->command_line,sizeof(args->command_line));
    if (target) {
        /* The parser above proved exactly one complete xnu_probe=<nonce>-P.
         * Copy the suffix itself through the return path, never synthesize it
         * in the loader or Linux. boot_args remains caller-owned writable RAM.
         */
        volatile char *cmd=(volatile char *)args->command_line;
        for (size_t i=0;i+44<=sizeof(args->command_line) && cmd[i];i++) {
            if ((i==0 || cmd[i-1]==' ') && cmd[i]=='x' && cmd[i+1]=='n' &&
                cmd[i+2]=='u' && cmd[i+3]=='_' && cmd[i+4]=='p' &&
                cmd[i+5]=='r' && cmd[i+6]=='o' && cmd[i+7]=='b' &&
                cmd[i+8]=='e' && cmd[i+9]=='=') {
                cmd[i+43]='D';
                break;
            }
        }
        extern void ums512_xnu_return_to_linux(const struct xnu_boot_args *,uint64_t) __attribute__((noreturn));
        ums512_xnu_return_to_linux(args,target);
    }
}
#endif

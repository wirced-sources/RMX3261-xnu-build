#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ums512_checkpoint_protocol.h"

int main(void)
{
    char good[608]="-noprogress cpus=1 xnu_probe=01234567890123456789012345678901-P xnu_return=0000000080081234 xnu_ckpt=0000000000000000";
    assert(!ums512_ckpt_is_el1_armi(good,sizeof(good)));
    assert(!ums512_ckpt_write(good,sizeof(good),4,0x41524d49));
    assert(ums512_ckpt_is_el1_armi(good,sizeof(good)));
    assert(strstr(good,"xnu_ckpt=0000000441524d49"));
    assert(ums512_ckpt_write(good,sizeof(good),4,0x41524d49)); /* no overwrite */
    char el2[128]="xnu_ckpt=0000000000000000";
    assert(!ums512_ckpt_write(el2,sizeof(el2),8,0x41524d49));
    assert(!ums512_ckpt_is_el1_armi(el2,sizeof(el2)));
    char wrong_stage[128]="xnu_ckpt=0000000000000000";
    assert(!ums512_ckpt_write(wrong_stage,sizeof(wrong_stage),4,0x41524d48));
    assert(!ums512_ckpt_is_el1_armi(wrong_stage,sizeof(wrong_stage)));
    char duplicated[128]="xnu_ckpt=0000000000000000 xnu_ckpt=0000000000000000";
    assert(ums512_ckpt_write(duplicated,sizeof(duplicated),4,0x41524d49));
    char malformed[128]="xnu_ckpt=00000000000000000";
    assert(ums512_ckpt_write(malformed,sizeof(malformed),4,0x41524d49));
    char no_end[26]; memset(no_end,'Z',sizeof(no_end));
    memcpy(no_end,"xnu_ckpt=",9);
    assert(ums512_ckpt_locate(no_end,sizeof(no_end))==sizeof(no_end));
    puts("M2.1 checkpoint protocol host tests: PASS (7 cases)");
    return 0;
}

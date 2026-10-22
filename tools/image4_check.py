"""Run real IM4M trust verification and rejection vectors on the host."""
import argparse
import json
import platform
import subprocess
from pathlib import Path
from image4_vendor import ROOT,CFILES,COMMIT
from xnu_crypto import SOURCES


def check(source,crypto,compiler=None,sanitize=False):
    source,crypto=Path(source).resolve(),Path(crypto).resolve()
    work=ROOT/'out/native/image4-host';work.mkdir(exist_ok=True)
    harness=work/'main.c'
    harness.write_text('''#include <stdio.h>
#include <string.h>
#include "ums512_img4.h"
#include "ums512_img4_vectors.h"
int main(void) { unsigned n=ums512_img4_selftest();
    if (!n) return 1;
    const struct ums_img4_case *good=&ums_img4_cases[0];
    unsigned rejected=0;
    unsigned char copy[65536];
    for (size_t i=0;i<good->manifest_size;i++) {
        memcpy(copy,good->manifest,good->manifest_size); copy[i]^=1;
        if (ums512_img4_verify(good->payload,good->payload_size,copy,good->manifest_size)==UMS_IMG4_OK) {
            printf("unexpected manifest mutation accepted: %zu\\n",i);return 2; }
        rejected++;
        if (ums512_img4_verify(good->payload,good->payload_size,good->manifest,i)==UMS_IMG4_OK) return 3;
        rejected++;
    }
    for (size_t i=0;i<good->payload_size;i++) {
        memcpy(copy,good->payload,good->payload_size); copy[i]^=1;
        if (ums512_img4_verify(copy,good->payload_size,good->manifest,good->manifest_size)==UMS_IMG4_OK) return 4;
        rejected++;
    }
    /* Extra unsigned top-level field must not be silently ignored. */
    if (good->manifest[1]!=0x82) return 5;
    memcpy(copy,good->manifest,good->manifest_size);copy[good->manifest_size]=5;copy[good->manifest_size+1]=0;
    unsigned length=((unsigned)copy[2]<<8)|copy[3];length+=2;
    copy[2]=(unsigned char)(length>>8);copy[3]=(unsigned char)length;
    if (ums512_img4_verify(good->payload,good->payload_size,copy,good->manifest_size+2)==UMS_IMG4_OK) return 6;
    rejected++;
    printf("Image4 actual verifier: %u manifest/query checks and %u rejected mutations/truncations passed\\n",n,rejected);
    return 0; }
''')
    def path(p):
        s=str(p)
        return '/mnt/'+s[0].lower()+'/'+s[3:].replace('\\','/') if platform.system()=='Windows' else s
    prefix=['wsl','-d','Ubuntu','--exec','/usr/bin/clang'] if platform.system()=='Windows' else [compiler or 'clang']
    paths=[harness,source/'ums512_img4.c',*[source/n for n in CFILES],
           *[crypto/('br_'+Path(n).name) for n in SOURCES]]
    binary=work/('verify-asan' if sanitize else 'verify')
    args=[*prefix,'-std=c11','-O1' if sanitize else '-O2','-Wall','-Wextra','-Werror',
          '-I'+path(source),'-I'+path(crypto),*map(path,paths),'-o',path(binary)]
    if sanitize:args+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    if platform.system()=='Darwin':
        sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True,timeout=30).strip()
        args[len(prefix):len(prefix)]=['-isysroot',sdk]
    subprocess.run(args,check=True,timeout=90)
    command=['wsl','-d','Ubuntu','--exec',path(binary)] if platform.system()=='Windows' else [str(binary)]
    subprocess.run(command,check=True,timeout=30)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('crypto',type=Path)
    p.add_argument('--compiler');p.add_argument('--sanitize',action='store_true');a=p.parse_args()
    check(a.source,a.crypto,a.compiler,a.sanitize)

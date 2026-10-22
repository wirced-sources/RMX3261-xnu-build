"""Execute the actual portable RNG adapter against a NIST KAT and fail-closed cases."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
from xnu_crypto import ROOT, SOURCES

def check(source, compiler=None):
    source = Path(source).resolve()
    binary = ROOT/'out/native/crypto-rng-kat'
    paths = [ROOT/'tests/crypto_rng_kat.c',source/'ums512_rng.c',
             *[source/('br_'+Path(n).name) for n in SOURCES]]
    def path(value):
        text = str(value)
        if platform.system() == 'Windows':
            return '/mnt/'+text[0].lower()+'/'+text[3:].replace('\\','/')
        return text
    prefix = (['wsl','-d','Ubuntu','--exec','/usr/bin/clang'] if platform.system() == 'Windows'
              else [compiler or 'clang'])
    command = [*prefix,'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+path(source),
               *map(path,paths),'-o',path(binary)]
    subprocess.run(command,check=True,timeout=90)
    command = (['wsl','-d','Ubuntu','--exec',path(binary)] if platform.system() == 'Windows' else [str(binary)])
    subprocess.run(command,check=True,timeout=15)

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    p.add_argument('--compiler')
    a=p.parse_args()
    check(a.source,a.compiler)

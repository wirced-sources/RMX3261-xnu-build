"""Pinned MIT-licensed portable crypto dependency, never Apple corecrypto export."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('rand/hmac_drbg.c','mac/hmac.c','hash/md5.c','hash/sha1.c',
           'hash/sha2small.c','hash/sha2big.c','codec/dec32be.c','codec/enc32be.c',
           'codec/dec32le.c','codec/enc32le.c','codec/dec64be.c','codec/enc64be.c')

def archive(fetch=False):
    spec = json.loads((ROOT/'xnu/native.lock.json').read_text())['portable_crypto']
    path = ROOT/'out/native/bearssl-0.6.tar.gz'
    if not path.exists():
        if not fetch:
            raise FileNotFoundError('pinned crypto archive absent; use --fetch')
        with urllib.request.urlopen(spec['url'],timeout=60) as response:
            data = response.read(spec['bytes']+1)
        if len(data) != spec['bytes'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
            raise ValueError('crypto download identity mismatch')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    data = path.read_bytes()
    if len(data) != spec['bytes'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
        raise ValueError('crypto archive changed')
    return path

def install(src):
    dest = Path(src)/'libkern/ums512'
    dest.mkdir(parents=True,exist_ok=False)
    with tarfile.open(archive()) as package:
        names = ['LICENSE.txt','src/inner.h','src/config.h',*['src/'+n for n in SOURCES]]
        names += [m.name[len('bearssl-0.6/'):] for m in package.getmembers()
                  if m.isfile() and m.name.startswith('bearssl-0.6/inc/') and m.name.endswith('.h')]
        for name in names:
            member = package.getmember('bearssl-0.6/'+name)
            if not member.isfile() or member.size > 256*1024:
                raise ValueError('unexpected crypto archive member')
            data = package.extractfile(member).read()
            base = Path(name).name
            if name.startswith('src/') and name.endswith('.c'):
                base = 'br_'+base
            (dest/base).write_bytes(data)
    for name in ('ums512_rng.h','ums512_rng.c','ums512_crypto.c'):
        shutil.copyfile(ROOT/'xnu/platform/ums512'/name,dest/name)
    files = ['ums512_crypto.c','ums512_rng.c',*['br_'+Path(n).name for n in SOURCES]]
    config = Path(src)/'libkern/conf/files'
    with config.open('a',newline='\n') as output:
        for name in files:
            output.write(f'\nlibkern/ums512/{name}\toptional ums512\n')
    print('CRYPTO: pinned BearSSL0.6 RNG/digest/HMAC sources installed; no cipher/RSA provider',flush=True)
    return dest

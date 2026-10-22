"""Pinned OpenCore libDER/libDERImg4 verifier, without UEFI policy/overrides.

Sources retain their upstream APSL2/BSD notices. Only portability configuration
is adapted; no certificate/signature/role check is removed. This is not AMFI.
"""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '25d02c8d051dc2e9d9166b5a3b343ec5b77104cc'
SIZE = 19128710
SHA256 = 'db71866f1b4d7f2606513e721b0dbe19c749fe75f6e124790b87ba362d9993d7'
DIRECTORY = 'Library/OcAppleImg4Lib/'
CFILES = ('libDER/DER_CertCrl.c','libDER/DER_Decode.c','libDER/DER_Digest.c',
          'libDER/DER_Keys.c','libDER/oids.c','libDERImg4/DER_Img4Manifest.c',
          'libDERImg4/Img4oids.c')


def archive(fetch=False):
    path = ROOT/'out/native/opencore-img4-research/source.tar.gz'
    if not path.exists():
        if not fetch:
            raise FileNotFoundError('pinned Image4 verifier source absent; use --fetch')
        url = 'https://codeload.github.com/acidanthera/OpenCorePkg/tar.gz/'+COMMIT
        with urllib.request.urlopen(url,timeout=60) as response:
            data = response.read(SIZE+1)
        if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('Image4 verifier source identity mismatch')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    data = path.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Image4 verifier archive changed')
    return path


def install(destination):
    dest = Path(destination)
    dest.mkdir(parents=True,exist_ok=False)
    prefix = 'OpenCorePkg-'+COMMIT+'/'+DIRECTORY
    originals = {}
    with tarfile.open(archive()) as package:
        for member in package.getmembers():
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            name = member.name[len(prefix):]
            if not (name.startswith(('libDER/','libDERImg4/')) or name=='libDER_config.h'):
                continue
            if not name.endswith(('.c','.h')) or member.size > 128*1024:
                raise ValueError('unexpected verifier source')
            target = dest/name
            target.resolve().relative_to(dest.resolve())
            target.parent.mkdir(parents=True,exist_ok=True)
            data = package.extractfile(member).read()
            target.write_bytes(data)
            originals[name] = hashlib.sha256(data).hexdigest()
    config = dest/'libDER_config.h'
    text = config.read_text()
    begin = text.index('#include <Base.h>')
    end = text.index('#define DER_ENCODE_ENABLE',begin)
    text = text[:begin]+'''#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#ifdef KERNEL
#include <kern/assert.h>
#else
#include <assert.h>
#endif
#define STATIC static
#define CONST const
#define CopyMem(d,s,n) memmove((d),(s),(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

'''+text[end:]
    config.write_text(text,newline='\n')
    # Store the descriptor with memmove instead of dereferencing a byte-aligned
    # destination as DERItem*. Keep all parse/length/signature checks intact.
    decode=dest/'libDER/DER_Decode.c'
    text=decode.read_text()
    text=text.replace('DERItem *dst = (DERItem *)byteDst;','DERItem item; DERItem *dst = &item;')
    old='\t\t\t\t\t\tdst->length += (currDecoded.content.data - currDER);\n\t\t\t\t\t}'
    if text.count(old)!=1:
        raise ValueError('pinned descriptor storage changed')
    text=text.replace(old,old+'\n\t\t\t\t\tDERMemmove(byteDst, dst, sizeof(*dst));')
    decode.write_text(text,newline='\n')
    config = dest/'libDERImg4/libDERImg4_config.h'
    text = config.read_text().replace('const UINT8 *','const uint8_t *').replace('const UINTN  *','const size_t *')
    config.write_text(text,newline='\n')
    for name in ('ums512_img4.h','ums512_img4.c','ums512_img4_vectors.h'):
        shutil.copyfile(ROOT/'xnu/platform/ums512'/name,dest/name)
    (dest/'upstream-hashes.json').write_text(json.dumps(originals,indent=2)+'\n')
    return dest

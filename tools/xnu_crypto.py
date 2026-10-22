"""Pinned MIT-licensed portable crypto dependency, never Apple corecrypto export."""
import hashlib
import json
import re
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('rand/hmac_drbg.c','mac/hmac.c','hash/md5.c','hash/sha1.c',
           'hash/sha2small.c','hash/sha2big.c','codec/dec32be.c','codec/enc32be.c',
           'codec/dec32le.c','codec/enc32le.c','codec/dec64be.c','codec/enc64be.c',
           'rsa/rsa_i31_pkcs1_vrfy.c','rsa/rsa_i31_pub.c','rsa/rsa_pkcs1_sig_unpad.c',
           'int/i31_decode.c','int/i31_decmod.c','int/i31_encode.c','int/i31_ninv31.c',
           'int/i31_modpow2.c','int/i31_montmul.c','int/i31_muladd.c','int/i31_tmont.c',
           'int/i31_fmont.c','int/i31_sub.c','int/i31_add.c','int/i31_bitlen.c',
           'int/i32_div32.c','codec/ccopy.c',
           'symcipher/aes_ct64.c','symcipher/aes_ct64_enc.c',
           'symcipher/aes_ct64_dec.c','symcipher/aes_ct64_cbcenc.c',
           'symcipher/aes_ct64_cbcdec.c')

def typed_vtables(dest):
    # BearSSL0.6 casts concrete functions to generic OO vtable signatures.
    # Typed thunks preserve dispatch/algorithms without undefined indirect
    # function calls (Clang UBSan function reports). Keep that check enabled.
    for name,algs in [('br_md5.c',('md5',)),('br_sha1.c',('sha1',)),
                      ('br_sha2small.c',('sha224','sha256')),('br_sha2big.c',('sha384','sha512'))]:
        path=dest/name;text=path.read_text()
        for alg in algs:
            base='br_'+alg;typ=base+'_context';prefix=base+'_typed_'
            wrappers=f'''static void {prefix}init(const br_hash_class **p) {{ {base}_init(({typ} *)(void *)p); }}
static void {prefix}update(const br_hash_class **p, const void *d, size_t n) {{ {base}_update(({typ} *)(void *)p,d,n); }}
static void {prefix}out(const br_hash_class *const *p, void *d) {{ {base}_out((const {typ} *)(const void *)p,d); }}
static uint64_t {prefix}state(const br_hash_class *const *p, void *d) {{ return {base}_state((const {typ} *)(const void *)p,d); }}
static void {prefix}set_state(const br_hash_class **p, const void *d, uint64_t n) {{ {base}_set_state(({typ} *)(void *)p,d,n); }}
'''
            needle='const br_hash_class '+base+'_vtable = {'
            if text.count(needle)!=1:raise ValueError('hash vtable changed')
            text=text.replace(needle,wrappers+needle)
            for op in ('init','update','out','state','set_state'):
                pattern=r'\((?:void|uint64_t) \(\*\)\([^;{}]*?\)\)\s*&'+base+'_'+op+r'\b'
                text,count=re.subn(pattern,prefix+op,text)
                if count!=1:raise ValueError('hash vtable cast changed: '+base+' '+op)
        path.write_text(text,newline='\n')

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
    # XNU uses freestanding headers and strict narrowing diagnostics. Adapt
    # headers/conversions and bound the public RSA unpadding inputs; retain
    # the verification algorithms and every authentication check.
    fixes = {
        'inner.h': [('#include <limits.h>', '#ifdef KERNEL\n#include <machine/limits.h>\n#else\n#include <limits.h>\n#endif')],
        'br_rsa_pkcs1_sig_unpad.c': [
            ('if (sig_len < 11)', 'if (sig_len < 11 || hash_len > 64 || (hash_oid != NULL && hash_oid[0] > 32))'),
            ('pad2[2] = x2 + hash_len + 4;', 'pad2[2] = (unsigned char)(x2 + hash_len + 4);'),
            ('pad2[4] = x2;', 'pad2[4] = (unsigned char)x2;'),
            ('pad2[pad_len - 1] = hash_len;', 'pad2[pad_len - 1] = (unsigned char)hash_len;')],
        'br_i31_modpow2.c': [('mask = -EQ(u, bits);','mask = -EQ((uint32_t)u, bits);')],
        'br_i31_montmul.c': [('NEQ(dh, 0)','NEQ((uint32_t)dh, 0)')],
        'br_ccopy.c': [('*d = MUX(ctl, x, y);','*d = (unsigned char)MUX(ctl, x, y);')],
        'bearssl_ssl.h': [('cc->version_min = version_min;', 'cc->version_min = (uint16_t)version_min;'),
                         ('cc->version_max = version_max;', 'cc->version_max = (uint16_t)version_max;'),
                         ('ctx->protocol_names_num = num;', 'ctx->protocol_names_num = (uint16_t)num;')]
    }
    for name,changes in fixes.items():
        text = (dest/name).read_text()
        for old,new in changes:
            if text.count(old) != 1:
                raise ValueError('pinned crypto support header changed: '+name)
            text = text.replace(old,new)
        (dest/name).write_text(text,newline='\n')
    typed_vtables(dest)
    for name in ('ums512_rng.h','ums512_rng.c','ums512_crypto.c','ums512_aes.h','ums512_aes.c'):
        shutil.copyfile(ROOT/'xnu/platform/ums512'/name,dest/name)
    files = ['ums512_crypto.c','ums512_rng.c','ums512_aes.c',*['br_'+Path(n).name for n in SOURCES]]
    config = Path(src)/'libkern/conf/files'
    with config.open('a',newline='\n') as output:
        for name in files:
            output.write(f'\nlibkern/ums512/{name}\toptional ums512\n')
    print('CRYPTO: BearSSL0.6 RNG/digest/HMAC/AES-CBC and lab RSA verifier; no AEAD or corecrypto RSA registration',flush=True)
    return dest

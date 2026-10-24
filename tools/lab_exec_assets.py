"""Owned laboratory CMS/CodeDirectory assets; private keys stay in ignored work.

Only public certificates and executable metadata reach logs. Keys are deleted
in finally; no credential/key/SDK/device/image upload is configured or used.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import time
from qemu_user_fixture import build as build_fixture

ROOT=Path(__file__).resolve().parents[1]

def command(args,timeout=60):
    result=subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError('laboratory asset tool failed: '+result.stderr.decode(errors='replace')[-2000:])
    return result.stdout

def header_array(name,data):
    return 'static const unsigned char '+name+'[] = {'+','.join(map(str,data))+'};\n'

def sign(work,staging,clang,ld,openssl=None,include_foreign=True):
    work,staging=Path(work).resolve(),Path(staging).resolve()
    work.relative_to((ROOT/'out').resolve());staging.relative_to(work)
    crypto=work/'lab-signing';crypto.mkdir()
    openssl=openssl or ('/opt/homebrew/opt/openssl@3/bin/openssl' if Path('/opt/homebrew/opt/openssl@3/bin/openssl').is_file() else shutil.which('openssl'))
    if not openssl or not command([openssl,'version']).startswith(b'OpenSSL 3.'):
        raise RuntimeError('genuine OpenSSL3 required for isolated CMS fixtures')
    def run(*args): return command([openssl,*args])
    root_key,leaf_key=crypto/'root.key',crypto/'leaf.key'
    root,leaf,csr=crypto/'root.pem',crypto/'leaf.pem',crypto/'leaf.csr'
    config=crypto/'cert.cnf'
    config.write_text('''[req]
distinguished_name=dn
prompt=no
[dn]
CN=RMX isolated QEMU laboratory root
[root]
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''',encoding='utf-8',newline='\n')
    try:
        run('req','-new','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','3','-set_serial','1',
            '-config',config,'-extensions','root','-keyout',root_key,'-out',root)
        run('req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=RMX owned QEMU init',
            '-config',config,'-keyout',leaf_key,'-out',csr)
        run('x509','-req','-in',csr,'-CA',root,'-CAkey',root_key,'-set_serial','2','-days','2','-sha256',
            '-extfile',config,'-extensions','leaf','-out',leaf)
        run('verify','-CAfile',root,'-purpose','any',leaf)
        root_der=run('x509','-in',root,'-outform','DER')
        leaf_der=run('x509','-in',leaf,'-outform','DER')
        trust=header_array('lab_exec_root',root_der)+header_array('lab_exec_leaf',leaf_der)
        (crypto/'lab_exec_trust.h').write_text('/* Public per-build pinned lab chain, no private keys. */\n'+trust,encoding='utf-8',newline='\n')
        unsigned=build_fixture(work,staging,clang,ld,name='unsigned-init')
        owned=build_fixture(work,staging,clang,ld,user=True)
        target=staging/'sbin/launchd';data=bytearray(target.read_bytes())
        count,size=struct.unpack_from('<II',data,16);at=32;linkedit=None
        for _ in range(count):
            cmd,length=struct.unpack_from('<II',data,at)
            if cmd==0x19 and data[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT': linkedit=at
            at+=length
        if at!=32+size or linkedit is None or any(data[at:at+16]): raise ValueError('owned Mach-O has no signature-command padding/linkedit')
        sig_at=(len(data)+16383)&-16384
        data.extend(b'\0'*(sig_at-len(data)))
        ident=b'org.rmx.qemu.init\0';slots=(sig_at+16383)//16384
        cdfile,cmsfile=crypto/'code-directory',crypto/'signature.cms'
        def cms(content):
            cdfile.write_bytes(content)
            run('cms','-sign','-binary','-noattr','-nosmimecap','-md','sha256','-in',cdfile,
                '-signer',leaf,'-inkey',leaf_key,'-certfile',root,'-outform','DER','-out',cmsfile)
            return cmsfile.read_bytes()
        cdlen=48+len(ident)+slots*32
        cmslen=len(cms(b'size probe; detached RSA signature has fixed width'))
        total=28+cdlen+8+cmslen
        struct.pack_into('<II',data,16,count+1,size+16)
        struct.pack_into('<4I',data,at,0x1d,16,sig_at,total)
        off=struct.unpack_from('<Q',data,linkedit+40)[0]
        struct.pack_into('<Q',data,linkedit+32,((sig_at+total-off)+16383)&-16384)
        struct.pack_into('<Q',data,linkedit+48,sig_at+total-off)
        cd=struct.pack('>9I4B2I',0xfade0c02,cdlen,0x20100,0x300,48+len(ident),48,0,slots,sig_at,32,2,0,14,0,0)+ident
        cd+=b''.join(hashlib.sha256(data[i*16384:min(sig_at,(i+1)*16384)]).digest() for i in range(slots))
        signature=cms(cd)
        if len(signature)!=cmslen: raise ValueError('unexpected CMS size change')
        run('cms','-verify','-binary','-inform','DER','-in',cmsfile,'-content',cdfile,'-CAfile',root,'-purpose','any','-out',crypto/'verified-directory')
        sb=struct.pack('>7I',0xfade0cc0,total,2,0,28,0x10000,28+cdlen)+cd+struct.pack('>2I',0xfade0b01,8+cmslen)+signature
        data+=sb;target.write_bytes(data);target.chmod(0o755)
        for name,offset in [('altered-init',int(owned['entry'],16)-0x100000000),('bad-cms-init',len(data)-1)]:
            bad=bytearray(data);bad[offset]^=1;(staging/'sbin'/name).write_bytes(bad);(staging/'sbin'/name).chmod(0o755)
        result=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),entry=owned['entry'],
            signature_offset=sig_at,signature_bytes=len(sb),cd_sha256=hashlib.sha256(cd).hexdigest(),
            leaf_sha256=hashlib.sha256(leaf_der).hexdigest(),root_sha256=hashlib.sha256(root_der).hexdigest(),
            laboratory_only=True,private_keys_exported=False,apple_userland=False,syscall='Darwin ARM64 getpid20, svc0x80',
            unsigned_fixture=unsigned)
        if include_foreign:
            # A genuine independently valid chain, deliberately absent from
            # the primary kernel pins. Its private keys are also discarded.
            foreign_work=work/'foreign-chain';foreign_work.mkdir()
            foreign_content=foreign_work/'content';(foreign_content/'sbin').mkdir(parents=True)
            foreign=sign(foreign_work,foreign_content,clang,ld,openssl,include_foreign=False)
            shutil.copyfile(foreign_content/'sbin/launchd',staging/'sbin/foreign-init')
            (staging/'sbin/foreign-init').chmod(0o755)
            result['foreign_chain_negative']=dict(sha256=foreign['sha256'],root_sha256=foreign['root_sha256'],
                leaf_sha256=foreign['leaf_sha256'],independent_cms_verified=True,private_keys_exported=False)
        (crypto/'audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
        return result
    finally:
        # These two freshly generated, isolated temporary keys are not backups.
        for key in (root_key,leaf_key):
            key.resolve().relative_to((ROOT/'out').resolve())
            if key.exists(): key.unlink()

def check(source,crypto,asset,compiler=None,sanitize=False):
    source,crypto,asset=map(lambda p:Path(p).resolve(),(source,crypto,asset))
    build_dir=crypto/'codesign-host-check';build_dir.mkdir()
    harness=build_dir/'codesign-check.c'
    harness.write_text('''#include "ums512_lab_codesign.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc,char **argv) {
 if(argc<3) return 2;
 FILE *f=fopen(argv[1],"rb");if(!f)return 3;
 unsigned char *p=malloc(262144);size_t n=fread(p,1,262144,f);fclose(f);
 unsigned char d[32];uint64_t now=strtoull(argv[2],NULL,10);
 if(!ums512_lab_verify_file(p,n,now,d))return 4;
 size_t points[]={0,4,16,100,16370,n-1,n-128};
 for(unsigned i=0;i<sizeof(points)/sizeof(points[0]);i++) {
  p[points[i]]^=1;
  if(ums512_lab_verify_file(p,n,now,d))return 5;
  p[points[i]]^=1;
 }
 if(ums512_lab_verify_file(p,n-1,now,d) || ums512_lab_verify_file(p,n,0,d) ||
    ums512_lab_verify_file(p,n,4102444800ULL,d))return 6;
 for(int i=3;i<argc;i++) {
  f=fopen(argv[i],"rb");if(!f)return 7;
  n=fread(p,1,262144,f);fclose(f);
  if(ums512_lab_verify_file(p,n,now,d))return 8;
 }
 free(p);puts("CMS chain/CodeDirectory/pages positive and altered/expired/foreign negative checks PASS");return 0;
}
''',encoding='utf-8',newline='\n')
    def path(p):
        s=str(p);return '/mnt/'+s[0].lower()+'/'+s[3:].replace('\\','/') if platform.system()=='Windows' else s
    prefix=['wsl','-d','Ubuntu','--exec','clang'] if platform.system()=='Windows' else [compiler or 'clang']
    binary=build_dir/'codesign-check'
    args=[*prefix,'-std=c11','-O1','-Wall','-Wextra','-Werror','-I'+path(source),'-I'+path(crypto),
          path(harness),path(source/'ums512_lab_codesign.c')]
    from xnu_crypto import SOURCES
    args += [path(crypto/('br_'+Path(n).name)) for n in SOURCES]
    args += ['-o',path(binary)]
    if sanitize: args+=['-fsanitize=address,undefined','-fno-sanitize-recover=all']
    if platform.system()=='Darwin': args+=['-isysroot',subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()]
    subprocess.run(args,check=True,timeout=120)
    negatives=[asset.parent/n for n in ('unsigned-init','altered-init','bad-cms-init','foreign-init')]
    if not all(p.is_file() for p in negatives):raise ValueError('missing actual untrusted CMS fixtures')
    command([*(['wsl','-d','Ubuntu','--exec'] if platform.system()=='Windows' else []),path(binary),path(asset),str(int(time.time())),
             *map(path,negatives)])
    print('CMS/CodeDirectory actual host verifier PASS',flush=True)

"""Build pinned upstream QEMU for the ephemeral macOS native-kernel job only."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

from xnu_native import ROOT, OUT, digest, run


def build():
    if platform.system() != 'Darwin':
        raise RuntimeError('this QEMU host builder is restricted to the macOS CI job')
    spec = json.loads((ROOT/'xnu/native.lock.json').read_text())['qemu_test_host']
    work = OUT/'qemu-host'
    work.mkdir(exist_ok=False)
    report = work/'report'
    report.mkdir()
    archive = work/'source.tar.xz'
    with urllib.request.urlopen(spec['url'], timeout=60) as response, archive.open('wb') as target:
        while data := response.read(1024*1024):
            target.write(data)
            if target.tell() > spec['bytes']:
                raise ValueError('QEMU download exceeded pinned archive size')
    if archive.stat().st_size != spec['bytes'] or digest(archive) != spec['sha256']:
        raise ValueError('QEMU source archive integrity mismatch')
    with tarfile.open(archive) as source:
        source.extractall(work, filter='data')
    src = work/('qemu-'+spec['version'])
    env = os.environ.copy()
    env['CC'] = subprocess.check_output(['xcrun','--find','clang'],text=True).strip()
    env['CXX'] = subprocess.check_output(['xcrun','--find','clang++'],text=True).strip()
    # Reuse the runner's libraries before installing any ordinary build deps.
    for binary, package in (('pkg-config','pkgconf'),('ninja','ninja')):
        if not shutil.which(binary):
            run(['brew','install',package],'dependency-'+package,report,env,work,900)
    if subprocess.run(['pkg-config','--exists','glib-2.0'],env=env).returncode:
        run(['brew','install','glib'],'dependency-glib',report,env,work,900)
    obj = work/'build'
    obj.mkdir()
    run([src/'configure','--target-list=aarch64-softmmu','--with-devices-aarch64=minimal','--without-default-features',
         '--enable-tcg','--enable-fdt','--enable-download','--disable-docs','--disable-tools',
         '--disable-user','--disable-pixman'], 'configure',report,env,obj,300)
    run(['ninja','-j2','qemu-system-aarch64'],'qemu-build',report,env,obj,1800)
    version = subprocess.check_output([obj/'qemu-system-aarch64','--version'],text=True,timeout=15)
    if not version.startswith('QEMU emulator version '+spec['version']):
        raise ValueError('unexpected built QEMU version')
    print(version.strip(),flush=True)
    print('QEMU_BUILT: '+str(obj/'qemu-system-aarch64'),flush=True)


if __name__ == '__main__':
    build()

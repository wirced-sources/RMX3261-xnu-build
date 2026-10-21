"""Build pinned upstream QEMU for the ephemeral macOS native-kernel job only."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

from xnu_native import ROOT, OUT, digest, run


def source_filter(member, destination):
    # The pinned archive contains an optional EDK2 X11 host-header symlink.
    # We build QEMU, not firmware. Do not create a link into the runner host.
    if (member.name == 'qemu-9.2.4/roms/edk2/EmulatorPkg/Unix/Host/X11IncludeHack'
            and member.issym() and member.linkname == '/opt/X11/include'):
        return None
    return tarfile.data_filter(member, destination)


def build():
    if platform.system() != 'Darwin':
        raise RuntimeError('this QEMU host builder is restricted to the macOS CI job')
    spec = json.loads((ROOT/'xnu/native.lock.json').read_text())['qemu_test_host']
    work = OUT/'qemu-host'
    work.mkdir(parents=True, exist_ok=False)
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
        source.extractall(work, filter=source_filter)
    src = work/('qemu-'+spec['version'])
    env = os.environ.copy()
    env['CC'] = subprocess.check_output(['xcrun','--find','clang'],text=True).strip()
    env['CXX'] = subprocess.check_output(['xcrun','--find','clang++'],text=True).strip()
    sdk = subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    env['SDKROOT'] = sdk
    env['MACOSX_DEPLOYMENT_TARGET'] = '14.0'
    env['CFLAGS'] = '-isysroot '+sdk+' -mmacosx-version-min=14.0'
    env['CXXFLAGS'] = env['CFLAGS']
    env['LDFLAGS'] = '-isysroot '+sdk+' -mmacosx-version-min=14.0'
    # Reuse the runner's libraries before installing any ordinary build deps.
    for binary, package in (('pkg-config','pkgconf'),('ninja','ninja')):
        if not shutil.which(binary):
            run(['brew','install',package],'dependency-'+package,report,env,work,900)
    if subprocess.run(['pkg-config','--exists','glib-2.0'],env=env).returncode:
        run(['brew','install','glib'],'dependency-glib',report,env,work,900)
    obj = work/'build'
    obj.mkdir()
    # QEMU9's mkvenv needs distlib. New Homebrew pip no longer vendors it.
    # Install actual pinned build packages into this job's own venv, leaving
    # system/Homebrew Python and its externally-managed environment untouched.
    python_env = work/'build-python'
    run([sys.executable,'-m','venv',python_env],'python-venv',report,env,work,120)
    python = python_env/'bin/python3'
    run([python,'-m','pip','install','--disable-pip-version-check','--only-binary=:all:',
         'distlib==0.3.9','meson==1.5.0','pycotap==1.3.1'], 'python-deps',report,env,work,180)
    try:
        run([src/'configure','--target-list=aarch64-softmmu','--with-devices-aarch64=minimal','--without-default-features',
             '--python='+str(python),
             '--enable-tcg','--enable-fdt','--enable-download','--disable-docs','--disable-tools',
             '--disable-user','--disable-pixman'], 'configure',report,env,obj,300)
    except RuntimeError:
        for path in (obj/'meson-logs/meson-log.txt',obj/'config.log'):
            if path.is_file():
                print('NESTED CONFIGURE LOG: '+path.name,flush=True)
                print('\n'.join(path.read_text(errors='replace').splitlines()[-90:])[-18000:],flush=True)
        raise
    run(['ninja','-j2','qemu-system-aarch64'],'qemu-build',report,env,obj,1800)
    version = subprocess.check_output([obj/'qemu-system-aarch64','--version'],text=True,timeout=15)
    if not version.startswith('QEMU emulator version '+spec['version']):
        raise ValueError('unexpected built QEMU version')
    print(version.strip(),flush=True)
    print('QEMU_BUILT: '+str(obj/'qemu-system-aarch64'),flush=True)


if __name__ == '__main__':
    build()

"""Build owned, deliberately unsigned ARM64 init for an actual exec-denial test.

Not Apple launchd, a signing provider, or a runnable-userland claim. If security
unexpectedly permits this binary, its first instruction traps rather than
running an unbounded program. No private keys or Apple binaries are inputs.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def audit(data,trap=True):
    if not 32<=len(data)<=256*1024:
        raise ValueError('unsigned test executable size outside profile')
    magic,cpu,sub,kind,count,size,_,reserved=struct.unpack_from('<8I',data)
    if (magic,cpu,sub,kind,reserved)!=(0xfeedfacf,0x100000c,0,2,0) or count>32 or size>len(data)-32:
        raise ValueError('expected owned plain ARM64 MH_EXECUTE')
    at,end,entry,segments=32,32+size,None,[]
    for _ in range(count):
        if at+8>end:
            raise ValueError('truncated test executable command')
        command,length=struct.unpack_from('<II',data,at)
        if length<8 or length%8 or length>end-at:
            raise ValueError('invalid test executable command length')
        if command==0x19:
            if length<72:
                raise ValueError('short test executable segment')
            va,mem,off,stored,maximum,initial,sections,_=struct.unpack_from('<4Q4I',data,at+24)
            if length!=72+80*sections or off>len(data) or stored>len(data)-off or stored>mem or initial&~maximum or initial&6==6:
                raise ValueError('invalid test executable segment extent/protection')
            segments.append((va,off,stored,initial))
        elif command==5:
            if length!=288 or entry is not None or struct.unpack_from('<II',data,at+8)!=(6,68):
                raise ValueError('invalid ARM_THREAD_STATE64 test entry')
            entry=struct.unpack_from('<Q',data,at+272)[0]
        elif command==0xb:
            if length!=80 or struct.unpack_from('<18I',data,at+8)[5]:
                raise ValueError('undefined imports in unsigned test executable')
        elif command in (0x1d,0xc,0xe,0x18,0x80000018,0x8000001f,0x80000023,0x21,0x2c,0x80000028):
            raise ValueError('test binary must have no signature, dyld dependency, encryption or LC_MAIN')
        at+=length
    if at!=end or entry is None or not 0x4000<=entry<0x0000800000000000:
        raise ValueError('missing/invalid user test entry point')
    owner=next((s for s in segments if s[3]&4 and s[0]<=entry and entry+4<=s[0]+s[2]),None)
    if not owner or entry%4:
        raise ValueError('test entry outside executable file-backed bytes')
    offset=owner[1]+entry-owner[0]
    expected=0xd420a2a0 if trap else 0xd2800290
    if struct.unpack_from('<I',data,offset)[0]!=expected:
        raise ValueError('test entry must match the owned trap/getpid program')
    labels={};at=32
    for _ in range(count):
        command,length=struct.unpack_from('<II',data,at)
        if command==2:
            symoff,nsyms,stroff,strsize=struct.unpack_from('<4I',data,at+8)
            if symoff+16*nsyms>len(data) or stroff+strsize>len(data):raise ValueError('invalid own symbol table')
            for i in range(nsyms):
                index,kind,section,desc,value=struct.unpack_from('<IBBHQ',data,symoff+16*i)
                if index>=strsize:raise ValueError('invalid own symbol name')
                end=data.find(b'\0',stroff+index,stroff+strsize)
                if end<0:raise ValueError('unterminated own symbol name')
                name=bytes(data[stroff+index:end]).decode('ascii')
                if name.startswith('_lab_'):labels[name]=hex(value)
        at+=length
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),architecture='ARM64',
                entry=hex(entry),entry_file_offset=offset,labels=labels,unsigned=True,apple_userland=False,entry_is_trap=trap)


def build(work,staging,clang,ld,name='launchd',user=False):
    work,staging=Path(work).resolve(),Path(staging).resolve()
    for path in (work,staging):
        path.relative_to((ROOT/'out').resolve())
    if name not in ('launchd','unsigned-init','lab-child'): raise ValueError('unknown owned fixture name')
    directory=work/(name+'-fixture')
    directory.mkdir()
    source,obj=directory/'init.s',directory/'init.o'
    target=staging/'sbin'/name
    if target.exists() or target.is_symlink():
        raise ValueError('refusing to overwrite executable fixture')
    text=((ROOT/'xnu/userspace'/('lab_child.s' if name=='lab-child' else 'lab_init.s')).read_text()
          if user else '.section __TEXT,__text,regular,pure_instructions\n.p2align 2\n.globl _start\n_start:\n brk #0x515\n b _start\n')
    source.write_text(text,encoding='utf-8',newline='\n')
    commands=([clang,'-target','arm64-apple-macos11','-c',str(source),'-o',str(obj)],
              [ld,'-arch','arm64','-static','-e','_start','-platform_version','macos','11.0','14.5',
               '-no_adhoc_codesign','-no_uuid',*(['-image_base','0x110000000'] if name=='lab-child' else []),'-o',str(target),str(obj)])
    for command in commands:
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        if result.returncode:
            raise RuntimeError('owned unsigned init build failed: '+(result.stdout+result.stderr)[-4000:])
    proof=audit(target.read_bytes(),trap=not user)
    target.chmod(0o755)
    (directory/'audit.json').write_text(json.dumps(proof,indent=2)+'\n',encoding='utf-8',newline='\n')
    return proof

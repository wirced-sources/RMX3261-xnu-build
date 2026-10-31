"""Bind native M4 assets and collect actual QEMU evidence; never run a guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def sha(data):return hashlib.sha256(data).hexdigest()


def bind(kernel,root,manifest,trust):
    profile=json.loads(manifest)['profile']
    if profile!='process-lifecycle-v2':raise ValueError('M4 requires lifecycle v2')
    at=kernel.find(root)
    if not root or at<0 or kernel.find(root,at+1)>=0:
        raise ValueError('exact HFS bytes must occur once in linked kernel')
    return dict(profile=profile,kernel_sha256=sha(kernel),root_sha256=sha(root),
        root_bytes=len(root),embedded_file_offset=at,userspace_sha256=sha(manifest),
        trust_header_sha256=sha(trust),builder_commit=os.environ.get('GITHUB_SHA'),
        run_id=os.environ.get('GITHUB_RUN_ID'))


def verify(kernel,record,manifest):
    proof=record.get('m4_assets')
    if not proof:raise ValueError('M4 kernel has no asset provenance')
    at,n=proof['embedded_file_offset'],proof['root_bytes']
    if (proof['profile']!='process-lifecycle-v2' or json.loads(manifest)['profile']!=proof['profile'] or
        proof['kernel_sha256']!=sha(kernel) or record['sha256']!=sha(kernel) or
        proof['userspace_sha256']!=sha(manifest) or at<0 or n<=0 or at+n>len(kernel) or
        proof['root_sha256']!=sha(kernel[at:at+n])):
        raise ValueError('M4 kernel/HFS/userspace SHA256 provenance mismatch')
    return proof


def collect(report,executions,out):
    report,out=Path(report),Path(out)
    result=dict(status='NOT PASS',el0=False,eauth=0,build=False,runs=[],
                builder_commit=os.environ.get('GITHUB_SHA'),run_id=os.environ.get('GITHUB_RUN_ID'))
    try:
        record=json.loads((report/'kernel-audit.json').read_bytes())
        kernel=(report/'kernel.development.ums512.macho').read_bytes()
        binding=verify(kernel,record,(report/'userspace.json').read_bytes())
        if not record.get('upstream_install_succeeded') or not record.get('kernel_linked'):
            raise ValueError('native make install/link did not succeed')
        if (sha((report/'root.hfs').read_bytes())!=binding['root_sha256'] or
            sha((report/'lab_exec_trust.h').read_bytes())!=binding['trust_header_sha256']):
            raise ValueError('retained HFS/certificate pins differ from native build')
        result.update(build=True,assets=binding)
        labels=('unsigned_exec_denied','altered_exec_denied','bad_cms_exec_denied','foreign_exec_denied')
        for path in executions:
            run=json.loads(Path(path).read_bytes());life=run.get('userspace_lifecycle',{})
            events=[e for e in life.get('events',[]) if e.get('marker') in labels]
            count=sum(e.get('errno')==80 and not int(e['cpsr'],16)&15 for e in events)
            result['runs'].append(dict(path=str(path),eauth=count))
            result['eauth']=count
            if (run.get('error') or run.get('userspace_profile')!='process-lifecycle-v2' or
                run.get('kernel_sha256')!=record['sha256'] or
                not all(run.get(k) for k in ('user_el0_execution_verified','syscall_roundtrip_verified',
                    'genuine_getpid_handler_returned','user_program_completed')) or
                not life.get('complete') or count!=4 or {e['marker'] for e in events}!=set(labels) or
                not all(life.get(k,{}).get('first_instruction_executed') for k in ('entry_init','entry_child')) or
                sum(e['function']=='_execve' for e in life.get('kernel_entries',[]))!=5 or
                run.get('lab_exec_runtime',{}).get('denials')!=8 or
                run.get('native_signature_attachment_returns')!=[0,0] or
                run.get('global_cs_enforcement')!=1):
                raise ValueError('incomplete genuine M4 EL0/syscall/signature/EAUTH evidence')
        if not result['runs']:raise ValueError('no real QEMU execution records')
        result.update(status='PASS',el0=True)
    except Exception as error:
        result['blocker']=str(error)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'negative-tests.json').write_text(json.dumps(result['runs'],indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return result['status']=='PASS'


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--execution',type=Path,action='append',required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    raise SystemExit(0 if collect(a.report,a.execution,a.out) else 1)

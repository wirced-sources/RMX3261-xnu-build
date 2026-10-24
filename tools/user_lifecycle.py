"""Read-only observation of owned EL0 programs; never creates a guest process."""
import struct

MARKER=b'Owned QEMU laboratory data; no Apple userland.\n'
INIT_LABELS=('init_pid','file_read','closed_read','parent_forked','parent_waited','pipe_read',
             'parent_reaped','parent_unmapped','parent_done','cow_child','unsigned_exec_denied',
             'altered_exec_denied','init_fail')
CHILD_LABELS=('child_pid','child_parent','child_file_read','child_pipe_written','child_exit','child_fail')


class UserLifecycle:
    def __init__(self, manifest):
        if manifest.get('profile')!='process-lifecycle-v1':raise ValueError('unknown userspace profile')
        self.boundaries={};self.proof={'events':[]};self.manifest=manifest
        for image,labels,base in ((manifest,INIT_LABELS,0x100000000),(manifest['child'],CHILD_LABELS,0x110000000)):
            if image['identifier']!='org.rmx.qemu.'+('init' if image is manifest else 'child'):
                raise ValueError('unexpected controlled signing identifier')
            entries={k:int(image['labels']['_lab_'+k],16) for k in labels}
            entries['entry_init' if image is manifest else 'entry_child']=int(image['entry'],16)
            for name,pc in entries.items():
                if not base<=pc<base+128*1024 or pc%4 or pc in self.boundaries:
                    raise ValueError('invalid/overlapping owned user marker')
                self.boundaries[pc]='user:'+name
        if manifest['cd_sha256']==manifest['child']['cd_sha256']:
            raise ValueError('child must have its own authenticated CodeDirectory')

    def observe(self,name,rsp,regs,inspect):
        p=self.proof
        def reg(n):return int(regs[n],16)
        def memory(addr,n):
            if not 0x4000<=addr<0x800000000000 or n>512:raise ValueError('unbounded owned user read')
            data=bytes.fromhex(rsp.command(f'm{addr:x},{n:x}'))
            if len(data)!=n:raise RuntimeError('short owned user memory read')
            return data
        def require(ok,message):
            if not ok:raise RuntimeError('user lifecycle: '+message)
        if reg('cpsr')&15:raise RuntimeError('owned program marker must execute in EL0')
        event=dict(marker=name,pc=regs['pc'],cpsr=regs['cpsr'])
        p['events'].append(event)
        error=bool(reg('cpsr')&0x20000000)
        if name.startswith('entry_'):
            require(memory(reg('pc'),8)==struct.pack('<II',0xd2800290,0xd4001001),'entry opcode differs')
            system=rsp.system_registers();mapping=inspect(rsp,reg('pc'),system)
            require(mapping.get('valid') and mapping.get('read_only') and not mapping.get('unprivileged_execute_never'),'user code is not RO/executable')
            event.update(ttbr0=system['TTBR0_EL1'],code_mapping=mapping)
            rsp.command(f'z1,{reg("pc"):x},4');rsp.command('s');after=rsp.registers()
            require(int(after['pc'],16)==reg('pc')+4 and int(after['x16'],16)==20 and not int(after['cpsr'],16)&15,'first EL0 instruction failed')
            p[name]=dict(event,first_instruction_executed=True)
        elif name in ('init_pid','child_pid','child_parent'):
            expected=p.get('child_pid') if name=='child_pid' else 1
            require(not error and (reg('x0')==expected if expected else reg('x0')>1),'getpid/getppid mismatch')
            p[name]=reg('x0');event['pid']=reg('x0')
        elif name in ('file_read','child_file_read'):
            require(not error and reg('x0')==47 and memory(reg('sp'),47)==MARKER,'actual HFS read differs')
            p[name]=True;event['bytes']=47
        elif name=='closed_read':
            require(error and reg('x0')==9,'closed descriptor did not return EBADF');p[name]=True
        elif name in ('parent_forked','cow_child'):
            pid=reg('x23' if name=='parent_forked' else 'x20')
            require(pid>1,'fork child PID invalid')
            value=int.from_bytes(memory(reg('x19'),8),'little')
            require(value==(0x111 if name=='parent_forked' else 0x222),'private memory sentinel differs')
            system=rsp.system_registers();mapping=inspect(rsp,reg('x19'),system)
            require(mapping.get('valid') and mapping.get('unprivileged_execute_never'),'data mapping must be NX')
            p[name]=dict(pid=pid,va=regs['x19'],value=value,ttbr0=system['TTBR0_EL1'],mapping=mapping)
            event.update(p[name])
        elif name in ('unsigned_exec_denied','altered_exec_denied'):
            require(error and reg('x0')==80,'actual execve did not reject EAUTH');p[name]=True;event['errno']=80
        elif name=='child_pipe_written':
            require(not error and reg('x0')==16,'child pipe write failed');p[name]=True
        elif name=='child_exit':
            require(reg('x0')==37,'child exit status differs');p[name]=37
        elif name=='parent_waited':
            status=struct.unpack('<I',memory(reg('sp')+304,4))[0]
            require(not error and reg('x0')>1 and status==37<<8,'wait4 status differs')
            require(int.from_bytes(memory(reg('x19'),8),'little')==0x111,'child changed parent private memory')
            p[name]=dict(pid=reg('x0'),status=status,parent_sentinel=0x111);event.update(p[name])
        elif name=='pipe_read':
            values=struct.unpack('<2Q',memory(reg('sp')+320,16))
            require(not error and reg('x0')==16 and values[0]>1 and values[1]==0x222,'parent pipe result differs')
            p[name]=dict(pid=values[0],child_value=values[1]);event.update(p[name])
        elif name=='parent_reaped':
            require(error and reg('x0')==10,'second wait4 did not return ECHILD');p[name]=True
        elif name=='parent_unmapped':
            require(not error and reg('x0')==0 and inspect(rsp,reg('x19'),rsp.system_registers()).get('valid') is False,'munmap left a valid mapping');p[name]=True
        elif name=='parent_done':
            require(reg('x0')==0x515,'parent did not finish its userspace checks')
            self.validate();p['complete']=True;return True
        elif name.endswith('_fail'):raise RuntimeError('owned user program reached failure trap: '+name)
        return False

    def validate(self):
        p=self.proof
        required=set(INIT_LABELS+CHILD_LABELS)-{'init_fail','child_fail','parent_done'}
        if not all(p.get(n) for n in required) or not p.get('entry_init') or not p.get('entry_child'):
            raise RuntimeError('incomplete real userspace lifecycle observations')
        pid=p['child_pid']
        if not pid>1 or any(p[n]['pid']!=pid for n in ('parent_forked','cow_child','parent_waited','pipe_read')):
            raise RuntimeError('fork/exec/pipe/wait must identify the same distinct child PID')
        parent,child=p['parent_forked'],p['cow_child']
        root=lambda value:int(value,16)&0x0000ffffffffc000
        if (parent['va']!=child['va'] or parent['mapping']['pa']==child['mapping']['pa'] or
            root(parent['ttbr0'])==root(child['ttbr0']) or
            root(parent['ttbr0'])==root(p['entry_child']['ttbr0'])):
            raise RuntimeError('separate VM roots and actual private CoW pages were not observed')
        p['distinct_pids_and_address_spaces']=True
        p['actual_fork_exec_exit_wait4']=True

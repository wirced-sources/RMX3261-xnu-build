"""Local/CI owned EL1 QEMU timer fixture. No guest register/memory writes via GDB.
Not an XNU runtime proof or any physical-device authorization.
"""
from pathlib import Path
import sys,socket,subprocess,time,json,struct
import argparse,shutil
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tools'))
parser=argparse.ArgumentParser(description='Owned QEMU-only architectural PAN and instruction-clock probe; not XNU')
parser.add_argument('--qemu',default=None);parser.add_argument('--clang',default=shutil.which('clang'))
args=parser.parse_args()
from xnu_kernel_qemu import extract_wrapper,symbols,RSP
work=root/'out/native/icount-clock-probe';work.mkdir(exist_ok=True)
source='''.section __TEXT,__text,regular,pure_instructions
Lhead:
 b Lstart
 .long 0
 .quad 0
 .quad Lend-Lhead
 .quad 8
 .quad 0,0,0
 .ascii "ARMd"
 .long 0
Lstart:
 mov x2,#0x42000000
 mrs x0,CNTPCT_EL0
 str x0,[x2]
L_pause:
 mov x1,#50000
Lloop:
 subs x1,x1,#1
 b.ne Lloop
 mrs x0,CNTPCT_EL0
 str x0,[x2,#8]
 mrs x0,CNTFRQ_EL0
 str x0,[x2,#16]
L_done:
 b L_done
Lend:
'''
(work/'probe.s').write_text(source)
subprocess.run([args.clang,'-target','arm64-apple-macos11','-c',work/'probe.s','-o',work/'probe.o'],check=True)
data=(work/'probe.o').read_bytes();blob=extract_wrapper(data);(work/'Image').write_bytes(blob);sym={'_pause':blob.index(struct.pack('<I',0xd2800000|(50000<<5)|1)),'_done':len(blob)-4}
with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
p=subprocess.Popen([(args.qemu or shutil.which('qemu-system-aarch64') or 'C:/Program Files/qemu/qemu-system-aarch64.exe'),'-machine','virt,virtualization=off','-cpu','cortex-a55','-m','512M','-smp','1','-nic','none','-display','none','-monitor','none','-serial','none','-accel','tcg,thread=single','-icount','shift=3,align=off,sleep=off','-rtc','base=utc,clock=vm','-S','-gdb',f'tcp:127.0.0.1:{port}','-device',f'loader,file={work / "Image"},addr=0x44000000,cpu-num=0,force-raw=on'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for i in range(10):
  if p.poll() is not None:raise RuntimeError(p.stderr.read().decode())
  try:c=socket.create_connection(('127.0.0.1',port),timeout=1);break
  except OSError:time.sleep(.05)
 else:raise RuntimeError('clock probe GDB unavailable')
 c.settimeout(10);rsp=RSP(c);rsp.command('?')
 for name in ('_pause','_done'):assert rsp.command(f'Z1,{0x44000000+sym[name]:x},4')=='OK'
 try:rsp.command('c')
 except TimeoutError:
  c.sendall(b'\x03');print('interrupted',rsp.receive(),rsp.registers(),rsp.system_registers(),flush=True);raise
 time.sleep(.2);rsp.command(f'z1,{0x44000000+sym["_pause"]:x},4');rsp.command('c')
 a,b,hz=struct.unpack('<QQQ',bytes.fromhex(rsp.command('m42000000,18')))
 assert hz>0 and abs((b-a)-100000*8*hz/1000000000)<=8,(a,b,hz)
 report=dict(scope='Owned EL1 local QEMU architectural timer fixture, not XNU',debugger_pause_ms=200,loop_iterations=50000,
 counter_delta_ticks=b-a,counter_frequency_hz=hz,pan_model=rsp.system_registers(),
 virtual_time='TCG icount shift3 sleep=off RTC vm',guest_register_writes=False)
 assert (int(report['pan_model']['ID_AA64MMFR1_EL1'],16)>>20)&15 in (1,2,3)
 print(json.dumps(report,indent=2));(work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
finally:
 p.terminate()
 try:p.wait(timeout=5)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

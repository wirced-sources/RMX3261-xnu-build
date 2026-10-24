/* Owned freestanding Darwin ARM64 process lifecycle; no library/entitlement. */
.section __TEXT,__text,regular,pure_instructions
.p2align 2
.macro CALL number
 mov x16,#\number
 svc #0x80
 b.cs L_fail
.endmacro
.macro EXEC path
 adr x0,\path
 str x0,[sp,#256]
 add x1,sp,#288
 str x1,[sp,#264]
 str xzr,[sp,#272]
 add x1,sp,#256
 mov x2,#0
 mov x16,#59
 svc #0x80
.endmacro
.globl _start
_start:
 mov x16,#20
 svc #0x80
.globl _lab_init_pid
_lab_init_pid:
 b.cs L_fail
 cmp x0,#1
 b.ne L_fail
 sub sp,sp,#512
 adr x0,L_root
 mov x1,#0
 mov x2,#0
 CALL 5
 mov x24,x0
 mov x1,sp
 mov x2,#47
 CALL 3
.globl _lab_file_read
_lab_file_read:
 cmp x0,#47
 b.ne L_fail
 adr x1,L_expected
 mov x2,sp
 mov x3,#47
L_compare:
 ldrb w4,[x1],#1
 ldrb w5,[x2],#1
 cmp w4,w5
 b.ne L_fail
 subs x3,x3,#1
 b.ne L_compare
 mov x0,x24
 mov x1,sp
 mov x2,#1
 CALL 3
 cbnz x0,L_fail
 mov x0,x24
 CALL 6
 mov x0,x24
 mov x1,sp
 mov x2,#1
 mov x16,#3
 svc #0x80
.globl _lab_closed_read
_lab_closed_read:
 b.cc L_fail
 cmp x0,#9
 b.ne L_fail
 mov x0,#0
 mov x1,#16384
 mov x2,#3
 mov x3,#0x1002
 mov x4,#-1
 mov x5,#0
 CALL 197
 mov x19,x0
 mov x1,#0x111
 str x1,[x19]
 CALL 42
 mov x21,x0
 mov x22,x1
 cmp x22,#9
 b.hi L_fail
 add w1,w22,#48
 strb w1,[sp,#288]
 strb wzr,[sp,#289]
 CALL 2
 cbnz x1,L_fork_child
 mov x23,x0
.globl _lab_parent_forked
_lab_parent_forked:
 cmp x23,#1
 b.ls L_fail
 mov x0,x22
 CALL 6
 mov x0,x23
 add x1,sp,#304
 mov x2,#0
 mov x3,#0
 CALL 7
.globl _lab_parent_waited
_lab_parent_waited:
 cmp x0,x23
 b.ne L_fail
 ldr w1,[sp,#304]
 mov w2,#0x2500
 cmp w1,w2
 b.ne L_fail
 ldr x1,[x19]
 cmp x1,#0x111
 b.ne L_fail
 mov x0,x21
 add x1,sp,#320
 mov x2,#16
 CALL 3
.globl _lab_pipe_read
_lab_pipe_read:
 cmp x0,#16
 b.ne L_fail
 ldr x1,[sp,#320]
 cmp x1,x23
 b.ne L_fail
 ldr x1,[sp,#328]
 cmp x1,#0x222
 b.ne L_fail
 mov x0,x21
 mov x1,sp
 mov x2,#1
 CALL 3
 cbnz x0,L_fail
 mov x0,x21
 CALL 6
 mov x0,x23
 add x1,sp,#304
 mov x2,#0
 mov x3,#0
 mov x16,#7
 svc #0x80
.globl _lab_parent_reaped
_lab_parent_reaped:
 b.cc L_fail
 cmp x0,#10
 b.ne L_fail
 mov x0,x19
 mov x1,#16384
 CALL 73
.globl _lab_parent_unmapped
_lab_parent_unmapped:
 CALL 20
 cmp x0,#1
 b.ne L_fail
 mov x0,#0x515
.globl _lab_parent_done
_lab_parent_done:
 b _lab_parent_done
L_fork_child:
 mov x0,x21
 CALL 6
 mov x0,#0x222
 str x0,[x19]
 CALL 20
 mov x20,x0
.globl _lab_cow_child
_lab_cow_child:
 cmp x20,#1
 b.ls L_fail
 EXEC L_unsigned
.globl _lab_unsigned_exec_denied
_lab_unsigned_exec_denied:
 b.cc L_fail
 cmp x0,#80
 b.ne L_fail
 EXEC L_altered
.globl _lab_altered_exec_denied
_lab_altered_exec_denied:
 b.cc L_fail
 cmp x0,#80
 b.ne L_fail
 EXEC L_child
 b L_fail
.globl _lab_init_fail
_lab_init_fail:
L_fail:
 brk #0x516
 b L_fail
L_root: .asciz "/root-proof.txt"
L_child: .asciz "/sbin/lab-child"
L_unsigned: .asciz "/sbin/unsigned-child"
L_altered: .asciz "/sbin/altered-child"
L_expected: .ascii "Owned QEMU laboratory data; no Apple userland.\n"

/* Independently CMS-signed child image. Inherited pipe fd arrives in argv[1]. */
.section __TEXT,__text,regular,pure_instructions
.p2align 2
.macro CALL number
 mov x16,#\number
 svc #0x80
 b.cs L_fail
.endmacro
.globl _start
_start:
 mov x16,#20
 svc #0x80
.globl _lab_child_pid
_lab_child_pid:
 b.cs L_fail
 cmp x0,#1
 b.ls L_fail
 mov x20,x0
 mov x9,sp
 and x10,x9,#-16
 mov sp,x10
 ldr x0,[x9]
 cmp x0,#2
 b.ne L_fail
 ldr x0,[x9,#16]
 ldrb w22,[x0]
 sub w22,w22,#48
 cmp w22,#9
 b.hi L_fail
 ldrb w1,[x0,#1]
 cbnz w1,L_fail
 sub sp,sp,#256
 CALL 39
.globl _lab_child_parent
_lab_child_parent:
 cmp x0,#1
 b.ne L_fail
 adr x0,L_root
 mov x1,#0
 mov x2,#0
 CALL 5
 mov x24,x0
 mov x1,sp
 mov x2,#47
 CALL 3
.globl _lab_child_file_read
_lab_child_file_read:
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
 CALL 6
 str x20,[sp,#64]
 mov x0,#0x222
 str x0,[sp,#72]
 mov x0,x22
 add x1,sp,#64
 mov x2,#16
 CALL 4
.globl _lab_child_pipe_written
_lab_child_pipe_written:
 cmp x0,#16
 b.ne L_fail
 mov x0,x22
 CALL 6
 mov x0,#37
.globl _lab_child_exit
_lab_child_exit:
 mov x16,#1
 svc #0x80
.globl _lab_child_fail
_lab_child_fail:
L_fail:
 brk #0x517
 b L_fail
L_root: .asciz "/root-proof.txt"
L_expected: .ascii "Owned QEMU laboratory data; no Apple userland.\n"

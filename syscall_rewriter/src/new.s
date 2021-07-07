.section .ktext
.globl dummy_asm_func
.type dummy_asm_func, @function

dummy_asm_func:
	ret 

fast_syscall_prologue:
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %r10
	push %r8
	push %r9
	mov %rsp,%rdi
	call fast_syscall_handler
	pop %r9
	pop %r8
	pop %r10
	pop %rdx
	pop %rsi
	pop %rdi
	pop %rax
	ret

syscall_4022fd_destination:
	mov %r10,%rcx 
	call sys_arch_prctl
	test   %rax,%rax
	push $0x00402302
	ret 

syscall_403ef5_destination:
	call fast_syscall_prologue
	mov    0x10(%r12),%rax
	push $0x00403efc
	ret 

syscall_40f488_destination:
	call fast_syscall_prologue
	mov    $0x27,%ecx
	push $0x0040f48f
	ret 

syscall_40f491_destination:
	mov %r10,%rcx 
	call sys_getpid
	mov    %rax,%rdi
	push $0x0040f496
	ret 

syscall_40f49b_destination:
	call fast_syscall_prologue
	mov    %eax,%esi
	push $0x0040f49f
	ret 

syscall_40f4a7_destination:
	mov %r10,%rcx 
	call sys_tgkill
	cmp    $0xfffffffffffff000,%rax
	push $0x0040f4af
	ret 

syscall_40f4c9_destination:
	call fast_syscall_prologue
	mov    0x108(%rsp),%rax
	push $0x0040f4d3
	ret 

syscall_413c58_destination:
	mov %r10,%rcx 
	call sys_writev
	cmp    $0xfffffffffffffffc,%rax
	push $0x00413c5e
	ret 

syscall_413ed3_destination:
	mov %r10,%rcx 
	call sys_writev
	cmp    $0xfffffffffffffffc,%rax
	push $0x00413ed9
	ret 

syscall_4170e1_destination:
	call fast_syscall_prologue
	nopl   0x0(%rax,%rax,1)
	push $0x004170e8
	ret 

syscall_448004_destination:
	mov %r10,%rcx 
	call sys_exit
	cmp    $0xfffffffffffff000,%rax
	push $0x0044800c
	ret 

syscall_448014_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x0044801c
	ret 

syscall_448549_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff001,%rax
	push $0x00448551
	ret 

syscall_4485e8_destination:
	mov %r10,%rcx 
	call sys_stat
	cmp    $0xfffffffffffff000,%rax
	push $0x004485f0
	ret 

syscall_448647_destination:
	mov %r10,%rcx 
	call sys_fstat
	cmp    $0xfffffffffffff000,%rax
	push $0x0044864f
	ret 

syscall_4486e9_destination:
	mov %r10,%rcx 
	call sys_openat
	cmp    $0xfffffffffffff000,%rax
	push $0x004486f1
	ret 

syscall_448762_destination:
	mov %r10,%rcx 
	call sys_openat
	cmp    $0xfffffffffffff000,%rax
	push $0x0044876a
	ret 

syscall_4487d0_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x004487d8
	ret 

syscall_44880a_destination:
	mov %r10,%rcx 
	call sys_read
	cmp    $0xfffffffffffff000,%rax
	push $0x00448812
	ret 

syscall_448875_destination:
	mov %r10,%rcx 
	call sys_write
	cmp    $0xfffffffffffff000,%rax
	push $0x0044887d
	ret 

syscall_4488ad_destination:
	mov %r10,%rcx 
	call sys_write
	cmp    $0xfffffffffffff000,%rax
	push $0x004488b5
	ret 

syscall_448909_destination:
	mov %r10,%rcx 
	call sys_lseek
	cmp    $0xfffffffffffff000,%rax
	push $0x00448911
	ret 

syscall_4489b0_destination:
	mov %r10,%rcx 
	call sys_getcwd
	cmp    $0xfffffffffffff000,%rax
	push $0x004489b8
	ret 

syscall_449099_destination:
	mov %r10,%rcx 
	call sys_close
	cmp    $0xfffffffffffff000,%rax
	push $0x004490a1
	ret 

syscall_449103_destination:
	mov %r10,%rcx 
	call sys_fcntl
	cmp    $0xfffffffffffff000,%rax
	push $0x0044910b
	ret 

syscall_449137_destination:
	mov %r10,%rcx 
	call sys_fcntl
	cmp    $0xfffff000,%eax
	push $0x0044913e
	ret 

syscall_449192_destination:
	mov %r10,%rcx 
	call sys_fcntl
	cmp    $0xfffffffffffff000,%rax
	push $0x0044919a
	ret 

syscall_4491c5_destination:
	mov %r10,%rcx 
	call sys_fcntl
	cmp    $0xfffff000,%eax
	push $0x004491cc
	ret 

syscall_44924a_destination:
	mov %r10,%rcx 
	call sys_openat
	cmp    $0xfffffffffffff000,%rax
	push $0x00449252
	ret 

syscall_4492e8_destination:
	mov %r10,%rcx 
	call sys_openat
	cmp    $0xfffffffffffff000,%rax
	push $0x004492f0
	ret 

syscall_449356_destination:
	mov %r10,%rcx 
	call sys_read
	cmp    $0xfffffffffffff000,%rax
	push $0x0044935e
	ret 

syscall_449389_destination:
	mov %r10,%rcx 
	call sys_write
	cmp    $0xfffffffffffff000,%rax
	push $0x00449391
	ret 

syscall_4493c2_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x004493ca
	ret 

syscall_449544_destination:
	mov %r10,%rcx 
	call sys_mmap
	cmp    $0xfffffffffffff000,%rax
	push $0x0044954c
	ret 

syscall_44958e_destination:
	mov %r10,%rcx 
	call sys_mmap
	mov    %rax,%rdi
	push $0x00449593
	ret 

syscall_4495d9_destination:
	mov %r10,%rcx 
	call sys_munmap
	cmp    $0xfffffffffffff001,%rax
	push $0x004495e1
	ret 

syscall_449609_destination:
	mov %r10,%rcx 
	call sys_mprotect
	cmp    $0xfffffffffffff001,%rax
	push $0x00449611
	ret 

syscall_449639_destination:
	mov %r10,%rcx 
	call sys_madvise
	cmp    $0xfffffffffffff001,%rax
	push $0x00449641
	ret 

syscall_44bd9c_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff001,%rax
	push $0x0044bda4
	ret 

syscall_44bdc9_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff001,%rax
	push $0x0044bdd1
	ret 

syscall_44c4ec_destination:
	mov %r10,%rcx 
	call sys_access
	cmp    $0xfffff000,%eax
	push $0x0044c4f3
	ret 

syscall_45c474_destination:
	mov %r10,%rcx 
	call sys_rt_sigaction
	cmp    $0xfffffffffffff000,%rax
	push $0x0045c47c
	ret 

syscall_45c619_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x0045c621
	ret 

syscall_46df11_destination:
	call fast_syscall_prologue
	mov    %fs:0x308,%eax
	push $0x0046df1b
	ret 

syscall_470dba_destination:
	mov %r10,%rcx 
	call sys_clock_gettime
	mov    %rax,%rdx
	push $0x00470dbf
	ret 

syscall_4714a9_destination:
	mov %r10,%rcx 
	call sys_uname
	cmp    $0xfffffffffffff001,%rax
	push $0x004714b1
	ret 

syscall_471528_destination:
	mov %r10,%rcx 
	call sys_lstat
	cmp    $0xfffffffffffff000,%rax
	push $0x00471530
	ret 

syscall_47158d_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x00471595
	ret 

syscall_471648_destination:
	mov %r10,%rcx 
	call sys_ioctl
	cmp    $0xfffffffffffff000,%rax
	push $0x00471650
	ret 

syscall_4716f9_destination:
	mov %r10,%rcx 
	call sys_brk
	cmp    $0xfffffffffffff000,%rax
	push $0x00471701
	ret 

syscall_47a17f_destination:
	mov %r10,%rcx 
	call sys_writev
	lea    -0x28(%rbp),%rsp
	push $0x0047a185
	ret 

syscall_47bde1_destination:
	mov %r10,%rcx 
	call sys_readlink
	cmp    $0xfffff000,%eax
	push $0x0047bde8
	ret 

syscall_485539_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x00485541
	ret 

syscall_48557c_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff000,%rax
	push $0x00485584
	ret 

syscall_48b2f9_destination:
	call fast_syscall_prologue
	cmp    $0xfffffffffffff001,%rax
	push $0x0048b301
	ret 


// SPDX-License-Identifier: Apache-2.0
// Original Bao Linux amd64 GNU2 TLSDESC thunk. RAX holds the descriptor on
// entry and the offset from the thread pointer on return. Preserve every other
// general register, flags, x87/MXCSR and the XSAVE AVX/AVX-512 state: the C
// lookup's first use per thread enters glibc allocation and copy routines.
.text
.p2align 4
.globl bao_tls_thunk
.type bao_tls_thunk, @function
bao_tls_thunk:
    .cfi_startproc
    pushq %rbp
    .cfi_def_cfa_offset 16
    .cfi_offset %rbp, -16
    movq %rsp, %rbp
    .cfi_def_cfa_register %rbp
    pushfq
    pushq %rbx
    .cfi_offset %rbx, -32
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    movq %rax, %rdi
    movl bao_tls_state_size(%rip), %esi
    testl %esi, %esi
    jnz 4f
    // Probe once. Sizes are idempotent, so racing first calls agree.
    movl $512, %esi
    movl $1, %eax
    cpuid
    btl $27, %ecx
    jnc 3f
    xorl %ecx, %ecx
    xgetbv
    andl $0xe4, %eax
    movl %eax, %r8d
    movl $576, %esi
    movl $2, %r9d
1:  btl %r9d, %r8d
    jnc 2f
    movl $0xd, %eax
    movl %r9d, %ecx
    cpuid
    addl %ebx, %eax
    cmpl %eax, %esi
    cmovbl %eax, %esi
2:  incl %r9d
    cmpl $8, %r9d
    jb 1b
3:  movl %esi, bao_tls_state_size(%rip)
4:  subq %rsi, %rsp
    andq $-64, %rsp
    cmpl $512, %esi
    je 5f
    // XRSTOR rejects a standard-form header with nonzero reserved bytes.
    xorl %ecx, %ecx
    movq %rcx, 512(%rsp)
    movq %rcx, 520(%rsp)
    movq %rcx, 528(%rsp)
    movq %rcx, 536(%rsp)
    movq %rcx, 544(%rsp)
    movq %rcx, 552(%rsp)
    movq %rcx, 560(%rsp)
    movq %rcx, 568(%rsp)
    // x87, SSE, AVX, opmask, ZMM_Hi256 and Hi16_ZMM; never AMX tile data.
    movl $0xe7, %eax
    xorl %edx, %edx
    xsave64 (%rsp)
    callq bao_tls_lookup
    subq %fs:0, %rax
    movq %rax, %rsi
    movl $0xe7, %eax
    xorl %edx, %edx
    xrstor64 (%rsp)
    movq %rsi, %rax
    jmp 6f
5:  fxsave64 (%rsp)
    callq bao_tls_lookup
    subq %fs:0, %rax
    fxrstor64 (%rsp)
6:  leaq -80(%rbp), %rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popfq
    popq %rbp
    retq
    .cfi_endproc
.size bao_tls_thunk, .-bao_tls_thunk

.bss
.p2align 2
.type bao_tls_state_size, @object
bao_tls_state_size:
    .zero 4
.size bao_tls_state_size, 4
.section .note.GNU-stack,"",@progbits

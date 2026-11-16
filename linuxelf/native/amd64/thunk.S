// SPDX-License-Identifier: Apache-2.0
// Original Bao Linux amd64 GNU2 TLSDESC thunk. RAX holds the descriptor on
// entry and the offset from the thread pointer on return. Preserve every other
// general register, x87/MXCSR and the XSAVE AVX/AVX-512 state: the C
// lookup's first use per thread enters glibc allocation and copy routines.
//
// Fast path: the calling thread's record, published in bao_tls_cache at the
// index tls.c's cache_index computes, gives the block without a call,
// spilling only RCX, RDX and RSI. It clobbers the flags, as glibc's own
// _dl_tlsdesc_undefweak does (SUB %fs:0); compilers treat a TLSDESC call as
// clobbering them. A missing or foreign entry takes the full-save path,
// which preserves the flags too and whose C lookup publishes the record.
.text
.p2align 4
.globl bao_tls_thunk
.type bao_tls_thunk, @function
bao_tls_thunk:
    .cfi_startproc
    pushq %rcx
    .cfi_adjust_cfa_offset 8
    pushq %rdx
    .cfi_adjust_cfa_offset 8
    pushq %rsi
    .cfi_adjust_cfa_offset 8
    movq %fs:0, %rdx
    movq %rdx, %rcx
    shrq $12, %rcx
    movq %rdx, %rsi
    shrq $23, %rsi
    xorq %rsi, %rcx
    andl $4095, %ecx
    movq bao_tls_cache@GOTPCREL(%rip), %rsi
    movq (%rsi,%rcx,8), %rsi
    testq %rsi, %rsi
    jz 7f
    cmpq (%rsi), %rdx
    jne 7f
    movq 8(%rax), %rax
    addq 8(%rsi), %rax
    subq %rdx, %rax
    popq %rsi
    .cfi_adjust_cfa_offset -8
    popq %rdx
    .cfi_adjust_cfa_offset -8
    popq %rcx
    .cfi_adjust_cfa_offset -8
    retq
    .cfi_adjust_cfa_offset 24
7:  popq %rsi
    .cfi_adjust_cfa_offset -8
    popq %rdx
    .cfi_adjust_cfa_offset -8
    popq %rcx
    .cfi_adjust_cfa_offset -8
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

// With glibc static TLS, bao_tls_use_static repoints every descriptor here
// and stores the block's constant thread-pointer offset in its argument.
.text
.p2align 4
.globl bao_tls_static_resolver
.type bao_tls_static_resolver, @function
bao_tls_static_resolver:
    .cfi_startproc
    movq 8(%rax), %rax
    retq
    .cfi_endproc
.size bao_tls_static_resolver, .-bao_tls_static_resolver

.bss
.p2align 2
.type bao_tls_state_size, @object
bao_tls_state_size:
    .zero 4
.size bao_tls_state_size, 4
.section .note.GNU-stack,"",@progbits

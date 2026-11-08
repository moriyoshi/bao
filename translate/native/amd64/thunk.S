// SPDX-License-Identifier: Apache-2.0
// Original Darwin amd64 TLV thunk, baseline x86-64/SSE2 profile. Return RAX;
// retain GPRs, flags, x87 state and all 128 bits of XMM0..15 across the C lookup.
.text
.p2align 4
.globl _bao_tls_thunk
_bao_tls_thunk:
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
    pushq %r12
    .cfi_offset %r12, -104
    pushq %r13
    .cfi_offset %r13, -112
    pushq %r14
    .cfi_offset %r14, -120
    pushq %r15
    .cfi_offset %r15, -128
    subq $512, %rsp
    fxsave64 (%rsp)
    callq _bao_tls_lookup
    fxrstor64 (%rsp)
    addq $512, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
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

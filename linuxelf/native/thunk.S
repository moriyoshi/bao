// SPDX-License-Identifier: Apache-2.0
// Original Bao Linux arm64 TLSDESC thunk. Preserve all registers except x0
// (the result) and LR, including complete SIMD registers and x16-x18.
//
// Fast path: the calling thread's record, published in bao_tls_cache at the
// index tls.c's cache_index computes, gives the block without a call. It
// spills only x1-x3 and leaves the flags alone. A missing or foreign entry
// takes the full-save path, whose C lookup publishes the record.
.text
.p2align 2
.globl bao_tls_thunk
.type bao_tls_thunk, %function
bao_tls_thunk:
    .cfi_startproc
    stp x1, x2, [sp, #-32]!
    .cfi_adjust_cfa_offset 32
    str x3, [sp, #16]
    mrs x1, tpidr_el0
    lsr x2, x1, #23
    eor x2, x2, x1, lsr #12
    and x2, x2, #4095
    adrp x3, :got:bao_tls_cache
    ldr x3, [x3, :got_lo12:bao_tls_cache]
    ldr x3, [x3, x2, lsl #3]
    cbz x3, 1f
    ldr x2, [x3]
    sub x2, x2, x1
    cbnz x2, 1f
    ldr x2, [x3, #8]
    ldr x0, [x0, #8]
    add x0, x0, x2
    sub x0, x0, x1
    ldr x3, [sp, #16]
    ldp x1, x2, [sp], #32
    .cfi_adjust_cfa_offset -32
    ret
    .cfi_adjust_cfa_offset 32
1:  ldr x3, [sp, #16]
    ldp x1, x2, [sp], #32
    .cfi_adjust_cfa_offset -32
    sub sp, sp, #672
    str x29, [sp, #656]
    str x30, [sp, #664]
    add x29, sp, #656
    .cfi_def_cfa w29, 16
    .cfi_offset w29, -16
    .cfi_offset w30, -8
    stp x1, x2, [sp, #0]
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x7, x8, [sp, #48]
    stp x9, x10, [sp, #64]
    stp x11, x12, [sp, #80]
    stp x13, x14, [sp, #96]
    stp x15, x16, [sp, #112]
    str x17, [sp, #640]
    str x18, [sp, #648]
    stp q0, q1, [sp, #128]
    stp q2, q3, [sp, #160]
    stp q4, q5, [sp, #192]
    stp q6, q7, [sp, #224]
    stp q8, q9, [sp, #256]
    stp q10, q11, [sp, #288]
    stp q12, q13, [sp, #320]
    stp q14, q15, [sp, #352]
    stp q16, q17, [sp, #384]
    stp q18, q19, [sp, #416]
    stp q20, q21, [sp, #448]
    stp q22, q23, [sp, #480]
    stp q24, q25, [sp, #512]
    stp q26, q27, [sp, #544]
    stp q28, q29, [sp, #576]
    stp q30, q31, [sp, #608]
    bl bao_tls_lookup_offset
    ldp q0, q1, [sp, #128]
    ldp q2, q3, [sp, #160]
    ldp q4, q5, [sp, #192]
    ldp q6, q7, [sp, #224]
    ldp q8, q9, [sp, #256]
    ldp q10, q11, [sp, #288]
    ldp q12, q13, [sp, #320]
    ldp q14, q15, [sp, #352]
    ldp q16, q17, [sp, #384]
    ldp q18, q19, [sp, #416]
    ldp q20, q21, [sp, #448]
    ldp q22, q23, [sp, #480]
    ldp q24, q25, [sp, #512]
    ldp q26, q27, [sp, #544]
    ldp q28, q29, [sp, #576]
    ldp q30, q31, [sp, #608]
    ldp x1, x2, [sp, #0]
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x7, x8, [sp, #48]
    ldp x9, x10, [sp, #64]
    ldp x11, x12, [sp, #80]
    ldp x13, x14, [sp, #96]
    ldp x15, x16, [sp, #112]
    ldr x17, [sp, #640]
    ldr x18, [sp, #648]
    ldr x29, [sp, #656]
    ldr x30, [sp, #664]
    add sp, sp, #672
    ret
    .cfi_endproc
.size bao_tls_thunk, .-bao_tls_thunk

// With glibc static TLS, bao_tls_use_static repoints every descriptor here
// and stores the block's constant thread-pointer offset in its argument.
.p2align 2
.globl bao_tls_static_resolver
.type bao_tls_static_resolver, %function
bao_tls_static_resolver:
    .cfi_startproc
    ldr x0, [x0, #8]
    ret
    .cfi_endproc
.size bao_tls_static_resolver, .-bao_tls_static_resolver
.section .note.GNU-stack,"",%progbits

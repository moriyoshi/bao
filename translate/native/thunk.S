// SPDX-License-Identifier: Apache-2.0
// Original Bao Darwin arm64 TLV thunk. Native TLS calls may clobber x0, x16,
// x17 and LR only. C preserves x19-x28; we preserve x1-x15 and every Q register.
.text
.p2align 2
.globl _bao_tls_thunk
_bao_tls_thunk:
    .cfi_startproc
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
    str x15, [sp, #112]
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
    bl _bao_tls_lookup
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
    ldr x15, [sp, #112]
    ldr x29, [sp, #656]
    ldr x30, [sp, #664]
    add sp, sp, #672
    ret
    .cfi_endproc

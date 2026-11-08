package main

import (
	"fmt"
	"strings"
)

// Exercise the special TLV convention with a conforming SysV C lookup that
// destroys caller registers. This independently tests every 128-bit XMM lane.
func registerProbeAMD64(direct bool) string {
	s := []string{".text", ".p2align 4", ".globl _bao_tls_register_probe", "_bao_tls_register_probe:", "pushq %rbp", "movq %rsp,%rbp", "pushq %rbx", "pushq %r12", "pushq %r13", "pushq %r14", "pushq %r15", "subq $8,%rsp"}
	if direct {
		s = append(s, "leaq _bao_test_descriptor(%rip),%rdi")
	} else {
		s = append(s, "movq _bao_tls_state@TLVP(%rip),%rdi")
	}
	s = append(s, "movq %rdi,(%rsp)")
	regs := []string{"rbx", "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	for i, r := range regs {
		s = append(s, fmt.Sprintf("movq $%d,%%%s", 0x101+i, r))
	}
	s = append(s, "movabsq $0x3535353535353535,%rax", "movq %rax,%xmm0", "punpcklqdq %xmm0,%xmm0")
	for i := 1; i < 16; i++ {
		s = append(s, fmt.Sprintf("movdqa %%xmm0,%%xmm%d", i))
	}
	s = append(s, "stc", "callq *(%rdi)", "jnc 1f", "cmpq (%rsp),%rdi", "jne 1f", "leaq 48(%rsp),%rax", "cmpq %rax,%rbp", "jne 1f")
	for i, r := range regs {
		s = append(s, fmt.Sprintf("cmpq $%d,%%%s", 0x101+i, r), "jne 1f")
	}
	s = append(s, "movabsq $0x3535353535353535,%r10")
	for i := 0; i < 16; i++ {
		s = append(s, fmt.Sprintf("movq %%xmm%d,%%rax", i), "cmpq %r10,%rax", "jne 1f", fmt.Sprintf("psrldq $8,%%xmm%d", i), fmt.Sprintf("movq %%xmm%d,%%rax", i), "cmpq %r10,%rax", "jne 1f")
	}
	s = append(s, "movl $1,%eax", "jmp 2f", "1: xorl %eax,%eax", "2: addq $8,%rsp", "popq %r15", "popq %r14", "popq %r13", "popq %r12", "popq %rbx", "popq %rbp", "retq")
	return strings.Join(s, "\n") + "\n"
}

func clobberLookupAMD64() string {
	s := []string{".data", ".p2align 3", "_bao_test_descriptor:", ".quad _bao_tls_thunk", ".quad 0", ".quad 0", ".text", ".globl _bao_tls_lookup", "_bao_tls_lookup:"}
	for _, r := range []string{"rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"} {
		s = append(s, fmt.Sprintf("movq $0x777,%%%s", r))
	}
	for i := 0; i < 16; i++ {
		s = append(s, fmt.Sprintf("pxor %%xmm%d,%%xmm%d", i, i))
	}
	return strings.Join(append(s, "clc", "movl $42,%eax", "retq"), "\n") + "\n"
}

package main

import (
	"fmt"
	"strings"
)

// writeAddressTable emits a file-local assembler table holding the native
// address of each symbol. Generated init code walks such tables in one loop,
// so the code the Go compiler sees does not grow with the number of sections,
// imports or unwind tables. Unrolled per-entry checks made the SSA prove pass
// exhaust memory on large Windows ARM64 libraries. A Go table of accessor
// function values would need one compiler-generated ABI wrapper per entry.
func writeAddressTable(asm *strings.Builder, name string, symbols []string) {
	for i, symbol := range symbols {
		fmt.Fprintf(asm, "DATA %s<>+%d(SB)/8, $%s(SB)\n", name, i*8, symbol)
	}
	fmt.Fprintf(asm, "GLOBL %s<>(SB), NOPTR, $%d\n", name, len(symbols)*8)
}

// goList formats composite literal elements, sixteen per line.
func goList[T any](values []T, format func(T) string) string {
	var b strings.Builder
	for i, v := range values {
		if i%16 == 0 {
			b.WriteString("\n")
		}
		b.WriteString(format(v))
		b.WriteString(",")
	}
	if len(values) != 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// addressSliceHelper converts an address table accessor result to a slice.
const addressSliceHelper = `
func baoAddresses(table uintptr, n int) []uintptr { return unsafe.Slice((*uintptr)(unsafe.Pointer(table)), n) }
`

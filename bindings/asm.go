package bindings

import (
	"fmt"
	"strings"
)

type location struct {
	reg          string
	offset, size int
}

func align(n, a int) int { return (n + a - 1) &^ (a - 1) }
func width(t string) int {
	switch t {
	case "int8", "uint8":
		return 1
	case "int16", "uint16":
		return 2
	case "int32", "uint32", "float32":
		return 4
	}
	return 8
}
func floating(t string) bool { return t == "float32" || t == "float64" }

func layout(target string, params []string) ([]location, int, error) {
	ints, floats, stack := 0, 0, 0
	var out []location
	for i, t := range params {
		l := location{size: width(t)}
		switch target {
		case "windows/amd64":
			if i < 4 {
				if floating(t) {
					l.reg = fmt.Sprintf("X%d", i)
				} else {
					l.reg = []string{"CX", "DX", "R8", "R9"}[i]
				}
			} else {
				l.offset = 32 + 8*(i-4)
				stack = l.offset + 8
			}
		case "darwin/amd64", "linux/amd64":
			if floating(t) && floats < 8 {
				l.reg = fmt.Sprintf("X%d", floats)
				floats++
			} else if !floating(t) && ints < 6 {
				l.reg = []string{"DI", "SI", "DX", "CX", "R8", "R9"}[ints]
				ints++
			}
		case "darwin/arm64", "linux/arm64", "windows/arm64":
			if floating(t) && floats < 8 {
				l.reg = fmt.Sprintf("F%d", floats)
				floats++
			} else if !floating(t) && ints < 8 {
				l.reg = fmt.Sprintf("R%d", ints)
				ints++
			}
		case "linux/loong64":
			if floating(t) && floats < 8 {
				l.reg = fmt.Sprintf("F%d", floats)
				floats++
			} else if ints < 8 {
				l.reg = fmt.Sprintf("R%d", 4+ints)
				ints++
			}
		case "linux/ppc64le":
			if floating(t) && floats < 13 {
				l.reg = fmt.Sprintf("F%d", 1+floats)
				floats++
			} else if !floating(t) && i < 8 {
				l.reg = fmt.Sprintf("R%d", 3+i)
			}
			l.offset = 32 + 8*i
			stack = max(stack, 32+8*(i+1))
			out = append(out, l)
			continue
		default:
			return nil, 0, fmt.Errorf("typed bindings unsupported for %s", target)
		}
		if target == "windows/amd64" {
			out = append(out, l)
			continue
		}
		if l.reg == "" {
			a, size := 8, 8
			if target == "darwin/arm64" {
				a = l.size
				size = l.size
			}
			stack = align(stack, a)
			l.offset = stack
			stack += size
		}
		out = append(out, l)
	}
	if target == "linux/ppc64le" {
		stack = max(96, stack)
	}
	if target == "windows/amd64" {
		stack = max(32, stack)
	}
	return out, stack, nil
}

func accessor(arch, name, symbol string) string {
	move, reg := "MOVD", "R0"
	switch arch {
	case "amd64":
		move, reg = "MOVQ", "AX"
	case "loong64":
		move, reg = "MOVV", "R4"
	case "ppc64le":
		reg = "R3"
	}
	return fmt.Sprintf("\nTEXT ·%s(SB),NOSPLIT,$0-8\n %s $%s(SB),%s\n %s %s,ret+0(FP)\n RET\n", name, move, symbol, reg, move, reg)
}

// callAssembly is an original, fixed-signature C ABI frame adapter. runtime.cgocall
// enters it on the native system stack; it does not run on a goroutine stack.
func callAssembly(target, symbol string, f Function) (string, error) {
	loc, spill, err := layout(target, f.Params)
	if err != nil {
		return "", err
	}
	var s strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&s, format+"\n", args...) }
	p("\nTEXT %s(SB),NOSPLIT|NOFRAME,$0-0", symbol)
	arch := strings.Split(target, "/")[1]
	switch arch {
	case "amd64":
		save := align(spill, 8)
		size := align(save+8, 16) + 8
		p(" SUBQ $%d,SP", size)
		frame := "DI"
		if target == "windows/amd64" {
			frame = "CX"
		}
		p(" MOVQ %s,%d(SP)", frame, save)
		p(" MOVQ %s,R10", frame)
		p(" MOVQ 0(R10),R11")
		for i, l := range loc {
			src := fmt.Sprintf("%d(R10)", 16+8*i)
			if l.reg != "" {
				op := "MOVQ"
				if floating(f.Params[i]) {
					op = "MOVSD"
					if l.size == 4 {
						op = "MOVSS"
					}
				}
				p(" %s %s,%s", op, src, l.reg)
			} else {
				p(" MOVQ %s,AX", src)
				p(" MOVQ AX,%d(SP)", l.offset)
			}
		}
		p(" CALL R11")
		p(" MOVQ %d(SP),R10", save)
		if floating(f.Result) {
			op := "MOVSD"
			if f.Result == "float32" {
				op = "MOVSS"
			}
			p(" %s X0,8(R10)", op)
		} else if f.Result != "" && f.Result != "void" {
			p(" MOVQ AX,8(R10)")
		}
		p(" ADDQ $%d,SP", size)
		p(" RET")
	case "arm64":
		save := align(spill, 16)
		size := save + 32
		p(" SUB $%d,RSP", size)
		p(" STP (R29,R30),%d(RSP)", save)
		p(" MOVD R0,%d(RSP)", save+16)
		p(" MOVD R0,R9")
		p(" MOVD 0(R9),R16")
		for i, l := range loc {
			src := fmt.Sprintf("%d(R9)", 16+8*i)
			if l.reg != "" {
				op := "MOVD"
				if floating(f.Params[i]) {
					op = "FMOVD"
					if l.size == 4 {
						op = "FMOVS"
					}
				}
				p(" %s %s,%s", op, src, l.reg)
			} else {
				p(" MOVD %s,R10", src)
				op := "MOVD"
				if target == "darwin/arm64" {
					op = map[int]string{1: "MOVB", 2: "MOVH", 4: "MOVW", 8: "MOVD"}[l.size]
				}
				p(" %s R10,%d(RSP)", op, l.offset)
			}
		}
		p(" CALL (R16)")
		p(" MOVD %d(RSP),R9", save+16)
		if floating(f.Result) {
			op := "FMOVD"
			if f.Result == "float32" {
				op = "FMOVS"
			}
			p(" %s F0,8(R9)", op)
		} else if f.Result != "" && f.Result != "void" {
			p(" MOVD R0,8(R9)")
		}
		p(" LDP %d(RSP),(R29,R30)", save)
		p(" ADD $%d,RSP", size)
		p(" RET")
	case "loong64":
		save := align(spill, 16)
		size := save + 16
		p(" SUBV $%d,R3", size)
		p(" MOVV R1,%d(R3)", save)
		p(" MOVV R4,%d(R3)", save+8)
		p(" MOVV R4,R12")
		p(" MOVV 0(R12),R13")
		for i, l := range loc {
			src := fmt.Sprintf("%d(R12)", 16+8*i)
			if l.reg != "" {
				op := "MOVV"
				if strings.HasPrefix(l.reg, "F") {
					op = "MOVD"
					if l.size == 4 {
						op = "MOVF"
					}
				} else if f.Params[i] == "uint32" {
					op = "MOVW"
				}
				p(" %s %s,%s", op, src, l.reg)
			} else {
				p(" MOVV %s,R14", src)
				p(" MOVV R14,%d(R3)", l.offset)
			}
		}
		p(" CALL (R13)")
		p(" MOVV %d(R3),R12", save+8)
		if floating(f.Result) {
			op := "MOVD"
			if f.Result == "float32" {
				op = "MOVF"
			}
			p(" %s F0,8(R12)", op)
		} else if f.Result != "" && f.Result != "void" {
			p(" MOVV R4,8(R12)")
		}
		p(" MOVV %d(R3),R1", save)
		p(" ADDV $%d,R3", size)
		p(" RET")
	case "ppc64le":
		save := align(spill, 16)
		size := save + 32
		p(" MOVD LR,R12")
		p(" MOVDU R1,-%d(R1)", size)
		p(" MOVD R12,%d(R1)", save)
		p(" MOVD R2,%d(R1)", save+8)
		p(" MOVD R3,%d(R1)", save+16)
		p(" MOVD R3,R11")
		p(" MOVD 0(R11),R12")
		for i, l := range loc {
			src := fmt.Sprintf("%d(R11)", 16+8*i)
			if l.reg != "" {
				op := "MOVD"
				if floating(f.Params[i]) {
					op = "FMOVD"
					if l.size == 4 {
						op = "FMOVS"
					}
				}
				p(" %s %s,%s", op, src, l.reg)
			} else {
				p(" MOVD %s,R0", src)
				p(" MOVD R0,%d(R1)", l.offset)
			}
		}
		p(" MOVD R12,CTR")
		p(" BL (CTR)")
		p(" MOVD %d(R1),R2", save+8)
		p(" MOVD %d(R1),R11", save+16)
		if floating(f.Result) {
			op := "FMOVD"
			if f.Result == "float32" {
				op = "FMOVS"
			}
			p(" %s F1,8(R11)", op)
		} else if f.Result != "" && f.Result != "void" {
			p(" MOVD R3,8(R11)")
		}
		p(" MOVD %d(R1),R12", save)
		p(" MOVD R12,LR")
		p(" ADD $%d,R1", size)
		p(" MOVD $0,R0")
		p(" RET")
	}
	return s.String(), nil
}

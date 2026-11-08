package main

import (
	"bao-runtime-check/native"
	"fmt"
	"github.com/ebitengine/purego"
	"runtime"
)

func main() {
	runtime.LockOSThread()
	var caught, workers, count func() uint64
	var touch func()
	purego.RegisterFunc(&caught, native.SymbolAddr0())
	purego.RegisterFunc(&workers, native.SymbolAddr1())
	purego.RegisterFunc(&touch, native.SymbolAddr2())
	purego.RegisterFunc(&count, native.SymbolAddr3())

	if got := workers(); got != 42 {
		panic(fmt.Sprintf("worker TLS drop=%d", got))
	}
	if got := count(); got != 8 {
		panic(fmt.Sprintf("worker destructors=%d", got))
	}

	var imported, interior, base, aligned func() uintptr
	var initialized func() uint32
	purego.RegisterFunc(&imported, native.SymbolAddr4())
	purego.RegisterFunc(&interior, native.SymbolAddr5())
	purego.RegisterFunc(&base, native.SymbolAddr6())
	purego.RegisterFunc(&aligned, native.SymbolAddr7())
	purego.RegisterFunc(&initialized, native.SymbolAddr8())
	expected, err := purego.Dlsym(purego.RTLD_DEFAULT, "_NSConcreteStackBlock")
	if err != nil || imported() != expected {
		panic(fmt.Sprintf("imported data pointer: got=%#x expected=%#x err=%v", imported(), expected, err))
	}
	if interior()-base() != 7 {
		panic("native pointer addend was lost")
	}
	if aligned()%128 != 0 {
		panic(fmt.Sprintf("native 128-byte alignment lost: %#x", aligned()))
	}
	if initialized() != 42 {
		panic(fmt.Sprintf("constructor ABI/order: %d", initialized()))
	}
	if got := caught(); got != 42 {
		panic(fmt.Sprintf("panic catch/drop=%d", got))
	}
	touch()
	native.TLSFinalizeCurrentThread()
	if got := count(); got != 9 {
		panic(fmt.Sprintf("main TLS destructor=%d", got))
	}
	if live := native.TLSLiveBlocks(); live != 0 {
		panic(fmt.Sprintf("live TLS=%d", live))
	}
	fmt.Printf("PASS: real Rust panic caught with 2 cleanup drops; 8 std threads joined with TLS destructors; imported data pointer/addend/alignment/constructor ABI and order; main TLS finalized; live=%d freed=%d\n", native.TLSLiveBlocks(), native.TLSDestroyedBlocks())
}

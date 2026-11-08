package main

import (
	"bao-gpui-headless/native"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/moriyoshi/gpui-go/client"
	"github.com/moriyoshi/gpui-go/scene"
)

func init() { runtime.LockOSThread() }

type bridge struct {
	rt       uintptr
	spawn    func(uintptr, uint32, *byte, uintptr, uint64)
	cancel   func(uint64)
	result   func(uint64, *int32, *uintptr, *uintptr)
	free     func(uint64)
	next     func(uintptr, *uint64, *uint64) int32
	shutdown func(uintptr)
	destroy  func(uintptr)
	tokens   atomic.Uint64
	waiting  sync.Map
	file     *os.File
	done     chan struct{}
}

func (b *bridge) Call(ctx context.Context, op client.Operation, req []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token := b.tokens.Add(1)
	ch := make(chan uint64, 1)
	b.waiting.Store(token, ch)
	b.spawn(b.rt, uint32(op), unsafe.SliceData(req), uintptr(len(req)), token)
	var h uint64
	select {
	case h = <-ch:
	case <-ctx.Done():
		b.cancel(token)
		h = <-ch
	}
	runtime.KeepAlive(req)
	if h == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("unexpected zero completion")
	}
	var ok int32
	var ptr, n uintptr
	b.result(h, &ok, &ptr, &n)
	var data []byte
	if n > 0 {
		data = append(data, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(n))...)
	}
	b.free(h)
	if ok == 0 {
		return nil, errors.New(string(data))
	}
	return data, nil
}

func main() {
	addresses := map[string]uintptr{"gpui_go_init": native.SymbolAddr0(),
		"gpui_go_run_headless":   native.SymbolAddr1(),
		"gpui_go_run_native":     native.SymbolAddr2(),
		"gpui_go_stop":           native.SymbolAddr3(),
		"sable_runtime_new":      native.SymbolAddr4(),
		"sable_completion_efd":   native.SymbolAddr5(),
		"sable_call_ctx":         native.SymbolAddr6(),
		"sable_call_cancel":      native.SymbolAddr7(),
		"sable_call_result":      native.SymbolAddr8(),
		"sable_call_free":        native.SymbolAddr9(),
		"sable_next_completion":  native.SymbolAddr10(),
		"sable_runtime_shutdown": native.SymbolAddr11(),
		"sable_runtime_free":     native.SymbolAddr12()}
	bind := func(fn any, name string) { purego.RegisterFunc(fn, addresses[name]) }
	var initBridge func() int32
	var run func() int32
	var stop func()
	var newRuntime func() uintptr
	var doorbell func(uintptr) int32
	bind(&initBridge, "gpui_go_init")
	bind(&run, "gpui_go_run_headless")
	bind(&stop, "gpui_go_stop")
	bind(&newRuntime, "sable_runtime_new")
	bind(&doorbell, "sable_completion_efd")
	var err error
	b := &bridge{done: make(chan struct{})}
	bind(&b.spawn, "sable_call_ctx")
	bind(&b.cancel, "sable_call_cancel")
	bind(&b.result, "sable_call_result")
	bind(&b.free, "sable_call_free")
	bind(&b.next, "sable_next_completion")
	bind(&b.shutdown, "sable_runtime_shutdown")
	bind(&b.destroy, "sable_runtime_free")
	if status := initBridge(); status != 0 {
		panic(status)
	}
	b.rt = newRuntime()
	if b.rt == 0 {
		panic("new runtime failed")
	}
	fd, err := syscall.Dup(int(doorbell(b.rt)))
	if err != nil {
		panic(err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		panic(err)
	}
	b.file = os.NewFile(uintptr(fd), "completion")
	drain := func() {
		var token, h uint64
		for b.next(b.rt, &token, &h) != 0 {
			ch, ok := b.waiting.LoadAndDelete(token)
			if !ok {
				panic("unknown completion")
			}
			ch.(chan uint64) <- h
		}
	}
	go func() {
		defer close(b.done)
		var buf [8]byte
		for {
			if _, err := b.file.Read(buf[:]); err != nil {
				drain()
				return
			}
			drain()
		}
	}()
	finished := make(chan error, 1)
	go func() {
		defer stop()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		app, err := client.NewClient(ctx, b)
		if err != nil {
			finished <- err
			return
		}
		win, err := app.OpenWindow(ctx, client.WindowOptions{Title: "purego probe", Width: 560, Height: 420}, scene.Text(1, "Hello"))
		if err != nil {
			finished <- err
			return
		}
		if err := win.Set(ctx, scene.Text(1, "Updated")); err != nil {
			finished <- err
			return
		}
		events, err := app.NextEvents(ctx)
		if err != nil || len(events) == 0 {
			finished <- fmt.Errorf("update events: %v %v", events, err)
			return
		}
		pending, cancelPull := context.WithTimeout(ctx, 20*time.Millisecond)
		_, err = app.NextEvents(pending)
		cancelPull()
		if !errors.Is(err, context.DeadlineExceeded) {
			finished <- fmt.Errorf("cancellation: %v", err)
			return
		}
		if err := win.Close(ctx); err != nil {
			finished <- err
			return
		}
		if _, err := app.NextEvents(ctx); err != nil {
			finished <- err
			return
		}
		finished <- app.Quit(ctx)
	}()
	status := run()
	err = <-finished
	b.shutdown(b.rt)
	b.file.Close()
	<-b.done
	b.destroy(b.rt)
	if status != 0 || err != nil {
		panic(fmt.Sprintf("run=%d app=%v", status, err))
	}
	native.TLSFinalizeCurrentThread()
	fmt.Printf("PASS: CGO_ENABLED=0 translated static archive; protobuf handshake/window/update/events, pending pull cancellation, quit and Sable teardown; TLS live=%d freed=%d\n", native.TLSLiveBlocks(), native.TLSDestroyedBlocks())
}

//go:build darwin || linux

package main

import (
	"os"
	"runtime"
	"syscall"
)

// peakRSS returns the peak resident set size of a finished command in bytes.
// The children it reaped, such as compile and asm under go build, are included.
func peakRSS(state *os.ProcessState) (int64, bool) {
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0, false
	}
	if runtime.GOOS == "darwin" {
		return int64(usage.Maxrss), true
	}
	return int64(usage.Maxrss) * 1024, true
}

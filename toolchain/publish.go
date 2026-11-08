//go:build !windows

package toolchain

import (
	"os"
	"syscall"
)

// Publish reserves a new directory exclusively, then replaces only that empty
// reservation with the completed package. On the supported Unix hosts, the
// underlying rename publishes the directory contents atomically. os.Rename's
// additional destination-directory check would reject our own reservation.
func Publish(staged, output string) error {
	if err := os.Mkdir(output, 0o755); err != nil {
		return err
	}
	if err := syscall.Rename(staged, output); err != nil {
		os.Remove(output) // Only an empty reservation, never recursively.
		return err
	}
	return nil
}

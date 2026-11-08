package toolchain

import (
	"errors"
	"os"
	"syscall"
)

// Publish moves a completed package to a new destination. Windows MoveFileW
// refuses existing destinations, so no placeholder directory is necessary.
// The producer stages beside the destination to keep this on one volume.
func Publish(staged, output string) error {
	fail := func(err error) error {
		return &os.LinkError{Op: "publish", Old: staged, New: output, Err: err}
	}
	info, err := os.Lstat(staged)
	if err != nil {
		return fail(err)
	}
	if !info.IsDir() {
		return fail(errors.New("staged package must be a directory"))
	}
	// The pinned Go Windows syscall.Rename calls MoveFileW without replacement.
	// Removing a reservation and using a replacing rename would introduce a
	// race that could overwrite someone else's output.
	if err := syscall.Rename(staged, output); err != nil {
		return fail(err)
	}
	return nil
}

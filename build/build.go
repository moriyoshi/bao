// Package build runs bao build from a Go program, so that a producer that
// imports bao as a module needs only Go: no separately installed bao. Run
// does what the bao build command does with the same flags, which Options
// spells out; it may run more than once in one process, for example once
// per target.
package build

import (
	"context"
	"errors"
	"io"
	"sort"
	"strconv"

	"github.com/moriyoshi/bao/internal/cli"
)

// Options are bao build's flags. Empty fields are left out, so the command's
// defaults apply. See the README for each flag.
type Options struct {
	// Input is the relocatable object, static archive or Linux shared
	// object to translate.
	Input string
	// Output is the generated Go package directory (-o). It must not exist.
	Output string
	// Target is the platform, such as linux/arm64 (-target). Bao detects
	// it from Input when empty.
	Target string
	// Package is the generated Go package name (-package), "native" when
	// empty.
	Package string
	// Sysroot is the target Linux glibc sysroot (-sysroot), and SDK the
	// macOS SDK (-sdk).
	Sysroot, SDK string
	// Symbols are the native C ABI exports, in accessor order (-symbol).
	Symbols []string
	// Bindings selects typed bindings (-bindings): dwarf, or a signature
	// file.
	Bindings string
	// Config is a bao configuration file (-config).
	Config string
	// LinkArchives are static dependency archives (-link-archive), and
	// LinkNotices license files to ship with the package (-link-notice).
	LinkArchives, LinkNotices []string
	// Linker is the partial linker (-ld).
	Linker string
	// StripDebug removes native debug information (-strip-debug).
	StripDebug bool
	// Wrap redirects each symbol to __wrap_SYMBOL, as ld.lld --wrap
	// (-wrap). With Linux.SharedObject it applies to that library's imports
	// too.
	Wrap []string
	// RedefineSymbols renames OLD to NEW in every input (-redefine-sym).
	RedefineSymbols map[string]string
	Linux           LinuxOptions
	Windows         WindowsOptions
	Darwin          DarwinOptions
	// Args are further bao build flags, as on the command line, for those
	// without a field here, such as the per-input symbol edits.
	Args []string
	// Stdout and Stderr receive the command's output; nil discards it.
	Stdout, Stderr io.Writer
}

// LinuxOptions are the Linux target's flags.
type LinuxOptions struct {
	// SharedObject is a linked PIC shared object to translate with the
	// input (-linux-shared-object).
	SharedObject string
	// SystemLibraries are further sysroot shared objects that may satisfy
	// imports (-linux-system-library).
	SystemLibraries []string
	// MaxSymbolVersions caps the symbol version imports bind, one per
	// namespace, such as GLIBC_2.17 (-linux-max-symbol-version).
	MaxSymbolVersions []string
	// MaxTextAlignment links executable sections that request more at this
	// alignment; only 4096 is supported (-linux-max-text-alignment).
	MaxTextAlignment uint
}

// WindowsOptions are the Windows target's flags.
type WindowsOptions struct {
	// Imports maps a symbol to its system DLL (-windows-import).
	Imports map[string]string
	// ImportLibraries are short-import libraries naming DLL functions
	// (-windows-import-library).
	ImportLibraries []string
	// CRT is ucrt or msvcrt (-windows-crt), and CXXRuntime auto, libstdc++
	// or libc++ (-windows-cxx-runtime).
	CRT, CXXRuntime string
	// MaxDataAlignment links read-only data that requests more at this
	// alignment; only 32 is supported (-windows-max-data-alignment).
	MaxDataAlignment uint
}

// DarwinOptions are the macOS target's flags.
type DarwinOptions struct {
	// MinOS is the deployment version for partial linking (-min-os).
	MinOS string
}

// CommandLine returns the bao build arguments, after "build", that Run
// passes.
func (o Options) CommandLine() []string {
	var args []string
	flag := func(name, value string) {
		if value != "" {
			args = append(args, "-"+name, value)
		}
	}
	each := func(name string, values []string) {
		for _, v := range values {
			args = append(args, "-"+name, v)
		}
	}
	pairs := func(name string, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "-"+name, k+"="+m[k])
		}
	}
	number := func(name string, n uint) {
		if n != 0 {
			args = append(args, "-"+name, strconv.FormatUint(uint64(n), 10))
		}
	}
	flag("config", o.Config)
	flag("target", o.Target)
	flag("o", o.Output)
	flag("package", o.Package)
	flag("sysroot", o.Sysroot)
	flag("sdk", o.SDK)
	each("symbol", o.Symbols)
	flag("bindings", o.Bindings)
	each("link-archive", o.LinkArchives)
	each("link-notice", o.LinkNotices)
	flag("ld", o.Linker)
	if o.StripDebug {
		args = append(args, "-strip-debug")
	}
	each("wrap", o.Wrap)
	pairs("redefine-sym", o.RedefineSymbols)
	flag("linux-shared-object", o.Linux.SharedObject)
	each("linux-system-library", o.Linux.SystemLibraries)
	each("linux-max-symbol-version", o.Linux.MaxSymbolVersions)
	number("linux-max-text-alignment", o.Linux.MaxTextAlignment)
	pairs("windows-import", o.Windows.Imports)
	each("windows-import-library", o.Windows.ImportLibraries)
	flag("windows-crt", o.Windows.CRT)
	flag("windows-cxx-runtime", o.Windows.CXXRuntime)
	number("windows-max-data-alignment", o.Windows.MaxDataAlignment)
	flag("min-os", o.Darwin.MinOS)
	args = append(args, o.Args...)
	// The input follows "--", so a path that starts with "-" is not a flag.
	return append(args, "--", o.Input)
}

// Run runs bao build with the options.
func Run(ctx context.Context, o Options) error {
	if o.Input == "" || o.Output == "" {
		return errors.New("bao build needs Input and Output")
	}
	stdout, stderr := o.Stdout, o.Stderr
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return cli.Run(ctx, append([]string{"build"}, o.CommandLine()...), stdout, stderr)
}

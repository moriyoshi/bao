// Package ar parses ordinary Unix ar archives, including BSD extended names,
// GNU/COFF long-name tables and Go package archives. It retains all members in
// archive order, including symbol and name tables, without interpreting their
// indexes or extracting files. Thin archives are unsupported.
//
// Member data aliases the input. Names are metadata, not safe extraction paths.
package ar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Kind identifies the role of an archive member.
type Kind uint8

const (
	// Regular is an ordinary archive member, including Go's __.PKGDEF.
	Regular Kind = iota
	// SymbolTable is a GNU or BSD archive symbol index. Data is left opaque.
	SymbolTable
	// NameTable is a GNU/COFF // long-name table. Data retains its delimiters.
	NameTable
)

// Member describes one archive entry. Duplicate names are preserved.
type Member struct {
	Name   string // Resolved name; GNU special entries retain /, /SYM64/ or //.
	Data   []byte // Payload without a BSD name prefix; aliases the input.
	Kind   Kind
	Offset int // Byte offset of the entry's 60-byte header in the input.
}

var (
	// ErrFormat identifies malformed archive framing or names.
	ErrFormat = errors.New("invalid ar archive")
	// ErrThinArchive identifies a GNU thin archive, which refers to external files.
	ErrThinArchive = errors.New("thin ar archives are unsupported")
)

// ParseError reports where parsing failed. Its Err may wrap ErrFormat,
// ErrThinArchive or io.ErrUnexpectedEOF; callers can use errors.Is or errors.As.
type ParseError struct {
	Offset int
	Err    error
}

func (e *ParseError) Error() string { return fmt.Sprintf("ar: offset %d: %v", e.Offset, e.Err) }
func (e *ParseError) Unwrap() error { return e.Err }

func invalid(offset int, format string, args ...any) error {
	return &ParseError{offset, fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))}
}

func truncated(offset int, what string) error {
	return &ParseError{offset, fmt.Errorf("truncated %s: %w", what, io.ErrUnexpectedEOF)}
}

// Parse validates an entire ordinary ar archive before returning its members.
// On failure it returns no partial result. An empty archive is valid.
//
// Names are resolved from GNU /N references and BSD #1/N prefixes. Symbol and
// name tables remain in the result and are distinguished by Kind. Numeric
// ownership, mode and timestamp fields and symbol-index contents are not decoded
// or validated.
// GNU name references are bounded byte offsets; duplicate name tables are rejected.
// Odd stored member sizes require an LF or NUL padding byte; BSD name prefixes
// count toward that stored size. NUL padding supports Go's archive writer.
//
// Data slices borrow the input and have capacity limited to their payload.
// Do not reuse the input while reading those slices; copy Data to own it.
// The parser neither invokes external programs nor opens paths found in an archive.
func Parse(b []byte) ([]Member, error) {
	if bytes.HasPrefix(b, []byte("!<thin>\n")) {
		return nil, &ParseError{0, ErrThinArchive}
	}
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		return nil, invalid(0, "missing ordinary archive signature")
	}
	var out []Member
	// Copy the name table once so references can share immutable string storage.
	// Copying every resolved name would amplify memory for repeated references.
	var names string
	hasNames := false
	for off := 8; off < len(b); {
		start := off
		if len(b)-off < 60 {
			return nil, truncated(off, "member header")
		}
		h := b[off : off+60]
		if string(h[58:60]) != "`\n" {
			return nil, invalid(off+58, "bad member header trailer")
		}
		size, err := strconv.ParseUint(strings.TrimSpace(string(h[48:58])), 10, 64)
		if err != nil {
			return nil, invalid(off+48, "invalid member size")
		}
		if size > uint64(len(b)-off-60) {
			return nil, truncated(off+60, "member payload")
		}
		name := strings.TrimRight(string(h[:16]), " ")
		end := off + 60 + int(size)
		data := b[off+60 : end : end]
		off = end
		if size%2 != 0 {
			if off == len(b) {
				return nil, truncated(off, "member padding")
			}
			if b[off] != '\n' && b[off] != 0 {
				return nil, invalid(off, "member padding must be LF or NUL")
			}
			off++
		}
		kind := Regular
		switch {
		case name == "//":
			if hasNames {
				return nil, invalid(start, "duplicate GNU name table")
			}
			names, hasNames = string(data), true
			kind = NameTable
		case name == "/" || name == "/SYM64/" || name == "/<ECSYMBOLS>/":
			kind = SymbolTable
		case strings.HasPrefix(name, "#1/"):
			n, err := strconv.ParseUint(name[3:], 10, 64)
			if err != nil || n > uint64(len(data)) {
				return nil, invalid(start, "invalid BSD name length")
			}
			name = strings.TrimRight(string(data[:int(n)]), "\x00")
			data = data[int(n):]
		case strings.HasPrefix(name, "/"):
			n, err := strconv.ParseUint(name[1:], 10, 64)
			if err != nil || n >= uint64(len(names)) {
				return nil, invalid(start, "invalid GNU name reference %q", name)
			}
			length := strings.IndexByte(names[int(n):], '\n')
			// Microsoft COFF libraries use the same byte-offset references
			// with NUL-terminated long names instead of GNU's slash/LF.
			if nul := strings.IndexByte(names[int(n):], 0); nul >= 0 && (length < 0 || nul < length) {
				length = nul
			}
			if length < 0 {
				return nil, invalid(start, "unterminated GNU name")
			}
			name = strings.TrimSuffix(names[int(n):int(n)+length], "/")
		default:
			name = strings.TrimSuffix(name, "/")
		}
		if name == "" || strings.ContainsRune(name, '\x00') {
			return nil, invalid(start, "empty or NUL-containing member name")
		}
		switch name {
		case "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED":
			kind = SymbolTable
		}
		out = append(out, Member{Name: name, Data: data, Kind: kind, Offset: start})
	}
	return out, nil
}

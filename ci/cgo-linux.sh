#!/bin/sh
# Exercise typed bindings alongside a real cgo dependency on native Linux.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mkdir -p "$root/.work"
work=$(mktemp -d "$root/.work/cgo-linux-XXXXXX")
echo "Cgo Linux fixture: $work"
cd "$root"
go build -o "$work/bao" ./cmd/bao
gcc -O2 -g -fPIC -c testdata/bindings_integration.c -o "$work/input.o"
ar rcs "$work/input.a" "$work/input.o"
mkdir "$work/app"
"$work/bao" build -target "linux/$(go env GOARCH)" -sysroot / -bindings dwarf \
  -symbol bao_scalar_tls_next -symbol bao_scalar_ints -symbol bao_scalar_floats \
  -symbol bao_scalar_mixed -symbol bao_scalar_narrow -symbol bao_scalar_pointer \
  -symbol bao_scalar_wait -symbol bao_scalar_u32 -o "$work/app/native" "$work/input.a"
printf 'module bao-bindings-check\n\ngo 1.26.0\n' > "$work/app/go.mod"
cp testdata/bindings_consumer.go.tmpl "$work/app/main.go"
cd "$work/app"
# Without another cgo dependency runtime/cgo is not linked; default flags link internally.
CGO_ENABLED=1 go build -o "$work/app-cgo-no-dependency" .
GOMAXPROCS=1 "$work/app-cgo-no-dependency"
GOMAXPROCS=4 "$work/app-cgo-no-dependency"
mkdir "$work/app/cgodep"
cat > "$work/app/cgodep/cgo.go" <<'EOF'
package cgodep
/* static int answer(void) { return 42; } */
import "C"
func Answer() int { return int(C.answer()) }
EOF
cat > "$work/app/cgo_check.go" <<'EOF'
//go:build cgo

package main
import "bao-bindings-check/cgodep"
func init() { if cgodep.Answer() != 42 { panic("cgo dependency") } }
EOF
# A real cgo dependency links runtime/cgo; Go's default external link must fail.
if CGO_ENABLED=1 go build -o "$work/app-cgo-not-produced" . > "$work/default-link.log" 2>&1; then
  echo "cgo dependency unexpectedly linked with the default external linker" >&2
  exit 1
fi
CGO_ENABLED=1 go build -ldflags=-linkmode=internal -o "$work/app-cgo" .
GOMAXPROCS=1 "$work/app-cgo"
GOMAXPROCS=4 "$work/app-cgo"
CGO_ENABLED=0 go build -o "$work/app-nocgo" .
GOMAXPROCS=1 "$work/app-nocgo"

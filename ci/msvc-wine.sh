#!/usr/bin/env bash
# Adapt the verification harness's Unix paths for an independently installed MSVC.
# Microsoft tools and their license are supplied by the user, never by Bao.
set -euo pipefail
: "${MSVC_TOOLS:?set MSVC_TOOLS to VC/Tools/MSVC/<version>}"
: "${MSVC_ARCH:?set MSVC_ARCH to x64 or arm64}"
case "$MSVC_ARCH" in x64|arm64) ;; *) echo 'Unsupported MSVC_ARCH' >&2; exit 2 ;; esac
tools=$(cd "$MSVC_TOOLS" && pwd)
if [[ -f "$tools/bin/Hostx64/$MSVC_ARCH/vctip.exe" ]]; then
  echo 'Rename vctip.exe to vctip.exe.disabled in this disposable toolchain copy before running MSVC under Wine (see msvc-wine/install.sh).' >&2
  exit 2
fi
export WINEDEBUG=${WINEDEBUG:--all}
export INCLUDE="Z:${tools//\//\\}\\include${INCLUDE:+;$INCLUDE}"
args=()
for arg in "$@"; do
  case "$arg" in
    /Fo/*) path=${arg#/Fo}; args+=("/FoZ:${path//\//\\}") ;;
    /*.c|/*.cpp) args+=("Z:${arg//\//\\}") ;;
    *) args+=("$arg") ;;
  esac
done
exec "${WINE:-wine}" "$tools/bin/Hostx64/$MSVC_ARCH/cl.exe" "${args[@]}"

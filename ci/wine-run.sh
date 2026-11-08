#!/usr/bin/env bash
set -euo pipefail
export WINEDEBUG=${WINEDEBUG:--all}
exec "${WINE:-wine}" "$@"

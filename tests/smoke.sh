#!/bin/bash
# Non-destructive smoke tests for the CLI and configuration validation.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$ROOT_DIR/hids.sh" "$ROOT_DIR/libs/common.sh" \
    "$ROOT_DIR/modules"/*.sh "$ROOT_DIR/tools"/*.sh
"$ROOT_DIR/hids.sh" --help >/dev/null
if "$ROOT_DIR/hids.sh" --module 9 >/dev/null 2>&1; then
    printf 'Expected invalid module to fail\n' >&2
    exit 1
fi
if "$ROOT_DIR/hids.sh" --watch 0 >/dev/null 2>&1; then
    printf 'Expected invalid watch interval to fail\n' >&2
    exit 1
fi
if "$ROOT_DIR/hids.sh" --config "$ROOT_DIR/hids.conf" --module 1 >/dev/null 2>&1; then
    :
fi
printf 'Smoke tests passed\n'
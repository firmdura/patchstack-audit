#!/bin/sh
# Shared prerequisites for the local, offline verification scripts.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly LC_ALL=C

require_go() {
    command -v go >/dev/null 2>&1 || { echo 'Go 1.27.4 is required' >&2; exit 1; }
    [ "$(go env GOVERSION)" = go1.27.4 ] || { echo 'Go 1.27.4 is required; prepare the pinned toolchain first' >&2; exit 1; }
}

require_runtime() {
    [ "$(uname -s)" = Linux ] || { echo 'Linux is required; use scripts/verify-linux.sh with its prepared container' >&2; exit 1; }
    [ "$(id -u)" != 0 ] || { echo 'Run verification as an unprivileged user' >&2; exit 1; }
    [ -d /proc/self/fd ] || { echo 'Accessible procfs is required' >&2; exit 1; }
    require_go
    command -v patch >/dev/null 2>&1 || { echo 'Real GNU patch 2.7.6 is required' >&2; exit 1; }
    patch_version=$(patch --version) || { echo 'GNU patch could not run' >&2; exit 1; }
    patch_first_line=$(printf '%s\n' "$patch_version" | sed -n '1p')
    [ "$patch_first_line" = 'GNU patch 2.7.6' ] || { echo 'Real GNU patch 2.7.6 is required' >&2; exit 1; }
}

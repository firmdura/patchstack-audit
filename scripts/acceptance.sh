#!/bin/sh
set -eu
. "$(dirname -- "$0")/common.sh"
require_runtime
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cd "$repo"
go build -trimpath -buildvcs=false -o "$work/patchstack" ./cmd/patchstack
go run ./scripts/acceptance "$work/patchstack"

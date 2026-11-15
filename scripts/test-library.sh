#!/bin/sh
set -eu
. "$(dirname -- "$0")/common.sh"
require_runtime
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cd "$repo"
go run ./examples/demo --output "$work/inputs" >/dev/null
mkdir "$work/module"
cp scripts/librarycheck/main.go "$work/module/main.go"
cp go.sum "$work/module/go.sum"
cat >"$work/module/go.mod" <<'EOF'
module example.org/patchstack-external-check

go 1.27.0

toolchain go1.27.4

require github.com/firmdura/patchstack-audit v0.0.0

require go.yaml.in/yaml/v3 v3.0.6 // indirect
EOF
cd "$work/module"
go mod edit -replace "github.com/firmdura/patchstack-audit=$repo"
go run . "$work/inputs" "$work"

#!/bin/sh
set -eu
. "$(dirname -- "$0")/common.sh"
case "${1-}" in
    '') prepare=false ;;
    --prepare) prepare=true ;;
    *) echo 'usage: scripts/verify-linux.sh [--prepare]' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo 'usage: scripts/verify-linux.sh [--prepare]' >&2; exit 2; }
cd "$repo"

if [ "$(uname -s)" = Linux ]; then
    if "$prepare"; then
        require_go
        # This is the only native preparation step allowed to use the network.
        GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download
        echo 'Pinned Go modules prepared; subsequent verification is offline.'
        exit 0
    fi
    require_runtime
    command -v gcc >/dev/null 2>&1 || { echo 'GCC is required for go test -race' >&2; exit 1; }
    go test ./...
    go test -race ./...
    go vet ./...
    mkdir -p bin
    go build -o bin/patchstack ./cmd/patchstack
    ./scripts/acceptance.sh
    ./scripts/test-library.sh
    echo 'PASS complete offline Linux verification'
    exit 0
fi

command -v docker >/dev/null 2>&1 || { echo 'Docker is required on non-Linux hosts' >&2; exit 1; }
image=patchstack-audit-linux:go1.27.4
uid=$(id -u)
gid=$(id -g)
[ "$uid" != 0 ] || { echo 'Run verification as an unprivileged user' >&2; exit 1; }

if "$prepare"; then
    docker build -f build/linux.Dockerfile -t "$image" .
    docker volume create patchstack-audit-gomodcache >/dev/null
    docker volume create patchstack-audit-gocache >/dev/null
    docker run --rm --network=none --user 0:0 \
        -v patchstack-audit-gomodcache:/deps -v patchstack-audit-gocache:/cache \
        "$image" chown "$uid:$gid" /deps /cache
    docker run --rm --user "$uid:$gid" -e HOME=/tmp -e GOTOOLCHAIN=local \
        -e GOMODCACHE=/deps -e GOCACHE=/cache \
        -e GOPROXY=https://proxy.golang.org -e GOSUMDB=sum.golang.org \
        -v patchstack-audit-gomodcache:/deps -v patchstack-audit-gocache:/cache \
        -v "$repo:/work:ro" -w /work "$image" go mod download
    echo 'Pinned Linux image and Go modules prepared; subsequent verification is offline.'
    exit 0
fi

docker image inspect "$image" >/dev/null
docker volume inspect patchstack-audit-gomodcache patchstack-audit-gocache >/dev/null
# A writable checkout comes only from the tracked HEAD. The mounted workspace is
# read-only; no generated output or unrelated workspace file enters verification.
docker run --rm --network=none --user "$uid:$gid" \
    -e HOME=/tmp -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off \
    -e GOFLAGS=-mod=readonly -e GOCACHE=/cache -e GOMODCACHE=/deps \
    -v patchstack-audit-gomodcache:/deps -v patchstack-audit-gocache:/cache \
    -v "$repo:/repository:ro" -w /tmp "$image" sh -eu -c '
        checkout=$(mktemp -d)
        trap '\''rm -rf "$checkout"'\'' EXIT HUP INT TERM
        git -c safe.directory=/repository -c tar.umask=0022 -C /repository archive HEAD | tar -x -C "$checkout"
        cd "$checkout"
        ./scripts/verify-linux.sh
    '

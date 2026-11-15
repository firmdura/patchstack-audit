#!/bin/sh
# Build local release candidates from one immutable tracked Git commit.
set -eu
umask 022
export GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=
. "$(dirname -- "$0")/common.sh"
[ "$#" = 3 ] || { echo 'usage: scripts/release.sh VERSION GIT_REF ABSENT_OUTPUT_DIR' >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo 'Build release archives in the pinned Linux environment' >&2; exit 1; }
require_go
version=$1
ref=$2
output=$3
case "$version" in
    v1.0.0) ;;
    *) echo 'Supported release version is v1.0.0' >&2; exit 2 ;;
esac
case "$output" in /*) ;; *) echo 'Release output must be an absolute path' >&2; exit 2 ;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Release output must be absent' >&2; exit 1; }
[ -d "$(dirname -- "$output")" ] || { echo 'Release output parent must exist' >&2; exit 1; }
cd "$repo"
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo 'Commit tracked changes before building a release candidate' >&2; exit 1; }
commit=$(git rev-parse --verify --end-of-options "$ref^{commit}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/source" "$work/assets"
git -c tar.umask=0022 archive --format=tar "$commit" >"$work/source.tar"
tar -xf "$work/source.tar" -C "$work/source"
prefix=patchstack-audit-$version
git -c tar.umask=0022 archive --format=tar --prefix="$prefix/" "$commit" >"$work/prefixed-source.tar"
gzip -n <"$work/prefixed-source.tar" >"$work/assets/$prefix-source.tar.gz"
cd "$work/source"
goroot=$(go env GOROOT)
cmp LICENSES/Go-LICENSE.txt "$goroot/LICENSE"
cmp LICENSES/Go-PATENTS.txt "$goroot/PATENTS"
for arch in amd64 arm64; do
    name=$prefix-linux-$arch
    mkdir -p "$work/$name/LICENSES"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
        -ldflags='-s -w -buildid=' -o "$work/$name/patchstack" ./cmd/patchstack
    chmod 0755 "$work/$name/patchstack"
    install -m 0644 LICENSE "$work/$name/LICENSE"
    install -m 0644 LICENSES/go-yaml-v3.txt "$work/$name/LICENSES/go-yaml-v3.txt"
    install -m 0644 LICENSES/Go-LICENSE.txt "$work/$name/LICENSES/Go-LICENSE.txt"
    install -m 0644 LICENSES/Go-PATENTS.txt "$work/$name/LICENSES/Go-PATENTS.txt"
    install -m 0644 README.md "$work/$name/README.md"
    cp -R docs "$work/$name/docs"
    go run ./examples/demo --output "$work/$name/example-inputs" >/dev/null
    chmod 0755 "$work/$name" "$work/$name/LICENSES"
    tar --sort=name --format=ustar --owner=0 --group=0 --numeric-owner --mtime=@0 \
        -cf "$work/$name.tar" -C "$work" "$name"
    gzip -n <"$work/$name.tar" >"$work/assets/$name.tar.gz"
done
cd "$work/assets"
sha256sum ./*.tar.gz | sed 's|  ./|  |' >SHA256SUMS
sha256sum -c SHA256SUMS
# GNU mv --no-clobber prevents replacing an independently created destination.
mv -T --no-clobber "$work/assets" "$output"
[ ! -d "$work/assets" ] || { echo 'Release output appeared during the build; it was not replaced' >&2; exit 1; }
echo "Release candidates for $commit are in $output"

.PHONY: build prepare verify release

build:
	go build -o bin/patchstack ./cmd/patchstack

prepare:
	./scripts/verify-linux.sh --prepare

verify:
	./scripts/verify-linux.sh

RELEASE_VERSION ?= v1.0.5
RELEASE_REF ?= HEAD
RELEASE_DIR ?= /tmp/patchstack-audit-$(RELEASE_VERSION)-release
release:
	./scripts/release.sh "$(RELEASE_VERSION)" "$(RELEASE_REF)" "$(RELEASE_DIR)"

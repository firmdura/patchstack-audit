# Network-enabled tool preparation; verification runs with --network=none.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea

RUN apt-get update \
    && apt-get install -y --no-install-recommends patch=2.7.6-7 \
    && rm -rf /var/lib/apt/lists/* \
    && test "$(go env GOVERSION)" = go1.27.4 \
    && test "$(patch --version | head -n 1)" = 'GNU patch 2.7.6'

ENV GOTOOLCHAIN=local
WORKDIR /work

# Hermetic .deb build on Ubuntu 24.04. For a byte-reproducible release, pin the
# base image by digest and record the golang-go version the build used:
#   FROM ubuntu:24.04@sha256:<digest>
#
#   podman build -t wisp-build .
#   podman run --rm -v "$PWD/out:/out" wisp-build
# Result: out/wisp_<version>_amd64.deb and out/SHA256SUMS
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends debhelper dpkg-dev fakeroot golang-go \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
# The build is offline: dependencies are vendored (GOFLAGS=-mod=vendor in debian/rules).
CMD dpkg-buildpackage -us -uc -b \
 && mkdir -p /out && cp /wisp_*.deb /out/ \
 && dpkg-query -W golang-go > /out/toolchain.txt \
 && cd /out && sha256sum wisp_*.deb > SHA256SUMS && cat SHA256SUMS toolchain.txt

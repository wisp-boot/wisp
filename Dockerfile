# Hermetic .deb build on Ubuntu 24.04, with every input pinned:
#   - the base image by digest (the multi-architecture index of ubuntu:24.04 as of 2026-09-15)
#   - the package archive by snapshot timestamp (snapshot.ubuntu.com), so golang-go, debhelper
#     and their dependencies are the same versions on every build
#   - the Go dependencies by go.sum, vendored in the tree
#
#   podman build -t wisp-build .
#   podman run --rm -v "$PWD/out:/out" wisp-build
# Result: out/wisp_<version>_amd64.deb, out/SHA256SUMS, out/toolchain.txt
#
# To move the pins: `podman pull docker.io/library/ubuntu:24.04` and take the digest from
# `podman image inspect --format '{{index .RepoDigests 0}}'`; choose a snapshot timestamp
# (YYYYMMDDTHHMMSSZ) and record both in CHANGELOG.md with the release.
FROM docker.io/library/ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
ARG APT_SNAPSHOT=20260914T000000Z
# console-setup's postinst configures a console; in a container it needs its
# debconf answers preseeded (only ckbcomp and xkb-data are used, see tools/mkkeymaps.sh).
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Snapshots=${APT_SNAPSHOT} update \
 && printf '%s\n' \
      'console-setup console-setup/charmap47 select UTF-8' \
      'console-setup console-setup/codeset47 select Guess optimal character set' \
      'console-setup console-setup/fontface47 select Fixed' \
      'console-setup console-setup/fontsize-text47 select 8x16' \
      'keyboard-configuration keyboard-configuration/modelcode string pc105' \
      'keyboard-configuration keyboard-configuration/layoutcode string us' \
      'keyboard-configuration keyboard-configuration/xkb-keymap select us' \
    | debconf-set-selections \
 && apt-get -o Acquire::Snapshots=${APT_SNAPSHOT} install -y --no-install-recommends \
      build-essential debhelper dpkg-dev fakeroot golang-go console-setup kbd xkb-data \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
# The build is offline: dependencies are vendored (GOFLAGS=-mod=vendor in debian/rules).
CMD dpkg-buildpackage -us -uc -b \
 && mkdir -p /out && cp /wisp_*.deb /out/ \
 && dpkg-query -W golang-go debhelper dpkg-dev console-setup kbd xkb-data > /out/toolchain.txt \
 && cd /out && sha256sum wisp_*.deb > SHA256SUMS && cat SHA256SUMS toolchain.txt

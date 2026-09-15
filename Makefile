# wisp — reproducible initramfs. Targets:
#   make            build both binaries into build/
#   make test       unit tests (root-only tests are opt-in, see README)
#   make deb        the Debian package via podman (hermetic)
#   make hashes     SHA-256 of the binaries (what a verifier compares against)
#   make vendor     refresh vendor/ from go.mod (needs network)

GOFLAGS := -mod=vendor -trimpath
LDFLAGS := -s -w -buildid= -X main.version=$(shell dpkg-parsechangelog -SVersion 2>/dev/null || echo dev)

.PHONY: all build test deb hashes vendor clean

all: build

build:
	CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" go build -ldflags "$(LDFLAGS)" -o build/wisp-init ./cmd/wisp-init
	CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" go build -ldflags "$(LDFLAGS)" -o build/wisp ./cmd/wisp

test:
	CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" go vet ./...
	CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" go test ./...

deb:
	podman build -t wisp-build .
	mkdir -p out && podman run --rm -v "$(CURDIR)/out:/out:Z" wisp-build

hashes: build
	sha256sum build/wisp-init build/wisp

vendor:
	go mod tidy && go mod vendor

clean:
	rm -rf build out

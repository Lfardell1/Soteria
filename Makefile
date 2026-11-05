.DEFAULT_GOAL := build
.DELETE_ON_ERROR:

GO ?= go
VERSION ?= 0.0.0-dev
COMMIT ?= $(shell git rev-parse --verify HEAD)
TARGET ?= debian13-amd64

.PHONY: toolchain build runtime-helper test vet race fmt-check script-check helper-test check runtime package evidence integration clean

toolchain:
	@GO="$(GO)" scripts/check-toolchain.sh

build: toolchain
	@GO="$(GO)" VERSION="$(VERSION)" COMMIT="$(COMMIT)" scripts/build.sh

runtime-helper: toolchain
	@GO="$(GO)" VERSION="$(VERSION)" COMMIT="$(COMMIT)" scripts/build.sh soteria-runtime

test: toolchain
	GOTOOLCHAIN=local "$(GO)" test -mod=readonly -count=1 -timeout=120s ./...

vet: toolchain
	GOTOOLCHAIN=local "$(GO)" vet -mod=readonly ./...

race: toolchain
	GOTOOLCHAIN=local CGO_ENABLED=1 "$(GO)" test -mod=readonly -race -count=1 -timeout=180s ./...

fmt-check: toolchain
	@GO="$(GO)" scripts/check-format.sh

script-check:
	@for file in scripts/*.sh scripts/integration/*.sh; do bash -n "$$file" || exit; done
	@python3 -I -B scripts/test_helpers.py --syntax-only

helper-test:
	@python3 -I -B scripts/test_helpers.py

check: fmt-check script-check helper-test test vet race

# No host installation. Runtime creation requires disposable-build opt-in.
runtime: build
	@GO="$(GO)" scripts/build-runtime.sh "$(TARGET)"

package: build
	@GO="$(GO)" VERSION="$(VERSION)" COMMIT="$(COMMIT)" TARGET="$(TARGET)" scripts/package-deb.sh

evidence: build
	@GO="$(GO)" VERSION="$(VERSION)" COMMIT="$(COMMIT)" scripts/release-evidence.sh

# Never selected by check/test/CI automatically; only for a disposable VM.
integration:
	@scripts/integration/offline-smoke.sh

# Runtime/package trees can be large and immutable. Destroy their disposable
# builder instead; clean only removes these known developer binaries.
clean:
	rm -f -- build/soteria build/soteria-starter build/soteria-engine build/soteria-entry build/soteria-runtime

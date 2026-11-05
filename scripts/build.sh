#!/usr/bin/env bash
set -euo pipefail
umask 022

go_command=${GO:-go}
version=${VERSION:-0.0.0-dev}
commit=${COMMIT:-$(git rev-parse --verify HEAD)}
[[ $version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([~.+-][A-Za-z0-9.+~-]+)?$ ]] || { printf 'Invalid version.\n' >&2; exit 1; }
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { printf 'COMMIT must be the full source commit.\n' >&2; exit 1; }
[[ $(git rev-parse --verify HEAD) == "$commit" ]] || { printf 'COMMIT must match this checkout.\n' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { printf 'The engine build target is Linux amd64 only.\n' >&2; exit 1; }
GO="$go_command" scripts/check-toolchain.sh
mkdir -p build
case "${1:-all}" in
  all) programs=(soteria soteria-starter soteria-engine soteria-entry soteria-runtime) ;;
  soteria-runtime) programs=(soteria-runtime) ;;
  *) printf 'Usage: scripts/build.sh [soteria-runtime]\n' >&2; exit 1 ;;
esac
[[ $# -le 1 ]] || exit 1
[[ -z ${RUNTIME_DIGEST:-} || ${RUNTIME_DIGEST} =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'Invalid runtime digest.\n' >&2; exit 1; }
work=$(mktemp -d "$(pwd -P)/build/binaries.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
for program in "${programs[@]}"; do
  flags="-X main.version=$version -X main.commit=$commit"
  if [[ $program == soteria && -n ${RUNTIME_DIGEST:-} ]]; then flags+=" -X main.runtimeDigest=$RUNTIME_DIGEST"; fi
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_command" build \
    -mod=readonly -trimpath -buildvcs=false -ldflags="$flags" \
    -o "$work/$program" "./cmd/$program"
done
# Publish only a complete build; a failed command must not mix old and new roles.
for program in "${programs[@]}"; do mv -- "$work/$program" "build/$program"; done

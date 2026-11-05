#!/usr/bin/env bash
# Explicit, checksum-pinned toolchain download. No sudo, package manager, or PATH edits.
set -euo pipefail
umask 022

fail() { printf 'Go toolchain: %s\n' "$*" >&2; exit 1; }
[[ $# == 1 && $EUID -ne 0 ]] || fail 'usage as a non-root user: bash scripts/download-go.sh /absolute/new/toolchain-directory'
destination=$1
[[ $destination == /* && $destination != / && $destination != */ && $destination != *'//'* && $destination != *'/../'* && $destination != */.. && $destination != *'/./'* && $destination != */. ]] || fail 'destination must be a clean absolute new directory'
parent=$(dirname -- "$destination")
[[ -d $parent && ! -L $parent && ! -e $destination && ! -L $destination ]] || fail 'parent must exist and destination must not exist'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'only the official Linux amd64 toolchain is pinned'
for tool in curl sha256sum tar mktemp mv; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
work=$(mktemp -d "$parent/.soteria-go.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --max-redirs 3 --max-time 120 --max-filesize 268435456 \
  https://go.dev/dl/go1.27.3.linux-amd64.tar.gz --output "$work/go.tar.gz"
printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 "$work/go.tar.gz" | sha256sum --check --strict -
tar --extract --gzip --file="$work/go.tar.gz" --directory="$work" --no-same-owner --no-same-permissions
[[ $(GOTOOLCHAIN=local "$work/go/bin/go" version) == 'go version go1.27.3 linux/amd64' ]] || fail 'unexpected archive toolchain'
mv --no-clobber -T -- "$work/go" "$destination"
[[ ! -e $work/go ]] || fail 'destination appeared during download; no existing toolchain was replaced'
printf 'Verified Go 1.27.3: %s/bin/go\nNo PATH, system packages, or module files were changed.\n' "$destination"

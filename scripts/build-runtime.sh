#!/usr/bin/env bash
set -euo pipefail
umask 022

fail() { printf 'Runtime build: %s\n' "$*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: SOTERIA_DISPOSABLE_BUILD=1 make runtime TARGET=debian13-amd64|ubuntu24.04-amd64'
[[ ${SOTERIA_DISPOSABLE_BUILD:-} == 1 && $EUID -ne 0 ]] || fail 'requires explicit disposable-build opt-in and a non-root account; never invoke with sudo'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'requires Linux amd64'
[[ -z ${APT_CONFIG:-} ]] || fail 'do not inherit APT_CONFIG; the builder must use its isolated signed snapshot configuration'
if command -v systemd-detect-virt >/dev/null 2>&1; then
  systemd-detect-virt --quiet --vm || systemd-detect-virt --quiet --container || fail 'no VM/container detected; use a disposable builder'
elif [[ ! -f /.dockerenv && ! -f /run/.containerenv ]]; then
  fail 'cannot establish a disposable VM/container context'
fi
for tool in mmdebstrap dpkg-deb sha256sum sort cmp readlink timeout cp; do
  command -v "$tool" >/dev/null || fail "missing build tool: $tool (see docs/building.md; no packages were installed)"
done
case "$1" in
  debian13-amd64) distro=debian; release=13; suite=trixie; keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
  ubuntu24.04-amd64) distro=ubuntu; release=24.04; suite=noble; keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
  *) fail 'unsupported target' ;;
esac
[[ -s $keyring ]] || fail "missing trusted distro keyring: $keyring"
[[ -x build/soteria-runtime && -x build/soteria-entry ]] || fail 'run make build first; the separately built trusted entry is required'
repo=$(pwd -P)
sources="$repo/packaging/runtime/$1.sources"
[[ -f $sources ]] || fail 'run from the repository root'
build/soteria-runtime check-sources --sources "$sources" --distro "$distro" --release "$release" >/dev/null
output="$repo/dist/runtime/$1"
[[ ! -e $output ]] || fail "refusing to overwrite $output; use a fresh disposable builder"
mkdir -p build dist/runtime
work=$(mktemp -d "$repo/build/runtime-$1.XXXXXX")
cleanup() {
  if [[ -d $work && ! -L $work && $work == "$repo"/build/runtime-* ]]; then
    chmod -R u+rwX -- "$work"
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT
include=bash,coreutils,findutils,grep,sed,nano,curl,jq,git,python3,openssl,ca-certificates,tar,gzip,util-linux

# extract+chrootless resolves/downloads authenticated packages but installs
# nothing and runs no package scripts. Never switch this to chrootless+install.
timeout --signal=TERM --kill-after=5s 180s mmdebstrap \
  --mode=chrootless --variant=extract --format=directory --architectures=amd64 \
  --include="$include" --aptopt='APT::Install-Recommends "false"' \
  --aptopt='APT::Get::AllowUnauthenticated "false"' \
  --aptopt='Acquire::AllowInsecureRepositories "false"' \
  --aptopt='Acquire::AllowDowngradeToInsecureRepositories "false"' \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  --customize-hook="$repo/scripts/runtime-package-lock.sh" \
  "$suite" "$work/packages" "$sources"
lock="$work/packages/.soteria-packages.lock"
[[ -s $lock ]] || fail 'extract builder did not produce a complete exact package lock'
if [[ -n ${PACKAGE_LOCK:-} ]]; then
  cmp -- "$PACKAGE_LOCK" "$lock" || fail 'resolved package/archive inventory differs from the reviewed lock'
fi
build/soteria-runtime prepare --source "$work/packages" --root "$work/runtime" \
  --distro "$distro" --release "$release" --packages "$lock" --sources "$sources" --entry "$repo/build/soteria-entry"
build/soteria-runtime sbom-runtime --root "$work/runtime" > "$work/runtime.cdx.json"
build/soteria-runtime licenses-runtime --root "$work/runtime" > "$work/runtime.licenses.json"
cp -- "$lock" "$work/packages.lock"
cp -- "$sources" "$work/snapshot.sources"
{
  mmdebstrap --version
  dpkg-deb --version
  sha256sum -- "$repo/build/soteria-entry" "$repo/build/soteria-runtime"
  sha256sum -- "$keyring"
} > "$work/builder-tools.txt"
[[ -d $work/packages/.soteria-repository-metadata ]] || fail 'signed repository metadata evidence is missing'
cp -R -- "$work/packages/.soteria-repository-metadata" "$work/repository-metadata"
mkdir "$work/result"
mv -- "$work/runtime" "$work/packages.lock" "$work/runtime.cdx.json" "$work/runtime.licenses.json" "$work/snapshot.sources" "$work/builder-tools.txt" "$work/repository-metadata" "$work/result/"
mv -- "$work/result" "$output"
printf 'Built staging runtime: %s/runtime\nReview packages.lock and scan runtime.cdx.json before packaging. VM validation remains required.\n' "$output"

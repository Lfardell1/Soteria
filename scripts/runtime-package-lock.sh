#!/usr/bin/env bash
# Fixed mmdebstrap extract-only hook. This does not run package maintainer code.
set -euo pipefail
shopt -s nullglob
umask 022

[[ ${MMDEBSTRAP_MODE:-} == chrootless && ${MMDEBSTRAP_HOOK:-} == customize && $EUID -ne 0 ]] || {
  printf 'Package inventory hook must run in the unprivileged extract builder.\n' >&2
  exit 1
}
root=${1:?mmdebstrap package tree is required}
archives=("$root"/var/cache/apt/archives/*.deb)
[[ ${#archives[@]} -gt 0 ]] || { printf 'No authenticated package archives found.\n' >&2; exit 1; }
temporary=$(mktemp "$root/.soteria-packages.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
for archive in "${archives[@]}"; do
  [[ -f $archive && ! -L $archive ]] || { printf 'Package archive is not a real regular file.\n' >&2; exit 1; }
  name=$(dpkg-deb --field "$archive" Package)
  version=$(dpkg-deb --field "$archive" Version)
  architecture=$(dpkg-deb --field "$archive" Architecture)
  checksum=$(sha256sum -- "$archive")
  printf '%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" "${checksum%% *}" >> "$temporary"
done
LC_ALL=C sort -- "$temporary" > "$root/.soteria-packages.lock"
metadata=("$root"/var/lib/apt/lists/*_InRelease "$root"/var/lib/apt/lists/*_Release "$root"/var/lib/apt/lists/*_Release.gpg)
[[ ${#metadata[@]} -gt 0 ]] || { printf 'No signed repository metadata found.\n' >&2; exit 1; }
mkdir -- "$root/.soteria-repository-metadata"
for input in "${metadata[@]}"; do
  [[ -f $input && ! -L $input ]] || exit 1
  cp -- "$input" "$root/.soteria-repository-metadata/"
done

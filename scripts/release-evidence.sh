#!/usr/bin/env bash
# This writes an unsigned local build record, never a SLSA/signature substitute.
set -euo pipefail
umask 022

version=${VERSION:?VERSION is required}
commit=${COMMIT:?COMMIT is required}
[[ $version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([~.+-][A-Za-z0-9.+~-]+)?$ ]] || { printf 'Invalid version.\n' >&2; exit 1; }
[[ $version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+[-~][A-Za-z0-9.+~-]+$ ]] || { printf 'Use an explicit development/prerelease version, not a stable label.\n' >&2; exit 1; }
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { printf 'Invalid source commit.\n' >&2; exit 1; }
[[ $(git rev-parse --verify HEAD) == "$commit" ]] || { printf 'COMMIT does not identify this checkout.\n' >&2; exit 1; }
for binary in soteria soteria-starter soteria-engine soteria-entry soteria-runtime; do
  [[ -x build/$binary && ! -L build/$binary ]] || { printf 'Build all five separate binaries first.\n' >&2; exit 1; }
done
[[ ! -e dist/evidence ]] || { printf 'Refusing to overwrite prior evidence; use a clean build workspace.\n' >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$commit")}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || exit 1
mkdir -p build dist
repo=$(pwd -P)
work=$(mktemp -d "$repo/build/evidence.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
output="$work/evidence"
mkdir "$output"
archive="soteria_${version}_linux_amd64"
mkdir "$work/$archive"
install -m 0755 build/soteria "$work/$archive/soteria"
install -m 0644 LICENSE README.md SECURITY.md "$work/$archive/"
tar --sort=name --format=posix --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --pax-option=delete=atime,delete=ctime --directory="$work" -cf - "$archive" | gzip -n > "$output/$archive.tar.gz"
go_command=${GO:-go}
GO="$go_command" scripts/check-toolchain.sh
module_cache=$(GOTOOLCHAIN=local "$go_command" env GOMODCACHE)
go_root=$(GOTOOLCHAIN=local "$go_command" env GOROOT)
for binary in soteria soteria-starter soteria-engine soteria-entry soteria-runtime; do
  build/soteria-runtime sbom-go --binary "build/$binary" --version "$version" > "$output/$binary.cdx.json"
  build/soteria-runtime licenses-go --binary "build/$binary" --source "$repo" --module-cache "$module_cache" --goroot "$go_root" > "$output/$binary.licenses.json"
  sha256sum -- "build/$binary" >> "$output/built-binaries.sha256"
done
cp -- packaging/vm/images.lock.json "$output/vm-images.lock.json"
dirty=false
checkout_status=$(git status --porcelain --untracked-files=normal)
[[ -z $checkout_status ]] || dirty=true
runtime_digest=null
runtime_included=false
if [[ -n ${RUNTIME_DIR:-} ]]; then
  [[ -n ${PACKAGE_LOCK:-} ]] || { printf 'Select the exact PACKAGE_LOCK when including a runtime inventory.\n' >&2; exit 1; }
  runtime=$(readlink -f -- "$RUNTIME_DIR")
  digest=$(build/soteria-runtime verify-staging --root "$runtime" --packages "$PACKAGE_LOCK" --entry "$repo/build/soteria-entry")
  runtime_digest="\"$digest\""
  build/soteria-runtime sbom-runtime --root "$runtime" > "$output/runtime.cdx.json"
  build/soteria-runtime licenses-runtime --root "$runtime" > "$output/runtime.licenses.json"
  cp -- "$runtime/.soteria-manifest.json" "$output/runtime-manifest.json"
  cp -- "$runtime/usr/share/soteria/packages.lock" "$output/packages.lock"
  cp -- "$runtime/usr/share/soteria/snapshot.sources" "$output/snapshot.sources"
  runtime_included=true
fi
printf '{"kind":"unsigned-local-build-record","version":"%s","source":"https://github.com/Lfardell1/Soteria","commit":"%s","dirty_checkout":%s,"toolchain":"go1.27.3","required_toolchain_archive_sha256":"65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40","target":"linux-amd64","source_date_epoch":%s,"runtime_inventory_included":%s,"runtime_digest":%s,"signature":null,"trusted_builder_attestation":null,"reproducibility_verified":false,"license_review":"pending","debian13_vm_matrix":"not-established-by-this-build","ubuntu24_04_vm_matrix":"not-established-by-this-build","release_ready":false}\n' \
  "$version" "$commit" "$dirty" "$SOURCE_DATE_EPOCH" "$runtime_included" "$runtime_digest" > "$output/build-record.json"
printf '%s\n' \
  'UNSIGNED DEVELOPMENT ARTIFACTS, NOT A RELEASE OR SECURITY ATTESTATION.' \
  'This archive has no installed immutable runtime and cannot run sessions by itself.' \
  'Other built roles have per-binary hashes, Go SBOMs, and actual license-file inventories, not installed artifacts.' \
  'Runtime SBOM/manifest, when present, describe a separately selected staging tree.' \
  'Required before release: matching .deb, runtime/module scans and license review,' \
  'clean-install/upgrade/uninstall and full disposable Debian/Ubuntu VM evidence,' \
  'independent clean-build comparison, reviewed provenance, and verified signatures.' \
  'See docs/releasing.md. Checksums detect changes; they do not establish origin.' > "$output/EVIDENCE-STATUS.txt"
(
  cd "$output"
  sha256sum -- ./* > SHA256SUMS
)
mv -- "$output" "$repo/dist/evidence"
printf 'Unsigned development evidence: %s/dist/evidence\nNo package was published or signed.\n' "$repo"

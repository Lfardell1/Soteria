#!/usr/bin/env bash
set -euo pipefail
umask 022

fail() { printf 'Debian package: %s\n' "$*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail 'build as a non-root account; archive ownership is normalized without chown or sudo'
version=${VERSION:?VERSION is required}
commit=${COMMIT:?COMMIT is required}
target=${TARGET:?TARGET is required}
deb_version=${version#v}
[[ $deb_version =~ ^[0-9]+\.[0-9]+\.[0-9]+([~.+-][A-Za-z0-9.+~-]+)?$ ]] || fail 'invalid package version'
[[ $deb_version =~ ^[0-9]+\.[0-9]+\.[0-9]+[-~][A-Za-z0-9.+~-]+$ ]] || fail 'only explicitly prerelease/development packages may be built by this tooling'
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'COMMIT must be a full source commit'
case "$target" in debian13-amd64|ubuntu24.04-amd64) ;; *) fail 'unsupported target' ;; esac
for tool in dpkg-deb sed du cut sha256sum timeout readlink install cp git; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
[[ $(git rev-parse --verify HEAD) == "$commit" ]] || fail 'COMMIT must match this checkout'
for binary in soteria soteria-starter soteria-engine soteria-entry soteria-runtime; do
  [[ -x build/$binary && ! -L build/$binary ]] || fail 'build all five separate binaries first'
done
[[ -n ${RUNTIME_DIR:-} && -n ${PACKAGE_LOCK:-} ]] || fail 'select a real RUNTIME_DIR and the reviewed exact PACKAGE_LOCK explicitly; no placeholder or floating package is built'
runtime=$(readlink -f -- "$RUNTIME_DIR") || fail 'cannot resolve the selected runtime; build it in a disposable environment first'
lock=$(readlink -f -- "$PACKAGE_LOCK") || fail 'cannot resolve the selected exact package lock'
[[ -d $runtime ]] || fail 'a real runtime is required; run the disposable runtime builder first'
case "$target" in
  debian13-amd64) distro=debian; release=13 ;;
  ubuntu24.04-amd64) distro=ubuntu; release=24.04 ;;
esac
repo=$(pwd -P)
sources="$repo/packaging/runtime/$target.sources"
digest=$(build/soteria-runtime verify-staging --root "$runtime" --distro "$distro" --release "$release" \
  --packages "$lock" --sources "$sources" --entry "$repo/build/soteria-entry")
lock_hash=$(sha256sum -- "$runtime/usr/share/soteria/packages.lock")
lock_hash=${lock_hash%% *}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$commit")}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || fail 'SOURCE_DATE_EPOCH must be an integer'
mkdir -p build dist/packages
work=$(mktemp -d "$repo/build/deb.XXXXXX")
cleanup() { chmod -R u+rwX -- "$work"; rm -rf -- "$work"; }
trap cleanup EXIT
stage="$work/root"
install -d -m 0755 "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/libexec/soteria" "$stage/usr/lib/soteria" "$stage/usr/share/doc/soteria" "$stage/etc/soteria"
install -d -m 0755 "$stage/etc/soteria/profiles"
install -m 0755 build/soteria "$stage/usr/bin/soteria"
install -m 0755 build/soteria-starter "$stage/usr/libexec/soteria/soteria-starter"
install -m 0755 build/soteria-engine "$stage/usr/libexec/soteria/soteria-engine"
cp -a --no-preserve=ownership -- "$runtime" "$stage/usr/lib/soteria/runtime"
build/soteria-runtime verify-staging --root "$stage/usr/lib/soteria/runtime" --packages "$lock" --sources "$sources" --entry "$repo/build/soteria-entry" >/dev/null
install -m 0644 LICENSE "$stage/usr/share/doc/soteria/copyright"
install -m 0644 README.md SECURITY.md CHANGELOG.md config/config.example.json "$stage/usr/share/doc/soteria/"
cp -R -- docs "$stage/usr/share/doc/soteria/"
size=$(du -sk "$stage" | cut -f1)
sed -e "s/@VERSION@/$deb_version/g" -e "s/@TARGET@/$target/g" -e "s/@DIGEST@/$digest/g" -e "s/@SIZE@/$size/g" -e "s/@COMMIT@/$commit/g" -e "s/@LOCK@/$lock_hash/g" \
  packaging/debian/control.in > "$stage/DEBIAN/control"
name="soteria_${deb_version}_${target}.deb"
for suffix in '' .runtime.cdx.json .runtime.licenses.json .sha256 .status.json .soteria.cdx.json .soteria.licenses.json .soteria-starter.cdx.json .soteria-starter.licenses.json .soteria-engine.cdx.json .soteria-engine.licenses.json .soteria-entry.cdx.json .soteria-entry.licenses.json; do
  [[ ! -e dist/packages/$name$suffix ]] || fail 'refusing to replace an existing package or evidence file'
done
build/soteria-runtime sbom-runtime --root "$runtime" > "$work/$name.runtime.cdx.json"
build/soteria-runtime licenses-runtime --root "$runtime" > "$work/$name.runtime.licenses.json"
go_command=${GO:-go}
GO="$go_command" scripts/check-toolchain.sh
module_cache=$(GOTOOLCHAIN=local "$go_command" env GOMODCACHE)
go_root=$(GOTOOLCHAIN=local "$go_command" env GOROOT)
for binary in soteria soteria-starter soteria-engine soteria-entry; do
  build/soteria-runtime sbom-go --binary "build/$binary" --version "$version" > "$work/$name.$binary.cdx.json"
  build/soteria-runtime licenses-go --binary "build/$binary" --source "$repo" --module-cache "$module_cache" --goroot "$go_root" > "$work/$name.$binary.licenses.json"
done
printf '{"kind":"unsigned-development-package","commit":"%s","version":"%s","runtime_digest":"%s","package_lock_sha256":"%s","installed_ownership_verified":false,"vm_matrix":"pending","release_ready":false}\n' \
  "$commit" "$version" "$digest" "$lock_hash" > "$work/$name.status.json"
timeout --signal=TERM --kill-after=5s 180s dpkg-deb --root-owner-group --uniform-compression -Zxz -z6 --build "$stage" "$work/$name"
checksum=$(sha256sum -- "$work/$name")
printf '%s  %s\n' "${checksum%% *}" "$name" > "$work/$name.sha256"
mv -- "$work/$name" "$work/$name."* dist/packages/
printf 'Built %s (unsigned; not VM-validated).\n' "dist/packages/$name"

# Building

## Safe Developer Commands

Use Linux amd64 and Go **1.27.3**. `GO=/absolute/path/to/go make build` selects that executable explicitly. Automatic Go toolchain downloads are disabled by `GOTOOLCHAIN=local`; module files are read-only during builds/tests. Make, Bash, Git, and coreutils are required; Python 3 is required for helper/syntax checks, and a C compiler for race tests. No developer target runs sudo, installs packages, starts a session, or rewrites go.mod/go.sum.

For an explicit, unprivileged toolchain download, `bash scripts/download-go.sh /absolute/new/go-directory` fetches only the official Linux amd64 Go 1.27.3 archive and checks SHA256 **`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`** before extraction. The parent must exist and the destination must not exist. No remote shell installer, automatic PATH change, or system install is used. The same checksum-pinned script is selected explicitly by CI.

```sh
make build
make runtime-helper
make helper-test
make test
make vet
make race
make check
```

`make build` compiles five separate static Linux amd64 binaries: `soteria`, `soteria-starter`, `soteria-engine`, `soteria-entry`, and `soteria-runtime`, all under `build/`. `soteria-runtime` is an unprivileged **build utility**, never the authorized session helper. The public CLI is stamped with version/commit; defaults are `0.0.0-dev` and the current full commit. It reports an unverified runtime digest unless a real digest was explicitly supplied at build time. Installed doctor/runtime inventory checks establish the selected runtime's actual digest. There is no root build-tree fallback or old `make run` target.

`make runtime-helper` builds only the inventory/build utility for focused development. `make clean` removes only the five named binaries, not an immutable runtime, caches, or session resources. Destroy the disposable builder when finished. `build/` and `dist/` are ignored outputs; never commit credentials or session contents.

## Runtime Inputs

The runtime is built from the checked-in Deb822 sources in `packaging/runtime/`, fixed at **20261101T000000Z**. Debian uses trixie, trixie-updates, and trixie-security; Ubuntu uses noble, noble-updates, and noble-security, main/universe. Apt must validate distro signatures using an already provisioned distro archive keyring. Only snapshot expiry is disabled for historical snapshots; signature or package-hash verification is not disabled.

The initial requested tools are Bash, coreutils, findutils, grep, sed, Nano, curl, jq, Git, Python 3, OpenSSL, CA certificates, tar, gzip, and util-linux (`setpriv`, `setsid`). Apt resolves their complete hard dependency closure with no recommends. `packages.lock` records **every resolved package's exact name/version/architecture and downloaded .deb SHA256**, not a floating top-level list. A fixed snapshot is not an update policy or evidence of vulnerability freedom.

These are selected snapshot coordinates, **not a claim of successful signed apt resolution or a working distro runtime**. The builder checks fixed target/suites, timestamped HTTPS origins, architecture, required signing keyring, and absence of signature-bypass options before resolution. No package versions/archive hashes are invented or checked in as a release lock. Successful authenticated extraction must emit the complete lock; review it and enforce it on the next clean build. Snapshot availability, signatures, required executables/libraries, and package completeness remain build gates until actually exercised.

## Disposable Builder Only

Provision a throwaway Linux amd64 VM or container with Go 1.27.3, Bash, Make, Git, coreutils, apt, dpkg-deb, mmdebstrap, and the correct distro keyring. The keyring must actually contain the selected release's signing keys; an older builder's keyring is not presumed sufficient. Obtain tools through reviewed distro packages, record exact versions, and discard this environment afterward. Scripts do not install them. Runtime extraction may use a disposable container; **session integration requires a booted disposable VM, not container root**.

Run from the checkout as a **non-root** build account. The builder requires both explicit opt-in and VM/container detection. These guards are useful accident prevention, not proof that a container lacks host mounts. Do not attach your home, credentials, SSH/GPG agents, privileged Docker socket, or sensitive host paths to it.

```sh
SOTERIA_DISPOSABLE_BUILD=1 make runtime TARGET=debian13-amd64 VERSION=0.1.0-alpha.1
# In a separate fresh disposable build workspace:
SOTERIA_DISPOSABLE_BUILD=1 make runtime TARGET=ubuntu24.04-amd64 VERSION=0.1.0-alpha.1
```

The runtime command uses **only** `mmdebstrap --mode=chrootless --variant=extract --format=directory`. This requests authenticated package extraction, not chroot execution, installation, or package maintainer scripts. Never change it to chrootless installation, whose scripts could affect the builder. No host userland is copied into the runtime. Missing tools/keyrings, unavailable snapshots, authentication errors, absent archive inventories/signed repository metadata, or a bounded timeout are failures. The extraction path itself has not been integration-validated here; no placeholder runtime is emitted on failure.

`soteria-runtime prepare --entry ABS --packages LOCK --sources SOURCES ...` copies public package `/usr` and compatibility paths into a fresh tree, breaks archive hard links by copying, removes OpenSSL's private-key-directory alias, and creates empty mount placeholders. It copies **the separately built** `build/soteria-entry` to runtime `/usr/libexec/soteria-entry` before sealing. It builds the CA bundle only from package public CA certificates, retains public OpenSSL configuration, and creates the five minimal `/etc` placeholders for selective session binds. The immutable CA tree is not hidden by a blanket `/etc` overlay. Host resolver/hostname/accounts/trust additions and maintainer scripts are not replayed; missing/dangling tools or unsafe content fail instead of falling back to host files.

The Go generator normalizes files to 0444/0555, directories to 0555, and package absolute symlinks to internal relative symlinks. It rejects hard-linked inputs, secret paths/PEM private keys, capabilities, special objects, unsafe/dangling links, incomplete inventories, and unsupported metadata. It generates `.soteria-manifest.json` using the **existing `toolkit.Inventory` and `toolkit.Digest` v1 encoding**, without a second digest format.

The canonical archive lock and snapshot sources are also copied into runtime `/usr/share/soteria/` and covered by its inventory. Verification checks their identities against `toolkit.Inventory`; packaging compares all archive hashes/architectures against the explicitly selected lock and the embedded entry against the current build.

Outputs under `dist/runtime/TARGET/` are `runtime/`, `packages.lock`, `snapshot.sources`, `runtime.cdx.json`, `runtime.licenses.json`, `builder-tools.txt`, and captured signed `repository-metadata/`. These are staging contents, **not proof of installed root ownership**. `verify-staging` allows builder-owned files while checking contents/modes/links/secrets; production `toolkit.Verify` still requires safe root-owned ancestors and every installed object root:root. An inventory does not authenticate its builder or substitute for signatures/review.

Enforce a reviewed complete package lock in another fresh builder:

```sh
SOTERIA_DISPOSABLE_BUILD=1 PACKAGE_LOCK=/absolute/reviewed/packages.lock \
  make runtime TARGET=debian13-amd64 VERSION=0.1.0-alpha.1
```

The full resolver result and archive hashes must match before a runtime is published to the output directory. Review distro advisories and scan `runtime.cdx.json`; an old pinned snapshot must be refreshed deliberately rather than silently accepting new versions.

## Debian Package

On the same non-root build account, after a real runtime exists:

```sh
RUNTIME_DIR="$PWD/dist/runtime/debian13-amd64/runtime" \
PACKAGE_LOCK=/absolute/reviewed/packages.lock \
  make package TARGET=debian13-amd64 VERSION=0.1.0-alpha.1
```

Use the same source/version throughout runtime and package builds, or the embedded entry hash can correctly differ. Select Ubuntu's matching runtime/lock and `TARGET=ubuntu24.04-amd64` for Ubuntu. A real explicit `RUNTIME_DIR`, exact `PACKAGE_LOCK`, matching target/sources/entry, and prerelease/development version are mandatory. A binary-only, fake-root, floating-lock, or stable-labeled package is refused. `dpkg-deb --root-owner-group` sets archive ownership without root/sudo/chown; it does not prove installed ownership.

Outputs include the unsigned `.deb`, checksum, runtime SBOM/license-file inventory, per-binary Go SBOM/license-file inventories for the four shipped executables, and a status record with VM/license/release gates pending. `SOURCE_DATE_EPOCH` defaults to the source commit time. Deterministic settings are an attempt, **not established reproducibility**. The script never installs its result, publishes a package, or provisions authorization/network policy.

Package layout:

| Path | Purpose |
| --- | --- |
| `/usr/bin/soteria` | Root-owned 0755 public executable |
| `/usr/libexec/soteria/soteria-starter` | Separate root-owned 0755 starter, no arguments |
| `/usr/libexec/soteria/soteria-engine` | Separate root-owned 0755 engine; fixed worker/cleanup and private namespace/transfer re-execs |
| `/usr/lib/soteria/runtime` | Complete root-owned immutable runtime and 0444 manifest |
| Runtime `/usr/libexec/soteria-entry` | Separate root-owned 0555 non-root launch verifier, included in the manifest |
| Runtime `/usr/share/soteria/{packages.lock,snapshot.sources}` | Inventoried exact build inputs, not host configuration |
| `/etc/soteria/profiles` | Empty root-owned profile directory, no keys or generated identity |
| `/usr/share/doc/soteria` | Usage, limitations, example config, source license |
| Runtime `/usr/share/doc/*/copyright` | Package-supplied license/source information retained with the userland |

Declared host dependencies are `bubblewrap (>= 0.8.0)`, `systemd (>= 255)`, `dbus`, and `sudo`. Runtime shared libraries are bundled from the snapshot, not linked to a guessed host `/lib`. systemd being installed does not prove that it is PID 1 or that required cgroup controls work; doctor/startup must check those facts. No maintainer scripts, permanent service, sudoers entry, privilege grant, network reconfiguration, or kernel policy change is installed by Soteria.

`soteria-runtime licenses-runtime` inventories actual bundled distro copyright files by package. `licenses-go --binary ABS --source ABS --module-cache ABS --goroot ABS` inventories actual top-level license/notice files for the application, compiler, and linked modules. Missing files are explicitly unavailable, not cleared. These tools hash files; they do not classify legal terms, prove source-offer compliance, or complete redistribution review.

Inspect with `dpkg-deb --info` and `dpkg-deb --contents`. Explicit installation using `sudo apt install ./dist/packages/SELECTED.deb` is an administrator decision on a disposable target VM, **not** a normal build step. Run the public CLI without sudo afterward. Installed root ownership and integrity must pass doctor; installation/upgrade/removal behavior still requires target VM evidence.

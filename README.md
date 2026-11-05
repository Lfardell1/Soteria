# Soteria

Soteria is an **experimental disposable Linux terminal workspace** for familiar CLI tools on a trusted host. The implementation uses an administrator-installed, read-only distro runtime, private tmpfs working state, explicit file transfers, and offline-by-default networking. An explicit administrator-provisioned WireGuard profile is the only online mode.

**It is not an anonymity system, a Tails replacement, a hostile-code sandbox, or a secure-erasure tool.** The host kernel, administrator, hypervisor, distro packages, and VPN provider remain trusted. No audit or completed VM validation is claimed. Do not put sensitive work in this development build on the assumption that its intended boundaries have already been proven.

## Status And Targets

| Target | Status |
| --- | --- |
| Debian 13, amd64, booted systemd, cgroup v2 | Initial target; experimental until the disposable-VM matrix passes |
| Ubuntu 24.04 LTS, amd64, booted systemd, cgroup v2 | Initial target; experimental until the disposable-VM matrix passes |
| Other Linux releases or architectures | Unsupported |
| macOS, including a Lima backend | Not implemented; requires a separately validated disposable Linux VM backend and arm64 runtime work |
| Windows, including Hyper-V/QEMU/WSL | Not implemented; no native or shared-WSL isolation claim |

The repository contains runtime/package builders and an opt-in offline VM smoke fixture. This change does **not** supply a built runtime or `.deb`, record a passed VM matrix, establish reproducibility, or publish signed releases. The manual GitHub build workflow produces explicitly unsigned **CLI-only development evidence**, not an installable or release-ready environment.

## Security Boundary

- Writable session paths must use bounded private tmpfs. Failure to establish isolation, privilege reduction, required resource controls, or the selected network boundary is fatal; there is no disk-workspace or direct-network fallback.
- Offline mode has no external workload interface. WireGuard mode is intended to permit only a full-tunnel IPv4 workload path, with workload IPv6 disabled. This is not a guarantee of anonymity or immutable outer peer endpoints.
- Commands use a curated package runtime, not automatic copies of `/bin`, `/usr`, a host home, credentials, or agent sockets. The public runtime itself is stored on disk read-only.
- Imports are explicitly copied to `/work/in/<basename>`. Outputs deliberately placed in `/work/out` may be exported only after a successful command. Stdout/stderr and exports are intentional persistence boundaries.
- Missing or unverified memory-retention protections cause specific warnings and continued execution with tmpfs. Ordinary tmpfs can swap; anonymous memory, piped dump collectors, hibernation, host snapshots, terminal/history/audit logs, remote logs, and physical RAM remanence are not erased by cleanup.

See [security boundaries and claims-to-tests](docs/security.md), [testing](docs/testing.md), and [security reporting](SECURITY.md).

## Build And Install

Use Go **1.27.3**, Make, Git, Bash, and a C compiler for race tests. These commands are unprivileged and do not install dependencies or run a root shell:

```sh
make build
make test
make vet
make race
# Formatting, shell syntax, unit, vet, and race checks:
make check
```

`make build` produces `build/soteria`, `build/soteria-starter`, `build/soteria-engine`, `build/soteria-entry`, and the build-only `build/soteria-runtime` utility. These are distinct programs, not copies of a unified helper. Building them does not install a runtime or authorize sessions. Run `build/soteria doctor --json` to inspect missing prerequisites; `version`, help, and config checks need no authorization.

For installation, first build a real runtime and `.deb` in a disposable Linux builder using [the pinned-snapshot build instructions](docs/building.md). On a disposable target VM, inspect the package and its checksums before explicitly installing it with the distro package manager. Never pipe a remote installer to a shell or run the checkout as root.

The development package layout is fixed:

| Path | Role |
| --- | --- |
| `/usr/bin/soteria` | Unprivileged public CLI using `internal/client` and `internal/protocol` |
| `/usr/libexec/soteria/soteria-starter` | One-shot authorized starter, with no command-line arguments |
| `/usr/libexec/soteria/soteria-engine` | Root service with fixed `__worker` and `__cleanup` commands; fixed same-engine `__namespace`/`__transfer` re-execs |
| `/usr/lib/soteria/runtime` | Curated root-owned, read-only userland and exact file inventory |
| Runtime `/usr/libexec/soteria-entry` | Separately built, immutable, inventoried non-root launch verifier, after the fixed credential drop |

The last path is **inside** the curated root, not a host `/usr/libexec` overlay. The package declares Bubblewrap, systemd, D-Bus, and sudo as host dependencies. It installs no Soteria setuid binary, sudoers rule, privilege-grant policy, persistent daemon, network configuration, or WireGuard credential. Existing administrator sudo policy is required. The CLI invokes only `sudo -- /usr/libexec/soteria/soteria-starter`, with no flags, argv, profile, or host paths passed as starter arguments. **Do not run `sudo soteria shell` or `sudo soteria run`.**

`scripts/install_dependencies.sh` now refuses the retired host-mutating installer. The old `make run` sudo target and automatic `go mod tidy` target are gone.

## Command Workflow

Run the installed public CLI as an ordinary non-root user:

```sh
soteria doctor --json
soteria config check
soteria version
soteria run -- jq --version
soteria shell
```

`run` executes argv directly, not through an implicit shell. `shell` selects `/bin/bash --noprofile --norc -i` and requires terminal stdin and stdout. For scripted Bash use `soteria run -- /bin/bash --noprofile --norc ...`. Sessions use offline networking unless **both** `--network=wireguard --profile NAME` are explicitly supplied, even when a configuration requests WireGuard. Commands refer to the runtime or imported snapshots, not arbitrary host executables.

For a local transformation, choose inputs and an existing empty destination deliberately:

```sh
mkdir results
soteria run --import "$PWD/input.json" --export "$PWD/results" -- \
  bash -c 'jq --sort-keys . /work/in/input.json > /work/out/formatted.json'
```

Repeated `--import HOST_PATH` flags copy bounded snapshots. The import stream is completed even with no imports. Default limits are 256 MiB and 10,000 entries; `max_files` counts directories as well as regular files. Basename collisions, symlinks, special files, traversal, and unsafe metadata are rejected. Exports use caller permissions and never overwrite or merge transferred directories into existing entries. The destination filesystem must support Linux `O_TMPFILE` and no-replace publication; missing support fails rather than using unsafe named temporary files. Per-file publication is atomic, but a multi-file export can fail after publishing some entries, which are not rolled back. Failed commands, cancellation, or disconnect default to **no export**. Crash recovery of ephemeral files is not promised.

After an administrator has installed a reviewed profile:

```sh
soteria run --network=wireguard --profile office -- curl https://example.com/
```

There is no OpenVPN, Tor, Proxychains, DNSCrypt, browser, or VPN-stack compatibility mode. [WireGuard profile format and permissions](docs/operations.md) are intentionally restricted; imported hooks are never run. Doctor/config checks do not bring up a tunnel or contact a health-check service.

The child status is propagated, except exit **125** is reserved for setup/runtime/export/cleanup infrastructure failure. Results preserve child-start/exit information separately from cleanup errors and boundary facts; cleanup failure is not success even when the child succeeded. Terminal, credential, service-lifetime, and signal behavior still require VM validation.

## Configuration

There is **no current-directory config discovery** or automatic credential discovery. Without `--config`, the CLI reads `/etc/soteria/config.json` if it exists, otherwise explicitly reports built-in defaults. An existing unreadable or invalid config is an error, not a silent fallback. Select another clean absolute config path explicitly:

```sh
soteria config check --config /absolute/path/to/config.json
soteria run --config /absolute/path/to/config.json --network=offline -- jq --version
```

The version-1 example is [config/config.example.json](config/config.example.json). Defaults are 1 GiB service memory maximum, 512 MiB writable workspace, 256 tasks, and transfer limits of 256 MiB/10,000 file-or-directory entries. Sizes use binary K/M/G units. Unknown/duplicate/case-mismatched fields, legacy schemas, overflow, invalid limits, and unsafe combinations are rejected. Effective settings are reported with the profile redacted. Configuration alone never enables WireGuard, reads a private key, or changes privileged paths.

Legacy OpenVPN/Tor configuration cannot be silently migrated into a WireGuard identity. Remove legacy filesystem-copy paths and kill-switch booleans; they cannot weaken the new boundary. See [operations and recovery](docs/operations.md).

## Development And Releases

Safe PR CI uses pinned actions and unprivileged Go unit/vet/race tests. Go vulnerability checks and runtime-package scanning are distinct. Privileged smoke testing is manual-only and guarded by a marked disposable Debian/Ubuntu VM; it is never part of `make test` or `make check`.

[Build instructions](docs/building.md), [VM test scope](docs/testing.md), [release evidence/gates](docs/releasing.md), and [the changelog](CHANGELOG.md) distinguish implementation from validation. Checksums and inventories are not signatures; signatures establish origin, not security. Stable labeling requires published limitations, clean-install/upgrade/uninstall and failure-test evidence, and independent review of the privilege, transfer, isolation, and networking boundaries.

No telemetry, automatic updates, hosted Soteria health checks, or persistent session logs are requested by default. Service stdout/stderr are `null`; bounded, redacted session diagnostics use private IPC, and service commands/descriptions contain no user argv. This does **not** remove sudo/systemd/audit metadata, public CLI command-line observations, terminal recordings, or remote logs. `LimitCORE=0` does not disable piped collectors; `Storage=none` alone is insufficient without `ProcessSizeMax=0`, and neither setting removes collector metadata. Soteria never changes host dump/swap policy automatically. Bug reports should not include session contents, profiles, private keys, home directories, or raw logs by default.

## License

Soteria source is [MIT licensed](LICENSE). Bundled distro packages and Go dependencies have their own licenses and source obligations; inventory generation is not a completed redistribution/license review.

# Soteria Delivery Plan

## Goal
Make Soteria a useful, evidence-backed disposable terminal workspace, not a tool that promises anonymity or forensic erasure. Deliver a dependable Linux product before adding VM-backed desktop-platform support.

## Agreed Scope
- Primary users: people running familiar CLI tools on a trusted host, with disposable working files and controlled networking.
- Initial networking: enforced offline mode by default, plus one full-tunnel WireGuard mode. Defer OpenVPN, Tor, DNSCrypt, Proxychains, and arbitrary network-layer combinations.
- Initial supported hosts: Debian 13 and Ubuntu 24.04 LTS, x86-64, systemd, cgroup v2. Pin exact tested VM images and dependency versions. Other releases are unsupported until validated, not presumed compatible.
- Platform sequence: Linux first; macOS through a disposable Linux VM next; Windows through a separately validated Linux VM backend later. macOS's Unix heritage does not supply Linux isolation facilities.
- Workspace: maintained, read-only toolkit plus tmpfs-backed writable state. Explicit input/output transfers; no automatic home-directory, credential, agent-socket, or host-directory sharing.
- Convenience decision: warn and continue when memory-retention protections are unavailable or unverified. This applies to swap/dump risks only. Missing isolation, privilege reduction, tmpfs, resource containment, or safe network setup remains fatal.
- Root authorization is required for Linux setup initially. Do not install setuid executables, permissive sudo rules, or an always-running privileged daemon.
- GUI/browser integration, hostile-code containment, persistence, plugins, rootless execution, and native non-Linux isolation are out of scope for the first release.

## Baseline Findings
- `cmd/soteria/main.go:13-27` and `internal/session/session.go:67-91` mount/populate, start host services, and open a TUI. They never execute a user shell or command.
- `internal/filesystem/filesystem.go:60-64` mounts ordinary swappable tmpfs. Copying host binaries into it creates no execution boundary; `zeroTree` cannot establish secure erasure.
- `internal/network/stack.go:186-255` alters host-global IPv4 policy and allows arbitrary direct traffic on VPN-associated ports. IPv6 is untouched. This implementation must not remain an alternative execution path.
- `internal/session/session.go:56-90,94-122` permits cancellation/cleanup races and discards cleanup failures. Status checks do not establish actual session health.
- The default/example configuration is inconsistent, JSON typos are accepted, and size multiplication can overflow in `internal/config/config.go`.
- `internal/network/stack_test.go:31-61` changes the live firewall under root despite its dry-test name. Ordinary tests must become safe before adding coverage.

## Security Contract
- Protect disposable session files from ordinary accidental writes to host storage, and restrict workload network access to the chosen mode. These are separate, testable properties.
- Writable session paths must use tmpfs even in best-effort memory mode. Never substitute a disk directory when tmpfs setup fails.
- Public runtime binaries and package metadata may live on disk read-only. Do not copy the whole host userland into RAM or claim that every executed byte originates in RAM.
- Trust the host kernel, administrator, hypervisor, runtime packages, and selected VPN provider. Namespaces and a VPN do not defeat a malicious host or provide Tails-equivalent anonymity.
- Explicitly exclude host terminal/history/audit logs, caller-side buffers, remote logs, account/browser identifiers, global traffic correlation, host memory capture, hibernation, and physical RAM remanence from the guarantee.
- Standard output and exports are intentional escape boundaries. A host shell can record redirected output; an explicitly exported file is persistent by design.
- Report individual facts: filesystem volatility, anonymous-memory swap control, tmpfs swap control, dump-policy confidence, network readiness, and cleanup result. Never collapse these into an unsupported green "anonymous/secure" verdict.
- No telemetry, automatic update checks, hosted Soteria health service, or persistent session logs by default. Required probes use only the configured VPN peer/resolver; other traffic comes from the user's commands.

## Runtime Design
```text
Caller CLI -> one-shot authorized starter -> transient systemd service
                                              root supervisor
                                                namespace-entry worker
                                                  Bubblewrap + PID-1 reaper
                                                    trusted credential/TTY entrypoint
                                                      non-root command

Workload network namespace: lo only, or lo + WireGuard
WireGuard encrypted UDP socket: host network namespace
```

- Keep CLI parsing, terminal relay, and host file access unprivileged. Use a packaged, root-owned starter to authorize creation of a fixed supervisor executable; never run a caller-selected program as the service's root command.
- Use systemd's transient-service D-Bus API with private FD handoff, not shell-generated commands. Authenticate the caller through the authorized starter/kernel credentials; never accept request-supplied UID/GID as authority. Reject root as the workload identity.
- Service ownership: `Type=exec`, `Restart=no`, `RemainAfterExit=no`, `KillMode=control-group`, `SendSIGKILL=yes`, `OOMPolicy=kill`, bounded setup/shutdown, `PrivateMounts=yes`, and a mode-0700 runtime directory. Set memory/task limits before receiving secrets; do not delegate cgroup controls to workloads.
- Maintain an independent CLI/supervisor lifeline. Its unexpected closure cancels the session; ordinary workload stdin EOF does not. `systemd-run --wait/--pty` alone is not a lifetime guarantee.
- Use a single lifecycle owner: `Validating -> Preparing -> NetworkReady -> Running -> Exporting -> Stopping -> Finished/Failed`. Cancellation prevents further acquisitions. Register each acquired resource immediately; concurrent stop requests await the same result.
- Use anonymous network-namespace FDs, private mount propagation, and a namespace-entry re-exec worker. Do not change namespaces in the live multithreaded Go CLI/supervisor.
- Bubblewrap supplies mount/PID/IPC/UTS isolation and reaping. It has no `--netns FD` option: enter the prepared netns before executing it, and do not subsequently unshare networking again.
- Initial rootful Bubblewrap setup must not confuse user-namespace UID mappings with a host credential drop. Avoid its user-namespace/UID-mapping flags in this design. Drop all payload capabilities except `CAP_SETUID`, `CAP_SETGID`, and `CAP_SETPCAP` needed by a fixed trusted `setpriv` entrypoint; that entrypoint sets real/effective/saved UID/GID to the nonzero caller, clears supplementary groups and all capability sets, and applies `no_new_privs` before any user program runs.
- Construct fixed wrapper argv, using curated util-linux `setsid --ctty`/`setpriv` as needed. Prove the chain against distro-packaged versions before adopting it. Do not implement a new PID-1 runtime, cryptography, or generalized sandbox framework.
- Mount a fresh procfs and minimal devices. Expose no host `/home`, `/run`, `/sys`, service sockets, or broad `/dev`. Reset environment, working directory, `HOME`, `TMPDIR`, and XDG directories.
- Close every descriptor except explicitly authorized command stdio. Namespace handles, host directories/sockets, control channels, and credentials must not reach the command; Bubblewrap does not blanket-close inherited FDs for the application.
- Normal cleanup terminates/reaps workload descendants, completes only authorized exports, removes WireGuard, and closes namespace/mount handles. Systemd owns descendant cleanup on supervisor death. A fixed `ExecStopPost` helper handles only positively identified residual host resources, including the brief WireGuard create-before-move window.
- Do not rely on `ExecStopPost` seeing mounts created by `ExecStart`; systemd gives these separate mount namespaces. Prefer namespace-lifetime cleanup over host mountpoints and named netns pins.

## Delivery Sequence

### 1. Establish Baseline
- Replace README absolutes with the security contract and experimental status. Add future implementation documentation for threat model, supported hosts, recovery, and limitations; this planning turn changes none of those files.
- Gate existing privileged tests behind explicit integration selection. Require disposable VMs, not merely EUID 0. Ordinary `go test ./...` must not mount filesystems, change firewall/DNS, or launch VPNs, even when invoked as root.
- Capture regression tests for strict JSON parsing, zero/overflowing sizes, default consistency, cancellation, and cleanup error propagation. Introduce test seams only at real OS/process boundaries.
- Retire the legacy host-network implementation from the product path; do not add an "unsafe compatibility" fallback.
- Done when safe unit tests run without host mutation and public claims clearly distinguish implemented, experimental, and deferred features.

### 2. Prove Offline Execution
- Implement the service ownership, Bubblewrap boundary, credential transition, and cancellation model above in disposable Debian/Ubuntu VMs before expanding presentation features.
- Build an admin-installed immutable runtime directory from pinned distro packages. Initial useful set: Bash, coreutils, find/grep/sed, a terminal editor, curl, jq, Git, Python 3, OpenSSL/CA certificates, tar/gzip, and the fixed util-linux entrypoints. Generate its inventory and digest; no session-time package installation or automatic host-tool discovery.
- Keep the root read-only. Put home, `/work`, temporary/runtime directories, and required variable state on bounded private tmpfs; inject minimal passwd/group/resolver configuration. Do not expose user secrets from the base image.
- Initial resource defaults: 1 GiB service memory maximum, 512 MiB writable workspace, and 256 tasks; validate bounds and document how to adjust them. Fail clearly on unsupported required controls, ENOSPC, or OOM rather than hanging or silently widening access.
- Offline netns has no external interface. Verify credentials/capabilities/descriptors from inside a real command, not just the supervisor's intended configuration.
- Done when a real shell/command works, cannot see host sentinel files or processes, and cannot reach IPv4, IPv6, host loopback services, or LAN addresses.

### 3. Deliver CLI Workflow
- Expose `soteria run -- COMMAND ARG...`, `soteria shell`, `soteria doctor [--json]`, `soteria config check`, `soteria version`, and `soteria cleanup SESSION_ID` for stale owned resources.
- Default to `--network=offline`; WireGuard requires explicit `--network=wireguard --profile NAME`. Execute argv directly, not through an implicit shell. Executable names refer to the curated runtime, not arbitrary host programs.
- Preserve stdin/stdout/stderr, pipes, non-TTY operation, and child status. Use a separate fresh PTY for interactive sessions, relay resize/signals, acquire a controlling terminal correctly, and restore the caller's terminal on all exits.
- Reserve exit 125 for setup/runtime/cleanup infrastructure failure; otherwise propagate the child's conventional status. If cleanup fails, report both the child result and cleanup failure and return infrastructure failure.
- Keep the TUI out of the execution/lifetime path. Initially use concise phase/error messages on stderr; optional dashboard work follows a dependable runner.
- Version the new config schema; reject unknown fields, invalid combinations, overflow, and unsafe paths. No config auto-discovery from the current directory when privileged. Show the selected path and redacted effective settings.
- `doctor` and config checks must not activate networking or mutate host configuration. Distinguish verified facts from checks requiring authorized startup. Check distro/kernel, systemd/cgroup controls, toolkit/dependency integrity, resources, and requested profile permissions.
- Start best-effort by attempting/verifying `tmpfs noswap` and `MemorySwapMax=0`. If unsupported or ineffective, warn specifically and continue with ordinary tmpfs. `noswap` does not protect heaps; cgroup limits do not cover the host frontend. Apply `LimitCORE=0` as mitigation, but report piped collectors and unknown hibernation/snapshot policy honestly. Never alter host swap/dump policy automatically.
- Keep service command lines/descriptions fixed and free of user argv/secrets. Route session diagnostics over private IPC into bounded, redacted memory buffers, not journald. Host service metadata/auditing can still persist and must be documented.
- Done when fresh users can diagnose prerequisites, launch interactive and scripted work, understand warnings, and obtain useful failure messages without the dashboard.

### 4. Add Explicit Transfers
- Define repeated `--import HOST_PATH` inputs as copied snapshots under `/work/in/<basename>`; reject name collisions. `--export HOST_DIRECTORY` copies regular file trees deliberately placed under `/work/out` after successful command completion. Stop/reap descendants before inspecting outputs, and retain the private filesystem until transfers finish. No host bind mounts, implicit home access, or automatic credential forwarding.
- Traverse/open host paths as the caller, never as root followed by chown. Transfer bytes via bounded streams to/from a worker running with dropped credentials; do not extract caller-supplied archives as root.
- Support bounded file/directory trees with normalized relative names, byte/file-count limits, and symlink-safe traversal. Reject symlinks, traversal, devices, sockets, privileged metadata, and paths outside designated roots.
- Exports use caller permissions, explicit destinations, atomic per-file publication, and no overwrite by default. Report partial multi-file export failure; do not imply the whole directory operation is transactional.
- On signal, disconnect, or failed command, default to no export and clean up disposable state. State this before use; do not promise crash recovery for ephemeral work.
- Done when realistic download/inspect/transform/export workflows work, including hostile filenames, source mutation, collisions, broken pipes, quota exhaustion, and failed exports without privileged host writes.

### 5. Add WireGuard
- Replace `internal/network/stack.go` with the structural namespace design, using maintained netlink/WireGuard control bindings and fixed operations. Never invoke `wg-quick` or execute imported profile hooks.
- Profiles are selected by validated IDs under a fixed admin-owned directory. Separate private-key credentials from readable metadata; verify ownership, permissions, parent paths, and symlink safety. Load credentials only within the service's resource boundary, never through CLI argv/environment/logs or workload mounts.
- First profile format supports one authenticated full-tunnel peer: `AllowedIPs=0.0.0.0/0`, explicit IPv4 address and DNS servers, literal initial IPv4 endpoint/UDP port, public key, and bounded MTU/keepalive. Reject hostname bootstrap, split routing, IPv6 settings, hooks, `Table`, `SaveConfig`, and arbitrary fwmarks/routes.
- Create a uniquely marked WireGuard link down in the host netns, move it into the anonymous workload netns, then configure it there. Its encrypted socket retains the host birthplace. Do not put the setup service in `PrivateNetwork=yes` before creation.
- Workload interfaces are only `lo` and WireGuard, with default IPv4 routing through WireGuard and native workload IPv6 disabled/verified. No veth, NAT, gateway namespace, host firewall flush/restore, host routes, forwarding sysctls, or host resolver replacement is needed.
- Generate the private resolver configuration from the profile. Trigger a bounded resolver probe through the workload path; require a new authenticated peer handshake and expected interface/route/DNS state before running a command. Do not treat interface-up as readiness.
- The protocol authenticates peer identity, not an immutable endpoint tuple: WireGuard may roam after authenticated traffic. Promise no plaintext workload fallback, not "zero outer IPv6 packets" or permanent endpoint pinning without additional enforcement.
- Monitor only owned runtime state. Use a 30-second network-readiness deadline and a 30-second sustained connectivity-failure grace period before stopping with an actionable error; do not classify an idle handshake timestamp alone as failure. The network boundary must remain closed independently of monitoring.
- Done when endpoint loss, interface deletion, route changes, startup failure, and reconnect cannot expose plaintext workload traffic, and host routes/firewall/resolver/sysctls remain unchanged.

### 6. Prove Reliability
- Use disposable VM integration fixtures with a controlled WireGuard peer/resolver and outer-uplink captures. Never require a commercial VPN, external IP-check service, or a developer's real firewall for tests.
- Exercise direct TCP/UDP, HTTPS/QUIC, literal IPv4/IPv6, link-local/LAN addresses, UDP/TCP DNS, and access to host sockets/services. Captures must distinguish encrypted transport from plaintext; document authenticated endpoint roaming separately.
- Inject failure at every acquisition and export stage: signals, early exits, service hangs, CLI death, supervisor SIGKILL, Bubblewrap/PID-1 death, OOM/ENOSPC, unavailable swap controls, failed tmpfs setup, and failed cleanup.
- Test Ctrl-C/Ctrl-Z, job control, EOF, terminal resize, pipes, binary output, disconnects, repeat sessions, and two isolated sessions. Assert no surviving owned processes, mounts, namespace references, links, or service state.
- Snapshot host network/resolver configuration before and after tests; unrelated or concurrently updated host configuration must survive. Cleanup must never delete resources based only on a loose name prefix.
- Fuzz config/profile parsing and transfer path handling; test forged caller identity, malicious control messages, unsafe profile ownership, and unit/resource-name injection. Run formatting, vet, race checks, Go vulnerability scanning, and runtime-package scanning. Unit tests cover deterministic failure ordering; privileged tests prove kernel behavior.
- Done when both supported host images pass the full matrix and sanitized test evidence can accompany a release. No runtime validation was performed during this planning turn.

### 7. Ship Credibly
- Package one versioned `.deb` with the engine, immutable runtime, starter, and cleanup helper. Declare actual dependencies such as Bubblewrap/systemd; remove the root installer that indiscriminately installs optional anonymity layers. Do not auto-reconfigure networking or grant privilege policy during install.
- Move from Go 1.22 to a currently supported toolchain, pin its patch release and runtime inputs, review dependency licenses, and keep a small documented dependency inventory.
- CI must separate safe PR tests from disposable privileged integrations. Pin action dependencies, minimize token permissions, and never run untrusted fork code with privileged release credentials.
- Publish version/commit/runtime digest, checksums, verifiable signatures/provenance, source-linked build instructions, and SBOMs for both Go and runtime packages. Verify reproducibility with independent clean builds before claiming it; signatures establish origin, not security.
- Add a security-reporting policy, maintainer/release policy, compatibility matrix, changelog, documented recovery, practical tutorials, and a security-claims-to-tests table. GitHub private reporting/protection settings require repository-owner action.
- Keep sessions/logs out of bug reports by default. Offer explicitly requested, reviewed/redacted diagnostics only. Maintain a vulnerability triage and runtime refresh process rather than shipping an unmaintained toolkit.
- Roll out offline development builds first, then Linux alpha with WireGuard, then a tested beta. Stable labeling requires published limitations, clean-install/upgrade/uninstall evidence, failure-test results, and independent review of privilege, transfer, isolation, and networking boundaries. Do not describe the project as audited without an actual published review scope.

### 8. Stage Other Platforms
- Before macOS support, add/test Linux arm64 runtime artifacts and engine coverage; Apple Silicon guests need arm64. Keep Linux-specific code behind build boundaries without inventing a general plugin framework now.
- Introduce a narrow versioned CLI/engine protocol when the second backend is implemented: argv, network/profile ID, resource limits, transfer streams, terminal events, warnings, and result. The host CLI must not pretend it can enforce guest Linux controls natively.
- Prototype a dedicated disposable Linux VM using an established manager such as Lima. Start with Apple Silicon; add Intel macOS only after validation. Disable automatic home mounts, host-agent/credential forwarding, clipboard integration, unnecessary port forwarding, and VM reuse/snapshots.
- Verify signed guest/runtime inputs, volatile guest working state/logs, VM startup and teardown, authenticated guest control, interrupted sessions, and destruction of the session's VM resources. Document host VM state, disks, swap, and memory-capture risks separately from guest tmpfs; deletion is not secure erasure. Warn-and-continue memory policy still applies.
- Gate public macOS support on the same workload-boundary/network tests plus host-side persistence and crash tests. An ordinary Lima default configuration is not the privacy profile.
- Evaluate one dedicated Windows VM path, such as Hyper-V or QEMU/WHPX, after the macOS backend proves the engine protocol. Validate supported editions, privilege/install needs, host-path semantics, and cleanup before advertising support. Do not present shared default WSL2 with automount/interop as equivalent isolation.
- Exact macOS/Windows manager versions, Windows edition coverage, and VM memory-retention guarantees are explicitly later feasibility decisions, not blockers or promises for the Linux release.

## Change Boundaries
- Refactor existing `cmd/soteria/main.go`, `internal/config`, `internal/session`, `internal/filesystem`, `internal/network`, and their tests. Reuse monitoring event presentation where useful, but replace host process-name scanning with owned process/interface state.
- Add only the necessary runner/worker, transfer, profile, runtime-packaging, disposable-VM test, and CI boundaries. Keep OS operations out of CLI/TUI code; do not retain the old insecure execution path.
- Replace example configuration and usage alongside implementation. Explicitly reject legacy schemas with migration instructions: existing OpenVPN profiles cannot silently become WireGuard profiles, and legacy kill-switch booleans must not weaken the new invariant.
- Do not switch branches, commit, push, change hosted settings, or publish packages as part of implementing this plan without separate authorization. Work with unrelated existing changes rather than reverting them.

## Completion Gates
- Usable: a clean supported machine can install, diagnose, run shell/commands, transfer work, understand warnings, and recover stale resources without reading the source.
- Safe: kernel-level tests prove the execution and network boundaries and cleanup behavior. Memory limitations remain visible even when startup is allowed.
- Trusted: public claims map to tests and limitations; releases are attributable and reproducible where demonstrated; dependencies and security reports have an ongoing maintenance path.
- Practical: first-release scope stays Linux/offline/WireGuard/CLI. New protocols and platforms enter only after they preserve the contract and pass equivalent evidence gates.

## Design References
- WireGuard namespace/socket birthplace: https://www.wireguard.com/netns/
- Bubblewrap policy/limitations and options: https://github.com/containers/bubblewrap and https://github.com/containers/bubblewrap/blob/main/bwrap.xml
- Credential reduction: https://man7.org/linux/man-pages/man1/setpriv.1.html
- Service/process ownership: https://www.freedesktop.org/software/systemd/man/252/systemd.service.html and https://www.freedesktop.org/software/systemd/man/252/systemd.kill.html
- Mount and swap controls: https://www.freedesktop.org/software/systemd/man/252/systemd.exec.html and https://www.freedesktop.org/software/systemd/man/252/systemd.resource-control.html
- Tmpfs and dump limitations: https://man7.org/linux/man-pages/man5/tmpfs.5.html and https://man7.org/linux/man-pages/man5/core.5.html
- Piped dump collectors: https://www.freedesktop.org/software/systemd/man/252/coredump.conf.html
- Validate all referenced behavior against the exact distro-packaged versions used in release tests; upstream documentation is design evidence, not a substitute for execution tests.

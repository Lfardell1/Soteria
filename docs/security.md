# Security Boundaries

## Contract And Exclusions

Soteria's intended contract has two independently testable properties: disposable **working files** use private bounded tmpfs rather than ordinary host storage, and **workload networking** is constrained to offline or the selected full-tunnel WireGuard mode. The public, maintained runtime is disk-resident and read-only. These statements are implementation goals with explicit runtime checks, not a blanket verdict that a development build is secure, anonymous, audited, or VM-proven.

Trust the host kernel, root administrator, hypervisor, distro signing keys/package maintainers, runtime build process, selected VPN provider, and familiar commands you choose to run. The first release is not intended for hostile code or an attacker controlling the host. Namespace isolation is not a defense against a malicious kernel/root, kernel exploits, or every side channel.

Excluded from erasure/privacy guarantees: host terminals and shell history, caller-side/stdout buffers and redirections, audit/sudo/systemd metadata, observations of the public CLI argv or process list, remote logs, browser/account identifiers, global traffic correlation, frontend heaps, swap/dump/hibernation/snapshot capture, and physical RAM remanence. Tmpfs teardown is not physical zeroing or forensic secure deletion. No GUI/browser, Tor, arbitrary VPN stack, native macOS/Windows isolation, or shared-default-WSL privacy profile is provided.

No automatic home/credential/agent/socket sharing, telemetry, automatic update checks, hosted health service, or persistent session log is requested by default. Required WireGuard readiness probes use the configured peer/resolvers; user commands can generate their own remote traffic and logs. An explicit import can itself contain credentials, and an explicit export is persistent by design.

## Execution Roles

The public `/usr/bin/soteria` uses `internal/client` and `internal/protocol`, not a root-capable CLI dispatcher or the retired session frontend. Its only sudo command is `/usr/libexec/soteria/soteria-starter`, with no starter arguments. The starter authorizes fixed `/usr/libexec/soteria/soteria-engine __worker` and `__cleanup` service commands. The same engine re-execs fixed private `__namespace` and `__transfer` roles; user argv never selects a root service command.

Inside the curated root `/usr/lib/soteria/runtime`, fixed `setsid`/`setpriv` wrappers precede **non-root** `/usr/libexec/soteria-entry UID GID -- EXEC ARG...`. This separate static executable is included at build time, root-owned 0555 when installed, and hashed in the runtime inventory. It verifies the credential/capability/descriptor/environment/mount state and participates in the private launch-proof handshake before direct exec. It is not mounted from a host helper directory, a caller program running as root, or a new PID-1 runtime. Bubblewrap supplies the PID namespace/reaper; its monitor exiting alone does not prove descendants stopped. The owned init/pidfd and worker subreaper barrier must establish quiescence before export or workspace teardown. These mechanisms still require distro/kernel VM proof.

The transient service requests `StandardOutput=null` and `StandardError=null`, fixed command lines/descriptions without user argv, and private bounded/redacted IPC diagnostics. This avoids deliberately sending session diagnostics to journald, not all host metadata. Unit names/IDs, times, authorization, failures, resource accounting, caller argv, audit events, and administrator monitoring may persist under host policy.

## Failures And Retention

Missing required namespaces, tmpfs, non-root credential reduction, safe immutable toolkit, memory/task controls, or chosen network state must fail closed. Cancellation prevents new resources and normal cleanup must terminate descendants before authorized exports. Systemd owns descendant cleanup if the supervisor dies; cleanup errors are infrastructure failure, not a green session result. A lifeline disconnect is separate from ordinary workload stdin EOF.

The best-effort memory policy is intentionally different. Unsupported/unverified tmpfs `noswap` and service `memory.swap.max=0` produce specific warnings and continue with ordinary tmpfs. `noswap` protects only tmpfs pages, not heaps. A cgroup swap limit does not cover the host frontend. `LimitCORE=0` does not disable piped collectors, and pre-exec dumpability settings do not establish a durable no-dumps policy. With systemd-coredump, `Storage=none` alone still permits processing the process image; preventing that also requires `ProcessSizeMax=0`. **Neither setting removes crash metadata**, and neither establishes hibernation/snapshot/host-collector policy. Administrators must assess the exact host independently; Soteria never changes global swap/dump policy automatically.

The runtime manifest uses the exact `toolkit.Inventory` version/build/files encoding and digest. Verification checks root ownership, non-writable modes, safe real ancestors, complete file hashes including the entrypoint and embedded archive lock/snapshot inputs, internal relative symlinks, no capabilities/special objects, a useful pinned baseline, and excluded secret paths/PEM private keys. This is integrity/inventory checking, **not a signature or proof that arbitrary secret formats are impossible**. A trusted administrator can replace both contents and inventory. Signed apt resolution, exact archive locks, actual license-file inventories, review, scans, release signatures, and independent builds address different supply-chain questions; none has a fabricated pass when unavailable.

## Claims To Tests

| Intended property | Implemented evidence/check | Current evidence limit |
| --- | --- | --- |
| Strict versioned config and bounded resource values | `internal/config` unit/fuzz tests; config check | Parser tests do not prove applied kernel limits |
| Config alone cannot enable online sessions; shell requires a TTY | `internal/cli`/`internal/client` tests for explicit flags and terminal selection | Frontend tests do not prove the authorized engine/kernel boundary |
| Runtime/entry inventory is complete, immutable, internal-link-only, and secret-restricted | `internal/toolkit` verifier/generator and `cmd/soteria-runtime` exact-input/CA tests | Synthetic files only; signed distro resolution, installed entry and actual tools/libraries need VM validation |
| Transfers reject traversal/symlinks/special metadata and publish as caller | `internal/transfer` unit/fuzz tests and session handoff checks, including empty streams and entry quotas | Needs real privilege-boundary, `O_TMPFILE` support, hostile-tree/mutation, partial-export VM tests |
| Nonzero real/effective/saved IDs, no groups/capabilities/extra FDs, `no_new_privs` | Credential wrapper/entrypoint checks plus `scripts/integration/workload-probe.py` assertions | Private unprivileged process tests are not proof of the root-to-caller transition; offline VM fixture unrun |
| Read-only root, private tmpfs, no host sentinel/namespace access | Runtime setup checks and the imported workload probe | Needs both target images, resource failure cases, and process/mount leak evidence |
| Offline IPv4/IPv6/host-loopback/LAN/UDP restriction | Only-lo structural check and controlled host listeners in offline smoke | Smoke fixture unrun; not the complete packet-capture matrix |
| WireGuard handshake/resolver readiness, no plaintext fallback, no host network reconfiguration | `internal/network` tests and namespace design | Full controlled-peer/resolver, outer capture, loss/delete/route/reconnect/roaming matrix not implemented or run by this packaging work |
| Binary pipes, child status, no failed-command export, isolated repeat session, Ctrl-C/PTY restore | Offline smoke fixtures | Unrun; Ctrl-Z/job control, resize transitions, disconnect/death and concurrency matrix remain |
| Descendant quiescence and independent child/cleanup facts, with exit 125 on infrastructure failure | Lifecycle/protocol/entry/subreaper tests; unit/cgroup/runtime-directory snapshots in smoke | Does not prove all acquisition/crash/OOM/ENOSPC/PID-1/kill windows or absence of every leaked namespace handle |
| Host routes/firewall/resolver/sysctls remain unchanged | Read-only before/after snapshots in a quiet disposable VM | No live VM observation in this change; snapshots are never flushed/restored |
| Dependency issues are discoverable | Separate govulncheck and runtime CycloneDX/Grype workflows | Workflows/scans are not claimed to have run; missing DB/scanner is not a pass |
| VM evidence is tied to real immutable inputs | `packaging/vm/images.lock.json`, strict lock helper and gated VM preflight | Both records are explicitly pending; a declared marker is not an attestation or a passed matrix |
| License/source obligations are inspectable | Per-package copyright and per-linked-module license-file hash inventories | Missing files remain missing; names/hashes/SBOMs do not classify terms or complete legal review |
| Artifacts have attributable origin and reproducible contents | Checksums/SBOMs and unsigned build-record scaffolding | No signatures, trusted provenance, independent rebuild comparison, or publication supplied |

Ordinary unit/race/vet checks must never mount filesystems, activate a VPN, or alter a live firewall even if accidentally invoked as root. Privileged evidence must come from [guarded disposable VMs](testing.md), never from a developer's real host. VM, package, scan, and review results should be published with exact scope, source commit, image digest, package lock, kernel/tool versions, and remaining failures rather than a single unsupported security score.

# Testing

## Safe Checks

`make test`, `make vet`, `make race`, and `make check` are unprivileged developer/PR checks with Go 1.27.3. They do not select integration fixtures, start sessions, install packages, bring up WireGuard, mount tmpfs, or change DNS/firewalls. CI explicitly rejects UID 0. Kernel behavior cannot be proved by mocks, command construction, or a unit-test pass.

`make helper-test` runs pure image-lock/schema tests; `make script-check` checks shell syntax and parses Python with `ast`, without executing integration code. Python 3 and Make must be installed separately. The runtime generator/lock/CA/entry/SBOM/license-file tests use synthetic temporary inputs only. Their fixture versions, addresses, hashes, and example.invalid URLs are parser data, not release pins, runtime artifacts, audits, or VM evidence. Entry/subreaper tests using ordinary private child processes do not prove the privileged launch chain.

## Opt-In VM Smoke

`scripts/integration/offline-smoke.sh` **has not been run by this change**. It is excluded from normal tests and permits only a non-root user in a detected VM, not a container/physical host, with booted systemd/cgroup v2, installed root-owned public/starter/engine binaries and immutable runtime entry, tmpfs fixture storage, explicit opt-in, a reviewed image lock, and a real root-owned marker. Root alone never selects integration. The guard prevents accidents; it is not secure proof that a machine is disposable.

Externally provision a fresh Debian 13 amd64 or Ubuntu 24.04 amd64 VM. Independently verify and record the exact image source URL, SHA256/signature, booted kernel, systemd/Bubblewrap versions, distro package inventory, runtime package lock/digest, and Soteria commit. **No tested image digest is supplied yet; neither target is a passed matrix entry.** Provision an ordinary test account with existing, interactive administrator sudo authorization and no personal credentials or forwarded host directories/agents.

`packaging/vm/images.lock.json` intentionally has **pending, null** image and publisher-verification records for both targets. Preflight refuses them. Before any VM run, review a real immutable HTTPS image URL and SHA256, publisher signed-checksum/signature URLs, independently verified signing-key fingerprint, UTC verification time, and SHA256 of the retained signature-verification record. Only then replace that target's pending record with real data and status `pinned`. Never fill in plausible hashes, moving `current`/`latest` URLs, or successful-test labels. The strict `scripts/check-image-lock.py` validates recorded fields and the exact declared digest; it does not download images, verify signatures itself, measure a running VM, or mark the VM matrix passed. Both the image download and publisher signature verification remain explicit operator work.

Install the candidate Soteria package explicitly. Test-only host dependencies are Python 3, iproute2, nftables, iptables (for read-only `iptables-save`), and normal systemd/util-linux/coreutils tools. They are not runtime host dependencies automatically installed by a smoke target. The fixture reads host network policy using fixed sudo read-only commands but never changes or restores it.

Only in that disposable VM, an administrator records a marker matching the independently checked image digest. For example, as the non-root test account:

```sh
export SOTERIA_VM_IMAGE_SHA256=THE_ACTUAL_64_LOWERCASE_HEX_DIGEST
export SOTERIA_EXPECTED_COMMIT="$(git rev-parse HEAD)"
printf 'soteria-disposable-vm-v1\nimage_sha256=%s\n' "$SOTERIA_VM_IMAGE_SHA256" > /dev/shm/soteria-vm-marker
sudo install -o root -g root -m 0444 /dev/shm/soteria-vm-marker /etc/soteria/disposable-vm
rm /dev/shm/soteria-vm-marker
sudo -v
SOTERIA_DISPOSABLE_VM=DISPOSABLE_VM_ONLY SOTERIA_VM_TARGET=debian13-amd64 \
  scripts/integration/offline-smoke.sh
```

Use `ubuntu24.04-amd64` only on that matching VM. The digest must match the reviewed target record in the lock and the root-owned marker. Both are **declared** image identity, not disk measurement or cryptographic attestation. The placeholder above is refused; there is no skip-lock switch. Do not run the frontend/fixture via sudo, add permissive sudoers rules, or use a root shell to work around failures.

The fixture uses an explicit synthetic version-1 config on tmpfs, so administrator default config cannot silently change its limits. Inputs/sentinels, fake agent/listening sockets, and export destinations are synthetic. Assertions inspect actual workload IDs/groups/capability sets/`no_new_privs`, FDs/environment, namespace differences, read-only root, bounded tmpfs paths, hidden sentinels, only-lo networking, controlled loopback denial, IPv4/IPv6 external/LAN/link-local and UDP-route denial, import/export, binary pipes/stdin EOF, child status, no failed-command exports, fresh sessions, PTY size/Ctrl-C/restoration, disappearance of unit/cgroup/runtime-directory names, and unchanged host routes/firewall/resolver/forwarding settings. This is not a complete census of every process, mount, or anonymous namespace handle. NFT counter values are ignored; concurrent host policy edits fail the test, never trigger snapshot restore.

It does not perform the complete privileged failure/network matrix. Success prints a small synthetic-only summary; raw session output, profiles, keys, home directories, and diagnostics are not automatically uploaded. Failure leaves ownership evidence for inspection and destroys no resource based on a loose prefix. Destroy the VM and its disks after each run, including failed runs. Deletion is not secure erasure or proof that host/hypervisor storage retained nothing.

The manual workflow requires the exact confirmation, repository default branch, owner opt-in `SOTERIA_VM_INTEGRATION_ENABLED=true`, target-specific runner label, and a protected `disposable-vm` environment configured by the owner. Target variables are `SOTERIA_DEBIAN13_VM_IMAGE_SHA256` and `SOTERIA_UBUNTU24_VM_IMAGE_SHA256`; the selected value must also match the checked-in lock. No hosted setting, approval policy, runner, or validated pin is supplied here. The **externally provisioned ephemeral** VM must be destroyed by its owner after one job; the workflow cannot prove or perform that destruction. Never attach personal/persistent or privileged runners to PR/fork code.

## Controlled Network Gate

Only the offline smoke driver exists. There is no automated WireGuard fixture, outer packet-capture driver, commercial-VPN dependency, or full failure-matrix pass. A future/manual controlled fixture must meet these requirements before a network claim is released:

1. Provision a separate operator-controlled WireGuard peer, private resolver, and synthetic TCP/UDP/HTTPS/QUIC endpoints. Record exact public topology/tool versions and image/profile identity without publishing private keys. Never substitute commercial VPN services, public IP-check pages, or a personal firewall.
2. Capture the test VM's actual outer uplink independently of its workload namespace. Use synthetic payload markers and controlled endpoint/resolver addresses so plaintext is distinguishable from encrypted outer UDP. Review captures locally; they are intentional metadata artifacts, not default session logging or automatically uploaded diagnostics.
3. Exercise successful DNS over UDP/TCP and literal IPv4/IPv6, host loopback/services/sockets, LAN/link-local, peer loss, readiness failure, interface deletion, route edits, reconnect, and authenticated endpoint roaming. Inject changes only in explicitly owned disposable fixture resources. No host route/firewall/resolver/forwarding setup or restore belongs in ordinary tests or an installer.
4. Bind observations to the exact source, image lock, runtime digest/archive lock, kernel/Bubblewrap/WireGuard versions, captures, host before/after policy snapshots, and residual-resource checks. A handshake timestamp alone is not ongoing connectivity proof. Keep every unexecuted case pending and discard the disposable VMs after testing.

## Remaining Matrix

| Gate | Debian 13 amd64 | Ubuntu 24.04 amd64 |
| --- | --- | --- |
| Reviewed immutable VM image/publisher verification lock | Pending | Pending |
| Real pinned runtime build and package scan/license review | Not established | Not established |
| Installed offline smoke | Not run by this change | Not run by this change |
| Clean install, upgrade, uninstall, package ownership/dependencies | Not run | Not run |
| Controlled WireGuard peer/resolver and outer-uplink captures | Not run | Not run |
| TCP/UDP, HTTPS/QUIC, IPv4/IPv6, UDP/TCP DNS, host sockets/services | Full matrix pending | Full matrix pending |
| Peer loss, interface deletion, route edits, readiness failure, reconnect/roaming | Pending | Pending |
| Failure at every acquisition/export/cleanup stage | Pending | Pending |
| SIGINT/SIGTERM, CLI death, supervisor/PID-1 SIGKILL, hangs, OOM/ENOSPC | Pending | Pending |
| Unavailable swap controls, failed tmpfs/resource setup, failed cleanup | Pending | Pending |
| Ctrl-Z/job control, resize transitions, disconnect, repeated/concurrent sessions | Full matrix pending | Full matrix pending |
| Source mutation, hostile filenames/trees, quota, broken pipe, partial export | Full matrix pending | Full matrix pending |
| Independent clean rebuild comparison and boundary review | Pending | Pending |

WireGuard validation must use a controlled peer/resolver and captures that distinguish encrypted outer transport from plaintext, not a commercial VPN or external IP-check page. A handshake timestamp alone is not an ongoing connectivity verdict. Test forged caller identity/control packets/profile ownership and all cleanup ownership windows. Record unavailable tests honestly rather than substituting host-root testing or treating this smoke fixture as the full plan.

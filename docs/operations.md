# Operations

## Configuration And Authorization

The public CLI reads an explicitly selected clean absolute `--config` path; otherwise it reads `/etc/soteria/config.json` if it exists, or explicitly reports built-in defaults. An existing invalid/unreadable default config is an error. It never searches the current directory, discovers host tools/credentials, or reads OpenVPN/wg-quick configuration. `soteria config check [--config ABS]` and `soteria doctor [--json] [--config ABS]` are read-only, with no authorization or network activation. Effective settings identify the selected source and redact the profile.

`run` and `shell` always select offline networking unless **both** `--network=wireguard --profile NAME` are explicitly present, even if the selected config requests WireGuard. `--profile` is invalid with offline mode; omit it rather than passing an empty flag. `run -- COMMAND ARG...` executes argv directly. `shell` requires terminal stdin/stdout and selects `/bin/bash --noprofile --norc -i`; scripted Bash must be requested through `run` instead.

Defaults are `memory_max=1G`, `workspace_size=512M`, `tasks_max=256`, and transfer limits `max_bytes=256M`, `max_files=10000`. `max_files` counts **all transferred entries, including directories**. Memory is bounded to 128M..64G, workspace to 16M..32G strictly below memory, tasks to 32..4096, and entry count to 1..100000. Transfer bytes must fit in the workspace. K/M/G are binary units; zero/overflow are rejected. A smaller workspace/quota may cause ENOSPC/transfer failure, never disk fallback.

Run `/usr/bin/soteria` as a non-root user. Its `internal/client`/`internal/protocol` path invokes only `sudo -- /usr/libexec/soteria/soteria-starter`, with **no arguments to the starter**, using existing administrator policy and authenticated private IPC. Only `/usr/libexec/soteria/soteria-engine __worker` and `__cleanup` are fixed root service commands; the same engine owns fixed namespace/transfer re-execs. The separate `/usr/libexec/soteria-entry` is inside the curated root and runs only after credential reduction. Do not invoke internal `__*` roles, sudo a checkout, grant `NOPASSWD: ALL`, add root shell wrappers, or disable isolation checks. Packaging creates no authorization policy or daemon.

Legacy configs are rejected. Replace host-copy filesystem settings, monitoring stacks, OpenVPN/Tor/DNSCrypt/Proxychains sections, and kill-switch booleans with version 1 limits and either offline mode or a separately provisioned WireGuard profile. There is no automatic credential migration, hook execution, or unsafe legacy backend.

## WireGuard Profile

Profiles are selected by a 1..48-character ID: lowercase alphanumeric first, then lowercase alphanumeric, `_`, or `-`. The only lookup location is `/etc/soteria/profiles/NAME.json` and `/etc/soteria/profiles/NAME.key`. Real parent directories must be root-owned, non-group/other-writable, and have no special mode bits. No symlink components are accepted. Use root:root 0755 for the profile directory, root:root 0644 (or 0600) for metadata, and **0600** for the private key; files must be regular with one link. Do not store them in the source checkout or runtime.

Every field in this version-1 metadata object is required. Replace the deliberately unusable public-key placeholder with the peer's canonical 44-character base64 WireGuard public key:

```json
{
  "version": 1,
  "address": "10.70.0.2/32",
  "dns": ["10.70.0.1"],
  "endpoint": "192.0.2.10:51820",
  "public_key": "REPLACE_WITH_THE_REAL_PEER_PUBLIC_KEY",
  "private_key_file": "office.key",
  "allowed_ips": ["0.0.0.0/0"],
  "mtu": 1380,
  "keepalive_seconds": 25
}
```

For ID `office`, `private_key_file` must be exactly `office.key`, not a path. That separate credential contains exactly a canonical nonzero 44-character base64 private key with at most one trailing newline, not a wg-quick file or JSON. Load it only inside the authorized service resource boundary; do not paste it into command lines, environment, reports, or this example. Provision files through an administrator-reviewed local process, not a curl-to-shell installer.

The address must be usable literal IPv4 with prefix length 1..32. DNS must have one to three distinct usable literal IPv4 resolvers, not the workload's own address. Endpoint must be a usable literal IPv4 address with UDP port 1..65535. MTU is 1280..1420; keepalive is 0..120 seconds. Endpoint/DNS hostnames, split AllowedIPs, IPv6 settings, extra peers, hooks, `Table`, `SaveConfig`, arbitrary fwmarks, and unknown/duplicate/missing fields are rejected. Documentation addresses above are examples, not a working VPN service.

```sh
soteria run --network=wireguard --profile office -- curl https://example.com/
```

The design creates WireGuard in the host namespace and moves the interface into the workload namespace, preserving the encrypted socket's birthplace. It requires an authenticated handshake and private resolver readiness before running user commands. It does not flush host firewall rules, enable forwarding, replace host DNS, or use veth/NAT/wg-quick. Native workload IPv6 is disabled; authenticated peer endpoint roaming and outer transport IPv6 are separate WireGuard behavior. Full loss/reconnect/capture tests remain release gates.

## Transfers And Results

`--import HOST_PATH` is a caller-opened snapshot under `/work/in/<basename>`. The import stream, terminal frame, and EOF are required **even for an empty import set**. Repeated imports cannot collide; no host bind mount, implicit home, or agent/credential forwarding is offered. The bounded stream rejects symlinks, devices, sockets, privileged metadata, traversal, and unsafe paths. Mutable source files can fail transfer; this is not a live shared directory.

`--export HOST_DIRECTORY` publishes regular files deliberately put under `/work/out`, only after successful command completion and descendant shutdown. The destination must already exist and be caller-authorized; an empty directory is convenient but no broad host path is given to root. Existing transferred entries are never overwritten or implicitly merged. Linux anonymous `O_TMPFILE` and no-replace proc-FD publication must be supported by the destination filesystem, or export fails closed. A file is published atomically, but multi-file export may partially succeed: published files/created directories remain and are reported, not rolled back. Inspect the destination before retrying. Failure, signal, lifeline disconnect, or setup failure defaults to no export. Crash recovery of ephemeral state is not promised.

Exit 125 means infrastructure/setup/runtime/export/cleanup failure. Otherwise expect conventional child status. Child-start/exit, infrastructure error, cleanup error, and filesystem/swap/dump/network/cleanup facts are separate result fields. When cleanup fails the CLI reports both the child result and cleanup failure and returns 125, including when the child succeeded. Error messages/stdout can contain user-chosen data; host redirection, terminal recording, CI logs, and bug reports are disclosure boundaries.

## Warnings And Recovery

Tmpfs is mandatory. `noswap` and cgroup `MemorySwapMax=0` are attempted/verified independently and warn specifically when unavailable. Those warnings do not make namespaces, credential reduction, memory/task containment, or networking optional. `LimitCORE=0` is only a mitigation and does not disable piped collectors. For systemd-coredump, `Storage=none` alone still allows image processing; preventing it also requires `ProcessSizeMax=0`. Neither removes crash metadata. Soteria never changes host dump/swap/hibernation/snapshot policy automatically, and the uncontained host frontend remains a separate retention risk.

If startup fails, run read-only doctor, inspect the exact reported prerequisite, and keep the host experimental. Do not fix a missing capability/control by running a caller-selected command as root or binding a host directory into the workspace. If a stale ID was reported, use only that exact 32-lowercase-hex ID:

```sh
soteria cleanup 0123456789abcdef0123456789abcdef
```

The ID above is an example, not a wildcard. Cleanup must verify ownership/recorded identity and refuse unknown or replaced resources. Do not delete `/run/soteria-*`, kill process-name matches, flush/restore a firewall snapshot, or remove similarly named WireGuard links. Missing/corrupt ownership evidence requires administrator inspection, not guesswork. A failed disposable test VM should be destroyed rather than repaired by prefix deletion.

The service sets stdout/stderr to `null`; session diagnostics use private bounded/redacted IPC, not journald. This does not suppress host systemd/sudo/audit metadata, unit IDs/times/failures, public CLI argv observation, or administrator recording. Fixed service commands/descriptions have no user argv, but the host can still observe its user processes.

Before uninstall/upgrade, stop sessions and verify exact owned units have finished. There are no package maintainer scripts to kill unknown processes, remove administrator profiles, or change networking. Package removal is not session erasure or permission to delete unrelated policy. Clean install, upgrade, uninstall, forced death, and stale recovery on both exact target images remain release gates.

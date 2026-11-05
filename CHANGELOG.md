# Changelog

## Unreleased

Experimental Linux implementation and delivery work. No stable release, completed VM matrix, built runtime/package, independent audit, or reproducibility evidence is implied by this entry.

- Replace the old anonymity/forensic-erasure claims with a trusted-host disposable-workspace contract and explicit limitations.
- Document the offline-first CLI, deliberate imports/exports, restricted administrator WireGuard profiles, diagnostics, resource limits, and ownership-checked recovery.
- Add an explicit disposable runtime builder using signed pinned Debian/Ubuntu snapshots, complete exact package/archive locks, immutable file inventory generation, and runtime verification.
- Reconcile five separate builds: public CLI, fixed argument-free starter, root engine, trusted non-root runtime entry, and build-only inventory utility. The public CLI uses the new client/protocol; the entry is copied inside the curated root and inventoried before installation.
- Add unprivileged developer targets, a checksum-pinned official Go 1.27.3 downloader, and root-normalized development `.deb` construction requiring a real explicit runtime and exact archive lock. No implicit sudo execution, package installation, network setup, or publication is performed; retire the host-mutating installer.
- Add pinned-action unprivileged CI, separate module/runtime vulnerability workflows, unsigned manual build evidence, and an explicitly opt-in disposable-VM offline smoke fixture.
- Bind runtime inventories to the exact embedded package/archive lock, snapshot sources, separate entry hash, and preserved public CA bundle. Add per-binary CycloneDX and actual license-file/copyright inventories with missing data and human review explicitly pending.
- Add immutable VM image-lock records that are intentionally pending with null pins until real publisher verification is available; guarded offline smoke refuses pending inputs. Controlled WireGuard/capture and full failure/terminal/transfer matrices remain unimplemented or unrun, not passed.
- Document fixed `/etc/soteria/config.json` selection else built-ins, mandatory explicit WireGuard flags, TTY-only shell, directory-inclusive transfer quotas, `O_TMPFILE` requirements/partial exports, and independent child/cleanup facts with infrastructure exit 125. Document piped-core and host-metadata limits without changing host policy.
- Keep checksums/build records explicitly unsigned. Signing/trusted provenance, scanner/license review, clean-install/upgrade/uninstall, full VM validation, independent rebuild comparisons, and boundary review remain required.
- Keep macOS/Lima, Linux arm64, and Windows backends unimplemented and unsupported rather than inferring portability from Unix compatibility.

# Security Policy

Soteria is experimental. No audited release, validated host matrix, secure erasure, anonymity, or hostile-code containment is claimed. The only initial targets are Debian 13 and Ubuntu 24.04 amd64 with systemd and cgroup v2, pending the documented VM gates. There is not yet a stable/security-maintained release series or a promised response SLA.

## Report Privately

If GitHub private vulnerability reporting is enabled, use:

https://github.com/Lfardell1/Soteria/security/advisories/new

Repository owners must enable and maintain that channel; this document does not assert that the hosted setting is enabled or monitored. If it is unavailable, open an issue asking for a private security contact **without** an exploit, session data, credentials, profile contents, private keys, or sensitive logs. No unverified maintainer email is supplied here.

Include the source commit/version, declared target/kernel, affected boundary, minimal synthetic reproduction, expected/actual behavior, and whether the reproduction ran in a disposable VM. Keep diagnostics minimal and explicitly reviewed/redacted. Never run a privileged proof of concept on a personal or production host to produce a report.

## Triage And Maintenance

- Prioritize privilege/authentication bypasses, host-file access, plaintext-network fallback, credential/descriptor leaks, unsafe transfer publication, and surviving session resources.
- Reproduce with synthetic data in fresh disposable target VMs; identify source, exact reviewed VM image lock, runtime digest/archive lock, installed role paths, and prerequisites without requesting private keys or session logs. Pending image inputs are not validated targets or successful tests.
- Review code, Go vulnerability results, runtime-package findings, distro advisories, dependency licenses, and full failure-path tests before a candidate fix is labeled release-ready.
- Refresh pinned runtime snapshots and the complete archive/version lock together. Preserve both scan results and the triage decision; unavailable scanners or databases are a missing gate, never a clean result.
- Treat actual license-file/SBOM inventories as review inputs, never legal clearance. Preserve missing-file/unknown-package findings and obtain a real license/source-obligation review before redistribution is labeled ready.
- Publish an advisory and changelog entry for a confirmed vulnerability when disclosure is coordinated. Distinguish a workaround, a code fix, and the target images actually verified.

Source/package protections, private reporting, signing identities, protected release environments, and ephemeral runner policy require repository-owner action. No hosted settings, credentials, publication, or branch rules are configured by this change.

The [security boundary](docs/security.md), [test limitations](docs/testing.md), and [release gates](docs/releasing.md) are part of the product contract. A manifest digest authenticates neither an administrator nor a build; a VPN does not authenticate the host; tmpfs teardown does not erase prior host storage or RAM capture.

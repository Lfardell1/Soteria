# Releasing

## Current Automation

All delivery remains experimental. No commit, push, hosted-setting change, artifact publication, signing operation, completed audit, or VM run is authorized or claimed by this implementation.

- `ci.yml` selects unprivileged Go 1.27.3 format/shell/helper/unit/vet/race checks and all five binary builds on PRs/main pushes, with read-only contents permissions, no persisted checkout credentials, secrets, release identities, or privileged self-hosted runners. Ordinary tests never select integration, including under root.
- Its independent govulncheck job runs the pinned `golang.org/x/vuln/cmd/govulncheck@v1.1.4`. The current advisory database is intentionally not frozen; retain its date/version/result and triage findings. Scanner incompatibility, timeout, or DB failure blocks the scan gate.
- `runtime-scan.yml` is manual-only and scans a deliberately selected, hash-checked public CycloneDX runtime package SBOM with pinned Grype 0.121.1, fetched as a binary only after a fixed SHA256 check. It requires an actual database update and retains tool/database identity. It neither scans a guessed host runtime nor proves that an SBOM came from a release artifact. Check source/manifest/lock correspondence independently. Unknown/missing distro/package matches need triage, not an assumed clean result.
- `integration.yml` is manual/default-branch-only, gated by owner opt-in and the reviewed image lock on a target-labeled, externally provisioned disposable VM, never PR/fork code. Both image records are pending, so preflight currently refuses execution. The owner must configure environment approvals and one-job runner destruction; the workflow does neither and implies no passed matrix.
- `release.yml` is manual/default-branch-only and produces **unsigned CLI-only development build evidence**, plus hashes/SBOMs/license-file inventories of the other actual builds. It has no release/package-publishing permissions, OIDC signing identity, trusted provenance attestation, or release-publication step. Workflow and local tooling refuse stable-looking version labels. A CLI archive is not an installable runtime or `.deb` release.

Action source pins are recorded against these release references, not represented as third-party audits:

| Action | Exact commit | Source |
| --- | --- | --- |
| actions/checkout v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` | https://github.com/actions/checkout/releases/tag/v4.2.2 |
| actions/upload-artifact v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | https://github.com/actions/upload-artifact/releases/tag/v4.6.2 |

Go comes directly from `https://go.dev/dl/go1.27.3.linux-amd64.tar.gz` through `scripts/download-go.sh`, with fixed SHA256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40` checked before extraction. There is no moving setup-script/toolchain selector or automatic version upgrade.

The Grype Linux amd64 tarball is pinned to SHA256 `bc3ea3f9e6fd56ac781c08c6c5e614271b79f438200757f6932085c19b0a4657`, checked against the official [v0.121.1 release checksum asset](https://github.com/anchore/grype/releases/download/v0.121.1/grype_0.121.1_checksums.txt). The workflow extracts only `grype` after checking the hash; it never executes a downloaded shell installer. Checking that published checksum is input verification, not a vulnerability scan, audit, or promise that a release asset can never be replaced. Pinned wrappers must not fetch unpinned downstream executable code.

A pin is source identity, not a completed third-party audit. Review updates, transitive downloads, advisories, runner images, and toolchain availability before changing it. `ubuntu-24.04` is the hosted CI runner label, not an exact supported-VM image or reproducibility input.

## Evidence Generation

```sh
make evidence VERSION=0.1.0-alpha.1
```

This writes `dist/evidence/` only after the five real separate binaries build: a public-CLI-only tarball, hashes and per-binary linked-Go CycloneDX SBOMs (actual compiler stdlib/module versions), actual license-file inventories, the current VM input lock, `SHA256SUMS`, an explicitly **unsigned local build record**, and `EVIDENCE-STATUS.txt`. The record captures commit, dirty-checkout status, required toolchain/archive hash, target, epoch, optional runtime digest, and missing gates. A dirty record does not identify a clean source tree. It is **not SLSA provenance, a signature, reproducibility evidence, or an attestation that VM tests passed**.

To include a separately built runtime's verified staging inventory/SBOM/license inventory, select both `RUNTIME_DIR` and the exact `PACKAGE_LOCK`. The embedded entry must match the current build. This does not put a runtime into the CLI archive. Build the matching development `.deb` separately; retain its actual checksum, four shipped executables' Go SBOMs/license files, runtime SBOM/copyright inventory, full archive/version lock, signed repository metadata, sources, tools/keyring identity, and digest. Never create an empty `.deb`, fake lock, placeholder SBOM, or successful evidence file when tooling is unavailable.

For a successful real build, the runtime CycloneDX SBOM lists exact distro identities from the complete resolver lock and the separately inventoried entry hash. It is not a dependency graph or completed license classification. Architecture/archive hashes are in the embedded lock; v1 inventory has only overall architecture, so SBOM purls do not invent amd64 qualifiers for `Architecture: all` archives. Its root hash is the canonical inventory digest, not the `.deb` checksum. Go SBOMs describe actually linked modules, not every go.mod entry. License tools retain actual copyright/license/notice file hashes and explicit missing-file status; they do not infer SPDX terms or clear source redistribution/source-offer obligations. Missing license files and legal review remain gates, never invented approvals.

## Candidate Gates

1. Select source commit and prerelease version deliberately. Review all changes, dependency updates/licenses, open security reports, and limitations. Do not silently relabel an untested development build stable.
2. Replace pending VM lock records only with actual reviewed immutable image URL/digest and publisher signature-verification evidence. Pin builder/tool versions. Build each runtime from its signed snapshot in clean disposable environments, review the entire archive/version lock, and enforce it during a second independent build. Pinning input identity does not mark any VM test passed.
3. Run safe Go tests/vet/race/fuzz coverage and both module/runtime scanners. Preserve scanner DB identity, results, false-positive/unfixed-vulnerability triage, package-license/source obligations, and unknown package matches. Never hide a failed scan behind a skipped job.
4. Build matching development `.deb` artifacts with separate public/starter/engine executables, the exact separately built entry inside the immutable runtime, real dependencies, and no privilege/network installation policy. Verify installed doctor output, all paths/ownership/modes/hashes, fixed sudo/service command shapes, and no host helper overlay on each target.
5. Collect clean-install/upgrade/uninstall, offline/WireGuard, terminal/transfer/concurrency, crash/OOM/ENOSPC, fail-closed startup, and exact-owned-resource cleanup evidence from both fresh target VMs. The smoke fixture is only a subset; see [remaining matrix](testing.md).
6. Compare independent clean-build outputs byte-for-byte. Document any nondeterminism and exact differences; fixed timestamps and `-trimpath` alone do not establish reproducibility.
7. Obtain an independent review of privileged authorization/IPC, credential and FD reduction, transfer/file traversal/publication, namespaces/tmpfs/resource containment, and WireGuard boundaries. Publish actual reviewer/scope/results before using "reviewed" or "audited" labels.
8. Assemble source-linked build instructions, version/commit/runtime digest, artifact checksums, both SBOMs/locks, sanitized test evidence, limitations, and reviewed provenance. Only after separate authorization configure protected signing/release identities and publication.

## Signing And Provenance

No signing key, identity, attestation workflow, or trusted builder identity is invented here. A future authorized release should sign the **actual artifact/checksum set**, retain a verifiable bundle/signature/certificate as applicable, and publish the expected key fingerprint or exact OIDC issuer/identity for verification. Generate provenance from the real build process/materials and bind it to actual artifact SHA256s. Verify the signature and subject identity from a separate environment before publication. A locally composed JSON build record must remain labeled unsigned; renaming it `provenance` does not turn it into proof.

Do not grant release credentials or privileged runners to fork code, `pull_request_target` checkout of untrusted heads, caller-controlled root commands, or unreviewed workflows. Repository private reporting/protection settings, ephemeral runners, approved signing identity, protected release environments, maintainer access, and an ongoing triage/runtime refresh owner require repository-owner action. Signatures establish origin and detect alteration; they do not establish isolation, anonymity, absence of vulnerabilities, or secure erasure.

## Maintenance And Platforms

Deliver offline development artifacts first, then a Linux alpha with validated WireGuard, then a tested beta. Stable requires the complete published evidence and limitations, not a broad feature roadmap. Refresh a snapshot and its entire lock intentionally when security updates require it; rebuild/rescan/retest both target artifacts and keep earlier vulnerability decisions traceable. An unmaintained frozen toolkit is not an acceptable stable release policy.

macOS/Lima, Linux arm64, and Windows VM backends are later feasibility work, not implemented release stages. Do not promise native Unix portability, trust a default Lima home mount, or advertise shared default WSL2 as equivalent isolation. A future backend must separately prove host/guest credential-sharing defaults, volatile guest state, authenticated control, network isolation, interruption/teardown, and host VM storage/swap/snapshot limitations.

#!/usr/bin/env bash
# This fixture is intentionally excluded from make test/check and PR workflows.
set -euo pipefail

fail() { printf 'Disposable VM smoke refused: %s\n' "$*" >&2; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --preflight-only ) ]] || fail 'unexpected arguments'
[[ ${SOTERIA_DISPOSABLE_VM:-} == DISPOSABLE_VM_ONLY ]] || fail 'explicit SOTERIA_DISPOSABLE_VM=DISPOSABLE_VM_ONLY is required'
[[ $EUID -ne 0 && $(id -g) -ne 0 ]] || fail 'run as the non-root VM test user, never sudo the frontend or this script'
[[ ${SOTERIA_VM_IMAGE_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || fail 'record the independently verified VM image SHA256 in SOTERIA_VM_IMAGE_SHA256'
[[ ${SOTERIA_EXPECTED_COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || fail 'select the full installed candidate source commit in SOTERIA_EXPECTED_COMMIT'
case "${SOTERIA_VM_TARGET:-}" in debian13-amd64|ubuntu24.04-amd64) ;; *) fail 'select SOTERIA_VM_TARGET explicitly' ;; esac
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'only Linux amd64 test targets are implemented'
command -v systemd-detect-virt >/dev/null || fail 'systemd-detect-virt is unavailable'
systemd-detect-virt --quiet --vm || fail 'a VM is required; containers and physical hosts are not integration targets'
if systemd-detect-virt --quiet --container; then fail 'container detected'; fi
marker=/etc/soteria/disposable-vm
[[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:444:1 ]] || fail 'missing real root:root 0444 /etc/soteria/disposable-vm marker'
mapfile -t marker_lines < "$marker"
[[ ${#marker_lines[@]} == 2 && ${marker_lines[0]} == soteria-disposable-vm-v1 && ${marker_lines[1]} == "image_sha256=$SOTERIA_VM_IMAGE_SHA256" ]] || fail 'VM marker does not match the declared image'
[[ -d /run/systemd/system && $(stat -f -c '%T' /sys/fs/cgroup) == cgroup2fs ]] || fail 'booted systemd and unified cgroup v2 are required'
[[ $(stat -f -c '%T' /dev/shm) == tmpfs ]] || fail 'fixtures require tmpfs at /dev/shm'
script_directory=$(dirname -- "$(readlink -f -- "$0")")
/usr/bin/python3 -I -B "$script_directory/../check-image-lock.py" --target "$SOTERIA_VM_TARGET" --sha256 "$SOTERIA_VM_IMAGE_SHA256" >/dev/null || fail 'reviewed immutable VM input lock is missing or pending; no bypass is provided'
for directory in / /etc /etc/soteria /usr /usr/bin /usr/libexec /usr/libexec/soteria /usr/lib /usr/lib/soteria /usr/lib/soteria/runtime; do
  [[ -d $directory && ! -L $directory && $(stat -c '%u:%g' "$directory") == 0:0 ]] || fail 'installed path/marker ancestry must be real root-owned directories'
  mode=$(stat -c '%a' "$directory")
  (( (8#$mode & 07022) == 0 )) || fail 'installed path/marker ancestors may not have special or group/other-write bits'
done
for tool in /usr/bin/python3 /usr/bin/soteria /usr/libexec/soteria/soteria-starter /usr/libexec/soteria/soteria-engine /usr/lib/soteria/runtime/usr/libexec/soteria-entry /usr/bin/sudo /usr/bin/ip /usr/bin/systemctl /usr/sbin/nft /usr/sbin/iptables-save; do
  [[ -x $tool ]] || fail "missing installed/test dependency: $tool"
done
for tool in /usr/bin/soteria /usr/libexec/soteria/soteria-starter /usr/libexec/soteria/soteria-engine; do
  [[ ! -L $tool && $(stat -c '%u:%g:%a:%h' "$tool") == 0:0:755:1 ]] || fail 'use the installed, root-owned package binaries'
done
entry=/usr/lib/soteria/runtime/usr/libexec/soteria-entry
[[ ! -L $entry && $(stat -c '%u:%g:%a:%h' "$entry") == 0:0:555:1 ]] || fail 'the trusted entry must be an inventoried immutable runtime file'
/usr/bin/sudo -n -v || fail 'authorize sudo interactively as the VM test user before running; do not install passwordless rules'
if [[ $# == 1 ]]; then exit 0; fi
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -I "$(dirname -- "$0")/offline-smoke.py"

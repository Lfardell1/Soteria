#!/usr/bin/env bash
# Install host dependencies required by Soteria.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

need_cmds=(rsync iptables openvpn)
optional_cmds=(tor dnscrypt-proxy proxychains4)

detect_pkg() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
  elif command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v pacman >/dev/null 2>&1; then
    echo pacman
  else
    echo unknown
  fi
}

install_pkgs() {
  local mgr="$1"
  shift
  case "$mgr" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    dnf)
      dnf install -y "$@"
      ;;
    pacman)
      pacman -Sy --noconfirm "$@"
      ;;
    *)
      echo "Unsupported package manager. Install manually: $*" >&2
      exit 1
      ;;
  esac
}

mgr="$(detect_pkg)"
echo "Detected package manager: ${mgr}"

case "$mgr" in
  apt)
    install_pkgs apt rsync iptables openvpn tor dnscrypt-proxy proxychains4
    ;;
  dnf)
    install_pkgs dnf rsync iptables-nft openvpn tor dnscrypt-proxy proxychains-ng
    ;;
  pacman)
    install_pkgs pacman rsync iptables openvpn tor dnscrypt-proxy proxychains-ng
    ;;
  *)
    echo "Cannot auto-install. Ensure these are present: ${need_cmds[*]} ${optional_cmds[*]}" >&2
    exit 1
    ;;
esac

echo "Checking required commands..."
missing=0
for c in "${need_cmds[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "MISSING required: $c" >&2
    missing=1
  else
    echo "OK  $c -> $(command -v "$c")"
  fi
done

echo "Checking optional commands..."
for c in "${optional_cmds[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "WARN optional missing: $c"
  else
    echo "OK  $c -> $(command -v "$c")"
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "Dependency installation incomplete." >&2
  exit 1
fi

echo "Soteria dependencies installed."

#!/usr/bin/env bash
# Kept only to prevent old installation instructions from mutating the host.
set -euo pipefail
printf '%s\n' \
  'The legacy host dependency installer has been retired. Nothing was changed.' \
  'Use a reviewed Soteria .deb built for your supported Debian/Ubuntu target.' \
  'See docs/building.md. Do not install OpenVPN, Tor, DNSCrypt, or Proxychains for Soteria.' >&2
exit 1

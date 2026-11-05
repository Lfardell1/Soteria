#!/usr/bin/env bash
set -euo pipefail

go_command=${GO:-go}
actual=$(GOTOOLCHAIN=local "$go_command" version)
if [[ $actual != 'go version go1.27.3 '* ]]; then
  printf 'Go 1.27.3 is required; found: %s\nNo toolchain or dependency files were changed.\n' "$actual" >&2
  exit 1
fi

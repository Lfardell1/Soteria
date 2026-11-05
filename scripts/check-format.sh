#!/usr/bin/env bash
set -euo pipefail

go_command=${GO:-go}
gofmt_command="$(GOTOOLCHAIN=local "$go_command" env GOROOT)/bin/gofmt"
shopt -s lastpipe
git ls-files -z --cached --others --exclude-standard -- '*.go' | mapfile -d '' files
present=()
for file in "${files[@]}"; do
  if [[ -f $file ]]; then present+=("$file"); fi
done
[[ ${#present[@]} -gt 0 ]] || exit 0
unformatted=$("$gofmt_command" -l "${present[@]}")
if [[ -n $unformatted ]]; then
  printf 'Run gofmt on these files:\n%s\n' "$unformatted" >&2
  exit 1
fi

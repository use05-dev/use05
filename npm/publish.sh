#!/usr/bin/env bash
# Publish the packages npm/build.sh made (D75): every platform package first, so the use05
# package never points at one that is not there, then use05 itself.
#
#   npm/publish.sh OUT [npm publish flags...]     e.g. npm/publish.sh out --dry-run
#
# Paths are given as ./out/..., never out/...: npm reads a bare a/b as a GitHub repository.
set -euo pipefail
OUT="${1:?usage: publish.sh OUT [flags]}"; shift
cd "$OUT"
for d in cli-*; do npm publish "./$d" "$@"; done
npm publish ./use05 "$@"

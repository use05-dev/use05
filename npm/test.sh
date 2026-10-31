#!/usr/bin/env bash
# Check the npm packaging end to end on this machine, publishing nothing: package the release
# binary the way the release workflow does, build the npm packages from it, pack them, install
# them into a throwaway prefix, and run use05 through npm's own launcher.
#
#   npm/test.sh [BINARY]     (default: target/release/use05, built if missing)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${1:-$ROOT/target/release/use05}"
[ -x "$BIN" ] || cargo build --release -q -p use05 --manifest-path "$ROOT/Cargo.toml"
V=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-aarch64) target=aarch64-unknown-linux-musl ;;
  Linux-x86_64) target=x86_64-unknown-linux-musl ;;
  *) echo "npm test: no npm package for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
D="use05-$V-$target"
mkdir -p "$tmp/dist/$D" "$tmp/packs"
cp "$BIN" "$tmp/dist/$D/use05"
(cd "$tmp/dist" && tar czf "$D.tar.gz" "$D" && rm -r "$D" && { command -v sha256sum >/dev/null && sha256sum "$D.tar.gz" || shasum -a 256 "$D.tar.gz"; } > "$D.tar.gz.sha256")
"$ROOT/npm/build.sh" "$V" "$tmp/dist" "$tmp/out" >/dev/null
(cd "$tmp/packs" && for d in "$tmp"/out/*; do npm pack -q "$d" >/dev/null; done)
npm install -g -q --offline --no-audit --no-fund --prefix "$tmp/prefix" "$tmp"/packs/*.tgz >/dev/null
got=$("$tmp/prefix/bin/use05" --version)
[ "$got" = "use05 $V" ] || { echo "npm test: expected \"use05 $V\", got \"$got\"" >&2; exit 1; }
set +e; "$tmp/prefix/bin/use05" no-such-command 2>/dev/null; code=$?; set -e
[ "$code" = 6 ] || { echo "npm test: the exit code was not passed through (got $code, want 6)" >&2; exit 1; }
# The publish step the workflow runs, as a dry run: nothing is sent.
"$ROOT/npm/publish.sh" "$tmp/out" --dry-run >/dev/null 2>&1 || { echo "npm test: npm/publish.sh --dry-run failed" >&2; exit 1; }
echo "npm test: installed from packed packages, ran $got, exit codes pass through, publish dry run ok"

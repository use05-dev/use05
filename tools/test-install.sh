#!/bin/sh
# Test tools/install.sh against a local, fake release built from a real binary:
#   tools/test-install.sh path/to/use05
set -eu
BIN="${1:?usage: test-install.sh path/to/use05}"
HERE="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64) target=aarch64-unknown-linux-musl ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  *) echo "unsupported test host"; exit 1 ;;
esac
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rel="$T/rel/download/v9.9.9"; mkdir -p "$rel" "$T/pkg/use05-9.9.9-$target"
cp "$BIN" "$T/pkg/use05-9.9.9-$target/use05"
# The helper ships beside it when it was built.
CLOUD="$(dirname "$BIN")/use05-cloud"
[ -x "$CLOUD" ] && cp "$CLOUD" "$T/pkg/use05-9.9.9-$target/use05-cloud"
(cd "$T/pkg" && tar czf "$rel/use05-9.9.9-$target.tar.gz" "use05-9.9.9-$target")
(cd "$rel" && { sha256sum "use05-9.9.9-$target.tar.gz" 2>/dev/null || shasum -a 256 "use05-9.9.9-$target.tar.gz"; } > SHA256SUMS)

# 1. a good release installs and runs
USE05_BASE_URL="file://$T/rel" USE05_VERSION=9.9.9 USE05_INSTALL_DIR="$T/bin" sh "$HERE/install.sh" >"$T/out.txt" 2>&1 || { cat "$T/out.txt"; exit 1; }
"$T/bin/use05" --version >/dev/null
if [ -x "$CLOUD" ]; then "$T/bin/use05-cloud" | grep -q "your own 05 console" || { echo "FAIL: use05-cloud was not installed with use05"; exit 1; }; fi
# 2. a tampered archive is refused and nothing is installed
rm -rf "$T/bin"
echo tampered >> "$rel/use05-9.9.9-$target.tar.gz"
if USE05_BASE_URL="file://$T/rel" USE05_VERSION=9.9.9 USE05_INSTALL_DIR="$T/bin" sh "$HERE/install.sh" >"$T/out2.txt" 2>&1; then echo "FAIL: installed a tampered archive"; exit 1; fi
grep -q "checksum mismatch" "$T/out2.txt" || { echo "FAIL: no mismatch message"; cat "$T/out2.txt"; exit 1; }
[ ! -e "$T/bin/use05" ] || { echo "FAIL: a binary was installed anyway"; exit 1; }
echo "installer ok"

#!/bin/sh
# Install use05 from a release: download, verify the checksum, put the binaries on your PATH.
#
#   curl -fsSL https://use05.dev/install.sh | sh
#
# Environment:
#   USE05_BASE_URL     where releases live (default: the project's GitHub releases; see below)
#   USE05_VERSION      a version like 0.1.0 (default: latest)
#   USE05_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#
# Releases are published at github.com/use05-dev/use05 from the first release on; before that,
# set USE05_BASE_URL. The script never installs a file whose checksum it cannot verify.
set -eu

BASE="${USE05_BASE_URL:-https://github.com/use05-dev/use05/releases}"
VERSION="${USE05_VERSION:-latest}"
DIR="${USE05_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) die "unsupported system $(uname -s). 05 supports macOS and Linux." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac
target="$arch-$os"

command -v git >/dev/null 2>&1 || die "git is required (05 runs it). Install git first."
command -v curl >/dev/null 2>&1 || die "curl is required"
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "need sha256sum or shasum to verify the download"; fi

if [ "$VERSION" = latest ]; then url="$BASE/latest/download"; else url="$BASE/download/v${VERSION#v}"; fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

say "Fetching the checksum list from $url"
curl -fsSL "$url/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "could not download SHA256SUMS from $url"
line="$(grep -- "-$target.tar.gz\$" "$tmp/SHA256SUMS" | head -n 1 || true)"
[ -n "$line" ] || die "no build for $target in this release"
expected="${line%% *}"
file="${line##* }"
file="${file#\*}"

say "Downloading $file"
curl -fsSL "$url/$file" -o "$tmp/$file" || die "could not download $file"
actual="$(sum "$tmp/$file")"
[ "$actual" = "$expected" ] || die "checksum mismatch for $file (expected $expected, got $actual). Not installing."

tar xzf "$tmp/$file" -C "$tmp"
bin="$(find "$tmp" -type f -name use05 | head -n 1)"
[ -n "$bin" ] || die "the archive has no use05 binary"
mkdir -p "$DIR"
install -m 0755 "$bin" "$DIR/use05"
say "Installed $("$DIR/use05" --version) to $DIR/use05"
# The helper for your own console comes in the same archive (0.0.7 and later).
cloud="$(find "$tmp" -type f -name use05-cloud | head -n 1)"
if [ -n "$cloud" ]; then
  install -m 0755 "$cloud" "$DIR/use05-cloud"
  say "Installed use05-cloud to $DIR/use05-cloud (for use05 cloud, if you run your own console)"
fi
case ":$PATH:" in *":$DIR:"*) ;; *) say "Add it to your PATH:  export PATH=\"$DIR:\$PATH\"" ;; esac
say "Next: cd into a repository and run: use05 init"

#!/usr/bin/env bash
# Build a release's macOS binaries on a Mac and attach them to its draft on GitHub.
#
#   tools/release-macos.sh vX.Y.Z [--publish]
#
# GitHub's hosted macOS runners are often not given to this repository at all, so the release
# workflow builds Linux and the console image only, and the macOS binaries are built here: from a
# fresh clone of the tag, with the Touch ID approver key required (a build without it fails), and
# packaged exactly as the workflow packages Linux. It adds them and a SHA256SUMS covering every
# platform to the draft. With --publish it then publishes the release and re-runs the console
# image job, so the image's latest tag moves to it. Needs git, cargo with rustup, Xcode's Swift
# (or the Command Line Tools) and gh, logged in with push rights.
set -euo pipefail
TAG="${1:?usage: release-macos.sh vX.Y.Z [--publish]}"
PUBLISH="${2:-}"
REPO="${USE05_RELEASE_REPO:-use05-dev/use05}"
V="${TAG#v}"
[ "$(uname -s)" = Darwin ] || { echo "release-macos: run this on a Mac" >&2; exit 1; }
case "$TAG" in v[0-9]*) ;; *) echo "release-macos: $TAG is not a tag like v0.1.0" >&2; exit 1 ;; esac
case "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft 2>/dev/null || echo none)" in
  true) ;;
  false) echo "release-macos: $TAG is already published on $REPO; nothing to attach" >&2; exit 1 ;;
  *) echo "release-macos: $TAG has no draft release on $REPO yet; wait for the release workflow" >&2; exit 1 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q --depth 1 --branch "$TAG" "https://github.com/$REPO.git" "$WORK/src"
cd "$WORK/src"
grep -q "^version = \"$V\"" Cargo.toml || { echo "release-macos: Cargo.toml at $TAG is not version $V" >&2; exit 1; }

mkdir -p "$WORK/dist"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target add "$target" >/dev/null
  USE05_REQUIRE_TOUCH_ID=1 cargo build --release --locked -p use05 -p use05-cloud --target "$target"
  bin="target/$target/release"
  otool -L "$bin/use05" | grep -q CryptoKit || { echo "release-macos: $target has no Touch ID" >&2; exit 1; }
  [ "$target" != "$(uname -m | sed 's/arm64/aarch64/')-apple-darwin" ] || "$bin/use05" --version | grep -qx "use05 $V"
  D="use05-$V-$target"
  mkdir "$WORK/$D" && cp "$bin/use05" "$bin/use05-cloud" "$WORK/$D/"
  cp LICENSE* README.md "$WORK/$D/" 2>/dev/null || true
  (cd "$WORK" && tar czf "dist/$D.tar.gz" "$D" && cd dist && shasum -a 256 "$D.tar.gz" > "$D.tar.gz.sha256")
done

# One SHA256SUMS for every platform: the draft's own checksums, then these.
gh release download "$TAG" --repo "$REPO" --pattern '*.tar.gz.sha256' --dir "$WORK/draft"
cat "$WORK"/draft/*.sha256 "$WORK"/dist/*.sha256 | sort -k2 -u > "$WORK/dist/SHA256SUMS"
gh release upload "$TAG" "$WORK"/dist/* --repo "$REPO" --clobber
echo "release-macos: attached the macOS binaries to the $TAG draft"

if [ "$PUBLISH" = --publish ]; then
  gh release edit "$TAG" --repo "$REPO" --draft=false >/dev/null
  run=$(gh run list --repo "$REPO" --workflow release --branch "$TAG" --limit 1 --json databaseId --jq '.[0].databaseId')
  job=$(gh run view "$run" --repo "$REPO" --json jobs --jq '.jobs[] | select(.name == "console image") | .databaseId')
  gh run rerun "$run" --repo "$REPO" --job "$job"
  echo "release-macos: published $TAG; the console image job runs again to move latest"
fi

#!/usr/bin/env bash
# Build the npm packages from a release's binaries (D75).
#
#   npm/build.sh VERSION DIST OUT
#
# DIST holds the release's use05-VERSION-<target>.tar.gz files and their .sha256 files. OUT gets
# one directory per package, ready for `npm publish`: a platform package @use05/cli-<os>-<cpu>
# holding the binary, and the `use05` package that runs whichever one npm installed. A tarball
# whose checksum does not match stops the build. Targets missing from DIST are skipped and named.
set -euo pipefail
VERSION="${1:?usage: build.sh VERSION DIST OUT}"
DIST="${2:?usage: build.sh VERSION DIST OUT}"
OUT="${3:?usage: build.sh VERSION DIST OUT}"
HERE=$(cd "$(dirname "$0")" && pwd)

# npm platform name, then the Rust target it is built from.
PLATFORMS="darwin-arm64:aarch64-apple-darwin darwin-x64:x86_64-apple-darwin linux-arm64:aarch64-unknown-linux-musl linux-x64:x86_64-unknown-linux-musl"

sum() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$OUT"
built=0
for pair in $PLATFORMS; do
  platform=${pair%%:*}; target=${pair#*:}
  os=${platform%-*}; cpu=${platform#*-}
  name="use05-$VERSION-$target"
  tarball="$DIST/$name.tar.gz"
  if [ ! -f "$tarball" ]; then
    echo "npm: no $name.tar.gz in $DIST; @use05/cli-$platform is not built"
    continue
  fi
  want=$(cut -d' ' -f1 < "$tarball.sha256")
  [ "$(sum "$tarball")" = "$want" ] || { echo "npm: $name.tar.gz does not match its checksum" >&2; exit 1; }
  dir="$OUT/cli-$platform"
  rm -rf "$dir" && mkdir -p "$dir/bin"
  tar -xzf "$tarball" -C "$dir" "$name/use05"
  mv "$dir/$name/use05" "$dir/bin/use05" && rmdir "$dir/$name"
  chmod 755 "$dir/bin/use05"
  cat > "$dir/package.json" <<JSON
{
  "name": "@use05/cli-$platform",
  "version": "$VERSION",
  "description": "The use05 binary for $os on $cpu. Install the use05 package instead.",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/use05-dev/use05.git" },
  "os": ["$os"],
  "cpu": ["$cpu"],
  "files": ["bin/use05"],
  "preferUnplugged": true
}
JSON
  built=$((built + 1))
done
[ "$built" -gt 0 ] || { echo "npm: no release binaries found in $DIST" >&2; exit 1; }

# The wrapper, pinned to exactly this version of every platform package.
rm -rf "$OUT/use05" && cp -R "$HERE/use05" "$OUT/use05"
node -e '
  const fs = require("fs"), file = process.argv[1], v = process.argv[2];
  const p = JSON.parse(fs.readFileSync(file, "utf8"));
  p.version = v;
  for (const k of Object.keys(p.optionalDependencies)) p.optionalDependencies[k] = v;
  fs.writeFileSync(file, JSON.stringify(p, null, 2) + "\n");
' "$OUT/use05/package.json" "$VERSION"
echo "npm: built use05 $VERSION and $built platform package(s) in $OUT"

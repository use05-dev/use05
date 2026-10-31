#!/usr/bin/env node
// Runs the use05 binary for this machine. npm installs exactly one platform package, chosen by
// its "os" and "cpu" fields; this finds it and hands over arguments, stdio and the exit code.
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const pkg = `@use05/cli-${process.platform}-${process.arch}`;
let bin;
try {
  bin = path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "bin", "use05");
} catch {
  const shipped = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"].includes(`${process.platform}-${process.arch}`);
  console.error(
    shipped
      ? `use05: npm did not install ${pkg}, which holds the binary. Reinstall without --no-optional or --omit=optional.`
      : `use05: there is no binary for ${process.platform}-${process.arch}. 05 ships for macOS and Linux on x64 and arm64.`
  );
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`use05: could not run ${bin}: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 1);

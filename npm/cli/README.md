# @use05/cli

05 lets AI-written code land with no pull request to review. Agents declare a plan; 05 seals it, checks the result on the exact code, signs the evidence and keeps several agents out of each other's way. You approve by exception, and the change lands as a commit.

```sh
npm install -g @use05/cli
use05 init
```

This package runs the native `use05` and `use05-cloud` binaries for your machine (macOS and Linux, x64 and arm64), installed from one of the `@use05/cli-*` packages; `use05-cloud` connects it to [your own console](https://github.com/use05-dev/use05/blob/main/docs/console.md). Every release's binaries are also on GitHub with checksums: https://github.com/use05-dev/use05/releases

Documentation: https://github.com/use05-dev/use05

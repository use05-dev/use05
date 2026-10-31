# Contributing

Thanks for helping. A few rules keep 05 small and trustworthy.

1. **Run the tests.** `cargo test --workspace --release` (the release flag matters: key derivation is slow in debug builds). Snapshot tests live in `crates/cli/tests/snapshots`; `UPDATE_SNAPSHOTS=1` regenerates them, then read the diff.
2. **Keep the CLI small.** Few commands, plain language, honest about enforcement strength. A new command needs a written reason in your pull request.
3. **No model in the gate.** Decisions are deterministic.
4. **Nothing leaves the machine.** No telemetry, no network calls except `git` talking to the remote you configured.
5. **Say how strong a control is.** If a change adds a control, document whether it is advisory or enforced.
6. **Add a test that fails without your change.** Security fixes especially.

By contributing you agree your work is licensed under Apache-2.0.

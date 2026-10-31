# Changelog

## 0.0.2

- **Folder and file rules.** In `.05/policy.toml`, `[protect]` can now mark paths `locked` (never changed; no approval clears it), `append_only` (new files only, for example database migrations; edits, renames and deletions are refused), `no_delete`, and `no_read` (agents may not open them). Agent hooks refuse these before they happen, through file tools and the shell; the gate and the CI gate deny them. A person can bypass a rule for one exact change with a stated reason, unless the path is listed in `absolute` or `bypass = false`. Rules are read from the change's base, so a change cannot unlock a file and edit it in one go. An organisation floor can add rules and turn bypass off. `no_read` is advisory: it holds only where an agent's own hooks report the read.
- **`[use05] min_version`.** A policy can name the oldest use05 that reads it, and `use05 init` writes it. An older version is told to upgrade instead of failing on a rule it does not know. Versions before 0.0.2 cannot read this line, so everyone working on a repository set up by 0.0.2 needs 0.0.2 or newer.
- Claude Code hooks now also see Read, Grep and Glob, so `no_read` can hold. Run `use05 init` again after upgrading: it now updates hooks an older version installed, keeping other tools' hooks.

## 0.0.1

First public version: init, start, prove, brief, approve, verify, policy, doctor and bypass; Claude Code and Codex hooks; a git pre-push gate and a CI gate; organisation policy floor; signed receipts on `05-receipts/*` branches; trusted-key expiry; local collision awareness between parallel agent sessions.

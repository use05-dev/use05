# Using 05

How to install 05, set it up in a repository, work with it day to day, and configure it. For what 05 is and why, see the [README](../README.md) and [use05.dev](https://use05.dev).

- [Install](#install)
- [Set up a repository](#set-up-a-repository)
- [Working with an agent](#working-with-an-agent)
- [Working by hand](#working-by-hand)
- [Reading the brief](#reading-the-brief)
- [Approving, rejecting and bypassing](#approving-rejecting-and-bypassing)
- [Long sessions, large changes and subagents](#long-sessions-large-changes-and-subagents)
- [Several agents at once](#several-agents-at-once)
- [Configure: `.05/policy.toml`](#configure-05policytoml)
- [Turn on the CI gate](#turn-on-the-ci-gate)
- [Commands](#commands)
- [Upgrade and uninstall](#upgrade-and-uninstall)

## Install

05 is one command line tool, `use05`, for macOS and Linux (x86_64 and arm64). Pick one way:

**Installer script** (for your whole machine):
```sh
curl -fsSL https://use05.dev/install.sh | sh
```
It downloads the release for your platform, checks its SHA-256 against `SHA256SUMS`, and refuses to install on a mismatch.

**npm, for your whole machine:**
```sh
npm install -g @use05/cli
```

**npm, for one project** (pinned in `package.json`, so everyone on the project gets the same version):
```sh
npm install --save-dev @use05/cli
npx use05 init
```
Run commands as `npx use05 …`. The hooks `init` writes find the project's copy in `node_modules/.bin`, in agents' worktrees too. If a teammate also has use05 installed for their whole machine, that one is used first.

**From source** (Rust 1.85 or newer, and `git`):
```sh
git clone https://github.com/use05-dev/use05 && cd use05
cargo build --release -p use05     # the binary is target/release/use05
```

Check it worked: `use05 --version`.

## Set up a repository

```sh
cd your-repo
use05 init
```

`init` lists exactly what it changed, and what is still not covered. It:

- writes `.05/policy.toml`, your rules, with a `test` check guessed from your project;
- creates a signing key for this machine;
- installs hooks for Claude Code (if `.claude/` exists) and Codex (if `.codex/` exists);
- installs a git pre-push hook;
- adds a short block to `AGENTS.md` so agents know how 05 works.

Commit `.05/` and `AGENTS.md`. Then run `use05 doctor`: it checks the setup and says how strongly each control is enforced. Until you turn on the CI gate, everything is advisory, and doctor says so.

`use05 init --no-hooks` skips the hooks, `--no-agents-md` leaves `AGENTS.md` alone, and `--ci github` also writes the CI workflow. `use05 uninstall` reverses exactly what `init` did.

To approve changes you need an approver key, protected by a passphrase the agent does not have:
```sh
use05 key new --approver
```

## Working with an agent

With Claude Code or Codex, most of 05 runs on its own through the hooks. Work as you normally do; this is what happens:

1. **The session starts.** The agent is told the rules: protected and locked paths, files it may not read, the checks it can name. Every subagent is told the same when it starts.
2. **The agent declares its plan** before its first edit:
   ```sh
   use05 start "Cap payment retries at three" --scope "src/billing/**" --check test
   ```
   The hook seals the plan, so a later change to it shows. If another agent's plan already covers that area, the agent is told who holds it.
3. **The agent works.** Before each tool call, the hook refuses what the policy forbids: a force push, `git reset --hard`, `--no-verify`, an edit to a protected or locked path without approval, a read of a do-not-read file. Each refusal tells the agent why, and is recorded.
4. **The agent stops.** The hook runs the required checks on the change and signs the result. It runs those that have run before and whose last run fits the time budget (60 seconds by default); slower ones are left for the pre-push hook and CI. If a check fails, Claude Code is asked to fix it before finishing. The agent can record what it says it did with `use05 finish --outcome "…"`.
5. **You read the brief.** `use05 brief`. If it ends in `ALLOW, nothing to read`, you don't need to read anything.
6. **You approve, if asked.** `use05 approve --outcome`.
7. **You land and push.**
   ```sh
   use05 land          # the change moves to its target branch; the agent's branch and worktree are removed
   git push origin main
   ```
   The pre-push hook checks what you push. No pull request is needed. If your team wants pull requests, push the branch and open one; the CI gate checks it either way.

Bare `use05` shows where you stand at any time: the current task, whether the staged change would be allowed, and which controls are on.

Any other agent with hooks of its own can call `use05 hook generic` (see [Extending 05](extending.md)). Every agent, hooks or not, is covered by the pre-push hook and the CI gate.

## Working by hand

The same flow works without an agent:

```sh
use05 start "Stop retrying failed charges" --scope "src/billing/**"
# … make the change, stage it with git add …
use05 prove                  # run the policy's checks on the staged files and sign the result
use05 finish --outcome "Retries capped at three; failed charges are not retried"
use05 brief
use05 approve --outcome      # only if the brief asks for it
use05 land
git push origin main
```

`use05 prove` runs every required check. `use05 prove test lint` runs named checks; `use05 prove -- cargo test` runs any command. Checks run on a copy of exactly the staged files, with a scrubbed environment. A failing check still gets a receipt that records the failure.

## Reading the brief

`use05 brief` is the one page a person reads instead of the diff. `use05 brief --json` prints the same as data.

| Section | What it tells you |
|---|---|
| Intent | What was asked and what the agent declared: goal, scope, checks, the agent and the person accountable for it, and how risky the change is (auth, money, migrations, secrets, deployment). |
| Outcome | How many files and lines changed, grouped into at most eight areas with lines added and removed, and anything outside the declared scope, grouped by area. |
| Evidence | Each required check: passed, failed, missing or stale, and who signed it. A check signed on your machine is marked advisory; one signed in CI is not. |
| Drift | Each place the change departs from the plan or the rules, with a stable code: `SCOPE_EXCEEDED`, `TESTS_WEAKENED`, `PROTECTED_PATH`, `LOCKED_PATH`, `OVERLAP` and others. |
| Approvals | Who approved or rejected, and whether each approval still counts. |
| Session | For agent work, what happened during the session in at most four lines: how long it ran, turns and tool calls, what 05 refused and why, which checks ran along the way and how they ended, and which subagents took part. |
| Log | Whether the record of what the agent did is intact, and how strongly it is sealed. |
| Unknowns | What 05 could not establish. 05 shows what was checked; it never judges whether the change is correct. |
| Undo | How to back the change out. |

It ends in one decision:

- **ALLOW, nothing to read**: the change matched its plan, and its checks passed.
- **ALLOW, read the notes**: allowed by your policy, but something is worth knowing.
- **WAIT**: evidence is missing, usually a check that has not run on this change. Run `use05 prove`.
- **APPROVAL REQUIRED**: a person must approve. The brief lists what holds the change back and the command for each.
- **DENY**: a rule no approval clears, such as a change to a locked file.

## Approving, rejecting and bypassing

```sh
use05 approve --intent       # approve a plan before the work, when the policy asks for it
use05 approve --outcome      # approve the finished change (the default)
use05 approve --reject --reason "Retries must stay at five"
```

You are asked for your approver passphrase. An approval is signed, tied to the exact content and the policy, and expires after `approvals.expire_days` (7 by default). If the change moves on, the approval no longer counts and the brief says so.

**Break glass.** To let one exact change through a block, with a reason:
```sh
use05 bypass --reason "Hotfix for the outage, reviewed on the call"
```
It lasts 4 hours by default (`--hours`), needs your passphrase, is logged, and shows in the brief. A folder or file listed in `absolute`, or any rule when `bypass = false`, cannot be bypassed. Agents can never bypass.

## Long sessions, large changes and subagents

05 is built for agent sessions that run for hours and change thousands of files:

- **The rules hold the whole time.** They are checked by the hooks on every tool call. They do not depend on the agent remembering `AGENTS.md`.
- **Subagents follow the same rules.** Their tool calls go through the same hooks, under the same task. Every action they take is recorded with the subagent that took it. Each subagent is told the rules when it starts.
- **The brief stays one page.** The Outcome groups files into named areas with line counts. The Session section digests the whole session in at most four lines. A 50,000-line change is briefed in well under a second.
- **Checks run as the agent goes.** Each time the agent stops, required checks whose last run fits the time budget run on the change. Slower ones are left for the pre-push hook and CI, and the Session section shows how each check went over the session.

## Several agents at once

Run as many agents as you like on one repository:

- **Each agent claims an area.** Its declared scope is reserved for it. Another agent that plans or edits inside that area is told which task holds it.
- **Each agent works on its own branch and git worktree.**
- **Shared files are flagged.** The brief reports `OVERLAP` when another task's change to the same file is not in this change's base.
- **Changes land one at a time.** `use05 land` only fast-forwards exactly what was checked; if the target moved, it says to rebase.

`[drift] overlap` sets how strict this is (`warn` by default), and `reservation_idle_hours` (2 by default) frees an idle session's area.

## Configure: `.05/policy.toml`

`use05 init` writes the file with comments. `use05 policy` shows the effective value of every setting and where it came from. A change is held to the rules at its **base**, never its own, so editing the policy is itself a change a person approves before it takes effect.

| Setting | Default | What it does |
|---|---|---|
| `[use05] min_version` | the version that ran `init` | The oldest use05 that reads this file. An older one is told to upgrade. |
| `[intent] mode` | `"inferred"` | `inferred`: no written plan needed. `risky`: a plan for risky changes. `always`: a plan for every change. |
| `[[check]]` `name`, `run` | `test` | A check 05 runs on the change: `run` is the command as a list, e.g. `["npm", "run", "test", "--silent"]`. Optional: `required` (default true), `env` (variables passed through), `timeout_secs` (default 900). |
| `[protect] paths` | `[]` | A change here needs a person's approval. `.05/**` is always protected. |
| `[protect] locked` | `[]` | Never changed. No approval clears it; a person's bypass can. |
| `[protect] absolute` | `[]` | Locked, and not even a bypass clears it. |
| `[protect] append_only` | `[]` | New files only, e.g. `["migrations/**"]`. Existing files are never edited, renamed or deleted. |
| `[protect] no_delete` | `[]` | May be edited, never deleted. |
| `[protect] no_read` | `[]` | Agents may not open these, e.g. `[".env*"]`. Advisory: it holds only where the agent's hooks report the read. |
| `[protect] bypass` | `true` | `false`: no bypass clears any of the rules above. |
| `[drift] scope` | `"warn"` | Files changed outside the declared scope: `allow`, `warn`, `approval` or `deny`. |
| `[drift] dependencies` | `"warn"` | Dependency files changed. |
| `[drift] overlap` | `"warn"` | Another agent session edited the same files: `warn` tells the agent, `approval` asks a person, `deny` refuses. |
| `[drift] tests` | `"approval"` | The change deletes, skips or loosens tests, or lets a failing check pass. |
| `[drift] claims` | `"warn"` | The agent claims something the evidence does not support, such as "tests pass" without a passing receipt. |
| `[drift] reservation_idle_hours` | `2` | A declared scope stops reserving its area after this long with no activity. |
| `[evidence] accept` | `["local", "runner"]` | Whose signatures count as evidence. `["runner"]` counts only evidence signed in CI. |
| `[evidence] stop_budget_secs` | `60` | How long the hook may spend running checks when an agent stops. `0` turns it off. |
| `[evidence] prove_at_push` | `true` | The pre-push hook runs required checks that are missing for what you push. |
| `[approvals] min` | `1` | Approvals needed. |
| `[approvals] expire_days` | `7` | How long an approval lasts. |
| `[risk] exempt` | `[]` | Paths a built-in risk pattern catches by mistake. |
| `[branches] keep` | `main`, `master`, `develop`, `release/*` | Real branches: never deleted. |
| `[branches] work` | `05/*`, `agent/*`, `claude/*`, `codex/*` | Agents' working branches: removed with their worktree once landed. |
| `[branches] land` | `"manual"` | `manual`: you run `use05 land`. `auto`: a change the gate allows lands when its agent stops. |
| `[record] middle` | `"local"` | What agents did is recorded on this machine and never uploaded. `off` records nothing. |
| `[enforce] on_error` | `"open"` | If 05 itself fails: `open` lets the change through and says so loudly; `closed` refuses it. |
| `[env] allow` | unrestricted | If set, the only environment variables any check may be passed. |
| `[[trust.key]]` | none | Public keys whose receipts count, e.g. your CI runner's. See the CI gate guide. |

An organisation can add a signed layer of rules on top. Repositories can tighten that layer, but never loosen it. `use05 policy` shows which settings came from it.

## Turn on the CI gate

Hooks and the pre-push hook run on your machine, where an agent running as you can reach them, so they are advisory. The CI gate is what enforces: a runner the agent cannot reach runs the checks and signs the result, and your Git host refuses a push without it. It takes about ten minutes, once per repository: see [Turn on the CI gate](turn-on-the-ci-gate.md).

## Commands

| Command | What it does |
|---|---|
| `use05` | Where you stand: the task, whether the staged change would be allowed, which controls are on. |
| `use05 init` | Set up this repository: policy, keys, hooks. Shows exactly what it changes. |
| `use05 start "<title>" --scope <glob>` | Begin a task: what you are about to do and where. Also `--goal`, `--exclude`, `--check`, `--no-new-deps`. |
| `use05 finish --outcome "<text>"` | Record what was done, in the author's words. Treated as a claim, never a fact. |
| `use05 prove [names] [-- command]` | Run checks on the change and sign the result. |
| `use05 brief` | The one page a person reads. `--json` for data, `--fetch` to pull others' receipts first. |
| `use05 approve` | Approve or reject a plan (`--intent`) or a finished change (`--outcome`). |
| `use05 bypass --reason "<text>"` | Let one exact change through a block, for a stated reason. Logged. |
| `use05 land` | Move an allowed change into its target branch, then clean up its branch and worktree. |
| `use05 verify <receipt>` | Check a receipt offline: no account, no network. |
| `use05 policy` | The effective policy, and where each setting came from. |
| `use05 doctor` | Check the setup, and how strongly each control is enforced. |
| `use05 key new --approver` | Create your passphrase-protected approver key. `use05 key show` lists this machine's keys. |
| `use05 uninstall` | Reverse exactly what `init` did. |

Every command takes `--help`, `--repo <dir>` and `--json`.

## Upgrade and uninstall

Upgrade the way you installed: run the installer script again, `npm install -g @use05/cli@latest`, or `npm install --save-dev @use05/cli@latest` in the project. Then run `use05 init` again in each repository. It updates the hooks an older version installed, keeps other tools' hooks, and leaves your policy alone.

`use05 uninstall` removes what `init` added and puts back every file it changed. Your code, branches and policy are never touched.

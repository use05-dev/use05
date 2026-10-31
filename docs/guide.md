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
- [Organisation rules](#organisation-rules)
- [Turn on the CI gate](#turn-on-the-ci-gate)
- [Commands](#commands)
- [Exit codes and environment variables](#exit-codes-and-environment-variables)
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

On a terminal, `init` first asks a few questions, each with a default you accept by pressing Enter:

1. **Who works in this repository:** just you, a small team, or a larger or regulated team. This sets how strict the rules start; you can change each one afterwards.
2. **Which branch finished changes land on.**
3. **Which environment each long-lived branch is:** dev, uat, pre-prod, prod, another environment you name, or not an environment. 05 suggests a level from the branch's name (`main` is dev, `staging` is uat, `production` is prod). A level can hold several environments: pick dev for a second branch and you name it, for example `dev-eu`. Then you can add any other branch as an environment. 05 records the environments and shows them; rules for promoting between them come in a later version.
4. **The checks that must pass**, and any you want to add (`lint: npm run lint`).
5. **Folder and file rules:** what needs a person's approval, what is locked, where only new files may be added (it suggests migration folders it finds), and what agents may not read (it suggests `.env*` if you have one).
6. **How strict to be** when an agent works outside its plan, and when a change weakens tests.
7. **How finished changes land:** you run `use05 land`, or automatically when 05 allows it.

It then shows a summary and asks before writing anything. To change your settings later, run `use05 init` again or `use05 policy --edit`: the same questions, with your current settings as the defaults. Your comments and any settings the questions don't cover are kept.

The answers can also be flags, for scripts: `use05 init --team small --target main --env dev=main --env uat=staging --env prod=production`. An environment whose name is not a level gives its level after a colon: `--env dev-eu=eu-main:dev`. `--defaults` skips the questions; `--guided` asks them even without a terminal, reading the answers from stdin.

Then `init` lists exactly what it changed, and what is still not covered. It:

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

Bare `use05` shows where you stand at any time: the current task, whether the staged change would be allowed, your environments and which controls are on.

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

**A written plan (a plan card).** Instead of flags, `use05 start` can read the plan from a TOML file: `use05 start "Cap payment retries" --card card.toml`.

```toml
title = "Cap payment retries at three"
goal = "Stop retrying failed charges forever"
acceptance = ["test"]                          # checks that must pass for this change
no_new_dependencies = true                     # dependency files must not change
out_of_scope = ["changing the payment gateway client"]
target = "main"                                # optional: the branch this lands on

[scope]
include = ["src/billing/**"]
exclude = ["src/billing/legacy/**"]
```

The same plan as flags: `use05 start "Cap payment retries" --goal "…" --scope "src/billing/**" --exclude "src/billing/legacy/**" --check test --no-new-deps`. With `[intent] mode = "risky"` or `"always"`, the policy asks for such a written plan.

**Another task than the current one.** `brief`, `approve`, `finish` and `land` work on the current task; `--task <id>` names another (bare `use05` shows ids). `brief`, `prove`, `approve` and `bypass` look at the staged files, else the working tree; `--tree index`, `--tree worktree` or `--tree <commit>` picks.

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

**Across machines and CI.** Approvals and receipts live on ordinary git branches (`05-receipts/<key>`). Add `--push` to `approve`, `bypass` or `prove` to push that branch to `origin`, and `use05 brief --fetch` pulls everyone else's first. In scripts, `--passphrase-stdin` reads the passphrase from the first line of stdin instead of the terminal (for `approve`, `bypass` and `key new --approver`).

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

`use05 init` writes the file with comments, and `use05 policy --edit` changes it by asking the setup questions again, so you rarely need to edit it by hand. `use05 policy` shows the effective value of every setting and where it came from. A change is held to the rules at its **base**, never its own, so editing the policy is itself a change a person approves before it takes effect.

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
| `[[risk.rules]]` `category`, `level`, `paths` | built-in only | Your own risk areas, on top of the built-in ones (auth, money, migration, secrets, privilege and deployment are high; persistence and network are medium). For example `category = "pricing"`, `level = "medium"`, `paths = ["src/pricing/**"]`. A high-risk change needs a person's approval. |
| `[branches] keep` | `main`, `master`, `develop`, `release/*` | Real branches: never deleted. |
| `[branches] work` | `05/*`, `agent/*`, `claude/*`, `codex/*` | Agents' working branches: removed with their worktree once landed. |
| `[branches] target` | the remote's default branch | The branch finished changes land on, unless a plan names another. |
| `[branches] land` | `"manual"` | `manual`: you run `use05 land`. `auto`: a change the gate allows lands when its agent stops. |
| `[record] middle` | `"local"` | What agents did is recorded on this machine and never uploaded. `off` records nothing. |
| `[enforce] on_error` | `"open"` | If 05 itself fails: `open` lets the change through and says so loudly; `closed` refuses it. |
| `[env] allow` | unrestricted | If set, the only environment variables any check may be passed. |
| `[[trust.key]]` `name`, `role`, `public`, `expires` | none | A public key whose signatures count: `role = "runner"` for a CI runner (authoritative), `"approver"` for a person's approval key, `"local"` for another machine (advisory). `public` is the contents of the `.pub` file; `expires` (for example `"2027-12-31"`) stops trusting it after that date. See the CI gate guide. |
| `[[environment]]` `name`, `branch`, `level` | none | Which branch is which environment, e.g. `name = "dev"`, `branch = "main"`. `level` (`dev`, `uat`, `pre-prod` or `prod`) is needed only when the name is not a level, such as a second dev environment `dev-eu`. Shown by `use05` and the brief, levels side by side; environment branches are never deleted. |

An organisation can add a signed layer of rules on top. Repositories can tighten that layer, but never loosen it. `use05 policy` shows which settings came from it.

## Organisation rules

An organisation can set a minimum for every repository: rules a repository can tighten but never loosen. 05 reads it on each machine and shows it in `use05 policy` as `[org]`.

1. Write the minimum as TOML. The settings use the policy's names joined with `_`:

   ```toml
   drift_scope = "approval"
   drift_tests = "deny"
   protect_paths = ["infra/**"]
   protect_locked = ["LICENSE"]
   approvals_min = 2
   evidence_accept = ["runner"]
   ```

   Also available: `intent_mode`, `check` (required checks), `drift_dependencies`, `drift_overlap`, `drift_claims`, `approvals_expire_days_max`, `record_middle`, `enforce_on_error`, `env_allow`, `trust_key`, `risk_rules`, `risk_exempt_allowed`, `protect_absolute`, `protect_append_only`, `protect_no_delete`, `protect_no_read` and `protect_bypass`.
2. Sign it with the organisation's key (make one with `use05 key new org.key`):

   ```sh
   use05 policy org-sign floor.toml --org Acme --key org.key --out org.json
   ```
3. On each machine, put `org.json` and the organisation's public key, named `org.pub`, in 05's config directory: `~/.config/05/` (or `$XDG_CONFIG_HOME/05/`, or `$USE05_HOME`). From then on, a missing or tampered `org.json` is an error, not a silent fallback.

## Turn on the CI gate

Hooks and the pre-push hook run on your machine, where an agent running as you can reach them, so they are advisory. The CI gate is what enforces: a runner the agent cannot reach runs the checks and signs the result, and your Git host refuses a push without it. It takes about ten minutes, once per repository: see [Turn on the CI gate](turn-on-the-ci-gate.md).

## Commands

| Command | What it does |
|---|---|
| `use05` | Where you stand: the task, whether the staged change would be allowed, which controls are on. |
| `use05 init` | Set up this repository, asking a few questions on a terminal: policy, keys, hooks. Shows exactly what it changes. Also `--team`, `--target`, `--env`, `--defaults`, `--guided`. |
| `use05 start "<title>" --scope <glob>` | Begin a task: what you are about to do and where. Also `--goal`, `--exclude`, `--check`, `--no-new-deps`. |
| `use05 finish --outcome "<text>"` | Record what was done, in the author's words. Treated as a claim, never a fact. |
| `use05 prove [names] [-- command]` | Run checks on the change and sign the result. |
| `use05 brief` | The one page a person reads. `--json` for data, `--fetch` to pull others' receipts first. |
| `use05 approve` | Approve or reject a plan (`--intent`) or a finished change (`--outcome`). |
| `use05 bypass --reason "<text>"` | Let one exact change through a block, for a stated reason. Logged. |
| `use05 land` | Move an allowed change into its target branch, then clean up its branch and worktree. |
| `use05 verify <receipt>` | Check a receipt offline: no account, no network. |
| `use05 policy` | The effective policy, and where each setting came from. `--edit` changes it through the setup questions. |
| `use05 doctor` | Check the setup, and how strongly each control is enforced. |
| `use05 key new --approver` | Create your passphrase-protected approver key. `use05 key show` lists this machine's keys. |
| `use05 gate` | The gate on its own: `--git-hook pre-push` is what the pre-push hook runs; `--ci` proves the required checks with the runner key, then gates (what the CI workflow runs; `--push` keeps the runner's receipts). |
| `use05 policy org-sign` | Sign an organisation's rules. See [Organisation rules](#organisation-rules). |
| `use05 hook <agent> <event>` | What agent hooks call: `claude-code`, `codex`, or `generic` for any other agent (see [Extending 05](extending.md)). |
| `use05 uninstall` | Reverse exactly what `init` did. |

Every command takes `--help`, `--repo <dir>` and `--json`.

More flags worth knowing:

- `use05 prove`: `--key <file>` signs with that key instead of this machine's (or the CI runner key); `--timeout <seconds>` stops a check after that long; `--env NAME` or `--env NAME=VALUE` passes a variable to the check; `--out <file>` also writes the receipt to a file; `--no-store` keeps it off the receipts branch; `--push` pushes the receipts branch.
- `use05 verify <receipt>`: `--key <file.pub>` checks against that public key instead of the trusted ones; `--tree <rev>` also checks the receipt is for that tree.
- `use05 bypass`: `--hours <n>` sets how long it lasts (4 by default).
- `use05 key new <path>` makes a key pair at `path` and `path.pub`; `use05 key new --approver` makes your passphrase-protected approver key.

## Exit codes and environment variables

`use05 brief` and `use05 gate` exit with the decision, so scripts and CI can act on it: **0** allow, **2** deny, **3** a person's approval is needed, **5** evidence is missing (a check has not run on this change). Other commands exit 0 on success; **6** means the command was used wrongly (an unknown flag, say).

| Variable | What it does |
|---|---|
| `USE05_HOME` | 05's config directory (keys, organisation rules). Default `~/.config/05`, or `$XDG_CONFIG_HOME/05`. |
| `USE05_RUNNER_KEY` | The CI runner's secret key, from a CI secret. `prove` and `gate --ci` sign with it. |
| `USE05_PUSH_TOKEN` | In CI, the token `gate --ci --push` pushes the runner's receipts with. |
| `USE05_SESSION_ID` | For a generic agent: its session id, so `use05 start` from inside it waits for its hook to seal the plan. Claude Code and Codex set their own. |
| `NO_COLOR`, `CLICOLOR_FORCE` | Turn colour off, or force it when output is not a terminal. |
| `USE05_UNICODE` | Use Unicode symbols even when the locale does not say UTF-8. |

## Upgrade and uninstall

Upgrade the way you installed: run the installer script again, `npm install -g @use05/cli@latest`, or `npm install --save-dev @use05/cli@latest` in the project. Then run `use05 init` again in each repository. It updates the hooks an older version installed, keeps other tools' hooks, and leaves your policy alone.

`use05 uninstall` removes what `init` added and puts back every file it changed. Your code, branches and policy are never touched.

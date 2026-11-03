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

Check it worked: `use05 --version`. Each way also installs `use05-cloud`, the helper for [your own console](#your-own-console) (`use05 cloud …`); from source, build it with `cargo build --release -p use05-cloud`.

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
5. **Folder and file rules:** what needs a person's approval, what is locked, where only new files may be added (it suggests migration folders it finds), what agents may not read (it suggests `.env*` if you have one), and which folders must be updated with every change, such as `docs/**` or `CHANGELOG.md` (a `[[require]]` rule on `**`; narrower rules go in the file).
6. **How strict to be** when an agent works outside its plan, when a change weakens tests, and when an agent starts from older code than origin has.
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

1. **The session starts.** The agent is told the rules: protected and locked paths, files it may not read, files that must change together, the checks it can name. Every subagent is told the same when it starts. With `fresh_base` on (new setups have it), 05 fetches origin first and tells the agent whether it is starting from the latest code, and how to update if not.
2. **The agent declares its plan** before its first edit:
   ```sh
   use05 start "Cap payment retries at three" --scope "src/billing/**" --check test
   ```
   The hook seals the plan, so a later change to it shows. If another agent's plan already covers that area, the agent is told who holds it.
3. **The agent works.** Before each tool call, the hook refuses what the policy forbids: a force push, `git reset --hard`, `--no-verify`, an edit to a protected or locked path without approval, a read of a do-not-read file. Each refusal tells the agent why, and is recorded.
4. **The agent stops.** The hook runs the required checks on the change and signs the result. It runs those that have run before and whose last run fits the time budget (60 seconds by default); slower ones are left for the pre-push hook and CI. If a check fails, or the change skipped files a `[[require]]` rule says must change with it, Claude Code is asked to fix it before finishing. The agent can record what it says it did with `use05 finish --outcome "…"`.
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
| Drift | Each place the change departs from the plan or the rules, with a stable code: `SCOPE_EXCEEDED`, `TESTS_WEAKENED`, `PROTECTED_PATH`, `LOCKED_PATH`, `OVERLAP`, `ALSO_CHANGE_MISSING`, `BASE_STALE` and others. |
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

You are asked for your approver passphrase. An approval is signed, tied to the exact content and the policy, and expires after `approvals.expire_days` (7 by default). If the change moves on, the approval no longer counts and the brief says so. So does an approval prepared elsewhere that is dated ahead or made to last longer than `approvals.expire_days`: 05 checks the dates against your policy, not against what the approval says.

**Across machines and CI.** Approvals and receipts live on ordinary git branches (`05-receipts/<key>`). Add `--push` to `approve`, `bypass` or `prove` to push that branch to `origin`, and `use05 brief --fetch` pulls everyone else's first. In scripts, `--passphrase-stdin` reads the passphrase from the first line of stdin instead of the terminal (for `approve`, `bypass` and `key new --approver`).

**Approving with a passkey, or anything that signs elsewhere.** A person can also approve with a passkey (Face ID, a fingerprint, a security key), from a page that holds it. 05 prepares the statement and files the signed result; the signing happens elsewhere:
```sh
use05 approve --unsigned --json      # the exact statement and the passkey challenge; nothing is signed or stored
use05 approve --signed approval.json # file it, if a key you trust as an approver signed it
```
`--unsigned` takes the same `--intent`, `--reject`, `--reason`, `--task` and `--tree` as a normal approval. `--signed` refuses an approval no trusted approver key signed (`APPROVAL_NOT_TRUSTED`) and files it under the tree or plan it names, whatever task is current. A passkey counts on your machine when its public key is a line in `passkeys.pub` in 05's per-user directory (`<public key> <name>`, one per line); for the CI gate, list it under `[[trust.key]]` with `role = "approver"` and `person` set to the owner's name, and list the preparing machine's key (the "machine" line of `use05 key show` on that machine) with `role = "local"`. `--unsigned` includes this machine's co-signature (`details.cosignature`); the signer puts it in the envelope next to the passkey's own entry. A passkey approval counts only with that co-signature and only for the person who owns the work; otherwise it is filed but does not count, and `--signed` and the brief say why. Passkeys approve and reject; they cannot bypass.

**Break glass.** To let one exact change through a block, with a reason:
```sh
use05 bypass --reason "Hotfix for the outage, reviewed on the call"
```
It lasts 4 hours by default (`--hours`), needs your passphrase, is logged, and shows in the brief. A folder or file listed in `absolute`, or any rule when `bypass = false`, cannot be bypassed. Agents can never bypass.

## Testing before a push

A policy can ask that the developer tried the change in their own development environment before it is pushed to chosen branches. In the policy:
```toml
[testing]
local = "required"          # off | skippable | required
branches = ["main"]         # optional; by default the branch changes land on
```
When you have tried it, sign off with a short note of what you tried:
```sh
use05 approve --tested --note "Signed up, paid an invoice, checked the receipt email"
```
Where the policy says `skippable`, you may skip it instead, saying why: `use05 approve --skip-testing --reason "Only a comment changed"`. Both need your approver passphrase, so an agent cannot sign off for you, and both are bound to the exact code: change it afterwards, and sign off again.

The pre-push hook holds a push to those branches until there is a sign-off (`TESTING_REQUIRED`), and so does the CI gate, for the branch a pull request or a merge queue merges into, or the branch pushed, so skipping the hook does not get around it. Without `branches`, the landing branch is the policy's `[branches] target`, else the host's default branch (in GitHub Actions), else origin's; never the target an agent declares. A CI run that names no branch at all is held as if it went to the landing branch. An approval never counts as a sign-off: accepting a change is not trying it. The sign-off, with its note, is filed with the change's receipts, shows in the brief under Tested, and, with your own console, on the task's page, where the person driving the work can also sign off from their phone with their passkey (`--unsigned` and `--signed` work for testing as they do for approvals).

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

**Work left behind.** An agent that stopped halfway leaves its worktree and branch, and the task keeps asking for a person. `use05 discard <task>` throws it away: it shows what would go (the worktree, the branch here and on origin) and what would be lost that exists nowhere else (commits on no remote branch and not landed, files never committed), and asks you at the terminal. Then it removes them and records the task as discarded, so briefs and gates stop asking about it. It never deletes the branch where work lands or one the policy keeps, never discards while an agent's session is still working on it, and does nothing if the work moved since you looked. An agent cannot discard: it needs a person at a terminal, or your passkey from your console (**Discard this work** on the task's page, where work untouched for a week is marked as looking abandoned). Receipts already pushed stay as they are.

## Configure: `.05/policy.toml`

`use05 init` writes the file with comments, and `use05 policy --edit` changes it by asking the setup questions again, so you rarely need to edit it by hand. To change one rule, change just that rule; the rest of the file, comments included, stays as it is:
```sh
use05 policy set testing.local required
use05 policy add protect.paths "billing/**"
use05 policy add require '{ when = ["src/api/**"], also = ["docs/api/**"], why = "the API docs" }'
use05 policy remove require 1           # a rule by its number, or by its name
```
Each prints the setting before and after, and says so when the change makes the rules less strict. `use05 policy` shows the effective value of every setting and where it came from. A change is held to the rules at its **base**, never its own, so editing the policy is itself a change a person approves before it takes effect.

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
| `[branches] fresh_base` | `"allow"` (new setups write `"warn"`) | An agent that starts behind origin's copy of the landing branch. When it is not `allow`, the hook fetches that branch when a new session starts (not on a resume or compaction; giving up after 5 seconds, and never asking for a password or passphrase) and tells the agent how far behind it is and how to update. Until the work contains what origin had, the brief reports `BASE_STALE`: `warn` notes it, `approval` asks a person, `deny` refuses. When the agent updates, by rebasing or merging, the commits it pulled in are not counted as its change, including any pushed after its session started. Checked on your machine only, not by the CI gate. |
| `[record] middle` | `"local"` | What agents did is recorded on this machine and never uploaded. `off` records nothing. |
| `[enforce] on_error` | `"open"` | If 05 itself fails: `open` lets the change through and says so loudly; `closed` refuses it. |
| `[env] allow` | unrestricted | If set, the only environment variables any check may be passed. |
| `[[trust.key]]` `name`, `role`, `public`, `expires`, `person` | none | A public key whose signatures count: `role = "runner"` for a CI runner (authoritative), `"approver"` for a person's approval key, `"local"` for another machine (advisory). `public` is the contents of the `.pub` file; `expires` (for example `"2027-12-31"`) stops trusting it after that date. `person` (0.0.7 and later) is whose key it is, as git records their name: a passkey approves only that person's work, and a machine key prepares approvals only for them. Use 0.0.7 or later everywhere that reads the policy (set `[use05] min_version = "0.0.7"`): an older use05 refuses a policy with `person`. See the CI gate guide. |
| `[[require]]` `when`, `also` | none | Files that must change together. A change that touches anything in `when` must also touch something in `also`, or the brief reports `ALSO_CHANGE_MISSING`. For example `when = ["src/api/**"]`, `also = ["docs/api/**"]`; `when = ["**"]` means every change. Optional: `severity` (`approval` by default; `warn` or `deny`) and `why`, which the agent and the brief are told. 05 checks only that a file there changed, not what the change says. Any number of rules. |
| `[testing] local` | `"off"` | Whether a person must try a change in their own environment before it is pushed: `skippable` asks for a sign-off and lets them skip it with a reason; `required` takes only a sign-off. See [Testing before a push](#testing-before-a-push). |
| `[testing] branches` | the landing branch | Which pushed-to branches need it, as patterns such as `main` or `release/*`. |
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

   Also available: `intent_mode`, `check` (required checks), `drift_dependencies`, `drift_overlap`, `drift_claims`, `approvals_expire_days_max`, `record_middle`, `enforce_on_error`, `env_allow`, `trust_key`, `risk_rules`, `risk_exempt_allowed`, `protect_absolute`, `protect_append_only`, `protect_no_delete`, `protect_no_read`, `protect_bypass`, `branches_fresh_base` and `require` (rules added to every repository's).
2. Sign it with the organisation's key (make one with `use05 key new org.key`):

   ```sh
   use05 policy org-sign floor.toml --org Acme --key org.key --out org.json
   ```
3. On each machine, put `org.json` and the organisation's public key, named `org.pub`, in 05's config directory: `~/.config/05/` (or `$XDG_CONFIG_HOME/05/`, or `$USE05_HOME`). From then on, a missing or tampered `org.json` is an error, not a silent fallback.

## Turn on the CI gate

Hooks and the pre-push hook run on your machine, where an agent running as you can reach them, so they are advisory. The CI gate is what enforces: a runner the agent cannot reach runs the checks and signs the result, and your Git host refuses a push without it. It takes about ten minutes, once per repository: see [Turn on the CI gate](turn-on-the-ci-gate.md).

## Your own console

The console is a web app you host yourself, for you or your team. From your phone you see what every agent on your machines is doing, approve the work that waits for you with a passkey, edit policies, and get an email when something needs you. There is no 05-run service: your console holds your team's activity and nobody else's.

**What it can read: none of your work.** Everything is encrypted end to end. Each machine seals what it reports (plans, file and folder names, checks and verdicts, the policy) to your team's key and signs it with its own; your browser checks the signature, opens it, and builds every page itself. The policy editor runs in your browser too. The console keeps sealed bytes and what it needs to route them: which machine, which repository (by an opaque id), what kind, when, and who must approve what. Emails say only that something needs you. Code, diffs, prompts and the agent's messages never leave the machine at all.

**What it cannot do.** Machines connect out to it; it never reaches into a machine. A machine runs nothing it is sent: it files a signed approval only of a statement it prepared itself, co-signed with its own key, and applies only policy edits that tighten the rules, checked again on the machine. So someone who took over the console could not read your work, run anything on your machines, or approve anything a machine did not ask for.

**The honest limit.** The web app's code comes from the console. Whoever controls the host could serve a page that reads what you unlock in that browser, or that shows you one thing and asks your passkey to sign another: a real approval, a policy edit, or a new team key for your machines. Host it where only you or your team can change it. Machines and CI keep their own checks even then: nothing runs that a machine did not prepare, and a policy edit only tightens. Two smaller limits: the console can show an older copy of a record to a browser that never saw the newer one (a browser that did refuses it), and someone who left could, working with whoever runs the host at the moment the key changes, take the copy of the new key meant for one member; that member then cannot unlock, and the admin's browser refuses it outright if it saw that member's key before.

**Run it.** One container image. Its data is one SQLite file, so give it a volume:

```sh
docker run -p 8080:8080 -v console-data:/data \
  -e ORIGIN=https://console.example.com \
  ghcr.io/use05-dev/use05-console
```

| Setting | What it is |
|---|---|
| `DATABASE` | The database file. In the image, `/data/console.db`; the console creates it and its tables on start. |
| `ORIGIN` | The address people open, with `https://`. Passkeys are tied to its host name, so choose it before anyone signs up: moving later means adding passkeys again. |
| `RP_ID` | The passkey site, if not `ORIGIN`'s host. |
| `SETUP_SECRET` | Optional: a claim code of your own. Without it, the console makes one each time it starts while it has no owner, and writes it to its log. |
| `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`, or `SMTP_URL` | Email: Cloudflare Email Service, or any SMTP server (`smtps://user:password@host:465`). Without either, alerts show in the console only. |
| `ALERT_FROM` | The address emails come from. |
| `PORT` | Default 8080. |

Put it behind HTTPS (passkeys need it), on a host only you or your team control. To back it up, copy the file while the console runs with `sqlite3 /data/console.db ".backup /data/backup.db"`; it holds sealed records the backup cannot read either. A host that mounts volumes owned by root (Railway, for one) needs the container to run as root to write there: on Railway, attach a volume at `/data` and set `RAILWAY_RUN_UID=0`.

**Claim it, then invite people if you want.** Until someone has made a passkey, whoever signs up first would own the console, so the first sign-up needs the claim code the console writes to its log when it starts (`05 console has no owner yet … claim code: ABCDE-FGH23`; on Railway, the service's deploy logs; with Docker, `docker logs`). Run `use05 cloud login ORIGIN` on your machine: it asks for the code, opens a one-time link where you give your name and make your passkey, and then pairs the machine. (Or open `ORIGIN` and type the code there.) You are the console's admin. You stay signed in until you have not used it for an hour, also when you open it from a link in an email; after that, or in a new browser, one passkey tap signs you in again. Open pages update as soon as anything changes.

If you work with others, admins invite people from **Team**. Admins invite people from **Team**: an invitation is a link that works once, for 48 hours, and each person makes their own passkey. Admins remove people, which ends their sessions and cuts off their machines at once. The person removed still holds the team's key, so removing them also makes a new one (one passkey tap by the admin), sealed to everyone who stays; the team still reads what came before. Each person then confirms the new key for their own machines from **Home**, with their passkey. A machine takes it only from a passkey pinned on it with `use05 cloud enrol`; until then it keeps sealing to the old key. Each person sets and confirms their own email under **Settings**, and uses the name git records them under (`git config user.name`), so approvals from their phone match their own work in CI.

**Passkeys and the recovery code.** Your passkey signs you in, approves, and unlocks your key to the team's records, which needs a passkey with the PRF feature: iCloud Keychain on iOS 18 or macOS 15 and later, Google Password Manager, a recent Chrome, 1Password, or a YubiKey 5. When you join you get a recovery code, 32 letters and digits, shown once. Keep it somewhere safe: it unlocks your key on a device whose passkey cannot (a passkey without PRF still signs you in), and it is the only way back if you lose your passkeys. Make a new one under **Settings**; it replaces the old.

**Pair a machine.** `use05-cloud` comes with 05 (0.0.7 and later). On each Mac or Linux machine:

```sh
use05 cloud login https://console.example.com   # shows a word to type under Machines, then a code
use05 cloud add                                   # in each repository you want to see
use05 cloud enrol                                 # pin your passkeys here, at the terminal
use05 cloud install                               # keep it running in the background
```

Run `login` inside a repository and it does the other three for that repository too, asking you to confirm each passkey; elsewhere, or with no person at the terminal, it says what is next.

`install` keeps the helper running: a launchd job on macOS, a `systemd --user` service on Linux (run `loginctl enable-linger $USER` to keep it running while you are logged out). Where there is neither, such as a container, it prints the command to run under your own supervisor. `use05 cloud status` says which, and where its keys are: files only you can read, which an agent running as you can still reach.

`login` shows a word; type it in the console, which only someone at that terminal can do. Then the terminal and your browser each show a code, worked out from your console's key, the machine's keys and a random number from each side; pair only if the two are the same, or the console has swapped a key. A machine belongs to whoever pairs it: only they can approve the work done on it. Another machine reporting a repository that one already reports waits until an admin allows it.

**For phone approvals to count in CI,** list each person's passkey under `[[trust.key]]` with `role = "approver"` and their `person`, and the machine that prepares their approvals with `role = "local"` and the same `person`; see [Turn on the CI gate](turn-on-the-ci-gate.md).

**Cloud agent sessions.** For 05 to hold work done in Claude Code or Codex in the cloud, it has to travel with the repository: run `use05 init --shared-hooks` and commit `.claude/settings.json`. In a Claude Code cloud session (and only there) the first hook installs this version of 05 when the session lacks it, and, when the session has a token, reports to your console. Make the token under **Machines**, *Cloud sessions and CI*, for one repository; in Claude Code store it in the cloud environment as `USE05_SESSION`. A session's token reports for that repository only, as you, and is sent nothing to run; what it reports shows as coming from the cloud session, and never replaces what a machine paired at a terminal reported. When someone leaves and the team's key changes, every token made before stops working (the Machines page says which): make new ones. The agent can read it, so treat what a session reports as the session's word. Codex cloud runs its agent offline by default, so there the work's receipts travel in the repository and CI reports for it (below). In both, CI is the strong control: local hooks are advisory everywhere.

**CI on the console.** Make a token for CI the same way and store it as the CI secret `USE05_CI`, next to `USE05_RUNNER_KEY`. Around the CI gate:
```sh
use05-cloud ci collect                            # file approvals signed on the console since the last run
use05 gate --ci --json > gate.json || true        # the gate, as before
use05-cloud ci report gate.json                   # the verdict, sealed to your team
```
The repository's page then shows CI's latest verdict, or "CI gate not seen" while nothing has come. When CI holds work for a person and no machine can prepare the approval (a cloud session that has ended, work done without 05), `report` prepares it for the person who made the token, co-signed by the runner key, and asks on the console; they approve with their passkey, and the next run's `collect` files it. It asks only when an approval would clear something: a missing testing sign-off is given at a terminal. For it to count, the policy lists their passkey with their `person` and the runner key with `role = "runner"`. Asking someone other than the token's person is not built yet.

**Edits from the phone only tighten.** The console may change where agents may work and how strictly 05 holds them, and only to make it stricter: protect or lock more, raise a strictness, require more. Anything that loosens a rule, and anything that decides what runs, what is trusted or what counts as proof, is changed at a terminal.

## Commands

| Command | What it does |
|---|---|
| `use05` | Where you stand: the task, whether the staged change would be allowed, which controls are on. |
| `use05 init` | Set up this repository, asking a few questions on a terminal: policy, keys, hooks. Shows exactly what it changes. Also `--team`, `--target`, `--env`, `--defaults`, `--guided`. |
| `use05 start "<title>" --scope <glob>` | Begin a task: what you are about to do and where. Several patterns go in one `--scope`, separated by spaces or commas, or in several. Also `--goal`, `--exclude`, `--check`, `--no-new-deps`. |
| `use05 finish --outcome "<text>"` | Record what was done, in the author's words. Treated as a claim, never a fact. |
| `use05 prove [names] [-- command]` | Run checks on the change and sign the result. |
| `use05 brief` | The one page a person reads. `--json` for data, `--fetch` to pull others' receipts first. |
| `use05 approve` | Approve or reject a plan (`--intent`) or a finished change (`--outcome`); `--tested --note` signs off that you tried it, `--skip-testing --reason` skips that where allowed; `--unsigned` and `--signed` for a passkey or another signer. |
| `use05 bypass --reason "<text>"` | Let one exact change through a block, for a stated reason. Logged. |
| `use05 land` | Move an allowed change into its target branch, then clean up its branch and worktree. |
| `use05 discard <task>` | Throw abandoned work away: its worktree and branch, here and on origin, after showing what would be lost. Needs a person at the terminal; `--unsigned` and `--signed` for a passkey. |
| `use05 verify <receipt>` | Check a receipt offline: no account, no network. |
| `use05 policy` | The effective policy, and where each setting came from. `set`, `add` and `remove` change one rule; `--edit` changes it through the setup questions. |
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

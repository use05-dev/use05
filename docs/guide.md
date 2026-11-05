# Using 05

How to install 05, set it up in a repository, work with it day to day, and configure it. For what 05 is and why, see the [README](../README.md) and [use05.dev](https://use05.dev).

- [Install](#install)
- [Set up a repository](#set-up-a-repository)
- [Working with an agent](#working-with-an-agent)
- [Working by hand](#working-by-hand)
- [Reading the brief](#reading-the-brief)
- [Approving, rejecting and bypassing](#approving-rejecting-and-bypassing)
- [Testing before a push](#testing-before-a-push)
- [Long sessions, large changes and subagents](#long-sessions-large-changes-and-subagents)
- [Several agents at once](#several-agents-at-once)
- [Environments and promotion](#environments-and-promotion)
- [Configure: `.05/policy.toml`](#configure-05policytoml)
- [Organisation rules](#organisation-rules)
- [Turn on the CI gate](#turn-on-the-ci-gate)
- [Your own console](#your-own-console)
- [Commands](#commands)
- [Exit codes and environment variables](#exit-codes-and-environment-variables)
- [Upgrade and uninstall](#upgrade-and-uninstall)

## How 05 works

- **A sealed plan.** Before its first edit, an agent declares what it will do and where (`use05 start`). 05 seals the declaration where the agent cannot change it, and holds the agent and its subagents to it.
- **Receipts.** `prove` runs a check on an exact git tree and signs the result: an in-toto statement in a DSSE envelope, signed with Ed25519 (see [Receipt format](receipts.md)). Anyone can verify one offline with `use05 verify`. Receipts live on ordinary `05-receipts/<key>` branches, so they travel with the repository.
- **A gate of fixed rules.** No model judges anything. The gate compares the plan, the files changed, the evidence on the exact tree, approvals and protected paths, and answers allow, wait, approval required or deny. A change is held to the rules at its base, never its own, so it cannot loosen them.
- **A record you can check later.** What the agent did (tools, paths and decisions; never contents or prompts) is a hash-chained log, sealed by signed receipts as the work happens and countersigned by CI. Anyone with the repository and the public keys can check it.
- **Honest about strength.** The agent's hooks and the pre-push hook are advisory: an agent running as you can reach them. Evidence signed by a CI runner key the agent cannot read, with a required check on your Git host, is what enforces. `use05 doctor` and the brief say which is which.
- **What it is not.** Not an agent, not a code reviewer powered by a model, not a Git host. 05 shows what was checked; it does not judge whether a change is correct.

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

## On Windows

05 runs on Windows inside WSL (Windows Subsystem for Linux), as the Linux build; there is no native Windows build. In a Windows terminal run `wsl --install` once, restart, and open the Linux shell (Ubuntu). Then, in that shell:

```sh
sudo apt install git nodejs npm     # if they are not there yet
npm i -g @use05/cli
mkdir -p ~/code && cd ~/code && git clone <your repository> && cd <your repository>
use05 init
```

Clone the repository inside WSL (`~/code`), not under `/mnt/c`: Git and the hooks run many small commands, and on a Windows drive each one is slow. `use05 doctor` warns when the repository is on one (`This repository is on a Windows drive (/mnt/c); hooks are slow there. Clone it inside WSL (~/code).`). Run Claude Code and Codex inside WSL too, so their hooks find `use05`. Touch ID is not available there; approvals use the passphrase key.

## Set up a repository

```sh
cd your-repo
use05 init
```

On a terminal, `init` first asks a few questions, each with a default you accept by pressing Enter:

1. **Who works in this repository:** just you, a small team, or a larger or regulated team. This sets how strict the rules start; you can change each one afterwards.
2. **Which branch finished changes land on.**
3. **Which environment each long-lived branch is:** dev, uat, pre-prod, prod, another environment you name, or not an environment. 05 suggests a level from the branch's name (`main` is dev, `staging` is uat, `production` is prod). A level can hold several environments: pick dev for a second branch and you name it, for example `dev-eu`. 05 shows them, and judges a promotion from one to the next under rules you set (see [Environments and promotion](#environments-and-promotion)).
4. **The checks that must pass**, and any you want to add (`lint: npm run lint`). In a monorepo (npm, pnpm or yarn workspaces, Cargo, Go, uv) it shows one check per package and asks once whether to use them; see [Monorepos](#monorepos).
5. **Folder and file rules:** what needs a person's approval, what is locked, where only new files may be added (it suggests migration folders it finds), what agents may not read (it suggests `.env*` if you have one), and which folders must be updated with every change, such as `docs/**` or `CHANGELOG.md` (a `[[require]]` rule on `**`; narrower rules go in the file).
6. **How strict to be** when an agent works outside its plan, when a change weakens tests, and when an agent starts from older code than origin has.
7. **How finished changes land:** you run `use05 land`, or automatically when 05 allows it (the default when you work alone). And who pushes them: you, or 05.

It then shows a summary and asks before writing anything. To change your settings later, run `use05 init` again or `use05 policy --edit`: the same questions, with your current settings as the defaults. Your comments and any settings the questions don't cover are kept.

The answers can also be flags, for scripts: `use05 init --team small --target main --env dev=main --env uat=staging --env prod=production`. An environment whose name is not a level gives its level after a colon: `--env dev-eu=eu-main:dev`. `--defaults` skips the questions; `--guided` asks them even without a terminal, reading the answers from stdin. A question nobody answers for ten minutes ends the setup with `No answer in 10 minutes; nothing was written.` and exit 1 (`INIT_NO_ANSWER`; `POLICY_NO_ANSWER` for `use05 policy --edit`); the end of piped answers still stops it at once, as before. `use05 init --defaults` sets up without asking.

Then `init` lists exactly what it changed, and what is still not covered. It:

- writes `.05/policy.toml`, your rules, with a `test` check guessed from your project;
- creates a signing key for this machine;
- at a terminal, makes your approver key, if you have none yet (Touch ID on a Mac that has it; see below);
- installs hooks for Claude Code (if `.claude/` exists) and Codex (if `.codex/` exists);
- installs a git pre-push hook;
- adds a short block to `AGENTS.md` so agents know how 05 works.

At a terminal, `init` then offers to commit what it wrote as "Set up 05"; otherwise it prints the exact `git add … && git commit` line. The policy counts at a push and in CI only once it is committed: until then they hold changes to 05's defaults. Your first push of the setup changes 05's own rules, which are always protected, so the pre-push hook shows why and asks "Approve it now?": say yes and confirm with Touch ID or your passphrase, once, and the push goes on. Then run `use05 doctor`: it checks the setup and says how strongly each control is enforced. Until you turn on the CI gate, everything is advisory, and doctor says so.

`use05 init --no-hooks` skips the hooks, `--no-agents-md` leaves `AGENTS.md` alone, and `--ci github` also writes the CI workflow. `use05 uninstall` reverses exactly what `init` did.

To approve changes you need an approver key that an agent cannot use. `init` makes one at a terminal; to make one yourself:
```sh
use05 key new --approver
```
On a Mac it offers **Touch ID**: the key is made inside the Mac's Secure Enclave and never leaves it, and the Secure Enclave signs only when you are there, with Touch ID or, on a Mac without a sensor, your Mac's password in the system's own dialog. Elsewhere, or with `--passphrase`, the key is protected by a passphrase the agent does not have. `--touch-id` asks for Touch ID outright. You can have both; break glass (`use05 bypass`) needs the passphrase key. A Touch ID approval is a passkey signature co-signed by this machine, so CI checks it as it checks a phone's: see [Phone approvals in CI](turn-on-the-ci-gate.md#phone-approvals-in-ci).

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
5. **You read one line, in the agent's window.** When Claude Code stops and 05 has nothing to ask of it, 05 tells you where the work stands and the one thing to do, if any, and says it again only when it changes:
   ```text
   05: "Cap payment retries" passed its checks and landed on main. Push when you are ready: git push origin main
   05: allowed, nothing to read (3 files, checks passed). Land it: use05 land
   05: allowed, nothing to read (1 file; no checks ran, behaviour not verified). Commit and push when you are ready.
   05: needs you (3 files): 1 protected file(s) changed. Approve: use05 approve
   ```
   With land set to automatic (the default when you work alone), work the gate allows lands on its own. Nothing to read means nothing to do. When the policy requires no check, the line says so (see [What the checks line means](#what-the-checks-line-means)).
6. **You approve, only if asked.** `use05 approve` shows what holds the change back and asks for Touch ID or your passphrase. Once the approval counts, the work lands too: on its own when the policy lands automatically, else it asks "Land it on main now?" (`--land` skips the question). `use05 brief` is there whenever you want the whole page.
7. **It is pushed.** After landing, 05 asks "Push main to origin now?" at a terminal; `use05 land --push` pushes without asking, and `[branches] push = "auto"` pushes every time. The push goes through the pre-push hook like any other. No pull request is needed. If your team wants pull requests, push the branch and open one; the CI gate checks it either way.

So a change that matches its plan and passes its checks takes nothing from you, or one yes to push; a change that needs you takes one approval, where you already are.

Bare `use05` is one page for the repository: the tasks that need you, the agents working now, what finished recently (marked when its work has already landed), whether the staged change would be allowed, your environments and which controls are on. Every task line carries its id. On a terminal its first menu entry is the one thing to do next (approve the task waiting for you, land one that is allowed, run the checks), and Enter does it; **Open a task** picks any task and offers its brief, its approval or discarding it. When you approve every change a rule holds back (five or more in 30 days, never a refusal), the page says so under **Tip**, and `use05 doctor` too: that rule costs attention and catches nothing, and `use05 policy --edit` loosens it. 05 counts; it never changes a rule itself. Outside a repository it lists every repository on this machine that 05 has been used in (see [Several agents at once](#several-agents-at-once)).

Any other agent with hooks of its own can call `use05 hook generic` (see [Extending 05](extending.md)). Every agent, hooks or not, is covered by the pre-push hook and the CI gate.

## Working by hand

Without an agent, you commit and push as you always have:

```sh
git commit -am "Stop retrying failed charges"
git push
```

The pre-push hook runs the required checks that have not run on what you push, signs the result and gates the push. When the push needs a person (billing is a risk area, say), it shows why and asks "Approve it now?" at the terminal: yes, then Touch ID or your passphrase, and the push goes on. Under an agent or in CI there is no terminal, so it is never asked there; the push stops and says what it needs.

The rest of the flow is there when you want it. Work on a branch of your own and `use05 land` moves it onto the landing branch, never from the landing branch itself:

```sh
git switch -c retries
use05 start "Stop retrying failed charges" --scope "src/billing/**"   # a declared plan, held to like an agent's
# … make the change …
git commit -am "Stop retrying failed charges"
use05 prove                  # run the policy's checks on exactly these files and sign the result
use05 brief                  # the one page
use05 approve                # only if the brief asks for it; then it offers to land and push
```

`use05 prove` runs every required check. `use05 prove test lint` runs named checks; `use05 prove -- cargo test` runs any command. Checks run on a copy of exactly those files (the staged ones if anything is staged, else the working tree), with a scrubbed environment. A failing check still gets a receipt that records the failure.

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

**Another task than the current one.** `brief`, `finish` and `land` work on the current task; `--task <id>` names another (bare `use05` shows ids). With `--task`, `brief` and `approve` look at that task's own checkout (the worktree its branch is checked out in), wherever you run them. `approve` without `--task` picks for you; see [Approving](#approving-rejecting-and-bypassing). `brief`, `prove`, `approve` and `bypass` look at the staged files, else the working tree; `--tree index`, `--tree worktree` or `--tree <commit>` picks.

## Reading the brief

`use05 brief` is the one page a person reads instead of the diff. `use05 brief --json` prints the same as data.

| Section | What it tells you |
|---|---|
| Story | The change in a few lines, each saying where it comes from, so you can stop there: **asked** (the person's words, when the agent's hooks kept them), **agent says** (its own report of what it did, marked as its own words, and how many of its claims a check backs, contradicts or has nothing to say about), **05 saw** (files and areas, work outside the plan, test files the change edits, risk areas, other sessions on the same files), **checked** (the checks line below), **needs you** (the first reasons it is held, at most three) and **not known**. An agent's words are never shown as something 05 found. It also says where the tests come from, as far as file names and your rules tell: edited by this change (it partly grades itself), under `[protect]` rules (`paths`, `locked`, `absolute` or `append_only` cover every file named like a test, so changing one needs a person), or not protected (a change could rewrite them); `assurance.test_origin` in `--json`. That says who could change the tests, never that they are good or check what was asked. In `--json` the story is `brief.story`. |
| Intent | What was asked and what the agent declared: goal, scope, checks, the agent and the person accountable for it, and how risky the change is (auth, money, migrations, secrets, deployment). |
| Outcome | How many files and lines changed, grouped into at most eight areas with lines added and removed, and anything outside the declared scope, grouped by area. |
| Evidence | Each required check: passed, failed, missing or stale, and who signed it. A check signed on your machine is marked advisory; one signed in CI is not. A check that names `paths` the change does not touch is listed as not required and never blocks. |
| Drift | Each place the change departs from the plan or the rules, with a stable code: `SCOPE_EXCEEDED`, `TESTS_WEAKENED`, `PROTECTED_PATH`, `LOCKED_PATH`, `OVERLAP`, `ALSO_CHANGE_MISSING`, `BASE_STALE` and others. |
| Approvals | Who approved or rejected, and whether each approval still counts. |
| Owners | When the change touches paths the policy gives owners: who owns each, how many approvals it needs, and which owners approved. See [Owners of paths](#owners-of-paths). |
| Session | For agent work, what happened during the session in at most four lines: how long it ran, turns and tool calls, what 05 refused and why, which checks ran along the way and how they ended, and which subagents took part. |
| Log | Whether the record of what the agent did is intact, and how strongly it is sealed. |
| Unknowns | What 05 could not establish. 05 shows what was checked; it never judges whether the change is correct. |
| Undo | How to back the change out. |

It ends in one decision:

- **ALLOW, nothing to read**: the change matched its plan, and every check the policy requires passed. If the policy requires none, the line under it says so.
- **ALLOW, read the notes**: allowed by your policy, but something is worth knowing.
- **WAIT**: evidence is missing, usually a check that has not run on this change. Run `use05 prove`.
- **APPROVAL REQUIRED**: a person must approve. The brief lists what holds the change back and the command for each.
- **DENY**: a rule no approval clears, such as a change to a locked file.

### What the checks line means

Under the decision (and under its reasons, if any), the brief says how much the decision rests on. It is not a score, and it never changes the decision:

```text
✓ ALLOW  nothing to read
  Checks: 1 passed on the machine that ran it (advisory: an agent can run as its user)
  Behaviour beyond these checks: not assessed
```

- **Checks** counts the checks required for this change: how many passed, and who signed them. "On the machine that ran it" means a machine key signed the result, which is advisory: an agent running as that user can sign too. "Signed by CI (merge enforcement not confirmed from here)" means a runner key signed the result; whether your Git host requires the gate before merging is something 05 cannot see from a run. Checks that failed, did not run on this tree, are stale or were signed by a key the policy does not accept are counted first, and never as passed.
- **Note** appears when checks ran and the change edits test files itself ("this change also edits 1 test file(s), so it partly grades itself").
- **Behaviour beyond these checks: not assessed.** 05 knows what the checks' commands returned, not whether the change does what was asked.

With no check required, it is one line, and the decision still stands:

```text
✓ ALLOW  nothing to read
  Checks: none required; behaviour not verified
```

The agent's window and the bare page say the same in a few words: "05: allowed, nothing to read (1 file; no checks ran, behaviour not verified)". `use05 brief --json` carries it as `brief.assurance`: the counts (`checks_required`, `passed`, `failed`, `missing`, `stale`, `not_accepted`, `not_required`, `local_only`, `tests_changed`), `evidence` (`none`, `local_advisory`, `runner_signed` or `mixed`), `behaviour` (`not_assessed`), `enforcement` (`ci_gate` in the CI gate's own run, else `unknown`), `summary` (the checks line) and `limitations`. `enforcement = "ci_gate"` names where this run happened, not what enforces merges: whether your Git host requires the gate is never known from a run. Every other field is as it was.

## Approving, rejecting and bypassing

```sh
use05 approve --intent       # approve a plan before the work, when the policy asks for it
use05 approve --outcome      # approve the finished change (the default)
use05 approve --reject --reason "Retries must stay at five"
```

**Which task.** Without `--task`, `approve` finds every task in this repository that waits for a person (its plan or its change; tasks untouched for two weeks are left out unless they are the only one). If one waits, it says which and asks for Touch ID or your passphrase. If several do, at a terminal it lists them (title, id, what it needs, agent, when it last changed) and you pick one by number; under an agent, in CI or in a pipe it never asks, and fails with `TASK_AMBIGUOUS`, listing them and saying `use05 approve --task <id>`. If nothing waits it says so (`NOTHING_WAITS`). What you approve is that task's own work, in the worktree its branch is checked out in, not whatever the directory you ran it in holds.

You confirm with Touch ID (or your Mac's password) when you have a Touch ID approver key, else with your approver passphrase; `--passphrase-stdin` always uses the passphrase key. An approval is signed, tied to the exact content and the policy, and expires after `approvals.expire_days` (7 by default).

**Then it lands.** An approval of a task's finished change that counts, for work the gate now allows, lands it: without asking when `[branches] land = "auto"` or with `--land`, else after "Land it on main now?" at the terminal. Then it is pushed, as after `use05 land`. Without a terminal and without either, the next step says `use05 land --task <id>`. An approval filed from your console lands the work the same way when the policy lands automatically. If the change moves on, the approval no longer counts and the brief says so. So does an approval prepared elsewhere that is dated ahead or made to last longer than `approvals.expire_days`: 05 checks the dates against your policy, not against what the approval says.

**Across machines and CI.** Approvals and receipts live on ordinary git branches (`05-receipts/<key>`). Add `--push` to `approve`, `bypass` or `prove` to push that branch to `origin`, and `use05 brief --fetch` pulls everyone else's first. In scripts, `--passphrase-stdin` reads the passphrase from the first line of stdin instead of the terminal (for `approve`, `bypass` and `key new --approver`).

**Approving with a passkey, or anything that signs elsewhere.** A person can also approve with a passkey (Face ID, a fingerprint, a security key), from a page that holds it. 05 prepares the statement and files the signed result; the signing happens elsewhere:
```sh
use05 approve --unsigned --json      # the exact statement and the passkey challenge; nothing is signed or stored
use05 approve --signed approval.json # file it, if a key you trust as an approver signed it
```
`--unsigned` takes the same `--intent`, `--reject`, `--reason`, `--task` and `--tree` as a normal approval. `--signed` refuses an approval no trusted approver key signed (`APPROVAL_NOT_TRUSTED`) and files it under the tree or plan it names, whatever task is current. A passkey counts on your machine when its public key is a line in `passkeys.pub` in 05's per-user directory (`<public key> <name>`, one per line); `use05 cloud enrol` writes it. A passkey approval counts only with the co-signature of the machine that prepared it (`details.cosignature` in the `--unsigned` output) and only for the person who owns the work; otherwise it is filed but does not count, and the brief says why. Passkeys approve and reject; they cannot bypass. For passkey approvals to count in CI, see [Turn on the CI gate](turn-on-the-ci-gate.md#phone-approvals-in-ci).

**Break glass.** To let one exact change through a block, with a reason:
```sh
use05 bypass --reason "Hotfix for the outage, reviewed on the call"
```
It lasts 4 hours by default (`--hours`), needs your passphrase key (not Touch ID), is logged, and shows in the brief. A folder or file listed in `absolute`, or any rule when `bypass = false`, cannot be bypassed. Agents can never bypass.

### Owners of paths

A policy can say who must approve a change to some paths:
```toml
[[signer]]
name = "eng-managers"
people = ["Dana", "Lee"]

[[protect.owner]]
paths = ["billing/**"]
signers = ["eng-managers"]   # groups, or people's names
min = 1                      # how many different owners; 1 unless you say
```
A change that touches `billing/**` then needs, besides the approvals it needs anyway, an approval of its outcome from `min` different people in the group. Until it has them, the brief reports `OWNER_APPROVAL_REQUIRED` ("billing/** needs an approval from eng-managers (Dana, Lee): 0 of 1", next: "ask Dana or Lee to run: use05 approve --outcome --rev <commit>") and shows under Owners who owns each path and who approved. An approval from someone else does not count for the path, and the brief says so with `OWNER_APPROVAL_NOT_COUNTED` ("Bob approved, but is not an owner of billing/**"). Only approvals of the outcome count, not of the plan. When the person driving the work is an owner, their one approval covers both.

**Who counts as an owner.** Only the policy says whose a key is: the `person` on it under `[[trust.key]]`, compared ignoring case and surrounding spaces. To be counted as an owner, list each key you approve with (your approver key, your Touch ID key, a passkey) with your name and `role = "approver"`; `use05 key show` prints this machine's public keys. A machine key's `person` (`role = "local"`, a machine that prepares approvals) never makes anyone an owner, whatever other entry lists the same key. Nothing on a machine makes a key someone's: not git's `user.name`, which an agent can change. Two keys of one person count as one owner, and a key listed for two people is an error. A name in `signers` or `people` that is neither a group nor the `person` on a trusted key stops the policy from loading (`UNKNOWN_SIGNER`), as does an empty list or a `min` higher than the people named; a group may not take a person's name (`SIGNER_NAME_TAKEN`).

**Who can change who owns what.** The rules are read from the change's base, so changing a group or an owner rule is itself a change a person approves. Removing an owner rule, dropping its paths, lowering `min`, adding people to a group, or adding a group with a name a rule already uses makes the rules less strict: `use05 policy` says so, and your console refuses it. Without an owner rule on the policy itself, any approver can approve such a change, and with it change who owns what. So give the rules their own owners:
```toml
[[protect.owner]]
paths = [".05/**"]
signers = ["eng-managers"]
```
A bypass clears an owner rule only when one of that rule's owners signed it; a bypass by anyone else clears the other rules it clears, and the owned paths still wait for an owner ("a bypass of an owned path must come from one of its owners (Dana, Lee)"); until then, each finding it will clear says "(a bypass covers this once an owner of billing/** approves or bypasses it)". A change that touches several owner rules needs one bypass from a person who owns every one of them: separate owners' bypasses do not combine. With `bypass = false`, no bypass clears it. A policy that uses these needs `[use05] min_version = "0.0.14"`.

**Approving someone else's work.** An owner approves work that is not a task on their machine by its commit:
```sh
git fetch origin
use05 brief --rev origin/<branch>                 # what it changes, who owns what, and its commit
use05 approve --outcome --rev <commit> --push     # approve the commit the brief showed, and send it to origin
```
Approve the commit id the brief shows ("origin/alex/billing at commit 1a2b3c4d5e6f"), not the branch name: a branch can move between reading and signing. `--rev` measures and judges that exact commit as a push of it would be: from where it forks from origin, under the rules there; `brief --rev` measures it the same way, so what you read is what you sign. Before asking for Touch ID or your passphrase it prints the full commit id and the owned files it changes. It reads no task of yours, says which owned paths the approval counts for, and needs you at the terminal like any approval, so an agent cannot. `--push` sends it to origin, where CI finds it. An owner's passkey approval of someone else's work counts only for the paths they own (the brief says "counts for billing/** only (an owner's approval)"), never as the approval the person driving the work gives, and only with the co-signature of a trusted machine or CI runner that may prepare for them. The console does not prepare such an approval yet: from there, only the person driving the work approves.

If an organisation's rules and the repository's leave a rule with nobody who can approve it, the brief says so ("nobody in eng-managers can approve changes to billing/**"; with several groups, "… the groups A, B have no one in common"). An organisation's own owner rules count only the people its own groups name, and only through the organisation's own keys: a key the repository lists never counts for them, whatever `person` it names.

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
Where the policy says `skippable`, you may skip it instead, saying why: `use05 approve --skip-testing --reason "Only a comment changed"`. Both need you (Touch ID or your approver passphrase), so an agent cannot sign off for you, and both are bound to the exact code: change it afterwards, and sign off again.

The pre-push hook, `use05 land` and the CI gate hold a push to those branches until there is a sign-off (`TESTING_REQUIRED`), so skipping the hook does not get around it. Without `branches`, the landing branch is the policy's `[branches] target`, else the host's default branch, else origin's; never the target an agent declares. An approval never counts as a sign-off: accepting a change is not trying it. The sign-off, with its note, is filed with the change's receipts and shows in the brief under Tested. With [your own console](console.md), the person driving the work can sign off from their phone (`--unsigned` and `--signed` work for testing as they do for approvals).

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

`use05 doctor` suggests a value for it from this machine's own record of the last 30 days (event times only, no paths or contents). When at least 20 gaps between an agent's edits within one task are known and the 90th percentile differs from `reservation_idle_hours` by more than half, it says `Tip: agents here go quiet up to 41 min between edits (p90, 30 days); reservations lapse after 2 h.` and gives the command, `use05 policy set drift.reservation_idle_hours 1` (whole hours, at least 1). A shorter time is less strict, so doctor says to set it at a terminal rather than from the console, and it gives no tip for 0. In the same way it compares the newest durations of your required checks that have run (the ones that always apply, plus the longest one limited to `paths`) with `[evidence] stop_budget_secs`: if together they take longer than the budget but at most 80 seconds, it prints the command with their total rounded up to 10 seconds; if they take longer than 80 seconds, it says CI or the pre-push hook proves them, because the Stop hook has 90 seconds. Tips appear only when the policy file is committed, so the command works, and they are counted apart from what is not set up (`"level": "tip"` in `--json`). 05 only suggests; it never changes a setting itself. Doctor also says when the agent hooks an older 05 installed lack events this one installs (`Agent hooks were installed by an older 05 and lack SubagentStart, SubagentStop`); `use05 init` brings them up to date. With no required check in the committed policy, it says that 05 never runs anything to see whether a change works, so every ALLOW rests on the rules alone, and prints the `use05 policy add check` command to add one, with the test command it found where it found one.

**Every repository on the machine.** 05 keeps a list of the repositories you have used it in: `repos.tsv` in 05's per-user directory, one line per repository (`<time last seen><TAB><absolute path>`), written by `use05 init` and refreshed, at most every ten minutes, when a command or hook opens a repository 05 is set up in. It never leaves the machine and nothing reads it but 05. Run bare `use05` outside a repository and it shows each listed repository (folders that are gone are left out), the tasks waiting for you and the agents working in it, and when it was last active, the repositories needing you first; on a terminal, pick one by number to open its page. `use05 uninstall` takes the repository off the list, and deleting the file loses nothing but the list.

**Work left behind.** An agent that stopped halfway leaves its worktree and branch, and the task keeps asking for a person. `use05 discard <task>` throws it away: it shows what would go (the worktree, the branch here and on origin) and what would be lost that exists nowhere else (commits on no remote branch and not landed, files never committed), and asks you at the terminal. Then it removes them and records the task as discarded, so briefs and gates stop asking about it. It never deletes the branch where work lands or one the policy keeps, never discards while an agent's session is still working on it, and does nothing if the work moved since you looked. An agent cannot discard: it needs a person at a terminal, or your passkey from your console (**Discard this work** on the task's page, where work untouched for a week is marked as looking abandoned). Receipts already pushed stay as they are.

## Environments and promotion

Environments are long-lived branches, lowest first: dev (where work lands), then uat, pre-prod and prod, or the ones you name. Promoting moves one exact commit from an environment into the next one up. 05 judges a promotion before anything moves:

```sh
use05 promote prod --check      # judge every rule for promoting into prod; nothing moves
use05 brief --promote prod      # the one page: what moves, each rule, who must sign, what next
```

Both fetch the two branches and everyone's receipts from origin first (five seconds at most, never asking for a password); if that fails they say so in one line and use the copies this machine has. Nothing is pushed and no branch moves. Both exit with the decision, as the brief does (0, 2, 3 or 5), and take `--json`. An agent may run them too.

**Promoting.** `use05 promote prod` judges it the same way and, only when the decision is allow, moves it:

1. The move is made away from your checkout. A fast-forward is the source's head itself. With `how = "merge"`, 05 makes a merge commit on the target's head in a temporary worktree, which it removes afterwards. Your branches and files are not touched.
2. It is judged once more just before the push, against the commit it evaluated and showed. If the source moved in between, nothing is pushed (`PROMOTE_NOT_EVALUATED_HEAD`); if the target moved on origin, nothing is pushed either (`PROMOTE_TARGET_MOVED`).
3. It pushes the target branch to origin, never by force, through the pre-push hook like any push. If the push is refused, the command says so with git's own first line and the first finding a hook named (`PROMOTE_PUSH_FAILED`, exit 4): origin is as it was, no branch here moved, and no record is written.
4. Only after the push goes through, 05 signs a promotion record (`promotion/v0`: what moved, from where to where, the rollback point, each rule's result, the sign-offs and bypasses it went with) with the CI runner key in CI, else this machine's key, stores it on the receipts branch and pushes that. Your copy of the target branch follows when no worktree has it checked out. If the record could not be signed, stored or pushed, the promotion still happened, and the command says so (`PROMOTED_WITHOUT_RECORD`, exit 0) with the command that puts the record on origin: until it is there, CI holds the branch.
5. Then it confirms the deploy (below), unless `--no-wait` leaves that to `use05 promote <env> --confirm`, which CI can run once the host has deployed.

**Confirming the deploy.** 05 never deploys; your host does, from the branch. To know what an environment runs, give it probes: commands that ask it, and print the commit it runs.

```sh
use05 promote prod --confirm    # ask prod's probes which commit it runs, run its smoke checks, file the record
use05 promote prod --no-wait    # promote, and leave confirming to --confirm (in CI, say)
```

A probe and a smoke check run like a check: in a copy of the deployed commit's exact files, with a scrubbed environment, only the variables they name in `env`, `timeout_secs` for each try, in `dir` when it is set, and as `USE05_CHECK_USER` in CI. A probe shows the commit when it exits 0 and prints its id, in full or by 12 or more of its first characters, in any case (05 reads the last 4 KB it prints); a longer or different run of hex does not count. Let a probe print only the commit the environment runs, nothing else that looks like one. A probe or smoke script kept in the repository is part of what a promotion moves, so a promotion can change it; prefer probes that ask the environment from outside, such as `curl -fsS https://example.com/version`. 05 asks again every `interval_secs` (15 by default) until it does or `wait_minutes` pass (10 by default; `0` is one try). A probe whose program is not there fails at once ("could not run ./probe.sh") and the others still run. Then each smoke check runs once (`paths` does not apply to them). The deploy is confirmed only when there is a probe, every probe showed the commit and every smoke check passed. 05 then signs a deployment record (`deployment/v0`: each probe's result with a hash of what it printed, never the text, each smoke check, whether it is confirmed, and what 05 did), with the CI runner key in CI, else this machine's key, and pushes it on the receipts branch. Promoting from this environment later reads it: `source_confirmed` needs the newest record of the source's head to confirm it, and `soak` counts from the first of the unbroken run of confirmations that ends with it.

With no probe, 05 never says the deploy is confirmed. It says "no probes: 05 cannot tell what prod runs", files a record with no probes that is not confirmed, and `source_confirmed` fails for a promotion from it. `use05 promote prod --confirm` exits 5 then (`NO_PROBES`); `use05 promote prod` still exits 0, since the promotion itself went through.

**When the deploy is not confirmed** (a probe did not show the commit in time, or a smoke check failed), the command says so (`DEPLOY_NOT_CONFIRMED`, exit 2) and does what `on_failure` says:

- `report` (the default): nothing else. The record, the page and the console show it, with the one command to go back: `use05 promote prod --rollback`.
- `revert`: 05 makes a new commit on the branch's head that holds the rollback point's files, `Revert prod to <commit> (deploy not confirmed)` with the trailers `05-Revert`, `05-Reverts` and `05-Rollback-To`, and pushes it like any push, never by force. It files the revert's own record (a promotion record whose `how` is `revert` and whose `reverts` names the commit it undid), then confirms the revert once. A revert that is not confirmed either is reported, never reverted again. The failed deploy's record says `action = "reverted"`.
- `command`: 05 runs the `rollback` command like a check, as the policy at the rollback point has it and in a copy of the rollback point's files (the known good ones, not those of the deploy that failed), with `USE05_ENV` (the environment), `USE05_ROLLBACK_TO` (the rollback point) and the variables `rollback_env` names, for at most `rollback_timeout_secs` (900 by default), and records `action = "rollback-command"`. What the command does is yours; 05 moves no branch.

An automatic revert acts for whoever ran the promotion where an agent or CI may promote (`agent = true`). Where `agent = false`, a revert is a person's, signed with their key, and 05 does not ask for it after the wait: it reports the deploy and names `use05 promote prod --rollback`. A rollback command runs for a person at the terminal there; under `use05 promote prod --confirm` with no person present (CI, say), it is reported instead. 05 goes back only to the rollback point of the newest promotion record into the environment that counts (`[evidence] accept`), only when that record is of the commit that was not confirmed, and only when the point is in the branch's own history (for a merge, its first parent; otherwise an ancestor of what was promoted): a record is a machine's word, and a revert passes none of the promotion's rules. Otherwise it says why and reports.

**Rolling back by hand.** `use05 promote prod --rollback` shows the rollback point (where the newest promotion into prod that counts found the branch), makes the same revert commit, pushes it, files its record and confirms it once (`--no-wait` leaves that out). It follows the same rule as promoting: where `agent = false` only a person may, at a terminal with their key, and the agent hooks hold it; elsewhere an agent or CI may. When the branch already holds the rollback point's files there is nothing to roll back (`NOTHING_TO_ROLL_BACK`); when the promotion created the branch there is no rollback point (`NO_ROLLBACK_POINT`). After a revert, prod has a commit uat lacks, so promoting into prod is refused (`PROMOTE_TARGET_AHEAD`) until uat has it too.

**The pre-push hook on an environment's branch.** A push to the branch of an environment that is promoted into is judged as that promotion, not as a task's change: by the promotion's rules, read as `--check` reads them, and only when the pushed commit is exactly the move they judged (the source's head, or a merge of it onto the target's head on origin that adds nothing). So a promotion whose changes touch protected paths goes through when its rules allow it, and a push by hand (`git push origin uat:prod`) is held by the same rules; anything else pushed there is held (`PROMOTE_NOT_EVALUATED_MOVE`). It also lets a hotfix's landing and a back-merge through, each judged by its own rules (see Hotfixes and merging back, below), and a revert as 05 makes one: its only parent is the branch's head on origin, and it holds exactly the files of the rollback point of the newest promotion record into the environment that counts; a commit on that head with any other files is held. Where the environment is kept for people (`agent = false`), the push must come from a person at a terminal with no agent session (`AGENT_MAY_NOT_PROMOTE` otherwise). A push that cannot be judged, say because the source branch is gone, is held too (`PROMOTE_NOT_JUDGED`), whatever `[enforce] on_error` says. Deleting an environment's branch, or one `[branches] keep` names, is held unless a person deletes it at a terminal (`ENVIRONMENT_DELETE_HELD`). A branch counts as kept when any policy that may name it says so (this checkout's, the one on the branch itself, or origin's default branch's), and a deletion is held when none of them can be read; and the agent hooks refuse `git push origin :prod` and `git push origin --delete prod`. The landing branch keeps the task gate, except for a back-merge into it. The hook does not ask for the promotion's record, which is written after the push; CI does.

A merge commit carries the promotion's summary at the end of its message, as git trailers, after each sign-off in its signer's words:

```text
Promote uat into prod (3f2a1b9c0d4e)

2 commits move from uat.

Dana signed off: Tried checkout and refunds in uat.

05-Promotion: prod from uat
05-Source: 3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345
05-Rules: source_checks=pass,source_confirmed=pass,soak=pass,migrations=pass,untasked=pass,sign_off=pass
05-Signed-off-by: Dana
05-Bypass: soak
```

A fast-forward makes no commit of its own, so its summary is only in the record. Held back, `use05 promote` moves nothing and exits with the decision (2, 3 or 5), its code being the first finding that holds it (`SIGNOFF_REQUIRED`, say).

**Who may promote.** Where the environment says `agent = false` (by default the last rung), only a person promotes, and 05 asks for positive proof of one: a terminal, no agent session, and the person's own key (Touch ID or the passphrase), which signs the record beside the machine's. Without a terminal (CI, a pipe, `--json`) it is refused (`NEEDS_A_PERSON`, exit 3): no agent session is no proof of a person by itself. The agent hooks hold `use05 promote prod` there too, and point the agent to `--check`. Where `agent = true`, an agent or CI may promote, and the record's signer says who did.

**Where it comes from.** An environment is promoted from the first environment on the rung below, unless it names one with `from`. The lowest rung is not promoted into: work lands there with `use05 land`.

**Whose rules.** The rules come from the policy committed on the target's branch (origin's copy if there is one), so what comes in never decides how it is judged. When what moves would make the target's rules less strict, that needs a person's sign-off (`POLICY_LOOSENED`). If the target's branch has no policy that names the environment, the source's rules apply and the page says so (`RULES_FROM_SOURCE`, a warning when the target has a policy of its own, which is still what loosening is weighed against). If the target's branch does not exist yet, promoting creates it (`PROMOTE_CREATES_BRANCH`), and there is no rollback point.

**Built in, always on, never bypassed.** A target that has commits the source lacks is refused (`PROMOTE_TARGET_AHEAD`): promoting would leave them behind or mix them in unseen. With `how = "merge"`, a merge commit that brings nothing of its own (one an earlier promotion made) does not count. Only the commit that was evaluated is promoted (`PROMOTE_NOT_EVALUATED_HEAD`). An agent may not promote where the environment says `agent = false` (`AGENT_MAY_NOT_PROMOTE`); by default an agent may promote on every rung but the last. When the target already has the source's head, there is nothing to promote (`NOTHING_TO_PROMOTE`).

**The rules.** Each is `allow`, `warn`, `approval` or `deny`. Every rule is judged and listed whatever its setting; only `warn` and above hold anything back.

| Rule | Default | Holds when | Otherwise |
|---|---|---|---|
| `source_checks` | `deny` | The required checks that apply to what moves passed on the source's exact head, by receipts the policy accepts (`[evidence] accept`), as the gate counts them | `SOURCE_CHECKS_MISSING` |
| `source_confirmed` | `warn` | The newest deployment record (`deployment/v0`) of that head says the source environment runs it, confirmed | `SOURCE_NOT_CONFIRMED` |
| `soak` | `warn` | The source environment has run it, confirmed, for `soak_minutes`, counted from the first record of the unbroken run of confirmations that ends with the newest; skipped while `soak_minutes` is not set | `SOAK_NOT_DONE` |
| `migrations` | `approval` | Nothing that moves is in the `migration` risk category (`**/migrations/**`, `*.sql`, ...) | `MIGRATIONS_IN_DELTA` |
| `untasked` | `warn` | Every commit that moves belongs to a 05 task (below) | `UNTASKED_COMMITS` |
| `sign_off` | `allow` | A person signed off on this promotion | `SIGNOFF_REQUIRED` |

**Belongs to a task.** Decided from the receipts branches alone, so CI decides the same: a commit belongs to a task when its tree is one a task finished on (an `outcome/v0` record, which `use05 finish` writes, names that tree); or when that record names the task's base (where the finished work meets the landing branch, which 05 records from this version on) and the commit is between that base and the finished commit; or when a promotion record names it, or it is a merge that brings nothing of its own, as 05's promotions make. A base counts only when it is a full commit id that comes before the finished commit, and a range stops at any other task's finished commit and any promotion's result; a finish with no such base marks only the commit it finished on. The base is where the finished work meets the landing branch when the task finishes (this machine's copy or origin's, whichever it meets nearer the work), so a task rebased onto newer work does not claim that work. This is how your machine reads it; CI works the range out for itself and never takes a machine's word for the base. So finish a task after committing its work.

**Whose records count.** Deployment, finish and promotion records count only when a key of a kind `[evidence] accept` takes signed them, as for check receipts. With the default (`local` and `runner`), a record this machine signed counts, so `source_confirmed`, `soak` and `untasked` rest on this machine's own word, which an agent running here could write: advisory. With `accept = ["runner"]` only CI's records count, and these rules rest on CI. A record's own time is its signer's word too. The page says which of the two holds.

**Sign-offs.** A person's sign-off is one statement, `signoff/v0`, bound to the environment, the source commit and the policy: their own words, their answers to `questions`, and each `confirm` statement, word for word. It counts when the policy names the signer's key for a person among `signers` (groups or people, as for [owners of paths](#owners-of-paths)); with no `signers`, your own approver key or any key the policy names for a person may sign. A counted sign-off also clears whatever a rule set to `approval` holds back; a rejection denies. A `[[environment.confirm]]` statement needs a sign-off that confirms it, so it makes `sign_off` at least `approval`. The page names who may sign, and says why a sign-off does not count.

```sh
use05 approve --promote prod --note "Tried checkout and refunds in uat"
use05 approve --promote prod --reject --reason "Not before the sale"
```

At a terminal, 05 asks for your words, each question and each statement to confirm, unless `--note`, `--answer` (once per question, in order) and `--confirm "<statement>"` give them. Words shorter than `min_length` are refused before anything is signed (`SIGNOFF_TOO_SHORT`), and so is a sign-off that would not count, such as one from outside `signers` (`SIGNOFF_NOT_COUNTED`). Like an approval, it is signed with your key and refused under an agent, in CI, in a pipe or with `--json` (`NEEDS_A_PERSON`). For a passkey on your console, `--unsigned` prepares the statement (every answer then comes by flag) and `--signed <file>` files it once signed, as for approvals. It lasts as long as an approval (`[approvals] expire_days`) and counts for that exact source commit only.

**Break glass.** A person may bypass one rule for one exact promotion, for a reason:

```sh
use05 bypass --promote prod --rule soak --reason "uat was checked by hand this morning"
```

It is signed with your passphrase key, refused under an agent or without a terminal (`NEEDS_A_PERSON`), lasts `--hours` (4 by default, 72 at most), and is bound to the environment, the environment it comes from, the source commit and the policy: a policy change voids it. The rule then shows as bypassed, and the record and the merge commit's trailers carry it (`05-Bypass`). It is refused for a rule in `[environment.bypass] never`, when `allowed = false`, for a reason shorter than `reason_min`, for a rule that holds nothing back, for a person's rejection, and for what is built in (`BYPASS_NOT_ALLOWED`).

```toml
[use05]
min_version = "0.0.14"         # a policy that uses these needs this version

[[environment]]
name = "prod"
branch = "prod"
from = "uat"                   # default: the first environment on the rung below
how = "fast-forward"           # or "merge"
agent = false                  # default: true on every rung but the last
soak_minutes = 60
on_failure = "report"          # or "revert", or "command" with rollback = ["./rollback.sh"]
# rollback_env = ["DEPLOY_TOKEN"] # variables the rollback command may be given, by name
# rollback_timeout_secs = 900

[[environment.probe]]          # asks prod which commit it runs; several may
name = "version"
run = ["curl", "-fsS", "https://example.com/version"]
env = []                       # variables it may be given, by name
timeout_secs = 60              # one try
wait_minutes = 10              # keep asking this long; 0: one try
interval_secs = 15             # between tries

[[environment.smoke]]          # shaped like [[check]]; runs once the probes show the commit
name = "health"
run = ["./smoke.sh"]

[environment.rules]
source_checks = "deny"
source_confirmed = "warn"
soak = "warn"
migrations = "approval"
untasked = "warn"
sign_off = "approval"

[environment.sign_off]
min_length = 20
signers = ["eng-managers"]
questions = ["What did you check in uat?"]

[[environment.confirm]]
text = "The release notes are published"

[environment.bypass]
allowed = true                 # whether a person may bypass a rule for one promotion
never = ["source_checks"]
reason_min = 10
```

A name that does not exist is an error, not a silent no-op: `from` naming no environment (`UNKNOWN_ENVIRONMENT`), a signer nobody has (`UNKNOWN_SIGNER`), a rule name that is not one of the six, `from` going round in a cycle, or `on_failure = "command"` without a `rollback` command (`ROLLBACK_MISSING`). A probe or smoke check needs a name of its own and a command, a probe waits at least a second between tries, and a `dir` outside the repository is refused (`CHECK_DIR_OUTSIDE`). Changing a probe, a smoke check or the rollback command, its variables or its time limit counts as loosening the rules. A policy that sets none of these keeps its digest, so approvals already given still count.

**Hotfixes and merging back.** When prod needs a fix that cannot wait for the ladder, start a hotfix:

```sh
use05 start --hotfix prod "Fix the checkout total"   # a working branch from origin's prod, judged by prod's rules
# ...do the work, then: use05 finish --outcome "<what you did>"
use05 approve --outcome                               # a person approves it: a hotfix always needs this
use05 land --push                                     # lands on prod and pushes, through the pre-push hook
use05 promote uat --back                              # merge prod back into uat
use05 promote dev --back                              # and uat into dev, where work lands
```

`use05 start --hotfix <env>` fetches the environment's branch from origin (five seconds at most) and checks out a new working branch, `05/hotfix-<env>-<id>`, at its head, following `origin/<branch>` so the work is judged by the rules on that branch. It is refused for the environment work lands on (`HOTFIX_ON_LANDING_BRANCH`: a fix there is ordinary work) and with uncommitted changes in the way (`UNCOMMITTED`). An agent may start one and do the work; landing it needs a person anyway.

A hotfix's landing needs a person's approval of its outcome given for this hotfix (`HOTFIX_NEEDS_APPROVAL`): `use05 approve --outcome` on the hotfix's task records the environment and the task in the approval (`hotfix`), and only such an approval counts. An approval of the same tree given for anything else, an approval of the plan, or one for another hotfix does not; nor does one from someone `[environment.sign_off] signers` leaves out, or in fewer words than its `min_length` (that one is refused before anything is signed, `HOTFIX_WORDS_TOO_SHORT`, so give `--reason "<what you checked>"`). This is built in: no setting turns it off and no bypass clears it. When the environment asks `questions` or has `[[environment.confirm]]` statements, a person also signs off with `use05 approve --promote prod --hotfix --note "<what you checked>"`, which asks them and is bound to the hotfix's exact commit (`SIGNOFF_REQUIRED` until then). `use05 land` judges the landing as its push will be judged, on the environment's branch: the task gate under that branch's rules, and the environment's promotion rules as `[environment.hotfix.rules]` sets them for a hotfix. Unset, the rules about the environment a promotion comes from (`source_checks`, `source_confirmed`, `soak`) allow, since a hotfix comes from none, and the others are the environment's own; the approval is the hotfix's sign-off. What lands must be the hotfix's own commits on the branch's head: a merge commit in it, or a commit already on origin's copy of another environment's branch or of the branch work lands on, is refused (`HOTFIX_NOT_ITS_WORK`, naming the commit), and so is a hotfix the branch moved on from (`HOTFIX_NOT_FAST_FORWARD`). It lands by fast-forward only, on this machine's copy of the branch (made from origin's when there is none). Its promotion record (`direction = "hotfix"`, naming the task) is filed only once the branch is on origin: until then no record exists, the command says so, and `use05 land --push` pushes it and files the record (or files it, when the branch was pushed by hand). The pre-push hook lets such a landing onto the environment's branch through: a fast-forward of origin's head to where a hotfix task for that environment ends, the task having started from that branch's history, and allowed by those same rules. Anything else pushed there is still held.

After a hotfix, prod has a commit uat lacks, so promoting into prod is refused (`PROMOTE_TARGET_AHEAD`), and the page names the hotfix task and the next step: `use05 promote uat --back`. That merges prod back into uat as a merge commit, never a fast-forward and never by force, made from git's clean merge of the two heads without touching your checkout, then pushed through the pre-push hook, with a promotion record whose `direction` is `back`. Its message starts `Merge prod back into uat`, and its trailers say `05-Direction: back`. It is judged by uat's own rules, read from uat's branch, except those about the source (`source_checks`, `source_confirmed` and `soak` are not judged); a sign-off it needs is `use05 approve --promote uat --back`, and a person may break glass for one of its rules with `use05 bypass --promote uat --back --rule <name> --reason "<why>"`, bound to uat, prod's head and the policy, as a promotion's bypass is. `--check` judges it and changes nothing. When what comes down includes a rollback 05 made above (`use05 promote prod --rollback`, or `on_failure = "revert"`), the merge back waits for a person (`BACK_MERGE_CARRIES_ROLLBACK`): merged down, the rollback undoes below the work it undid above, and the page names both. If the lower environment should lose that work too, a person signs off on the merge back (`use05 approve --promote uat --back --note "<why>"`); if not, revert the rollback above first. Each rung down asks again. Then uat is ahead of dev by the same hotfix, and `use05 promote dev --back` merges uat into dev; the branch work lands on keeps the task gate for everything else, but the pre-push hook judges a back-merge onto it as one. One rung at a time, until promoting up works again. A back-merge follows the agent rule of the environment it goes into: where `agent = false`, only a person, at a terminal with their key, and the agent hooks hold `use05 promote <env> --back` there. The pre-push hook knows a back-merge by its parents (origin's head of the branch, then origin's head of the environment above) and its tree (their clean merge); a merge made any other way is not one, except one resolved by hand (below).

When the two do not merge cleanly, `use05 promote uat --back` is refused (`BACK_MERGE_CONFLICT`, exit 2), naming the files, and nothing is left behind. Resolve it by hand: on a branch from origin/uat, `git merge origin/prod`, change only the files that conflicted, and commit. The pre-push hook takes that merge as a back-merge when its parents are as above and it differs from git's merge only in those files; it holds it (`BACK_MERGE_RESOLVED`) until a person signs off on that exact merge commit with `use05 approve --promote uat --back --rev <merge commit> --note "<how it was resolved>"`, then lets the push through. A merge that changes anything else is held as any other push is.

```toml
[environment.hotfix]           # under prod's [[environment]]
approval = true                # always; false is refused

[environment.hotfix.rules]     # each optional; unset as described above
source_checks = "deny"         # the required checks must have passed on the hotfix
migrations = "deny"
```

Holding a hotfix rule less strongly counts as loosening the rules.

**Destinations.** A destination is a place outside this repository that work is promoted to with the same command, rules, sign-offs and bypasses: a branch pushed to another remote (`how = "push"`), or a folder copied into another repository (`how = "export"`), such as the public copy of one part of a private repository.

```sh
use05 promote public --check    # judge it; nothing moves
use05 brief --promote public    # the one page
use05 promote public            # push it, or make and push the export's commit, then file the record
```

```toml
[[destination]]
name = "public"
how = "export"                 # or "push"
from = "product/"              # export: the folder; push: a branch (default: where work lands)
remote = "git@github.com:org/public.git"   # a remote's name here, or a URL
branch = "main"                # the branch there
agent = false                  # default: false, only a person promotes here
# [destination.rules], [destination.sign_off], [[destination.confirm]] and [destination.bypass]: as for an environment
```

- **push** sends the head of `from` (by default the branch work lands on, origin's copy when there is one) to `branch` on the remote, by fast-forward only. When the destination has commits that branch lacks, it is refused (`PROMOTE_TARGET_AHEAD`). The push goes through the pre-push hook, which judges a push to a destination's branch as promoting to it: by hand (`git push public main`), only the head 05 judged goes through (`PROMOTE_NOT_EVALUATED_MOVE` otherwise).
- **export** copies the exact committed content of the folder `from` at the evaluated head (never your working files) and makes it the whole tree of `branch` there, as one new commit on top of it: `Sync from <commit>`, with the promotion's trailers. Anything in that branch that is not in the folder is gone from its next commit (its history keeps it). When the folder is as the branch already has it, there is nothing to promote (`NOTHING_TO_PROMOTE`), whatever else changed. The folder must be a relative path with no `..`, and must exist at the evaluated head (`EXPORT_FOLDER_MISSING`). The commit is made and pushed from a temporary copy, so nothing from the other repository enters this one; a push of this repository's own history to an export's branch is held (`PROMOTE_NOT_EVALUATED_MOVE`).

Pushing is never forced. A refused push says why (`PROMOTE_PUSH_FAILED`, exit 4) and leaves no record; the promotion record (`how = "push"` or `"export"`, `env` the destination's name, `from` the environment its source branch is, else that branch) is filed only once the push went through. The rules that judge a destination are the policy at the evaluated head, the source side, since its branch lives in another repository; if that policy does not name the destination, nothing moves (`DESTINATION_NOT_AT_HEAD`). Loosening is weighed against the policy on origin's branch where work lands (`POLICY_LOOSENED`). `source_confirmed` is judged from the deployments of the environment the source branch is, and skipped when it is none; a destination has no soak, probes, smoke checks, rollback, hotfix or merging back, and the policy refuses those keys on one, as `promote --back`, `--confirm`, `--rollback` and `--no-wait` refuse one (`NOT_FOR_A_DESTINATION`). A destination may not share a name with an environment or another destination (`DUPLICATE_TARGET`). Adding a destination, sending one elsewhere, or easing its rules counts as loosening the rules. Where `agent` is not true, only a person promotes there, and the agent hooks hold `use05 promote public`. Locally this is advisory: nothing but this command and the pre-push hook judges what reaches the destination, so protect its branch where it is hosted.

**Where an agent may push.** `[push] agent` lists the remotes an agent may push to, by their name here or their URL:

```toml
[push]
agent = ["origin"]             # unset: any remote; [] none
```

A remote matches by its name, or by a URL equal to one listed or to the configured URL of a remote listed by name. An agent's `git push` to any other remote (named, or given as a URL) is refused by the agent hooks and held by the pre-push hook when an agent session is present (`PUSH_REMOTE_NOT_ALLOWED`: ask the person to push it, or add the remote to `[push] agent`). A person's own push is not held by it. A push `use05 promote` makes to a destination whose `agent = true` lets an agent in is judged by the destination's rules instead. Both policies count: this checkout's and the one on origin's default branch, and either can hold a push. Locally this is advisory, as every hook is: `git push --no-verify` skips the pre-push hook. Adding a remote to the list, or removing the list, loosens the rules.

**How strong.** On your machine this is advisory, like every local check: it is the same judgement CI makes, but nothing stops a person or an agent who pushes the branch by hand. The CI gate on the environment's branch is the strong control, where the host waits for CI before it deploys.

**In CI.** On a push to an environment's branch that is promoted into, or to the branch work lands on when the push is a merge back, the CI gate does not judge the push as a change. It asks for the move's promotion record: one whose result is the pushed commit, filed by a key of a kind the policy takes evidence from (`evidence.accept`). It waits up to a minute for it, since the record follows the push; with none, the push is held (`PROMOTION_RECORD_MISSING`). It then checks the record against the repository's history: the branch's head before must be where the pushed commit came from (its first parent for a merge, its only parent for a revert, an ancestor otherwise; `PROMOTION_RECORD_MISMATCH`); the move must start where the last counted promotion of that environment ended (`PROMOTION_CHAIN_BROKEN`; the first one is taken on its word, and the brief says so); and the source commit must be on the source environment's branch (`PROMOTION_SOURCE_NOT_ON_BRANCH`). Then it judges the move again, as of before the push, with the same rules and the same code as the pre-push hook: a promotion, a revert, a hotfix's landing (rebuilt from its record, with the approval that names the hotfix) or a merge back. Where people keep the environment (`agent = false`), the record must carry a person's co-signature, since CI has no terminal to look at. The required checks of the pushed commit are proved first, as for any change, so the next promotion up finds their evidence. What each part rests on: the record is a claim of which move was made, checked against the history and the chain of records; the rules are CI's own judgement on the evidence it counts. Under `evidence.accept = ["runner"]`, a record signed on a developer's machine does not count, so the environment moves only by a promotion made from CI. Whether the host waits for this gate before it deploys is set on the host; 05 cannot see it.

## Configure: `.05/policy.toml`

Commit the file. A change is held to the rules at its base, so until the policy is committed, a push, CI and approvals use 05's defaults, while the hooks already follow your file; `use05 doctor` and the brief say so.

`use05 init` writes the file with comments, and `use05 policy --edit` changes it by asking the setup questions again, so you rarely need to edit it by hand. To change one rule, change just that rule; the rest of the file, comments included, stays as it is:
```sh
use05 policy set testing.local required
use05 policy add protect.paths "billing/**"
use05 policy add require '{ when = ["src/api/**"], also = ["docs/api/**"], why = "the API docs" }'
use05 policy remove require 1           # a rule by its number, or by its name
use05 policy set environment.prod.rules.sign_off approval   # one environment's setting, by its name
use05 policy set environment.prod.agent false
```
Each prints the setting before and after, and says so when the change makes the rules less strict. `use05 policy` shows the effective value of every setting and where it came from. A change is held to the rules at its **base**, never its own, so editing the policy is itself a change a person approves before it takes effect.

| Setting | Default | What it does |
|---|---|---|
| `[use05] min_version` | the version that ran `init` | The oldest use05 that reads this file. An older one is told to upgrade. |
| `[intent] mode` | `"inferred"` | `inferred`: no written plan needed. `risky`: a plan for risky changes. `always`: a plan for every change. |
| `[[check]]` `name`, `run` | none (`init` proposes `test` when it finds one) | A check 05 runs on the change: `run` is the command as a list, e.g. `["npm", "run", "test", "--silent"]`. Optional: `required` (default true), `env` (variables passed through), `timeout_secs` (default 900), `paths` (required only when a change touches them) and `dir` (the folder it runs in): see [Monorepos](#monorepos). |
| `[protect] paths` | `[]` | A change here needs a person's approval. `.05/**` is always protected. |
| `[protect] locked` | `[]` | Never changed. No approval clears it; a person's bypass can. |
| `[protect] absolute` | `[]` | Locked, and not even a bypass clears it. |
| `[protect] append_only` | `[]` | New files only, e.g. `["migrations/**"]`. Existing files are never edited, renamed or deleted. |
| `[protect] no_delete` | `[]` | May be edited, never deleted. |
| `[protect] no_read` | `[]` | Agents may not open these, e.g. `[".env*"]`. Advisory: it holds only where the agent's hooks report the read. |
| `[protect] bypass` | `true` | `false`: no bypass clears any of the rules above, or an owner rule. |
| `[[protect.owner]]` `paths`, `signers`, `min` | none | Who must approve a change to these paths: `min` (1 by default) different people that `signers` (group or people's names) name, besides the approvals the change needs anyway. See [Owners of paths](#owners-of-paths). Needs `[use05] min_version = "0.0.14"`. |
| `[[signer]]` `name`, `people` | none | A named group of people, for owner rules. Each person must be the `person` on a trusted key. |
| `[drift] scope` | `"warn"` | Files changed outside the declared scope: `allow`, `warn`, `approval` or `deny`. |
| `[drift] dependencies` | `"warn"` | Dependency files changed. |
| `[drift] overlap` | `"warn"` | Another agent session edited the same files: `warn` tells the agent, `approval` asks a person, `deny` refuses. |
| `[drift] tests` | `"approval"` | The change deletes, skips or loosens tests, or lets a failing check pass. |
| `[drift] claims` | `"warn"` | The agent claims something the evidence does not support, such as "tests pass" without a passing receipt. |
| `[drift] reservation_idle_hours` | `2` | A declared scope stops reserving its area after this long with no activity. |
| `[evidence] accept` | `["local", "runner"]` | Whose signatures count as evidence. `["runner"]` counts only evidence signed in CI. |
| `[evidence] stop_budget_secs` | `60` | How long the hook may spend running checks when an agent stops. `0` turns it off. |
| `[evidence] prove_at_push` | `true` | The pre-push hook runs required checks that are missing for what you push. |
| `[evidence] lfs` | `false` | Git LFS: run checks on the real files, not the small pointer files git stores. See [Git LFS](#git-lfs). Needs `[use05] min_version = "0.0.14"`. |
| `[approvals] min` | `1` | Approvals needed. |
| `[approvals] expire_days` | `7` | How long an approval lasts. |
| `[risk] exempt` | `[]` | Paths a built-in risk pattern catches by mistake. |
| `[[risk.rules]]` `category`, `level`, `paths` | built-in only | Your own risk areas, on top of the built-in ones (auth, money, migration, secrets, privilege and deployment are high; persistence and network are medium). For example `category = "pricing"`, `level = "medium"`, `paths = ["src/pricing/**"]`. A high-risk change needs a person's approval. |
| `[branches] keep` | `main`, `master`, `develop`, `release/*` | Real branches: never deleted. |
| `[branches] work` | `05/*`, `agent/*`, `claude/*`, `codex/*` | Agents' working branches: removed with their worktree once landed. |
| `[branches] target` | the remote's default branch | The branch finished changes land on, unless a plan names another. |
| `[branches] land` | `"manual"` (the "just you" setup writes `"auto"`) | `manual`: you run `use05 land`. `auto`: a change the gate allows lands when its agent stops, or when you approve it. |
| `[branches] push` | `"manual"` | After a change lands: `manual`, you push (at a terminal 05 asks); `auto`, 05 pushes the landing branch to origin, through the pre-push hook, and the receipts branches first so CI finds the approvals. |
| `[branches] fresh_base` | `"allow"` (new setups write `"warn"`) | An agent that starts behind origin's copy of the landing branch. When it is not `allow`, the hook fetches that branch as a session starts (giving up after 5 seconds, never asking for a password) and tells the agent how far behind it is and how to update. Until the work contains what origin had, the brief reports `BASE_STALE`: `warn` notes it, `approval` asks a person, `deny` refuses. Commits the agent pulls in by rebasing or merging are not counted as its change. Checked on your machine only, not by the CI gate. |
| `[record] middle` | `"local"` | What agents did is recorded on this machine and never uploaded. `off` records nothing. |
| `[enforce] on_error` | `"open"` | If 05 itself fails: `open` lets the change through and says so loudly; `closed` refuses it. |
| `[env] allow` | unrestricted | If set, the only environment variables any check may be passed. |
| `[[trust.key]]` `name`, `role`, `public`, `expires`, `person` | none | A public key whose signatures count: `role = "runner"` for a CI runner (authoritative), `"approver"` for a person's approval key or passkey, `"local"` for another machine (advisory). `public` is the contents of the `.pub` file; `expires` (for example `"2027-12-31"`) stops trusting it after that date; `person` is whose key it is, as git records their name (needs 0.0.7 or later wherever the policy is read); owner rules know people by it. See [Turn on the CI gate](turn-on-the-ci-gate.md). |
| `[[require]]` `when`, `also` | none | Files that must change together. A change that touches anything in `when` must also touch something in `also`, or the brief reports `ALSO_CHANGE_MISSING`. For example `when = ["src/api/**"]`, `also = ["docs/api/**"]`; `when = ["**"]` means every change. Optional: `severity` (`approval` by default; `warn` or `deny`) and `why`, which the agent and the brief are told. 05 checks only that a file there changed, not what the change says. Any number of rules. |
| `[testing] local` | `"off"` | Whether a person must try a change in their own environment before it is pushed: `skippable` asks for a sign-off and lets them skip it with a reason; `required` takes only a sign-off. See [Testing before a push](#testing-before-a-push). |
| `[testing] branches` | the landing branch | Which pushed-to branches need it, as patterns such as `main` or `release/*`. |
| `[[environment]]` `name`, `branch`, `level` | none | Which branch is which environment, e.g. `name = "dev"`, `branch = "main"`. `level` (`dev`, `uat`, `pre-prod` or `prod`) is needed only when the name is not a level, such as a second dev environment `dev-eu`. Shown by `use05` and the brief, levels side by side; environment branches are never deleted. |
| `[[environment]]` `from`, `how`, `agent`, `soak_minutes`, `on_failure`, `rollback`, `rollback_env`, `rollback_timeout_secs`, `[environment.rules]`, `[environment.sign_off]`, `[[environment.confirm]]`, `[environment.bypass]`, `[[environment.probe]]`, `[[environment.smoke]]` | see [Environments and promotion](#environments-and-promotion) | How a promotion into the environment is judged: where from, fast-forward or merge, whether an agent may promote, each rule's strength, who signs off and what they confirm; how its deploy is confirmed, and what happens when it is not. |
| `[[destination]]` `name`, `how`, `from`, `remote`, `branch`, `agent`, and `rules`, `sign_off`, `confirm`, `bypass` as for an environment | none | A place outside this repository promoted to with `use05 promote <name>`: a branch pushed to another remote, or a folder exported into another repository. See Destinations under [Environments and promotion](#environments-and-promotion). |
| `[push] agent` | unset: any remote | The remotes an agent may push to, by name or URL; the agent hooks and the pre-push hook hold any other for a person (`PUSH_REMOTE_NOT_ALLOWED`). |

An organisation can add a signed layer of rules on top. Repositories can tighten that layer, but never loosen it. `use05 policy` shows which settings came from it.

### Monorepos

One policy covers the whole repository. A `[[check]]` can say which changes call for it with `paths`, and which folder it runs in with `dir`:

```toml
[[check]]
name = "test-api"
run = ["pnpm", "--filter", "./packages/api", "test"]
paths = ["packages/api/**", "pnpm-lock.yaml"]

[[check]]
name = "test-svc"
run = ["go", "test", "./..."]
dir = "svc"
paths = ["svc/**", "go.work.sum"]
```

- **`paths`** are patterns from the top of the repository, the same kind as `protect` paths (`*` within a folder, `**` any depth; a bare `**` names every file). The check is required only when the change touches one of them. Otherwise the brief shows it as `not required: no change in its paths`; it never blocks the change and never counts as missing. If a receipt for it exists anyway, the brief shows how it ended, marked not required and not counted. Without `paths`, a check is required for every change. A check the plan names (`use05 start --check`) is required for that change whatever its paths. Put the root lockfile and the files that define the workspace in `paths` so a dependency change reruns the packages (init does). When a change touches files that no check's `paths` name and no check is required for every change, the brief says so under Unknowns ("2 changed files are outside every check's paths ..."): nothing checked them.
- **`dir`** is the folder of the checked tree the command runs in, relative to the top: no `..`, no leading `/`, or the policy is refused with `CHECK_DIR_OUTSIDE` (a link in the tree that leads out of it is refused too). The receipt records it, and the same command in two folders is two checks. It works with `USE05_CHECK_USER`: the command runs as that user in that folder.
- A `dir` that is not in the tree (a package the change deleted, say) fails that check alone, with the reason; the other checks still run.
- A package that depends on another is not rerun when only the other changes, unless its `paths` also name the other's folder.
- `use05 prove` with no names still runs every required check, since it does not know what the change touches. `use05 prove test-api` runs one. The pre-push hook and the hook that runs when an agent stops run only what the change calls for. The CI gate proves only the required checks the change calls for (plus any the plan names), so a toolchain or package the change does not touch cannot stop it.

`use05 init` reads the workspace files at the top of the repository, with no network and no package manager, and suggests one check per package, with that package's folder, the root files that define the workspace and its root lockfile as `paths`. At a terminal it shows them and asks once whether to use them (yes is the default); `--defaults` uses them. They replace the single `test` check found at the top; other checks stay. If the top is itself a package (a root crate beside its members, `use .` in `go.work`, a root with its own `src` and test script), its `test` check stays too, required for every change.

| Found in | Check for each package | Lockfile |
|---|---|---|
| `package.json` `workspaces` | `npm test --workspace <dir>`, or `yarn workspace <name> test` when `yarn.lock` exists | `package-lock.json`, `yarn.lock` |
| `pnpm-workspace.yaml` | `pnpm --filter ./<dir> test` | `pnpm-lock.yaml` |
| `Cargo.toml` `[workspace] members` | `cargo test -p <package name>` | `Cargo.lock` |
| `go.work` | `go test ./...`, with `dir` set to the module | `go.work.sum` |
| `pyproject.toml` `[tool.uv.workspace] members` | `uv run --package <name> pytest` | `uv.lock` |

A member list is expanded when it is a folder or `folder/*`; `init` says which patterns it left out (such as `packages/**`) so you can add those checks yourself. A JavaScript package with no `test` script gets no check, and `init` says so. The policy needs `[use05] min_version = "0.0.14"`, which `init` writes.

### Git LFS

05 checks exactly what is committed, with no line-ending changes and no filters. A repository that uses Git LFS commits small pointer files in place of its large ones, so by default the checks run on the pointers, and the brief says so under Unknowns: "2 LFS files were checked as pointers (set [evidence] lfs = true to check the real files)".

To check the real files, set `lfs = true` under `[evidence]` and `min_version = "0.0.14"` under `[use05]`, and install [git-lfs](https://git-lfs.com). Before a check runs, 05 replaces each pointer in its copy of the tree with the real file, fetched by `git lfs smudge` (from your LFS storage, or the LFS server if it is not there) and checked against the size and SHA-256 the pointer names. The receipt lists each file's path, object id and size, so it still says exactly what was checked, and the tree it is for is still the committed one.

Turning it on is judged by the rules before it, as any change to the policy is: when a check needs the real files to pass, the push that sets `lfs = true` runs that check on the pointers and is held (`CHECK_FAILED`). Push the policy change on its own and let a person break glass for it once (`use05 bypass --reason "turn on lfs"`); every push after it is checked with the real files.

If `git-lfs` is not installed (`LFS_UNAVAILABLE`), or a file cannot be fetched or does not match its pointer (`LFS_FAILED`), nothing runs and no receipt is made. A tree with no LFS pointers needs neither. In CI, install git-lfs in the step before the gate and give the checkout access to the LFS server. Each file gets five minutes (`USE05_LFS_TIMEOUT_SECS` changes that); if the LFS server does not answer in that time the proof stops with `LFS_FAILED`. An `ssh` LFS endpoint is never allowed to ask a question (`BatchMode`), unless you set `GIT_SSH_COMMAND` or `core.sshCommand` yourself.

Exactly which files are replaced: when some `.gitattributes` in the tree has a line with `filter=lfs`, every committed file of 1024 bytes or less that is a well-formed LFS pointer is replaced, whatever its path. 05 does not match the `.gitattributes` patterns to paths. It does not read macro lines, `-filter` unsets, `.git/info/attributes` or your global attributes. A file shaped like a pointer that LFS does not actually track therefore fails the proof with `LFS_FAILED` when `lfs = true`, rather than being checked as it is. Nothing else in the tree is ever changed.

Pushing: Git LFS uploads a push's large files from the `pre-push` hook, and git runs only one. The hook `use05 init` writes (which treats a repository as using LFS when its own git config has `lfs.*` settings or a tracked `.gitattributes` has a `filter=lfs` line that is not a comment) runs `git lfs pre-push` first when git-lfs is installed and the repository uses LFS (and fails the push if that fails), then 05's check. If the repository uses LFS and git-lfs is not on the hook's PATH (a graphical git client can have a short one), the push stops with a message, exit 2, as Git LFS's own hook does. If `init` finds Git LFS's own standard hook, exactly as `git lfs install` writes it, it replaces it with this one and says so; any other hook, including one with anything added to Git LFS's, it leaves alone. `use05 doctor` reports a problem if 05's own hook in an LFS repository lacks the call, and a note, since it may reach Git LFS another way, if another tool's hook does. After `use05 uninstall`, run `git lfs update` to put Git LFS's own hook back.

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

   Also available: `intent_mode`, `check` (required checks), `drift_dependencies`, `drift_overlap`, `drift_claims`, `approvals_expire_days_max`, `record_middle`, `enforce_on_error`, `env_allow`, `trust_key`, `risk_rules`, `risk_exempt_allowed`, `protect_absolute`, `protect_append_only`, `protect_no_delete`, `protect_no_read`, `protect_bypass`, `branches_fresh_base`, `require` (rules added to every repository's), `signer` (groups; one a repository also defines keeps only the people both list) and `protect_owner` (owner rules added to every repository's).
2. Sign it with the organisation's key (make one with `use05 key new org.key`):

   ```sh
   use05 policy org-sign floor.toml --org Acme --key org.key --out org.json
   ```
3. On each machine, put `org.json` and the organisation's public key, named `org.pub`, in 05's config directory: `~/.config/05/` (or `$XDG_CONFIG_HOME/05/`, or `$USE05_HOME`). From then on, a missing or tampered `org.json` is an error, not a silent fallback.

## Turn on the CI gate

Everything above runs on your machine, where an agent running as you can reach it, so it is advisory. The CI gate is what enforces: a runner the agent cannot reach runs the checks and signs the result, and your Git host refuses a push without it. About ten minutes, once per repository: [Turn on the CI gate](turn-on-the-ci-gate.md).

## Your own console

An optional web app you host yourself, to see every agent's work and approve it from your phone with a passkey. One container image, one SQLite file, no hosted version, encrypted end to end so that the console relays your work without being able to read it.

```sh
docker run -p 8080:8080 -v console-data:/data -e ORIGIN=https://console.example.com ghcr.io/use05-dev/use05-console
use05 cloud login https://console.example.com   # inside a repository: claim it, pair this machine, report the repository
```

Everything else is in [Your own console](console.md).

## Commands

| Command | What it does |
|---|---|
| `use05` | One page for the repository: who needs you, who is working, what finished, which controls are on. Outside a repository, every repository 05 is used in. On a terminal the first entry is the next thing to do, and Enter does it. |
| `use05 init` | Set up this repository, asking a few questions on a terminal: policy, keys, hooks. Shows exactly what it changes. Also `--team`, `--target`, `--env`, `--defaults`, `--guided`. |
| `use05 start "<title>" --scope <glob>` | Begin a task: what you are about to do and where. Several patterns go in one `--scope`, separated by spaces or commas, or in several. Also `--goal`, `--exclude`, `--check`, `--no-new-deps`; `--hotfix <env>` starts a hotfix from that environment's branch ([Hotfixes and merging back](#environments-and-promotion)). |
| `use05 finish --outcome "<text>"` | Record what was done, in the author's words. Treated as a claim, never a fact. |
| `use05 prove [names] [-- command]` | Run checks on the change and sign the result. |
| `use05 brief` | The one page a person reads. `--json` for data, `--fetch` to pull others' receipts first, `--rev <revision>` for someone else's work, as `approve --rev` judges it; `--promote <env>` for a promotion. |
| `use05 approve` | Approve or reject a plan (`--intent`) or a finished change (`--outcome`) of the task that waits for you, or of the one you pick when several do (`--task <id>` names it); `--tested --note` signs off that you tried it, `--skip-testing --reason` skips that where allowed; `--unsigned` and `--signed` for a passkey or another signer; `--land` lands the approved change straight away; `--outcome --rev <commit>` approves someone else's work, by the commit `use05 brief --rev origin/<branch>` shows ([Owners of paths](#owners-of-paths)). |
| `use05 bypass --reason "<text>"` | Let one exact change through a block, for a stated reason. Logged. |
| `use05 land` | Move an allowed change into its target branch, then clean up its branch and worktree. `--push` pushes the landing branch afterwards; at a terminal it asks. |
| `use05 promote <env>` | Promote into an environment from the one below it when its rules allow, then confirm the deploy. `--check` judges every rule and changes nothing (`use05 brief --promote <env>` is the one page); `--no-wait` leaves confirming to `--confirm`, which asks the environment's probes what it runs; `--rollback` goes back to where the newest promotion found it, with a new commit; `--back` merges the environment above back into it, after a hotfix. `use05 promote <destination>` pushes to a `[[destination]]` or exports a folder to it. See [Environments and promotion](#environments-and-promotion). |
| `use05 discard <task>` | Throw abandoned work away: its worktree and branch, here and on origin, after showing what would be lost. Needs a person at the terminal; `--unsigned` and `--signed` for a passkey. |
| `use05 verify <receipt>` | Check a receipt offline: no account, no network. |
| `use05 policy` | The effective policy, and where each setting came from. `set`, `add` and `remove` change one rule; `--edit` changes it through the setup questions. |
| `use05 doctor` | Check the setup, and how strongly each control is enforced. |
| `use05 key new --approver` | Create your approver key: Touch ID on a Mac that has it (`--touch-id`), else passphrase-protected (`--passphrase`). `use05 key show` lists this machine's keys. |
| `use05 gate` | The gate on its own: `--git-hook pre-push` is what the pre-push hook runs; `--ci` proves the required checks with the runner key, then gates (what the CI workflow runs; `--push` keeps the runner's receipts). |
| `use05 policy org-sign` | Sign an organisation's rules. See [Organisation rules](#organisation-rules). |
| `use05 hook <agent> <event>` | What agent hooks call: `claude-code`, `codex`, or `generic` for any other agent (see [Extending 05](extending.md)). |
| `use05 uninstall` | Reverse exactly what `init` did. |
| `use05 cloud <login\|add\|enrol\|install\|status\|sync>` | Connect this machine to [your own console](console.md), through the `use05-cloud` helper. |

Commands take `--help`; most take `--repo <dir>` and `--json`.

More flags worth knowing:

- `use05 prove`: `--key <file>` signs with that key instead of this machine's (or the CI runner key); `--timeout <seconds>` stops a check after that long; `--env NAME` or `--env NAME=VALUE` passes a variable to the check; `--out <file>` also writes the receipt to a file; `--no-store` keeps it off the receipts branch; `--push` pushes the receipts branch.
- `use05 verify <receipt>`: `--key <file.pub>` checks against that public key instead of the trusted ones; `--tree <rev>` also checks the receipt is for that tree.
- `use05 bypass`: `--hours <n>` sets how long it lasts (4 by default).
- `use05 key new <path>` makes a key pair at `path` and `path.pub`; `use05 key new --approver` makes your approver key (Touch ID or passphrase).

## Exit codes and environment variables

`use05 brief`, `use05 gate` and `use05 promote` exit with the decision, so scripts and CI can act on it: **0** allow, **2** deny, **3** a person's approval is needed (or, for what only a person may do, there is no person here), **5** evidence is missing (a check has not run on this change). Other commands exit 0 on success; **4** means something outside 05 failed (git, the disk, or a push the remote refused); **6** means the command was used wrongly (an unknown flag, say).

| Variable | What it does |
|---|---|
| `USE05_HOME` | 05's config directory (keys, organisation rules, the list of repositories). Default `~/.config/05`, or `$XDG_CONFIG_HOME/05`. |
| `USE05_NO_TOUCH_ID` | Do not use or offer the Touch ID approver key: approvals use the passphrase key. |
| `USE05_RUNNER_KEY` | The CI runner's secret key, from a CI secret. `prove` and `gate --ci` sign with it. |
| `USE05_PUSH_TOKEN` | In CI, the token `gate --ci --push` pushes the runner's receipts with, and posts the `05` commit status with. |
| `USE05_STATUS_TOKEN` | In CI, the token the `05` commit status is posted with: your 05 app's, so no branch can forge the status. Else `USE05_PUSH_TOKEN`, else `GITHUB_TOKEN`, and the job summary says a branch can forge it. |
| `USE05_CHECK_USER` | Run the checks as this OS user (through `sudo -n`), which cannot read the key 05 signs with. The CI gate sets `use05-check`. If the checks cannot run as that user, nothing runs (`CHECK_USER_UNAVAILABLE`); a command that user cannot find or reach is not started (`COMMAND_NOT_STARTED`). |
| `USE05_LFS_TIMEOUT_SECS` | With `[evidence] lfs = true`, how long each Git LFS file may take to fetch (default 300). On expiry the proof stops with `LFS_FAILED`. |
| `USE05_SESSION_ID` | For a generic agent: its session id, so `use05 start` from inside it waits for its hook to seal the plan. Claude Code and Codex set their own. |
| `NO_COLOR`, `CLICOLOR_FORCE` | Turn colour off, or force it when output is not a terminal. |
| `USE05_UNICODE` | Use Unicode symbols even when the locale does not say UTF-8. |

## Upgrade and uninstall

Upgrade the way you installed: run the installer script again, `npm install -g @use05/cli@latest`, or `npm install --save-dev @use05/cli@latest` in the project. Then run `use05 init` again in each repository. It updates the hooks an older version installed, keeps other tools' hooks, and leaves your policy alone.

`use05 uninstall` removes what `init` added and puts back every file it changed, and takes the repository off the machine's list of repositories. Your code, branches and policy are never touched.

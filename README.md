<p align="center">
  <a href="https://use05.dev">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
      <img src="docs/assets/logo.svg" alt="05" height="88">
    </picture>
  </a>
</p>

<h3 align="center">Land AI-written code with no pull request to review.</h3>

<p align="center">
  Agents declare a plan. 05 checks the result on the exact code, signs the evidence,<br>
  and keeps several agents out of each other's way. You approve by exception; it lands as a commit.
</p>

<p align="center">
  <a href="https://github.com/use05-dev/use05/actions/workflows/ci.yml"><img src="https://github.com/use05-dev/use05/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/use05-dev/use05/releases/latest"><img src="https://img.shields.io/github/v/release/use05-dev/use05?color=0f6b47&label=release" alt="Latest release"></a>
  <a href="https://www.npmjs.com/package/use05"><img src="https://img.shields.io/npm/v/use05?color=0f6b47&label=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-0f6b47" alt="Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://use05.dev">Website</a> ·
  <a href="#install">Install</a> ·
  <a href="#five-minutes">Five minutes</a> ·
  <a href="docs/turn-on-the-ci-gate.md">CI gate</a> ·
  <a href="docs/extending.md">Extend</a>
</p>

<p align="center">
  <img src="docs/assets/brief-clean.png" alt="use05 brief on an agent's branch: the change stayed in its declared scope, its checks passed on the exact tree, and the verdict is ALLOW, nothing to read." width="820">
</p>

**You own the request and the acceptance. Agents own the plan and the work. 05 holds them to the plan.**

05 is an acceptance layer for AI-written code that takes the place of pull-request review. The agent declares what it will do before it starts, and 05 seals that plan where the agent cannot change it. When it finishes, 05 proves what was checked on the exact files and compares the result to the plan. When everything matched, you approve, the change lands as a commit and you push it: no pull request to review. When something did not match, you read one page instead of the diff. With several agents in one repository, 05 keeps them out of each other's way. Everything runs on your machine: no account, no telemetry, nothing uploaded.

## Install

```sh
curl -fsSL https://use05.dev/install.sh | sh
```

The installer downloads a release for your platform, checks its SHA-256 against `SHA256SUMS`, and refuses to install on a mismatch. Linux and macOS (x86_64 and arm64). With npm: `npm install -g use05`, which installs the same binary for your platform. Or build it: `cargo build --release -p use05` (Rust 1.85+, and `git` at runtime).

## Five minutes

```sh
cd your-repo
use05 init                    # policy, keys, hooks; says exactly what it changed and what is not covered
use05 start "Stop retrying failed charges" --scope "src/billing/**"
# ... you or an agent do the work ...
use05 prove                   # runs the policy's checks on the exact files, signs the result
use05 brief                   # the one page you read: intent, outcome, evidence, drift, decision
use05 approve --outcome       # a person signs, with a passphrase the agent does not have
use05 land                    # the approved change becomes a commit on its target branch
git push origin main          # no pull request needed; CI gates every pushed branch
```

Bare `use05` shows where you stand. `use05 doctor` says how strongly each control is enforced.

## What it looks like

Real output from the `use05` binary on a demo repository.

| | |
|---|---|
| <img src="docs/assets/prove-verify.png" alt="use05 prove signs a receipt for a check on the exact tree; use05 verify checks it offline."> | <img src="docs/assets/brief.png" alt="use05 brief on a change that drifted: files outside scope, a migration, a risky area, and the verdict approval required."> |
| **Prove, then verify.** A check on the exact tree, signed; verified offline. | **When something did not match**, the brief says what, and only that needs a person. |
| <img src="docs/assets/land-and-clean-up.png" alt="use05 land fast-forwards an agent's branch onto main, removes its worktree and deletes the branch."> | <img src="docs/assets/hook-denied.png" alt="A Claude Code hook refuses an agent's edit to 05's own policy file until a person approves."> |
| **Land it**, and the agent's branch and worktree are cleaned up. | **Agents are held to the rules** by their own hooks. |

## Several agents, one codebase

Run as many agents as you like on one repository. 05 keeps them orchestrated so they do not overwrite each other's work:

1. **Each agent claims an area.** It declares a scope (`use05 start "Cap retries" --scope "src/billing/**"`) before its first edit; 05 seals it as that session's reservation.
2. **A clash is caught at the plan.** An overlapping scope is told which task holds the area, which agent declared it and what it is doing, so it narrows its plan or waits.
3. **And again at every edit.** The agent's hook checks each file it is about to write: inside another task's area, it is told to stay out; changed by another session in the last 30 minutes, it is told to read that change first.
4. **Each agent works apart**, on its own branch and git worktree.
5. **Shared files are flagged.** The brief reports `OVERLAP` while another task's change to the same file is not in this change's base.
6. **Changes land one at a time.** `use05 land` only fast-forwards exactly what was checked; if the target moved, it refuses and says to rebase.
7. **Nothing is left behind.** A landed change's branch and worktree are removed; kept branches, unmerged work and anything uncommitted never are.

`overlap = "warn"` (the default), `"approval"` or `"deny"` under `[drift]` in `.05/policy.toml` sets how strict this is, and `reservation_idle_hours` (default 2) frees an idle session's area. Only file paths are compared, never contents. Live warnings cover every agent and worktree on one machine; across machines, git still refuses a push that is not a fast-forward.

## How it works

- **Receipts.** `prove` runs a check on an exact git tree and signs the result as an in-toto statement inside a DSSE envelope (Ed25519). Anyone can verify it offline with `use05 verify`, with no account or network. Receipts live on ordinary `05-receipts/<key>` branches.
- **Policy.** `.05/policy.toml` says which checks are required, which paths are protected, and how drift is treated. A change is held to the rules at its **base**, never its own, so a change cannot loosen its own rules. An organisation can sign a floor that repositories may tighten but never loosen.
- **The gate is deterministic.** No model judges anything. It compares intent, files changed, evidence on the exact tree, approvals and protected paths, and answers allow, wait, approval required or deny.
- **Approvals** are signed with a passphrase-protected key, bound to the exact content and the policy, and expire.
- **Agents.** Hooks for Claude Code and Codex seal each agent's declaration, guard risky commands and protected paths, keep parallel agents out of each other's declared scope, run the checks when the agent stops, and write an `AGENTS.md` block so agents know the rules. Each declaration names the agent and an accountable owner.
- **A record you can prove later.** What the agent did (tools, paths and decisions; never contents or prompts) is a hash-chained log, sealed by signed receipts as the work happens and countersigned by CI. It travels with the receipts, so anyone with the repository and the public keys can check it.
- **Extensible from outside.** A `use05-<name>` program on your PATH is the command `use05 <name>`; any agent can use the generic hook; programs you list hear what happened; other tools can keep their own signed records next to 05's. None of them can change what the gate decides. See [Extending 05](docs/extending.md).
- **Land and clean up.** `use05 land` moves an allowed change into its target branch as a fast-forward and removes the agent's finished branch and worktree.
- **Honest about strength.** Hooks and the pre-push gate are advisory: an agent running as you can reach them. Evidence signed by a CI runner key the agent cannot read, plus a required check on your Git host, is what enforces. 05 says which is which, everywhere.

## What 05 does not do

It is not an agent, an agent runner, a code reviewer powered by a model, a session recorder or a Git host. It keeps the agents you already run coordinated, and shows what was checked; it does not judge whether the change is correct.

## Documentation

- [Turn on the CI gate](docs/turn-on-the-ci-gate.md) (the strong control)
- [Receipt format](docs/receipts.md)
- [Extending 05](docs/extending.md): commands, any agent's hooks, events, your own record types
- [How 05 maps to AI governance guidance](docs/compliance-mapping.md) (TBS agentic AI guide, Directive on Automated Decision-Making, ISO/IEC 42001, NIST AI RMF)
- [Security policy](SECURITY.md) and [contributing](CONTRIBUTING.md)

## License

Apache-2.0. See [LICENSE](LICENSE).

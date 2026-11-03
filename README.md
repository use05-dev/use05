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
  Agents declare a plan. 05 holds them to it, checks the result on the exact code and signs the evidence.<br>
  You approve by exception, at your terminal or from your phone.
</p>

<p align="center">
  <a href="https://github.com/use05-dev/use05/actions/workflows/ci.yml"><img src="https://github.com/use05-dev/use05/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/use05-dev/use05/releases/latest"><img src="https://img.shields.io/github/v/release/use05-dev/use05?color=0f6b47&label=release" alt="Latest release"></a>
  <a href="https://www.npmjs.com/package/@use05/cli"><img src="https://img.shields.io/npm/v/@use05/cli?color=0f6b47&label=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-0f6b47" alt="Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://use05.dev">Website</a> ·
  <a href="#get-started">Get started</a> ·
  <a href="docs/guide.md">Guide</a> ·
  <a href="docs/console.md">Your own console</a> ·
  <a href="docs/turn-on-the-ci-gate.md">CI gate</a>
</p>

<p align="center">
  <img src="docs/assets/brief-clean.png" alt="use05 brief on an agent's branch: the change stayed in its declared scope, its checks passed on the exact tree, and the verdict is ALLOW, nothing to read." width="820">
</p>

An agent can write fifty thousand lines in an afternoon. Nobody can review that, so pull requests get approved unread, or people go back to writing the code by hand. 05 replaces the review with proof. **You own the request and the acceptance. Agents own the plan and the work. 05 holds them to the plan.** When everything matched, there is nothing to read. When something did not, you read one page, not the diff.

## What you get

- **Agents held to their plan.** Each agent declares what it will do and where before its first edit. 05 seals that plan where the agent cannot change it, and the agent's hooks refuse what your rules forbid.
- **Evidence, not "tests pass".** Your checks run on the exact files, and the result is signed as a receipt anyone can verify offline. No model judges anything; the gate is fixed rules.
- **One page instead of the diff.** The brief compares the plan with what changed and what was proved. A 500-file build still fits on one page.
- **Several agents, one codebase.** Each claims an area; a clash is caught at the plan and at every edit, and changes land one at a time.
- **Approve from your phone.** Run your own console: see every agent's work, approve with a passkey, sign off that you tested a change, throw away abandoned work. Self-hosted, one container, encrypted end to end.
- **Your rules, honestly enforced.** Protected, locked and append-only paths, testing before a push, an organisation floor. Hooks are advisory, a required CI check enforces, and 05 says which is which.

It works with the agents you already run (Claude Code, Codex, and any agent with hooks). It is not an agent, not a code reviewer powered by a model, not a Git host. Free and open source; everything runs on your machine, with no account and no telemetry.

## Five principles, hence the name

| # | Principle | What it means |
|---|---|---|
| 01 | **Policy** | Your rules in `.05/policy.toml`, set by answering a few questions. |
| 02 | **Gates** | Where the rules hold: the agent's hooks, a pre-push gate, a required CI check. |
| 03 | **Intent** | The agent declares its plan before it starts; 05 seals it and holds the agent to it. |
| 04 | **Evidence** | Checks run on the change itself, and the result is signed. |
| 05 | **Review** | Only by exception: one page, never the diff. |

## Get started

```sh
curl -fsSL https://use05.dev/install.sh | sh        # or: npm install -g @use05/cli
cd your-repo
use05 init                                          # a few questions, then rules and hooks
git add .05 AGENTS.md && git commit -m "Set up 05"  # your rules count once committed (add .codex too if init wrote it)
use05 key new --approver                            # your approval key, behind a passphrase no agent has
```

Then work with Claude Code or Codex as you do now. When an agent is done:

```sh
use05 brief                   # one page: what was asked, what changed, what was proved
use05 approve --outcome       # only when the brief asks for a person
use05 land                    # the agent's branch lands on main and is cleaned up
git push origin main          # checked again on the way out; no pull request
```

macOS and Linux, x86_64 and arm64. The [guide](docs/guide.md) covers the rest, including working without an agent.

## See it

| | |
|---|---|
| <img src="docs/assets/brief-large.png" alt="use05 brief on a 497-file, 52,475-line feature build: areas with line counts, 26 files outside the declared scope, refusals by reason, the test check failing then passing during the session, two subagents, and the verdict approval required."> | <img src="docs/assets/prove-verify.png" alt="use05 prove signs a receipt for a check on the exact tree; use05 verify checks it offline."> |
| **A 497-file build, one page.** What changed by area, what fell outside the plan, what 05 refused and why. | **Prove, then verify.** A check on the exact tree, signed, verifiable offline. |
| <img src="docs/assets/land-and-clean-up.png" alt="use05 land fast-forwards an agent's branch onto main, removes its worktree and deletes the branch."> | <img src="docs/assets/hook-denied.png" alt="A Claude Code hook refuses an agent's edit to 05's own policy file until a person approves."> |
| **Land it**, and the agent's branch and worktree are cleaned up. | **Agents are held to the rules** by their own hooks. |

## Documentation

- [Using 05](docs/guide.md): how it works, set up, working with agents, the brief, approvals, every setting and command
- [Your own console](docs/console.md): approvals from your phone, self-hosted and encrypted end to end
- [Turn on the CI gate](docs/turn-on-the-ci-gate.md): the control that enforces
- [Receipt format](docs/receipts.md) · [Extending 05](docs/extending.md) · [AI governance mapping](docs/compliance-mapping.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

Apache-2.0. See [LICENSE](LICENSE).

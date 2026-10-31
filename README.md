# 05

**You own the request and the acceptance. Agents own the plan and the work. 05 holds them to the plan.**

05 is an acceptance layer for AI-written code that takes the place of pull-request review. The agent declares what it will do before it starts, and 05 seals that plan where the agent cannot change it. When it finishes, 05 proves what was checked on the exact files and compares the result to the plan. When everything matched, you approve, the change lands as a commit and you push it: no pull request to review. When something did not match, you read one page instead of the diff. With several agents in one repository, 05 keeps them out of each other's way. Everything runs on your machine: no account, no telemetry, nothing uploaded.

```
$ use05 prove
✓ Proved: the check passed
  check     test
  result    passed in 396ms
  tree      7fa8fe0e10a8 (working tree)
  signed    def1b067b692 (this machine, advisory)
  Advisory: a key on this machine can be used by an agent running as you.
  Authoritative evidence is produced in CI.
```

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

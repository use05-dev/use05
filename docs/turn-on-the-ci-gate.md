# Turn on the CI gate (the strong control)

Hooks and the pre-push gate are advisory. The CI gate is what makes 05 enforceable: a runner the agent cannot reach proves the checks and signs the receipt, and the Git host refuses the push or merge without it. About ten minutes, once per repository.

The runner key is what makes a receipt authoritative, so it must be out of reach of the code it judges. An agent can push a branch, and a branch can carry its own workflow files: any workflow that runs from a branch's own copy, and any repository secret, is the agent's to read. So the key goes to one job only, which a branch cannot change, and the change's own checks run as another user even there.

1. **Make a runner key** (on any machine, once per organisation or repository):
   `use05 key new runner.key` writes `runner.key` (secret) and `runner.key.pub` (public).
2. **Store the secret where only the gate gets it.** In the GitHub repository: Settings, Environments, New environment, named `use05`. Under Deployment branches and tags choose "Selected branches and tags" and add your default branch (`main`) as the only rule. In that environment add the secret `USE05_RUNNER_KEY`, value the whole contents of `runner.key`. Then delete the local `runner.key`. Do not make it a repository or organisation secret: those reach every workflow on every branch. If you have one from an earlier setup, delete it (Settings, Secrets and variables, Actions). A job on any other branch that asks for the `use05` environment is refused by GitHub, so a workflow an agent adds to its branch cannot read the key. `use05 doctor` reminds you of this step; it cannot read GitHub's settings, so it cannot check it.
   In a private repository, environments with secrets and branch rules need GitHub Pro, Team or Enterprise. On GitHub Free this step cannot be done. The key would then have to be a repository secret, which any branch's workflow can read: the risk `CI_KEY_EXPOSED` reports, whatever the gate's workflow says. Choose a paid plan, a public repository (where environments are free), or that risk, knowingly.
3. **Trust the public key** in `.05/policy.toml`:
   ```toml
   [evidence]
   accept = ["runner"]            # only CI-signed evidence counts

   [[trust.key]]
   name = "ci"
   role = "runner"
   public = "use05-ed25519-public:..."   # the contents of runner.key.pub
   ```
   Add `expires = "2027-12-31"` to the key so a leaked CI key cannot stay trusted forever; after that date what it signed stops counting and `use05 doctor` tells you (and warns 30 days ahead).
   Because the policy is read from the change's base, this edit needs a person's approval (`use05 approve --outcome`) and takes effect once merged.
4. **Add the workflows:** `use05 init --ci github` writes two files. Commit them and get them onto your default branch: GitHub runs the gate only from there.
   - `.github/workflows/05.yml` runs on every pushed branch, pull request and merge queue. It runs from the branch's own copy: 05's copy holds no secret, asks only for `contents: read` and runs nothing of the change. It exists to start the gate. A branch can change its own copy to ask for more, including `statuses: write`, which is why the status needs step 5.
   - `.github/workflows/05-gate.yml` runs when the 05 workflow finishes (`workflow_run`). GitHub reads this file from the default branch, whatever the branch being checked holds, and runs it there, so it is the only job the `use05` environment admits. Before anything of the change is on disk, it makes the user `use05-check` (barred from cron and at, so it leaves nothing behind), installs the toolchains you name and installs use05 with the checksum-verified installer. Only then does it check out the exact commit the 05 workflow ran for (`persist-credentials: false`, so no token is left in `.git/config`) and run `use05 gate --ci --push`. 05 checks, seals and pushes the action log before any of the change's own code runs; then the change's checks run as `use05-check` (`USE05_CHECK_USER`), through `sudo -n` with a scrubbed environment, so they cannot read the runner key in 05's environment or 05's memory. The receipt records the user they ran as (`runner.check_user`). If that user cannot be used, nothing runs (`CHECK_USER_UNAVAILABLE`); the checks never fall back to the key holder's user. The runner's home is closed to `use05-check`, so a tool installed there (rustup's `~/.cargo`, for one) cannot be found or run: the check is not started (`COMMAND_NOT_STARTED`) and nothing is signed. That probe looks only at the command 05 runs (the first word of the check), so a script that calls an unreachable tool inside it still ends as a failed check. Install toolchains system-wide in the marked placeholder step, which runs before the checkout; the `setup-*` actions install under `/opt/hostedtoolcache`, which it can reach. Name toolchains only there, with versions pinned in `05-gate.yml` itself, never read from the change's files: that step runs as the key holder, with sudo, in the job that holds the key, and anything of the change run there (`npm ci`, `pip install -r requirements.txt`, `bundle install`, `make deps`) could leave something behind (in `$GITHUB_ENV`, `$GITHUB_PATH`, or a process) that reads the key in a later step. The change's own dependencies are installed inside the check command, which runs as `use05-check`: for example `run = ["sh", "-c", "npm ci && npm test"]`. The verdict goes on the commit as the commit status `05`: pending while it runs, then success, or failure with the first reason ("denied: …", "needs a person's approval"). If the status cannot be posted, the job fails and its summary says so, since branch protection would not see the verdict. The workflow has `contents: write` so the runner can push its own receipts branch (`05-receipts/<runner key>`; the token reaches git through its environment, never its command line), and `statuses: write` for the verdict.
   With a new policy, `init` also locks `.github/workflows/**` (`[protect] locked`), so a change cannot alter the gate or add a workflow; a person's bypass can. With an existing policy it prints the command: `use05 policy add protect.locked ".github/workflows/**"`.
5. **Post the status as your own app** (recommended). Any workflow's own token can post a commit status, and a branch defines its own workflows, so with the workflow token a branch can post `05: success` on its own commit after the gate, and the newest status wins. A token only your app holds closes that:
   - Create a GitHub App (Settings, Developer settings, GitHub Apps) with only the repository permissions "Commit statuses: Read and write" and "Contents: Read-only", no webhook, and install it on this repository.
   - Add the repository variable `USE05_APP_CLIENT_ID` (Settings, Secrets and variables, Actions, Variables) with the app's Client ID, shown under "About" on the app's settings page (Settings, Developer settings, GitHub Apps, Edit; it starts with `Iv`, and is not the numeric App ID). Generate a private key on the same page and store it as the secret `USE05_APP_PRIVATE_KEY` in the `use05` environment, beside the runner key.
   - The gate's workflow then makes an installation token with `actions/create-github-app-token` (pinned by commit) and posts the status with it (`USE05_STATUS_TOKEN`). The job summary says "posted by your 05 app".
   Without the app the gate posts with the workflow token, and its summary says so: "a branch can forge this status". The status is then a convenience, not evidence. What holds is the signed receipts, which no branch can forge: `use05 land`, `use05 verify` and the brief check signatures, never statuses.
6. **Require it.** Settings, Branches (or Rules), protection for `main`: require the status check `05` to pass, with your app as its expected source (classic branch protection) or the app as the check's integration (a ruleset), and block force pushes. If an earlier setup required `acceptance`, remove that: the job of that name is gone, and the new 05 workflow's own job passes without checking anything. Turn on "require branches to be up to date before merging", or use a merge queue: the gate checks a pull request's head commit, not GitHub's merge of it. Leave "require a pull request" off if changes should land without one. This is the step that turns advice into enforcement. If you skip it, nothing here is stronger than advisory, and `use05 doctor` says so.

What the gate does for each pull request and each pushed branch: it reads the rules from the base branch (from the default branch when the change shares no history with it, never from the change itself), proves the base's required checks on the exact head commit with the runner key, fetches approvals from `05-receipts/*` branches, checks the agent's action log against its seals and countersigns it with the runner key, prints the brief into the job summary and posts the `05` status. Exit 0 allows, 2 denies, 3 needs a person's approval, 5 means evidence is missing.

If the policy asks for testing before a push (`[testing]`), the gate holds a pull request or a merge queue into one of those branches, or a push to one, until a person's testing sign-off for that exact tree is on a receipts branch (`TESTING_REQUIRED`). Like an approval of the outcome, a sign-off is for the tree it names.

**Without pull requests.** The workflow gates every pushed branch except 05's own receipts branches. Push the agent's branch, let the gate pass, then `use05 land` and `git push origin main`. Landing is a fast-forward, so the commit that reaches `main` is the one CI already checked. Branch protection accepts it because its `05` status is success; that settles it only when your app posted the status (step 5). Otherwise `use05 land` is what checks the signed receipts.

**Pull requests from forks.** The gate runs and signs for them too: their code runs only as `use05-check`, and the job summary says the change came from a fork. Nothing is pushed for a fork but 05's own receipts branch, and only with `--push`. GitHub asks a person to approve the first workflow run of a new contributor.

**What is left, stated plainly.**
- Without your own app (step 5), a branch can forge the `05` status: its own workflow can ask for `statuses: write`, and an agent whose push credential can write statuses needs no workflow at all. Branch protection then rests on a status anyone with write access can set. The signed receipts still cannot be forged, so `use05 land`, `use05 verify` and the brief remain right; a merge button that trusts only the status does not.
- The status belongs to a commit, while the verdict depends on where the change goes. A pull request into `release` is judged by `release`'s rules, and its success then shows on the same commit if it is proposed into `main`. A branch gated as a push to `agent/x` and pushed unchanged to `main` keeps that status. A pull request whose run names no pull request (closed, or its head moved) is judged as going to the landing branch. Re-run the gate for the place it actually lands, or rely on `use05 land`, which judges the landing branch itself.
- Anyone with admin rights on the repository can change the environment's branch rule, add a repository secret or edit the gate on the default branch. That is a person's act, outside an agent's reach, but it is not something 05 can see.
- The checks run on the same machine as 05, as another OS user. They cannot read the key, 05's environment or 05's memory, but they share the machine: a flaw in the operating system's separation of users would reach the key.
- The token with `contents: write` can push to any branch your branch protection allows. Only 05 holds it, never the checks, but protect `main`. If that is not enough for you, drop `--push` and `contents: write`; CI then still gates every change, but its log seal is not kept.

**Moving from an earlier setup.** Before 0.0.14, `init --ci github` wrote one workflow, `05.yml`, that ran from each branch's own copy with `secrets.USE05_RUNNER_KEY`: an agent's push could change it to read the key. The gate still runs under it but reports `CI_KEY_EXPOSED` (a warning), and `use05 doctor` names the file. To move:
1. Run `use05 init --ci github`. If 05 wrote the old `05.yml` and nobody changed it, `init` replaces it; otherwise move your changes over to the new pair by hand and delete what is left of the old one.
2. Make the `use05` environment and its secret (step 2), and delete the repository secret `USE05_RUNNER_KEY`.
3. Set up your app for the status (step 5), get the change onto your default branch, then require `05` instead of `acceptance` (step 6).
4. Rotate the runner key (below), since any branch pushed while the old workflow was in place could have read it.
5. Lock `.github/workflows/**` in the policy, after the move: the lock holds back the change that does the move as well.

**Environment branches.** A push to an environment's branch is judged as the move it must be: a promotion, a revert, a hotfix's landing or a merge back, each with the promotion record 05 files after its push. Without a counted record, or when the record does not match what was pushed, the push is held. See "In CI" under Environments and promotion in [the guide](guide.md#environments-and-promotion). Require `05` on those branches as on the branch work lands on, and have your host deploy only after it passed.

Known limits:
- Approvals have to be on the remote: use `use05 approve --push` (or push the `05-receipts/<key>` branch yourself) before CI runs. `use05 brief --fetch` pulls other people's receipts.

## Phone approvals in CI

An approval signed with a passkey on [your own console](console.md) counts in CI only if both keys are in the policy:

```toml
[[trust.key]]
name = "alex-phone"
role = "approver"
person = "Alex Example"                # as in git config user.name
public = "use05-passkey-p256-public:..."

[[trust.key]]
name = "alex-macbook"
role = "local"
person = "Alex Example"                # the machine that prepares the approvals may prepare only for them
public = "use05-ed25519-public:..."    # the "machine" line of `use05 key show` on that machine
```

A Touch ID approver key from a Mac (`use05 key new --approver`) is trusted the same way: its public key is the "Touch ID" line of `use05 key show` (`use05-passkey-p256-public:touch-id:...`), with that Mac's machine key beside it. Reading it needs nothing newer than a phone's passkey does.

`person` needs use05 0.0.7 or later wherever the policy is read, so set `[use05] min_version = "0.0.7"`. Without the machine's key the brief says `no machine that prepared it co-signed it`. Keep `[evidence] accept = ["runner"]`: with `local` accepted, a machine key listed here could also sign check results that CI would believe.

**Path owners in CI.** 05 knows a person only by the `person` on their keys here, in CI and on every machine, so for [owners of paths](guide.md#owners-of-paths) list each owner's approver key (and a Touch ID key or passkey, with the machine key that prepares for them) with their name; `use05 key show` prints a machine's keys. An approval from a key with no `person` never counts as an owner's.

With a CI token from the console's Machines page stored as the secret `USE05_CI` in the `use05` environment (beside the runner key, for the same reason), CI can also file approvals signed on a phone and report its verdict to the console. Around the gate step in `05-gate.yml`:

```yaml
      - run: use05-cloud ci collect                    # file approvals signed on a phone, before the gate
        env: { USE05_CI: "${{ secrets.USE05_CI }}", USE05_RUNNER_KEY: "${{ secrets.USE05_RUNNER_KEY }}", USE05_PUSH_TOKEN: "${{ github.token }}" }
      - run: use05 gate --ci --push --json > gate.json  # the gate, as in step 4; its exit status still decides
        env: { USE05_RUNNER_KEY: "${{ secrets.USE05_RUNNER_KEY }}", USE05_PUSH_TOKEN: "${{ github.token }}", USE05_CHECK_USER: use05-check }
      - if: always()
        run: use05-cloud ci report gate.json           # send the verdict, whatever it was
        env: { USE05_CI: "${{ secrets.USE05_CI }}", USE05_RUNNER_KEY: "${{ secrets.USE05_RUNNER_KEY }}" }
```

Nothing about the gate changes: what counts is still the signatures on the receipts branches. `collect` co-signs what it files with the runner key; `report` uses it to prepare an approval CI is held for, when no machine can (a cloud session that has ended, work done without 05). The console then asks the person who made the token; they approve with their passkey, and the next run's `collect` files it. When the console's key changes (someone was removed), every token made before stops working.

## Rotating the runner key

1. `use05 key new runner-2.key`.
2. Add the new public key as a second `[[trust.key]]` entry; set `expires` on the old one if it has none. Get that policy change approved and merged.
3. Replace the `USE05_RUNNER_KEY` secret of the `use05` environment with the contents of `runner-2.key`, then delete the local file.
4. Once nothing depends on the old key, remove its entry in another approved change. Receipts it signed stop counting, so open pull requests re-prove on their next run.
If the old key leaked, do steps 2 to 4 at once and remove the old entry in the same change.

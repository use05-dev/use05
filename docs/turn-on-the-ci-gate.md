# Turn on the CI gate (the strong control)

Hooks and the pre-push gate are advisory. The CI gate is what makes 05 enforceable: a runner the agent cannot reach proves the checks and signs the receipt, and the Git host refuses the push or merge without it. About ten minutes, once per repository.

1. **Make a runner key** (on any machine, once per organisation or repository):
   `use05 key new runner.key` writes `runner.key` (secret) and `runner.key.pub` (public).
2. **Store the secret in CI.** In the GitHub repository: Settings, Secrets and variables, Actions, new repository secret named `USE05_RUNNER_KEY`, value is the whole contents of `runner.key`. Then delete the local `runner.key`. The agent and anyone without secret access cannot read it.
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
4. **Add the workflow:** `use05 init --ci github` writes `.github/workflows/05.yml`. It installs use05 with the checksum-verified installer, then runs `use05 gate --ci --push`. The workflow has `contents: write` so the runner can push its own receipts branch (`05-receipts/<runner key>`); that is how what it sealed outlives the job. The checkout keeps no credentials (`persist-credentials: false`), the token reaches 05 only by name (`USE05_PUSH_TOKEN`), and 05 checks, seals and pushes the action log before it runs any of the change's own code; the checks run with a scrubbed environment. Residual risk, stated plainly: the change's checks run on the same runner as the same user, and a token with `contents: write` can push to any branch your branch protection allows. Protect `main`, and if that is not enough for you, drop `--push` and `contents: write`; CI then still gates every change, but its log seal is not kept.
5. **Require it.** Settings, Branches (or Rules), protection for `main`: require the `acceptance` check (job name in 05.yml) to pass, and block force pushes. Leave "require a pull request" off if changes should land without one. This is the step that turns advice into enforcement. If you skip it, nothing here is stronger than advisory, and `use05 doctor` says so.

What the gate does on each pull request and each pushed branch: it reads the rules from the base branch, proves the base's required checks on the exact merge tree with the runner key, fetches approvals from `05-receipts/*` branches, checks the agent's action log against its seals and countersigns it with the runner key, and prints the brief into the job summary. Exit 0 allows, 2 denies, 3 needs a person's approval, 5 means evidence is missing.

If the policy asks for testing before a push (`[testing]`), the gate holds a pull request or a merge queue into one of those branches, or a push to one, until a person's testing sign-off for that exact tree is on a receipts branch (`TESTING_REQUIRED`). Like an approval of the outcome, a sign-off is for the tree it names: GitHub tests the merge of a pull request, which is the same tree only when the branch is up to date with its base, so bring the branch up to date before signing off.

**Without pull requests.** The workflow gates every pushed branch except 05's own receipts branches. Push the agent's branch, let the gate pass, then `use05 land` and `git push origin main`. Landing is a fast-forward, so the commit that reaches `main` is the one CI already checked, and branch protection accepts it because its required check passed.

Known limits:
- Pull requests from forks get no secrets and a read-only token, so the gate cannot sign (it fails with `NO_RUNNER_KEY`) and could not push. A refused push is reported, never fatal. Review fork PRs by hand, or run the gate on a trusted branch after review.
- Phone (passkey) approvals count in CI only if both keys are in the policy: the passkey with `role = "approver"` and `person = "<the owner's name, as in git config user.name>"`, and the key of the machine that prepared the approval (the "machine" line of `use05 key show` on that machine) with `role = "local"`. `person` needs use05 0.0.7 or later wherever the policy is read, including the CI gate: set `[use05] min_version = "0.0.7"` so an older one says to upgrade instead of refusing the file. Without the machine's key the brief says `no machine that prepared it co-signed it`. Give the machine key the same `person` so it can only prepare for them. Keep `[evidence] accept = ["runner"]` (step 3): with `local` accepted, a machine key listed here could also sign check results that CI would believe.
- Approvals have to be on the remote: use `use05 approve --push` (or push the `05-receipts/<key>` branch yourself) before CI runs. `use05 brief --fetch` pulls other people's receipts.

## Your own console

With [your own console](console.md), CI can report each verdict there and collect approvals signed on a phone. Store a CI token from the console's Machines page as the secret `USE05_CI`, then around the gate step:

```yaml
      - run: use05-cloud ci collect                    # file approvals signed on a phone, before the gate
        env: { USE05_CI: "${{ secrets.USE05_CI }}" }
      - run: use05 gate --ci --push --json > gate.json  # the gate, as in step 4; its exit status still decides
        env: { USE05_RUNNER_KEY: "${{ secrets.USE05_RUNNER_KEY }}", USE05_PUSH_TOKEN: "${{ github.token }}" }
      - if: always()
        run: use05-cloud ci report gate.json           # send the verdict, whatever it was
        env: { USE05_CI: "${{ secrets.USE05_CI }}" }
```

Nothing about the gate changes: what counts is still the signatures on the receipts branches.

## Rotating the runner key

1. `use05 key new runner-2.key`.
2. Add the new public key as a second `[[trust.key]]` entry; set `expires` on the old one if it has none. Get that policy change approved and merged.
3. Replace the `USE05_RUNNER_KEY` secret with the contents of `runner-2.key`, then delete the local file.
4. Once nothing depends on the old key, remove its entry in another approved change. Receipts it signed stop counting, so open pull requests re-prove on their next run.
If the old key leaked, do steps 2 to 4 at once and remove the old entry in the same change.

# Your own console

The console is a web app you host yourself. Open it on your phone or laptop to see what every agent on your machines is doing, approve the work that waits for you with a passkey (Face ID, a fingerprint, a security key), sign off that you tested a change, throw away work an agent left behind, tighten a policy, and get an email when something needs you. Pages update as things happen.

It is optional: everything else in 05 works without it. There is no hosted version: nobody runs a console for you, and 05 never sends anything anywhere else. Your console runs where you put it, holds your activity and nobody else's, and is encrypted end to end, so even the host it runs on cannot read your work.

- [What it can and cannot do](#what-it-can-and-cannot-do)
- [Run it](#run-it)
- [Claim it](#claim-it)
- [Connect your machines](#connect-your-machines)
- [Approve from your phone](#approve-from-your-phone)
- [Testing, discarding and policy edits](#testing-discarding-and-policy-edits)
- [Email](#email)
- [Cloud sessions and CI](#cloud-sessions-and-ci)
- [Encryption and what the server sees](#encryption-and-what-the-server-sees)
- [Passkeys and the recovery code](#passkeys-and-the-recovery-code)
- [If you work with others](#if-you-work-with-others)
- [When something is stuck](#when-something-is-stuck)
- [Commands](#commands)

## What it can and cannot do

**What you see.** **Home** says how many things need you and lists them: approvals your machines asked for, work held for a person even when no approval was asked yet (each says how to unblock it), testing sign-offs a push waits for, and work that looks abandoned (untouched for a week). **Activity** is everything your machines reported. **Repositories** shows each repository with its tasks, its policy and CI's latest verdict. A task's page shows the plan, the files touched (names only), what 05 found, the checks, and what you can do about it. **Machines** lists your machines and passkeys, and makes tokens for cloud sessions and CI.

**What you can do from it.**

- Approve an agent's plan or result with your passkey ([below](#approve-from-your-phone)).
- Sign off that you tried a change in your own environment, when the policy asks for it before a push.
- Discard work an agent left behind: its worktree, its branch here and on origin, and 05's record of it.
- Tighten a repository's policy, one rule at a time, and keep a base policy to start new repositories from.
- Allow a second machine to report a repository, pair machines, add and remove passkeys.

**What it never does.** Machines connect out to the console; it never reaches into a machine. A machine runs nothing it is sent. When the console asks, the helper on your machine does only these things: send the repository's folder tree (names only), prepare a statement for you to sign (an approval, a testing sign-off, a discard), file what you signed if it is exactly what it prepared, prepare and apply a policy edit that only tightens, and take a new console key you confirmed with your passkey. So someone who took over the console could not read your work, run anything on your machines, loosen a rule, or approve anything a machine did not ask for. The [honest limit](#the-honest-limit) says what they could do.

**What never leaves your machine.** Code, diffs, prompts and the agent's messages. What a machine reports (plans, file and folder names, checks and verdicts, the policy) is sealed before it leaves.

## Run it

One container image; its data is one SQLite file, so give it a volume:

```sh
docker run -p 8080:8080 -v console-data:/data \
  -e ORIGIN=https://console.example.com \
  ghcr.io/use05-dev/use05-console
```

Put it behind HTTPS: passkeys need it (plain `http://` works only on `localhost`). Host it where only you can change what it serves (see [the honest limit](#the-honest-limit)).

| Setting | What it is |
|---|---|
| `ORIGIN` | The address you open, with `https://`. Passkeys are tied to its host name, so **choose it before you sign up**: moving to another address later means adding your passkeys again. |
| `RP_ID` | The passkey site, if it is not `ORIGIN`'s host (for example a parent domain). |
| `DATABASE` | The database file. In the image, `/data/console.db`; the console creates it and its tables when it starts, and updates the tables when a new version starts. (`DATABASE_URL` from older versions is refused with a message saying so.) |
| `SETUP_SECRET` | Optional: a claim code of your own. Without it, the console makes one each time it starts while nobody owns it, and writes it to its log. |
| `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`, or `SMTP_URL` | Email, through Cloudflare Email Service or any SMTP server (`smtps://user:password@host:465`, or `smtp://…?tls=required`; plain SMTP is refused). Without either, alerts show in the console only. See [Email](#email). |
| `ALERT_FROM` | The address emails come from, on your own domain. Required when email is on. |
| `PORT` | Default 8080. |
| `RUST_LOG` | Log detail, default `info`. |

**On Railway.** Deploy the image, attach a volume at `/data`, and set `ORIGIN` to the service's address and `RAILWAY_RUN_UID=0`: Railway mounts volumes owned by root, so the container must run as root to write there. The claim code is in the service's deploy logs.

**Back it up** while it runs: `sqlite3 /data/console.db ".backup /data/backup.db"`. The backup holds the same sealed records, which it cannot read either.

**Upgrade** by running the new image on the same volume. The console updates its tables as it starts; machines keep working, and each machine's helper says which `use05` it runs.

**Logs** go to standard output (`docker logs`, or your host's log view). They never contain what machines report.

## Claim it

Until someone has made a passkey, whoever signs up first would own the console, and a new public address can be found within minutes. So the first sign-up needs a claim code. The console writes it to its log when it starts:

```
05 console has no owner yet. Claim it from your terminal: use05 cloud login https://console.example.com (claim code: ABCDE-FGH23)
```

Then, on your machine, inside a repository:

```sh
use05 cloud login https://console.example.com
```

It asks for the claim code (case, spaces and dashes do not matter), then gives you a one-time link (good for 15 minutes) where you give your name and make your passkey. You are the console's owner. You are then shown your recovery code once: keep it ([why](#passkeys-and-the-recovery-code)). The terminal goes on to pair the machine, and, because you ran it inside a repository, reports that repository, pins your passkeys on the machine (asking you to confirm each one), and starts the helper in the background. Outside a repository, it lists those steps instead. You can also open the console and type the claim code there.

The code changes each time the console restarts until it is claimed; `SETUP_SECRET`, if set, is the code instead. After the first passkey exists, neither does anything.

**Signing in.** You stay signed in until you have not used the console for an hour, also when you open it from a link in an email. A page left open on its own does not keep you signed in. After an hour, or in a new browser, one passkey tap signs you in again; the page returns to sign-in by itself when a session ends. Once signed in, your passkey also unlocks your records in that browser ([Encryption](#encryption-and-what-the-server-sees)).

## Connect your machines

`use05-cloud`, the helper, comes with 05 (0.0.7 and later) on macOS and Linux. On each machine:

```sh
use05 cloud login https://console.example.com   # pair this machine: a word, then a code to compare
use05 cloud add                                   # in each repository you want to see
use05 cloud enrol                                 # pin your passkeys here, so approvals from your phone count
use05 cloud install                               # keep the helper running in the background
```

`login` inside a repository does the other three for that repository too.

**Pairing.** `login` shows a word. Open the console, choose **Pair this machine**, and type it: only someone at that terminal can see it. Then the terminal and the console each show a code, worked out on each side from your console's key, the machine's keys and a random number from each side. Approve only if the two codes are the same; if they differ, something swapped a key, so do not pair. A machine belongs to whoever pairs it, and only they approve the work done on it.

**Repositories.** `use05 cloud add [path]` reports a repository (the one you are in by default). The first machine to report a repository speaks for it. Another machine reporting the same repository waits on **Machines** until you allow it, so a pairing taken from one machine cannot change what another machine asks you to sign.

**Pinning passkeys.** `use05 cloud enrol`, at a terminal, shows each passkey on your console (its name, whose it is, the site it was made for and the day it was added) and asks before pinning it on this machine; a machine files an approval only from a passkey pinned on it. It warns when git on this machine knows you by another name: approvals count only for work recorded under your name (`git config user.name`).

**In the background.** `use05 cloud install` adds the helper as a listener for 05's events and keeps it running: a launchd job on macOS (`dev.use05.cloud`), a `systemd --user` service on Linux (run `loginctl enable-linger $USER` to keep it running while you are logged out). Where there is neither, such as a container, it prints the command to run under your own supervisor. Its log is `~/.config/05/cloud.log`.

**Status.** `use05 cloud status` shows the console, this machine's name, which `use05` it uses, the repositories it reports, how many passkeys are pinned, how the helper runs, where its keys are, and whether the console answers. `use05 cloud sync` sends everything once, now.

**Its keys** are files in `~/.config/05` that only you can read. An agent running as you can still read them, which is why 05 calls local enforcement advisory and CI the strong control.

## Approve from your phone

When an agent's work needs a person (a protected file, a risky change, a plan your policy wants approved), 05 on your machine says so, the helper asks it to prepare the exact approval, and the approval appears on **Home** (with an email, if email is on).

1. Open it. You see the plan, the files touched (names only), what 05 found, and the checks.
2. Tap **Approve with passkey**. Before your passkey is asked, the page reads the statement your machine prepared and checks that it is an approval of exactly what is shown: this task, this tree, under the policy in force now. It shows until when it lasts.
3. Your passkey signs exactly that statement, which your machine has already co-signed with its own key. The helper files it on your machine within seconds.
4. Tell the agent to carry on, in the app you prompt it from. Nothing wakes it by itself.

If the work changes after you approve, the approval stops counting and 05 asks again. To reject a change, tell the agent, or run `use05 approve --reject --reason "…"` at a terminal.

**Why a phone approval is safe to count.** A passkey approval counts only with a trusted machine's (or CI runner's) co-signature on the same statement, and only when the passkey belongs to the person who owns the work: you approve your own agents' work, not someone else's. A page holding a passkey can be made to sign anything; this way, what it signs counts only for what a machine prepared.

**For phone approvals to count in CI too,** list each passkey under `[[trust.key]]` with `role = "approver"` and its `person`, and the machine that prepares the approvals with `role = "local"` and the same `person`. That is a change to the policy you approve at a terminal; see [Turn on the CI gate](turn-on-the-ci-gate.md).

## Testing, discarding and policy edits

**Testing before a push.** If the policy asks for testing (`[testing] local = "required"` or `"skippable"`), a push to the chosen branches waits until the person driving the work has tried the change in their own environment and signed off. On the task's page, under **Tested before a push**, write what you tried and sign with your passkey: your machine prepares the statement for this exact tree, your passkey signs it, and your machine files it. Where the policy allows skipping, you can skip with a reason. See [Testing before a push](guide.md#testing-before-a-push).

**Discard this work.** Work an agent left behind keeps asking for you. Open the task and choose **Discard this work**. Your machine (it must be online) says what would go (the worktree, the branch here and on origin) and what would be lost that exists nowhere else (commits on no remote branch, files never committed). Your passkey confirms, and the machine removes it all and marks the task discarded; the console then forgets it. It cannot be undone. It never deletes your landing branch or a branch the policy keeps, never touches work an agent's session is still doing, and does nothing if the work moved after you looked. Nothing is ever deleted on its own: work untouched for a week is only marked as looking abandoned. At a terminal, `use05 discard <task>` does the same.

**Edit a policy.** Open a repository and choose **Edit policy**. Every setting is a switch, a choice or a list; folders and files come from your repository's tree (names only). The bar at the bottom shows what changed, and **Show the file** shows exactly what will be written, comments kept. Save one rule at a time with **Save this rule**, or every change at once. Saving is approving: your machine builds the edit as a commit on top of origin's landing branch and checks it, you sign it with your passkey, and the machine pushes the commit. Your other machines get it with their next pull.

Edits from the console only tighten: protect or lock more, raise a strictness, require more. Anything that loosens a rule, and anything that decides what runs, what is trusted or what counts as proof (check commands and their variables, trusted keys, accepted evidence, how many approvals are needed, locks no bypass clears, whether 05 fails open), is changed at a terminal. A check your machine found by itself can be added; a typed command never can.

**Base policy.** Under **Base policy** keep the settings you like to start a repository with. On a repository's policy page, **Use base policy** copies them into the editor for you to review and save; the repository's own checks and keys are kept. A repository without 05 is set up at a terminal first, with `use05 init`.

## Email

Email comes only when something needs you: an approval of your work waiting, a policy edit of yours that could not be applied, a machine of yours refusing a request, a passkey added, and a machine asking to report a repository another already reports. Each email says only that something needs you and links to it: never the repository's goal, the plan or file names. Several at once become one email.

To turn it on, whoever hosts the console sets either:

- **Cloudflare Email Service:** add your domain as a sending domain (Cloudflare adds its DNS records), create an API token that may send email, and set `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`; or
- **SMTP:** `SMTP_URL`, for example `smtps://user:password@mail.example.com:465`;

and `ALERT_FROM`, an address on that domain. Then, under **Settings**, set your address, confirm it from the link, and send a test email; if the provider refuses one, the reason shows there.

## Cloud sessions and CI

**Claude Code cloud sessions.** For 05 to hold work done in a cloud session, its hooks travel with the repository: run `use05 init --shared-hooks` and commit `.claude/settings.json`. Under **Machines**, **Cloud sessions and CI**, make a token for one repository and store it in the Claude Code cloud environment as `USE05_SESSION`. In a cloud session (and only there) the first hook installs this version of 05 when the session lacks it, and reports to your console with `use05-cloud session`.

A session's token reports for that one repository, as you, and is sent nothing to run. What it reports shows as coming from the cloud session and never replaces what a machine paired at a terminal reported. The agent can read the token, so treat what a session reports as the session's word. Codex cloud runs its agent offline by default; there, the work's receipts travel in the repository and CI reports for it.

**CI.** Make a token the same way and store it as the CI secret `USE05_CI`, next to `USE05_RUNNER_KEY` (see [Turn on the CI gate](turn-on-the-ci-gate.md)). The installer the workflow already runs puts `use05-cloud` next to `use05`. In `.github/workflows/05.yml`, around the gate step `use05 init --ci github` wrote:

```yaml
      - name: File approvals signed on the console
        env:
          USE05_CI: ${{ secrets.USE05_CI }}
          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}
          USE05_PUSH_TOKEN: ${{ github.token }}
        run: use05-cloud ci collect
      - name: Prove and gate
        env:
          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}
          USE05_PUSH_TOKEN: ${{ github.token }}
        run: use05 gate --ci --push --json > gate.json
      - name: Tell the console
        if: always()
        env:
          USE05_CI: ${{ secrets.USE05_CI }}
          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}
        run: use05-cloud ci report gate.json
```

The gate step still fails the job when the gate holds the change; the last step runs either way. `collect` co-signs what it files with the runner key, and `report` uses it to prepare an approval CI is held for.

The repository's page then shows CI's latest verdict, or "CI gate not seen" until one arrives. When CI holds work for a person and no machine can prepare the approval (a cloud session that has ended, work done without 05), `report` prepares it for the person who made the token, co-signed by the runner key, and asks on the console; they approve with their passkey, and the next run's `collect` files it. It asks only when an approval would clear something; a missing testing sign-off is given at a terminal. For it to count, the policy lists their passkey with their `person` and the runner key with `role = "runner"`. Only the token's person is asked.

When the console's key changes (someone was removed), every token made before stops working, and **Machines** says which: make new ones.

## Encryption and what the server sees

**Sealed on the machine, opened in your browser.** Each machine seals what it reports to your console's key and signs it with its own. Your browser checks the signature, opens it, and builds every page itself; the policy editor runs in your browser too. Your console's key is never on the server in a form it can use: it is wrapped for each of your passkeys (using the passkey's PRF feature) and for your recovery code, and unwrapped only in your browser.

**What the server stores:** sealed records it cannot open, and what it needs to route them: which machine sent what, which repository (by an opaque id), what kind of record, when, and who must approve what. It also knows your name, your email if you set one, your passkeys' public keys, your machines' names and when they were last heard from.

**What it cannot see:** plans and goals, file and folder names, checks and verdicts, the policy, approval contents. Code, diffs, prompts and agents' messages never leave your machine at all.

| Who | What they could do | What they could not do |
|---|---|---|
| Someone who copies the database or a backup | Read the routing data above | Read any record |
| Whoever controls the host (see below) | Serve a page that reads what you unlock in that browser, or asks your passkey to sign something other than what it shows | Run anything on your machines, loosen a policy, approve what no machine prepared, make CI count a passkey the policy does not list |
| Someone who took a machine's pairing | Report as that machine for the repositories it speaks for | Speak for another machine's repositories, run anything, approve |
| An agent running as you | Read the helper's keys on that machine (local enforcement is advisory) | Make CI count anything: CI trusts only the keys listed in the committed policy |
| Someone you removed | Nothing new: their sessions end, their machines are cut off, and a new key is made that they do not have | Read what is sealed after the key changed |

### The honest limit

The web app's code comes from the console. Whoever controls the host could serve a page that reads what you unlock in that browser, or that shows you one thing and asks your passkey to sign another: an approval a machine really asked for, a policy edit that tightens, or a new console key for your machines. So host it where only you can change what it serves. Machines and CI keep their own checks even then: nothing runs that a machine did not prepare, and a policy edit only tightens. Approvals and edits show in git and in 05's brief.

Two smaller limits. The console can show an older copy of a record to a browser that never saw the newer one (a browser that did refuses it). And if you work with others: someone who left could, working with whoever runs the host at the moment the key changes, take the copy of the new key meant for one member; that member then cannot unlock, and an admin's browser refuses it outright if it saw that member's key before.

If a machine refuses a request, it says so on **Home**, emails you, and keeps its own record in `~/.config/05/cloud-refusals.log`. If you did not ask for what it refused, revoke the machine's pairing under **Machines**, remove and re-add your passkeys (which signs you out everywhere), and find out who can change the host.

## Passkeys and the recovery code

**Your passkey** signs you in, approves, and unlocks your records. Unlocking needs a passkey with the PRF feature: iCloud Keychain on iOS 18 or macOS 15 and later, Google Password Manager, a recent Chrome, 1Password, or a YubiKey 5. A passkey without PRF still signs you in.

**Keep a second passkey.** Signing in always takes one of your passkeys. Add another under **Machines**, **Add a passkey** (another device, or a security key); it asks for a passkey you already have first, and emails you. Synced passkeys (iCloud Keychain, Google Password Manager) survive a lost phone. If you lose a device, sign in with another passkey and remove the lost one under **Machines**.

**The recovery code**, 32 letters and digits, is shown once when you claim or join. It unlocks your records in a browser where your passkey cannot: a passkey without PRF, or a new passkey you just added (sign in with it once, then unlock with the code). Make a new one under **Settings**; it replaces the old.

**If every passkey is gone,** you cannot sign in again, and with your recovery code alone you cannot either. Working alone, start over: stop the console, move its database aside, start it (it prints a new claim code), claim it, and pair your machines again; they report again what they still have. Your git history, receipts and policy are on your machines and are not affected. If you work with others, an admin can invite you again as a new person.

## If you work with others

The console works for one person by default. To bring in others, go to **Team**:

- **Invite** someone: an invitation is a link that works once, for 48 hours. They give their name and make their own passkey, and get their own recovery code.
- **Admins** invite and remove people and allow machines to report repositories; **members** see the team's work and approve their own. Change someone's role under **Team**.
- **Each person approves their own work.** A machine belongs to whoever paired it, and only they approve what is done on it. Each person uses the name git records them under, so approvals from their phone match their own work in CI, and sets and confirms their own email under **Settings**.
- **Removing someone** ends their sessions and cuts off their machines at once. Because they still hold the console's key, removing them also makes a new one (one passkey tap by the admin), sealed to everyone who stays; what came before stays readable. Each person then confirms the new key for their own machines from **Home**, with their passkey. A machine takes a new key only from a passkey pinned on it (`use05 cloud enrol`); until then it keeps sealing to the old key. Tokens for cloud sessions and CI made before the change stop working.

## When something is stuck

- **A machine shows offline.** A machine is online when it was heard from in the last 90 seconds. Is it awake? `use05 cloud status` says whether it reaches the console; the log is `~/.config/05/cloud.log`. If the helper is not running, `use05 cloud install`.
- **"Nothing needs you", but work is held.** Home counts both approvals asked for and work held without a request; each held task says how to unblock it. If a task waits for an approval that never appears, the machine that did the work is offline or the passkey is not pinned there.
- **An approval is filed but does not count.** The work or the policy changed after it was prepared. Ask the agent to finish again; a fresh request appears.
- **The machine could not file an approval.** Usually the passkey is not pinned there yet: run `use05 cloud enrol` on that machine.
- **A policy edit is stuck because origin moved.** Someone pushed meanwhile. Save the edit again; it is prepared on the new tip.
- **A policy edit is stuck because the push was refused.** The landing branch is protected on your Git host (pull requests required, for example). Change the policy at a terminal and open a pull request, or allow direct pushes to that branch.
- **You are signed out.** An hour without use ends a session; one passkey tap brings you back.
- **The passkey prompt never appears.** The console must be on `https://` and `ORIGIN` must be the address in your browser's bar; `RP_ID` must be that host or a parent of it.
- **The claim code is lost.** Restart the console: while nobody owns it, it makes a new code at each start and writes it to its log.
- **A second machine's repository does not show.** It waits on **Machines** until you allow it.

## Commands

| Command | What it does |
|---|---|
| `use05 cloud login <url> [--name NAME]` | Claim a new console, or pair this machine with one: type its word in the console, then compare codes. Inside a repository it also reports it, pins your passkeys and starts the helper. |
| `use05 cloud add [PATH]` | Report this repository (default: the one you are in). |
| `use05 cloud enrol` | Pin your console's passkeys as approvers on this machine, one by one, at a terminal. |
| `use05 cloud install` | Run the helper in the background (launchd or `systemd --user`) and hear 05's events. |
| `use05 cloud status` | What is set up, and whether the console answers. |
| `use05 cloud sync` | Send everything once, now. |
| `use05-cloud session [--background]` | In a cloud agent session, report with the token in `USE05_SESSION`. |
| `use05-cloud ci collect` | In CI, file approvals signed on the console since the last run (token in `USE05_CI`). |
| `use05-cloud ci report <gate.json>` | In CI, send the gate's verdict, and ask for an approval CI is held for. |
| `use05 discard <task>` | Throw away work an agent left behind, after seeing what would be lost. |

`use05 cloud …` and `use05-cloud …` are the same program.

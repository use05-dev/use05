# Receipt format

A 05 receipt is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope around an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), signed with Ed25519, or, for a person's approval, with a passkey. Any DSSE implementation can verify an Ed25519 signature; 05's own check adds the tree comparison. The reference implementation is `crates/receipt`, and a test there fails if this page stops naming every record type, subject and field the code writes.

## Envelope

```json
{ "payloadType": "application/vnd.in-toto+json", "payload": "<base64 of the statement>",
  "signatures": [ { "keyid": "<hint, never trusted>", "sig": "<base64 Ed25519 signature>" } ] }
```

`payload` is the statement's exact bytes, `payloadType` is always `application/vnd.in-toto+json`, and `signatures` holds one or more entries. The signature is over the DSSE pre-authentication encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`. The key id (`keyid`) is an unauthenticated hint; a verifier is always given the public key it should trust.

### Passkey signatures

A passkey (WebAuthn) cannot sign arbitrary bytes, so an entry it made carries the rest of its assertion:

```json
{ "sig": "<base64 DER ECDSA P-256 signature>",
  "webauthn": { "authenticatorData": "<base64>", "clientDataJSON": "<base64>" } }
```

The page asks the passkey to sign with the challenge set to the SHA-256 of the pre-authentication encoding, so `sig` still covers exactly the statement. A verifier holding the passkey's public key and the site it was made for (its relying party id) checks, in this order: that `sig` is a valid ES256 signature over `authenticatorData` followed by the SHA-256 of `clientDataJSON` (both halves of the curve order are accepted); that `authenticatorData` starts with the SHA-256 of the relying party id and has the user-present and user-verified flags set (Face ID, a fingerprint or a PIN was used); and that `clientDataJSON` has `type` `webauthn.get`, a `challenge` (base64url) equal to that SHA-256, an `origin` of `https://` and the relying party id (`http://localhost:<port>` only for `localhost`), and no `crossOrigin: true`. Entries with `webauthn` are skipped by an Ed25519 check, and entries without it by a passkey check.

A passkey approval carries a second entry: the Ed25519 signature of the machine (or CI runner) that prepared the statement, made when `use05 approve --unsigned` printed it (`details.cosignature`). A page that holds a passkey could be made to sign any challenge, so a passkey approval counts only when a key trusted with `role = "local"` or `"runner"` co-signed the same statement, and only when the passkey belongs to the person driving the work: a `[[trust.key]]` passkey whose `person` matches the approver the co-signed statement names and, when the work's owner is recorded, the owner's name (ignoring case and surrounding spaces); or a passkey pinned in `passkeys.pub` on the machine whose approver owns the work. A machine key listed with a `person` prepares only for that person. Otherwise the approval is kept but void, and the brief says why: `no machine that prepared it co-signed it`, `its trust entry names no person`, `it was signed by someone other than the person driving the work`, or `it was prepared on someone else's machine`. Approvals signed with an Ed25519 approver key at a terminal need no co-signature.

A passkey's public key is written `use05-passkey-p256-public:<relying party id>:<base64 of the 65-byte uncompressed point>`. 05 counts passkey signatures for approvals only: intent approvals, and outcome approvals and rejections. A bypass, evidence or any other record signed by a passkey does not count.

## Statement

`_type` is `https://in-toto.io/Statement/v1`. A statement has a `subject` (a list of `name` and `digest`), a `predicateType` and a `predicate`.

### Subjects

| `name` | `digest` | Used by |
|---|---|---|
| `tree` | `gitTree`: the git tree id; `sha256`: a SHA-256 over the tree's content, so a SHA-1 collision in git cannot move a receipt to different content | evidence, outcome approvals, bypasses, outcomes |
| `intent` | `sha256`: the digest of the intent card | intent approvals, declarations |
| `log` | `task`: the task id; `sha256`: the chain hash of the last line the seal covers | log seals |
| `commit` | `gitCommit`: the commit id | promotions, sign-offs and a promotion's bypasses (the source commit), deployments (the deployed commit) |

The `tree` digest is always over the committed bytes. When the repository uses Git LFS, those bytes are the small pointer files, and with `[evidence] lfs = true` the check runs on the real files instead. The evidence then carries `lfs`: one entry per file, with its `path`, `oid` (the SHA-256 the pointer names, which 05 checked the fetched file against) and `size`. A reader can see exactly which large files the check saw. Line endings and other filters are never applied.

### Record types

| `predicateType` | Meaning | Predicate fields |
|---|---|---|
| `https://use05.dev/evidence/v0` | A command ran on that exact tree | `command` (`argv`, `cwd`; `dir`, the folder of the tree the command ran in, only when the policy check names one), `environment` (`fingerprint`, `names`: variable names only, never values), `result` (`status`: passed, failed or timed_out; `exit_code`; `signal`; `duration_ms`; `stdout` and `stderr`, each `total_bytes`, `retained_bytes`, `truncated` and a `sha256` of the stream, never its text), `runner` (`name`, `version`, `platform`; `check_user`, the OS user the command ran as when that was not the user holding the key, as in CI), `created`, `check` (the policy check's name, if any), `lfs` (only when the policy asks for Git LFS files, see below: each `path`, `oid` and `size` of a file fetched in place of its pointer) |
| `https://use05.dev/approval/v0` | A person approved or rejected an intent or an outcome | `decision` (approve or reject), `scope` (intent or outcome), `task`, `intent_sha256` (for intent approvals), `policy_sha256` (the rules in force; a policy change voids it), `rationale`, `approver`, `created`, `expires`, and only on an approval of a hotfix's outcome, `hotfix` (the environment it lands on: only such an approval, for that environment and that `task`, counts for landing it; an ordinary approval of the same tree never does) |
| `https://use05.dev/bypass/v0` | A logged break-glass override of one exact blocked tree; or of one rule of promoting one exact commit into an environment, whose subject is then that commit | `reason`, `by`, `findings` (what it overrode), `created`, `expires`, and for a promotion `env` (promoted into), `from` (promoted from), `rule` (the rule it clears) and `policy_sha256` (the rules in force; a policy change voids it) |
| `https://use05.dev/testing/v0` | A person's word that they tried that exact tree in their own development environment, or that they skipped it and why. Signed by their approver key or passkey; never an approval | `outcome` (tested or skipped), `task`, `note` (what they tried, or why not, in their words), `tester`, `created` |
| `https://use05.dev/discard/v0` | A person's word to throw a task's work away: its worktree, its branch here and on origin, and what the console holds about it. Prepared and co-signed by the machine that holds the work, signed by the person's approver key or passkey, and acted on there only; never stored as a receipt. Its subject is the work (`task`, and `gitCommit`, the branch's head) | `task`, `branch`, `head`, `unpushed` (commits on no remote branch and not landed), `uncommitted` (files never committed), `by`, `created` |
| `https://use05.dev/org-layer/v0` | An organisation's policy floor, signed by its pinned key | `org`, `floor`, `created` |
| `https://use05.dev/intent/v0` | An agent's declaration of what it will do, sealed by its hook | `task`, `title`, `author`, `card` (scope, acceptance checks, goal), `sealed`, `policy_sha256`, and when known `agent` (`kind`, `session`, `model`), `owner` (`name`, `key_id`: recorded, and confirmed only by that key's signed approval) and `sandbox` (what the agent's own process reported; its word, not a fact) |
| `https://use05.dev/outcome/v0` | What the author said they did, for the tree they finished on. An assertion, never a fact | `task`, `outcome`, `finished`, `base` (where the finished work met the landing branch when the task finished, when known) |
| `https://use05.dev/log/v0` | A seal on an agent's action log: the log had `seq` lines and the last one had chain hash `head` | `task`, `seq`, `head`, `created` |
| `https://use05.dev/promotion/v0` | One exact commit moved into an environment, or sent to a destination (see "Environments and promotion" in the guide), written only once the push went through. Signed by the CI runner key, or by the key of the machine that promoted; where a person promoted, their approver key or Touch ID key signs it too | `env` (promoted into), `from` (promoted from), `direction` (up, back or hotfix), `source_commit` (the commit that was evaluated and moved), `target_before` (the branch's head before; absent when the promotion created it), `result_commit` (its head after), `how` (fast-forward or merge, or revert; push or export for a destination), `rollback_point` (the commit to go back to; absent when there was none), `rules` (each `rule`, its `severity` (allow, warn, approval or deny), `outcome` (pass, fail, bypassed or skipped) and `detail`), `bypasses` and `signoffs` (the receipts it went with, by path), `policy_sha256`, `created`, `by`, and only on a revert 05 made because a deploy was not confirmed or a person rolled back, `reverts` (the head it undid; the revert commit is then its `source_commit` and `result_commit`, its `how` is `revert`, it has no rules and no rollback point, and it keeps the `from` and `direction` of the promotion it undoes). A hotfix's record (`direction` hotfix) names its `task`, and its `from` is the environment itself; a back-merge's (`direction` back) is from the environment above, and its `how` is merge. A destination's record has the destination's name as `env`, and as `from` the environment its source branch is, else that branch; for an export, `result_commit` is the commit made in the other repository and `target_before` its branch's head there |
| `https://use05.dev/deployment/v0` | What an environment was seen running: its probes and smoke checks, and whether they confirm the commit. Signed like a promotion | `env`, `commit`, `probes` (each `name`, `matched`, `output_sha256`: a hash of what it printed, never the text, `attempts`, `seconds`), `smoke` (each `name`, `passed`), `confirmed` (every probe showed the commit and every smoke check passed; never true without a probe), `created`, `action` (none, reverted or rollback-command) |
| `https://use05.dev/signoff/v0` | A person's sign-off on promoting one exact commit into an environment, or their rejection of it; a promotion's approval is one too. Signed by their approver key or passkey | `env`, `from`, `source_commit`, `decision` (approve or reject), `signer_person` (as the policy names them on their key), `text` (their own words), `answers` (to the policy's questions, in order), `confirmations` (the policy's `confirm` statements they confirm, word for word), `policy_sha256` (a policy change voids it), `created`, `expires` |

Receipts never contain command output, file contents, diffs or prompts; a testing sign-off carries only the note its person wrote. Unknown fields are ignored when reading; the signature covers every byte, so nothing can be added after signing. In the environment records (promotion, deployment, sign-off rules), a field that holds one of a few words (`direction`, `severity`, `outcome`, `action`) may gain words in v0: readers treat a value they do not know as unknown, never as an error.

### Keys

A receipt counts only if a key the verifier trusts signed it. Keys have roles: `local` (this machine; advisory, since any process running as you can use it), `runner` (a CI secret; authoritative evidence) and `approver` (a person's passphrase-protected key, or a passkey). Approvals, sign-offs and bypasses count only when an approver key signed them, and bypasses only an Ed25519 one; a machine key cannot approve. Promotions and deployments are what a machine did and saw: they count only from a machine or runner key, never a person's alone. A person's signature beside the machine's on a promotion says who promoted.

## The action log and its seals

An agent's action log is JSON lines, one event per line: `seq` (1, 2, ...), `t` (RFC 3339), `prev` (the previous line's `hash`, empty for the first), `event` (tool, paths and decision; never contents or prompts) and `hash`. A line's hash is the SHA-256 of `prev`, then `seq` in decimal, then `t`, then the event serialised as compact JSON (no spaces, keys in sorted order, UTF-8 with non-ASCII characters left unescaped, integers written as integers), concatenated without separators.

A copy of the log travels on the receipts branch at `logs/<task>.jsonl`, written at each declaration and finish. A log seal is checked by recomputing the chain and confirming that line `seq` still has hash `head`. Editing, removing or reordering anything up to that line, or rewriting the whole file as a fresh chain, fails the check. Seals are written with this machine's key at each declaration, finish and stop. Once pushed, they hold against anyone without that key; the machine key is usable by any process running as you, so an agent running unsandboxed could rewrite the log and its own seals before they are pushed. The CI runner (`use05 gate --ci`) reads the log only from the branch of a key whose seals it trusts, never countersigns past the last such seal, and signs with its own key: that is the record that does not depend on the developer's machine. A break in the chain after the last seal is reported as an unsealed tail, not as tampering.

## Verifying

`use05 verify RECEIPT --key PUBLIC_KEY [--tree REV]` checks the signature (the key file may hold an Ed25519 or a passkey public key), reads the statement, and, with `--tree`, that the receipt is for that exact tree. It exits 0 for a valid receipt (for evidence, of a passing check), 2 for a valid receipt of a failing check or an invalid signature, 5 for a good signature on a different tree, and 6 for a malformed receipt. Verification needs no network and no repository. The brief (`use05 brief`, and `use05 gate --ci` in CI) also checks a task's action log against its seals and says how strongly it is sealed.

## Where receipts live

Each signer has an ordinary git branch, `05-receipts/<key id>`, holding `receipts/<subject>/<hash>.json` (the subject is a tree id, an intent digest, a task id or, for an environment's records, a commit id) and `logs/<task>.jsonl`. One branch per signer means two signers never conflict, and any Git host accepts the push. Receipts travel only when asked (`--push`, `--fetch`); in CI, `use05 gate --ci --push` pushes the runner's branch. When a push is refused because the remote holds receipts this machine lacks (two machines of one signer, or two CI jobs, pushed at once), 05 fetches that branch, merges it into its own with a plain commit that holds both sides' files (receipts are files with unique names, so the merge never conflicts, and an action log that grew on both sides keeps its longer copy) and pushes again, up to five times with a short random wait. It never forces a push.

## Stability

The record types are stable. From 0.0.14:

- A `…/v0` record type only gains fields. A field it has is never removed, renamed or given another type, and a new field is always optional, so a receipt written by an older 05 stays valid and one written by a newer 05 still reads in an older one (unknown fields are ignored).
- A change that cannot be made that way gets a new type URI (`…/v1`). It is a new record type beside the old one.
- Every later 05 verifies every earlier type. A receipt that verified once keeps verifying.
- Receipts are never pruned, and their branches are never force-pushed. `use05 doctor` reports how many there are and how much space they take.

Each type has a [JSON Schema](https://json-schema.org/draft/2020-12) (draft 2020-12) for the statement inside the envelope's payload. A schema requires the fields the code always writes and allows others (`additionalProperties: true`), so a field added later stays valid. A test builds a statement of every type with the code and checks it against its schema, and fails if a type has no schema or a schema belongs to no type.

| Record type | Schema |
|---|---|
| `https://use05.dev/evidence/v0` | [evidence-v0.schema.json](receipts/evidence-v0.schema.json) |
| `https://use05.dev/approval/v0` | [approval-v0.schema.json](receipts/approval-v0.schema.json) |
| `https://use05.dev/bypass/v0` | [bypass-v0.schema.json](receipts/bypass-v0.schema.json) |
| `https://use05.dev/org-layer/v0` | [org-layer-v0.schema.json](receipts/org-layer-v0.schema.json) |
| `https://use05.dev/intent/v0` | [intent-v0.schema.json](receipts/intent-v0.schema.json) |
| `https://use05.dev/outcome/v0` | [outcome-v0.schema.json](receipts/outcome-v0.schema.json) |
| `https://use05.dev/log/v0` | [log-v0.schema.json](receipts/log-v0.schema.json) |
| `https://use05.dev/testing/v0` | [testing-v0.schema.json](receipts/testing-v0.schema.json) |
| `https://use05.dev/discard/v0` | [discard-v0.schema.json](receipts/discard-v0.schema.json) |

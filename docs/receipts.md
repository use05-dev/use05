# Receipt format

A 05 receipt is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope around an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), signed with Ed25519. Any DSSE implementation can verify the signature; 05's own check adds the tree comparison. The reference implementation is `crates/receipt`, and a test there fails if this page stops naming every record type, subject and field the code writes.

## Envelope

```json
{ "payloadType": "application/vnd.in-toto+json", "payload": "<base64 of the statement>",
  "signatures": [ { "keyid": "<hint, never trusted>", "sig": "<base64 Ed25519 signature>" } ] }
```

The signature is over the DSSE pre-authentication encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`. The key id is an unauthenticated hint; a verifier is always given the public key it should trust.

## Statement

`_type` is `https://in-toto.io/Statement/v1`. A statement has a `subject` (a list of `name` and `digest`), a `predicateType` and a `predicate`.

### Subjects

| `name` | `digest` | Used by |
|---|---|---|
| `tree` | `gitTree`: the git tree id; `sha256`: a SHA-256 over the tree's content, so a SHA-1 collision in git cannot move a receipt to different content | evidence, outcome approvals, bypasses, outcomes |
| `intent` | `sha256`: the digest of the intent card | intent approvals, declarations |
| `log` | `task`: the task id; `sha256`: the chain hash of the last line the seal covers | log seals |

### Record types

| `predicateType` | Meaning | Predicate fields |
|---|---|---|
| `https://use05.dev/evidence/v0` | A command ran on that exact tree | `command` (`argv`, `cwd`), `environment` (`fingerprint`, `names`: variable names only, never values), `result` (`status`: passed, failed or timed_out; `exit_code`; `signal`; `duration_ms`; `stdout` and `stderr`, each `total_bytes`, `retained_bytes`, `truncated` and a `sha256` of the stream, never its text), `runner` (`name`, `version`, `platform`), `created`, `check` (the policy check's name, if any) |
| `https://use05.dev/approval/v0` | A person approved or rejected an intent or an outcome | `decision` (approve or reject), `scope` (intent or outcome), `task`, `intent_sha256` (for intent approvals), `policy_sha256` (the rules in force; a policy change voids it), `rationale`, `approver`, `created`, `expires` |
| `https://use05.dev/bypass/v0` | A logged break-glass override of one exact blocked tree | `reason`, `by`, `findings` (what it overrode), `created`, `expires` |
| `https://use05.dev/org-layer/v0` | An organisation's policy floor, signed by its pinned key | `org`, `floor`, `created` |
| `https://use05.dev/intent/v0` | An agent's declaration of what it will do, sealed by its hook | `task`, `title`, `author`, `card` (scope, acceptance checks, goal), `sealed`, `policy_sha256`, and when known `agent` (`kind`, `session`, `model`), `owner` (`name`, `key_id`: recorded, and confirmed only by that key's signed approval) and `sandbox` (what the agent's own process reported; its word, not a fact) |
| `https://use05.dev/outcome/v0` | What the author said they did, for the tree they finished on. An assertion, never a fact | `task`, `outcome`, `finished` |
| `https://use05.dev/log/v0` | A seal on an agent's action log: the log had `seq` lines and the last one had chain hash `head` | `task`, `seq`, `head`, `created` |

Receipts never contain command output, file contents, diffs or prompts. Unknown fields are ignored when reading; the signature covers every byte, so nothing can be added after signing.

### Keys

A receipt counts only if a key the verifier trusts signed it. Keys have roles: `local` (this machine; advisory, since any process running as you can use it), `runner` (a CI secret; authoritative evidence) and `approver` (a person's passphrase-protected key). Approvals and bypasses count only when an approver key signed them; a machine key cannot approve.

## The action log and its seals

An agent's action log is JSON lines, one event per line: `seq` (1, 2, ...), `t` (RFC 3339), `prev` (the previous line's `hash`, empty for the first), `event` (tool, paths and decision; never contents or prompts) and `hash`. A line's hash is the SHA-256 of `prev`, then `seq` in decimal, then `t`, then the event serialised as compact JSON (no spaces, keys in sorted order, UTF-8 with non-ASCII characters left unescaped, integers written as integers), concatenated without separators.

A copy of the log travels on the receipts branch at `logs/<task>.jsonl`, written at each declaration and finish. A log seal is checked by recomputing the chain and confirming that line `seq` still has hash `head`. Editing, removing or reordering anything up to that line, or rewriting the whole file as a fresh chain, fails the check. Seals are written with this machine's key at each declaration, finish and stop. Once pushed, they hold against anyone without that key; the machine key is usable by any process running as you, so an agent running unsandboxed could rewrite the log and its own seals before they are pushed. The CI runner (`use05 gate --ci`) reads the log only from the branch of a key whose seals it trusts, never countersigns past the last such seal, and signs with its own key: that is the record that does not depend on the developer's machine. A break in the chain after the last seal is reported as an unsealed tail, not as tampering.

## Verifying

`use05 verify RECEIPT --key PUBLIC_KEY [--tree REV]` checks the signature, reads the statement, and, with `--tree`, that the receipt is for that exact tree. It exits 0 for a valid receipt (for evidence, of a passing check), 2 for a valid receipt of a failing check or an invalid signature, 5 for a good signature on a different tree, and 6 for a malformed receipt. Verification needs no network and no repository. The brief (`use05 brief`, and `use05 gate --ci` in CI) also checks a task's action log against its seals and says how strongly it is sealed.

## Where receipts live

Each signer has an ordinary git branch, `05-receipts/<key id>`, holding `receipts/<subject>/<hash>.json` (the subject is a tree id, an intent digest or a task id) and `logs/<task>.jsonl`. One branch per signer means two signers never conflict, and any Git host accepts the push. Receipts travel only when asked (`--push`, `--fetch`); in CI, `use05 gate --ci --push` pushes the runner's branch.

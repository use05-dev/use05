# Security

05 is trust infrastructure, so reports matter. Please email **security@use05.dev** with details and, if you can, a reproduction. Do not open a public issue for a vulnerability.

What we want to hear about most:
- a way to make `use05 verify` accept a receipt that was altered, or signed by a key it should not trust;
- a way for a change to loosen its own rules, skip a protected path, or approve itself;
- a way for an agent to obtain or use an approver key, or to make the gate allow without evidence;
- anything that sends code, diffs or transcripts off the machine (05 should never do this).
- for your own console: a way for the console, or whoever runs it, to read sealed records, make a machine run or file something it did not prepare, loosen a policy, pair a machine without the word and the matching codes, or claim a console it does not own.

## What is and is not a security boundary

- Hooks and the pre-push gate are **advisory** by design: an agent running as the same user can bypass them, and 05 says so. Report a bypass that the documentation claims is prevented, not the documented limits.
- A key in your user directory (`local.key`) is advisory evidence for the same reason.
- The strong controls are: a runner key held only by CI, an approver key protected by a passphrase or a passkey, and your Git host's required checks.
- The console serves its own web app's code, so whoever controls its host could serve a page that reads what you unlock there. That limit is documented in [Your own console](docs/console.md); report a way around it that the documentation claims is prevented, such as a machine accepting a statement it did not prepare.

## Cryptography

Receipts use Ed25519 over DSSE (PAE) with in-toto Statement v1. The key id in an envelope is an unauthenticated hint and is never trusted; verification takes the key explicitly. Approver keys are encrypted with scrypt and XChaCha20-Poly1305. A passkey approval is an ECDSA P-256 WebAuthn signature over the statement, counted only with the co-signature of the machine that prepared it. The console's records are sealed with X25519, HKDF-SHA256 and AES-256-GCM to the console's key, which each person unlocks with their passkey's PRF output or a recovery code.

We will acknowledge reports within three working days.

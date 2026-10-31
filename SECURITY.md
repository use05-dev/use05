# Security

05 is trust infrastructure, so reports matter. Please email **security@use05.dev** with details and, if you can, a reproduction. Do not open a public issue for a vulnerability.

What we want to hear about most:
- a way to make `use05 verify` accept a receipt that was altered, or signed by a key it should not trust;
- a way for a change to loosen its own rules, skip a protected path, or approve itself;
- a way for an agent to obtain or use an approver key, or to make the gate allow without evidence;
- anything that sends code, diffs or transcripts off the machine (05 should never do this).

## What is and is not a security boundary

- Hooks and the pre-push gate are **advisory** by design: an agent running as the same user can bypass them, and 05 says so. Report a bypass that the documentation claims is prevented, not the documented limits.
- A key in your user directory (`local.key`) is advisory evidence for the same reason.
- The strong controls are: a runner key held only by CI, an approver key protected by a passphrase, and your Git host's required checks.

## Cryptography

Receipts use Ed25519 over DSSE (PAE) with in-toto Statement v1. The key id in an envelope is an unauthenticated hint and is never trusted; verification takes the key explicitly. Approver keys are encrypted with scrypt and XChaCha20-Poly1305.

We will acknowledge reports within three working days.

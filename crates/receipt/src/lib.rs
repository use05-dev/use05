//! Signed evidence receipts.
//!
//! A receipt is an in-toto-style statement inside a DSSE envelope, signed with Ed25519.
//! This crate does no I/O and knows nothing about git, so the same code can verify receipts in
//! the CLI, in a server, or compiled to WebAssembly.
#![forbid(unsafe_code)]

mod dsse;
mod keys;
mod lfs;
mod passkey;
mod statement;

pub use dsse::{Envelope, EnvelopeSignature, Fault, PAYLOAD_TYPE, WebAuthnSig, cosignature, pae};
pub use keys::{
    KeyError, PublicKey, key_id, parse_any_public_key, parse_public_key, parse_secret_key, public_key_text, secret_key_text,
};
pub use lfs::{MAX_LFS_POINTER_BYTES, attributes_use_lfs, lfs_pointer, looks_like_lfs_pointer};
pub use passkey::{LocalAssertion, PasskeyKey, TOUCH_ID_SITE, local_assertion, passkey_challenge, passkey_entry, passkey_public_text};
pub use statement::{
    APPROVAL_TYPE, AgentRef, AnyStatement, Approval, ApprovalScope, BYPASS_TYPE, Bypass, Command, Completion, DEPLOYMENT_TYPE,
    DISCARD_TYPE, Decision, Declaration, DeployAction, Deployment, Direction, Discard, Environment, Evidence, INTENT_TYPE, LOG_TYPE,
    LfsFile, LogSeal, ORG_TYPE, OUTCOME_TYPE, OrgLayer, Outcome, OwnerRef, PREDICATE_TYPE, PROMOTION_TYPE, Predicate, ProbeResult,
    Promotion, RECORD_TYPES, RuleOutcome, RuleResult, RuleSeverity, Runner, SIGNOFF_TYPE, STATEMENT_TYPE, SignOff, SmokeResult,
    Statement, Status, Stream, Subject, TESTING_TYPE, Tested, Testing, commit_subject, intent_subject, log_subject, tree_subject,
    work_subject,
};

pub use ed25519_dalek::{SigningKey, VerifyingKey};

/// A receipt whose signature and structure have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<S = Statement<Evidence>> {
    pub statement: S,
    /// Short id of the key that verified the signature (derived from the key you supplied).
    pub key_id: String,
    /// True when the envelope's key id hint names a different key than the one you supplied.
    /// Informational only: the hint is unauthenticated and never decides anything.
    pub hint_mismatch: bool,
}

/// Sign any statement bytes, including kinds this version does not know. For tests of forward
/// compatibility and for tools that write their own record types.
pub fn seal_bytes(body: &[u8], key: &SigningKey) -> Envelope {
    dsse::sign(PAYLOAD_TYPE, body, key)
}

/// Sign a statement and return the envelope.
pub fn seal<P: Predicate>(statement: &Statement<P>, key: &SigningKey) -> Envelope {
    let body = serde_json::to_vec(statement).expect("statement serialises");
    dsse::sign(PAYLOAD_TYPE, &body, key)
}

/// Verify an envelope's signature against the key you supplied, then read an evidence statement.
///
/// The key id inside the envelope is only a hint and is never used to decide anything.
/// The statement is parsed from the exact bytes that were verified.
pub fn verify(envelope_json: &[u8], key: &VerifyingKey) -> Result<Verified, Fault> {
    let opened = dsse::verify(envelope_json, key)?;
    let statement = statement::parse_as::<Evidence>(&opened.payload)?;
    Ok(finish(statement, opened.hint, key))
}

/// Like [`verify`], for a receipt of any kind.
pub fn verify_any(envelope_json: &[u8], key: &VerifyingKey) -> Result<Verified<AnyStatement>, Fault> {
    let opened = dsse::verify(envelope_json, key)?;
    let statement = statement::parse_any(&opened.payload)?;
    Ok(finish(statement, opened.hint, key))
}

/// Like [`verify_any`], with either kind of key. A passkey verifies only its own (WebAuthn)
/// signatures; what it may sign is decided by the caller (05 counts them for approvals only).
pub fn verify_any_with(envelope_json: &[u8], key: &PublicKey) -> Result<Verified<AnyStatement>, Fault> {
    match key {
        PublicKey::Ed25519(k) => verify_any(envelope_json, k),
        PublicKey::Passkey(p) => {
            let opened = passkey::verify(envelope_json, p)?;
            let statement = statement::parse_any(&opened.payload)?;
            Ok(finish_id(statement, opened.hint, key.id()))
        }
    }
}

/// Verify an envelope's signature with either kind of key and return the exact bytes it signed,
/// whatever they are: the counterpart of [`seal_bytes`], for tools with their own record types.
pub fn verify_bytes_with(envelope_json: &[u8], key: &PublicKey) -> Result<Vec<u8>, Fault> {
    match key {
        PublicKey::Ed25519(k) => dsse::verify(envelope_json, k).map(|o| o.payload),
        PublicKey::Passkey(p) => passkey::verify(envelope_json, p).map(|o| o.payload),
    }
}

/// Like [`verify`], for a statement with a specific predicate type.
pub fn verify_as<P: Predicate>(envelope_json: &[u8], key: &VerifyingKey) -> Result<Verified<Statement<P>>, Fault> {
    let opened = dsse::verify(envelope_json, key)?;
    let statement = statement::parse_as::<P>(&opened.payload)?;
    Ok(finish(statement, opened.hint, key))
}

fn finish<S>(statement: S, hint: Option<String>, key: &VerifyingKey) -> Verified<S> {
    finish_id(statement, hint, key_id(key))
}

fn finish_id<S>(statement: S, hint: Option<String>, id: String) -> Verified<S> {
    let hint_mismatch = hint.as_deref().is_some_and(|hint| hint != id);
    Verified { statement, key_id: id, hint_mismatch }
}

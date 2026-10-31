//! Who is trusted, and what their receipts say.

use serde::Serialize;
use use05_receipt::{AnyStatement, Approval, Bypass, Evidence, Statement, VerifyingKey, key_id, parse_public_key, verify_any};

use crate::keys;
use crate::policy::{Policy, Role};
use crate::store::Raw;

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub name: String,
    pub role: Role,
    pub key: VerifyingKey,
    pub id: String,
}

#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub keys: Vec<TrustedKey>,
}

impl Trust {
    /// Keys the policy names, plus this machine's own keys. A policy edited by the change under
    /// review is never used here: callers pass the *base* policy.
    pub fn new(policy: &Policy, include_machine_keys: bool) -> Trust {
        let mut keys = Vec::new();
        let now = crate::time::now_secs();
        for entry in &policy.trust.key {
            // An expired key is simply not trusted, as if it had been removed from the policy.
            // An unreadable expiry also means not trusted: failing closed.
            if entry.expires.is_some() && entry.expires_at().is_none_or(|t| t < now) {
                continue;
            }
            if let Ok(key) = parse_public_key(&entry.public) {
                keys.push(TrustedKey { name: entry.name.clone(), role: entry.role, id: key_id(&key), key });
            }
        }
        if include_machine_keys {
            if let Some(key) = keys::local_public() {
                keys.push(TrustedKey { name: "this machine".into(), role: Role::Local, id: key_id(&key), key });
            }
            if let Some(key) = keys::approver_public() {
                keys.push(TrustedKey { name: "you (approver)".into(), role: Role::Approver, id: key_id(&key), key });
            }
        }
        Trust { keys }
    }

    pub fn by_id(&self, id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| k.id == id)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Signer {
    pub name: String,
    pub role: Role,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct Signed<S> {
    pub statement: S,
    pub signer: Signer,
    pub source: String,
    /// The receipt's path (it contains a hash of its bytes), so one receipt seen twice is one receipt.
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct Found {
    pub evidence: Vec<Signed<Statement<Evidence>>>,
    pub approvals: Vec<Signed<Statement<Approval>>>,
    pub bypasses: Vec<Signed<Statement<Bypass>>>,
    /// Agents' sealed declarations and their statements of what was done (D65).
    pub declarations: Vec<Signed<Statement<use05_receipt::Declaration>>>,
    pub completions: Vec<Signed<Statement<use05_receipt::Completion>>>,
    /// Seals on agents' action logs (D70), by a machine key or the CI runner.
    pub log_seals: Vec<Signed<Statement<use05_receipt::LogSeal>>>,
    /// Receipts that no trusted key verified, or that were signed by a key not allowed to sign
    /// that kind of statement.
    pub unverified: usize,
    /// Signed by a trusted key, but of a kind this version does not know (a newer 05 wrote it).
    pub newer: usize,
    /// Records of another tool's kind (its predicate type is not 05's), kept on the same branch.
    /// They are not 05's to read or to judge (D73).
    pub foreign: usize,
}

/// How long the newest receipt for this command took, on any tree. Used to decide what fits in
/// a short budget before running it.
pub fn last_duration_ms(found: &Found, argv: &[String]) -> Option<u64> {
    found
        .evidence
        .iter()
        .filter(|e| e.statement.predicate.command.argv == argv)
        .max_by(|a, b| a.statement.predicate.created.cmp(&b.statement.predicate.created))
        .map(|e| e.statement.predicate.result.duration_ms)
}

const OURS: &str = "https://use05.dev/";

/// The predicate type an envelope names, read without checking its signature.
fn predicate_type(envelope: &[u8]) -> Option<String> {
    use base64::Engine;
    let payload = serde_json::from_slice::<serde_json::Value>(envelope).ok().and_then(|v| v["payload"].as_str().and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok()))?;
    serde_json::from_slice::<serde_json::Value>(&payload).ok()?["predicateType"].as_str().map(str::to_string)
}

/// A record of a kind this version does not know counts as "from a newer 05" only if it names a
/// 05 type; anything else signed but unreadable is just not read.
fn names_a_05_type(envelope: &[u8]) -> bool {
    predicate_type(envelope).is_some_and(|t| t.starts_with(OURS) && t.len() > OURS.len())
}

/// Another tool's record: a well-formed type that is not 05's. Whoever signed it, 05 neither reads
/// nor judges it, and a record naming a 05 type can never pass as one.
fn names_another_tools_type(envelope: &[u8]) -> bool {
    predicate_type(envelope).is_some_and(|t| !t.starts_with(OURS) && t.split_once("://").is_some_and(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty()))
}

/// Verify raw receipts against the trusted keys and sort them by kind.
pub fn classify(trust: &Trust, raws: &[Raw]) -> Found {
    let mut found = Found::default();
    for raw in raws {
        if names_another_tools_type(&raw.bytes) {
            found.foreign += 1;
            continue;
        }
        let mut newer = false;
        let verified = trust.keys.iter().find_map(|k| match verify_any(&raw.bytes, &k.key) {
            Ok(v) => Some((k, v.statement)),
            // The signature checked out with this key; only the kind is unknown to this version.
            Err(use05_receipt::Fault::Invalid { code: "PREDICATE_TYPE_UNSUPPORTED", .. }) => {
                newer = true;
                None
            }
            Err(_) => None,
        });
        let Some((key, statement)) = verified else {
            if newer && names_a_05_type(&raw.bytes) {
                found.newer += 1;
            } else {
                found.unverified += 1;
            }
            continue;
        };
        let signer = Signer { name: key.name.clone(), role: key.role, key_id: key.id.clone() };
        let (source, path) = (raw.source.clone(), raw.path.clone());
        match statement {
            // People decide; machines produce evidence. A machine key cannot approve.
            AnyStatement::Approval(statement) if key.role == Role::Approver => found.approvals.push(Signed { statement, signer, source, path }),
            AnyStatement::Bypass(statement) if key.role == Role::Approver => found.bypasses.push(Signed { statement, signer, source, path }),
            AnyStatement::Evidence(statement) if key.role != Role::Approver => found.evidence.push(Signed { statement, signer, source, path }),
            AnyStatement::Declaration(statement) => found.declarations.push(Signed { statement, signer, source, path }),
            AnyStatement::Completion(statement) => found.completions.push(Signed { statement, signer, source, path }),
            AnyStatement::LogSeal(statement) => found.log_seals.push(Signed { statement, signer, source, path }),
            _ => found.unverified += 1,
        }
    }
    found
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use crate::policy::{Policy, TrustKey};
    use use05_receipt::{SigningKey, public_key_text};

    fn policy_with(expires: Option<&str>) -> (Policy, String) {
        let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let mut policy = Policy::default();
        policy.trust.key.push(TrustKey { name: "ci".into(), role: Role::Runner, public: public_key_text(&key), expires: expires.map(str::to_string) });
        (policy, key_id(&key))
    }

    #[test]
    fn a_key_is_trusted_until_its_expiry_and_an_unreadable_expiry_fails_closed() {
        for (expires, trusted) in [(None, true), (Some("2099-12-31"), true), (Some("2099-12-31T00:00:00Z"), true), (Some("2020-01-01"), false), (Some("2020-01-01T00:00:00Z"), false), (Some("soon"), false), (Some(""), false)] {
            let (policy, id) = policy_with(expires);
            assert_eq!(Trust::new(&policy, false).by_id(&id).is_some(), trusted, "expires = {expires:?}");
        }
    }
}

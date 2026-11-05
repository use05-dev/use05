//! Who is trusted, and what their receipts say.

use serde::Serialize;
use use05_receipt::{AnyStatement, Approval, Bypass, Evidence, PublicKey, Statement, parse_any_public_key, verify_any_with};

use crate::keys;
use crate::policy::{Policy, Role};
use crate::store::Raw;

/// Whose approval key this is (D86).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// Named in the policy (`person`).
    Person(String),
    /// Pinned on this machine (`passkeys.pub`): the person this machine works for.
    ThisMachine,
    /// Nobody said.
    Unnamed,
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub name: String,
    pub role: Role,
    /// An Ed25519 key, or a passkey (which only ever counts for approvals).
    pub key: PublicKey,
    pub id: String,
    pub holder: Holder,
}

#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub keys: Vec<TrustedKey>,
    /// The key ids of this machine's approver keys (passphrase and Touch ID), when this
    /// machine's keys are trusted: the person work started here is recorded under (D71, D91).
    pub this_person: Vec<String>,
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
            if let Ok(key) = parse_any_public_key(&entry.public) {
                // A passkey is only ever a person's approval key, whatever role it was given.
                if key.is_passkey() && entry.role != Role::Approver {
                    continue;
                }
                let holder = entry.person.as_deref().map(str::trim).filter(|p| !p.is_empty()).map_or(Holder::Unnamed, |p| Holder::Person(p.to_string()));
                keys.push(TrustedKey { name: entry.name.clone(), role: entry.role, id: key.id(), key, holder });
            }
        }
        let mut this_person = Vec::new();
        if include_machine_keys {
            if let Some(key) = keys::local_public().map(PublicKey::Ed25519) {
                keys.push(TrustedKey { name: "this machine".into(), role: Role::Local, id: key.id(), key, holder: Holder::Unnamed });
            }
            if let Some(key) = keys::approver_public().map(PublicKey::Ed25519) {
                this_person.push(key.id());
                keys.push(TrustedKey { name: "you (approver)".into(), role: Role::Approver, id: key.id(), key, holder: Holder::ThisMachine });
            }
            if let Some(key) = keys::touch_id_public().map(PublicKey::Passkey) {
                this_person.push(key.id());
                keys.push(TrustedKey { name: "you (Touch ID)".into(), role: Role::Approver, id: key.id(), key, holder: Holder::ThisMachine });
            }
            for (name, passkey) in keys::pinned_passkeys() {
                let key = PublicKey::Passkey(passkey);
                keys.push(TrustedKey { name: format!("passkey {name}"), role: Role::Approver, id: key.id(), key, holder: Holder::ThisMachine });
            }
        }
        Trust { keys, this_person }
    }

    /// Whether a key is one of this machine's person's approval keys: its approver key, its Touch
    /// ID key, or a passkey pinned here (`use05 cloud enrol`). Such a key signs for the person at
    /// this machine where the policy names no signers (D93), as it approves their own work.
    pub fn is_this_machines(&self, key_id: &str) -> bool {
        self.keys.iter().any(|k| k.id == key_id && k.role == Role::Approver && k.holder == Holder::ThisMachine)
    }

    pub fn by_id(&self, id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| k.id == id)
    }

    /// The person a key belongs to (D92): the `person` the policy names for it, and nothing else.
    /// Nothing on a machine (the name in its config, which an agent can set) makes a key someone's.
    /// Only an approver entry counts: a machine key named for a person (a preparer, D86) signs
    /// without them, so another entry for the same key cannot borrow its `person`.
    pub fn person_of(&self, key_id: &str) -> Option<String> {
        self.keys.iter().filter(|k| k.id == key_id && k.role == Role::Approver).find_map(|k| match &k.holder {
            Holder::Person(p) => Some(p.clone()),
            _ => None,
        })
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
    /// For an approval or a testing sign-off: the machine or runner keys that also signed it, the
    /// ones that prepared it. For a promotion: the person's key that also signed it, where a
    /// person promoted (D93); the machine that moved it is the signer.
    pub cosigners: Vec<Signer>,
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
    /// People's word that they tried a tree themselves, or skipped it (D87).
    pub testing: Vec<Signed<Statement<use05_receipt::Testing>>>,
    /// People's word to throw a task's work away (D89), prepared and co-signed by a machine.
    pub discards: Vec<Signed<Statement<use05_receipt::Discard>>>,
    /// Commits moved into an environment (D93), signed by a machine or the CI runner.
    pub promotions: Vec<Signed<Statement<use05_receipt::Promotion>>>,
    /// What an environment was seen running (D93), signed by a machine or the CI runner.
    pub deployments: Vec<Signed<Statement<use05_receipt::Deployment>>>,
    /// People's sign-offs on promotions (D93), signed like approvals.
    pub signoffs: Vec<Signed<Statement<use05_receipt::SignOff>>>,
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
/// a short budget before running it. The folder it ran in (D97) is part of which command it was.
pub fn last_duration_ms(found: &Found, argv: &[String], dir: Option<&str>) -> Option<u64> {
    found
        .evidence
        .iter()
        .filter(|e| e.statement.predicate.command.argv == argv && e.statement.predicate.command.dir.as_deref() == dir)
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

/// A person's statement, which a person's key signs and the machine that prepared it co-signs:
/// an approval, a testing sign-off, a discard or a promotion's sign-off.
fn is_persons(statement: &AnyStatement) -> bool {
    matches!(statement, AnyStatement::Approval(_) | AnyStatement::Testing(_) | AnyStatement::Discard(_) | AnyStatement::SignOff(_))
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
        // Every trusted key that signed it: an approval can carry a person's signature and the
        // signature of the machine that prepared it, and a promotion a person made the machine's
        // and that person's. Anything else needs only the first.
        let mut all: Vec<(&TrustedKey, AnyStatement)> = Vec::new();
        for k in &trust.keys {
            match verify_any_with(&raw.bytes, &k.key) {
                Ok(v) => {
                    let several = is_persons(&v.statement) || matches!(v.statement, AnyStatement::Promotion(_));
                    all.push((k, v.statement));
                    if !several {
                        break;
                    }
                }
                // The signature checked out with this key; only the kind is unknown to this version.
                Err(use05_receipt::Fault::Invalid { code: "PREDICATE_TYPE_UNSUPPORTED", .. }) => newer = true,
                Err(_) => {}
            }
        }
        let signer_of = |k: &TrustedKey| Signer { name: k.name.clone(), role: k.role, key_id: k.id.clone() };
        // A testing sign-off is a person's statement too, prepared and co-signed the same way.
        let is_approval = all.iter().any(|(_, s)| is_persons(s));
        let is_promotion = all.iter().any(|(_, s)| matches!(s, AnyStatement::Promotion(_)));
        let cosigners: Vec<Signer> = if is_approval {
            all.iter().filter(|(k, _)| matches!(k.role, Role::Local | Role::Runner)).map(|(k, _)| signer_of(k)).collect()
        } else if is_promotion {
            all.iter().filter(|(k, _)| k.role == Role::Approver).map(|(k, _)| signer_of(k)).collect()
        } else {
            Vec::new()
        };
        // For an approval, the person's key is the signer; for a promotion, the machine's; otherwise
        // the first key that verified.
        let chosen = if is_approval {
            all.iter().position(|(k, _)| k.role == Role::Approver).unwrap_or(0)
        } else if is_promotion {
            all.iter().position(|(k, _)| k.role != Role::Approver).unwrap_or(0)
        } else {
            0
        };
        let verified = all.into_iter().nth(chosen);
        let Some((key, statement)) = verified else {
            if newer && names_a_05_type(&raw.bytes) {
                found.newer += 1;
            } else {
                found.unverified += 1;
            }
            continue;
        };
        // A passkey may approve, sign off testing or a promotion, or discard work from a phone,
        // nothing else: not a bypass, a declaration, an outcome, a log seal, evidence or a machine's
        // record of a promotion. A page that holds it could be made to sign anything.
        if key.key.is_passkey() && !is_persons(&statement) {
            found.unverified += 1;
            continue;
        }
        let signer = Signer { name: key.name.clone(), role: key.role, key_id: key.id.clone() };
        let (source, path) = (raw.source.clone(), raw.path.clone());
        match statement {
            // People decide; machines produce evidence. A machine key cannot approve.
            AnyStatement::Approval(statement) if key.role == Role::Approver => found.approvals.push(Signed { statement, signer, source, path, cosigners }),
            AnyStatement::Testing(statement) if key.role == Role::Approver => found.testing.push(Signed { statement, signer, source, path, cosigners }),
            AnyStatement::Discard(statement) if key.role == Role::Approver => found.discards.push(Signed { statement, signer, source, path, cosigners }),
            AnyStatement::Bypass(statement) if key.role == Role::Approver => found.bypasses.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            AnyStatement::Evidence(statement) if key.role != Role::Approver => found.evidence.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            AnyStatement::Declaration(statement) => found.declarations.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            AnyStatement::Completion(statement) => found.completions.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            AnyStatement::LogSeal(statement) => found.log_seals.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            AnyStatement::SignOff(statement) if key.role == Role::Approver => found.signoffs.push(Signed { statement, signer, source, path, cosigners }),
            // What a machine did: a machine's key signs it, and a person who promoted signs it too.
            AnyStatement::Promotion(statement) if key.role != Role::Approver => found.promotions.push(Signed { statement, signer, source, path, cosigners }),
            AnyStatement::Deployment(statement) if key.role != Role::Approver => found.deployments.push(Signed { statement, signer, source, path, cosigners: Vec::new() }),
            _ => found.unverified += 1,
        }
    }
    found
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use crate::policy::{Policy, TrustKey};
    use use05_receipt::{SigningKey, key_id, public_key_text};

    fn policy_with(expires: Option<&str>) -> (Policy, String) {
        let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let mut policy = Policy::default();
        policy.trust.key.push(TrustKey { name: "ci".into(), role: Role::Runner, public: public_key_text(&key), expires: expires.map(str::to_string), person: None });
        (policy, key_id(&key))
    }

    #[test]
    fn an_environments_records_count_only_from_the_kind_of_key_that_may_sign_them() {
        use use05_receipt::{DeployAction, Deployment, Direction, Promotion, SignOff, Statement, commit_subject, seal};
        let machine = SigningKey::from_bytes(&[7; 32]);
        let person = SigningKey::from_bytes(&[8; 32]);
        let mut policy = Policy::default();
        policy.trust.key.push(TrustKey { name: "ci".into(), role: Role::Runner, public: public_key_text(&machine.verifying_key()), expires: None, person: None });
        policy.trust.key.push(TrustKey { name: "dana".into(), role: Role::Approver, public: public_key_text(&person.verifying_key()), expires: None, person: Some("Dana".into()) });
        let trust = Trust::new(&policy, false);
        let sha = "c1".repeat(20);
        let raw = |bytes: Vec<u8>, n: usize| Raw { source: "s".into(), path: format!("receipts/{sha}/{n}.json"), bytes };
        let promotion = Statement::new(vec![commit_subject(&sha)], Promotion { env: "prod".into(), from: "uat".into(), direction: Direction::Up, source_commit: sha.clone(), target_before: None, result_commit: sha.clone(), how: "fast-forward".into(), rollback_point: None, rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: "c".into(), by: "ci".into(), reverts: None, task: None });
        let deployment = Statement::new(vec![commit_subject(&sha)], Deployment { env: "uat".into(), commit: sha.clone(), probes: vec![], smoke: vec![], confirmed: false, created: "c".into(), action: DeployAction::None });
        let signoff = Statement::new(vec![commit_subject(&sha)], SignOff { env: "prod".into(), from: "uat".into(), source_commit: sha.clone(), decision: use05_receipt::Decision::Approve, signer_person: "Dana".into(), text: "t".into(), answers: vec![], confirmations: vec![], policy_sha256: "p".into(), created: "c".into(), expires: "e".into() });
        let found = classify(&trust, &[
            raw(seal(&promotion, &machine).to_json_bytes(), 1),
            raw(seal(&deployment, &machine).to_json_bytes(), 2),
            raw(seal(&signoff, &person).to_json_bytes(), 3),
            // The wrong kind of key for each: a person's key on a machine's record, and back.
            raw(seal(&promotion, &person).to_json_bytes(), 4),
            raw(seal(&signoff, &machine).to_json_bytes(), 5),
        ]);
        assert_eq!((found.promotions.len(), found.deployments.len(), found.signoffs.len()), (1, 1, 1));
        assert_eq!(found.signoffs[0].signer.role, Role::Approver);
        assert_eq!(found.unverified, 2, "neither counts as anything");

        // A person who promoted signs the machine's record too: the machine is its signer, the
        // person its co-signer, whichever key the policy lists first.
        let mut both = seal(&promotion, &machine);
        both.signatures.push(use05_receipt::cosignature(use05_receipt::PAYLOAD_TYPE, &serde_json::to_vec(&promotion).unwrap(), &person));
        let mut first_person = Policy::default();
        first_person.trust.key = policy.trust.key.iter().rev().cloned().collect();
        for trust in [Trust::new(&policy, false), Trust::new(&first_person, false)] {
            let found = classify(&trust, &[raw(both.to_json_bytes(), 6)]);
            assert_eq!(found.promotions.len(), 1, "{found:?}");
            assert_eq!((found.promotions[0].signer.role, found.promotions[0].cosigners.iter().map(|c| c.role).collect::<Vec<_>>()), (Role::Runner, vec![Role::Approver]));
        }
    }

    #[test]
    fn a_key_is_trusted_until_its_expiry_and_an_unreadable_expiry_fails_closed() {
        for (expires, trusted) in [(None, true), (Some("2099-12-31"), true), (Some("2099-12-31T00:00:00Z"), true), (Some("2020-01-01"), false), (Some("2020-01-01T00:00:00Z"), false), (Some("soon"), false), (Some(""), false)] {
            let (policy, id) = policy_with(expires);
            assert_eq!(Trust::new(&policy, false).by_id(&id).is_some(), trusted, "expires = {expires:?}");
        }
    }
}

//! The statements a receipt can carry: in-toto Statement v1 with a 05 predicate.
//!
//! Four predicate types exist: `Evidence` (a check ran on a tree), `Approval` (a person decided),
//! `Bypass` (a person overrode a block, with a reason) and `OrgLayer` (a signed policy floor).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::dsse::Fault;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://use05.dev/evidence/v0";
pub const APPROVAL_TYPE: &str = "https://use05.dev/approval/v0";
pub const BYPASS_TYPE: &str = "https://use05.dev/bypass/v0";
pub const ORG_TYPE: &str = "https://use05.dev/org-layer/v0";
pub const INTENT_TYPE: &str = "https://use05.dev/intent/v0";
pub const OUTCOME_TYPE: &str = "https://use05.dev/outcome/v0";
pub const LOG_TYPE: &str = "https://use05.dev/log/v0";

/// A predicate has a fixed type URI.
pub trait Predicate: Serialize + DeserializeOwned {
    const TYPE: &'static str;

    /// Reject a statement whose subjects do not suit this predicate.
    fn check(_subject: &[Subject]) -> Result<(), &'static str> {
        Ok(())
    }
}

fn has_tree(subject: &[Subject]) -> bool {
    subject.iter().any(|s| s.name == "tree" && s.digest.contains_key("gitTree") && s.digest.contains_key("sha256"))
}

fn has_intent(subject: &[Subject]) -> bool {
    subject.iter().any(|s| s.name == "intent" && s.digest.contains_key("sha256"))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Statement<P = Evidence> {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: P,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

// ----------------------------------------------------------------------------- evidence

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub command: Command,
    pub environment: Environment,
    pub result: Outcome,
    pub runner: Runner,
    /// RFC 3339, UTC. The signer's clock; not trusted.
    pub created: String,
    /// The policy check this ran, when it was run by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

impl Predicate for Evidence {
    const TYPE: &'static str = PREDICATE_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) { Ok(()) } else { Err("the statement has no tree subject with a gitTree and sha256 digest") }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub argv: Vec<String>,
    /// Always relative to the exported tree.
    pub cwd: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// Hash of the scrubbed environment. Values are not recorded.
    pub fingerprint: String,
    pub names: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    TimedOut,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub stdout: Stream,
    pub stderr: Stream,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub total_bytes: u64,
    pub retained_bytes: u64,
    pub truncated: bool,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Runner {
    pub name: String,
    pub version: String,
    pub platform: String,
}

// ----------------------------------------------------------------------------- approval

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Approves a declared intent before work starts. Subject: the intent card digest.
    Intent,
    /// Approves a finished outcome. Subject: the exact tree.
    Outcome,
}

/// A person's decision, bound to exactly what they were shown.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub decision: Decision,
    pub scope: ApprovalScope,
    pub task: String,
    /// Digest of the intent card the decision was made against (always present for intent approvals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_sha256: Option<String>,
    /// Digest of the effective policy at the time. A policy change makes the approval stale.
    pub policy_sha256: String,
    pub rationale: String,
    pub approver: String,
    pub created: String,
    pub expires: String,
}

impl Predicate for Approval {
    const TYPE: &'static str = APPROVAL_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) || has_intent(subject) { Ok(()) } else { Err("an approval needs a tree or intent subject") }
    }
}

// ----------------------------------------------------------------------------- bypass

/// Break-glass: a person overrode a block for one exact tree, for a stated reason.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Bypass {
    pub reason: String,
    pub by: String,
    /// What was bypassed, in words, so the audit trail is readable.
    pub findings: Vec<String>,
    pub created: String,
    pub expires: String,
}

impl Predicate for Bypass {
    const TYPE: &'static str = BYPASS_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) { Ok(()) } else { Err("a bypass needs a tree subject") }
    }
}

// ----------------------------------------------------------------------------- declarations

/// An agent's sealed declaration of what it will do (D65). Subject: the intent card digest.
/// The person's request is never in it: that stays on the machine where it was typed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    pub task: String,
    pub title: String,
    pub author: String,
    /// The intent card, in the core crate's shape.
    pub card: Value,
    pub sealed: String,
    pub policy_sha256: String,
    /// Which agent declared it (D71).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentRef>,
    /// The accountable person (D71), as recorded; their signed approval confirms it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerRef>,
    /// The agent's own report of its sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentRef {
    pub kind: String,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OwnerRef {
    pub name: String,
    pub key_id: String,
}

impl Predicate for Declaration {
    const TYPE: &'static str = INTENT_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_intent(subject) { Ok(()) } else { Err("a declaration needs an intent subject") }
    }
}

/// What the agent said it did, for the tree it finished on. An assertion, never a fact.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub task: String,
    pub outcome: String,
    pub finished: String,
}

impl Predicate for Completion {
    const TYPE: &'static str = OUTCOME_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) { Ok(()) } else { Err("an outcome needs a tree subject") }
    }
}

// ----------------------------------------------------------------------------- log seals

/// A seal on an agent's action log (D70): the log of `task` had `seq` lines, the last with
/// chain hash `head`. Any edit, removal or reordering before that line no longer verifies.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LogSeal {
    pub task: String,
    pub seq: u64,
    pub head: String,
    pub created: String,
}

impl Predicate for LogSeal {
    const TYPE: &'static str = LOG_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if subject.iter().any(|s| s.name == "log") { Ok(()) } else { Err("a log seal needs a log subject") }
    }
}

// ----------------------------------------------------------------------------- org layer

/// A policy floor issued by an organisation. `floor` has the policy's shape; the core crate
/// interprets it. It is signed, and verified against a key the repository cannot change.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrgLayer {
    pub org: String,
    pub floor: Value,
    pub created: String,
}

impl Predicate for OrgLayer {
    const TYPE: &'static str = ORG_TYPE;
}

// ----------------------------------------------------------------------------- helpers

impl<P: Predicate> Statement<P> {
    pub fn new(subject: Vec<Subject>, predicate: P) -> Statement<P> {
        Statement {
            type_: STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: P::TYPE.to_string(),
            predicate,
        }
    }

    /// The digest map of the subject with this name.
    pub fn digest_of(&self, name: &str) -> Option<&BTreeMap<String, String>> {
        self.subject.iter().find(|s| s.name == name).map(|s| &s.digest)
    }

    /// The tree this statement is about: `(gitTree, sha256)`.
    pub fn tree_subject(&self) -> Option<(&str, &str)> {
        let digest = self.digest_of("tree")?;
        Some((digest.get("gitTree")?, digest.get("sha256")?))
    }

    /// The log this statement seals: `(task, chain head)`.
    pub fn log_subject(&self) -> Option<(&str, &str)> {
        let digest = self.digest_of("log")?;
        Some((digest.get("task")?, digest.get("sha256")?))
    }

    /// The intent-card digest this statement is about.
    pub fn intent_subject(&self) -> Option<&str> {
        self.digest_of("intent")?.get("sha256").map(String::as_str)
    }
}

pub fn tree_subject(oid: &str, content_sha256: &str) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("gitTree".to_string(), oid.to_string());
    digest.insert("sha256".to_string(), content_sha256.to_string());
    Subject { name: "tree".to_string(), digest }
}

pub fn log_subject(task: &str, head: &str) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("task".to_string(), task.to_string());
    digest.insert("sha256".to_string(), head.to_string());
    Subject { name: "log".to_string(), digest }
}

pub fn intent_subject(card_sha256: &str) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), card_sha256.to_string());
    Subject { name: "intent".to_string(), digest }
}

impl Statement<Evidence> {
    pub fn for_evidence(tree_oid: &str, content_sha256: &str, evidence: Evidence) -> Statement<Evidence> {
        Statement::new(vec![tree_subject(tree_oid, content_sha256)], evidence)
    }
}

/// Parse the bytes that were verified as a statement with predicate `P`.
///
/// A statement that is signed but unreadable is malformed. One that is readable but of another
/// type is invalid for this caller.
pub(crate) fn parse_as<P: Predicate>(payload: &[u8]) -> Result<Statement<P>, Fault> {
    let value: Value = serde_json::from_slice(payload).map_err(|e| {
        Fault::malformed(
            "RECEIPT_BAD_STATEMENT",
            format!("the signed statement is not readable ({})", crate::dsse::without_position(&e)),
        )
    })?;
    check_types(&value, Some(P::TYPE))?;
    let statement: Statement<P> = serde_json::from_value(value).map_err(|e| {
        Fault::malformed("RECEIPT_BAD_STATEMENT", format!("the signed statement is not readable ({e})"))
    })?;
    if statement.subject.is_empty() {
        return Err(Fault::malformed("RECEIPT_BAD_STATEMENT", "the statement has no subject"));
    }
    P::check(&statement.subject).map_err(|why| Fault::malformed("RECEIPT_BAD_STATEMENT", why))?;
    Ok(statement)
}

fn check_types(value: &Value, want: Option<&str>) -> Result<(), Fault> {
    let statement_type = value.get("_type").and_then(Value::as_str).unwrap_or("");
    if statement_type != STATEMENT_TYPE {
        return Err(Fault::invalid(
            "STATEMENT_TYPE_UNSUPPORTED",
            format!("statement type {statement_type:?} is not supported"),
        ));
    }
    let predicate_type = value.get("predicateType").and_then(Value::as_str).unwrap_or("");
    let known = [PREDICATE_TYPE, APPROVAL_TYPE, BYPASS_TYPE, ORG_TYPE, INTENT_TYPE, OUTCOME_TYPE, LOG_TYPE].contains(&predicate_type);
    if !known || want.is_some_and(|w| w != predicate_type) {
        return Err(Fault::invalid(
            "PREDICATE_TYPE_UNSUPPORTED",
            format!("predicate type {predicate_type:?} is not supported here"),
        ));
    }
    Ok(())
}

/// Any statement 05 understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyStatement {
    Evidence(Statement<Evidence>),
    Approval(Statement<Approval>),
    Bypass(Statement<Bypass>),
    OrgLayer(Statement<OrgLayer>),
    Declaration(Statement<Declaration>),
    Completion(Statement<Completion>),
    LogSeal(Statement<LogSeal>),
}

pub(crate) fn parse_any(payload: &[u8]) -> Result<AnyStatement, Fault> {
    let value: Value = serde_json::from_slice(payload).map_err(|e| {
        Fault::malformed(
            "RECEIPT_BAD_STATEMENT",
            format!("the signed statement is not readable ({})", crate::dsse::without_position(&e)),
        )
    })?;
    check_types(&value, None)?;
    match value.get("predicateType").and_then(Value::as_str).unwrap_or("") {
        PREDICATE_TYPE => parse_as::<Evidence>(payload).map(AnyStatement::Evidence),
        APPROVAL_TYPE => parse_as::<Approval>(payload).map(AnyStatement::Approval),
        BYPASS_TYPE => parse_as::<Bypass>(payload).map(AnyStatement::Bypass),
        INTENT_TYPE => parse_as::<Declaration>(payload).map(AnyStatement::Declaration),
        OUTCOME_TYPE => parse_as::<Completion>(payload).map(AnyStatement::Completion),
        LOG_TYPE => parse_as::<LogSeal>(payload).map(AnyStatement::LogSeal),
        _ => parse_as::<OrgLayer>(payload).map(AnyStatement::OrgLayer),
    }
}

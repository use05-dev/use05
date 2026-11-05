//! The statements a receipt can carry: in-toto Statement v1 with a 05 predicate.
//!
//! Predicate types: `Evidence` (a check ran on a tree), `Approval` (a person decided), `Bypass` (a
//! person overrode a block, with a reason), `Testing` (a person tried a tree themselves, or skipped
//! it), `Discard` (a person threw a task's work away), `OrgLayer` (a signed policy floor), the task's declaration, outcome and log seals,
//! and an environment's records (D93): `Promotion` (a commit moved into an environment), `Deployment` (what an environment was seen
//! running) and `SignOff` (a person's word on a promotion).

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
pub const TESTING_TYPE: &str = "https://use05.dev/testing/v0";
pub const DISCARD_TYPE: &str = "https://use05.dev/discard/v0";
pub const PROMOTION_TYPE: &str = "https://use05.dev/promotion/v0";
pub const DEPLOYMENT_TYPE: &str = "https://use05.dev/deployment/v0";
pub const SIGNOFF_TYPE: &str = "https://use05.dev/signoff/v0";

/// Every record type this version reads. Each has a JSON Schema in docs/receipts (D95), checked
/// against the code by a test. A type is only ever added to this list, never removed.
pub const RECORD_TYPES: &[&str] = &[PREDICATE_TYPE, APPROVAL_TYPE, BYPASS_TYPE, ORG_TYPE, INTENT_TYPE, OUTCOME_TYPE, LOG_TYPE, TESTING_TYPE, DISCARD_TYPE, PROMOTION_TYPE, DEPLOYMENT_TYPE, SIGNOFF_TYPE];

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

fn has_commit(subject: &[Subject]) -> bool {
    subject.iter().any(|s| s.name == "commit" && s.digest.contains_key("gitCommit"))
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
    /// The Git LFS files that were fetched into the exported tree in place of their pointers (D96).
    /// The tree digest still covers the committed pointers; these say which real files the check saw.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lfs: Vec<LfsFile>,
}

/// One Git LFS file the check ran on: where it is, and the object that stands for its bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LfsFile {
    pub path: String,
    /// The SHA-256 of the file's real bytes, as its pointer names it (hex).
    pub oid: String,
    pub size: u64,
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
    /// Always relative to the exported tree: its root. The folder the command ran in is `dir`.
    pub cwd: String,
    /// The folder of the exported tree the command ran in, when the check named one (D97).
    /// Not written when the command ran at the root, so older receipts keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
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
    /// The OS user the command ran as, when it ran as a user other than the one holding the
    /// signing key (D94).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_user: Option<String>,
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
    /// Set only on an approval of a hotfix's outcome (D93): the environment it lands on. Only such
    /// an approval, for that environment and that `task`, counts for landing a hotfix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotfix: Option<String>,
}

impl Predicate for Approval {
    const TYPE: &'static str = APPROVAL_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) || has_intent(subject) { Ok(()) } else { Err("an approval needs a tree or intent subject") }
    }
}

// ----------------------------------------------------------------------------- bypass

/// Break-glass: a person overrode a block for one exact tree, for a stated reason. Or, for a
/// promotion (D93), one rule of promoting one exact commit into an environment: then `env`,
/// `from` and `rule` say which, and the subject is the source commit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Bypass {
    pub reason: String,
    pub by: String,
    /// What was bypassed, in words, so the audit trail is readable.
    pub findings: Vec<String>,
    pub created: String,
    pub expires: String,
    /// For a promotion's bypass: the environment promoted into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// For a promotion's bypass: the environment promoted from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// For a promotion's bypass: the promotion rule it clears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// For a promotion's bypass: the policy it was given under; a policy change voids it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_sha256: Option<String>,
}

impl Predicate for Bypass {
    const TYPE: &'static str = BYPASS_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) || has_commit(subject) { Ok(()) } else { Err("a bypass needs a tree subject, or a commit subject for a promotion") }
    }
}

// ----------------------------------------------------------------------------- testing

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tested {
    /// The person tried the change in their own development environment.
    Tested,
    /// The person did not, and said why. Counts only where the policy lets testing be skipped.
    Skipped,
}

/// A person's word that they tried one exact tree themselves before it is pushed (D87), or that
/// they skipped it and why. Never an approval: it says nothing about accepting the change.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Testing {
    pub outcome: Tested,
    pub task: String,
    /// What they tried, or why they skipped, in their words.
    pub note: String,
    pub tester: String,
    pub created: String,
}

impl Predicate for Testing {
    const TYPE: &'static str = TESTING_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_tree(subject) { Ok(()) } else { Err("a testing sign-off needs a tree subject") }
    }
}

// ----------------------------------------------------------------------------- discards

/// A person's word to throw a task's work away: its worktree, its branch here and on origin, and
/// what the console holds about it (D89). It says what would be lost that exists nowhere else, so
/// whoever signs it has seen that. Subject: the work (the task, and its branch's head).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Discard {
    pub task: String,
    /// The task's own branch, when it has one 05 may delete.
    pub branch: Option<String>,
    /// That branch's head when the discard was prepared: if it moves, the discard does not apply.
    pub head: Option<String>,
    /// Commits on the branch that are on no remote branch and not in where work lands.
    pub unpushed: u32,
    /// Changed or new files in its worktree that were never committed.
    pub uncommitted: u32,
    pub by: String,
    pub created: String,
}

impl Predicate for Discard {
    const TYPE: &'static str = DISCARD_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if subject.iter().any(|s| s.name == "work") { Ok(()) } else { Err("a discard needs a work subject") }
    }
}

// ----------------------------------------------------------------------------- environments (D93)

/// Which way a promotion went: up the ladder, a fix merged back down one rung, or a hotfix landed
/// straight on an environment's branch.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Up,
    Back,
    Hotfix,
    /// A value a newer 05 wrote that this one does not know (D95: a v0 list of words may grow).
    #[serde(other)]
    Unknown,
}

/// How strongly a promotion rule holds a promotion back, as the policy set it. Not ordered: a
/// value a newer 05 wrote (`Unknown`) has no place among the others, so nothing takes a maximum
/// of these; the policy's own severity is what is compared.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSeverity {
    Allow,
    Warn,
    Approval,
    Deny,
    /// A value a newer 05 wrote that this one does not know (D95: a v0 list of words may grow).
    #[serde(other)]
    Unknown,
}

/// What one rule found.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    /// The rule holds.
    Pass,
    /// The rule does not hold.
    Fail,
    /// It did not hold, and a person bypassed it for this promotion.
    Bypassed,
    /// Nothing to judge: not asked for, or nothing it looks at moved.
    Skipped,
    /// A value a newer 05 wrote that this one does not know (D95: a v0 list of words may grow).
    #[serde(other)]
    Unknown,
}

/// One promotion rule's result, in words a person reads.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RuleResult {
    /// `source_checks`, `source_confirmed`, `soak`, `migrations`, `untasked` or `sign_off`.
    pub rule: String,
    pub severity: RuleSeverity,
    pub outcome: RuleOutcome,
    pub detail: String,
}

/// A commit moved into an environment (D93): what moved, from where to where, the rollback point,
/// each rule's result, and the bypasses and sign-offs it went with. Subject: the source commit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    /// The environment or destination promoted into.
    pub env: String,
    /// The environment promoted from; for a destination, the environment its source branch is, else that branch.
    pub from: String,
    pub direction: Direction,
    /// The exact commit that was evaluated and moved.
    pub source_commit: String,
    /// The target branch's head before; absent when the promotion created the branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_before: Option<String>,
    /// The target branch's head after.
    pub result_commit: String,
    /// `fast-forward`, `merge`, `revert`, or for a destination `push` or `export`. A word, not a fixed list.
    pub how: String,
    /// The commit to go back to if the deploy fails; absent when there was none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_point: Option<String>,
    pub rules: Vec<RuleResult>,
    /// The receipts of the bypasses it went with, by path.
    pub bypasses: Vec<String>,
    /// The receipts of the sign-offs it went with, by path.
    pub signoffs: Vec<String>,
    pub policy_sha256: String,
    pub created: String,
    /// Who promoted: a person's name, or the agent or CI that did.
    pub by: String,
    /// Set only on a revert 05 made (D93), because a deploy was not confirmed or a person rolled
    /// back with `use05 promote <env> --rollback`: the commit it reverts, which was the branch's head. The revert's own commit is `source_commit` and
    /// `result_commit`, its `how` is `revert`, and it keeps the direction of the promotion it undoes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverts: Option<String>,
    /// Set only on a hotfix (`direction = "hotfix"`): the 05 task whose work landed straight on
    /// the environment's branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

impl Predicate for Promotion {
    const TYPE: &'static str = PROMOTION_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_commit(subject) { Ok(()) } else { Err("a promotion needs a commit subject") }
    }
}

/// One probe's result: did the environment say it runs the commit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub name: String,
    pub matched: bool,
    /// The SHA-256 of what the probe printed last, never the text.
    pub output_sha256: String,
    pub attempts: u32,
    pub seconds: u64,
}

/// One smoke check's result.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SmokeResult {
    pub name: String,
    pub passed: bool,
}

/// What 05 did about a deploy it could not confirm.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeployAction {
    None,
    Reverted,
    RollbackCommand,
    /// A value a newer 05 wrote that this one does not know (D95: a v0 list of words may grow).
    #[serde(other)]
    Unknown,
}

/// What an environment was seen running (D93): its probes and smoke checks, and whether they
/// confirm the commit. Subject: the deployed commit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub env: String,
    pub commit: String,
    pub probes: Vec<ProbeResult>,
    pub smoke: Vec<SmokeResult>,
    /// Every probe showed the commit and every smoke check passed. Never true without a probe.
    pub confirmed: bool,
    pub created: String,
    pub action: DeployAction,
}

impl Predicate for Deployment {
    const TYPE: &'static str = DEPLOYMENT_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_commit(subject) { Ok(()) } else { Err("a deployment needs a commit subject") }
    }
}

/// A person's sign-off on promoting one exact commit into an environment, or their rejection of
/// it (D93): their own words, their answers to the policy's questions, and the statements they
/// confirm. Bound to the environment, the source commit and the policy. Subject: the source commit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignOff {
    pub env: String,
    pub from: String,
    pub source_commit: String,
    pub decision: Decision,
    /// The person, as the policy names them on their key.
    pub signer_person: String,
    /// What they say, in their words.
    pub text: String,
    /// Their answers to the policy's questions, in order.
    pub answers: Vec<String>,
    /// The policy's `confirm` statements they confirm, word for word.
    pub confirmations: Vec<String>,
    pub policy_sha256: String,
    pub created: String,
    pub expires: String,
}

impl Predicate for SignOff {
    const TYPE: &'static str = SIGNOFF_TYPE;
    fn check(subject: &[Subject]) -> Result<(), &'static str> {
        if has_commit(subject) { Ok(()) } else { Err("a sign-off needs a commit subject") }
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
    /// Where the finished work met the landing branch when the task finished, when known: with it, the commits from there to
    /// the finished tree are the task's (D93). Not written when unknown, so older records keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
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

    /// The work a discard is about: `(task, branch head)`, the head empty when there is no branch.
    pub fn work_subject(&self) -> Option<(&str, &str)> {
        let digest = self.digest_of("work")?;
        Some((digest.get("task")?, digest.get("gitCommit").map(String::as_str).unwrap_or("")))
    }

    /// The intent-card digest this statement is about.
    pub fn intent_subject(&self) -> Option<&str> {
        self.digest_of("intent")?.get("sha256").map(String::as_str)
    }

    /// The commit this statement is about: a promotion's, a deployment's or a sign-off's.
    pub fn commit_subject(&self) -> Option<&str> {
        self.digest_of("commit")?.get("gitCommit").map(String::as_str)
    }
}

/// The subject of an environment's records: one commit.
pub fn commit_subject(commit: &str) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("gitCommit".to_string(), commit.to_string());
    Subject { name: "commit".to_string(), digest }
}

pub fn tree_subject(oid: &str, content_sha256: &str) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("gitTree".to_string(), oid.to_string());
    digest.insert("sha256".to_string(), content_sha256.to_string());
    Subject { name: "tree".to_string(), digest }
}

pub fn work_subject(task: &str, head: Option<&str>) -> Subject {
    let mut digest = BTreeMap::new();
    digest.insert("task".to_string(), task.to_string());
    if let Some(head) = head {
        digest.insert("gitCommit".to_string(), head.to_string());
    }
    Subject { name: "work".to_string(), digest }
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
    let known = RECORD_TYPES.contains(&predicate_type);
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
    Testing(Statement<Testing>),
    Discard(Statement<Discard>),
    Promotion(Statement<Promotion>),
    Deployment(Statement<Deployment>),
    SignOff(Statement<SignOff>),
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
        TESTING_TYPE => parse_as::<Testing>(payload).map(AnyStatement::Testing),
        DISCARD_TYPE => parse_as::<Discard>(payload).map(AnyStatement::Discard),
        PROMOTION_TYPE => parse_as::<Promotion>(payload).map(AnyStatement::Promotion),
        DEPLOYMENT_TYPE => parse_as::<Deployment>(payload).map(AnyStatement::Deployment),
        SIGNOFF_TYPE => parse_as::<SignOff>(payload).map(AnyStatement::SignOff),
        _ => parse_as::<OrgLayer>(payload).map(AnyStatement::OrgLayer),
    }
}

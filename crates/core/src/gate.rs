//! The gate: given a change, the rules it is held to, and every receipt we can verify,
//! decide whether it may proceed. Deterministic: the same inputs give the same decision,
//! and nothing here asks a model for an opinion.

use std::path::Path;

use serde::Serialize;
use use05_receipt::{ApprovalScope, Decision as Vote, Status};

use crate::claims::{self, Judged, Observed};
use crate::error::Result;
use crate::evidence::{Found, Holder, Signed, Signer, Trust, classify};
use crate::git::{self, Change};
use crate::intent::{Risk, is_dependency_file, is_protected, risk_of_paths};
use crate::policy::{IntentMode, Policy, Role, Severity, same_person};
use crate::store;
use crate::task::Task;
use crate::time::parse_rfc3339;

/// How strongly a finding holds the change back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Info,
    Warn,
    /// Evidence is missing or old: produce it.
    Wait,
    /// A person must approve.
    Approval,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Wait,
    ApprovalRequired,
    Deny,
}

impl Decision {
    pub fn word(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Wait => "wait",
            Decision::ApprovalRequired => "approval_required",
            Decision::Deny => "deny",
        }
    }

    /// Exit codes: 0 allow, 2 deny, 3 approval needed, 5 evidence missing or stale.
    pub fn exit_code(self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Deny => 2,
            Decision::ApprovalRequired => 3,
            Decision::Wait => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub effect: Effect,
    pub message: String,
    pub paths: Vec<String>,
    pub next: Option<String>,
    /// Any person's approval that counts can clear this finding. An owner rule's
    /// (`OWNER_APPROVAL_REQUIRED`, D92) is cleared only by its owners, so it is not marked.
    pub approvable: bool,
}

impl Finding {
    pub fn new(code: &'static str, effect: Effect, message: impl Into<String>) -> Finding {
        Finding { code, effect, message: message.into(), paths: Vec::new(), next: None, approvable: false }
    }
    fn paths(mut self, paths: Vec<String>) -> Finding {
        self.paths = paths;
        self
    }
    fn next(mut self, next: impl Into<String>) -> Finding {
        self.next = Some(next.into());
        self
    }
    fn approvable(mut self) -> Finding {
        self.approvable = true;
        self
    }
}

/// The runner key reached a run the change's own branch defines, so the change's code could have
/// read it (D94). A warning, never a refusal: refusing would not take the key back. `fix` is the
/// next step: move to a gate the branch cannot change.
pub fn ci_key_exposed(fix: &str) -> Finding {
    Finding::new(
        "CI_KEY_EXPOSED",
        Effect::Warn,
        "the runner key was given to this branch's own workflow, which the branch can change, so the code it checks could have read the key",
    )
    .next(format!("{fix}, then rotate the runner key"))
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckState {
    Passed { by: Signer, ms: u64 },
    Failed { by: Signer, exit_code: Option<i32> },
    TimedOut { by: Signer },
    /// A receipt exists, but only from a signer policy does not accept.
    NotAuthoritative { by: Signer },
    /// A receipt exists for an earlier tree, not this one.
    Stale,
    Missing,
    /// The intent card names a check the policy does not define.
    Undefined,
    /// The check names `paths` (D97) and the change touches none of them. It never blocks and
    /// never counts as missing. `result` is what a receipt for it says, if one exists anyway.
    NotRequired {
        reason: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<SeenResult>,
    },
}

/// What a receipt says about a check that was not required for the change.
#[derive(Debug, Clone, Serialize)]
pub struct SeenResult {
    pub status: Status,
    pub by: Signer,
    pub ms: u64,
}

/// Why a check with `paths` was not required.
pub const NOT_REQUIRED_REASON: &str = "no change in its paths";

#[derive(Debug, Clone, Serialize)]
pub struct CheckStatus {
    pub name: String,
    pub run: Vec<String>,
    /// The folder of the tree it runs in, when the check names one (D97).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// The paths that call for it, when it names some (D97).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    pub required: bool,
    #[serde(flatten)]
    pub state: CheckState,
}

/// The evidence on `found` that is for this exact tree: its tree id and its content digest both
/// match. A receipt naming the tree id with another digest is a finding of its own.
fn evidence_for<'f>(found: &'f Found, tree: &str, digest: &str) -> (Vec<&'f Signed<use05_receipt::Statement<use05_receipt::Evidence>>>, Option<Finding>) {
    let mut mismatch = false;
    let mut evidence = Vec::new();
    for e in &found.evidence {
        match e.statement.tree_subject() {
            Some((oid, d)) if oid == tree && d == digest => evidence.push(e),
            Some((oid, _)) if oid == tree => mismatch = true,
            _ => {}
        }
    }
    let finding = mismatch.then(|| Finding::new("TREE_DIGEST_MISMATCH", Effect::Deny, "a receipt names this tree id but its contents hash differently; do not trust it or this repository's objects"));
    (evidence, finding)
}

/// What one tree's checks are judged from.
struct Proof<'a> {
    top: &'a Path,
    policy: &'a Policy,
    trust: &'a Trust,
    tree: &'a str,
    evidence: &'a [&'a Signed<use05_receipt::Statement<use05_receipt::Evidence>>],
    /// Added to `use05 prove <name>` in the next step: empty for the tree at hand, ` --tree <rev>`
    /// for another one.
    prove_on: &'a str,
}

/// One check, judged on one exact tree: the newest accepted receipt of the policy's own command
/// (run in its own folder) speaks for it. Shared by the gate and promotion (D93), so a check
/// counts the same wherever it is asked for. `applies` is false for a check whose `paths` the
/// change does not touch: it is listed, never required.
fn judge_check(def: &crate::policy::CheckDef, required: bool, applies: bool, at: &Proof<'_>, all: &mut Option<Found>) -> (CheckStatus, Option<Finding>) {
    let accepted = |role: Role| at.policy.evidence.accept.contains(&role);
    let name = &def.name;
    let mine: Vec<&&Signed<_>> = at
        .evidence
        .iter()
        // The command must be the policy's own: a receipt merely *named* after the check is not enough.
        // So is the folder it ran in: the same command in two packages is two checks.
        .filter(|e| e.statement.predicate.command.argv == def.run && e.statement.predicate.command.dir == def.dir)
        .collect();
    let accepted_mine: Vec<_> = mine.iter().filter(|e| accepted(e.signer.role)).collect();
    // The most recent accepted receipt speaks for the check.
    let latest = accepted_mine.iter().max_by(|a, b| a.statement.predicate.created.cmp(&b.statement.predicate.created));
    let status = |required: bool, state: CheckState| CheckStatus { name: name.clone(), run: def.run.clone(), dir: def.dir.clone(), paths: def.paths.clone(), required, state };
    if !applies {
        let result = latest.map(|e| SeenResult { status: e.statement.predicate.result.status, by: e.signer.clone(), ms: e.statement.predicate.result.duration_ms });
        return (status(false, CheckState::NotRequired { reason: NOT_REQUIRED_REASON, result }), None);
    }
    let state = match latest {
        Some(e) => {
            let result = &e.statement.predicate.result;
            match result.status {
                Status::Passed => CheckState::Passed { by: e.signer.clone(), ms: result.duration_ms },
                Status::Failed => CheckState::Failed { by: e.signer.clone(), exit_code: result.exit_code },
                Status::TimedOut => CheckState::TimedOut { by: e.signer.clone() },
            }
        }
        None => match mine.first() {
            Some(e) => CheckState::NotAuthoritative { by: e.signer.clone() },
            None => {
                let everything = all.get_or_insert_with(|| classify(at.trust, &store::find_all(at.top)));
                let earlier = everything.evidence.iter().any(|e| {
                    e.statement.predicate.command.argv == def.run
                        && e.statement.predicate.command.dir == def.dir
                        && accepted(e.signer.role)
                        && e.statement.tree_subject().is_some_and(|(oid, _)| oid != at.tree)
                });
                if earlier { CheckState::Stale } else { CheckState::Missing }
            }
        },
    };
    let prove = format!("use05 prove {name}{}", at.prove_on);
    let finding = match &state {
        CheckState::Failed { exit_code, .. } => Some(Finding::new("CHECK_FAILED", Effect::Deny, format!("the check {name:?} failed{}", exit_code.map(|c| format!(" (exit {c})")).unwrap_or_default())).next("fix it, then: ".to_string() + &prove)),
        CheckState::TimedOut { .. } => Some(Finding::new("CHECK_FAILED", Effect::Deny, format!("the check {name:?} timed out")).next(prove)),
        CheckState::NotAuthoritative { by } => Some(
            Finding::new(
                "EVIDENCE_NOT_ACCEPTED",
                Effect::Wait,
                format!("the check {name:?} was only proved by a {} key ({}); policy accepts {}", by.role.word(), by.name, at.policy.evidence.accept.iter().map(|r| r.word()).collect::<Vec<_>>().join(" or ")),
            )
            .next("run it where policy accepts it, for example in CI"),
        ),
        CheckState::Stale => Some(Finding::new("EVIDENCE_STALE", Effect::Wait, format!("the check {name:?} passed on an earlier tree, not this one; the code changed since")).next(prove)),
        CheckState::Missing => Some(Finding::new("CHECK_MISSING", Effect::Wait, format!("the check {name:?} has not been proved on this tree")).next(prove)),
        CheckState::Passed { .. } | CheckState::Undefined | CheckState::NotRequired { .. } => None,
    };
    (status(required, state), finding)
}

/// The policy's required checks on one exact tree (`tree`, whose content digest is `digest`),
/// judged as the gate judges them: a check whose `paths` none of `changed` touches is listed as
/// not required. `prove_on` names the tree in the next step (` --tree <rev>`). Used to read a
/// promotion's source head (D93).
pub fn checks_at(top: &Path, policy: &Policy, trust: &Trust, tree: &str, digest: &str, changed: &[String], prove_on: &str) -> (Vec<CheckStatus>, Vec<Finding>) {
    let found = classify(trust, &store::find(top, tree));
    let (evidence, mismatch) = evidence_for(&found, tree, digest);
    let at = Proof { top, policy, trust, tree, evidence: &evidence, prove_on };
    let mut all = None;
    let mut findings: Vec<Finding> = mismatch.into_iter().collect();
    let mut checks = Vec::new();
    for def in policy.required_checks() {
        let (status, finding) = judge_check(def, true, def.applies_to(changed.iter().map(String::as_str)), &at, &mut all);
        findings.extend(finding);
        checks.push(status);
    }
    (checks, findings)
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimStatus {
    pub text: String,
    pub category: claims::Category,
    #[serde(flatten)]
    pub judged: Judged,
}

/// A person's testing sign-off or skip for this tree (D87), and whether it counts.
#[derive(Debug, Clone, Serialize)]
pub struct TestingInfo {
    pub outcome: use05_receipt::Tested,
    pub by: Signer,
    pub note: String,
    pub created: String,
    /// It counts toward a push to a branch the policy names.
    pub counts: bool,
    /// Why it does not count, if it does not.
    pub void: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalInfo {
    pub scope: ApprovalScope,
    pub vote: Vote,
    pub by: Signer,
    pub rationale: String,
    /// When it was signed, RFC 3339.
    pub created: String,
    pub expires: String,
    /// `None` when it counts; otherwise why it does not.
    pub void: Option<&'static str>,
    /// The owned paths it counts for as an owner's approval (D92), whether or not it counts
    /// otherwise: an owner's passkey approval of someone else's work counts for these only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owner_of: Vec<String>,
    /// It approves this hotfix's outcome for landing (D93): an outcome approval naming this task
    /// and its environment. Only these count for a hotfix.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub for_hotfix: bool,
}

/// An owner rule a change touches (D92): who may approve it and who did.
#[derive(Debug, Clone, Serialize)]
pub struct OwnerStatus {
    /// The rule's paths, as the policy writes them.
    pub paths: Vec<String>,
    /// The groups and people the rule names.
    pub signers: Vec<String>,
    /// The people those signers name.
    pub people: Vec<String>,
    pub min: u32,
    /// The changed files the rule owns.
    pub changed: Vec<String>,
    /// The owners whose approval of this outcome counts for it, each once.
    pub approved_by: Vec<String>,
    pub met: bool,
}

impl OwnerStatus {
    /// Who may approve, for a person: `eng-managers (Dana, Lee)`, or just the names when the rule
    /// names people.
    pub fn named(&self) -> String {
        let plain = self.people.len() == self.signers.len() && self.people.iter().zip(&self.signers).all(|(p, s)| same_person(p, s));
        if plain { self.signers.join(", ") } else { format!("{} ({})", self.signers.join(", "), self.people.join(", ")) }
    }

    /// How many of the owners it needs have approved, at most `min`.
    pub fn counted(&self) -> usize {
        self.approved_by.len().min(self.min as usize)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BypassInfo {
    pub by: Signer,
    pub reason: String,
    pub expires: String,
    /// What it let through.
    pub suppressed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateResult {
    pub decision: Decision,
    pub findings: Vec<Finding>,
    pub checks: Vec<CheckStatus>,
    pub claims: Vec<ClaimStatus>,
    pub changed: Vec<ChangeInfo>,
    pub risk: Risk,
    /// Which risk categories the changed files fall into (D66).
    pub risk_reasons: Vec<crate::risk::Reason>,
    /// How strongly the task's action log is sealed (D70).
    pub log: Option<crate::logseal::LogIntegrity>,
    pub approvals: Vec<ApprovalInfo>,
    /// The owner rules the change touches (D92). Left out when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<OwnerStatus>,
    pub bypass: Option<BypassInfo>,
    pub policy_sha256: String,
    pub unverified_receipts: usize,
    /// Signed by a trusted key, but of a kind only a newer 05 reads.
    pub newer_receipts: usize,
    /// Other tools' records on the same branch, not read (D73).
    pub foreign_receipts: usize,
    /// People's testing sign-offs and skips for this tree (D87).
    pub testing: Vec<TestingInfo>,
    /// Git LFS files in the tree that the checks saw only as pointers, because the policy does not
    /// ask for the real files (`[evidence] lfs`, D96). 0 when it does.
    #[serde(skip_serializing_if = "is_zero")]
    pub lfs_pointers: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl GateResult {
    /// A decision made by rules other than a task's (a promotion's, D93), as the pre-push hook
    /// shows it: its findings and nothing else.
    pub fn of_findings(decision: Decision, findings: Vec<Finding>, policy_sha256: String) -> GateResult {
        GateResult {
            decision,
            findings,
            checks: Vec::new(),
            claims: Vec::new(),
            changed: Vec::new(),
            risk: Risk::Low,
            risk_reasons: Vec::new(),
            log: None,
            approvals: Vec::new(),
            owners: Vec::new(),
            bypass: None,
            policy_sha256,
            unverified_receipts: 0,
            newer_receipts: 0,
            foreign_receipts: 0,
            testing: Vec::new(),
            lfs_pointers: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeInfo {
    pub status: char,
    pub path: String,
    /// Lines added and removed; 0 and 0 for a binary file.
    pub added: u64,
    pub removed: u64,
}

pub struct GateInput<'a> {
    pub top: &'a Path,
    /// The effective policy, read from the change's base.
    pub policy: &'a Policy,
    pub trust: &'a Trust,
    pub task: Option<&'a Task>,
    pub base_tree: Option<&'a str>,
    pub target_tree: &'a str,
    pub target_digest: &'a str,
    pub now: u64,
    /// Files in the declared scope that were edited before the declaration was sealed.
    pub late: &'a [String],
    /// Changed files another task also edited, whose work is not in this change's base (D64).
    pub overlaps: &'a [String],
    /// How strongly the task's action log is sealed (D70).
    pub log: Option<&'a crate::logseal::LogIntegrity>,
    /// The work started behind origin's copy of its target and has not caught up since.
    pub stale_base: Option<&'a StaleBase>,
    /// The branch this change is being pushed (or landed, or merged) to, when gated for that: a
    /// policy can ask that a person tried it first (D87).
    /// `Some("")` when it is being pushed but CI could not tell where: held as if to the landing branch.
    pub pushing_to: Option<&'a str>,
    /// The host's default branch, when CI knows it: where work lands unless the policy names a target.
    pub default_branch: Option<&'a str>,
}

/// How far behind origin a task's work started, as the hook saw it when the session began.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleBase {
    /// `origin/main`.
    pub remote_ref: String,
    /// Commits on it the work does not have.
    pub behind: u32,
}

/// Rebuild, from signed receipts alone, the task that finished on `target_tree`: what its agent
/// declared and what it said it did. This is how CI sees the declaration (D65). Returns the task
/// and who signed what it was rebuilt from.
pub fn task_from_receipts(found: &crate::evidence::Found, target_tree: &str) -> Option<(Task, Signer)> {
    let done = found.completions.iter().filter(|c| c.statement.tree_subject().is_some_and(|(oid, _)| oid == target_tree)).max_by(|a, b| a.statement.predicate.finished.cmp(&b.statement.predicate.finished))?;
    let id = &done.statement.predicate.task;
    let declared = found.declarations.iter().filter(|d| &d.statement.predicate.task == id).max_by(|a, b| a.statement.predicate.sealed.cmp(&b.statement.predicate.sealed));
    let card: Option<crate::intent::IntentCard> = declared.and_then(|d| serde_json::from_value(d.statement.predicate.card.clone()).ok());
    let task = Task {
        id: id.clone(),
        title: declared.map(|d| d.statement.predicate.title.clone()).unwrap_or_else(|| "Agent work".into()),
        author: declared.map(|d| d.statement.predicate.author.clone()).unwrap_or_else(|| "unverified".into()),
        created: declared.map(|d| d.statement.predicate.sealed.clone()).unwrap_or_else(|| done.statement.predicate.finished.clone()),
        base_commit: None,
        base_tree: String::new(),
        branch: None,
        intent_sha256: card.as_ref().map(crate::intent::IntentCard::digest),
        intent: card,
        status: crate::task::Status::Finished,
        outcome: Some(done.statement.predicate.outcome.clone()).filter(|o| !o.is_empty()),
        finished: Some(done.statement.predicate.finished.clone()),
        session: None,
        sealed: declared.map(|d| d.statement.predicate.sealed.clone()),
        revisions: Vec::new(),
        request: None,
        head: None,
        ended: None,
        agent: declared.and_then(|d| d.statement.predicate.agent.clone()).map(|a| crate::task::AgentId { kind: a.kind, session: a.session, model: a.model }),
        owner: declared.and_then(|d| d.statement.predicate.owner.clone()).map(|o| crate::task::Owner { name: o.name, key_id: o.key_id }),
        sandbox: declared.and_then(|d| d.statement.predicate.sandbox.clone()),
        fresh: None,
        hotfix: None,
    };
    Some((task, done.signer.clone()))
}

fn expired(expires: &str, now: u64) -> bool {
    parse_rfc3339(expires).is_none_or(|t| t <= now)
}

/// Why a passkey's approval does not count, if it does not (D86). A page that holds a passkey can
/// be made to sign anything, so it counts only when the machine (or runner) that prepared the
/// statement co-signed it, and only for the person driving the work: the person the co-signed
/// statement names as approver and, when one is recorded, the work's owner. A machine key listed
/// with a `person` prepares only for that person. Keys that sign at a terminal are not passkeys and
/// are not checked here.
pub fn passkey_void(a: &Signed<use05_receipt::Statement<use05_receipt::Approval>>, trust: &Trust, driver: Option<&crate::task::Owner>) -> Option<&'static str> {
    passkey_void_of(&a.signer, &a.cosigners, &a.statement.predicate.approver, trust, driver)
}

/// [`passkey_void`] for any person's statement (an approval, a testing sign-off): who signed it,
/// who co-signed it, and the person it names.
pub fn passkey_void_of(by: &Signer, cosigners: &[Signer], approver: &str, trust: &Trust, driver: Option<&crate::task::Owner>) -> Option<&'static str> {
    let may_sign = |k: &crate::evidence::TrustedKey| match &k.holder {
        Holder::Person(p) => same_person(p, approver) && driver.is_none_or(|d| same_person(p, &d.name)),
        Holder::ThisMachine => driver.is_none_or(|d| trust.this_person.iter().any(|id| *id == d.key_id)),
        Holder::Unnamed => false,
    };
    passkey_void_when(by, cosigners, approver, trust, may_sign, "it was signed by someone other than the person driving the work")
}

/// Why a passkey's approval does not count for an owner rule (D92), if it does not, when the rule
/// says the key is `owner`'s (the caller looked that up for the rule, so a floor's rule goes only
/// by the floor's own keys). The driver's own counts as it does for any rule; otherwise an owner
/// may approve someone else's work, here only: the statement must name that owner, and a trusted
/// machine that may prepare for them must have co-signed it, as [`passkey_void_of`] asks.
fn owner_passkey_void(a: &Signed<use05_receipt::Statement<use05_receipt::Approval>>, trust: &Trust, driver: Option<&crate::task::Owner>, owner: &str) -> Option<&'static str> {
    // Counts as the driver's own approval: nothing more to ask.
    passkey_void(a, trust, driver)?;
    let approver = &a.statement.predicate.approver;
    passkey_void_when(&a.signer, &a.cosigners, approver, trust, |_| same_person(owner, approver), "it names someone other than its signer as the approver")
}

/// The checks a passkey's statement passes whoever it is for: a trusted preparer co-signed it, one
/// of the key's trust entries `may_sign` it, and no preparer named for another person prepared it.
fn passkey_void_when(by: &Signer, cosigners: &[Signer], approver: &str, trust: &Trust, may_sign: impl Fn(&crate::evidence::TrustedKey) -> bool, not_theirs: &'static str) -> Option<&'static str> {
    let same = same_person;
    // A key can be both listed in the policy and pinned here; any of its entries may vouch for it.
    let holders = |id: &str| trust.keys.iter().filter(|k| k.id == id).collect::<Vec<_>>();
    let signer = holders(&by.key_id);
    if !signer.iter().any(|k| k.key.is_passkey()) {
        return None;
    }
    if cosigners.is_empty() {
        return Some("no machine that prepared it co-signed it");
    }
    let theirs = signer.iter().any(|k| may_sign(k));
    if !theirs {
        return Some(if signer.iter().all(|k| k.holder == Holder::Unnamed) { "its trust entry names no person" } else { not_theirs });
    }
    // A preparing machine named for a person prepares only for that person.
    let prepared_for_them = cosigners.iter().any(|c| {
        holders(&c.key_id).iter().all(|k| match &k.holder {
            Holder::Person(q) => same(q, approver),
            _ => true,
        })
    });
    if !prepared_for_them {
        return Some("it was prepared on someone else's machine");
    }
    None
}

/// Clocks differ a little between the machine that prepared an approval and the one reading it.
const CLOCK_SKEW_SECS: u64 = 300;

/// Why an approval does not count, if it does not: given under other rules, expired, dated ahead,
/// or made to last longer than `approvals.expire_days`. Whoever prepared the statement chose its
/// dates, so the reader checks them against its own policy.
pub fn approval_void(a: &use05_receipt::Approval, policy: &Policy, now: u64) -> Option<&'static str> {
    if a.policy_sha256 != policy.digest() {
        return Some("it was given under a different policy");
    }
    if expired(&a.expires, now) {
        return Some("expired");
    }
    let (Some(created), Some(expires)) = (parse_rfc3339(&a.created), parse_rfc3339(&a.expires)) else {
        return Some("it is not dated");
    };
    if created > now + CLOCK_SKEW_SECS {
        return Some("it is dated in the future");
    }
    if expires.saturating_sub(created) > policy.approvals.expire_days as u64 * 86_400 + CLOCK_SKEW_SECS {
        return Some("it lasts longer than the policy allows");
    }
    None
}

/// `Dana`, `Dana or Lee`, `Dana, Lee or Sam`.
fn either(people: &[String]) -> String {
    match people {
        [] => "an owner".to_string(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

fn effect_for(severity: Severity) -> Option<Effect> {
    match severity {
        Severity::Allow => None,
        Severity::Warn => Some(Effect::Warn),
        Severity::Approval => Some(Effect::Approval),
        Severity::Deny => Some(Effect::Deny),
    }
}

pub fn evaluate(input: &GateInput<'_>) -> Result<GateResult> {
    let policy = input.policy;
    let policy_sha256 = policy.digest();
    let changes: Vec<Change> = git::changed(input.top, input.base_tree, input.target_tree)?;
    let paths: Vec<String> = changes.iter().map(|c| c.path.clone()).collect();
    let card = input.task.and_then(|t| t.intent.as_ref());
    let card_digest = input.task.and_then(|t| t.intent_sha256.as_deref());

    let mut risk = risk_of_paths(policy, paths.iter().map(String::as_str));
    let risk_reasons = crate::risk::of_paths(policy, &paths);
    if let Some(card) = card {
        risk = risk.max(card.risk(policy));
    }

    // ------------------------------------------------------------- receipts
    let at_tree = classify(input.trust, &store::find(input.top, input.target_tree));
    let intent_receipts = card_digest.map(|d| classify(input.trust, &store::find(input.top, d))).unwrap_or_default();
    let (evidence, mismatch) = evidence_for(&at_tree, input.target_tree, input.target_digest);
    let accepted = |role: Role| policy.evidence.accept.contains(&role);

    let mut findings: Vec<Finding> = mismatch.into_iter().collect();
    let mut checks: Vec<CheckStatus> = Vec::new();

    // ------------------------------------------------------------- required checks
    let mut wanted: Vec<(String, bool)> = policy.required_checks().map(|c| (c.name.clone(), true)).collect();
    if let Some(card) = card {
        for name in &card.acceptance {
            if !wanted.iter().any(|(n, _)| n == name) {
                wanted.push((name.clone(), true)); // a card's acceptance checks are required for that change
            }
        }
    }
    let mut all_receipts: Option<Found> = None;
    for (name, required) in &wanted {
        let Some(def) = policy.check_named(name) else {
            checks.push(CheckStatus { name: name.clone(), run: Vec::new(), dir: None, paths: Vec::new(), required: *required, state: CheckState::Undefined });
            findings.push(
                Finding::new("CHECK_UNDEFINED", Effect::Wait, format!("the intent asks for the check {name:?}, which the policy does not define"))
                    .next("add it to .05/policy.toml, or remove it from the intent"),
            );
            continue;
        };
        // A check scoped to paths is required only for a change that touches them. One a card asks
        // for by name is required for that change whatever its paths.
        let asked_for_by_card = card.is_some_and(|c| c.acceptance.contains(name));
        let applies = asked_for_by_card || def.applies_to(paths.iter().map(String::as_str));
        let (status, finding) = judge_check(def, *required, applies, &Proof { top: input.top, policy, trust: input.trust, tree: input.target_tree, evidence: &evidence, prove_on: "" }, &mut all_receipts);
        findings.extend(finding);
        checks.push(status);
    }

    // ------------------------------------------------------------- intent
    let needs_card = match policy.intent.mode {
        IntentMode::Inferred => false,
        IntentMode::Risky => risk > Risk::Low,
        IntentMode::Always => true,
    };
    if input.task.is_some() && card.is_none() && needs_card {
        findings.push(
            Finding::new("INTENT_REQUIRED", Effect::Wait, format!("policy requires an intent card here (mode: {:?}), and this task has none", policy.intent.mode).to_lowercase())
                .next("use05 start \"what you are doing\" --scope \"src/**\" --check test"),
        );
    }

    // ------------------------------------------------------------- scope
    match card {
        Some(card) if card.has_scope() || !card.scope.exclude.is_empty() => {
            let outside: Vec<String> = paths.iter().filter(|p| !card.allows(p)).cloned().collect();
            if !outside.is_empty() {
                let effect = effect_for(policy.drift.scope).unwrap_or(Effect::Info);
                let mut f = Finding::new("SCOPE_EXCEEDED", effect, format!("{} file(s) changed outside the declared scope", outside.len())).paths(outside);
                if effect == Effect::Approval {
                    f = f.approvable();
                }
                findings.push(f);
            }
        }
        _ if input.task.is_some() => findings.push(Finding::new("SCOPE_UNDECLARED", Effect::Info, "no scope was declared, so scope drift cannot be checked")),
        _ => {}
    }

    // ------------------------------------------------------------- declared late
    if !input.late.is_empty() && card.is_some() {
        let mut f = Finding::new("DECLARED_LATE", Effect::Warn, format!("{} file(s) in the declared scope were edited before the declaration was sealed", input.late.len()))
            .paths(input.late.to_vec())
            .next("declare before you edit: use05 start \"what you will do\" --scope \"<paths>\"");
        if policy.intent.mode == IntentMode::Always {
            f.effect = Effect::Approval;
            f = f.approvable();
        }
        findings.push(f);
    }

    // ------------------------------------------------------------- the action log
    if let Some(line) = input.log.and_then(|l| l.altered_at) {
        findings.push(Finding::new("LOG_ALTERED", Effect::Warn, format!("the action log was changed after it was sealed: line {line} no longer matches")).next("ask who changed it; the copy on the receipts branch is the sealed one"));
    }

    // ------------------------------------------------------------- overlap with other tasks
    if !input.overlaps.is_empty() {
        if let Some(effect) = effect_for(policy.drift.overlap) {
            let mut f = Finding::new("OVERLAP", effect, format!("{} file(s) were also changed by another task whose work is not in this change's base yet", input.overlaps.len()))
                .paths(input.overlaps.to_vec())
                .next("rebase onto the other task's work once it lands, then prove again");
            if effect == Effect::Approval {
                f = f.approvable();
            }
            findings.push(f);
        }
    }

    // ------------------------------------------------------------- started behind origin
    if let (Some(stale), Some(effect)) = (input.stale_base.filter(|s| s.behind > 0), effect_for(policy.branches.fresh_base)) {
        let (remote, branch) = stale.remote_ref.split_once('/').unwrap_or(("origin", stale.remote_ref.as_str()));
        let mut f = Finding::new("BASE_STALE", effect, format!("the work started {} commit{} behind {}", stale.behind, if stale.behind == 1 { "" } else { "s" }, stale.remote_ref))
            .next(format!("update first: git pull --rebase {remote} {branch}, then prove again"));
        if effect == Effect::Approval {
            f = f.approvable();
        }
        findings.push(f);
    }

    // ------------------------------------------------------------- files that change together
    for rule in &policy.require {
        let unmet = rule.unmet(&paths);
        if unmet.is_empty() {
            continue;
        }
        let Some(effect) = effect_for(rule.severity) else { continue };
        let why = rule.why.as_deref().map(|w| format!(" ({w})")).unwrap_or_default();
        let mut f = Finding::new("ALSO_CHANGE_MISSING", effect, format!("{} file(s) changed that need {} to change too, and nothing there did{why}", unmet.len(), rule.also.join(" or ")))
            .paths(unmet)
            .next(format!("update {} in this change", rule.also.join(" or ")));
        if effect == Effect::Approval {
            f = f.approvable();
        }
        findings.push(f);
    }

    // ------------------------------------------------------------- protected paths and dependencies
    // Path rules (D79): no approval clears these; a person's bypass can, unless it is absolute.
    let rules = &policy.protect;
    let locked: Vec<String> = paths.iter().filter(|p| rules.is_locked(p)).cloned().collect();
    if !locked.is_empty() {
        findings.push(
            Finding::new("LOCKED_PATH", Effect::Deny, format!("{} locked file(s) changed; locked files are never changed here", locked.len()))
                .paths(locked.clone())
                .next("undo the change to them; unlocking is its own change to .05/policy.toml, approved by a person and landed first"),
        );
    }
    let rewritten: Vec<String> = changes.iter().filter(|c| c.status != 'A' && rules.is_append_only(&c.path) && !locked.contains(&c.path)).map(|c| c.path.clone()).collect();
    if !rewritten.is_empty() {
        findings.push(
            Finding::new("APPEND_ONLY", Effect::Deny, format!("{} file(s) in an append-only area were edited, renamed or deleted; only new files may be added there", rewritten.len()))
                .paths(rewritten.clone())
                .next("put the change in a new file instead"),
        );
    }
    let deleted: Vec<String> = changes.iter().filter(|c| c.status == 'D' && rules.is_no_delete(&c.path) && !locked.contains(&c.path) && !rewritten.contains(&c.path)).map(|c| c.path.clone()).collect();
    if !deleted.is_empty() {
        findings.push(Finding::new("NO_DELETE", Effect::Deny, format!("{} file(s) that may not be deleted were deleted", deleted.len())).paths(deleted).next("restore them"));
    }
    let absolute: Vec<String> = locked.iter().filter(|p| rules.is_absolute(p)).cloned().collect();
    let path_rule_unbypassable = !absolute.is_empty() || (!rules.bypass && findings.iter().any(|f| ["APPEND_ONLY", "NO_DELETE"].contains(&f.code)));

    let protected: Vec<String> = paths.iter().filter(|p| is_protected(policy, p) && !locked.contains(p)).cloned().collect();
    if !protected.is_empty() {
        let own_rules = protected.iter().any(|p| p.starts_with(".05/"));
        let mut message = format!("{} protected file(s) changed", protected.len());
        if own_rules {
            message.push_str("; the change edits 05's own rules, which only take effect after it is merged");
        }
        findings.push(Finding::new("PROTECTED_PATH", Effect::Approval, message).paths(protected).approvable().next("use05 approve --outcome"));
    }
    let deps: Vec<String> = paths.iter().filter(|p| is_dependency_file(p)).cloned().collect();
    let promised_none = card.is_some_and(|c| c.no_new_dependencies);
    if !deps.is_empty() {
        let base = effect_for(policy.drift.dependencies);
        let effect = match (base, promised_none) {
            (_, true) => Some(Effect::Deny.max(base.unwrap_or(Effect::Info))),
            (b, false) => b,
        };
        if let Some(effect) = effect {
            let message = if promised_none { "dependency files changed, against the card's promise of none" } else { "dependency files changed" };
            let mut f = Finding::new("DEP_FILES_CHANGED", effect, message).paths(deps);
            if effect == Effect::Approval {
                f = f.approvable().next("use05 approve --outcome");
            }
            findings.push(f);
        }
    }

    // ------------------------------------------------------------- weakened tests
    let weakened = crate::weakening::analyse(input.top, input.base_tree, input.target_tree, &changes)?;
    if !weakened.is_empty() {
        if let Some(effect) = effect_for(policy.drift.tests) {
            let mut kinds: Vec<&str> = weakened.iter().map(|w| w.kind).collect();
            kinds.dedup();
            let mut paths: Vec<String> = weakened.iter().map(|w| w.path.clone()).collect();
            paths.sort();
            paths.dedup();
            let words = kinds.iter().map(|k| k.replace('_', " ")).collect::<Vec<_>>().join(", ");
            let mut f = Finding::new("TESTS_WEAKENED", effect, format!("the change weakens its own checks: {words}")).paths(paths);
            if effect == Effect::Approval {
                f = f.approvable().next("restore the tests, or ask a person: use05 approve --outcome");
            }
            findings.push(f);
        }
    }

    // ------------------------------------------------------------- claims
    let observed_store: Vec<(String, Vec<String>, Status)> = evidence
        .iter()
        .filter(|e| accepted(e.signer.role))
        .map(|e| (e.statement.predicate.check.clone().unwrap_or_else(|| e.statement.predicate.command.argv.join(" ")), e.statement.predicate.command.argv.clone(), e.statement.predicate.result.status))
        .collect();
    let observed: Vec<Observed<'_>> = observed_store.iter().map(|(n, a, s)| Observed { name: n, argv: a, status: *s }).collect();
    let mut claim_status = Vec::new();
    for claim in input.task.and_then(|t| t.outcome.as_deref()).map(claims::extract).unwrap_or_default() {
        let judged = claims::judge(&claim, &observed);
        match &judged {
            Judged::Supported { .. } => {}
            Judged::Unsupported => {
                if let Some(effect) = effect_for(policy.drift.claims) {
                    findings.push(Finding::new("CLAIM_UNSUPPORTED", effect, format!("claimed \"{}\", but no {} check was proved on this tree", claim.text, claim.category.word())).next("use05 prove"));
                }
            }
            Judged::Contradicted { by } => findings.push(Finding::new("CLAIM_CONTRADICTED", Effect::Deny, format!("claimed \"{}\", but the check {by:?} did not pass", claim.text))),
        }
        claim_status.push(ClaimStatus { text: claim.text, category: claim.category, judged });
    }

    // ------------------------------------------------------------- approvals
    let mut approval_info = Vec::new();
    let mut counting_for_intent: Vec<String> = Vec::new();
    let mut counting_for_outcome: Vec<String> = Vec::new();
    // Approvals of this hotfix's outcome, for its environment and this task alone (D93).
    let mut counting_for_hotfix: Vec<String> = Vec::new();
    let mut hotfix_said: Vec<String> = Vec::new();
    let mut given_for_other = false;
    let mut rejected_by: Option<Signer> = None;
    let mut changed_intent = false;
    let everything = all_receipts.get_or_insert_with(|| classify(input.trust, &store::find_all(input.top)));
    let candidates = at_tree.approvals.iter().chain(intent_receipts.approvals.iter()).chain(everything.approvals.iter());
    let mut seen = Vec::new();
    // Approvals and rejections of this exact outcome, each once, with where each is in
    // `approval_info`: what owner rules read (D92).
    let mut of_outcome: Vec<(&Signed<use05_receipt::Statement<use05_receipt::Approval>>, usize)> = Vec::new();
    for a in candidates {
        // The same receipt can arrive from several refs; count it once.
        if seen.contains(&a.path) {
            continue;
        }
        seen.push(a.path.clone());
        let p = &a.statement.predicate;
        let (subject_ok, task_ok) = match p.scope {
            ApprovalScope::Outcome => (a.statement.tree_subject().is_some_and(|(oid, d)| oid == input.target_tree && d == input.target_digest), true),
            ApprovalScope::Intent => (
                card_digest.is_some_and(|d| a.statement.intent_subject() == Some(d)),
                input.task.is_none_or(|t| t.id == p.task),
            ),
        };
        // An approval of an older card for this same task: the intent changed since.
        if p.scope == ApprovalScope::Intent && input.task.is_some_and(|t| t.id == p.task) && !subject_ok && p.decision == Vote::Approve {
            changed_intent = true;
        }
        if !subject_ok || !task_ok {
            continue;
        }
        if p.scope == ApprovalScope::Outcome {
            of_outcome.push((a, approval_info.len()));
        }
        let void = approval_void(p, policy, input.now).or_else(|| passkey_void(a, input.trust, input.task.and_then(|t| t.owner.as_ref())));
        // Given for this hotfix: an outcome approval naming its environment and this task. It counts
        // for landing it only from someone the environment lets sign, in as many words as it asks.
        let given_for_hotfix = p.scope == ApprovalScope::Outcome && input.task.is_some_and(|t| t.hotfix.is_some() && t.hotfix == p.hotfix && t.id == p.task);
        let hotfix_env = p.hotfix.as_deref().and_then(|e| policy.environment_named(e));
        let hotfix_why = hotfix_env.filter(|_| given_for_hotfix && p.decision == Vote::Approve).and_then(|e| {
            let id = a.signer.key_id.as_str();
            crate::promote::signer_void(input.trust.person_of(id).as_deref(), input.trust.is_this_machines(id), policy, e).or_else(|| crate::promote::words_void(&p.rationale, e))
        });
        let for_hotfix = given_for_hotfix && hotfix_why.is_none();
        if let (Some(why), None) = (&hotfix_why, void) {
            hotfix_said.push(format!("{}'s approval does not count for it: {why}", input.trust.person_of(&a.signer.key_id).unwrap_or_else(|| p.approver.clone())));
        }
        if !given_for_hotfix && void.is_none() && p.scope == ApprovalScope::Outcome && p.decision == Vote::Approve {
            given_for_other = true;
        }
        approval_info.push(ApprovalInfo { scope: p.scope, vote: p.decision, by: a.signer.clone(), rationale: p.rationale.clone(), created: p.created.clone(), expires: p.expires.clone(), void, owner_of: Vec::new(), for_hotfix });
        if void.is_none() && for_hotfix && p.decision == Vote::Approve {
            counting_for_hotfix.push(a.signer.key_id.clone());
        }
        if void.is_none() {
            match (p.decision, p.scope) {
                (Vote::Reject, ApprovalScope::Outcome) => rejected_by = Some(a.signer.clone()),
                (Vote::Approve, ApprovalScope::Intent) => counting_for_intent.push(a.signer.key_id.clone()),
                (Vote::Approve, ApprovalScope::Outcome) => counting_for_outcome.push(a.signer.key_id.clone()),
                _ => {}
            }
        }
    }
    let distinct = |ids: &mut Vec<String>| {
        ids.sort();
        ids.dedup();
        ids.len()
    };
    let mut both: Vec<String> = counting_for_intent.iter().chain(counting_for_outcome.iter()).cloned().collect();
    let approved = distinct(&mut both) as u32 >= policy.approvals.min;
    if let Some(by) = rejected_by {
        findings.push(Finding::new("REJECTED", Effect::Deny, format!("{} rejected this outcome", by.name)));
    }
    if changed_intent && !approved {
        findings.push(Finding::new("INTENT_CHANGED", Effect::Approval, "the intent card changed after it was approved").approvable().next("use05 approve --intent"));
    }
    let protected_raised = findings.iter().any(|f| f.code == "PROTECTED_PATH");
    let intent_rule = risk == Risk::High && card.is_some();
    if intent_rule && !approved && !protected_raised {
        findings.push(Finding::new("INTENT_NOT_APPROVED", Effect::Approval, "this is a high-risk task and its intent has not been approved").approvable().next("use05 approve --intent"));
    }
    // A change in a risk category needs one person's approval, of the plan or of the outcome.
    if crate::risk::highest(&risk_reasons) >= Risk::Medium && !intent_rule && !protected_raised {
        let what = risk_reasons.iter().map(|r| format!("{} ({}): {} file(s)", r.category, r.level.word(), r.paths.len())).collect::<Vec<_>>().join("; ");
        let next = if card.is_some() { "use05 approve --intent" } else { "use05 approve --outcome" };
        findings.push(
            Finding::new("RISK_NOT_APPROVED", Effect::Approval, format!("this change is in a risk area and nobody approved it: {what}"))
                .paths(risk_reasons.iter().flat_map(|r| r.paths.clone()).collect())
                .approvable()
                .next(next),
        );
    }

    // Approvals clear what approvals can clear.
    if approved {
        for f in findings.iter_mut().filter(|f| f.approvable && f.effect == Effect::Approval) {
            f.effect = Effect::Info;
            f.message.push_str(" (approved)");
        }
    } else if findings.iter().any(|f| f.approvable && f.effect == Effect::Approval) {
        // An approval that is there but does not count is named, with why, never passed over
        // as if nobody had approved.
        let mut said = Vec::new();
        for a in approval_info.iter().filter(|a| a.vote == Vote::Approve) {
            if let Some(why) = a.void {
                let what = if a.scope == ApprovalScope::Intent { "intent" } else { "outcome" };
                // Approving twice is one person's approval, said once.
                if said.contains(&(a.by.key_id.clone(), what, why)) {
                    continue;
                }
                said.push((a.by.key_id.clone(), what, why));
                findings.push(
                    Finding::new("APPROVAL_NOT_COUNTED", Effect::Approval, format!("an approval of the {what} by {} does not count: {why}", a.by.name))
                        .approvable()
                        .next(format!("use05 approve --{what}")),
                );
            }
        }
    }

    // ------------------------------------------------------------- a hotfix (D93)
    // A hotfix lands straight on an environment's branch, past the environments below it: a
    // person's approval of its outcome is always needed. Built in: no setting turns it off, an
    // approval of the intent does not count for it, and no bypass clears it.
    let mut hotfix_unmet = false;
    if let Some(env) = input.task.and_then(|t| t.hotfix.as_deref()) {
        let mut outcome = counting_for_hotfix.clone();
        let n = distinct(&mut outcome) as u32;
        let min = policy.approvals.min.max(1);
        hotfix_unmet = n < min;
        let needs = if min == 1 { "a person's approval of its outcome".to_string() } else { format!("approvals of its outcome from {min} people") };
        let mut message = format!("a hotfix lands straight on {env}, so it needs {needs}, given for this hotfix: {n} of {min}");
        // An approval of the same tree given for something else is no hotfix's approval.
        if hotfix_unmet && given_for_other {
            message.push_str("; an approval of this tree given for something else does not count for it");
        }
        if hotfix_unmet {
            for said in &hotfix_said {
                message.push_str(&format!("; {said}"));
            }
        }
        let mut f = Finding::new("HOTFIX_NEEDS_APPROVAL", if hotfix_unmet { Effect::Approval } else { Effect::Info }, message);
        if hotfix_unmet {
            f = f.next("ask a person to approve it: use05 approve --outcome");
        } else {
            f.message.push_str(" (approved)");
        }
        findings.push(f);
    }

    // ------------------------------------------------------------- path owners (D92)
    // Besides the approvals above, a change to owned paths needs approvals of its outcome from
    // `min` distinct owners. The generic `approved` never clears these: only owners do. A key is
    // an owner's only through the policy's `person` for it, and for a floor's rule only through the
    // floor's own keys.
    let driver = input.task.and_then(|t| t.owner.as_ref());
    let mut owners = Vec::new();
    // For each unmet rule: its finding, and the rule, whose owners alone may bypass it.
    let mut held: Vec<(usize, crate::policy::ResolvedOwner)> = Vec::new();
    for rule in policy.owner_rules() {
        let touched = rule.touched(&paths);
        if touched.is_empty() {
            continue;
        }
        let people = rule.people.clone();
        let owned = rule.paths.join(", ");
        let is_owner = |name: &str| people.iter().any(|p| same_person(p, name));
        let mut approved_by: Vec<String> = Vec::new();
        let mut said: Vec<String> = Vec::new();
        for (a, at) in of_outcome.iter().filter(|(a, _)| a.statement.predicate.decision == Vote::Approve) {
            let void = approval_void(&a.statement.predicate, policy, input.now);
            let who = rule.person_of(&a.signer.key_id, input.trust, input.now);
            let message = match &who {
                Some(w) if is_owner(w) => match void.or_else(|| owner_passkey_void(a, input.trust, driver, w)) {
                    None => {
                        // The name as the policy writes it, so one person reads the same everywhere.
                        let name = people.iter().find(|q| same_person(q, w)).cloned().unwrap_or_else(|| w.clone());
                        if !approved_by.contains(&name) {
                            approved_by.push(name);
                        }
                        if !approval_info[*at].owner_of.contains(&owned) {
                            approval_info[*at].owner_of.push(owned.clone());
                        }
                        continue;
                    }
                    Some(why) => format!("{w}'s approval does not count for {owned}: {why}"),
                },
                // An approval that is void anyway is named where it is void; here only who it is from.
                _ if void.is_some() => continue,
                Some(w) => format!("{w} approved, but is not an owner of {owned}"),
                None if rule.keys.is_some() => format!("an approval by {} does not count for {owned}: the organisation's rule goes only by the keys the organisation lists", a.signer.name),
                None => format!("an approval by {} does not count for {owned}: its key names no person", a.signer.name),
            };
            if !said.contains(&message) {
                said.push(message);
            }
        }
        let met = approved_by.len() as u32 >= rule.min;
        let status = OwnerStatus { paths: rule.paths.clone(), signers: rule.signers.clone(), people, min: rule.min, changed: touched, approved_by, met };
        let needs = if rule.min == 1 { "an approval" } else { "approvals" };
        let mut message = match status.people.len() {
            // An organisation floor's groups and the repository's can leave a rule nobody can meet.
            0 if rule.signers.len() == 1 => format!("nobody in {} can approve changes to {owned}", rule.signers[0]),
            0 => format!("nobody can approve changes to {owned}: the groups {} have no one in common", rule.signers.join(", ")),
            n if (n as u32) < rule.min => format!("too few people can approve changes to {owned}: it needs {} owners, and {} names {n}", rule.min, status.named()),
            _ => format!("{owned} needs {needs} from {}: {} of {}", status.named(), status.counted(), rule.min),
        };
        if met {
            message.push_str(&format!(" (approved by {})", status.approved_by.join(", ")));
        }
        let ask = if (status.people.len() as u32) < rule.min { "correct the groups in .05/policy.toml, or in the organisation's rules".to_string() } else { format!("ask {} to run: use05 approve --outcome --rev <commit>", either(&status.people)) };
        if !met {
            held.push((findings.len(), rule.clone()));
        }
        findings.push(Finding::new("OWNER_APPROVAL_REQUIRED", if met { Effect::Info } else { Effect::Approval }, message).paths(status.changed.clone()).next(ask.clone()));
        if !met {
            for m in said {
                findings.push(Finding::new("OWNER_APPROVAL_NOT_COUNTED", Effect::Approval, m).next(ask.clone()));
            }
        }
        owners.push(status);
    }

    // ------------------------------------------------------------- testing before a push (D87)
    let mut testing = Vec::new();
    if policy.testing.local != crate::policy::LocalTesting::Off {
        let skippable = policy.testing.local == crate::policy::LocalTesting::Skippable;
        let driver = input.task.and_then(|t| t.owner.as_ref());
        let mut seen = Vec::new();
        for t in at_tree.testing.iter().chain(everything.testing.iter()) {
            if seen.contains(&t.path) || !t.statement.tree_subject().is_some_and(|(oid, d)| oid == input.target_tree && d == input.target_digest) {
                continue;
            }
            seen.push(t.path.clone());
            let p = &t.statement.predicate;
            let mut void = passkey_void_of(&t.signer, &t.cosigners, &p.tester, input.trust, driver);
            if void.is_none() && p.outcome == use05_receipt::Tested::Skipped && !skippable {
                void = Some("the policy requires testing, so a skip does not count");
            }
            testing.push(TestingInfo { outcome: p.outcome, by: t.signer.clone(), note: p.note.clone(), created: p.created.clone(), counts: void.is_none(), void });
        }
        let signed = testing.iter().any(|t| t.counts);
        // The policy says where, never the agent's declaration; a push CI could not place is held.
        let landing = crate::branches::landing_for(policy, input.default_branch, input.top);
        let applies = |branch: &str| branch.is_empty() || if policy.testing.branches.is_empty() { branch == landing } else { policy.testing.branches.iter().any(|p| crate::glob::matches(p, branch)) };
        let next = "use05 approve --tested --note \"<what you tried>\"";
        let or_skip = if skippable { ", or skip it with a reason (use05 approve --skip-testing)" } else { "" };
        match input.pushing_to {
            Some(branch) if applies(branch) && !signed => {
                let skipped = testing.iter().any(|t| t.outcome == use05_receipt::Tested::Skipped);
                let why = if skipped && !skippable { "; a skip does not count here: the policy requires testing" } else { "" };
                let to = if branch.is_empty() { String::new() } else { format!(" to {branch}") };
                findings.push(Finding::new("TESTING_REQUIRED", Effect::Approval, format!("before this is pushed{to}, a person must try it in their own environment and sign off{or_skip}{why}")).next(next));
            }
            None if !signed => {
                let to = if policy.testing.branches.is_empty() { landing.clone() } else { policy.testing.branches.join(", ") };
                findings.push(Finding::new("TESTING_NOT_SIGNED", Effect::Info, format!("before it is pushed to {to}, a person must try it in their own environment and sign off{or_skip}")).next(next));
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------- decision
    let worst = findings.iter().map(|f| f.effect).max().unwrap_or(Effect::Info);
    let mut decision = match worst {
        Effect::Deny => Decision::Deny,
        Effect::Approval => Decision::ApprovalRequired,
        Effect::Wait => Decision::Wait,
        Effect::Warn | Effect::Info => Decision::Allow,
    };

    // Break-glass: a person overrode this exact tree, for a stated reason. Recorded, never silent.
    let mut bypass = None;
    if decision != Decision::Allow {
        let valid: Vec<_> = at_tree
            .bypasses
            .iter()
            .filter(|b| b.statement.tree_subject().is_some_and(|(oid, d)| oid == input.target_tree && d == input.target_digest) && !expired(&b.statement.predicate.expires, input.now))
            .collect();
        // Owner rules are path rules (D79): with `bypass = false`, no bypass clears them either.
        let owners_unbypassable = !rules.bypass && !held.is_empty();
        // And only one of its owners may bypass an owner rule (D92), by the policy's `person`.
        // One signer must own every held rule: separate owners' bypasses do not combine.
        let owns = |b: &Signed<use05_receipt::Statement<use05_receipt::Bypass>>, rule: &crate::policy::ResolvedOwner| rule.person_of(&b.signer.key_id, input.trust, input.now).is_some_and(|p| rule.people.iter().any(|q| same_person(q, &p)));
        let valid = valid.iter().copied().find(|b| held.iter().all(|(_, rule)| owns(b, rule))).or(valid.first().copied());
        let not_theirs: Vec<&(usize, crate::policy::ResolvedOwner)> = valid.map(|b| held.iter().filter(|(_, rule)| !owns(b, rule)).collect()).unwrap_or_default();
        if valid.is_some() && (path_rule_unbypassable || owners_unbypassable || hotfix_unmet) {
            let message = if hotfix_unmet {
                "a person bypassed this tree, but a hotfix needs a person's approval of its outcome, and no bypass clears that".to_string()
            } else if absolute.is_empty() {
                "a person bypassed this tree, but policy allows no bypass of its path rules".to_string()
            } else {
                format!("a person bypassed this tree, but no bypass can clear {}: its lock is absolute", absolute.join(", "))
            };
            findings.push(Finding::new("BYPASS_NOT_ALLOWED", Effect::Info, message));
        } else if !not_theirs.is_empty() {
            // It clears what it may; the owned paths still wait for one of their owners.
            for (i, rule) in &not_theirs {
                findings[*i].message.push_str(&format!("; a bypass of an owned path must come from one of its owners ({})", rule.people.join(", ")));
            }
            // What the bypass will clear is not what is left: said, so neither the brief nor the
            // JSON reads as if it still held the change back on its own.
            let owned = not_theirs.iter().map(|(_, rule)| rule.paths.join(", ")).collect::<Vec<_>>().join("; ");
            let held_at: Vec<usize> = not_theirs.iter().map(|(i, _)| *i).collect();
            for (i, f) in findings.iter_mut().enumerate() {
                if f.effect >= Effect::Wait && !held_at.contains(&i) && f.code != "OWNER_APPROVAL_NOT_COUNTED" {
                    f.message.push_str(&format!(" (a bypass covers this once an owner of {owned} approves or bypasses it)"));
                }
            }
            decision = Decision::ApprovalRequired;
        } else if let Some(b) = valid {
            bypass = Some(BypassInfo {
                by: b.signer.clone(),
                reason: b.statement.predicate.reason.clone(),
                expires: b.statement.predicate.expires.clone(),
                suppressed: findings.iter().filter(|f| f.effect >= Effect::Wait).map(|f| f.code.to_string()).collect(),
            });
            decision = Decision::Allow;
        }
    }

    findings.sort_by(|a, b| b.effect.cmp(&a.effect));
    Ok(GateResult {
        decision,
        findings,
        checks,
        claims: claim_status,
        changed: {
            let counts = git::numstat(input.top, input.base_tree, input.target_tree)?;
            changes.iter().map(|c| {
                let (added, removed) = counts.get(&c.path).copied().unwrap_or((0, 0));
                ChangeInfo { status: c.status, path: c.path.clone(), added, removed }
            }).collect()
        },
        risk,
        risk_reasons,
        log: input.log.cloned(),
        approvals: approval_info,
        owners,
        bypass,
        policy_sha256,
        unverified_receipts: at_tree.unverified,
        newer_receipts: at_tree.newer,
        foreign_receipts: at_tree.foreign,
        testing,
        lfs_pointers: if policy.evidence.lfs { 0 } else { git::lfs_pointer_count(input.top, input.target_tree) },
    })
}

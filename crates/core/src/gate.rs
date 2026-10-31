//! The gate: given a change, the rules it is held to, and every receipt we can verify,
//! decide whether it may proceed. Deterministic: the same inputs give the same decision,
//! and nothing here asks a model for an opinion.

use std::path::Path;

use serde::Serialize;
use use05_receipt::{ApprovalScope, Decision as Vote, Status};

use crate::claims::{self, Judged, Observed};
use crate::error::Result;
use crate::evidence::{Found, Signed, Signer, Trust, classify};
use crate::git::{self, Change};
use crate::intent::{Risk, is_dependency_file, is_protected, risk_of_paths};
use crate::policy::{IntentMode, Policy, Role, Severity};
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
    /// A person's approval can clear this finding.
    pub approvable: bool,
}

impl Finding {
    fn new(code: &'static str, effect: Effect, message: impl Into<String>) -> Finding {
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
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckStatus {
    pub name: String,
    pub run: Vec<String>,
    pub required: bool,
    #[serde(flatten)]
    pub state: CheckState,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimStatus {
    pub text: String,
    pub category: claims::Category,
    #[serde(flatten)]
    pub judged: Judged,
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
    pub bypass: Option<BypassInfo>,
    pub policy_sha256: String,
    pub unverified_receipts: usize,
    /// Signed by a trusted key, but of a kind only a newer 05 reads.
    pub newer_receipts: usize,
    /// Other tools' records on the same branch, not read (D73).
    pub foreign_receipts: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeInfo {
    pub status: char,
    pub path: String,
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
    };
    Some((task, done.signer.clone()))
}

fn expired(expires: &str, now: u64) -> bool {
    parse_rfc3339(expires).is_none_or(|t| t <= now)
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
    // Evidence is only evidence for this exact tree if both digests match.
    let mut digest_mismatch = false;
    let mut evidence: Vec<&Signed<_>> = Vec::new();
    for e in &at_tree.evidence {
        match e.statement.tree_subject() {
            Some((oid, digest)) if oid == input.target_tree && digest == input.target_digest => evidence.push(e),
            Some((oid, _)) if oid == input.target_tree => digest_mismatch = true,
            _ => {}
        }
    }
    let accepted = |role: Role| policy.evidence.accept.contains(&role);

    let mut findings: Vec<Finding> = Vec::new();
    let mut checks: Vec<CheckStatus> = Vec::new();

    if digest_mismatch {
        findings.push(
            Finding::new("TREE_DIGEST_MISMATCH", Effect::Deny, "a receipt names this tree id but its contents hash differently; do not trust it or this repository's objects"),
        );
    }

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
            checks.push(CheckStatus { name: name.clone(), run: Vec::new(), required: *required, state: CheckState::Undefined });
            findings.push(
                Finding::new("CHECK_UNDEFINED", Effect::Wait, format!("the intent asks for the check {name:?}, which the policy does not define"))
                    .next("add it to .05/policy.toml, or remove it from the intent"),
            );
            continue;
        };
        let mine: Vec<&&Signed<_>> = evidence
            .iter()
            // The command must be the policy's own: a receipt merely *named* after the check is not enough.
            .filter(|e| e.statement.predicate.command.argv == def.run)
            .collect();
        let accepted_mine: Vec<_> = mine.iter().filter(|e| accepted(e.signer.role)).collect();
        // The most recent accepted receipt speaks for the check.
        let latest = accepted_mine.iter().max_by(|a, b| a.statement.predicate.created.cmp(&b.statement.predicate.created));
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
                    let everything = all_receipts.get_or_insert_with(|| classify(input.trust, &store::find_all(input.top)));
                    let earlier = everything.evidence.iter().any(|e| {
                        e.statement.predicate.command.argv == def.run
                            && accepted(e.signer.role)
                            && e.statement.tree_subject().is_some_and(|(oid, _)| oid != input.target_tree)
                    });
                    if earlier { CheckState::Stale } else { CheckState::Missing }
                }
            },
        };
        let prove = format!("use05 prove {name}");
        match &state {
            CheckState::Passed { .. } => {}
            CheckState::Failed { exit_code, .. } => findings.push(
                Finding::new("CHECK_FAILED", Effect::Deny, format!("the check {name:?} failed{}", exit_code.map(|c| format!(" (exit {c})")).unwrap_or_default())).next("fix it, then: ".to_string() + &prove),
            ),
            CheckState::TimedOut { .. } => findings.push(Finding::new("CHECK_FAILED", Effect::Deny, format!("the check {name:?} timed out")).next(prove)),
            CheckState::NotAuthoritative { by } => findings.push(
                Finding::new(
                    "EVIDENCE_NOT_ACCEPTED",
                    Effect::Wait,
                    format!("the check {name:?} was only proved by a {} key ({}); policy accepts {}", by.role.word(), by.name, policy.evidence.accept.iter().map(|r| r.word()).collect::<Vec<_>>().join(" or ")),
                )
                .next("run it where policy accepts it, for example in CI"),
            ),
            CheckState::Stale => findings.push(Finding::new("EVIDENCE_STALE", Effect::Wait, format!("the check {name:?} passed on an earlier tree, not this one; the code changed since")).next(prove)),
            CheckState::Missing => findings.push(Finding::new("CHECK_MISSING", Effect::Wait, format!("the check {name:?} has not been proved on this tree")).next(prove)),
            CheckState::Undefined => {}
        }
        checks.push(CheckStatus { name: name.clone(), run: def.run.clone(), required: *required, state });
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
    let mut rejected_by: Option<Signer> = None;
    let mut changed_intent = false;
    let everything = all_receipts.get_or_insert_with(|| classify(input.trust, &store::find_all(input.top)));
    let candidates = at_tree.approvals.iter().chain(intent_receipts.approvals.iter()).chain(everything.approvals.iter());
    let mut seen = Vec::new();
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
        let void = if p.policy_sha256 != policy_sha256 {
            Some("the policy changed since")
        } else if expired(&p.expires, input.now) {
            Some("expired")
        } else {
            None
        };
        approval_info.push(ApprovalInfo { scope: p.scope, vote: p.decision, by: a.signer.clone(), rationale: p.rationale.clone(), created: p.created.clone(), expires: p.expires.clone(), void });
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
        let valid = at_tree.bypasses.iter().find(|b| {
            b.statement.tree_subject().is_some_and(|(oid, d)| oid == input.target_tree && d == input.target_digest) && !expired(&b.statement.predicate.expires, input.now)
        });
        if valid.is_some() && path_rule_unbypassable {
            findings.push(Finding::new(
                "BYPASS_NOT_ALLOWED",
                Effect::Info,
                if absolute.is_empty() { "a person bypassed this tree, but policy allows no bypass of its path rules".to_string() } else { format!("a person bypassed this tree, but no bypass can clear {}: its lock is absolute", absolute.join(", ")) },
            ));
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
        changed: changes.iter().map(|c| ChangeInfo { status: c.status, path: c.path.clone() }).collect(),
        risk,
        risk_reasons,
        log: input.log.cloned(),
        approvals: approval_info,
        bypass,
        policy_sha256,
        unverified_receipts: at_tree.unverified,
        newer_receipts: at_tree.newer,
        foreign_receipts: at_tree.foreign,
    })
}

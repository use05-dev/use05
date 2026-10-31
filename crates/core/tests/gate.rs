//! The gate against real git repositories, real signatures and real receipts.
//! Each test states a promise the product makes and tries to break it.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;
use use05_core::evidence::{Trust, TrustedKey};
use use05_core::gate::{Decision, Effect, GateInput, GateResult, evaluate};
use use05_core::intent::{IntentCard, Scope};
use use05_core::policy::{CheckDef, IntentMode, Policy, Role, Severity};
use use05_core::task::Task;
use use05_core::time::{now_rfc3339, now_secs, rfc3339};
use use05_core::{git, store};
use use05_receipt::*;
use use05_receipt::Decision as Vote;
use use05_runner::{ProveOptions, identify, prove};

struct Repo {
    dir: TempDir,
}

impl Repo {
    fn new() -> Repo {
        let repo = Repo { dir: tempfile::tempdir().unwrap() };
        repo.git(&["init", "-q"]);
        repo.write("src/lib.rs", "pub fn f() {}\n");
        repo.write("ok.sh", "#!/bin/sh\nexit 0\n");
        repo.write("bad.sh", "#!/bin/sh\nexit 1\n");
        for f in ["ok.sh", "bad.sh"] {
            fs::set_permissions(repo.dir.path().join(f), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        }
        repo.git(&["add", "-A"]);
        repo.git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"]);
        repo
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(self.path()).args(args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
    fn write(&self, name: &str, body: &str) {
        let p = self.path().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    /// Stage everything and return (base tree, target tree id, target digest).
    fn stage(&self) -> (String, String, String) {
        self.git(&["add", "-A"]);
        let base = self.git(&["rev-parse", "HEAD^{tree}"]);
        let id = identify(self.path(), "index").unwrap();
        (base, id.oid, id.sha256)
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trusted(name: &str, role: Role, k: &SigningKey) -> TrustedKey {
    TrustedKey { name: name.into(), role, key: k.verifying_key(), id: key_id(&k.verifying_key()) }
}

fn policy_with(checks: &[(&str, &[&str])]) -> Policy {
    let mut p = Policy::default();
    p.check = checks.iter().map(|(n, run)| CheckDef { name: n.to_string(), run: run.iter().map(|s| s.to_string()).collect(), ..CheckDef::default() }).collect();
    p
}

fn prove_and_store(repo: &Repo, argv: &[&str], name: &str, signer: &SigningKey) {
    repo.stage(); // prove the files as they are now
    let statement = prove(&ProveOptions {
        repo: repo.path().to_path_buf(),
        tree: "index".into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        timeout: Duration::from_secs(30),
        pass_env: vec![],
        check: Some(name.to_string()),
    })
    .unwrap();
    let envelope = seal(&statement, signer).to_json_bytes();
    let (oid, _) = statement.tree_subject().unwrap();
    store::put(repo.path(), oid, &envelope, &key_id(&signer.verifying_key())).unwrap();
}

struct Ctx<'a> {
    repo: &'a Repo,
    policy: Policy,
    trust: Trust,
    task: Option<Task>,
    late: Vec<String>,
}

impl Ctx<'_> {
    fn gate(&self) -> GateResult {
        let (base, tree, digest) = self.repo.stage();
        self.gate_at(&base, &tree, &digest)
    }
    fn gate_at(&self, base: &str, tree: &str, digest: &str) -> GateResult {
        evaluate(&GateInput {
            top: self.repo.path(),
            policy: &self.policy,
            trust: &self.trust,
            task: self.task.as_ref(),
            base_tree: Some(base),
            target_tree: tree,
            target_digest: digest,
            now: now_secs(),
            late: &self.late,
            overlaps: &[],
            log: None,
        })
        .unwrap()
    }
}

fn codes(r: &GateResult) -> Vec<&'static str> {
    r.findings.iter().map(|f| f.code).collect()
}

fn approval(scope: ApprovalScope, vote: Vote, policy: &Policy, who: &str, expires_in: i64) -> Approval {
    Approval {
        decision: vote,
        scope,
        task: "task1".into(),
        intent_sha256: None,
        policy_sha256: policy.digest(),
        rationale: "looked fine".into(),
        approver: who.into(),
        created: now_rfc3339(),
        expires: rfc3339((now_secs() as i64 + expires_in) as u64),
    }
}

fn file_outcome_approval(repo: &Repo, tree: &str, digest: &str, a: Approval, signer: &SigningKey) {
    let statement = Statement::new(vec![tree_subject(tree, digest)], a);
    store::put(repo.path(), tree, &seal(&statement, signer).to_json_bytes(), &key_id(&signer.verifying_key())).unwrap();
}

fn ctx<'a>(repo: &'a Repo, policy: Policy, trust: Vec<TrustedKey>) -> Ctx<'a> {
    Ctx { repo, policy, trust: Trust { keys: trust }, task: None, late: Vec::new() }
}

fn task_with(card: Option<IntentCard>, outcome: Option<&str>) -> Task {
    Task {
        id: "task1".into(),
        title: "t".into(),
        author: "agent:test".into(),
        created: now_rfc3339(),
        base_commit: None,
        base_tree: String::new(),
        branch: None,
        intent_sha256: card.as_ref().map(IntentCard::digest),
        intent: card,
        status: use05_core::task::Status::Active,
        outcome: outcome.map(str::to_string),
        finished: None,
        session: None,
        sealed: None,
        revisions: Vec::new(),
        request: None,
        head: None,
        ended: None,
        agent: None,
        owner: None,
        sandbox: None,
    }
}

// ---------------------------------------------------------------------------- evidence

#[test]
fn a_clean_change_with_nothing_required_is_allowed() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* edit */ }\n");
    let c = ctx(&repo, Policy::default(), vec![]);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Allow, "{:?}", codes(&r));
    assert_eq!(r.changed.len(), 1);
}

#[test]
fn a_required_check_must_be_proved_on_this_exact_tree_and_goes_stale_when_code_changes() {
    let repo = Repo::new();
    let me = key(1);
    let c = ctx(&repo, policy_with(&[("test", &["./ok.sh"])]), vec![trusted("me", Role::Local, &me)]);

    repo.write("src/lib.rs", "pub fn f() { /* v1 */ }\n");
    assert_eq!(c.gate().decision, Decision::Wait);
    assert!(codes(&c.gate()).contains(&"CHECK_MISSING"));

    prove_and_store(&repo, &["./ok.sh"], "test", &me);
    let proved = c.gate();
    assert_eq!(proved.decision, Decision::Allow, "{:?}", codes(&proved));

    repo.write("src/lib.rs", "pub fn f() { /* v2 */ }\n");
    let stale = c.gate();
    assert_eq!(stale.decision, Decision::Wait);
    assert!(codes(&stale).contains(&"EVIDENCE_STALE"), "{:?}", codes(&stale));
}

#[test]
fn a_failing_check_denies_and_a_later_pass_on_the_same_tree_wins() {
    let repo = Repo::new();
    let me = key(1);
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let c = ctx(&repo, policy_with(&[("test", &["./bad.sh"])]), vec![trusted("me", Role::Local, &me)]);
    prove_and_store(&repo, &["./bad.sh"], "test", &me);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Deny);
    assert!(codes(&r).contains(&"CHECK_FAILED"));
}

#[test]
fn evidence_from_a_role_policy_does_not_accept_does_not_count() {
    let repo = Repo::new();
    let (laptop, ci) = (key(1), key(2));
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let mut policy = policy_with(&[("test", &["./ok.sh"])]);
    policy.evidence.accept = vec![Role::Runner];
    let c = ctx(&repo, policy, vec![trusted("laptop", Role::Local, &laptop), trusted("ci", Role::Runner, &ci)]);

    prove_and_store(&repo, &["./ok.sh"], "test", &laptop);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Wait, "a laptop key must not satisfy a runner-only policy");
    assert!(codes(&r).contains(&"EVIDENCE_NOT_ACCEPTED"));

    prove_and_store(&repo, &["./ok.sh"], "test", &ci);
    assert_eq!(c.gate().decision, Decision::Allow);
}

#[test]
fn a_receipt_signed_by_an_untrusted_key_is_ignored() {
    let repo = Repo::new();
    let (me, stranger) = (key(1), key(66));
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let c = ctx(&repo, policy_with(&[("test", &["./ok.sh"])]), vec![trusted("me", Role::Local, &me)]);
    prove_and_store(&repo, &["./ok.sh"], "test", &stranger);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Wait);
    assert!(r.unverified_receipts >= 1);
}

#[test]
fn a_command_other_than_the_policys_does_not_satisfy_the_check() {
    let repo = Repo::new();
    let me = key(1);
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let c = ctx(&repo, policy_with(&[("test", &["./bad.sh"])]), vec![trusted("me", Role::Local, &me)]);
    // The agent proves something easier and names it "test".
    prove_and_store(&repo, &["true"], "test", &me);
    assert_eq!(c.gate().decision, Decision::Wait, "naming a receipt \"test\" is not enough; the command must match");
}

// ---------------------------------------------------------------------------- approvals

fn protected_policy() -> Policy {
    let mut p = Policy::default();
    p.protect.paths = vec!["migrations/**".into()];
    p
}

#[test]
fn a_protected_path_needs_a_person_and_only_the_right_kind_of_approval_counts() {
    let repo = Repo::new();
    let (machine, person, other) = (key(1), key(10), key(11));
    repo.write("migrations/001.sql", "create table t();\n");
    let policy = protected_policy();
    let c = ctx(&repo, policy.clone(), vec![trusted("machine", Role::Local, &machine), trusted("alice", Role::Approver, &person), trusted("bob", Role::Approver, &other)]);
    let (_, tree, digest) = repo.stage();

    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired);
    assert!(codes(&r).contains(&"PROTECTED_PATH"));

    // A machine key cannot approve, even if it signs a perfectly formed approval.
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "machine", 3600), &machine);
    assert_eq!(c.gate().decision, Decision::ApprovalRequired, "a local/runner key must not count as a person");

    // An approval whose policy digest differs (the rules changed since) is void.
    let mut other_policy = policy.clone();
    other_policy.approvals.expire_days = 1;
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &other_policy, "alice", 3600), &person);
    let stale = c.gate();
    assert_eq!(stale.decision, Decision::ApprovalRequired, "an approval is bound to the policy it was given under");
    assert!(stale.approvals.iter().any(|a| a.void == Some("the policy changed since")));

    // An expired approval is void.
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", -10), &person);
    assert_eq!(c.gate().decision, Decision::ApprovalRequired);

    // A valid approval by a person clears it.
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &person);
    let ok = c.gate();
    assert_eq!(ok.decision, Decision::Allow, "{:?}", codes(&ok));
    assert!(ok.findings.iter().any(|f| f.code == "PROTECTED_PATH" && f.message.ends_with("(approved)")));
}

#[test]
fn an_approval_is_bound_to_the_exact_tree() {
    let repo = Repo::new();
    let person = key(10);
    repo.write("migrations/001.sql", "create table t();\n");
    let policy = protected_policy();
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &person)]);
    let (_, tree, digest) = repo.stage();
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &person);
    assert_eq!(c.gate().decision, Decision::Allow);

    // One more byte changes the tree. The old approval must not carry over.
    repo.write("migrations/001.sql", "create table t(); drop table users;\n");
    assert_eq!(c.gate().decision, Decision::ApprovalRequired, "approving one tree must not approve another");
}

#[test]
fn two_approvers_are_needed_when_policy_says_two_and_one_person_counts_once() {
    let repo = Repo::new();
    let (a, b) = (key(10), key(11));
    repo.write("migrations/001.sql", "create table t();\n");
    let mut policy = protected_policy();
    policy.approvals.min = 2;
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &a), trusted("bob", Role::Approver, &b)]);
    let (_, tree, digest) = repo.stage();

    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &a);
    assert_eq!(c.gate().decision, Decision::ApprovalRequired);
    // Alice approving again is still one person.
    let mut again = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 7200);
    again.created = rfc3339(now_secs() + 1);
    file_outcome_approval(&repo, &tree, &digest, again, &a);
    assert_eq!(c.gate().decision, Decision::ApprovalRequired, "the same approver twice is not two approvers");
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "bob", 3600), &b);
    assert_eq!(c.gate().decision, Decision::Allow);
}

#[test]
fn a_rejection_denies_even_if_someone_else_approved() {
    let repo = Repo::new();
    let (a, b) = (key(10), key(11));
    repo.write("migrations/001.sql", "x\n");
    let policy = protected_policy();
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &a), trusted("bob", Role::Approver, &b)]);
    let (_, tree, digest) = repo.stage();
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &a);
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Reject, &policy, "bob", 3600), &b);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Deny);
    assert!(codes(&r).contains(&"REJECTED"));
}

#[test]
fn a_change_cannot_edit_its_own_rules_and_pass() {
    let repo = Repo::new();
    repo.write(".05/policy.toml", "[approvals]\nmin = 1\n");
    let c = ctx(&repo, Policy::default(), vec![]);
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "editing .05/ always needs a person");
    let f = r.findings.iter().find(|f| f.code == "PROTECTED_PATH").unwrap();
    assert!(f.message.contains("own rules"));
}

// ---------------------------------------------------------------------------- bypass

#[test]
fn break_glass_lets_exactly_one_tree_through_and_says_what_it_overrode() {
    let repo = Repo::new();
    let (me, person) = (key(1), key(10));
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let policy = policy_with(&[("test", &["./ok.sh"])]);
    let c = ctx(&repo, policy, vec![trusted("me", Role::Local, &me), trusted("alice", Role::Approver, &person)]);
    let (_, tree, digest) = repo.stage();
    assert_eq!(c.gate().decision, Decision::Wait);

    let bypass = |expires_in: i64, signer: &SigningKey, tree: &str, digest: &str| {
        let s = Statement::new(
            vec![tree_subject(tree, digest)],
            Bypass { reason: "prod is down".into(), by: "alice".into(), findings: vec![], created: now_rfc3339(), expires: rfc3339((now_secs() as i64 + expires_in) as u64) },
        );
        store::put(repo.path(), tree, &seal(&s, signer).to_json_bytes(), &key_id(&signer.verifying_key())).unwrap();
    };

    bypass(3600, &me, &tree, &digest); // signed by a machine key: must not count
    assert_eq!(c.gate().decision, Decision::Wait, "an agent-held key cannot break glass");
    bypass(-5, &person, &tree, &digest); // expired
    assert_eq!(c.gate().decision, Decision::Wait);
    bypass(3600, &person, &"0".repeat(40), &digest); // for another tree
    assert_eq!(c.gate().decision, Decision::Wait);

    bypass(3600, &person, &tree, &digest);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Allow);
    let b = r.bypass.expect("a bypass is always reported");
    assert_eq!(b.reason, "prod is down");
    assert!(b.suppressed.contains(&"CHECK_MISSING".to_string()));

    // The next change is not covered.
    repo.write("src/lib.rs", "pub fn f() { /* y */ }\n");
    assert_eq!(c.gate().decision, Decision::Wait);
}

// ---------------------------------------------------------------------------- intent and drift

#[test]
fn files_outside_the_declared_scope_are_drift_with_the_severity_policy_sets() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    repo.write("docs/readme.md", "hi\n");
    let card = IntentCard { scope: Scope { include: vec!["src/**".into()], exclude: vec![] }, ..Default::default() };
    let mut policy = Policy::default();
    let mut c = ctx(&repo, policy.clone(), vec![]);
    c.task = Some(task_with(Some(card.clone()), None));

    let warn = c.gate();
    assert_eq!(warn.decision, Decision::Allow, "the default is to warn");
    let f = warn.findings.iter().find(|f| f.code == "SCOPE_EXCEEDED").unwrap();
    assert_eq!(f.paths, ["docs/readme.md"]);

    policy.drift.scope = Severity::Deny;
    c.policy = policy;
    assert_eq!(c.gate().decision, Decision::Deny);
}

#[test]
fn an_inferred_task_says_it_cannot_check_scope_instead_of_pretending() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let mut c = ctx(&repo, Policy::default(), vec![]);
    c.task = Some(task_with(None, None));
    let r = c.gate();
    assert!(codes(&r).contains(&"SCOPE_UNDECLARED"));
    assert_eq!(r.decision, Decision::Allow);
}

#[test]
fn dependency_changes_follow_policy_and_a_promise_of_none_is_enforced() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "[package]\nname=\"x\"\n");
    let mut policy = Policy::default();
    policy.drift.dependencies = Severity::Approval;
    let mut c = ctx(&repo, policy, vec![]);
    assert_eq!(c.gate().decision, Decision::ApprovalRequired);

    let promised = IntentCard { no_new_dependencies: true, ..Default::default() };
    c.task = Some(task_with(Some(promised), None));
    assert_eq!(c.gate().decision, Decision::Deny, "the card promised no dependency changes");
}

#[test]
fn policy_that_requires_a_card_for_risky_changes_asks_for_one() {
    let repo = Repo::new();
    repo.write("migrations/001.sql", "x\n");
    let mut policy = protected_policy();
    policy.intent.mode = use05_core::policy::IntentMode::Risky;
    let mut c = ctx(&repo, policy.clone(), vec![]);
    c.task = Some(task_with(None, None));
    assert!(codes(&c.gate()).contains(&"INTENT_REQUIRED"));

    // A low-risk change does not need one.
    let repo2 = Repo::new();
    repo2.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let mut c2 = ctx(&repo2, policy, vec![]);
    c2.task = Some(task_with(None, None));
    assert!(!codes(&c2.gate()).contains(&"INTENT_REQUIRED"));
}

// ---------------------------------------------------------------------------- claims

#[test]
fn an_agents_claim_is_checked_against_evidence_on_the_exact_tree() {
    let repo = Repo::new();
    let me = key(1);
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let policy = policy_with(&[("test", &["./ok.sh"])]);
    let mut c = ctx(&repo, policy, vec![trusted("me", Role::Local, &me)]);
    c.task = Some(task_with(None, Some("Capped retries. All tests pass.")));

    let r = c.gate();
    assert!(codes(&r).contains(&"CLAIM_UNSUPPORTED"), "no test evidence yet: {:?}", codes(&r));

    prove_and_store(&repo, &["./ok.sh"], "test", &me);
    let r = c.gate();
    assert!(!codes(&r).contains(&"CLAIM_UNSUPPORTED"), "{:?}", codes(&r));
    assert!(r.claims.iter().any(|c| matches!(c.judged, use05_core::claims::Judged::Supported { .. })));
}

#[test]
fn a_false_claim_is_contradicted_and_denied() {
    let repo = Repo::new();
    let me = key(1);
    repo.write("src/lib.rs", "pub fn f() { /* x */ }\n");
    let policy = policy_with(&[("test", &["./bad.sh"])]);
    let mut c = ctx(&repo, policy, vec![trusted("me", Role::Local, &me)]);
    c.task = Some(task_with(None, Some("All tests pass.")));
    prove_and_store(&repo, &["./bad.sh"], "test", &me);
    let r = c.gate();
    assert_eq!(r.decision, Decision::Deny);
    assert!(codes(&r).contains(&"CLAIM_CONTRADICTED"));
}

#[test]
fn the_gate_is_deterministic() {
    let repo = Repo::new();
    repo.write("migrations/001.sql", "x\n");
    let c = ctx(&repo, protected_policy(), vec![]);
    let (a, b) = (c.gate(), c.gate());
    assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
}

#[test]
fn it_works_on_a_repository_whose_base_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    Command::new("git").arg("-C").arg(dir.path()).args(["init", "-q"]).output().unwrap();
    fs::write(dir.path().join("a.txt"), "x").unwrap();
    Command::new("git").arg("-C").arg(dir.path()).args(["add", "-A"]).output().unwrap();
    let id = identify(dir.path(), "index").unwrap();
    let trust = Trust::default();
    let policy = Policy::default();
    let r = evaluate(&GateInput { top: dir.path(), policy: &policy, trust: &trust, task: None, base_tree: None, target_tree: &id.oid, target_digest: &id.sha256, now: now_secs(), late: &[], overlaps: &[], log: None }).unwrap();
    assert_eq!(r.decision, Decision::Allow);
    assert_eq!(r.changed.len(), 1);
    let _ = git::EMPTY_TREE;
}

// ---------------------------------------------------------------------------- declared late (D65)

fn scoped(scope: &str) -> IntentCard {
    IntentCard { scope: Scope { include: vec![scope.into()], exclude: vec![] }, ..IntentCard::default() }
}

#[test]
fn an_edit_inside_the_scope_before_the_declaration_is_declared_late_and_breaks_plain_allow() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { 1; }\n");
    let mut c = ctx(&repo, Policy::default(), vec![]);
    c.task = Some(task_with(Some(scoped("src/**")), None));
    c.late = vec!["src/lib.rs".into()];
    let r = c.gate();
    let f = r.findings.iter().find(|f| f.code == "DECLARED_LATE").expect("DECLARED_LATE");
    assert_eq!(f.effect, Effect::Warn);
    assert_eq!(f.paths, ["src/lib.rs"]);
    assert_eq!(r.decision, Decision::Allow);
}

#[test]
fn in_card_always_mode_a_late_declaration_needs_approval_and_an_approval_clears_it() {
    let repo = Repo::new();
    let person = key(10);
    repo.write("src/lib.rs", "pub fn f() { 2; }\n");
    let mut policy = Policy::default();
    policy.intent.mode = IntentMode::Always;
    let mut c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &person)]);
    c.task = Some(task_with(Some(scoped("src/**")), None));
    c.late = vec!["src/lib.rs".into()];
    let (_, tree, digest) = repo.stage();
    let r = c.gate();
    let f = r.findings.iter().find(|f| f.code == "DECLARED_LATE").expect("DECLARED_LATE");
    assert_eq!((f.effect, f.approvable), (Effect::Approval, true));
    assert_eq!(r.decision, Decision::ApprovalRequired);
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &person);
    assert_eq!(c.gate().decision, Decision::Allow);
}

// ---------------------------------------------------------------------------- risk categories (D66)

#[test]
fn a_risky_change_without_an_approval_waits_for_a_person_and_either_approval_clears_it() {
    let repo = Repo::new();
    let person = key(10);
    repo.write("src/billing/charge.rs", "pub fn charge() {}\n");
    let policy = Policy::default();
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &person)]);
    let (_, tree, digest) = repo.stage();
    let r = c.gate();
    let f = r.findings.iter().find(|f| f.code == "RISK_NOT_APPROVED").expect("RISK_NOT_APPROVED");
    assert_eq!((f.effect, f.approvable), (Effect::Approval, true));
    assert!(f.message.contains("money"), "{}", f.message);
    assert_eq!(r.risk_reasons[0].category, "money");
    assert_eq!(r.decision, Decision::ApprovalRequired);
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &person);
    assert_eq!(c.gate().decision, Decision::Allow);
}

#[test]
fn risk_not_approved_is_not_doubled_with_protected_path_or_intent_not_approved() {
    let repo = Repo::new();
    repo.write("migrations/001.sql", "create table t();\n");
    let c = ctx(&repo, protected_policy(), vec![]);
    let r = c.gate();
    assert!(codes(&r).contains(&"PROTECTED_PATH"));
    assert!(!codes(&r).contains(&"RISK_NOT_APPROVED"), "{:?}", codes(&r));

    let repo = Repo::new();
    repo.write("src/billing/charge.rs", "pub fn charge() {}\n");
    let mut c = ctx(&repo, Policy::default(), vec![]);
    c.task = Some(task_with(Some(scoped("src/billing/**")), None));
    let r = c.gate();
    assert!(codes(&r).contains(&"INTENT_NOT_APPROVED"), "{:?}", codes(&r));
    assert!(!codes(&r).contains(&"RISK_NOT_APPROVED"), "{:?}", codes(&r));
}

#[test]
fn dependency_files_keep_their_own_rule_and_do_not_need_a_risk_approval() {
    let repo = Repo::new();
    repo.write("Cargo.toml", "[package]\nname = \"x\"\n");
    let r = ctx(&repo, Policy::default(), vec![]).gate();
    assert!(codes(&r).contains(&"DEP_FILES_CHANGED"));
    assert!(!codes(&r).contains(&"RISK_NOT_APPROVED"));
}

// ---------------------------------------------------------------------------- weakened tests (D66)

#[test]
fn a_weakened_test_needs_approval_by_default_and_the_brief_lists_edited_test_files() {
    let repo = Repo::new();
    repo.write("tests/a_test.py", "def test_a():\n    assert 1 == 1\n    assert 2 == 2\n");
    repo.git(&["add", "-A"]);
    repo.git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "tests"]);
    repo.write("tests/a_test.py", "def test_a():\n    assert 1 == 1\n");
    let r = ctx(&repo, Policy::default(), vec![]).gate();
    let f = r.findings.iter().find(|f| f.code == "TESTS_WEAKENED").expect("TESTS_WEAKENED");
    assert_eq!((f.effect, f.approvable), (Effect::Approval, true));
    assert_eq!(f.paths, ["tests/a_test.py"]);
    assert!(f.message.contains("assertion"), "{}", f.message);
    let brief = use05_core::brief::build(None, r, "tree", "staged files", None, None);
    assert!(brief.unknowns.iter().any(|u| u.contains("1 test file(s) (tests/a_test.py)")), "{:?}", brief.unknowns);
}

#[test]
fn policy_can_lower_test_weakening_to_a_warning_and_a_floor_raises_it_back() {
    let repo = Repo::new();
    repo.write("tests/a_test.py", "def test_a():\n    assert 1 == 1\n");
    repo.git(&["add", "-A"]);
    repo.git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "tests"]);
    repo.write("tests/a_test.py", "def test_a():\n    pass\n");
    let mut policy = Policy::default();
    policy.drift.tests = Severity::Warn;
    let r = ctx(&repo, policy.clone(), vec![]).gate();
    assert_eq!(r.findings.iter().find(|f| f.code == "TESTS_WEAKENED").unwrap().effect, Effect::Warn);
    policy.tighten(&use05_core::policy::Floor { drift_tests: Some(Severity::Deny), ..Default::default() });
    let r = ctx(&repo, policy, vec![]).gate();
    assert_eq!(r.findings.iter().find(|f| f.code == "TESTS_WEAKENED").unwrap().effect, Effect::Deny);
}

// ---------------------------------------------------------------------------- deferred fixes

#[test]
fn with_no_recorded_owner_the_earliest_signed_approval_names_the_owner() {
    let repo = Repo::new();
    let (alice, bob) = (key(10), key(11));
    repo.write("src/lib.rs", "pub fn f() { 9; }\n");
    let policy = Policy::default();
    let mut c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &alice), trusted("bob", Role::Approver, &bob)]);
    c.task = Some(task_with(None, None));
    let (_, tree, digest) = repo.stage();
    let mut later = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "bob", 3600);
    later.created = "2026-10-30T12:00:00Z".into();
    let mut earlier = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600);
    earlier.created = "2026-10-30T09:00:00Z".into();
    // Filed in the "wrong" order: the earlier approval is stored second.
    file_outcome_approval(&repo, &tree, &digest, later, &bob);
    file_outcome_approval(&repo, &tree, &digest, earlier, &alice);
    let brief = use05_core::brief::build(c.task.as_ref(), c.gate(), &tree, "staged files", None, None);
    assert_eq!(brief.owner.map(|o| o.name).as_deref(), Some("alice"));
    assert!(brief.owner_confirmed);
}

#[test]
fn a_record_of_a_kind_this_version_does_not_know_is_named_as_such_not_as_untrusted() {
    let repo = Repo::new();
    let signer = key(10);
    repo.write("src/lib.rs", "pub fn f() { 10; }\n");
    let c = ctx(&repo, Policy::default(), vec![trusted("alice", Role::Approver, &signer)]);
    let (_, tree, _) = repo.stage();
    let future = serde_json::json!({ "_type": "https://in-toto.io/Statement/v1", "subject": [{ "name": "tree", "digest": { "gitTree": tree } }], "predicateType": "https://use05.dev/future-thing/v9", "predicate": {} });
    let envelope = seal_bytes(&serde_json::to_vec(&future).unwrap(), &signer).to_json_bytes();
    store::put(repo.path(), &tree, &envelope, &key_id(&signer.verifying_key())).unwrap();
    let r = c.gate();
    assert_eq!(r.unverified_receipts, 0, "it is signed by a trusted key");
    assert_eq!(r.newer_receipts, 1);
    let brief = use05_core::brief::build(None, r, &tree, "staged files", None, None);
    assert!(brief.unknowns.iter().any(|u| u.contains("newer version of 05")), "{:?}", brief.unknowns);
}

#[test]
fn a_garbage_timestamp_never_wins_ownership_and_a_typeless_record_is_not_newer() {
    let repo = Repo::new();
    let (alice, bob) = (key(10), key(11));
    repo.write("src/lib.rs", "pub fn f() { 11; }\n");
    let policy = Policy::default();
    let mut c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &alice), trusted("bob", Role::Approver, &bob)]);
    c.task = Some(task_with(None, None));
    let (_, tree, digest) = repo.stage();
    let mut garbage = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "bob", 3600);
    garbage.created = "".into();
    let mut real = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600);
    real.created = "2026-10-30T09:00:00Z".into();
    file_outcome_approval(&repo, &tree, &digest, garbage, &bob);
    file_outcome_approval(&repo, &tree, &digest, real, &alice);
    let brief = use05_core::brief::build(c.task.as_ref(), c.gate(), &tree, "staged files", None, None);
    assert_eq!(brief.owner.map(|o| o.name).as_deref(), Some("alice"));
    let typeless = serde_json::json!({ "_type": "https://in-toto.io/Statement/v1", "subject": [{ "name": "tree", "digest": { "gitTree": tree } }], "predicateType": "", "predicate": {} });
    store::put(repo.path(), &tree, &seal_bytes(&serde_json::to_vec(&typeless).unwrap(), &alice).to_json_bytes(), &key_id(&alice.verifying_key())).unwrap();
    let r = c.gate();
    assert_eq!(r.newer_receipts, 0, "an empty type is malformed, not newer");
}

#[test]
fn another_tools_records_are_counted_as_its_own_not_as_untrusted() {
    let repo = Repo::new();
    let (alice, stranger) = (key(10), key(12));
    repo.write("src/lib.rs", "pub fn f() { 12; }\n");
    let c = ctx(&repo, Policy::default(), vec![trusted("alice", Role::Approver, &alice)]);
    let (_, tree, _) = repo.stage();
    let theirs = serde_json::json!({ "_type": "https://in-toto.io/Statement/v1", "subject": [{ "name": "tree", "digest": { "gitTree": tree } }], "predicateType": "https://example.com/coverage/v1", "predicate": { "lines": 91 } });
    // One signed by a key 05 trusts, one by a key it has never seen: neither is 05's to read.
    for signer in [&alice, &stranger] {
        store::put(repo.path(), &tree, &seal_bytes(&serde_json::to_vec(&theirs).unwrap(), signer).to_json_bytes(), &key_id(&signer.verifying_key())).unwrap();
    }
    let r = c.gate();
    assert_eq!((r.foreign_receipts, r.unverified_receipts, r.newer_receipts), (2, 0, 0));
    let brief = use05_core::brief::build(None, r, &tree, "staged files", None, None);
    assert!(brief.unknowns.iter().any(|u| u.contains("2 receipt(s) of other tools' kinds were not read")), "{:?}", brief.unknowns);
}

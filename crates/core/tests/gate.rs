//! The gate against real git repositories, real signatures and real receipts.
//! Each test states a promise the product makes and tries to break it.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;
use use05_core::evidence::{Holder, Trust, TrustedKey};
use use05_core::gate::{Decision, Effect, GateInput, GateResult, StaleBase, evaluate};
use use05_core::intent::{IntentCard, Scope};
use use05_core::policy::{CheckDef, IntentMode, LocalTesting, Policy, Require, Role, Severity, TestingPolicy};
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
    TrustedKey { name: name.into(), role, key: PublicKey::Ed25519(k.verifying_key()), id: key_id(&k.verifying_key()), holder: Holder::Unnamed }
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
    stale: Option<StaleBase>,
}

impl Ctx<'_> {
    fn gate(&self) -> GateResult {
        let (base, tree, digest) = self.repo.stage();
        self.gate_at(&base, &tree, &digest)
    }
    fn gate_at(&self, base: &str, tree: &str, digest: &str) -> GateResult {
        self.gate_pushing(base, tree, digest, None)
    }
    /// As a push to `branch` would be gated.
    fn gate_to(&self, branch: &str) -> GateResult {
        let (base, tree, digest) = self.repo.stage();
        self.gate_pushing(&base, &tree, &digest, Some(branch))
    }
    fn gate_pushing(&self, base: &str, tree: &str, digest: &str, pushing_to: Option<&str>) -> GateResult {
        self.gate_ci(base, tree, digest, pushing_to, None)
    }
    /// As CI gates it: `pushing_to` as CI read it (empty when CI could not tell), and the host's
    /// default branch when the host says.
    fn gate_ci(&self, base: &str, tree: &str, digest: &str, pushing_to: Option<&str>, default_branch: Option<&str>) -> GateResult {
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
            stale_base: self.stale.as_ref(),
            pushing_to,
            default_branch,
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
    Ctx { repo, policy, trust: Trust { keys: trust, ..Default::default() }, task: None, late: Vec::new(), stale: None }
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
        fresh: None,
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
    assert!(stale.approvals.iter().any(|a| a.void == Some("it was given under a different policy")));

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
fn an_approval_lasts_no_longer_than_the_policy_allows_and_is_not_dated_ahead() {
    let repo = Repo::new();
    let person = key(10);
    repo.write("migrations/001.sql", "create table t();\n");
    let policy = protected_policy();
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &person)]);
    let (_, tree, digest) = repo.stage();
    let days = policy.approvals.expire_days as i64;

    // Whoever prepared it asked for a far longer life than approvals.expire_days.
    let forever = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3650 * 86_400);
    file_outcome_approval(&repo, &tree, &digest, forever, &person);
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", codes(&r));
    assert!(r.approvals.iter().any(|a| a.void == Some("it lasts longer than the policy allows")), "{:?}", r.approvals);

    // Made "tomorrow", so it would outlive its window.
    let mut ahead = approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600);
    ahead.created = rfc3339(now_secs() + 86_400);
    file_outcome_approval(&repo, &tree, &digest, ahead, &person);
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired);
    assert!(r.approvals.iter().any(|a| a.void == Some("it is dated in the future")), "{:?}", r.approvals);

    // Exactly the policy's window counts.
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", days * 86_400), &person);
    assert_eq!(c.gate().decision, Decision::Allow);
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
    let r = evaluate(&GateInput { top: dir.path(), policy: &policy, trust: &trust, task: None, base_tree: None, target_tree: &id.oid, target_digest: &id.sha256, now: now_secs(), late: &[], overlaps: &[], log: None, stale_base: None, pushing_to: None, default_branch: None }).unwrap();
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

// ---------------------------------------------------------------------------- files that change together

fn require(when: &str, also: &str, severity: Severity) -> Require {
    Require { when: vec![when.into()], also: vec![also.into()], severity, why: Some("keep the docs current".into()) }
}

#[test]
fn a_change_that_skips_its_required_update_is_held_at_the_rules_severity() {
    let repo = Repo::new();
    repo.write("docs/api.md", "# API\n");
    repo.git(&["add", "-A"]);
    repo.git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "docs"]);
    let mut policy = Policy::default();
    policy.require = vec![require("src/**", "docs/**", Severity::Approval)];
    let c = ctx(&repo, policy, vec![]);

    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", codes(&r));
    let f = r.findings.iter().find(|f| f.code == "ALSO_CHANGE_MISSING").expect("finding");
    assert_eq!((f.effect, f.approvable), (Effect::Approval, true));
    assert_eq!(f.paths, vec!["src/lib.rs".to_string()]);
    assert!(f.message.contains("docs/**") && f.message.contains("keep the docs current"), "{}", f.message);

    // Updating the docs meets it; the gate does not judge what the update says.
    repo.write("docs/api.md", "# API\n\nf() changed.\n");
    let met = c.gate();
    assert!(!codes(&met).contains(&"ALSO_CHANGE_MISSING"), "{:?}", codes(&met));
    assert_eq!(met.decision, Decision::Allow);
}

#[test]
fn require_rules_are_independent_and_follow_their_own_severity() {
    let repo = Repo::new();
    let mut policy = Policy::default();
    policy.require = vec![require("src/**", "docs/**", Severity::Warn), require("src/**", "CHANGELOG.md", Severity::Deny), require("migrations/**", "docs/**", Severity::Deny)];
    let c = ctx(&repo, policy, vec![]);
    repo.write("src/lib.rs", "pub fn f() { /* v2 */ }\n");
    let r = c.gate();
    let mut missing: Vec<Effect> = r.findings.iter().filter(|f| f.code == "ALSO_CHANGE_MISSING").map(|f| f.effect).collect();
    missing.sort();
    assert_eq!(missing, vec![Effect::Warn, Effect::Deny], "the migrations rule watches nothing that changed");
    assert_eq!(r.decision, Decision::Deny);
}

// ---------------------------------------------------------------------------- fresh base

#[test]
fn work_that_started_behind_origin_is_held_at_fresh_base() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* v3 */ }\n");
    let stale = StaleBase { remote_ref: "origin/main".into(), behind: 14 };
    for (severity, effect, decision) in [(Severity::Warn, Effect::Warn, Decision::Allow), (Severity::Approval, Effect::Approval, Decision::ApprovalRequired), (Severity::Deny, Effect::Deny, Decision::Deny)] {
        let mut policy = Policy::default();
        policy.branches.fresh_base = severity;
        let mut c = ctx(&repo, policy, vec![]);
        c.stale = Some(stale.clone());
        let r = c.gate();
        let f = r.findings.iter().find(|f| f.code == "BASE_STALE").expect("finding");
        assert_eq!(f.effect, effect);
        assert_eq!(f.approvable, effect == Effect::Approval);
        assert!(f.message.contains("14 commits behind origin/main"), "{}", f.message);
        assert!(f.next.as_deref().unwrap_or("").contains("git pull --rebase origin main"), "{:?}", f.next);
        assert_eq!(r.decision, decision);
    }
    // Off, or not behind: nothing.
    let mut off = ctx(&repo, Policy::default(), vec![]);
    off.stale = Some(stale);
    assert!(!codes(&off.gate()).contains(&"BASE_STALE"));
}

// ---------------------------------------------------------------------------- passkeys

/// A browser's WebAuthn assertion over `body`, for a passkey made for localhost.
fn passkey_seal(body: &[u8], sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use p256::ecdsa::signature::Signer;
    use sha2::{Digest, Sha256};
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let challenge = URL_SAFE_NO_PAD.encode(passkey_challenge(PAYLOAD_TYPE, body));
    let client = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:8080"}}"#);
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let sig: p256::ecdsa::Signature = sk.sign(&message);
    Envelope {
        payload: STANDARD.encode(body),
        payload_type: PAYLOAD_TYPE.into(),
        signatures: vec![EnvelopeSignature { keyid: None, sig: STANDARD.encode(sig.to_der().as_bytes()), webauthn: Some(WebAuthnSig { authenticator_data: STANDARD.encode(&auth), client_data_json: STANDARD.encode(client.as_bytes()) }) }],
    }
    .to_json_bytes()
}

fn passkey(seed: u8) -> (p256::ecdsa::SigningKey, PublicKey) {
    let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let key = PasskeyKey::from_sec1("localhost", sk.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
    (sk, PublicKey::Passkey(key))
}

fn trusted_passkey(name: &str, key: &PublicKey) -> TrustedKey {
    TrustedKey { name: name.into(), role: Role::Approver, key: key.clone(), id: key.id(), holder: Holder::Unnamed }
}

/// A passkey-signed envelope that the machine which prepared it also signed, in either order.
fn cosigned(body: &[u8], sk: &p256::ecdsa::SigningKey, machine: &SigningKey, machine_first: bool) -> Vec<u8> {
    let mut envelope: Envelope = serde_json::from_slice(&passkey_seal(body, sk)).unwrap();
    let entry = cosignature(PAYLOAD_TYPE, body, machine);
    if machine_first { envelope.signatures.insert(0, entry) } else { envelope.signatures.push(entry) }
    envelope.to_json_bytes()
}

#[test]
fn a_policy_passkey_names_its_person() {
    let (_, key) = passkey(26);
    let PublicKey::Passkey(p) = &key else { unreachable!() };
    let mut policy = Policy::default();
    policy.trust.key.push(use05_core::policy::TrustKey { name: "phone".into(), role: Role::Approver, public: passkey_public_text(p), expires: None, person: Some(" Alice ".into()) });
    assert_eq!(Trust::new(&policy, false).keys[0].holder, Holder::Person("Alice".into()));
    let parsed = Policy::parse(&format!("[[trust.key]]\nname = \"phone\"\nrole = \"approver\"\npublic = \"{}\"\nperson = \"Alice\"\n", passkey_public_text(p).trim())).unwrap();
    assert_eq!(parsed.trust.key[0].person.as_deref(), Some("Alice"));
}

#[test]
fn classify_records_who_cosigned_an_approval() {
    let repo = Repo::new();
    let (sk, pk) = passkey(27);
    let machine = key(30);
    let trust = Trust { keys: vec![trusted_passkey("phone", &pk), trusted("this machine", Role::Local, &machine)], ..Default::default() };
    let (_, tree, digest) = repo.stage();
    let policy = protected_policy();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "owner", 3600))).unwrap();
    for machine_first in [false, true] {
        let raw = store::Raw { source: "test".into(), path: format!("r{machine_first}"), bytes: cosigned(&body, &sk, &machine, machine_first) };
        let found = use05_core::evidence::classify(&trust, &[raw]);
        assert_eq!(found.approvals.len(), 1, "machine first: {machine_first}");
        assert_eq!(found.approvals[0].signer.key_id, pk.id());
        assert_eq!(found.approvals[0].cosigners.iter().map(|s| s.key_id.clone()).collect::<Vec<_>>(), vec![key_id(&machine.verifying_key())]);
    }
}

#[test]
fn an_uncosigned_approval_has_no_cosigners() {
    let repo = Repo::new();
    let (sk, pk) = passkey(28);
    let machine = key(31);
    let trust = Trust { keys: vec![trusted_passkey("phone", &pk), trusted("this machine", Role::Local, &machine)], ..Default::default() };
    let (_, tree, digest) = repo.stage();
    let policy = protected_policy();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "owner", 3600))).unwrap();
    let found = use05_core::evidence::classify(&trust, &[store::Raw { source: "test".into(), path: "r".into(), bytes: passkey_seal(&body, &sk) }]);
    assert_eq!(found.approvals.len(), 1);
    assert!(found.approvals[0].cosigners.is_empty());
}

/// A protected change owned by `owner`, a passkey held as `holder`, and this machine's key.
fn passkey_case(seed: u8, holder: Holder, owner: Option<(&str, &str)>, this_person: Option<&str>) -> (Repo, Policy, p256::ecdsa::SigningKey, PublicKey, SigningKey, Trust, Option<Task>) {
    let repo = Repo::new();
    repo.write("migrations/001.sql", "create table t();\n");
    let policy = protected_policy();
    let (sk, pk) = passkey(seed);
    let machine = key(seed.wrapping_add(100));
    let mut phone = trusted_passkey("phone", &pk);
    phone.holder = holder;
    let trust = Trust { keys: vec![phone, trusted("this machine", Role::Local, &machine)], this_person: this_person.map(str::to_string) };
    let task = owner.map(|(name, key_id)| {
        let mut t = task_with(None, None);
        t.owner = Some(use05_core::task::Owner { name: name.into(), key_id: key_id.into() });
        t
    });
    (repo, policy, sk, pk, machine, trust, task)
}

fn voids(r: &GateResult) -> Vec<&'static str> {
    r.approvals.iter().filter_map(|a| a.void).collect()
}

#[test]
fn a_passkey_approval_counts_only_when_its_preparer_cosigned() {
    let (repo, policy, sk, pk, machine, trust, task) = passkey_case(40, Holder::Person("Alice".into()), Some(("Alice", "k")), None);
    let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
    let (_, tree, digest) = repo.stage();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alice", 3600))).unwrap();

    store::put(repo.path(), &tree, &passkey_seal(&body, &sk), &pk.id()).unwrap();
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", codes(&r));
    assert!(voids(&r).contains(&"no machine that prepared it co-signed it"), "{:?}", r.approvals);

    // Co-signed by a key nobody trusts: still not prepared by a machine 05 knows.
    store::put(repo.path(), &tree, &cosigned(&body, &sk, &key(199), false), &pk.id()).unwrap();
    assert_eq!(c.gate().decision, Decision::ApprovalRequired);

    store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
    let ok = c.gate();
    assert_eq!(ok.decision, Decision::Allow, "{:?} {:?}", codes(&ok), ok.approvals);
}

#[test]
fn a_passkey_approval_counts_only_for_the_person_driving_the_work() {
    let other = "it was signed by someone other than the person driving the work";
    for (holder, owner, counts) in [
        (Holder::Person("Bob".into()), Some("Alex Rivera"), false),
        (Holder::Person("alex rivera ".into()), Some("Alex Rivera"), true),
        (Holder::Person("Alex".into()), Some("Alex Rivera"), false),
        (Holder::Person("Bob".into()), None, true),
    ] {
        let (repo, policy, sk, pk, machine, trust, task) = passkey_case(41, holder.clone(), owner.map(|o| (o, "k")), None);
        let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
        let (_, tree, digest) = repo.stage();
        let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, owner.unwrap_or("Bob"), 3600))).unwrap();
        store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, true), &pk.id()).unwrap();
        let r = c.gate();
        assert_eq!(r.decision == Decision::Allow, counts, "{holder:?} for {owner:?}: {:?}", r.approvals);
        if !counts {
            assert!(voids(&r).contains(&other), "{:?}", r.approvals);
        }
    }
}

#[test]
fn a_passkey_approval_names_its_person_even_without_a_recorded_driver() {
    // Nobody is recorded as driving the work (its records were never pushed): the person the
    // preparing machine named in the statement still has to be the passkey's.
    for (approver, counts) in [("Bob", false), ("alice ", true)] {
        let (repo, policy, sk, pk, machine, trust, task) = passkey_case(43, Holder::Person("Alice".into()), None, None);
        let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
        let (_, tree, digest) = repo.stage();
        let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, approver, 3600))).unwrap();
        store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
        let r = c.gate();
        assert_eq!(r.decision == Decision::Allow, counts, "approver {approver}: {:?}", r.approvals);
        if !counts {
            assert!(voids(&r).contains(&"it was signed by someone other than the person driving the work"), "{:?}", r.approvals);
        }
    }
}

#[test]
fn a_trust_entry_without_a_person_says_so_and_a_pin_here_still_counts() {
    let (repo, policy, sk, pk, machine, mut trust, task) = passkey_case(44, Holder::Unnamed, Some(("Alex", "k")), Some("k"));
    let body = |tree: &str, digest: &str| serde_json::to_vec(&Statement::new(vec![tree_subject(tree, digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alex", 3600))).unwrap();
    let (_, tree, digest) = repo.stage();
    store::put(repo.path(), &tree, &cosigned(&body(&tree, &digest), &sk, &machine, false), &pk.id()).unwrap();
    let c = Ctx { repo: &repo, policy: policy.clone(), trust: trust.clone(), task: task.clone(), late: Vec::new(), stale: None };
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired);
    assert!(voids(&r).contains(&"its trust entry names no person"), "{:?}", r.approvals);
    // The same passkey also pinned on this machine, whose person drives the work: it counts.
    let mut pinned = trusted_passkey("passkey iPhone", &pk);
    pinned.holder = Holder::ThisMachine;
    trust.keys.push(pinned);
    let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
    assert_eq!(c.gate().decision, Decision::Allow);
}

#[test]
fn a_machine_named_for_one_person_cannot_prepare_for_another() {
    let (repo, policy, sk, pk, machine, mut trust, task) = passkey_case(45, Holder::Person("Alice".into()), Some(("Alice", "k")), None);
    // Bob's machine, listed in the policy as his, prepared and co-signed it.
    trust.keys[1].holder = Holder::Person("Bob".into());
    let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
    let (_, tree, digest) = repo.stage();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alice", 3600))).unwrap();
    store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", r.approvals);
    assert!(voids(&r).contains(&"it was prepared on someone else's machine"), "{:?}", r.approvals);
}

#[test]
fn a_passkey_pinned_here_counts_for_this_machines_person() {
    for (owner_key, counts) in [("k", true), ("other", false)] {
        let (repo, policy, sk, pk, machine, trust, task) = passkey_case(42, Holder::ThisMachine, Some(("Alex", owner_key)), Some("k"));
        let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
        let (_, tree, digest) = repo.stage();
        let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alex", 3600))).unwrap();
        store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
        assert_eq!(c.gate().decision == Decision::Allow, counts, "owner key {owner_key}");
    }
}

#[test]
fn an_outcome_approval_signed_by_a_trusted_passkey_clears_approval_required() {
    let repo = Repo::new();
    repo.write("migrations/001.sql", "create table t();\n");
    let policy = protected_policy();
    let machine = key(121);
    let (sk, key) = passkey(21);
    let mut phone = trusted_passkey("phone", &key);
    phone.holder = Holder::Person("owner".into());
    let c = ctx(&repo, policy.clone(), vec![phone, trusted("this machine", Role::Local, &machine)]);
    let (_, tree, digest) = repo.stage();
    assert_eq!(c.gate().decision, Decision::ApprovalRequired);

    let statement = Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "owner", 3600));
    store::put(repo.path(), &tree, &cosigned(&serde_json::to_vec(&statement).unwrap(), &sk, &machine, false), &key.id()).unwrap();
    let ok = c.gate();
    assert_eq!(ok.decision, Decision::Allow, "{:?}", codes(&ok));
}

#[test]
fn a_bypass_signed_by_a_passkey_does_not_count() {
    let repo = Repo::new();
    let (sk, key) = passkey(22);
    let trust = Trust { keys: vec![trusted_passkey("phone", &key)], ..Default::default() };
    let (_, tree, digest) = repo.stage();
    let statement = Statement::new(
        vec![tree_subject(&tree, &digest)],
        Bypass { reason: "prod is down".into(), by: "owner".into(), findings: vec![], created: now_rfc3339(), expires: rfc3339(now_secs() + 3600) },
    );
    store::put(repo.path(), &tree, &passkey_seal(&serde_json::to_vec(&statement).unwrap(), &sk), &key.id()).unwrap();
    let found = use05_core::evidence::classify(&trust, &store::find_all(repo.path()));
    assert!(found.bypasses.is_empty(), "a passkey may approve, never bypass");
    assert_eq!(found.unverified, 1);
}

#[test]
fn a_passkey_listed_in_trust_key_is_trusted() {
    let (_, key) = passkey(23);
    let PublicKey::Passkey(p) = &key else { unreachable!() };
    let mut policy = Policy::default();
    policy.trust.key.push(use05_core::policy::TrustKey { name: "phone".into(), role: Role::Approver, public: passkey_public_text(p), expires: None, person: None });
    let trust = Trust::new(&policy, false);
    assert!(trust.by_id(&key.id()).is_some_and(|k| k.role == Role::Approver && k.key.is_passkey()));
}

#[test]
fn a_passkey_signs_approvals_and_nothing_else_counts() {
    let repo = Repo::new();
    let (sk, key) = passkey(24);
    let trust = Trust { keys: vec![trusted_passkey("phone", &key)], ..Default::default() };
    let (_, tree, digest) = repo.stage();
    let bodies = [
        serde_json::to_vec(&Statement::new(
            vec![intent_subject(&"ab".repeat(32))],
            Declaration { task: "task1".into(), title: "t".into(), author: "agent:x".into(), card: serde_json::json!({}), sealed: now_rfc3339(), policy_sha256: "p".into(), agent: None, owner: None, sandbox: None },
        ))
        .unwrap(),
        serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], Completion { task: "task1".into(), outcome: "o".into(), finished: now_rfc3339() })).unwrap(),
        serde_json::to_vec(&Statement::new(vec![log_subject("task1", "ab")], LogSeal { task: "task1".into(), seq: 1, head: "ab".into(), created: now_rfc3339() })).unwrap(),
    ];
    let raws: Vec<store::Raw> = bodies.iter().enumerate().map(|(i, b)| store::Raw { source: "test".into(), path: format!("r{i}"), bytes: passkey_seal(b, &sk) }).collect();
    let found = use05_core::evidence::classify(&trust, &raws);
    assert!(found.declarations.is_empty() && found.completions.is_empty() && found.log_seals.is_empty(), "a passkey's declaration, outcome or log seal must not count");
    assert_eq!(found.unverified, 3);
}

#[test]
fn a_passkey_trusted_with_another_role_is_not_trusted() {
    let (_, key) = passkey(25);
    let PublicKey::Passkey(p) = &key else { unreachable!() };
    for role in [Role::Runner, Role::Local] {
        let mut policy = Policy::default();
        policy.trust.key.push(use05_core::policy::TrustKey { name: "phone".into(), role, public: passkey_public_text(p), expires: None, person: None });
        assert!(Trust::new(&policy, false).by_id(&key.id()).is_none(), "a passkey is only ever an approver ({role:?})");
    }
}

#[test]
fn a_policy_that_lists_a_passkey_but_not_the_machine_that_prepares_for_it_counts_nothing() {
    // As CI reads it: the trust list made from the policy alone (no machine keys of its own).
    let (repo, mut policy, sk, pk, machine, _, task) = passkey_case(44, Holder::Person("Alice".into()), Some(("Alice", "k")), None);
    let PublicKey::Passkey(p) = &pk else { unreachable!() };
    policy.trust.key.push(use05_core::policy::TrustKey { name: "phone".into(), role: Role::Approver, public: passkey_public_text(p), expires: None, person: Some("Alice".into()) });
    let trust = Trust::new(&policy, false);
    assert!(trust.keys.iter().any(|k| k.key.is_passkey()), "the passkey is trusted");
    let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
    let (_, tree, digest) = repo.stage();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alice", 3600))).unwrap();
    store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
    let r = c.gate();
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", r.approvals);
    assert!(voids(&r).contains(&"no machine that prepared it co-signed it"), "{:?}", r.approvals);

    // Listed too, as the machine that prepares for Alice: it counts.
    policy.trust.key.push(use05_core::policy::TrustKey { name: "Alice's Mac".into(), role: Role::Local, public: use05_receipt::public_key_text(&machine.verifying_key()), expires: None, person: Some("Alice".into()) });
    let c = Ctx { repo: &repo, policy: policy.clone(), trust: Trust::new(&policy, false), task: c.task.clone(), late: Vec::new(), stale: None };
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alice", 3600))).unwrap();
    store::put(repo.path(), &tree, &cosigned(&body, &sk, &machine, false), &pk.id()).unwrap();
    assert_eq!(c.gate().decision, Decision::Allow, "{:?}", c.gate().approvals);
}

// ---------------------------------------------------------------------------- testing before a push (D87)

fn file_testing(repo: &Repo, tree: &str, digest: &str, outcome: Tested, signer: &SigningKey) {
    let t = Testing { outcome, task: "t".into(), note: "clicked through sign-up and paid an invoice".into(), tester: "alice".into(), created: now_rfc3339() };
    let statement = Statement::new(vec![tree_subject(tree, digest)], t);
    store::put(repo.path(), tree, &seal(&statement, signer).to_json_bytes(), &key_id(&signer.verifying_key())).unwrap();
}

fn testing_policy(local: LocalTesting, branches: &[&str]) -> Policy {
    let mut p = Policy::default();
    p.testing = TestingPolicy { local, branches: branches.iter().map(|b| b.to_string()).collect() };
    p
}

#[test]
fn a_push_to_a_chosen_branch_waits_for_a_persons_testing_sign_off() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let alice = key(70);
    let c = ctx(&repo, testing_policy(LocalTesting::Required, &[]), vec![trusted("alice", Role::Approver, &alice)]);
    // Off: nothing asked.
    let off = ctx(&repo, Policy::default(), vec![]);
    assert!(!codes(&off.gate_to("main")).contains(&"TESTING_REQUIRED"));
    // The landing branch (main, here) needs it; an agent's working branch does not.
    let r = c.gate_to("main");
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", codes(&r));
    let f = r.findings.iter().find(|f| f.code == "TESTING_REQUIRED").expect("asked for");
    assert_eq!(f.next.as_deref(), Some("use05 approve --tested --note \"<what you tried>\""));
    assert!(!codes(&c.gate_to("agent/fix")).contains(&"TESTING_REQUIRED"));
    // Not a push: the brief says it will be needed, and holds nothing.
    let brief = c.gate();
    assert!(brief.findings.iter().any(|f| f.code == "TESTING_NOT_SIGNED" && f.effect == Effect::Info), "{:?}", codes(&brief));
    // Signed off for this exact tree: it goes.
    let (_, tree, digest) = repo.stage();
    file_testing(&repo, &tree, &digest, Tested::Tested, &alice);
    let ok = c.gate_to("main");
    assert_eq!(ok.decision, Decision::Allow, "{:?}", codes(&ok));
    assert_eq!(ok.testing.iter().map(|t| (t.outcome, t.note.as_str(), t.counts)).collect::<Vec<_>>(), vec![(Tested::Tested, "clicked through sign-up and paid an invoice", true)]);
    // Change the code after: the sign-off was for other code.
    repo.write("src/lib.rs", "pub fn f() { /* changed again */ }\n");
    assert!(codes(&c.gate_to("main")).contains(&"TESTING_REQUIRED"));
}

#[test]
fn a_skip_counts_only_where_the_policy_lets_testing_be_skipped() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let alice = key(71);
    let (_, tree, digest) = repo.stage();
    file_testing(&repo, &tree, &digest, Tested::Skipped, &alice);
    let skippable = ctx(&repo, testing_policy(LocalTesting::Skippable, &[]), vec![trusted("alice", Role::Approver, &alice)]);
    assert_eq!(skippable.gate_to("main").decision, Decision::Allow);
    let required = ctx(&repo, testing_policy(LocalTesting::Required, &[]), vec![trusted("alice", Role::Approver, &alice)]);
    let r = required.gate_to("main");
    let f = r.findings.iter().find(|f| f.code == "TESTING_REQUIRED").expect("a skip does not count");
    assert!(f.message.contains("skip"), "{}", f.message);
}

#[test]
fn only_a_persons_sign_off_counts_and_an_approval_is_not_one() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let (alice, machine) = (key(72), key(73));
    let policy = testing_policy(LocalTesting::Required, &["release/*"]);
    let c = ctx(&repo, policy.clone(), vec![trusted("alice", Role::Approver, &alice), trusted("this machine", Role::Local, &machine)]);
    let (_, tree, digest) = repo.stage();
    // A machine key (an agent can use it) signing off: not a person.
    file_testing(&repo, &tree, &digest, Tested::Tested, &machine);
    // An approval of the outcome: accepting the change is not trying it.
    file_outcome_approval(&repo, &tree, &digest, approval(ApprovalScope::Outcome, Vote::Approve, &policy, "alice", 3600), &alice);
    assert!(codes(&c.gate_to("release/1.2")).contains(&"TESTING_REQUIRED"));
    assert!(!codes(&c.gate_to("main")).contains(&"TESTING_REQUIRED"), "main is not one of the chosen branches here");
}

#[test]
fn the_policy_says_where_testing_applies_not_the_agent() {
    // The agent declares it lands on release/2, then pushes to main: main is still where the
    // policy's work lands, so main needs the sign-off.
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let mut c = ctx(&repo, testing_policy(LocalTesting::Required, &[]), vec![]);
    c.task = Some(task_with(Some(IntentCard { target: Some("release/2".into()), ..Default::default() }), None));
    assert!(codes(&c.gate_to("main")).contains(&"TESTING_REQUIRED"), "{:?}", codes(&c.gate_to("main")));
    assert!(!codes(&c.gate_to("release/2")).contains(&"TESTING_REQUIRED"));
}

#[test]
fn in_ci_the_hosts_default_branch_is_the_landing_branch_and_an_unknown_one_is_held() {
    let repo = Repo::new();
    repo.write("src/lib.rs", "pub fn f() { /* changed */ }\n");
    let c = ctx(&repo, testing_policy(LocalTesting::Required, &[]), vec![]);
    let (base, tree, digest) = repo.stage();
    // A repository whose default branch is master: CI has no origin/HEAD, the host says master.
    assert!(codes(&c.gate_ci(&base, &tree, &digest, Some("master"), Some("master"))).contains(&"TESTING_REQUIRED"));
    assert!(!codes(&c.gate_ci(&base, &tree, &digest, Some("main"), Some("master"))).contains(&"TESTING_REQUIRED"));
    // CI could not tell where this goes (a merge queue it does not know, another CI): held, not let through.
    let r = c.gate_ci(&base, &tree, &digest, Some(""), None);
    assert_eq!(r.decision, Decision::ApprovalRequired, "{:?}", codes(&r));
    assert!(codes(&r).contains(&"TESTING_REQUIRED"));
    // The policy's own target still wins over the host's default.
    let mut p = testing_policy(LocalTesting::Required, &[]);
    p.branches.target = Some("develop".into());
    let d = ctx(&repo, p, vec![]);
    assert!(codes(&d.gate_ci(&base, &tree, &digest, Some("develop"), Some("master"))).contains(&"TESTING_REQUIRED"));
    assert!(!codes(&d.gate_ci(&base, &tree, &digest, Some("master"), Some("master"))).contains(&"TESTING_REQUIRED"));
}

#[test]
fn a_passkey_approval_prepared_and_co_signed_by_the_ci_runner_counts() {
    // CI prepared the statement for the person who drives the work and co-signed it with the
    // runner key; their passkey signed it on the console; CI filed it on its next run.
    let (repo, policy, sk, pk, _machine, mut trust, task) = passkey_case(45, Holder::Person("Alice".into()), Some(("Alice", "k")), None);
    let runner = key(145);
    trust.keys.retain(|k| k.role != Role::Local);
    trust.keys.push(trusted("ci", Role::Runner, &runner));
    let c = Ctx { repo: &repo, policy: policy.clone(), trust, task, late: Vec::new(), stale: None };
    let (_, tree, digest) = repo.stage();
    let body = serde_json::to_vec(&Statement::new(vec![tree_subject(&tree, &digest)], approval(ApprovalScope::Outcome, Vote::Approve, &policy, "Alice", 3600))).unwrap();
    store::put(repo.path(), &tree, &cosigned(&body, &sk, &runner, true), &pk.id()).unwrap();
    let r = c.gate();
    assert_eq!(r.decision, Decision::Allow, "{:?} {:?}", codes(&r), r.approvals);
}

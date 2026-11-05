//! `use05 promote <env>`: move a commit from one environment into the next when the rules the
//! target's own branch holds allow it (D77, D93). `--check` evaluates every rule and changes
//! nothing; `use05 brief --promote <env>` is the one page. Without `--check` it makes the merge or
//! fast-forward in a temporary worktree, pushes it, and files the signed promotion record; then it
//! confirms the deploy, as `deploy.rs` does for `--confirm` and `--rollback`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use use05_core::evidence::{Trust, classify};
use use05_core::gate::{Decision, Effect, Finding};
use use05_core::policy::{Environment, POLICY_PATH, Policy, Target};
use use05_core::promote::{self, BypassSeen, DeploymentSeen, Moving, PromoteInput, PromoteResult, SignOffSeen, short};
use use05_core::{fresh, git, store};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

/// Set only by the CI gate (`ci_env.rs`), which judges a push to an environment as of before it,
/// on refs it set itself: then nothing here fetches, so origin's newer copies cannot replace them.
static OFFLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn set_offline() {
    OFFLINE.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn offline() -> bool {
    OFFLINE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Everything gathered for one promotion, and what the rules make of it: into an environment, or
/// (`Prepared<Destination>`, see `destination.rs`) to a destination.
pub struct Prepared<T = Environment> {
    pub result: PromoteResult,
    /// Where the rules were read: `origin/prod`, or `this checkout`.
    pub rules_from: String,
    /// The refs the heads were read from: `origin/uat`, `prod`.
    pub source_ref: String,
    pub target_ref: Option<String>,
    /// The commits that would move, oldest first, with their subjects.
    pub moving: Vec<Moving>,
    /// Lines added and removed per file that would change.
    pub numstat: HashMap<String, (u64, u64)>,
    /// What a person should know about how this was read (a fetch that failed, say).
    pub notes: Vec<String>,
    /// The sign-off's questions and the statements to confirm, for the page.
    pub questions: Vec<String>,
    pub confirm: Vec<String>,
    pub org: Option<String>,
    /// The policy counts records this machine signs, so the record-based rules are its own claim.
    pub accepts_local: bool,
    /// The rules that judged it (the target branch's policy, with any organisation floor), and
    /// the target and the environment it comes from as they name them. A destination's source is
    /// a branch: the environment it is, else one named by the branch alone.
    pub policy: Policy,
    pub env: T,
    pub source: Environment,
    /// The repository's top folder.
    pub top: PathBuf,
    /// For a back-merge: the tree git's clean merge of the two heads gives, which the merge commit
    /// holds. `None` for a promotion, or when the two do not merge cleanly.
    pub merged_tree: Option<String>,
}

fn finding(code: &'static str, message: String) -> Finding {
    Finding { code, effect: Effect::Info, message, paths: Vec::new(), next: None, approvable: false }
}

fn names(policy: &Policy) -> String {
    policy.environment.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
}

/// The ref a branch is read from: origin's copy if there is one, else the local branch.
pub(crate) fn branch_ref(top: &Path, branch: &str) -> Option<String> {
    [format!("refs/remotes/origin/{branch}"), format!("refs/heads/{branch}")].into_iter().find(|r| git::resolve_commit(top, r).is_some())
}

/// `refs/remotes/origin/uat` as a person reads it: `origin/uat`.
pub(crate) fn ref_label(r: &str) -> String {
    r.strip_prefix("refs/remotes/").or_else(|| r.strip_prefix("refs/heads/")).unwrap_or(r).to_string()
}

/// When this repository last fetched anything, as RFC 3339: the time of its `FETCH_HEAD`.
fn last_fetched(top: &Path) -> Option<String> {
    let path = git::text(top, &["rev-parse", "--git-path", "FETCH_HEAD"]).ok()?;
    let path = top.join(path.trim());
    let at = std::fs::metadata(path).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(use05_core::time::rfc3339(at.as_secs()))
}

/// Fetch these branches and everyone's receipts from origin, never asking for a password and
/// giving up after a few seconds each. Never fails, and never quietly: when origin cannot be
/// reached, or a branch origin has could not be fetched, a note says what it is judged on instead.
pub(crate) fn fetch(top: &Path, branches: &[&str], notes: &mut Vec<String>) {
    if offline() {
        return;
    }
    if git::text(top, &["remote", "get-url", "origin"]).is_err() {
        notes.push("This repository has no origin; judged on its own branches.".to_string());
        return;
    }
    let when = last_fetched(top).map(|t| format!(", last fetched {t}")).unwrap_or_default();
    let mut failed: Vec<(&str, String)> = Vec::new();
    for b in branches {
        if let Err(e) = fresh::fetch(top, "origin", b, fresh::FETCH_TIMEOUT) {
            failed.push((b, e));
        }
    }
    let spec = format!("+refs/heads/{0}/*:refs/remotes/origin/{0}/*", store::BRANCH_DIR);
    match fresh::quiet_git(top, &["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", &spec], fresh::FETCH_TIMEOUT) {
        Err(e) => notes.push(format!("Could not reach origin ({e}): judged on what this machine last fetched{when}.")),
        // Origin answered. A branch it was seen to have before but that did not come now is said;
        // one it never had is no failure: promoting creates it.
        Ok(()) => {
            for (b, e) in failed.iter().filter(|(b, _)| git::resolve_commit(top, &format!("refs/remotes/origin/{b}")).is_some()) {
                notes.push(format!("Could not fetch {b} from origin ({e}): judged on what this machine last fetched of it{when}."));
            }
        }
    }
}

/// The rules an environment is judged by, read as a promotion into it reads them (D77): the policy
/// committed on its own branch (origin's copy if there is one), else the one on the branch it is
/// promoted from, else this checkout's; with any organisation floor. Its branch, the branch below
/// it and everyone's receipts are fetched from origin first.
pub struct Rules {
    pub top: PathBuf,
    pub policy: Policy,
    pub env: Environment,
    /// Where it is promoted from, by those rules. `None` for the lowest rung, which work lands on.
    pub source: Option<Environment>,
    /// Where the rules were read: `prod's policy (origin/prod)`.
    pub rules_from: String,
    /// What reading them found (`RULES_FROM_SOURCE`).
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    /// The ref the environment's branch was read from, and the policy committed there.
    pub target_ref: Option<String>,
    pub target_policy: Option<Policy>,
    pub org: Option<String>,
}

/// The policy committed at the head of `branch` (origin's copy if there is one), and where.
pub(crate) fn policy_on(top: &Path, branch: &str) -> use05_core::Result<Option<(Policy, String)>> {
    branch_ref(top, branch).map(|r| Policy::load_at(top, &r).map(|p| p.map(|p| (p, ref_label(&r))))).transpose().map(Option::flatten)
}

/// Read the rules for the environment `name`; see [`Rules`]. Fetches, and changes nothing else.
pub fn rules_for(repo: &Path, name: &str) -> Result<Rules, Report> {
    let fail = |e| Report::from_core("promote", e);
    let here = Ctx::open_for_commit(repo, None).map_err(fail)?;
    let top: PathBuf = here.top().to_path_buf();
    let Some(env) = here.policy.environment_named(name) else {
        let (message, next) = if here.policy.environment.is_empty() {
            ("this repository names no environments".to_string(), format!("name them in {POLICY_PATH} ([[environment]]), or run: use05 policy --edit"))
        } else {
            (format!("there is no environment {name:?} here; the environments are {}", names(&here.policy)), format!("use05 promote <{}>", names(&here.policy).replace(", ", "|")))
        };
        return Err(Report::error("promote", "UNKNOWN_ENVIRONMENT", message, Some(next), 6));
    };
    let below = here.policy.source_of(env).cloned();
    let mut notes = Vec::new();
    let fetched: Vec<String> = below.iter().map(|s| s.branch.clone()).chain([env.branch.clone()]).collect();
    fetch(&top, &fetched.iter().map(String::as_str).collect::<Vec<_>>(), &mut notes);

    // The rules come from the target's own branch (D77): what is there now judges what comes in.
    let target_ref = branch_ref(&top, &env.branch);
    let target_policy = match &target_ref {
        Some(r) => Policy::load_at(&top, r).map_err(fail)?,
        None => None,
    };
    let mut findings = Vec::new();
    let from_target = target_policy.as_ref().is_some_and(|p| p.environment_named(name).is_some());
    let (repo_policy, rules_from) = match target_policy.clone().filter(|_| from_target) {
        Some(p) => (p, format!("{name}'s policy ({})", ref_label(target_ref.as_deref().unwrap_or_default()))),
        None => {
            let on_source = match &below {
                Some(source) => policy_on(&top, &source.branch).map_err(fail)?.filter(|(p, _)| p.environment_named(name).is_some()).map(|(p, at)| (p, format!("{}'s policy ({at})", source.name))),
                None => None,
            };
            let (p, from) = on_source.unwrap_or_else(|| (here.repo_policy.clone(), "this checkout's policy".to_string()));
            let had = if target_ref.is_some() { format!("{}'s branch has no policy that names {name}", env.branch) } else { format!("{} does not exist yet", env.branch) };
            let mut f = finding("RULES_FROM_SOURCE", format!("{had}, so the rules come from {from}"));
            // The target has rules, just none for this environment: worth reading, not only noting.
            if target_policy.is_some() {
                f.effect = Effect::Warn;
            }
            findings.push(f);
            (p, from)
        }
    };
    let mut policy = repo_policy;
    if let Some((_, floor)) = use05_core::org::load().map_err(fail)? {
        policy.tighten(&floor);
    }
    policy.check_effective().map_err(fail)?;
    let env: Environment = policy.environment_named(name).cloned().expect("the judging policy names it");
    let source = policy.source_of(&env).cloned();
    // The judging policy may promote from another environment than this checkout's said.
    if let Some(s) = source.as_ref().filter(|s| !fetched.contains(&s.branch)) {
        fetch(&top, &[&s.branch], &mut notes);
        notes.dedup();
    }
    Ok(Rules { top, policy, env, source, rules_from, findings, notes, target_ref, target_policy, org: here.org.clone() })
}

/// Gather what promoting into `name` would move and judge it. Reads git and the receipts and
/// fetches from origin; changes nothing else.
pub fn prepare(repo: &Path, name: &str) -> Result<Prepared, Report> {
    prepare_expecting(repo, name, None)
}

/// As [`prepare`], judged against the source head an earlier evaluation saw: if the source moved
/// since, the promotion is refused (`PROMOTE_NOT_EVALUATED_HEAD`).
pub fn prepare_expecting(repo: &Path, name: &str, expected: Option<&str>) -> Result<Prepared, Report> {
    prepare_from(rules_for(repo, name)?, expected)
}

/// As [`prepare_expecting`], from rules already read.
fn prepare_from(rules: Rules, expected: Option<&str>) -> Result<Prepared, Report> {
    let fail = |e| Report::from_core("promote", e);
    let Rules { top, policy, env, source, rules_from, mut findings, mut notes, target_ref, target_policy, org } = rules;
    let name = env.name.clone();
    let Some(source) = source else {
        return Err(Report::error("promote", "NOTHING_PROMOTES_HERE", format!("{name} is the lowest environment: work lands on {} with use05 land, and nothing is promoted into it", env.branch), Some("use05 land".into()), 6));
    };
    let Some(source_ref) = branch_ref(&top, &source.branch) else {
        return Err(Report::error("promote", "SOURCE_NOT_FOUND", format!("there is no branch {} ({}) here or on origin", source.branch, source.name), Some(format!("push {} first, or check [[environment]] in {POLICY_PATH}", source.branch)), 6));
    };
    let source_head = git::resolve_commit(&top, &source_ref).expect("resolved above");
    let target_head = target_ref.as_deref().and_then(|r| git::resolve_commit(&top, r));
    if target_head.is_none() {
        findings.push(finding("PROMOTE_CREATES_BRANCH", format!("{} does not exist yet: promoting creates it at {}'s head, and there is no rollback point", env.branch, source.name)));
    }
    // Commits on this machine's branch that origin does not have are not part of it.
    let local = format!("refs/heads/{}", source.branch);
    if source_ref != local {
        if let Some(mine) = git::resolve_commit(&top, &local).filter(|c| *c != source_head) {
            let ahead = git::count_commits(&top, &source_head, &mine);
            if ahead > 0 {
                notes.push(format!("Your {} has {ahead} commit{} that {} lacks; only what is on origin is promoted.", source.branch, if ahead == 1 { "" } else { "s" }, ref_label(&source_ref)));
            }
        }
    }

    let moving = promote::commits(&top, &source_head, target_head.as_deref()).map_err(fail)?;
    let target_commits = match &target_head {
        Some(t) => promote::commits(&top, t, Some(&source_head)).map_err(fail)?,
        None => Vec::new(),
    };
    let ahead = promote::target_ahead(&top, &target_commits, env.how());
    let source_tree = git::resolve_tree(&top, &source_head).map_err(fail)?;
    let target_tree = target_head.as_deref().map(|t| git::resolve_tree(&top, t)).transpose().map_err(fail)?;
    let changed: Vec<String> = git::changed(&top, target_tree.as_deref(), &source_tree).map_err(fail)?.into_iter().map(|c| c.path).collect();
    let numstat = git::numstat(&top, target_tree.as_deref(), &source_tree).map_err(fail)?;

    // The source head's checks, read exactly as the gate reads a tree's.
    let trust = Trust::new(&policy, true);
    let digest = crate::ctx::tree_digest(&top, &source_tree).map_err(fail)?;
    let (checks, check_findings) = use05_core::gate::checks_at(&top, &policy, &trust, &source_tree, &digest, &changed, &format!(" --tree {}", short(&source_head)));
    // What the checks say is the source_checks rule's; a receipt that does not match the tree's
    // content is a finding of its own, denied whatever that rule's setting.
    findings.extend(check_findings.into_iter().filter(|f| f.code == "TREE_DIGEST_MISMATCH"));
    let found = classify(&trust, &store::find_all(&top));
    let now = use05_core::time::now_secs();
    let accept = &policy.evidence.accept;
    let deployments = deployments_of(&found, accept, &source.name, &source_head);
    let (signoffs, bypasses) = signed_for(&found, &trust, &policy, &env, &source.name, &source_head, now);
    let untasked = promote::untasked(&top, &moving, &found, accept);
    // A hotfix that landed on the target is why it is ahead, and says what merges it back.
    let hotfixes = promote::hotfixes_among(&found, accept, &target_commits.iter().map(|c| c.id.clone()).collect::<Vec<_>>());
    // The policy file moves with the promotion: what it would then hold is weighed against what
    // the target holds now, whenever the target has a policy.
    let loosened = match (&target_policy, policy_on(&top, &source.branch).map_err(fail)?) {
        (Some(before), Some((after, _))) if *before != after => use05_policy_edit::guard::loosens(before, &after),
        _ => Vec::new(),
    };
    let input = PromoteInput {
        policy: &policy,
        target: &env,
        source: &source.name,
        source_deployed: true,
        source_head: source_head.clone(),
        target_head,
        expected_source: expected.map(str::to_string),
        delta: moving.iter().map(|c| c.id.clone()).collect(),
        target_only: ahead,
        changed,
        checks,
        deployments,
        untasked,
        signoffs,
        bypasses,
        loosened,
        agent: use05_core::inbox::agent_session().is_some(),
        now,
        notes: findings,
        direction: use05_receipt::Direction::Up,
        task: None,
        hotfixes,
    };
    let result = promote::evaluate(&input);
    Ok(Prepared {
        result,
        rules_from,
        source_ref: ref_label(&source_ref),
        target_ref: target_ref.as_deref().map(ref_label),
        moving,
        numstat,
        notes,
        questions: env.sign_off.as_ref().map(|s| s.questions.clone()).unwrap_or_default(),
        confirm: env.confirm.iter().map(|c| c.text.clone()).collect(),
        org,
        accepts_local: accept.contains(&use05_core::policy::Role::Local),
        policy,
        env,
        source,
        top,
        merged_tree: None,
    })
}

/// The deployment records of `env` running `head`, oldest first. A machine's record counts only
/// from a key of a kind the policy takes evidence from (`accept`): with `["runner"]`, only CI's.
pub(crate) fn deployments_of(found: &use05_core::evidence::Found, accept: &[use05_core::policy::Role], env: &str, head: &str) -> Vec<DeploymentSeen> {
    let mut deployments: Vec<_> = found
        .deployments
        .iter()
        .filter(|d| accept.contains(&d.signer.role))
        .filter(|d| d.statement.predicate.env == env && d.statement.predicate.commit == head && d.statement.commit_subject() == Some(head))
        .collect();
    deployments.sort_by(|a, b| a.statement.predicate.created.cmp(&b.statement.predicate.created));
    // A record that says confirmed with no probe says more than it can know: not confirmed.
    deployments
        .into_iter()
        .map(|d| {
            let p = &d.statement.predicate;
            DeploymentSeen { confirmed: p.confirmed && !p.probes.is_empty(), created: p.created.clone(), by: d.signer.name.clone(), probes: p.probes.len() }
        })
        .collect()
}

/// The sign-offs and the bypasses filed for this exact move, each once and with whether it
/// counts: into `env`, from the environment `source`, of the commit `head`.
pub(crate) fn signed_for(found: &use05_core::evidence::Found, trust: &Trust, policy: &Policy, env: &dyn Target, source: &str, head: &str, now: u64) -> (Vec<SignOffSeen>, Vec<BypassSeen>) {
    let mut seen = Vec::new();
    let signoffs: Vec<SignOffSeen> = found
        .signoffs
        .iter()
        .filter(|s| {
            let p = &s.statement.predicate;
            p.env == env.name() && p.from == source && p.source_commit == head && s.statement.commit_subject() == Some(head)
        })
        .filter(|s| {
            let new = !seen.contains(&s.path);
            seen.push(s.path.clone());
            new
        })
        .map(|s| {
            let p = &s.statement.predicate;
            let own = trust.is_this_machines(&s.signer.key_id);
            let void = promote::signoff_void(p, trust.person_of(&s.signer.key_id).as_deref(), own, policy, env, now)
                .or_else(|| use05_core::gate::passkey_void_of(&s.signer, &s.cosigners, &p.signer_person, trust, None).map(str::to_string));
            SignOffSeen { person: p.signer_person.clone(), decision: p.decision, text: p.text.clone(), confirmations: p.confirmations.clone(), path: s.path.clone(), void }
        })
        .collect();
    // A person's bypass of one rule of this exact promotion.
    let mut seen = Vec::new();
    let bypasses: Vec<BypassSeen> = found
        .bypasses
        .iter()
        .filter(|b| {
            let p = &b.statement.predicate;
            p.env.as_deref() == Some(env.name()) && p.from.as_deref() == Some(source) && p.rule.is_some() && b.statement.commit_subject() == Some(head)
        })
        .filter(|b| {
            let new = !seen.contains(&b.path);
            seen.push(b.path.clone());
            new
        })
        .map(|b| {
            let p = &b.statement.predicate;
            let person = trust.person_of(&b.signer.key_id).unwrap_or_else(|| p.by.clone());
            BypassSeen { rule: p.rule.clone().unwrap_or_default(), person, reason: p.reason.clone(), path: b.path.clone(), void: promote::bypass_void(p, policy, env, now) }
        })
        .collect();
    (signoffs, bypasses)
}

/// The facts as `--json` gives them: the decision, the findings and each rule's result.
pub fn details<T>(p: &Prepared<T>) -> serde_json::Value {
    let r = &p.result;
    json!({
        "env": r.target_env,
        "from": r.source_env,
        "direction": r.direction,
        "decision": r.decision.word(),
        "source_head": r.source_head,
        "target_head": r.target_head,
        "source_ref": p.source_ref,
        "target_ref": p.target_ref,
        "how": r.how,
        "rollback_point": r.rollback_point,
        "delta": r.delta,
        "changed": r.changed,
        "rules": r.rules,
        "findings": r.findings,
        "checks": r.checks,
        "signoffs": r.signoffs,
        "bypasses": r.bypasses,
        "signers": r.signers,
        "agent_allowed": r.agent_allowed,
        "rules_from": p.rules_from,
        "policy_sha256": r.policy_sha256,
        "notes": p.notes,
    })
}

/// What a decision means for a promotion, in a few words.
pub fn verdict(r: &PromoteResult) -> (&'static str, Tone) {
    if r.delta.is_empty() && r.decision == Decision::Allow {
        return ("nothing to promote", Tone::Good);
    }
    match r.decision {
        Decision::Allow => ("allowed", Tone::Good),
        Decision::ApprovalRequired => ("needs a person's sign-off", Tone::Warn),
        Decision::Wait => ("waiting for evidence", Tone::Info),
        Decision::Deny => ("denied", Tone::Bad),
    }
}

/// How strong this answer is, for a check.
pub fn strength<T: Target>(p: &Prepared<T>) -> String {
    format!("Checked only: nothing was moved or pushed. {}", how_strong(&p.env, p.accepts_local))
}

/// How strong a promotion's judgement is here, and whose records it rests on.
pub(crate) fn how_strong(target: &dyn Target, accepts_local: bool) -> String {
    let records = if accepts_local {
        " Deployment, finish and promotion records this machine signs count, so source_confirmed, soak and untasked rest on its own word; with [evidence] accept = [\"runner\"] only CI's records count."
    } else {
        " Only CI's deployment, finish and promotion records count."
    };
    let name = target.name();
    if target.is_destination() {
        return format!("Here this is advisory: only this command and the pre-push hook judge what reaches {name}, and nothing stops a push to it by hand; protect its branch where it is hosted.{records}");
    }
    format!("Here this is advisory; the CI gate on {name}'s branch is the strong control.{records}")
}

/// The next step: the first thing that holds it back, else the promotion itself.
pub fn next_step(r: &PromoteResult) -> Option<String> {
    match r.findings.iter().find(|f| f.effect >= Effect::Wait) {
        Some(f) => f.next.clone(),
        None if r.delta.is_empty() => None,
        None if r.direction == use05_receipt::Direction::Back => Some(format!("use05 promote {} --back", r.target_env)),
        None => Some(format!("use05 promote {}", r.target_env)),
    }
}

pub fn summary<T>(p: &Prepared<T>) -> String {
    let r = &p.result;
    let (added, removed) = p.numstat.values().fold((0, 0), |(a, d), (x, y)| (a + x, d + y));
    let commits = r.delta.len();
    let files = r.changed.len();
    format!("{commits} commit{} · {files} file{} · +{added} −{removed}", if commits == 1 { "" } else { "s" }, if files == 1 { "" } else { "s" })
}

/// `use05 promote <env> --check`: evaluate every rule, change nothing.
pub fn run_check(repo: &Path, name: &str) -> Report {
    match prepare(repo, name) {
        Ok(p) => page(&p, "PROMOTE_CHECKED", "", &strength(&p)),
        Err(r) => r,
    }
}

/// The judgement as a report: what moves, each rule, the findings, how strong it is.
pub(crate) fn page<T: Target>(p: &Prepared<T>, code: &'static str, said: &str, strength: &str) -> Report {
    let r = &p.result;
    let (word, tone) = verdict(r);
    let onto = match (&r.target_head, &p.target_ref) {
        (Some(t), Some(at)) => format!("onto {} ({at})", short(t)),
        _ => "creating it".to_string(),
    };
    let mut rows = vec![("moves".to_string(), format!("{} · {} {} ({}) {onto}", summary(p), r.how, short(&r.source_head), p.source_ref))];
    for rule in &r.rules {
        let outcome = promote::outcome_word(rule.outcome);
        let severity = format!("{:?}", rule.severity).to_lowercase();
        rows.push((rule.rule.clone(), format!("{outcome} ({severity}): {}", rule.detail)));
    }
    rows.push(("rules".into(), format!("from {}", p.rules_from)));
    // A destination is never rolled back by 05: a fix is promoted to it.
    if !p.env.is_destination() {
        rows.push(("rollback".into(), r.rollback_point.as_deref().map_or_else(|| "none: the branch is created".to_string(), |c| short(c).to_string())));
    }
    let mut notes = p.notes.clone();
    for f in &r.findings {
        let effect = format!("{:?}", f.effect).to_lowercase();
        notes.push(format!("{effect} {}: {}", f.code, f.message));
    }
    notes.push(strength.to_string());
    Report {
        command: "promote",
        outcome: r.decision.word(),
        code,
        tone,
        headline: format!("{} → {}{}: {word}{said}", r.source_env, r.target_env, if r.direction == use05_receipt::Direction::Back { " (merging back)" } else { "" }),
        rows,
        notes,
        next: next_step(r),
        excerpt: vec![],
        details: details(p),
        exit: r.decision.exit_code(),
    }
}

/// `use05 promote <env>`: judge it, and when the rules allow, make the merge or fast-forward away
/// from the person's checkout, push it, and file the signed record (D93); then, unless `wait` is
/// false (`--no-wait`), confirm the deploy and handle a failure as the policy says. `interactive`:
/// a person at a terminal, with no `--json`.
pub fn run(repo: &Path, name: &str, wait: bool, interactive: bool) -> Report {
    let p = match prepare(repo, name) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(held) = held(&p) {
        return held;
    }
    let r = &p.result;
    let top = p.top.clone();
    // Where the policy keeps this environment for people, positive proof of one: a terminal, no
    // agent, and their key on the record. Elsewhere an agent or CI may promote, and the record's
    // signer says who did.
    let person = !r.agent_allowed;
    if person {
        if let Err(refused) = crate::cmd::approve::person_here("promote", interactive, &format!("promoting into {name}")) {
            return refused;
        }
    }
    if git::text(&top, &["remote", "get-url", "origin"]).is_err() {
        return Report::error("promote", "NO_REMOTE", format!("this repository has no origin to push {} to", p.env.branch), Some("git remote add origin <url>".into()), 6);
    }

    // The move, away from the person's checkout. Nothing is pushed and no branch moves yet.
    let result_commit = match make_move(&p) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let runner = crate::cmd::deploy::runner_key();
    let by = crate::cmd::deploy::by_whom(&top, &p.policy, person, runner.is_some());
    let statement = promote::record(r, &result_commit, &by, use05_core::time::now_rfc3339());

    // A person sees what moves, then their key signs the record before anything is pushed. It is
    // stored only once the push went through.
    let mut signatures = Vec::new();
    if person {
        eprintln!("You are about to promote {} from {} into {}: {}, by {}.", short(&r.source_head), r.source_env, r.target_env, summary(&p), r.how);
        eprintln!("  {} on origin moves {}; the record is signed and filed once the push goes through.", p.env.branch, r.target_head.as_deref().map_or_else(|| format!("to {}, created", short(&result_commit)), |t| format!("from {} to {}", short(t), short(&result_commit))));
        for f in r.findings.iter().filter(|f| f.effect >= Effect::Warn) {
            eprintln!("  - {}: {}", f.code, f.message);
        }
        match crate::cmd::approve::sign_as_person(&statement, &format!("promote {} into {name}", short(&r.source_head)), false, "promote") {
            Ok((envelope, _)) => signatures = envelope.signatures,
            Err(refused) => return refused,
        }
    }

    // Judged once more just before the push, against the commit that was evaluated and shown.
    let again = match prepare_expecting(repo, name, Some(&r.source_head)) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(held) = held(&again) {
        return held;
    }
    if again.result.target_head != r.target_head {
        return Report::error("promote", "PROMOTE_TARGET_MOVED", format!("{} moved on origin while this ran; nothing was pushed", p.env.branch), Some(format!("use05 promote {name}")), 4);
    }

    if let Err(line) = push_target(&top, &p.env.branch, &result_commit) {
        let mut refused = Report::error("promote", "PROMOTE_PUSH_FAILED", format!("the push of {} to origin was refused: {line}", p.env.branch), Some(format!("fix what refused it, then: use05 promote {name}")), 4);
        let at = r.target_head.as_deref().map_or_else(|| "still does not exist".to_string(), |t| format!("is where it was ({})", short(t)));
        refused.notes = vec![format!("Nothing moved: origin's {} {at}, no branch here was moved, and no promotion record was written.", p.env.branch)];
        refused.details = json!({ "env": r.target_env, "from": r.source_env, "source_head": r.source_head, "target_head": r.target_head, "pushed": false, "git": line });
        return refused;
    }

    let mut notes = Vec::new();
    notes.extend(follow_local(&top, &p.env.branch, &result_commit));
    let filed = file_record(&top, &statement, &statement.predicate.source_commit, signatures, runner.as_ref(), "The push went through, but");
    let branch = filed.branch.clone();
    notes.extend(filed.notes);
    notes.extend(push_receipts(&top));
    if !filed.on_origin {
        notes.push(format!("CI holds {}'s branch until this promotion's record is on origin.", r.target_env));
    }
    if result_commit == r.source_head {
        notes.push("A fast-forward makes no commit of its own, so the promotion's trailers are only in its record.".into());
    }
    for f in r.findings.iter().filter(|f| f.effect >= Effect::Warn) {
        notes.push(format!("{} {}: {}", format!("{:?}", f.effect).to_lowercase(), f.code, f.message));
    }
    notes.push(format!("Here this is advisory: it is the judgement CI makes, but nothing stops a person or an agent who pushes {}'s branch by hand. The CI gate on {}'s branch is the strong control.", r.target_env, r.target_env));
    // The deploy: confirmed now, or left to `--confirm`.
    let deploy = if wait {
        Some(crate::cmd::deploy::confirm_deploy(&top, &p.policy, &p.env, &result_commit, &by, runner.as_ref(), Ok(person), true))
    } else {
        notes.push(format!("The deploy is not confirmed yet: once {name} has deployed {}, run use05 promote {name} --confirm (CI can).", short(&result_commit)));
        None
    };
    let rules = r.rules.iter().map(|x| format!("{} {}", x.rule, promote::outcome_word(x.outcome))).collect::<Vec<_>>().join(" · ");
    let mut rows = vec![
        ("moved".to_string(), format!("{} · {} {} ({})", summary(&p), r.how, short(&r.source_head), p.source_ref)),
        ("pushed".to_string(), format!("{} → origin, now at {}", p.env.branch, short(&result_commit))),
        ("rules".to_string(), rules),
        ("rollback".to_string(), r.rollback_point.as_deref().map_or_else(|| "none: the branch was created".to_string(), |c| short(c).to_string())),
        ("by".to_string(), by.clone()),
    ];
    if let Some(b) = &branch {
        rows.push(("record".to_string(), format!("on {b}")));
    }
    if let Some(d) = &deploy {
        rows.extend(d.rows());
        notes.splice(0..0, d.notes.clone());
    }
    let above = p.policy.environment.iter().find(|e| p.policy.source_of(e).is_some_and(|s| s.name == r.target_env)).map(|e| e.name.clone());
    // Pushed, but with no record on origin: not a clean success, and the next step says how to
    // put it there. A deploy that was not confirmed is said first.
    let failed = deploy.as_ref().filter(|d| d.failed);
    let (code, tone, headline, next) = if let Some(d) = failed {
        ("DEPLOY_NOT_CONFIRMED", Tone::Bad, format!("Promoted {} → {}: {} ({}), but the deploy was not confirmed{}", r.source_env, r.target_env, short(&r.source_head), r.how, d.done()), d.next.clone())
    } else if filed.on_origin {
        ("PROMOTED", Tone::Good, format!("Promoted {} → {}: {} ({})", r.source_env, r.target_env, short(&r.source_head), r.how), above.map(|e| format!("use05 promote {e} --check")))
    } else {
        let next = match &branch {
            Some(b) => format!("git push origin {b}"),
            None => "fix this machine's key (use05 doctor); until a record is on origin, CI holds the branch".to_string(),
        };
        ("PROMOTED_WITHOUT_RECORD", Tone::Warn, format!("Promoted {} → {}: {} ({}), but its record is not on origin", r.source_env, r.target_env, short(&r.source_head), r.how), Some(next))
    };
    Report {
        command: "promote",
        outcome: "promoted",
        code,
        tone,
        headline,
        rows,
        notes,
        next,
        excerpt: vec![],
        details: json!({
            "env": r.target_env,
            "from": r.source_env,
            "source_commit": r.source_head,
            "result_commit": result_commit,
            "target_before": r.target_head,
            "how": r.how,
            "pushed": true,
            "record_branch": branch,
            "record_on_origin": filed.on_origin,
            "by": by,
            "rules": r.rules,
            "findings": r.findings,
            "deploy": deploy.as_ref().map(crate::cmd::deploy::Deploy::details),
        }),
        exit: if failed.is_some() { 2 } else { 0 },
    }
}

/// What stops a promotion before anything moves: nothing to promote, or a decision that is not
/// allow (its exit code is the decision's, as for `--check`).
pub(crate) fn held<T: Target>(p: &Prepared<T>) -> Option<Report> {
    let r = &p.result;
    if r.decision == Decision::Allow && r.delta.is_empty() {
        let back = r.direction == use05_receipt::Direction::Back;
        let mut report = page(p, if back { "NOTHING_TO_MERGE_BACK" } else { "NOTHING_TO_PROMOTE" }, "", "Nothing was moved or pushed.");
        report.headline = if back {
            format!("{} → {}: nothing to merge back; {} already has everything {} has", r.source_env, r.target_env, r.target_env, r.source_env)
        } else {
            format!("{} → {}: nothing to promote; {} already has {}", r.source_env, r.target_env, r.target_env, short(&r.source_head))
        };
        report.next = None;
        return Some(report);
    }
    if r.decision == Decision::Allow {
        return None;
    }
    let code = r.findings.iter().find(|f| f.effect >= Effect::Wait).map_or("PROMOTE_HELD", |f| f.code);
    Some(page(p, code, "; nothing moved", &format!("Nothing was moved or pushed. {}", how_strong(&p.env, p.accepts_local))))
}

/// The pre-push hook's judgement of a push to an environment's branch that is promoted into:
/// the promotion's rules, as `--check` judges them, and the pushed commit must be exactly the
/// move they judged: the source's head (a fast-forward), or a merge whose first parent is the
/// target's head on origin, whose second is the source's head, and whose tree is their merge
/// with nothing added. A hand push of anything else is held. The record is not asked for here:
/// it is written once the push went through, and CI asks for it.
pub fn judge_push(repo: &Path, name: &str, pushed: &str) -> Result<use05_core::gate::GateResult, Report> {
    let rules = rules_for(repo, name)?;
    // A revert 05 makes, back to where the newest promotion found the branch, is its own move.
    if let Some(revert) = crate::cmd::deploy::judge_revert(&rules, pushed) {
        return Ok(revert);
    }
    // A hotfix task's landing on this environment, and a back-merge of the one above into it, are
    // moves of their own (D93), judged by their own rules.
    if let Some(landing) = crate::cmd::hotfix::judge_hotfix_push(&rules, pushed) {
        return landing;
    }
    if let Some(kind) = crate::cmd::hotfix::back_merge(&rules, pushed) {
        return crate::cmd::hotfix::judge_back_push(rules, pushed, &kind);
    }
    let p = prepare_from(rules, None)?;
    let r = &p.result;
    let pushed = git::resolve_commit(&p.top, pushed).unwrap_or_else(|| pushed.to_string());
    let mut findings = r.findings.clone();
    let mut decision = r.decision;
    // Pushing what is there already moves nothing.
    if r.target_head.as_deref() == Some(pushed.as_str()) {
        return Ok(use05_core::gate::GateResult::of_findings(Decision::Allow, Vec::new(), r.policy_sha256.clone()));
    }
    if pushed != r.source_head && !is_evaluated_merge(&p.top, &pushed, r) {
        let merge = r.target_head.as_deref().map(|t| format!(", or a merge of it onto {}'s head {}", r.target_env, short(t))).unwrap_or_default();
        findings.insert(
            0,
            Finding {
                code: "PROMOTE_NOT_EVALUATED_MOVE",
                effect: Effect::Deny,
                message: format!("what is pushed to {} ({}) is not the promotion 05 judged: {}'s head {}{merge}", p.env.branch, short(&pushed), r.source_env, short(&r.source_head)),
                paths: Vec::new(),
                next: Some(format!("promote it with 05: use05 promote {name}")),
                approvable: false,
            },
        );
        decision = Decision::Deny;
    }
    // Kept for people: the push must come from one, at a terminal and with no agent session, as
    // `use05 promote` asks. (Under an agent the rules already said no.)
    if !r.agent_allowed && !crate::cmd::gate::person_at_terminal() && !findings.iter().any(|f| f.code == "AGENT_MAY_NOT_PROMOTE") {
        findings.insert(
            0,
            Finding {
                code: "AGENT_MAY_NOT_PROMOTE",
                effect: Effect::Deny,
                message: format!("{name} is kept for people, and nothing here shows a person pushing: there is no terminal"),
                paths: Vec::new(),
                next: Some(format!("a person pushes it at their terminal, or runs: use05 promote {name}")),
                approvable: false,
            },
        );
        decision = Decision::Deny;
    }
    Ok(use05_core::gate::GateResult::of_findings(decision, findings, r.policy_sha256.clone()))
}

/// A merge commit exactly as `use05 promote` makes one: first parent the target's head, second
/// the source's head, and the tree git's merge of the two gives (or, where this git cannot work
/// that out, the source's own tree).
fn is_evaluated_merge(top: &Path, pushed: &str, r: &PromoteResult) -> bool {
    let Some(target) = r.target_head.as_deref() else { return false };
    let parents = git::text(top, &["rev-list", "--parents", "-n", "1", pushed]).unwrap_or_default();
    if parents.split_whitespace().skip(1).collect::<Vec<_>>() != [target, r.source_head.as_str()] {
        return false;
    }
    let merged = git::text(top, &["merge-tree", "--write-tree", target, &r.source_head]).ok().and_then(|t| t.lines().next().map(str::to_string)).or_else(|| git::resolve_tree(top, &r.source_head).ok());
    merged.is_some() && git::resolve_tree(top, pushed).ok() == merged
}

/// Who promoted, as the record says: the person whose key signs it, the agent, CI, or this
/// machine's user.
pub(crate) fn actor(top: &Path, person: Option<String>, runner: bool) -> String {
    if let Some(p) = person {
        return p;
    }
    if let Some((kind, _)) = use05_core::inbox::agent_session() {
        return format!("{kind} (an agent)");
    }
    if runner {
        return "CI".into();
    }
    git::text(top, &["config", "user.name"]).ok().filter(|n| !n.is_empty()).map_or_else(|| "this machine".to_string(), |n| format!("{n} (this machine)"))
}

/// A temporary worktree, removed when dropped.
struct Scratch {
    top: PathBuf,
    dir: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = git::run(&self.top, &["worktree", "remove", "--force", &self.dir.display().to_string()]);
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = git::run(&self.top, &["worktree", "prune"]);
    }
}

/// Make the move away from the person's checkout. A fast-forward, or a branch to create, is the
/// source head itself; a merge is a merge commit on the target's head, with the summary in its
/// trailers, made in a temporary worktree that is removed afterwards. Returns the commit the
/// target will point at. Nothing is pushed and no branch moves.
pub(crate) fn make_move(p: &Prepared) -> Result<String, Report> {
    let r = &p.result;
    let (Some(target), "merge") = (r.target_head.as_deref(), r.how) else {
        return Ok(r.source_head.clone());
    };
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("use05-promote-{}-{nanos}", std::process::id()));
    let could_not = |what: &str, e: use05_core::Error| Report::error("promote", "PROMOTE_MOVE_FAILED", format!("could not {what}: {}", e.message), None, 4);
    git::run(&p.top, &["worktree", "add", "--quiet", "--detach", &dir.display().to_string(), target]).map_err(|e| could_not("make a temporary worktree", e))?;
    let scratch = Scratch { top: p.top.clone(), dir: dir.clone() };
    // A merge commit needs a name; CI often has none set.
    let named = |key: &str| git::text(&dir, &["config", key]).ok().is_some_and(|v| !v.is_empty());
    let mut args: Vec<&str> = Vec::new();
    if !named("user.name") || !named("user.email") {
        args.extend(["-c", "user.name=use05", "-c", "user.email=use05@localhost"]);
    }
    let message = promote::merge_message(r);
    args.extend(["merge", "--quiet", "--no-ff", "--no-edit", "-m", &message, &r.source_head]);
    if let Err(e) = git::run(&dir, &args) {
        // A conflict leaves unmerged paths; anything else (a hook, a lock, a full disk) is not
        // the change's fault.
        let conflicted = git::text(&dir, &["diff", "--name-only", "--diff-filter=U"]).is_ok_and(|t| !t.is_empty());
        let _ = git::run(&dir, &["merge", "--abort"]);
        drop(scratch);
        if !conflicted {
            return Err(could_not("make the merge commit", e));
        }
        return Err(Report::error("promote", "PROMOTE_MERGE_CONFLICT", format!("{} does not merge cleanly into {}: {}", short(&r.source_head), p.env.branch, e.message), Some(format!("merge {} into {} by hand, then promote again", p.source.branch, p.env.branch)), 2));
    }
    let commit = git::text(&dir, &["rev-parse", "HEAD"]).map_err(|e| could_not("read the merge commit", e))?;
    if git::text(&dir, &["rev-parse", "HEAD^2"]).ok().as_deref() != Some(r.source_head.as_str()) {
        return Err(Report::error("promote", "PROMOTE_MOVE_FAILED", format!("the merge onto {} did not take {}; nothing was pushed", p.env.branch, short(&r.source_head)), None, 4));
    }
    drop(scratch);
    Ok(commit)
}

/// After the push, this machine's receipts branches follow the record, so the sign-offs and
/// bypasses the promotion went with are on origin for CI to read. Never before: a refused push
/// leaves origin as it was. Best effort: a failure here is not the promotion's.
pub(crate) fn push_receipts(top: &Path) -> Vec<String> {
    let mut ids: Vec<String> = use05_core::keys::approver_ids();
    ids.extend(use05_core::keys::local_public().map(|k| use05_receipt::key_id(&k)));
    let mut said = Vec::new();
    for id in ids {
        let branch = store::branch_for(&id);
        if git::resolve_commit(top, &format!("refs/heads/{branch}")).is_some() {
            if let Err(e) = store::push(top, &branch) {
                said.push(format!("{} Push it yourself: git push origin {branch}", e.message));
            }
        }
    }
    said
}

/// Push `commit` to origin's `branch`, never forced and through the pre-push hook like any push.
/// When it is refused: git's own first line, then the first finding a hook (05's own) named,
/// so the reason shows and not only that it stopped.
pub(crate) fn push_target(top: &Path, branch: &str, commit: &str) -> Result<(), String> {
    push_to(top, "origin", branch, commit)
}

/// Push `commit` to `remote`'s `branch` (a remote's name here, or a URL), never forced and
/// through the pre-push hook like any push; see [`push_target`].
pub(crate) fn push_to(top: &Path, remote: &str, branch: &str, commit: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let out = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["push", remote, &format!("{commit}:refs/heads/{branch}")])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("git could not be started ({e})"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(refusal(&String::from_utf8_lossy(&out.stderr)))
}

/// What a refused push said, in one line: its first line, and a hook's first finding
/// (`CODE  message`) when one is named after it.
pub(crate) fn refusal(said: &str) -> String {
    let lines: Vec<&str> = said.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("To ")).collect();
    let one = |l: &str| l.split_whitespace().collect::<Vec<_>>().join(" ");
    let first = lines.first().map_or_else(|| "git push failed".to_string(), |l| one(l));
    let is_code = |w: &str| w.len() > 3 && w.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
    match lines.iter().skip(1).find(|l| l.split_once("  ").is_some_and(|(code, _)| is_code(code))) {
        Some(finding) => format!("{first}: {}", one(finding)),
        None => first,
    }
}

/// After the push: this machine's own copy of the branch follows, when it can without touching a
/// checkout (it exists, no worktree has it checked out, and the new head contains it). Otherwise
/// a note says why it was left.
pub(crate) fn follow_local(top: &Path, branch: &str, commit: &str) -> Option<String> {
    let local = format!("refs/heads/{branch}");
    let mine = git::resolve_commit(top, &local)?;
    if mine == commit {
        return None;
    }
    let checked_out = git::text(top, &["worktree", "list", "--porcelain"]).is_ok_and(|t| t.lines().any(|l| l == format!("branch {local}")));
    if checked_out {
        return Some(format!("Your {branch} is checked out, so it was left at {}; bring it up to date with: git merge --ff-only origin/{branch}", short(&mine)));
    }
    if git::run(top, &["merge-base", "--is-ancestor", &mine, commit]).is_err() {
        return Some(format!("Your {branch} has commits origin's lacks, so it was left as it is."));
    }
    git::run(top, &["update-ref", &local, commit, &mine]).err().map(|e| format!("Your {branch} could not be moved to {}: {}", short(commit), e.message))
}

/// What became of a record: a promotion's or a deploy's.
#[derive(Clone)]
pub(crate) struct Filed {
    /// The receipts branch it is stored on, when it was stored.
    pub(crate) branch: Option<String>,
    /// Stored and pushed to origin, where CI reads it.
    pub(crate) on_origin: bool,
    pub(crate) notes: Vec<String>,
}

/// Sign the record and file it under `subject` on the signer's receipts branch, then push that
/// branch: the CI runner key in CI, else this machine's key, beside the signatures of the person
/// who acted. `lead` begins what is said when that fails ("The push went through, but").
pub(crate) fn file_record<P: use05_receipt::Predicate>(top: &Path, statement: &use05_receipt::Statement<P>, subject: &str, person: Vec<use05_receipt::EnvelopeSignature>, runner: Option<&use05_receipt::SigningKey>, lead: &str) -> Filed {
    let failed = |note: String| Filed { branch: None, on_origin: false, notes: vec![note] };
    let local = match runner {
        Some(_) => None,
        None => match use05_core::keys::ensure_local() {
            Ok((key, _)) => Some(key),
            Err(e) => return failed(format!("{lead} no record was written: this machine's key could not be read ({}).", e.message)),
        },
    };
    let key = runner.or(local.as_ref()).expect("one of them");
    let signer = use05_receipt::key_id(&key.verifying_key());
    let mut envelope = use05_receipt::seal(statement, key);
    // A person's Touch ID statement already carries this machine's signature: once is enough.
    let mine = envelope.signatures[0].keyid.clone();
    envelope.signatures.extend(person.into_iter().filter(|s| s.keyid != mine));
    let branch = match store::put(top, subject, &envelope.to_json_bytes(), &signer) {
        Ok(b) => b,
        Err(e) => return failed(format!("{lead} the record could not be stored: {}", e.message)),
    };
    match store::push(top, &branch) {
        Ok(_) => Filed { branch: Some(branch), on_origin: true, notes: Vec::new() },
        Err(e) => Filed { notes: vec![format!("The record is stored here, but could not be pushed: {}", e.message)], branch: Some(branch), on_origin: false },
    }
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_refusal_says_git_s_first_line_and_the_hook_s_first_finding() {
        let hook = "✗ 05 stopped this push  (DENIED)\n  3f2a1b9c0d → prod\n    PROMOTE_NOT_EVALUATED_MOVE  what is pushed to prod (3f2a1b9c0d4e) is not\n      the promotion 05 judged\n      → promote it with 05: use05 promote prod\nerror: failed to push some refs to '/tmp/remote'\n";
        assert_eq!(refusal(hook), "✗ 05 stopped this push (DENIED): PROMOTE_NOT_EVALUATED_MOVE what is pushed to prod (3f2a1b9c0d4e) is not");
        let remote = "remote: prod is frozen today\nTo /tmp/remote\n ! [remote rejected] 3f2a -> prod (pre-receive hook declined)\nerror: failed to push some refs to '/tmp/remote'\n";
        assert_eq!(refusal(remote), "remote: prod is frozen today");
        assert_eq!(refusal(""), "git push failed");
    }
}

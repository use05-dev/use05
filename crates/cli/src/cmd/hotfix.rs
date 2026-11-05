//! Hotfixes and back-merges (D93 part 6).
//!
//! `use05 start --hotfix <env>` starts a task from that environment's branch on origin; `land`
//! lands it there, once a person approved its outcome, and files a promotion record with
//! `direction = "hotfix"`. Promoting into that environment is then refused (the target is ahead)
//! until `use05 promote <lower> --back` merges it down, one rung at a time: a merge commit of the
//! environment above into `<lower>`, judged by `<lower>`'s rules except those about the source,
//! filed as a promotion record with `direction = "back"`. The pre-push hook knows both moves.

use std::path::Path;

use serde_json::json;
use use05_core::evidence::{Trust, classify};
use use05_core::gate::{Decision, Effect, Finding, GateResult};
use use05_core::policy::{Environment, POLICY_PATH, Policy};
use use05_core::promote::{self, PromoteInput, PromoteResult, SignOffSeen, short};
use use05_core::task::{Status, Store, Task};
use use05_core::{branches, fresh, git, store};
use use05_receipt::{Decision as Vote, Direction};

use crate::cmd::promote::{self as promotion, Prepared, Rules};
use crate::ctx::Ctx;
use crate::report::{Report, Tone};

fn is_ancestor(top: &Path, a: &str, b: &str) -> bool {
    git::run(top, &["merge-base", "--is-ancestor", a, b]).is_ok()
}

fn names(policy: &Policy) -> String {
    policy.environment.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
}

/// The environment just above `lower`: the first one promoted from it.
pub fn above<'p>(policy: &'p Policy, lower: &Environment) -> Option<&'p Environment> {
    policy.environment.iter().find(|e| policy.source_of(e).is_some_and(|s| s.name == lower.name))
}

// ----------------------------------------------------------------------------- starting one

/// What `start --hotfix <env>` set up before its task is made: a working branch at origin's head
/// of the environment's branch, checked out here and following it, so the work is judged by the
/// rules that branch holds.
pub struct Begun {
    pub env: Environment,
    pub branch: String,
    pub base: String,
    /// Where it started: `origin/prod`.
    pub from: String,
    pub notes: Vec<String>,
    /// Where this checkout was before: its branch, else its commit.
    previous: String,
}

impl Begun {
    /// Take the hotfix's branch away again, when the start it was made for is refused: back to
    /// where this checkout was, and the new branch, which has no commit of its own, deleted.
    pub fn undo(&self, top: &Path) {
        let _ = git::run(top, &["switch", "-q", "--no-guess", &self.previous]).or_else(|_| git::run(top, &["switch", "-q", "--detach", &self.previous]));
        let _ = git::run(top, &["branch", "-q", "-D", &self.branch]);
    }
}

/// Check out a new working branch for a hotfix of `name` at origin's head of its branch (fetched
/// first, five seconds at most). Refused for the environment work lands on, and with uncommitted
/// changes in the way. Nothing else is changed.
pub fn begin(ctx: &Ctx, name: &str) -> Result<Begun, Report> {
    let top = ctx.top();
    let policy = &ctx.policy;
    let Some(env) = policy.environment_named(name).cloned() else {
        let (message, next) = if policy.environment.is_empty() {
            ("this repository names no environments".to_string(), format!("name them in {POLICY_PATH} ([[environment]]), or run: use05 policy --edit"))
        } else {
            (format!("there is no environment {name:?} here; the environments are {}", names(policy)), format!("use05 start --hotfix <{}> \"<what you will fix>\"", names(policy).replace(", ", "|")))
        };
        return Err(Report::error("start", "UNKNOWN_ENVIRONMENT", message, Some(next), 6));
    };
    if policy.source_of(&env).is_none() {
        return Err(Report::error("start", "HOTFIX_ON_LANDING_BRANCH", format!("{name} is where work lands ({}): a fix for it is ordinary work, not a hotfix", env.branch), Some("use05 start \"<what you will fix>\"".into()), 6));
    }
    if !branches::is_committed(top) {
        return Err(Report::error("start", "UNCOMMITTED", format!("this checkout has uncommitted changes; a hotfix starts from a clean checkout of {}", env.branch), Some(format!("commit or stash them, then: use05 start --hotfix {name} \"<what you will fix>\"")), 6));
    }
    let mut notes = Vec::new();
    if git::text(top, &["remote", "get-url", "origin"]).is_ok() {
        if let Err(e) = fresh::fetch(top, "origin", &env.branch, fresh::FETCH_TIMEOUT) {
            notes.push(format!("Could not fetch {} from origin ({e}): started from what this machine last fetched of it.", env.branch));
        }
    }
    let Some(from_ref) = promotion::branch_ref(top, &env.branch) else {
        return Err(Report::error("start", "HOTFIX_BASE_NOT_FOUND", format!("there is no branch {} here or on origin to start a hotfix of {name} from", env.branch), Some(format!("check [[environment]] in {POLICY_PATH}")), 6));
    };
    let base = git::resolve_commit(top, &from_ref).expect("resolved above");
    let from = promotion::ref_label(&from_ref);
    let previous = git::current_branch(top).or_else(|| git::head_commit(top)).unwrap_or_default();
    let id = use05_core::task::random_id().map_err(|e| Report::from_core("start", e))?;
    let safe: String = env.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let branch = format!("05/hotfix-{safe}-{id}");
    // Following origin's copy, so what decides acceptance reads that branch's rules.
    let mut args = vec!["switch", "-q", "-c", branch.as_str()];
    if from_ref.starts_with("refs/remotes/") {
        args.extend(["--track", from.as_str()]);
    } else {
        args.push(base.as_str());
    }
    git::run(top, &args).map_err(|e| Report::error("start", "HOTFIX_BRANCH_FAILED", format!("could not make the branch {branch} from {from}: {}", e.message), None, 4))?;
    Ok(Begun { env, branch, base, from, notes, previous })
}

/// Make `task` a hotfix for `env`, started where this checkout is now: the branch `start --hotfix`
/// checked out, from where it meets origin's copy of the environment's branch. For an agent's
/// declaration, which its hook seals after `start` ran.
pub fn begin_here(top: &Path, task: &mut Task, env: &Environment) {
    let head = git::head_commit(top);
    let onto = git::resolve_commit(top, &format!("refs/remotes/origin/{}", env.branch)).or_else(|| git::resolve_commit(top, &format!("refs/heads/{}", env.branch)));
    let base = match (&head, &onto) {
        (Some(h), Some(o)) => git::merge_base(top, o, h).or_else(|| head.clone()),
        _ => head.clone(),
    };
    task.hotfix = Some(env.name.clone());
    if let Some(b) = base {
        if let Ok(tree) = git::resolve_tree(top, &b) {
            task.base_tree = tree;
        }
        task.base_commit = Some(b);
    }
    if let Some(branch) = git::current_branch(top) {
        task.branch = Some(branch);
    }
}

// ----------------------------------------------------------------------------- landing one

/// A hotfix task's landing, judged: its task gate (with the approval a hotfix always needs) and
/// the environment's hotfix rules together, and the promotion result its record is made from.
pub struct Landing {
    pub gate: GateResult,
    pub result: PromoteResult,
    /// The environment branch's head it lands on (origin's copy if there is one).
    pub onto: String,
}

/// Judge the landing of `task`'s work, ending at `head`, on its environment's branch, by the rules
/// that branch holds (`rules`). Built in: `head` comes after the branch's head (a fast-forward),
/// and the task started from the branch's history, so what lands is only its work.
pub fn judge_landing(rules: &Rules, task: &Task, head: &str) -> Result<Landing, Report> {
    let top = rules.top.as_path();
    let env = &rules.env;
    let fail = |e| Report::from_core("land", e);
    let Some(onto) = rules.target_ref.as_deref().and_then(|r| git::resolve_commit(top, r)) else {
        return Err(Report::error("land", "HOTFIX_TARGET_NOT_FOUND", format!("there is no branch {} here or on origin to land the hotfix on", env.branch), None, 6));
    };
    let id = task.id.as_str();
    let mut notes = rules.findings.clone();
    if head == onto || !is_ancestor(top, &onto, head) {
        let mut f = Finding::new("HOTFIX_NOT_FAST_FORWARD", Effect::Deny, format!("the hotfix ({}) does not come after {}'s head ({}): {} moved on since it started, or it has nothing to land", short(head), env.branch, short(&onto), env.branch));
        f.next = Some(format!("rebase it onto origin/{}, prove it and have it approved again, then: use05 land", env.branch));
        notes.push(f);
    }
    if !task.base_commit.as_deref().is_some_and(|b| b == onto || is_ancestor(top, b, &onto)) {
        let mut f = Finding::new("HOTFIX_NOT_ITS_WORK", Effect::Deny, format!("the hotfix task {id} did not start from {}'s history, so what would land is not only its work", env.branch));
        f.next = Some(format!("start it again from {}: use05 start --hotfix {} \"<what you will fix>\"", env.branch, env.name));
        notes.push(f);
    }
    // What lands is the hotfix's own commits on the branch's head: no merge, and nothing that is
    // already on another environment's branch or where work lands (origin's copies).
    let moving = promote::commits(top, head, Some(&onto)).map_err(fail)?;
    if let Some(f) = not_its_own(top, &rules.policy, env, &moving) {
        notes.push(f);
    }
    // The task gate, under the rules on the branch it lands on, for exactly what lands.
    let ctx = Ctx::open_with(top, Some(id), Some(&onto)).map_err(fail)?;
    let target = ctx.target_from(head, Some(&onto)).map_err(fail)?;
    let mut gate = ctx.gate_for(&target, Some(&env.branch)).map_err(fail)?;
    // The environment's hotfix rules. A person's approval of this hotfix's outcome, from someone
    // the environment lets sign (the gate checked), is its sign-off; so is a sign-off receipt for
    // this exact commit, which answers the environment's questions and statements.
    let mut signoffs: Vec<SignOffSeen> = gate
        .approvals
        .iter()
        .filter(|a| a.for_hotfix && a.vote == Vote::Approve && a.void.is_none())
        .map(|a| SignOffSeen { person: ctx.trust.person_of(&a.by.key_id).unwrap_or_else(|| a.by.name.clone()), decision: a.vote, text: a.rationale.clone(), confirmations: Vec::new(), path: String::new(), void: None })
        .collect();
    let now = use05_core::time::now_secs();
    let found = classify(&ctx.trust, &store::find_all(top));
    signoffs.extend(promotion::signed_for(&found, &ctx.trust, &rules.policy, env, &env.name, head, now).0);
    let untasked = promote::untasked(top, &moving, &found, &rules.policy.evidence.accept);
    let loosened = match (Policy::load_at(top, &onto), Policy::load_at(top, head)) {
        (Ok(Some(before)), Ok(Some(after))) if before != after => use05_policy_edit::guard::loosens(&before, &after),
        _ => Vec::new(),
    };
    let input = PromoteInput {
        policy: &rules.policy,
        target: env,
        source: &env.name,
        source_deployed: true,
        source_head: head.to_string(),
        target_head: Some(onto.clone()),
        expected_source: None,
        delta: moving.iter().map(|c| c.id.clone()).collect(),
        target_only: Vec::new(),
        changed: gate.changed.iter().map(|c| c.path.clone()).collect(),
        checks: gate.checks.clone(),
        deployments: Vec::new(),
        untasked,
        signoffs,
        bypasses: Vec::new(),
        loosened,
        agent: false,
        now,
        notes,
        direction: Direction::Hotfix,
        task: Some(id.to_string()),
        hotfixes: Vec::new(),
    };
    let result = promote::evaluate(&input);
    let more: Vec<Finding> = result.findings.iter().filter(|f| !gate.findings.iter().any(|g| g.code == f.code)).cloned().collect();
    gate.findings.extend(more);
    gate.findings.push(Finding::new("HOTFIX_LANDING", Effect::Info, format!("the landing of hotfix task {id} on {}, judged by its task gate and {}'s hotfix rules", env.branch, env.name)));
    gate.findings.sort_by(|a, b| b.effect.cmp(&a.effect));
    gate.decision = gate.decision.max(result.decision);
    Ok(Landing { gate, result, onto })
}

/// Why what would land on `env` is not only a hotfix's own work, if it is not: a merge commit in
/// the range, or a commit already on origin's copy of another environment's branch or of the
/// branch work lands on, named.
fn not_its_own(top: &Path, policy: &Policy, env: &Environment, moving: &[promote::Moving]) -> Option<Finding> {
    let landing = branches::landing_for(policy, None, top);
    let mut others: Vec<String> = policy.environment.iter().filter(|e| e.name != env.name).map(|e| e.branch.clone()).collect();
    if !others.contains(&landing) && landing != env.branch {
        others.push(landing);
    }
    let others: Vec<(String, String)> = others.into_iter().filter_map(|b| git::resolve_commit(top, &format!("refs/remotes/origin/{b}")).map(|c| (b, c))).collect();
    let next = Some(format!("start it again from {}, with only the fix: use05 start --hotfix {} \"<what you will fix>\"", env.branch, env.name));
    for c in moving {
        let why = if c.parents.len() > 1 {
            Some(format!("{} is a merge commit", short(&c.id)))
        } else {
            others.iter().find(|(_, head)| is_ancestor(top, &c.id, head)).map(|(b, _)| format!("{} is already on {b}", short(&c.id)))
        };
        if let Some(why) = why {
            let mut f = Finding::new("HOTFIX_NOT_ITS_WORK", Effect::Deny, format!("{why}: what would land on {} is not only this hotfix's own commits", env.branch));
            f.next = next;
            return Some(f);
        }
    }
    None
}

/// The pre-push hook's judgement of a push to `rules.env`'s branch that is a hotfix task's
/// landing there: a fast-forward of origin's head to the commit a hotfix task for this
/// environment ends at (where it landed, or its branch's head), the task having started from
/// that branch's history. `None` when the push is no such thing.
pub fn judge_hotfix_push(rules: &Rules, pushed: &str) -> Option<Result<GateResult, Report>> {
    let top = rules.top.as_path();
    let pushed = git::resolve_commit(top, pushed)?;
    let onto = rules.target_ref.as_deref().and_then(|r| git::resolve_commit(top, r))?;
    if pushed == onto || !is_ancestor(top, &onto, &pushed) {
        return None;
    }
    let tasks = Store::open(top).ok()?.list();
    let task = tasks.into_iter().find(|t| {
        let ends_here = t.head.as_deref() == Some(pushed.as_str()) || t.branch.as_deref().and_then(|b| git::resolve_commit(top, &format!("refs/heads/{b}"))).as_deref() == Some(pushed.as_str());
        t.hotfix.as_deref() == Some(rules.env.name.as_str()) && t.status != Status::Discarded && ends_here && t.base_commit.as_deref().is_some_and(|b| b == onto || is_ancestor(top, b, &onto))
    })?;
    Some(judge_landing(rules, &task, &pushed).map(|l| l.gate))
}

/// `use05 land` for a hotfix task: judged as its push will be, landed on the environment's
/// branch here (made from origin's copy when this machine has none) by fast-forward only, and
/// filed as a promotion record with `direction = "hotfix"`. Pushing follows, as for any landing.
pub fn land(ctx: &Ctx, mut task: Task) -> Report {
    let top = ctx.top().to_path_buf();
    let env_name = task.hotfix.clone().unwrap_or_default();
    let rules = match promotion::rules_for(&top, &env_name) {
        Ok(r) => r,
        Err(mut r) => {
            r.command = "land";
            return r;
        }
    };
    let env = rules.env.clone();
    // Landed here already, its record waiting for the push.
    if let Some(landed) = task.head.clone().filter(|h| pending_path(ctx, &task.id).exists() && branches::landed_commit(&top, h, &env.branch)) {
        return land_pending(ctx, &task, &rules, &landed);
    }
    let Some(branch) = task.branch.clone() else {
        return Report::error("land", "NO_BRANCH", "this hotfix was not started on a branch, so there is nothing to land".into(), None, 6);
    };
    if branches::is_kept(&rules.policy, &branch) {
        return Report::error("land", "KEPT_BRANCH", format!("{branch} is a kept branch; a hotfix lands from a working branch onto {}", env.branch), Some(format!("start it on a branch of its own: use05 start --hotfix {env_name} \"<what you will fix>\"")), 6);
    }
    if let Some(dir) = branches::checked_out_at(&top, &branch) {
        if !branches::is_committed(&dir) {
            return Report::error("land", "UNCOMMITTED", format!("{branch} has uncommitted changes at {}", dir.display()), Some("commit the work first; only committed work lands".into()), 6);
        }
    }
    let Some(head) = git::resolve_commit(&top, &format!("refs/heads/{branch}")) else {
        return Report::error("land", "BRANCH_NOT_FOUND", format!("there is no branch {branch}"), None, 6);
    };
    let landing = match judge_landing(&rules, &task, &head) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let gate = &landing.gate;
    if gate.decision != Decision::Allow {
        let first = gate.findings.iter().find(|f| f.effect >= Effect::Wait);
        return Report::error(
            "land",
            "NOT_ALLOWED",
            format!("the gate holds {branch} back ({}): {}", gate.decision.word().replace('_', " "), first.map(|f| f.message.clone()).unwrap_or_default()),
            first.and_then(|f| f.next.clone()).or(Some("use05 brief".into())),
            gate.decision.exit_code(),
        );
    }
    // The environment's branch here, from origin's copy when this machine has none yet.
    let local = format!("refs/heads/{}", env.branch);
    if git::resolve_commit(&top, &local).is_none() {
        if let Err(e) = git::run(&top, &["update-ref", &local, &landing.onto, ""]) {
            return Report::from_core("land", e);
        }
    }
    let landed = match branches::fast_forward(&top, &branch, &env.branch, &head) {
        Ok(h) => h,
        Err(e) => {
            let next = e.next.clone();
            return Report::error("land", e.code, e.message, next, 2);
        }
    };
    if task.status == Status::Active {
        let _ = ctx.store.finish(&mut task, None);
    }
    // Where its work ends: what the pre-push hook knows this landing by.
    task.head = Some(landed.clone());
    let _ = ctx.store.save(&task);
    let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "landed", "branch": branch, "target": env.branch, "head": landed, "hotfix": env.name }));
    crate::extend::emit("landed", &top, json!({ "task": task.id, "branch": branch, "target": env.branch, "head": landed }));

    // The record is made now and filed only once the environment's branch is on origin (D93):
    // until then it waits on this machine, and no record of it exists anywhere.
    let runner = crate::cmd::deploy::runner_key();
    let by = promotion::actor(&top, None, runner.is_some());
    let statement = promote::record(&landing.result, &landed, &by, use05_core::time::now_rfc3339());
    if let Err(e) = keep_pending(ctx, &task.id, &statement) {
        return Report::from_core("land", e);
    }
    let removed = branches::tidy(&ctx.store, &rules.policy, &top, false);
    let approvers: Vec<String> = landing.result.signoffs.iter().map(|s| s.person.clone()).collect();
    let mut rows = vec![("landed".to_string(), format!("{branch} → {} ({})", env.branch, short(&landed)))];
    rows.push(("hotfix".into(), format!("{} · approved by {}", env.name, if approvers.is_empty() { "nobody".to_string() } else { approvers.join(", ") })));
    for r in &removed {
        if let Some(w) = &r.worktree {
            rows.push(("removed".into(), format!("worktree {w}")));
        }
        rows.push(("deleted".into(), format!("branch {}", r.branch)));
    }
    let below = rules.source.as_ref().map(|s| s.name.clone()).unwrap_or_default();
    let notes = vec![
        not_filed_yet(&env.branch),
        format!("{} now has a commit {below} lacks: promoting into {} is refused until the fix is merged down, one rung at a time, starting with: use05 promote {below} --back", env.name, env.name),
    ];
    landed_report(&task, &branch, &env, &landed, rows, notes, json!(removed))
}

/// What a hotfix landed here but not yet on origin says: no record yet, and what files it.
pub const NOT_FILED_YET: &str = "no hotfix record exists yet";

fn not_filed_yet(branch: &str) -> String {
    format!("{branch} is not on origin yet, so {NOT_FILED_YET}: it is filed once the push goes through (use05 land --push).")
}

fn landed_report(task: &Task, branch: &str, env: &Environment, landed: &str, rows: Vec<(String, String)>, notes: Vec<String>, removed: serde_json::Value) -> Report {
    Report {
        command: "land",
        outcome: "landed",
        code: "LANDED",
        tone: Tone::Good,
        headline: format!("Landed the hotfix: {}", task.title),
        rows,
        notes,
        next: Some(format!("push {} and file its record: use05 land --push", env.branch)),
        excerpt: vec![],
        details: json!({ "task": task.id, "branch": branch, "target": env.branch, "head": landed, "removed": removed, "hotfix": env.name, "hotfix_pending": task.id }),
        exit: 0,
    }
}

/// Where a landed hotfix's record waits until its push goes through.
fn pending_path(ctx: &Ctx, task: &str) -> std::path::PathBuf {
    ctx.store.state_dir().join("hotfix-records").join(format!("{task}.json"))
}

fn keep_pending(ctx: &Ctx, task: &str, statement: &use05_receipt::Statement<use05_receipt::Promotion>) -> use05_core::Result<()> {
    let path = pending_path(ctx, task);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| use05_core::Error::io("keeping the hotfix's record", e))?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(statement).expect("a statement serialises")).map_err(|e| use05_core::Error::io("keeping the hotfix's record", e))
}

/// After the environment's branch was pushed: sign and file the hotfix record that waited, and
/// push it. Rows and notes for the report; nothing when no record waits.
pub fn file_pending(ctx: &Ctx, task: &str) -> (Vec<(String, String)>, Vec<String>) {
    let path = pending_path(ctx, task);
    let Some(mut statement) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<use05_receipt::Statement<use05_receipt::Promotion>>(&b).ok()) else {
        return (Vec::new(), Vec::new());
    };
    statement.predicate.created = use05_core::time::now_rfc3339();
    let runner = crate::cmd::deploy::runner_key();
    let filed = promotion::file_record(ctx.top(), &statement, &statement.predicate.source_commit, Vec::new(), runner.as_ref(), "The push went through, but");
    if filed.branch.is_some() {
        let _ = std::fs::remove_file(&path);
    }
    (filed.branch.iter().map(|b| ("record".to_string(), format!("on {b}"))).collect(), filed.notes)
}

/// The current hotfix task's landing on `name`, as a sign-off on it reads it (`approve --promote
/// <env> --hotfix`): the hotfix's head, judged as its landing is. Fetches; changes nothing.
pub fn prepare_landing(repo: &Path, name: &str) -> Result<Prepared, Report> {
    let ctx = Ctx::open(repo, None).map_err(|e| Report::from_core("approve", e))?;
    let Some(task) = ctx.task.clone().filter(|t| t.hotfix.as_deref() == Some(name)) else {
        return Err(Report::error("approve", "NO_HOTFIX", format!("the current task is not a hotfix of {name}"), Some(format!("start one: use05 start --hotfix {name} \"<what you will fix>\"")), 6));
    };
    let Some(head) = task.branch.as_deref().and_then(|b| git::resolve_commit(ctx.top(), &format!("refs/heads/{b}"))) else {
        return Err(Report::error("approve", "BRANCH_NOT_FOUND", format!("the hotfix task {} has no branch here to sign off on", task.id), None, 6));
    };
    let rules = promotion::rules_for(repo, name)?;
    let landing = judge_landing(&rules, &task, &head)?;
    let fail = |e| Report::from_core("approve", e);
    let top = rules.top.clone();
    let moving = promote::commits(&top, &head, Some(&landing.onto)).map_err(fail)?;
    let (before, after) = (git::resolve_tree(&top, &landing.onto).map_err(fail)?, git::resolve_tree(&top, &head).map_err(fail)?);
    let numstat = git::numstat(&top, Some(&before), &after).map_err(fail)?;
    let env = rules.env.clone();
    Ok(Prepared {
        result: landing.result,
        rules_from: rules.rules_from,
        source_ref: task.branch.clone().unwrap_or_default(),
        target_ref: rules.target_ref.as_deref().map(promotion::ref_label),
        moving,
        numstat,
        notes: rules.notes,
        questions: env.sign_off.as_ref().map(|s| s.questions.clone()).unwrap_or_default(),
        confirm: env.confirm.iter().map(|c| c.text.clone()).collect(),
        org: rules.org,
        accepts_local: rules.policy.evidence.accept.contains(&use05_core::policy::Role::Local),
        policy: rules.policy,
        source: env.clone(),
        env,
        top,
        merged_tree: None,
    })
}

/// A hotfix landed here whose record still waits: push it, or, when origin already has it (a
/// push by hand), file the record now.
fn land_pending(ctx: &Ctx, task: &Task, rules: &Rules, landed: &str) -> Report {
    let env = &rules.env;
    let branch = task.branch.clone().unwrap_or_default();
    let on_origin = git::resolve_commit(&rules.top, &format!("refs/remotes/origin/{}", env.branch)).is_some_and(|o| o == landed || is_ancestor(&rules.top, landed, &o));
    if on_origin {
        let (mut rows, notes) = file_pending(ctx, &task.id);
        rows.insert(0, ("landed".to_string(), format!("{} on origin ({})", env.branch, short(landed))));
        let mut report = landed_report(task, &branch, env, landed, rows, notes, json!([]));
        report.headline = format!("Filed the hotfix's record: {}", task.title);
        report.next = None;
        report.details["hotfix_pending"] = serde_json::Value::Null;
        return report;
    }
    let rows = vec![("landed".to_string(), format!("{} here, at {}", env.branch, short(landed)))];
    landed_report(task, &branch, env, landed, rows, vec![not_filed_yet(&env.branch)], json!([]))
}

// ----------------------------------------------------------------------------- merging back

/// git's merge of `ours` and `theirs`: the tree it writes (with conflict markers where it could
/// not merge), and the paths that conflict (none for a clean merge). Needs a git that has
/// `merge-tree --write-tree` (2.38 or newer).
struct Merged {
    tree: String,
    conflicts: Vec<String>,
}

fn merge_tree(top: &Path, ours: &str, theirs: &str) -> Result<Merged, Report> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["merge-tree", "--write-tree", "--name-only", "--no-messages", ours, theirs])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Report::error("promote", "BACK_MERGE_FAILED", format!("git could not be started ({e})"), None, 4))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    match out.status.code() {
        Some(code @ (0 | 1)) => {
            let tree = lines.next().unwrap_or_default().to_string();
            let mut conflicts: Vec<String> = if code == 1 { lines.map(str::to_string).collect() } else { Vec::new() };
            conflicts.dedup();
            Ok(Merged { tree, conflicts })
        }
        _ => {
            let said = String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("it failed").trim().to_string();
            Err(Report::error("promote", "BACK_MERGE_FAILED", format!("git could not work out the merge ({said}); merging back needs git 2.38 or newer"), None, 4))
        }
    }
}

/// Gather what merging the environment above `lower` back into it would bring, and judge it by
/// `lower`'s rules (read from its own branch) except those about the source. Reads git and the
/// receipts and fetches from origin; changes nothing else.
pub fn prepare_back(repo: &Path, lower: &str) -> Result<Prepared, Report> {
    prepare_back_from(promotion::rules_for(repo, lower)?, None, None)
}

/// As [`prepare_back`], refused if the environment above moved since `expected` was evaluated.
fn prepare_back_expecting(repo: &Path, lower: &str, expected: &str) -> Result<Prepared, Report> {
    prepare_back_from(promotion::rules_for(repo, lower)?, Some(expected), None)
}

/// A back-merge into `lower` that a person resolved by hand, as `approve --promote <lower> --back
/// --rev <merge commit>` signs off on it. Refused when `merge` is no such merge.
pub fn prepare_resolved(repo: &Path, lower: &str, merge: &str) -> Result<Prepared, Report> {
    let rules = promotion::rules_for(repo, lower)?;
    match back_merge(&rules, merge) {
        Some(BackMerge::Resolved(m)) => prepare_back_from(rules, None, Some(&m)),
        _ => Err(Report::error("approve", "NOT_A_RESOLVED_BACK_MERGE", format!("{merge} is not a merge of origin's head of the environment above {lower} into origin's {lower} that changes only the files that conflicted"), Some(format!("make one as use05 promote {lower} --back says when it is refused, then sign off on it")), 6)),
    }
}

/// The rollbacks 05 made (counted promotion records whose `how` is `revert`) that a merge back
/// would bring down, from any environment, one finding each, for a person's sign-off on that merge back.
fn rollbacks_carried(top: &Path, found: &use05_core::evidence::Found, accept: &[use05_core::policy::Role], moving: &[promote::Moving], upper: &str, lower: &str) -> Vec<Finding> {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for s in found.promotions.iter().filter(|p| accept.contains(&p.signer.role)).map(|p| &p.statement) {
        let p = &s.predicate;
        if p.how != "revert" || s.commit_subject() != Some(p.source_commit.as_str()) || seen.contains(&p.result_commit.as_str()) {
            continue;
        }
        if !moving.iter().any(|c| c.id == p.result_commit) {
            continue;
        }
        seen.push(&p.result_commit);
        let undone = p.reverts.as_deref().unwrap_or_default();
        let what = git::text(top, &["log", "-1", "--format=%s", undone]).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let named = what.map_or_else(|| short(undone).to_string(), |s| format!("{} (\"{s}\")", short(undone)));
        let mut f = Finding::new(
            "BACK_MERGE_CARRIES_ROLLBACK",
            Effect::Approval,
            format!("this merge back from {upper} brings down the rollback of {} ({}), which undid {named} there: merged into {lower}, it undoes that work here too, where it may still be wanted", p.env, short(&p.result_commit)),
        );
        f.approvable = true;
        f.next = Some(format!("if {lower} should lose that work too, a person signs off: use05 approve --promote {lower} --back --note \"<why>\"; otherwise revert the rollback above first"));
        out.push(f);
    }
    out
}

fn prepare_back_from(rules: Rules, expected: Option<&str>, resolved: Option<&str>) -> Result<Prepared, Report> {
    let fail = |e| Report::from_core("promote", e);
    let Rules { top, policy, env, source: _, rules_from, mut findings, mut notes, target_ref, target_policy, org } = rules;
    let Some(upper) = above(&policy, &env).cloned() else {
        return Err(Report::error("promote", "NOTHING_ABOVE", format!("{} is the top environment: there is nothing above it to merge back", env.name), None, 6));
    };
    promotion::fetch(&top, &[&upper.branch], &mut notes);
    notes.dedup();
    let Some(source_ref) = promotion::branch_ref(&top, &upper.branch) else {
        return Err(Report::error("promote", "SOURCE_NOT_FOUND", format!("there is no branch {} ({}) here or on origin", upper.branch, upper.name), Some(format!("check [[environment]] in {POLICY_PATH}")), 6));
    };
    let Some(target_head) = target_ref.as_deref().and_then(|r| git::resolve_commit(&top, r)) else {
        return Err(Report::error("promote", "TARGET_NOT_FOUND", format!("there is no branch {} ({}) here or on origin to merge back into", env.branch, env.name), Some(format!("push {} first", env.branch)), 6));
    };
    let upper_head = git::resolve_commit(&top, &source_ref).expect("resolved above");
    let merged = merge_tree(&top, &target_head, &upper_head)?;
    // A merge resolved by hand is what moves, and what a person signs off on.
    let source_head = resolved.map_or_else(|| upper_head.clone(), str::to_string);
    let moving = promote::commits(&top, &source_head, Some(&target_head)).map_err(fail)?;
    let target_tree = git::resolve_tree(&top, &target_head).map_err(fail)?;
    let clean = merged.conflicts.is_empty();
    let after = match resolved {
        Some(m) => {
            let mut f = Finding::new("BACK_MERGE_RESOLVED", Effect::Approval, format!("{} was merged into {} by hand ({}), resolving {}: a person must sign off on that exact merge commit", upper.name, env.name, short(m), merged.conflicts.join(", ")));
            f.paths = merged.conflicts.clone();
            f.approvable = true;
            f.next = Some(format!("ask a person to sign off on it: use05 approve --promote {} --back --rev {m} --note \"<how it was resolved>\"", env.name));
            findings.push(f);
            git::resolve_tree(&top, m).map_err(fail)?
        }
        None if clean => merged.tree.clone(),
        None => {
            let mut f = Finding::new("BACK_MERGE_CONFLICT", Effect::Deny, format!("{} does not merge cleanly into {}: {} changed on both", upper.name, env.name, merged.conflicts.join(", ")));
            f.paths = merged.conflicts.clone();
            f.next = Some(format!(
                "resolve it by hand: on a branch from origin/{}, git merge origin/{}, change only the conflicted files ({}) and commit; a person signs off on that merge commit: use05 approve --promote {} --back --rev <merge commit>; then push it: git push origin <merge commit>:{}",
                env.branch, upper.branch, merged.conflicts.join(", "), env.name, env.branch
            ));
            findings.push(f);
            git::resolve_tree(&top, &upper_head).map_err(fail)?
        }
    };
    let changed: Vec<String> = git::changed(&top, Some(&target_tree), &after).map_err(fail)?.into_iter().map(|c| c.path).collect();
    let numstat = git::numstat(&top, Some(&target_tree), &after).map_err(fail)?;
    let trust = Trust::new(&policy, true);
    let found = classify(&trust, &store::find_all(&top));
    let now = use05_core::time::now_secs();
    let accept = &policy.evidence.accept;
    // A rollback above undid a promotion there. Merged down, it would undo that work here too,
    // where it may still be wanted: a person decides, by a sign-off on this merge back.
    for f in rollbacks_carried(&top, &found, accept, &moving, &upper.name, &env.name) {
        findings.push(f);
    }
    // Sign-offs are on what moves: the merge resolved by hand, else the head above. Bypasses are
    // of the merge of that head.
    let (signoffs, _) = promotion::signed_for(&found, &trust, &policy, &env, &upper.name, &source_head, now);
    let (_, bypasses) = promotion::signed_for(&found, &trust, &policy, &env, &upper.name, &upper_head, now);
    // A merge resolved by hand is a person's to sign off on, not a task's.
    let untasked: Vec<String> = promote::untasked(&top, &moving, &found, accept).into_iter().filter(|c| Some(c.as_str()) != resolved).collect();
    // The policy file comes down with the merge: what it would then hold is weighed against what
    // the lower environment holds now.
    let merged_policy = (clean || resolved.is_some()).then(|| Policy::load_at(&top, &after).ok().flatten()).flatten();
    let loosened = match (&target_policy, merged_policy) {
        (Some(before), Some(after)) if *before != after => use05_policy_edit::guard::loosens(before, &after),
        _ => Vec::new(),
    };
    let input = PromoteInput {
        policy: &policy,
        target: &env,
        source: &upper.name,
        source_deployed: true,
        source_head: source_head.clone(),
        target_head: Some(target_head),
        expected_source: expected.map(str::to_string),
        delta: moving.iter().map(|c| c.id.clone()).collect(),
        target_only: Vec::new(),
        changed,
        checks: Vec::new(),
        deployments: Vec::new(),
        untasked,
        signoffs,
        bypasses,
        loosened,
        agent: use05_core::inbox::agent_session().is_some(),
        now,
        notes: findings,
        direction: Direction::Back,
        task: None,
        hotfixes: Vec::new(),
    };
    let result = promote::evaluate(&input);
    Ok(Prepared {
        result,
        rules_from,
        source_ref: promotion::ref_label(&source_ref),
        target_ref: target_ref.as_deref().map(promotion::ref_label),
        moving,
        numstat,
        notes,
        questions: env.sign_off.as_ref().map(|s| s.questions.clone()).unwrap_or_default(),
        confirm: env.confirm.iter().map(|c| c.text.clone()).collect(),
        org,
        accepts_local: accept.contains(&use05_core::policy::Role::Local),
        policy,
        env,
        source: upper,
        top,
        merged_tree: (clean && resolved.is_none()).then_some(merged.tree),
    })
}

/// The parents of a commit, in order.
fn parents(top: &Path, commit: &str) -> Vec<String> {
    git::text(top, &["rev-list", "--parents", "-n", "1", commit]).unwrap_or_default().split_whitespace().skip(1).map(str::to_string).collect()
}

/// A push that is a back-merge: as `promote --back` makes one, or resolved by a person.
pub enum BackMerge {
    /// Git's clean merge of the two heads.
    Clean,
    /// The two conflict, and this merge commit differs from git's merge only in the files that
    /// conflict.
    Resolved(String),
}

/// Whether `pushed` is a back-merge into `rules.env`: a merge commit whose first parent is
/// origin's head of its branch and whose second is origin's head of the environment above it
/// (fetched first), and whose tree is git's clean merge of the two, or, where they conflict,
/// differs from git's merge only in the files that conflict.
pub fn back_merge(rules: &Rules, pushed: &str) -> Option<BackMerge> {
    let top = rules.top.as_path();
    let upper = above(&rules.policy, &rules.env)?;
    let pushed = git::resolve_commit(top, pushed)?;
    let lower = git::resolve_commit(top, &format!("refs/remotes/origin/{}", rules.env.branch))?;
    if parents(top, &pushed).first() != Some(&lower) {
        return None;
    }
    if !promotion::offline() && git::text(top, &["remote", "get-url", "origin"]).is_ok() {
        let _ = fresh::fetch(top, "origin", &upper.branch, fresh::FETCH_TIMEOUT);
    }
    let upper_head = git::resolve_commit(top, &format!("refs/remotes/origin/{}", upper.branch))?;
    if parents(top, &pushed) != [lower.clone(), upper_head.clone()] {
        return None;
    }
    let merged = merge_tree(top, &lower, &upper_head).ok()?;
    let tree = git::resolve_tree(top, &pushed).ok()?;
    if merged.conflicts.is_empty() {
        return (tree == merged.tree).then_some(BackMerge::Clean);
    }
    let differs = git::text(top, &["diff", "--name-only", "--no-renames", &merged.tree, &tree]).ok()?;
    differs.lines().all(|p| merged.conflicts.iter().any(|c| c == p)).then_some(BackMerge::Resolved(pushed))
}

/// The pre-push hook's judgement of a back-merge (see [`back_merge`]): the lower environment's
/// rules but those about the source, a person's sign-off on a merge resolved by hand, and where
/// people keep it (`agent = false`), a person pushing.
pub fn judge_back_push(rules: Rules, pushed: &str, kind: &BackMerge) -> Result<GateResult, Report> {
    let resolved = match kind {
        BackMerge::Resolved(m) => Some(m.as_str()),
        BackMerge::Clean => None,
    };
    let p = prepare_back_from(rules, None, resolved)?;
    let r = &p.result;
    let mut findings = r.findings.clone();
    let mut decision = r.decision;
    let name = &p.env.name;
    if !r.agent_allowed && !crate::cmd::gate::person_at_terminal() && !findings.iter().any(|f| f.code == "AGENT_MAY_NOT_PROMOTE") {
        let mut f = Finding::new("AGENT_MAY_NOT_PROMOTE", Effect::Deny, format!("{name} is kept for people, and nothing here shows a person pushing: there is no terminal"));
        f.next = Some(format!("a person pushes it at their terminal, or runs: use05 promote {name} --back"));
        findings.insert(0, f);
        decision = Decision::Deny;
    }
    findings.push(Finding::new("BACK_MERGE", Effect::Info, format!("a back-merge of {} ({}) into {name}, judged by {name}'s rules but those about the source", p.source.name, short(pushed))));
    Ok(GateResult::of_findings(decision, findings, r.policy_sha256.clone()))
}

/// The pre-push hook, for a push to the branch work lands on (which keeps the task gate): its
/// judgement when the push is a back-merge of the environment above into it, else `None`.
pub fn judge_back_into(repo: &Path, name: &str, pushed: &str) -> Option<GateResult> {
    let top = git::dirs(repo).ok()?.top;
    // Cheap first: only a merge on origin's head of the branch can be one; nothing is fetched else.
    let branch = crate::ctx::Ctx::open(repo, None).ok()?.policy.environment_named(name)?.branch.clone();
    let lower = git::resolve_commit(&top, &format!("refs/remotes/origin/{branch}"))?;
    let pushed = git::resolve_commit(&top, pushed)?;
    let ps = parents(&top, &pushed);
    if ps.len() != 2 || ps[0] != lower {
        return None;
    }
    let rules = promotion::rules_for(repo, name).ok()?;
    let kind = back_merge(&rules, &pushed)?;
    let digest = rules.policy.digest();
    Some(judge_back_push(rules, &pushed, &kind).unwrap_or_else(|r| {
        let mut f = Finding::new("PROMOTE_NOT_JUDGED", Effect::Deny, format!("05 could not judge this back-merge into {name}: {}", r.headline));
        f.next = r.next.clone().or_else(|| Some(format!("see why: use05 promote {name} --back --check")));
        GateResult::of_findings(Decision::Deny, vec![f], digest)
    }))
}

/// `use05 promote <lower> --back --check`: judge it, change nothing.
pub fn run_back_check(repo: &Path, lower: &str) -> Report {
    match prepare_back(repo, lower) {
        Ok(p) => promotion::page(&p, "PROMOTE_CHECKED", "", &promotion::strength(&p)),
        Err(r) => r,
    }
}

/// The merge commit a back-merge makes: on `lower`'s head, with the environment above's head as
/// its second parent and git's clean merge of the two as its tree, made from objects alone (no
/// worktree, no checkout touched). Nothing is pushed and no branch moves.
fn make_back_merge(p: &Prepared) -> Result<String, Report> {
    let r = &p.result;
    let (Some(tree), Some(lower)) = (p.merged_tree.as_deref(), r.target_head.as_deref()) else {
        return Err(Report::error("promote", "BACK_MERGE_FAILED", "there is no clean merge to make".into(), None, 4));
    };
    let named = |key: &str| git::text(&p.top, &["config", key]).ok().is_some_and(|v| !v.is_empty());
    let mut args: Vec<&str> = Vec::new();
    // A merge commit needs a name; CI often has none set.
    if !named("user.name") || !named("user.email") {
        args.extend(["-c", "user.name=use05", "-c", "user.email=use05@localhost"]);
    }
    let message = promote::merge_message(r);
    args.extend(["commit-tree", tree, "-p", lower, "-p", &r.source_head, "-m", &message]);
    git::text(&p.top, &args).map_err(|e| Report::error("promote", "BACK_MERGE_FAILED", format!("could not make the merge commit: {}", e.message), None, 4))
}

/// `use05 promote <lower> --back`: merge the environment above `lower` into it, as a merge commit
/// (never a fast-forward, never forced), when `lower`'s rules allow it; push it through the
/// pre-push hook and file the signed record (`direction = "back"`). Refused, with nothing left
/// behind, when the two do not merge cleanly. Where `lower` is kept for people, only a person.
pub fn run_back(repo: &Path, lower: &str, interactive: bool) -> Report {
    let p = match prepare_back(repo, lower) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(f) = p.result.findings.iter().find(|f| f.code == "BACK_MERGE_CONFLICT") {
        let mut refused = Report::error("promote", "BACK_MERGE_CONFLICT", f.message.clone(), f.next.clone(), 2);
        refused.notes = vec!["Nothing was moved or pushed: no merge commit was made, and no branch here or on origin changed.".into()];
        refused.details = promotion::details(&p);
        return refused;
    }
    if let Some(held) = promotion::held(&p) {
        return held;
    }
    let r = &p.result;
    let top = p.top.clone();
    let name = p.env.name.clone();
    let person = !r.agent_allowed;
    if person {
        if let Err(refused) = crate::cmd::approve::person_here("promote", interactive, &format!("merging back into {name}")) {
            return refused;
        }
    }
    if git::text(&top, &["remote", "get-url", "origin"]).is_err() {
        return Report::error("promote", "NO_REMOTE", format!("this repository has no origin to push {} to", p.env.branch), Some("git remote add origin <url>".into()), 6);
    }
    let merge = match make_back_merge(&p) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let runner = crate::cmd::deploy::runner_key();
    let by = crate::cmd::deploy::by_whom(&top, &p.policy, person, runner.is_some());
    let statement = promote::record(r, &merge, &by, use05_core::time::now_rfc3339());
    let mut signatures = Vec::new();
    if person {
        eprintln!("You are about to merge {} from {} back into {}: {}.", short(&r.source_head), r.source_env, r.target_env, promotion::summary(&p));
        match crate::cmd::approve::sign_as_person(&statement, &format!("merge {} back into {name}", short(&r.source_head)), false, "promote") {
            Ok((envelope, _)) => signatures = envelope.signatures,
            Err(refused) => return refused,
        }
    }
    // Judged once more just before the push, against the commit that was evaluated.
    let again = match prepare_back_expecting(repo, lower, &r.source_head) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(held) = promotion::held(&again) {
        return held;
    }
    if again.result.target_head != r.target_head {
        return Report::error("promote", "PROMOTE_TARGET_MOVED", format!("{} moved on origin while this ran; nothing was pushed", p.env.branch), Some(format!("use05 promote {name} --back")), 4);
    }
    if let Err(line) = promotion::push_target(&top, &p.env.branch, &merge) {
        let mut refused = Report::error("promote", "PROMOTE_PUSH_FAILED", format!("the push of {} to origin was refused: {line}", p.env.branch), Some(format!("fix what refused it, then: use05 promote {name} --back")), 4);
        refused.notes = vec![format!("Nothing moved: origin's {} is where it was, no branch here was moved, and no record was written.", p.env.branch)];
        return refused;
    }
    let mut notes = Vec::new();
    notes.extend(promotion::follow_local(&top, &p.env.branch, &merge));
    let filed = promotion::file_record(&top, &statement, &statement.predicate.source_commit, signatures, runner.as_ref(), "The push went through, but");
    notes.extend(filed.notes.clone());
    notes.extend(promotion::push_receipts(&top));
    for f in r.findings.iter().filter(|f| f.effect >= Effect::Warn) {
        notes.push(format!("{} {}: {}", format!("{:?}", f.effect).to_lowercase(), f.code, f.message));
    }
    notes.push(format!("Here this is advisory: it is the judgement CI makes, but nothing stops a person or an agent who pushes {}'s branch by hand.", name));
    let rules = r.rules.iter().map(|x| format!("{} {}", x.rule, promote::outcome_word(x.outcome))).collect::<Vec<_>>().join(" · ");
    let mut rows = vec![
        ("merged".to_string(), format!("{} · {} ({}) into {}", promotion::summary(&p), short(&r.source_head), p.source_ref, p.env.branch)),
        ("pushed".to_string(), format!("{} → origin, now at {} (a merge commit)", p.env.branch, short(&merge))),
        ("rules".to_string(), rules),
        ("rollback".to_string(), r.target_head.as_deref().map(short).unwrap_or_default().to_string()),
        ("by".to_string(), by.clone()),
    ];
    if let Some(b) = &filed.branch {
        rows.push(("record".to_string(), format!("on {b}")));
    }
    // One rung at a time: the next one down, or, at the bottom, promoting up again.
    let next = match p.policy.source_of(&p.env) {
        Some(below) => format!("use05 promote {} --back", below.name),
        None => format!("use05 promote {} --check", p.source.name),
    };
    let (code, tone, headline) = if filed.on_origin {
        ("MERGED_BACK", Tone::Good, format!("Merged {} back into {}: {} (merge)", r.source_env, r.target_env, short(&r.source_head)))
    } else {
        ("MERGED_BACK_WITHOUT_RECORD", Tone::Warn, format!("Merged {} back into {}: {} (merge), but its record is not on origin", r.source_env, r.target_env, short(&r.source_head)))
    };
    Report {
        command: "promote",
        outcome: "merged_back",
        code,
        tone,
        headline,
        rows,
        notes,
        next: Some(next),
        excerpt: vec![],
        details: json!({
            "env": r.target_env,
            "from": r.source_env,
            "direction": r.direction,
            "source_commit": r.source_head,
            "result_commit": merge,
            "target_before": r.target_head,
            "how": r.how,
            "pushed": true,
            "record_branch": filed.branch,
            "record_on_origin": filed.on_origin,
            "by": by,
            "rules": r.rules,
            "findings": r.findings,
        }),
        exit: 0,
    }
}

//! What every command needs: the repository, the current task, the rules that apply to it
//! (read from the change's base), the organisation floor, and the keys we trust.

use std::path::Path;

use use05_core::evidence::Trust;
use use05_core::gate::{GateInput, GateResult, evaluate};
use use05_core::policy::{POLICY_PATH, Policy};
use use05_core::task::{Store, Task};
use use05_core::time::now_secs;
use use05_core::{Error, Result, git, org};

pub struct Ctx {
    pub store: Store,
    pub task: Option<Task>,
    /// The repository's own policy, before any organisation floor.
    pub repo_policy: Policy,
    /// What actually applies: the repository's policy, tightened by the organisation.
    pub policy: Policy,
    pub org: Option<String>,
    pub trust: Trust,
    /// The base has no committed policy, so a push and CI hold the change to 05's defaults,
    /// while the working policy file is not the rules yet.
    pub policy_uncommitted: bool,
    /// The current task's receipts, read and checked once however many times they are asked for.
    task_found: std::cell::OnceCell<use05_core::evidence::Found>,
}

pub struct Target {
    pub oid: String,
    pub digest: String,
    /// How to describe it to a person.
    pub label: String,
    pub base_tree: Option<String>,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
}

impl Ctx {
    pub fn top(&self) -> &Path {
        &self.store.dirs.top
    }

    pub fn open(repo: &Path, task_id: Option<&str>) -> Result<Ctx> {
        Ctx::open_with(repo, task_id, None)
    }

    /// For what decides whether a change is accepted (an approval, the brief, a landing): the
    /// rules a push and CI will hold it to, read from its base as the gate reads them. Hooks and
    /// `prove` may follow a policy file not committed yet; an approval must not, or the push it
    /// was given for never counts it.
    pub fn open_judging(repo: &Path, task_id: Option<&str>) -> Result<Ctx> {
        Ctx::open_rules(repo, task_id, None, true, true)
    }

    /// For a commit that is not a task here (someone else's branch, fetched): no task of this
    /// machine's is read, and the rules come from `policy_rev` as a push of it would read them, or
    /// as [`Ctx::open_judging`] does without one.
    pub fn open_for_commit(repo: &Path, policy_rev: Option<&str>) -> Result<Ctx> {
        Ctx::open_rules(repo, None, policy_rev, true, false)
    }

    /// Like [`Ctx::open`], but read the rules from `policy_rev` (a commit). Gating a push or a
    /// pull request passes the change's base here, so a change cannot loosen its own rules. In
    /// that case a base with no policy means defaults, never the change's own file.
    pub fn open_with(repo: &Path, task_id: Option<&str>, policy_rev: Option<&str>) -> Result<Ctx> {
        Ctx::open_rules(repo, task_id, policy_rev, policy_rev.is_some(), true)
    }

    fn open_rules(repo: &Path, task_id: Option<&str>, policy_rev: Option<&str>, strict: bool, current: bool) -> Result<Ctx> {
        let store = Store::open(repo)?;
        // Best effort, and one small read when it was done in the last few minutes.
        use05_core::repos::touch(&store.dirs);
        let mut task = match task_id {
            Some(id) => Some(store.load(id)?),
            None if current => store.current(),
            None => None,
        };
        let top = store.dirs.top.clone();
        // Fresh base: work updated since its session started has its base moved, so the commits
        // it pulled in are not counted as its change (the hooks do the same as the agent works).
        if let Some(t) = task.as_mut().filter(|t| t.fresh.is_some()) {
            if use05_core::fresh::catch_up(&top, t) {
                store.save_keeping_time(t)?;
            }
        }
        // Whatever decides acceptance reads its rules where a push would be judged: the commit the
        // work forks from on the remote. Approving must sign under those same rules, or a task that
        // began before the policy changed could never be approved in a way a push counts. With no
        // remote, or when the hooks are only watching, the task's own base is used.
        let judged_at = if strict && policy_rev.is_none() { git::head_commit(&top).and_then(|h| git::fork_from_remote(&top, &h)) } else { None };
        let base = policy_rev.map(str::to_string).or(judged_at).or_else(|| task.as_ref().and_then(|t| t.base_commit.clone())).or_else(|| git::head_commit(&top));
        // A change's rules come from its base. If there is no committed policy yet, the hooks
        // and `prove` follow the working file, so a fresh `init` works before its first commit;
        // a push, CI and whatever decides acceptance hold the change to the defaults.
        let from_base = match &base {
            Some(rev) => Policy::load_at(&top, rev)?,
            None => None,
        };
        let policy_uncommitted = base.is_some() && from_base.is_none() && top.join(POLICY_PATH).exists();
        let repo_policy = match from_base {
            Some(p) => p,
            None if strict && base.is_some() => Policy::default(),
            None => Policy::load_file(&top.join(POLICY_PATH))?.unwrap_or_default(),
        };
        let mut policy = repo_policy.clone();
        let org = match org::load()? {
            Some((name, floor)) => {
                policy.tighten(&floor);
                Some(name)
            }
            None => None,
        };
        // A floor adds trusted keys: groups and people must still be told apart once it has.
        policy.check_effective()?;
        let trust = Trust::new(&policy, true);
        Ok(Ctx { store, task, repo_policy, policy, org, trust, policy_uncommitted, task_found: std::cell::OnceCell::new() })
    }

    /// Someone else's work, named by a revision (D92), measured and judged as a push of it would
    /// be: from where it forks from the remote (else its parent), under the rules there. No task
    /// of this machine's is read; whose work it is comes from its signed records, as CI reads them.
    /// `brief --rev` and `approve --rev` both use this, so what a person reads is what they sign.
    pub fn open_rev(repo: &Path, rev: &str) -> Result<(Ctx, Target)> {
        let top = git::dirs(repo)?.top;
        let commit = git::resolve_commit(&top, rev).ok_or_else(|| {
            Error::new("REV_NOT_FOUND", format!("there is no commit {rev:?} here")).with_next("fetch it first: git fetch origin, then name it, as in --rev origin/<branch>")
        })?;
        let base = git::fork_from_remote(&top, &commit).filter(|b| *b != commit).or_else(|| git::resolve_commit(&top, &format!("{commit}^")));
        let mut ctx = Ctx::open_for_commit(repo, base.as_deref())?;
        let mut target = ctx.target_from(&commit, base.as_deref())?;
        let short = &commit[..12.min(commit.len())];
        target.label = if commit.starts_with(rev.trim()) { format!("commit {short}") } else { format!("{rev} at commit {short}") };
        target.head_commit = Some(commit);
        let found = use05_core::evidence::classify(&ctx.trust, &use05_core::store::find_all(ctx.top()));
        ctx.task = use05_core::gate::task_from_receipts(&found, &target.oid).map(|(task, _)| task);
        Ok((ctx, target))
    }

    /// Resolve what to look at: `index` (staged files) or any commit or tree.
    pub fn target(&self, spec: Option<&str>) -> Result<Target> {
        let top = self.top();
        let spec = spec.unwrap_or_else(|| git::default_spec(top));
        let oid = git::resolve_tree(top, spec)?;
        let digest = tree_digest(top, &oid)?;
        let head_commit = git::head_commit(top);
        let (base_tree, base_commit) = match &self.task {
            Some(t) if !t.base_tree.is_empty() => (Some(t.base_tree.clone()), t.base_commit.clone()),
            _ => default_base(top, spec),
        };
        let label = match spec {
            "index" => "staged files".to_string(),
            "worktree" => "working tree".to_string(),
            other => other.to_string(),
        };
        Ok(Target { oid, digest, label, base_tree, base_commit, head_commit })
    }

    /// Like [`Ctx::target`] for a commit, measured against an explicit base commit.
    pub fn target_from(&self, spec: &str, base_commit: Option<&str>) -> Result<Target> {
        let mut t = self.target(Some(spec))?;
        let top = self.top();
        t.base_commit = base_commit.map(str::to_string);
        t.base_tree = base_commit.and_then(|c| git::resolve_tree(top, c).ok());
        Ok(t)
    }

    /// The current task's receipts and log seals, verified against the trusted keys.
    pub fn task_found(&self) -> Option<&use05_core::evidence::Found> {
        let task = self.task.as_ref()?;
        Some(self.task_found.get_or_init(|| use05_core::evidence::classify(&self.trust, &use05_core::store::find(self.top(), &task.id))))
    }

    pub fn gate(&self, target: &Target) -> Result<GateResult> {
        self.gate_for(target, None)
    }

    /// The gate for a push (or a landing, or a merge) to `branch`: what a policy asks only then,
    /// such as a person's testing sign-off (D87), is asked too.
    pub fn gate_for(&self, target: &Target, pushing_to: Option<&str>) -> Result<GateResult> {
        self.gate_on_host(target, pushing_to, None)
    }

    /// As `gate_for`, where the host (CI) also says which branch is its default.
    pub fn gate_on_host(&self, target: &Target, pushing_to: Option<&str>, default_branch: Option<&str>) -> Result<GateResult> {
        let late = self.task.as_ref().map(|t| use05_core::task::declared_late(&self.store, t)).unwrap_or_default();
        let log = self.task.as_ref().and_then(|t| use05_core::logseal::check(self.top(), Some(&self.store.state_dir()), self.task_found().expect("a task"), &t.id));
        let overlaps = match &self.task {
            Some(t) => {
                let changed: Vec<String> = git::changed(self.top(), target.base_tree.as_deref(), &target.oid)?.into_iter().map(|c| c.path).collect();
                let idle = u64::from(self.policy.drift.reservation_idle_hours) * 3600;
                use05_core::overlap::unmerged(&self.store, self.top(), t, &changed, target.base_commit.as_deref(), idle, now_secs())
            }
            None => Vec::new(),
        };
        // Fresh base: only what the session-start hook recorded, and only while the policy asks.
        let stale = match (&self.task, self.policy.branches.fresh_base) {
            (_, use05_core::policy::Severity::Allow) | (None, _) => None,
            (Some(t), _) => t.fresh.as_ref().and_then(|f| use05_core::fresh::stale(self.top(), f, target.head_commit.as_deref())),
        };
        let mut result = evaluate(&GateInput {
            top: self.top(),
            policy: &self.policy,
            trust: &self.trust,
            task: self.task.as_ref(),
            base_tree: target.base_tree.as_deref(),
            target_tree: &target.oid,
            target_digest: &target.digest,
            now: now_secs(),
            late: &late,
            overlaps: &overlaps,
            log: log.as_ref(),
            stale_base: stale.as_ref(),
            pushing_to,
            default_branch,
        })?;
        if self.policy_uncommitted {
            result.findings.push(use05_core::gate::Finding {
                code: "POLICY_NOT_COMMITTED",
                effect: use05_core::gate::Effect::Warn,
                message: format!("{POLICY_PATH} is not committed, so it is not the rules yet: a push, CI and approvals hold this change to 05's defaults until it is"),
                paths: vec![POLICY_PATH.to_string()],
                next: Some(format!("commit {POLICY_PATH}")),
                approvable: false,
            });
        }
        Ok(result)
    }
}

/// With no task, what is this change relative to? Staged files: HEAD. A commit: where its branch
/// forked from upstream, else its parent.
fn default_base(top: &Path, spec: &str) -> (Option<String>, Option<String>) {
    let tree = |c: &str| git::resolve_tree(top, c).ok();
    if spec == "index" || spec == "worktree" {
        let head = git::head_commit(top);
        return (head.as_deref().and_then(tree), head);
    }
    let Some(commit) = git::resolve_commit(top, spec) else { return (None, None) };
    let upstream = ["@{upstream}", "origin/HEAD", "origin/main", "origin/master"].iter().find_map(|u| git::resolve_commit(top, u));
    let base = upstream
        .and_then(|u| git::merge_base(top, &u, &commit))
        .filter(|b| *b != commit)
        .or_else(|| git::resolve_commit(top, &format!("{spec}^")));
    (base.as_deref().and_then(tree), base)
}


impl Ctx {
    /// Has a person approved this task's current intent card, under the current rules?
    pub fn intent_approved(&self) -> bool {
        use use05_core::evidence::classify;
        use use05_core::time::{now_secs, parse_rfc3339};
        use use05_receipt::{ApprovalScope, Decision};
        let Some(task) = &self.task else { return false };
        let Some(digest) = &task.intent_sha256 else { return false };
        let found = classify(&self.trust, &use05_core::store::find(self.top(), digest));
        let policy = self.policy.digest();
        let now = now_secs();
        let mut ids: Vec<&str> = found
            .approvals
            .iter()
            .filter(|a| {
                let p = &a.statement.predicate;
                p.scope == ApprovalScope::Intent
                    && p.decision == Decision::Approve
                    && a.statement.intent_subject() == Some(digest.as_str())
                    && p.task == task.id
                    && p.policy_sha256 == policy
                    && parse_rfc3339(&p.expires).is_some_and(|t| t > now)
            })
            .map(|a| a.signer.key_id.as_str())
            .collect();
        ids.sort();
        ids.dedup();
        ids.len() as u32 >= self.policy.approvals.min
    }
}

/// The SHA-256 of a tree's content. A tree id fixes its content inside one repository (git itself
/// relies on that), so the digest is computed once per tree and kept in the repository's 05 state,
/// which makes `brief`, `status` and the gate cost the same on a huge repository as on a small one.
pub(crate) fn tree_digest(top: &Path, oid: &str) -> Result<String> {
    let dir = git::dirs(top)?.common.join("05").join("digests");
    let cached = dir.join(oid);
    if let Ok(text) = std::fs::read_to_string(&cached) {
        let text = text.trim();
        if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(text.to_string());
        }
    }
    let identity = use05_runner::identify(top, oid).map_err(|e| Error::new(e.code(), e.to_string()))?;
    // Best effort: a read-only repository just recomputes next time.
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(&cached, &identity.sha256);
    }
    Ok(identity.sha256)
}

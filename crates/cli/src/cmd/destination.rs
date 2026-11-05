//! Destinations (D93): `use05 promote <name>` for a `[[destination]]`, a place outside this
//! repository. `push` sends a branch's head to another remote's branch, by fast-forward only;
//! `export` makes one folder's exact committed content the whole tree of another repository's
//! branch, as one new commit on top of it per sync. Both are judged by the rules an environment is
//! judged by, read from the policy at the source's evaluated head, and their record is filed only
//! once the push went through. Nothing here force-pushes, and nothing touches the person's
//! checkout: what is read from the destination goes into a temporary repository of its own.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use use05_core::evidence::{Trust, classify};
use use05_core::gate::{Decision, Effect, Finding, GateResult};
use use05_core::policy::{Destination, DestinationHow, Environment, POLICY_PATH, Policy, PromoteHow};
use use05_core::promote::{self, Moving, PromoteInput, short};
use use05_core::{fresh, git, store};

use crate::cmd::promote::{self as promotion, Prepared};
use crate::ctx::Ctx;
use crate::report::{Report, Tone};

/// How long reading or pushing to a destination may take.
const REMOTE_TIMEOUT: Duration = Duration::from_secs(60);

/// The destination `name`, as this checkout's policy defines it, else origin's landing branch's
/// (which may name one this checkout has not caught up with). `None` when neither does, or the
/// name is an environment's.
pub fn named(repo: &Path, name: &str) -> Option<Destination> {
    let ctx = Ctx::open_for_commit(repo, None).ok()?;
    if ctx.policy.environment_named(name).is_some() {
        return None;
    }
    if let Some(d) = ctx.policy.destination_named(name) {
        return Some(d.clone());
    }
    let landing = use05_core::branches::landing_for(&ctx.policy, None, ctx.top());
    promotion::policy_on(ctx.top(), &landing).ok().flatten().and_then(|(p, _)| p.destination_named(name).cloned())
}

/// The destination a push goes to, by the policy here: one whose remote is the one git pushes to
/// (`name`, at `url`) and whose branch is `branch`.
pub fn pushed_to<'a>(top: &Path, policy: &'a Policy, name: &str, url: &str, branch: &str) -> Option<&'a Destination> {
    policy.destination.iter().find(|d| d.branch == branch && use05_core::policy::remote_matches(&d.remote, name, url, |r| urls_of(top, r)))
}

/// Every URL a remote here is configured with, to fetch from and to push to. None for a name that
/// is no remote here (a URL, say).
pub(crate) fn urls_of(top: &Path, remote: &str) -> Vec<String> {
    if remote.starts_with('-') || remote.contains(char::is_whitespace) {
        return Vec::new();
    }
    ["url", "pushurl"].iter().filter_map(|k| git::text(top, &["config", "--get-all", &format!("remote.{remote}.{k}")]).ok()).flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>()).filter(|u| !u.is_empty()).collect()
}

/// A temporary bare repository, removed when dropped. It borrows this repository's objects, so
/// what is fetched into it from a destination never enters this one.
pub struct TempRepo {
    pub dir: PathBuf,
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TempRepo {
    fn new(top: &Path) -> Result<TempRepo, String> {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("use05-destination-{}-{nanos}", std::process::id()));
        git::run(&std::env::temp_dir(), &["init", "--quiet", "--bare", &dir.display().to_string()]).map_err(|e| e.message)?;
        let repo = TempRepo { dir };
        let objects = git::dirs(top).map_err(|e| e.message)?.common.join("objects");
        let objects = objects.canonicalize().unwrap_or(objects);
        std::fs::write(repo.dir.join("objects").join("info").join("alternates"), format!("{}\n", objects.display())).map_err(|e| e.to_string())?;
        Ok(repo)
    }

    /// `git <args>` against it, from this repository's top, so a remote given as a relative path
    /// means what it means here; never asking for a password, and giving up after a while.
    fn remote_git(&self, top: &Path, args: &[&str]) -> Result<String, String> {
        let dir = self.dir.display().to_string();
        let mut all = vec!["--git-dir", dir.as_str()];
        all.extend(args);
        fresh::quiet_git_output(top, &all, REMOTE_TIMEOUT)
    }
}

/// The destination as it was read: where it is, and its branch's head there.
pub struct Remote {
    /// What a push from this repository names: the remote's name here, or its URL.
    pub push_to: String,
    pub push_url: String,
    /// The branch's head there. `None`: it does not exist yet, and promoting creates it.
    pub head: Option<String>,
    /// Holds what was fetched: the destination's branch at `refs/heads/destination`.
    pub scratch: TempRepo,
    /// For an export: the folder's tree at the evaluated head.
    pub tree: Option<String>,
}

/// Read the destination's branch, into a temporary repository.
fn read(top: &Path, d: &Destination) -> Result<Remote, Report> {
    let url = |push: bool| {
        let mut args = vec!["remote", "get-url"];
        if push {
            args.push("--push");
        }
        args.push(d.remote.as_str());
        git::text(top, &args).ok().filter(|u| !u.is_empty()).unwrap_or_else(|| d.remote.clone())
    };
    let (fetch_url, push_url) = (url(false), url(true));
    // Never taken for one of git's options.
    if fetch_url.starts_with('-') || push_url.starts_with('-') {
        return Err(Report::error("promote", "POLICY_INVALID", format!("{} is configured with a URL that starts with -, which git would take for an option", d.remote), None, 6));
    }
    let unreachable = |e: String| Report::error("promote", "DESTINATION_UNREACHABLE", format!("{} could not be read at {fetch_url}: {e}", d.name), Some(format!("check that this machine can reach it (git ls-remote {fetch_url}), then: use05 promote {} --check", d.name)), 4);
    let scratch = TempRepo::new(top).map_err(|e| Report::error("promote", "PROMOTE_MOVE_FAILED", format!("could not make a temporary repository: {e}"), None, 4))?;
    let refspec = format!("refs/heads/{}", d.branch);
    let listed = scratch.remote_git(top, &["ls-remote", "--heads", &fetch_url, &refspec]).map_err(unreachable)?;
    let head = match listed.lines().any(|l| l.split_whitespace().nth(1) == Some(refspec.as_str())) {
        false => None,
        true => {
            scratch.remote_git(top, &["fetch", "--quiet", "--no-tags", &fetch_url, &format!("+{refspec}:refs/heads/destination")]).map_err(unreachable)?;
            git::resolve_commit(&scratch.dir, "refs/heads/destination")
        }
    };
    Ok(Remote { push_to: d.remote.clone(), push_url, head, scratch, tree: None })
}

/// The tree of `folder` (empty: the whole tree) in `commit`, when it is a folder there.
fn folder_tree(top: &Path, commit: &str, folder: &str) -> Option<String> {
    if folder.is_empty() {
        return git::resolve_tree(top, commit).ok();
    }
    let spec = format!("{commit}:{folder}");
    let id = git::text(top, &["rev-parse", "--verify", "--quiet", &spec]).ok()?;
    (git::text(top, &["cat-file", "-t", &id]).ok().as_deref() == Some("tree")).then_some(id)
}

/// The commit `head` alone, as one that moves.
fn only(top: &Path, head: &str) -> use05_core::Result<Vec<Moving>> {
    let parent = git::resolve_commit(top, &format!("{head}^"));
    let mut all = promote::commits(top, head, parent.as_deref())?;
    all.retain(|c| c.id == head);
    Ok(all)
}

/// Gather what promoting to the destination `name` would send and judge it. Reads git, the
/// receipts and the destination, and fetches from origin; changes nothing else.
pub fn prepare(repo: &Path, name: &str) -> Result<(Prepared<Destination>, Remote), Report> {
    prepare_expecting(repo, name, None)
}

/// As [`prepare`], judged against the source head an earlier evaluation saw.
pub fn prepare_expecting(repo: &Path, name: &str, expected: Option<&str>) -> Result<(Prepared<Destination>, Remote), Report> {
    let fail = |e| Report::from_core("promote", e);
    let here = Ctx::open_for_commit(repo, None).map_err(fail)?;
    let top: PathBuf = here.top().to_path_buf();
    let Some(asked) = named(repo, name) else {
        return Err(Report::error("promote", "UNKNOWN_ENVIRONMENT", format!("there is no environment or destination {name:?} here"), Some(format!("name it in {POLICY_PATH} ([[environment]] or [[destination]])")), 6));
    };
    let landing = use05_core::branches::landing_for(&here.policy, None, &top);
    // The branch whose head is judged: a push's `from`, else where work lands.
    let branch = asked.push_from(&landing).unwrap_or(&landing).to_string();
    let mut notes = Vec::new();
    promotion::fetch(&top, &[&branch], &mut notes);
    let Some(source_ref) = promotion::branch_ref(&top, &branch) else {
        return Err(Report::error("promote", "SOURCE_NOT_FOUND", format!("there is no branch {branch} here or on origin to promote to {name} from"), Some(format!("push {branch} first, or check [[destination]] in {POLICY_PATH}")), 6));
    };
    let source_head = git::resolve_commit(&top, &source_ref).expect("resolved above");

    // The rules are the policy at the evaluated head (D93): the destination's branch is in another
    // repository, so this one's source side judges it.
    let mut findings = Vec::new();
    let at_head = Policy::load_at(&top, &source_ref).map_err(fail)?;
    let head_def = at_head.as_ref().and_then(|p| p.destination_named(name));
    let (mut policy, rules_from) = match head_def {
        Some(d) if d.push_from(&landing).unwrap_or(&landing) == branch => (at_head.clone().expect("named there"), format!("{branch}'s policy ({})", promotion::ref_label(&source_ref))),
        other => {
            let why = if other.is_some() { format!("the policy at {branch}'s head ({}) promotes {name} from another branch", short(&source_head)) } else { format!("the policy at {branch}'s head ({}) does not name {name}", short(&source_head)) };
            let mut f = Finding::new("DESTINATION_NOT_AT_HEAD", Effect::Deny, format!("{why}, and a destination is judged by the rules there"));
            f.next = Some(format!("land the policy that names it on {branch} first, then: use05 promote {name}"));
            findings.push(f);
            (here.repo_policy.clone(), "this checkout's policy".to_string())
        }
    };
    if let Some((_, floor)) = use05_core::org::load().map_err(fail)? {
        policy.tighten(&floor);
    }
    policy.check_effective().map_err(fail)?;
    let dest = policy.destination_named(name).cloned().unwrap_or(asked);
    let mut remote = read(&top, &dest)?;
    let shown = format!("{} on {}", dest.branch, dest.remote);
    if remote.head.is_none() {
        findings.push(Finding::new("PROMOTE_CREATES_BRANCH", Effect::Info, format!("{shown} does not exist yet: promoting creates it")));
    }
    let source_env = policy.environment.iter().find(|e| e.branch == branch).cloned();
    let source = source_env.clone().unwrap_or_else(|| Environment::new(&branch, &branch, None));
    let source_tree = git::resolve_tree(&top, &source_head).map_err(fail)?;
    let scratch = remote.scratch.dir.clone();
    let target_tree = remote.head.as_deref().map(|h| git::resolve_tree(&scratch, h)).transpose().map_err(fail)?;

    let (moving, target_only, changed, numstat) = match dest.how {
        DestinationHow::Push => {
            // The destination's history is in the temporary repository, beside this one's.
            let moving = promote::commits(&scratch, &source_head, remote.head.as_deref()).map_err(fail)?;
            let theirs = match &remote.head {
                Some(h) => promote::commits(&scratch, h, Some(&source_head)).map_err(fail)?,
                None => Vec::new(),
            };
            let ahead = promote::target_ahead(&scratch, &theirs, PromoteHow::FastForward);
            let changed = git::changed(&scratch, target_tree.as_deref(), &source_tree).map_err(fail)?.into_iter().map(|c| c.path).collect();
            let numstat = git::numstat(&scratch, target_tree.as_deref(), &source_tree).map_err(fail)?;
            (moving, ahead, changed, numstat)
        }
        DestinationHow::Export => {
            let folder = dest.folder().unwrap_or_default();
            let Some(tree) = folder_tree(&top, &source_head, &folder) else {
                return Err(Report::error("promote", "EXPORT_FOLDER_MISSING", format!("{name} exports {folder}/, which is not a folder at {branch}'s head ({})", short(&source_head)), Some(format!("check `from` of the [[destination]] {name:?} in {POLICY_PATH}")), 6));
            };
            remote.tree = Some(tree.clone());
            if target_tree.as_deref() == Some(tree.as_str()) {
                (Vec::new(), Vec::new(), Vec::new(), Default::default())
            } else {
                // What changed the folder since the source commit the last sync names.
                let last = remote.head.as_deref().and_then(|h| git::text(&scratch, &["log", "-1", "--format=%B", h]).ok()).and_then(|m| promote::synced_from(&m)).filter(|c| git::run(&top, &["merge-base", "--is-ancestor", c, &source_head]).is_ok());
                let paths: Vec<&str> = if folder.is_empty() { Vec::new() } else { vec![folder.as_str()] };
                let mut moving = promote::commits_touching(&top, &source_head, last.as_deref(), &paths).map_err(fail)?;
                // The folder differs, yet no commit since the last sync changed it: the head carries it.
                if moving.is_empty() {
                    moving = only(&top, &source_head).map_err(fail)?;
                }
                let inside = |p: String| if folder.is_empty() { p } else { format!("{folder}/{p}") };
                let changed = git::changed(&scratch, target_tree.as_deref(), &tree).map_err(fail)?.into_iter().map(|c| inside(c.path)).collect();
                let numstat = git::numstat(&scratch, target_tree.as_deref(), &tree).map_err(fail)?.into_iter().map(|(p, n)| (inside(p), n)).collect();
                (moving, Vec::new(), changed, numstat)
            }
        }
    };

    // The source head's checks, read exactly as the gate reads a tree's.
    let trust = Trust::new(&policy, true);
    let digest = crate::ctx::tree_digest(&top, &source_tree).map_err(fail)?;
    let (checks, check_findings) = use05_core::gate::checks_at(&top, &policy, &trust, &source_tree, &digest, &changed, &format!(" --tree {}", short(&source_head)));
    findings.extend(check_findings.into_iter().filter(|f| f.code == "TREE_DIGEST_MISMATCH"));
    let found = classify(&trust, &store::find_all(&top));
    let now = use05_core::time::now_secs();
    let accept = &policy.evidence.accept;
    let deployments = if source_env.is_some() { promotion::deployments_of(&found, accept, &source.name, &source_head) } else { Vec::new() };
    let (signoffs, bypasses) = promotion::signed_for(&found, &trust, &policy, &dest, &source.name, &source_head, now);
    let untasked = promote::untasked(&top, &moving, &found, accept);
    // Loosening is weighed against the rules where work lands on origin (D93).
    let loosened = match (promotion::policy_on(&top, &landing).map_err(fail)?, &at_head) {
        (Some((before, _)), Some(after)) if before != *after => use05_policy_edit::guard::loosens(&before, after),
        _ => Vec::new(),
    };
    let input = PromoteInput {
        policy: &policy,
        target: &dest,
        source: &source.name,
        source_deployed: source_env.is_some(),
        source_head: source_head.clone(),
        target_head: remote.head.clone(),
        expected_source: expected.map(str::to_string),
        delta: moving.iter().map(|c| c.id.clone()).collect(),
        target_only,
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
        hotfixes: Vec::new(),
    };
    let result = promote::evaluate(&input);
    let prepared = Prepared {
        result,
        rules_from,
        source_ref: promotion::ref_label(&source_ref),
        target_ref: remote.head.as_ref().map(|_| shown.clone()),
        moving,
        numstat,
        notes,
        questions: dest.sign_off.as_ref().map(|s| s.questions.clone()).unwrap_or_default(),
        confirm: dest.confirm.iter().map(|c| c.text.clone()).collect(),
        org: here.org.clone(),
        accepts_local: accept.contains(&use05_core::policy::Role::Local),
        policy,
        env: dest,
        source,
        top,
        merged_tree: None,
    };
    Ok((prepared, remote))
}

/// What `promote` cannot do for a destination: it has no deploy to confirm, no rollback, and no
/// environment above it to merge back from.
pub fn not_for_a_destination(name: &str, flag: &str) -> Report {
    Report::error("promote", "NOT_FOR_A_DESTINATION", format!("{name} is a destination, and {flag} is for environments: a destination has no deploy to confirm, no rollback and nothing to merge back"), Some(format!("use05 promote {name} --check")), 6)
}

/// `use05 promote <destination> --check`: evaluate every rule, change nothing.
pub fn run_check(repo: &Path, name: &str) -> Report {
    match prepare(repo, name) {
        Ok((p, _)) => promotion::page(&p, "PROMOTE_CHECKED", "", &promotion::strength(&p)),
        Err(r) => r,
    }
}

/// Make the export's commit in the temporary repository: the folder's tree on top of the
/// destination's head (or as its first commit), its message saying what was copied, with the
/// promotion's trailers. Nothing is pushed.
fn sync_commit(p: &Prepared<Destination>, remote: &Remote) -> Result<String, Report> {
    let r = &p.result;
    let tree = remote.tree.clone().expect("an export reads its folder's tree");
    let message = promote::export_message(r, &p.env.folder().unwrap_or_default());
    // Named as this repository's commits are; CI often has no name set.
    let config = |key: &str| git::text(&p.top, &["config", key]).ok().filter(|v| !v.is_empty());
    let (name, email) = (config("user.name").unwrap_or_else(|| "use05".into()), config("user.email").unwrap_or_else(|| "use05@localhost".into()));
    let (name, email) = (format!("user.name={name}"), format!("user.email={email}"));
    let mut args = vec!["-c", name.as_str(), "-c", email.as_str(), "commit-tree", tree.as_str(), "-F", "-"];
    if let Some(parent) = &remote.head {
        args.extend(["-p", parent.as_str()]);
    }
    let out = git::run_with(&remote.scratch.dir, &args, &[], Some(message.as_bytes())).map_err(|e| Report::error("promote", "PROMOTE_MOVE_FAILED", format!("could not make the sync commit: {}", e.message), None, 4))?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// `use05 promote <destination>`: judge it, and when the rules allow, push the branch's head (a
/// `push`) or the export's new commit (an `export`) to the destination, never forced; then file
/// the signed record. `interactive`: a person at a terminal, with no `--json`.
pub fn run(repo: &Path, name: &str, interactive: bool) -> Report {
    let (p, remote) = match prepare(repo, name) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(held) = promotion::held(&p) {
        return held;
    }
    let r = &p.result;
    let top = p.top.clone();
    let person = !r.agent_allowed;
    if person {
        if let Err(refused) = crate::cmd::approve::person_here("promote", interactive, &format!("promoting to {name}")) {
            return refused;
        }
    }
    let how = p.env.how;
    let result_commit = match how {
        DestinationHow::Push => r.source_head.clone(),
        DestinationHow::Export => match sync_commit(&p, &remote) {
            Ok(c) => c,
            Err(r) => return r,
        },
    };
    let runner = crate::cmd::deploy::runner_key();
    let by = crate::cmd::deploy::by_whom(&top, &p.policy, person, runner.is_some());
    let statement = promote::record(r, &result_commit, &by, use05_core::time::now_rfc3339());
    let shown = format!("{} on {}", p.env.branch, p.env.remote);
    let mut signatures = Vec::new();
    if person {
        eprintln!("You are about to promote {} from {} to {name}: {}, by {}.", short(&r.source_head), r.source_env, promotion::summary(&p), r.how);
        eprintln!("  {shown} moves {}; the record is signed and filed once the push goes through.", r.target_head.as_deref().map_or_else(|| format!("to {}, created", short(&result_commit)), |t| format!("from {} to {}", short(t), short(&result_commit))));
        for f in r.findings.iter().filter(|f| f.effect >= Effect::Warn) {
            eprintln!("  - {}: {}", f.code, f.message);
        }
        match crate::cmd::approve::sign_as_person(&statement, &format!("promote {} to {name}", short(&r.source_head)), false, "promote") {
            Ok((envelope, _)) => signatures = envelope.signatures,
            Err(refused) => return refused,
        }
    }

    // Judged once more just before the push, against the commit that was evaluated and shown.
    let again = match prepare_expecting(repo, name, Some(&r.source_head)) {
        Ok((a, _)) => a,
        Err(r) => return r,
    };
    if let Some(held) = promotion::held(&again) {
        return held;
    }
    if again.result.target_head != r.target_head {
        return Report::error("promote", "PROMOTE_TARGET_MOVED", format!("{shown} moved while this ran; nothing was pushed"), Some(format!("use05 promote {name}")), 4);
    }
    // A push goes through this repository's pre-push hook, like any; an export's commit is in the
    // temporary repository, whose push no hook of this one sees.
    let pushed = match how {
        DestinationHow::Push => promotion::push_to(&top, &remote.push_to, &p.env.branch, &result_commit),
        DestinationHow::Export => {
            let refspec = format!("{result_commit}:refs/heads/{}", p.env.branch);
            remote.scratch.remote_git(&top, &["-c", "core.hooksPath=/dev/null", "push", "--quiet", &remote.push_url, &refspec]).map(|_| ()).map_err(|e| promotion::refusal(&e))
        }
    };
    if let Err(line) = pushed {
        let mut refused = Report::error("promote", "PROMOTE_PUSH_FAILED", format!("the push to {shown} was refused: {line}"), Some(format!("fix what refused it, then: use05 promote {name}")), 4);
        let at = r.target_head.as_deref().map_or_else(|| "still does not exist".to_string(), |t| format!("is where it was ({})", short(t)));
        refused.notes = vec![format!("Nothing moved: {shown} {at}, and no promotion record was written.")];
        refused.details = json!({ "env": r.target_env, "from": r.source_env, "source_head": r.source_head, "target_head": r.target_head, "pushed": false, "git": line });
        return refused;
    }

    let mut notes = Vec::new();
    let filed = promotion::file_record(&top, &statement, &statement.predicate.source_commit, signatures, runner.as_ref(), "The push went through, but");
    let branch = filed.branch.clone();
    notes.extend(filed.notes);
    notes.extend(promotion::push_receipts(&top));
    if how == DestinationHow::Push {
        notes.push("A push to a destination makes no commit of its own, so the promotion's trailers are only in its record.".to_string());
    }
    for f in r.findings.iter().filter(|f| f.effect >= Effect::Warn) {
        notes.push(format!("{} {}: {}", format!("{:?}", f.effect).to_lowercase(), f.code, f.message));
    }
    notes.push(promotion::how_strong(&p.env, p.accepts_local));
    let rules = r.rules.iter().map(|x| format!("{} {}", x.rule, promote::outcome_word(x.outcome))).collect::<Vec<_>>().join(" · ");
    let what = match how {
        DestinationHow::Push => format!("{} · {} {} ({})", promotion::summary(&p), r.how, short(&r.source_head), p.source_ref),
        DestinationHow::Export => format!("{} · {}/ of {} ({}) as one commit", promotion::summary(&p), p.env.folder().unwrap_or_default(), short(&r.source_head), p.source_ref),
    };
    let mut rows = vec![("moved".to_string(), what), ("pushed".to_string(), format!("{shown}, now at {}", short(&result_commit))), ("rules".to_string(), rules), ("by".to_string(), by.clone())];
    if let Some(b) = &branch {
        rows.push(("record".to_string(), format!("on {b}")));
    }
    let (code, tone, headline, next) = if filed.on_origin {
        ("PROMOTED", Tone::Good, format!("Promoted {} → {}: {} ({})", r.source_env, r.target_env, short(&r.source_head), r.how), None)
    } else {
        let next = match &branch {
            Some(b) => format!("git push origin {b}"),
            None => "fix this machine's key (use05 doctor)".to_string(),
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
            "destination": true,
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
        }),
        exit: 0,
    }
}

/// The pre-push hook's judgement of a push from this repository to a destination's branch: a
/// `push` destination's rules, as `--check` judges them, and the pushed commit must be exactly
/// the source head they judged. An `export` is synced only by `use05 promote`, from a copy of its
/// folder, so a push of this repository's history to it is always held.
pub fn judge_push(repo: &Path, name: &str, pushed: &str) -> Result<GateResult, Report> {
    let (p, _remote) = prepare(repo, name)?;
    let r = &p.result;
    let pushed = git::resolve_commit(&p.top, pushed).unwrap_or_else(|| pushed.to_string());
    if r.target_head.as_deref() == Some(pushed.as_str()) {
        return Ok(GateResult::of_findings(Decision::Allow, Vec::new(), r.policy_sha256.clone()));
    }
    let mut findings = r.findings.clone();
    let mut decision = r.decision;
    let held = |message: String, next: String| Finding { code: "PROMOTE_NOT_EVALUATED_MOVE", effect: Effect::Deny, message, paths: Vec::new(), next: Some(next), approvable: false };
    if p.env.how == DestinationHow::Export {
        findings.insert(0, held(format!("{name} is an export of {}/: only use05 promote {name} syncs it, as one commit holding that folder; this push would send this repository's history", p.env.folder().unwrap_or_default()), format!("sync it with 05: use05 promote {name}")));
        decision = Decision::Deny;
    } else if pushed != r.source_head {
        findings.insert(0, held(format!("what is pushed to {name} ({}) is not the promotion 05 judged: {}'s head {}", short(&pushed), r.source_env, short(&r.source_head)), format!("promote it with 05: use05 promote {name}")));
        decision = Decision::Deny;
    }
    if !r.agent_allowed && !crate::cmd::gate::person_at_terminal() && !findings.iter().any(|f| f.code == "AGENT_MAY_NOT_PROMOTE") {
        let mut f = Finding::new("AGENT_MAY_NOT_PROMOTE", Effect::Deny, format!("{name} is kept for people, and nothing here shows a person pushing: there is no terminal"));
        f.next = Some(format!("a person pushes it at their terminal, or runs: use05 promote {name}"));
        findings.insert(0, f);
        decision = Decision::Deny;
    }
    Ok(GateResult::of_findings(decision, findings, r.policy_sha256.clone()))
}

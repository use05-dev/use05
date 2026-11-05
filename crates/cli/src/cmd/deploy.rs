//! A promotion's deploy (D93 4–5): `use05 promote <env> --confirm` asks the environment's probes
//! which commit it runs and runs its smoke checks; a deploy that is not confirmed is reported,
//! reverted with a new commit, or handed to the policy's rollback command; `--rollback` makes
//! that revert by hand. The pre-push hook knows such a revert as a move of its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use use05_core::evidence::{Trust, classify};
use use05_core::gate::{Decision, Effect, Finding};
use use05_core::policy::{Environment, OnFailure, POLICY_PATH, Policy};
use use05_core::promote::{self, Answer, DeployCommand, DeployRunner, short};
use use05_core::{fresh, git, store};
use use05_receipt::DeployAction;

use crate::cmd::promote::{Filed, Rules, actor, branch_ref, file_record, follow_local, push_receipts, push_target, ref_label, rules_for};
use crate::report::{Report, Tone};

/// Runs a deploy's probes, smoke checks and rollback command as checks run (D93): through the
/// runner, in an export of the deployed commit's exact tree, with a scrubbed environment, only the
/// variables each names (as far as an organisation floor allows), its time limit, and as the
/// `USE05_CHECK_USER` user when that is set. A probe keeps its export from one try to the next; a
/// smoke check gets its own, as a check does.
struct Live {
    top: PathBuf,
    commit: String,
    lfs: bool,
    allow: Option<Vec<String>>,
    exports: HashMap<String, use05_runner::Export>,
    /// `USE05_TEST_NO_SLEEP` is internal, for 05's own tests only, and not documented: a wait
    /// between tries moves a pretend clock instead. It can only shorten a wait, never confirm.
    pretend: bool,
    slept: u64,
    notes: Vec<String>,
}

impl Live {
    fn new(top: &Path, policy: &Policy, commit: &str) -> Live {
        let pretend = std::env::var_os("USE05_TEST_NO_SLEEP").is_some();
        Live { top: top.to_path_buf(), commit: commit.to_string(), lfs: policy.evidence.lfs, allow: policy.env.allow.clone(), exports: HashMap::new(), pretend, slept: 0, notes: Vec::new() }
    }

    /// Run one command with the variables it names, and `extra` set for it by 05.
    fn run_with(&mut self, c: &DeployCommand<'_>, extra: &[(String, String)]) -> Answer {
        let key = format!("{} {}", c.kind, c.name);
        if c.kind != "probe" {
            self.exports.remove(&key);
        }
        if !self.exports.contains_key(&key) {
            match use05_runner::Export::new(&self.top, &self.commit, self.lfs) {
                Ok(e) => {
                    self.exports.insert(key.clone(), e);
                }
                Err(e) => return Answer::NotRun(format!("could not export {}: {e}", short(&self.commit))),
            }
        }
        let mut pass = Vec::new();
        for name in c.env {
            if self.allow.as_ref().is_some_and(|a| !a.contains(name)) {
                let note = format!("{name} was not passed to the {key}: the organisation's policy does not allow it");
                if !self.notes.contains(&note) {
                    self.notes.push(note);
                }
            } else if let Ok(v) = std::env::var(name) {
                pass.push((name.clone(), v));
            }
        }
        pass.extend(extra.iter().cloned());
        let user = crate::cmd::prove::check_user();
        match self.exports[&key].run(c.run, c.dir, std::time::Duration::from_secs(c.timeout_secs), &pass, user.as_deref()) {
            Ok(ran) => Answer::Ran {
                passed: ran.status == use05_receipt::Status::Passed,
                timed_out: ran.status == use05_receipt::Status::TimedOut,
                stdout: String::from_utf8_lossy(&ran.stdout_tail).into_owned(),
                stdout_sha256: ran.stdout_sha256,
            },
            Err(use05_runner::RunnerError::Spawn { program, .. }) => Answer::NotRun(format!("could not run {program}")),
            Err(e) => Answer::NotRun(e.to_string()),
        }
    }
}

impl DeployRunner for Live {
    fn run(&mut self, c: &DeployCommand<'_>) -> Answer {
        self.run_with(c, &[])
    }
    fn now(&self) -> u64 {
        use05_core::time::now_secs() + self.slept
    }
    fn sleep(&mut self, secs: u64) {
        if self.pretend {
            self.slept += secs;
        } else {
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
    }
}

/// A revert 05 pushed: the new commit, the rollback point whose files it holds, and the head it
/// reverts.
struct Reverted {
    commit: String,
    to: String,
    reverts: String,
    filed: Filed,
    notes: Vec<String>,
}

/// A deploy: what confirming it found, its record, and what 05 did about a failure.
pub(crate) struct Deploy {
    env: String,
    branch: String,
    commit: String,
    confirmed: bool,
    probes: usize,
    /// Probes ran and did not all show it, or a smoke check failed: on_failure applies.
    pub(crate) failed: bool,
    summary: String,
    said: Vec<(String, String)>,
    action: DeployAction,
    filed: Filed,
    /// The revert 05 pushed, and what confirming it found.
    revert: Option<(Reverted, Box<Deploy>)>,
    /// What the rollback command did.
    rollback: Option<String>,
    pub(crate) notes: Vec<String>,
    pub(crate) next: Option<String>,
}

impl Deploy {
    pub(crate) fn rows(&self) -> Vec<(String, String)> {
        let mut rows = vec![("deploy".to_string(), self.summary.clone())];
        rows.extend(self.said.iter().cloned());
        if let Some(line) = &self.rollback {
            rows.push(("rollback ran".into(), line.clone()));
        }
        if let Some((r, d)) = &self.revert {
            rows.push(("reverted".into(), format!("{} → origin, now at {}: the files of {}, as a new commit", self.branch, short(&r.commit), short(&r.to))));
            rows.push(("its deploy".into(), d.summary.clone()));
        }
        rows
    }

    /// What 05 did about it, for the end of a headline.
    pub(crate) fn done(&self) -> String {
        match (&self.action, &self.revert) {
            (DeployAction::Reverted, Some((r, _))) => format!("; 05 reverted {} to {}", self.env, short(&r.to)),
            (DeployAction::RollbackCommand, _) => format!("; 05 ran {}'s rollback command", self.env),
            _ => String::new(),
        }
    }

    pub(crate) fn details(&self) -> serde_json::Value {
        json!({
            "env": self.env,
            "commit": self.commit,
            "confirmed": self.confirmed,
            "probes": self.probes,
            "summary": self.summary,
            "checks": self.said.iter().map(|(name, said)| json!({ "name": name, "said": said })).collect::<Vec<_>>(),
            "action": self.action,
            "record_branch": self.filed.branch,
            "record_on_origin": self.filed.on_origin,
            "rollback": self.rollback,
            "revert": self.revert.as_ref().map(|(r, d)| json!({ "commit": r.commit, "to": r.to, "reverts": r.reverts, "record_branch": r.filed.branch, "deploy": d.details() })),
        })
    }
}

/// The rollback point an automatic revert or rollback command goes back to: the newest counted
/// promotion record into `env` must be the one that moved it to `commit`, and say where it was.
fn point_for(top: &Path, policy: &Policy, env: &Environment, commit: &str) -> Result<promote::RollbackPoint, String> {
    let found = classify(&Trust::new(policy, true), &store::find_all(top));
    match promote::rollback_point(top, &found, &policy.evidence.accept, &env.name, commit) {
        None => Err(format!("no promotion record into {} that counts here says where {} was before", env.name, env.branch)),
        Some(p) if p.result != commit => Err(format!("the newest promotion into {} that counts here moved it to {}, not to {}", env.name, short(&p.result), short(commit))),
        Some(p) if p.to.is_none() => Err(format!("that promotion created {}, so there is nothing to go back to", env.branch)),
        Some(p) => Ok(p),
    }
}

/// Confirm that `env` runs `commit` and file the deploy's record (signed like a promotion's).
/// When `act` and it is not confirmed, do what `on_failure` says: report it, revert (then confirm
/// the revert, once, and do nothing more), or run `rollback`. `may_act` says who acts on a
/// failure here: `Ok(true)` a person at the terminal, `Ok(false)` an agent or CI the policy lets
/// act, `Err(why)` nobody here. Where a person acts, 05 does not revert by itself: a revert there
/// is signed by the person's key, which is not asked for after the wait; they run `--rollback`.
/// No probes: nothing is claimed, and nothing is done.
#[allow(clippy::too_many_arguments)]
pub(crate) fn confirm_deploy(top: &Path, policy: &Policy, env: &Environment, commit: &str, by: &str, runner_key: Option<&use05_receipt::SigningKey>, may_act: Result<bool, String>, act: bool) -> Deploy {
    let mut live = Live::new(top, policy, commit);
    let c = promote::confirm(env, commit, &mut live);
    let mut record = c.deployment;
    // Dated when the confirmation ended, by this machine's clock.
    record.created = use05_core::time::now_rfc3339();
    let probes = record.probes.len();
    let smoke_failed = record.smoke.iter().any(|s| !s.passed);
    let failed = !record.confirmed && (probes > 0 || smoke_failed);
    let (name, shown) = (env.name.as_str(), short(commit));
    let summary = match (record.confirmed, probes, smoke_failed) {
        (true, _, _) => format!("confirmed: {name} runs {shown}"),
        (false, 0, false) => format!("no probes: 05 cannot tell what {name} runs"),
        (false, 0, true) => format!("no probes: 05 cannot tell what {name} runs, and a smoke check failed"),
        (false, _, true) if record.probes.iter().all(|p| p.matched) => format!("not confirmed: {name} runs {shown}, but a smoke check failed"),
        (false, _, _) => format!("not confirmed: {name} did not show it runs {shown}"),
    };
    let mut notes = Vec::new();
    if probes == 0 {
        notes.push(format!("Not confirmed: give {name} a probe ([[environment.probe]] in {POLICY_PATH}), a command that prints the commit {name} runs; then run use05 promote {name} --confirm."));
    }
    let (mut revert, mut rollback, mut next) = (None, None, None);
    let below = policy.source_of(env).map(|s| s.name.clone());
    if failed && act {
        let by_hand = format!("use05 promote {name} --rollback");
        next = Some(by_hand.clone());
        let ready = || point_for(top, policy, env, commit).and_then(|point| may_act.clone().map(|person| (point, person)));
        match env.on_failure() {
            OnFailure::Report => notes.push(format!("Nothing was rolled back: the policy says to report a deploy that is not confirmed (on_failure = \"report\"). To roll it back: {by_hand}")),
            OnFailure::Revert => match ready() {
                Err(why) => notes.push(format!("05 did not revert {name}: {why}.")),
                Ok((_, true)) => notes.push(format!("05 did not revert {name} by itself: {name} is kept for people, so a revert is signed with your key. To roll it back: {by_hand}")),
                Ok((point, false)) => match revert_to(top, policy, env, commit, &point, "deploy not confirmed", by, false, runner_key) {
                    Err(refused) => notes.push(format!("05 could not revert {name}: {}.", refused.headline)),
                    Ok(r) => {
                        record.action = DeployAction::Reverted;
                        notes.extend(r.notes.clone());
                        if let Some(below) = &below {
                            notes.push(format!("{name} now has a commit {below} lacks (the revert), so promoting into {name} is refused until {below} has it too."));
                        }
                        // Confirmed once more, and nothing more: a revert is never reverted.
                        let again = confirm_deploy(top, policy, env, &r.commit, by, runner_key, Err("a revert is not undone".into()), false);
                        next = Some(if again.failed || again.probes == 0 {
                            format!("look at {name}: it was reverted to {}'s files, and 05 could not confirm it runs {}", short(&r.to), short(&r.commit))
                        } else {
                            "fix what failed where work lands, then promote it again".to_string()
                        });
                        notes.extend(again.notes.clone());
                        revert = Some((r, Box::new(again)));
                    }
                },
            },
            OnFailure::Command => match ready().and_then(|(point, _)| rollback_at(top, env, point)) {
                Err(why) => notes.push(format!("05 did not run {name}'s rollback command: {why}.")),
                Ok((to, known_good)) => {
                    // The command, its variables and its time limit as the rollback point's policy
                    // has them, run in a copy of the rollback point's files: the known good ones,
                    // not those of the deploy that failed.
                    let extra = [("USE05_ENV".to_string(), name.to_string()), ("USE05_ROLLBACK_TO".to_string(), to.clone())];
                    let command = DeployCommand { kind: "rollback", name: "command", run: &known_good.rollback, env: &known_good.rollback_env, dir: None, timeout_secs: known_good.rollback_timeout_secs };
                    let said = crate::report::command_text(&known_good.rollback);
                    let mut at_point = Live::new(top, policy, &to);
                    // (ran, passed, what it did)
                    let (ran, passed, line) = match at_point.run_with(&command, &extra) {
                        Answer::Ran { passed: true, .. } => (true, true, format!("{said} passed: {name} goes back to {}", short(&to))),
                        Answer::Ran { timed_out: true, .. } => (true, false, format!("{said} ran out of time ({}s)", command.timeout_secs)),
                        Answer::Ran { .. } => (true, false, format!("{said} failed")),
                        Answer::NotRun(why) => (false, false, why),
                    };
                    if ran {
                        record.action = DeployAction::RollbackCommand;
                    }
                    next = Some(if passed {
                        format!("look at {name}: its rollback command went back to {}; then fix what failed where work lands", short(&to))
                    } else {
                        format!("roll {name} back by hand: its rollback command did not pass")
                    });
                    rollback = Some(line);
                    notes.extend(std::mem::take(&mut at_point.notes));
                }
            },
        }
    }
    notes.extend(std::mem::take(&mut live.notes));
    let statement = use05_receipt::Statement::new(vec![use05_receipt::commit_subject(commit)], record.clone());
    let filed = file_record(top, &statement, commit, Vec::new(), runner_key, "The deploy was checked, but");
    notes.extend(filed.notes.clone());
    Deploy { env: name.to_string(), branch: env.branch.clone(), commit: commit.to_string(), confirmed: record.confirmed, probes, failed, summary, said: c.said, action: record.action, filed, revert, rollback, notes, next }
}

/// The rollback point and the environment as the policy committed there names it, with the
/// rollback command to run: the known good one, not the one the failed deploy brought.
fn rollback_at(top: &Path, env: &Environment, point: promote::RollbackPoint) -> Result<(String, Environment), String> {
    let to = point.to.ok_or_else(|| format!("there is no rollback point: the promotion created {}", env.branch))?;
    let policy = Policy::load_at(top, &to).map_err(|e| format!("the policy at {} could not be read ({})", short(&to), e.message))?;
    match policy.and_then(|p| p.environment_named(&env.name).cloned()) {
        Some(e) if !e.rollback.is_empty() => Ok((to, e)),
        _ => Err(format!("the policy at the rollback point {} names no rollback command for {}", short(&to), env.name)),
    }
}

/// A commit whose tree is `tree` and whose only parent is `parent`, made without a checkout.
fn commit_tree(top: &Path, tree: &str, parent: &str, message: &str) -> Result<String, Report> {
    let named = |key: &str| git::text(top, &["config", key]).ok().is_some_and(|v| !v.is_empty());
    let mut args: Vec<&str> = Vec::new();
    if !named("user.name") || !named("user.email") {
        args.extend(["-c", "user.name=use05", "-c", "user.email=use05@localhost"]);
    }
    args.extend(["commit-tree", tree, "-p", parent, "-m", message]);
    git::text(top, &args).map(|c| c.trim().to_string()).map_err(|e| Report::error("promote", "ROLLBACK_FAILED", format!("could not make the revert commit: {}", e.message), None, 4))
}

/// Revert `env`'s branch from `head` to the files of the rollback point (D93): a new commit on
/// `head` holding the rollback point's tree, pushed to origin through the pre-push hook like any
/// push, never by force, and its record filed (a promotion record whose `how` is `revert`). A
/// person, where one acts, sees it and signs the record before anything is pushed.
#[allow(clippy::too_many_arguments)]
fn revert_to(top: &Path, policy: &Policy, env: &Environment, head: &str, point: &promote::RollbackPoint, why: &str, by: &str, person: bool, runner_key: Option<&use05_receipt::SigningKey>) -> Result<Reverted, Report> {
    let Some(to) = point.to.clone() else {
        return Err(Report::error("promote", "NO_ROLLBACK_POINT", format!("the newest promotion into {} created {}, so there is nothing to go back to", env.name, env.branch), None, 6));
    };
    let could_not = |what: &str, e: use05_core::Error| Report::error("promote", "ROLLBACK_FAILED", format!("could not {what}: {}", e.message), None, 4);
    let tree = git::resolve_tree(top, &to).map_err(|e| could_not("read the rollback point's files", e))?;
    if git::resolve_tree(top, head).ok().as_deref() == Some(tree.as_str()) {
        return Err(Report::error("promote", "NOTHING_TO_ROLL_BACK", format!("{} already holds the files of {}", env.branch, short(&to)), None, 0));
    }
    // The revert goes onto exactly the head origin has: if it moved, nothing is pushed.
    let _ = fresh::fetch(top, "origin", &env.branch, fresh::FETCH_TIMEOUT);
    let on_origin = git::resolve_commit(top, &format!("refs/remotes/origin/{}", env.branch));
    if on_origin.as_deref() != Some(head) {
        return Err(Report::error("promote", "PROMOTE_TARGET_MOVED", format!("{} moved on origin (it is at {}, not {}); nothing was pushed", env.branch, on_origin.as_deref().map_or("nothing", short), short(head)), Some(format!("look at it, then: use05 promote {} --rollback", env.name)), 4));
    }
    let message = promote::revert_message(&env.name, &to, head, why);
    let commit = commit_tree(top, &tree, head, &message)?;
    let statement = promote::revert_record(&env.name, &point.from, point.direction, &commit, head, &policy.digest(), by, use05_core::time::now_rfc3339());
    let mut signatures = Vec::new();
    if person {
        eprintln!("You are about to roll {} back to {}: a new commit on {} holding {}'s files, on top of {} ({why}).", env.name, short(&to), env.branch, short(&to), short(head));
        eprintln!("  {} on origin moves from {} to {}, never by force; the record is signed and filed once the push goes through.", env.branch, short(head), short(&commit));
        let (envelope, _) = crate::cmd::approve::sign_as_person(&statement, &format!("roll {} back to {}", env.name, short(&to)), false, "promote")?;
        signatures = envelope.signatures;
    }
    if let Err(line) = push_target(top, &env.branch, &commit) {
        let mut refused = Report::error("promote", "ROLLBACK_PUSH_FAILED", format!("the push of the revert of {} to origin was refused: {line}", env.branch), Some(format!("fix what refused it, then: use05 promote {} --rollback", env.name)), 4);
        refused.notes = vec![format!("Nothing moved: origin's {} is where it was ({}), and no record was written.", env.branch, short(head))];
        return Err(refused);
    }
    let mut notes: Vec<String> = follow_local(top, &env.branch, &commit).into_iter().collect();
    let filed = file_record(top, &statement, &commit, signatures, runner_key, "The revert was pushed, but");
    notes.extend(filed.notes.clone());
    notes.extend(push_receipts(top));
    if !filed.on_origin {
        notes.push(format!("CI holds {}'s branch until the revert's record is on origin.", env.name));
    }
    Ok(Reverted { commit, to, reverts: head.to_string(), filed, notes })
}

/// Who acts, as the records say: the person (by the name the policy gives their key), the agent,
/// CI, or this machine's user.
pub(crate) fn by_whom(top: &Path, policy: &Policy, person: bool, runner: bool) -> String {
    let trust = Trust::new(policy, true);
    actor(top, person.then(|| crate::cmd::approve::person_key_id().and_then(|id| trust.person_of(&id)).unwrap_or_else(|| crate::cmd::approve::approver_name(top))), runner)
}

pub(crate) fn runner_key() -> Option<use05_receipt::SigningKey> {
    std::env::var("USE05_RUNNER_KEY").ok().and_then(|k| use05_receipt::parse_secret_key(&k).ok())
}

/// How strong a deploy's record is here.
fn deploy_strength(policy: &Policy, name: &str) -> String {
    if policy.evidence.accept.contains(&use05_core::policy::Role::Local) {
        format!("Here this is advisory: a deployment record this machine signs is its own word. With [evidence] accept = [\"runner\"] only CI's count; CI can run use05 promote {name} --confirm.")
    } else {
        format!("Only CI's deployment records count here: this one is kept, but counts only once CI runs use05 promote {name} --confirm.")
    }
}

/// `use05 promote <env> --confirm`: confirm what `<env>` runs now (its branch's head, origin's
/// copy if there is one) with its probes and smoke checks, file the record, and when it is not
/// confirmed do what `on_failure` says. CI can run it (D93).
pub fn run_confirm(repo: &Path, name: &str, interactive: bool) -> Report {
    let rules = match rules_for(repo, name) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Rules { top, policy, env, notes: read, .. } = rules;
    let Some(at) = branch_ref(&top, &env.branch) else {
        return Report::error("promote", "ENVIRONMENT_NOT_FOUND", format!("there is no branch {} ({name}) here or on origin", env.branch), Some(format!("check [[environment]] in {POLICY_PATH}")), 6);
    };
    let head = git::resolve_commit(&top, &at).expect("resolved above");
    let runner = runner_key();
    // Acting on a failure where people promote is a person's act; confirming is anyone's.
    let person = !policy.agent_may_promote(&env);
    let may_act = if person { crate::cmd::approve::person_here("promote", interactive, &format!("acting on a failed deploy of {name}")).map(|_| true).map_err(|r| r.headline) } else { Ok(false) };
    let by = by_whom(&top, &policy, may_act == Ok(true), runner.is_some());
    let d = confirm_deploy(&top, &policy, &env, &head, &by, runner.as_ref(), may_act, true);
    let mut rows = vec![("commit".to_string(), format!("{} ({})", short(&head), ref_label(&at)))];
    rows.extend(d.rows());
    if let Some(b) = &d.filed.branch {
        rows.push(("record".into(), format!("on {b}")));
    }
    let mut notes = read;
    notes.extend(d.notes.clone());
    notes.push(deploy_strength(&policy, name));
    let (code, tone, headline, next, exit) = if d.confirmed {
        ("DEPLOY_CONFIRMED", Tone::Good, format!("{name} runs {}: confirmed", short(&head)), None, 0)
    } else if d.failed {
        ("DEPLOY_NOT_CONFIRMED", Tone::Bad, format!("{name} was not confirmed running {}{}", short(&head), d.done()), d.next.clone(), 2)
    } else {
        ("NO_PROBES", Tone::Warn, format!("no probes: 05 cannot tell what {name} runs, so {} is not confirmed", short(&head)), Some(format!("give {name} a probe ([[environment.probe]] in {POLICY_PATH})")), 5)
    };
    Report { command: "promote", outcome: if d.confirmed { "confirmed" } else { "not_confirmed" }, code, tone, headline, rows, notes, next, excerpt: vec![], details: d.details(), exit }
}

/// `use05 promote <env> --rollback`: revert `<env>` to the rollback point of the newest promotion
/// into it that counts, with a new commit (never a force-push), then confirm that once unless
/// `wait` is false. Where people promote (`agent = false`) a person does it, at a terminal.
pub fn run_rollback(repo: &Path, name: &str, wait: bool, interactive: bool) -> Report {
    let rules = match rules_for(repo, name) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Rules { top, policy, env, source, notes: read, .. } = rules;
    if git::text(&top, &["remote", "get-url", "origin"]).is_err() {
        return Report::error("promote", "NO_REMOTE", format!("this repository has no origin to push {} to", env.branch), Some("git remote add origin <url>".into()), 6);
    }
    let Some(head) = git::resolve_commit(&top, &format!("refs/remotes/origin/{}", env.branch)) else {
        return Report::error("promote", "ENVIRONMENT_NOT_FOUND", format!("{} ({name}) is not on origin, so there is nothing to roll back", env.branch), None, 6);
    };
    let person = !policy.agent_may_promote(&env);
    if person {
        if let Err(refused) = crate::cmd::approve::person_here("promote", interactive, &format!("rolling back {name}")) {
            return refused;
        }
    }
    let found = classify(&Trust::new(&policy, true), &store::find_all(&top));
    let point = match promote::rollback_point(&top, &found, &policy.evidence.accept, name, &head) {
        Some(p) if p.to.is_some() => p,
        Some(_) => return Report::error("promote", "NO_ROLLBACK_POINT", format!("the newest promotion into {name} created {}, so there is nothing to go back to", env.branch), None, 6),
        None => return Report::error("promote", "NO_ROLLBACK_POINT", format!("no promotion record into {name} that counts here says where {} was before", env.branch), Some(format!("use05 promote {name} --check")), 6),
    };
    let to = point.to.clone().expect("checked above");
    if matches!((git::resolve_tree(&top, &head), git::resolve_tree(&top, &to)), (Ok(a), Ok(b)) if a == b) {
        let mut nothing = Report::error("promote", "NOTHING_TO_ROLL_BACK", format!("{name} already holds the files of {}, where the newest promotion found it: nothing to roll back", short(&to)), None, 0);
        (nothing.outcome, nothing.tone) = ("nothing", Tone::Good);
        return nothing;
    }
    let mut notes = read;
    if point.result != head {
        notes.push(format!("{} moved after that promotion ({} → {}): the revert undoes that too.", env.branch, short(&point.result), short(&head)));
    }
    let runner = runner_key();
    let by = by_whom(&top, &policy, person, runner.is_some());
    let r = match revert_to(&top, &policy, &env, &head, &point, &format!("rolled back by {by}"), &by, person, runner.as_ref()) {
        Ok(r) => r,
        Err(refused) => return refused,
    };
    notes.extend(r.notes.clone());
    if let Some(below) = source.as_ref().map(|s| s.name.as_str()) {
        notes.push(format!("{name} now has a commit {below} lacks (the revert), so promoting into {name} is refused until {below} has it too."));
    }
    let deploy = wait.then(|| confirm_deploy(&top, &policy, &env, &r.commit, &by, runner.as_ref(), Err("a revert is not undone".into()), false));
    if !wait {
        notes.push(format!("The deploy is not confirmed yet: once {name} has deployed {}, run use05 promote {name} --confirm (CI can).", short(&r.commit)));
    }
    let mut rows = vec![
        ("reverted".to_string(), format!("{} → {}: the files of {}", short(&head), short(&r.commit), short(&to))),
        ("pushed".to_string(), format!("{} → origin, now at {}, a new commit", env.branch, short(&r.commit))),
        ("by".to_string(), by.clone()),
    ];
    if let Some(b) = &r.filed.branch {
        rows.push(("record".into(), format!("on {b}")));
    }
    if let Some(d) = &deploy {
        rows.extend(d.rows());
        notes.extend(d.notes.clone());
    }
    notes.push(format!("Here this is advisory: it is what CI checks, but nothing stops a person or an agent who pushes {name}'s branch by hand. The CI gate on {name}'s branch is the strong control."));
    let failed = deploy.as_ref().filter(|d| d.failed);
    let (code, tone, headline, next, exit) = match (failed, r.filed.on_origin) {
        (Some(_), _) => ("DEPLOY_NOT_CONFIRMED", Tone::Bad, format!("Rolled {name} back to {}, but the deploy of {} was not confirmed", short(&to), short(&r.commit)), Some(format!("look at {name} by hand: 05 could not confirm it runs {}", short(&r.commit))), 2),
        (None, true) => ("ROLLED_BACK", Tone::Good, format!("Rolled {name} back to {}: {} holds its files", short(&to), short(&r.commit)), None, 0),
        (None, false) => ("ROLLED_BACK_WITHOUT_RECORD", Tone::Warn, format!("Rolled {name} back to {}, but the revert's record is not on origin", short(&to)), r.filed.branch.as_ref().map(|b| format!("git push origin {b}")), 0),
    };
    Report {
        command: "promote",
        outcome: "rolled_back",
        code,
        tone,
        headline,
        rows,
        notes,
        next,
        excerpt: vec![],
        details: json!({
            "env": name,
            "rollback_to": to,
            "reverts": head,
            "result_commit": r.commit,
            "record_branch": r.filed.branch,
            "record_on_origin": r.filed.on_origin,
            "by": by,
            "deploy": deploy.as_ref().map(Deploy::details),
        }),
        exit,
    }
}

/// A revert as 05 makes one (D93): its only parent is the head of the environment's branch on
/// origin, and its tree is the files of the rollback point, the branch's head before the newest
/// promotion into it that counts. Allowed to whoever may promote there, whatever the promotion's
/// rules say: going back to where the branch was is always open. `None`: it is not one.
pub(crate) fn judge_revert(rules: &Rules, pushed: &str) -> Option<use05_core::gate::GateResult> {
    let top = &rules.top;
    let head = git::resolve_commit(top, &format!("refs/remotes/origin/{}", rules.env.branch))?;
    let pushed = git::resolve_commit(top, pushed)?;
    let parents = git::text(top, &["rev-list", "--parents", "-n", "1", &pushed]).ok()?;
    if parents.split_whitespace().skip(1).collect::<Vec<_>>() != [head.as_str()] {
        return None;
    }
    let found = classify(&Trust::new(&rules.policy, true), &store::find_all(top));
    let to = promote::rollback_point(top, &found, &rules.policy.evidence.accept, &rules.env.name, &head)?.to?;
    if git::resolve_tree(top, &pushed).ok()? != git::resolve_tree(top, &to).ok()? {
        return None;
    }
    let name = &rules.env.name;
    let mut findings = Vec::new();
    if !rules.policy.agent_may_promote(&rules.env) {
        let why = match use05_core::inbox::agent_session() {
            Some((kind, _)) => Some(format!("an agent ({kind}) may not roll back {name}: the policy keeps it for people")),
            None if !crate::cmd::gate::person_at_terminal() => Some(format!("{name} is kept for people, and nothing here shows a person pushing: there is no terminal")),
            None => None,
        };
        if let Some(message) = why {
            let mut f = Finding::new("AGENT_MAY_NOT_PROMOTE", Effect::Deny, message);
            f.next = Some(format!("a person runs: use05 promote {name} --rollback"));
            findings.push(f);
        }
    }
    let decision = if findings.is_empty() { Decision::Allow } else { Decision::Deny };
    Some(use05_core::gate::GateResult::of_findings(decision, findings, rules.policy.digest()))
}

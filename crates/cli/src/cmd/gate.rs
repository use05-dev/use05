//! `use05 gate`: the decision at a boundary. As a git pre-push hook it stops a push; in CI it
//! proves the base's required checks with the runner key and gates the change. Rules are read
//! from the change's base, so a change cannot loosen its own.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use use05_core::gate::{Decision, Effect, GateResult};
use use05_core::{git, store};

use crate::cmd::{brief, prove};
use crate::ctx::Ctx;
use crate::host::{self, EventKind, Host, Verdict};
use crate::report::Report;
use crate::ui::{Glyph, Tone, Ui};

pub struct Args {
    pub git_hook: Option<String>,
    pub ci: bool,
    pub tree: Option<String>,
    pub push: bool,
    /// As a pre-push hook: what git passes, the remote's name and its URL (a push to a URL has
    /// the URL for both).
    pub remote: Vec<String>,
    pub repo: PathBuf,
    pub json: bool,
}

const ZERO: &str = "0000000000000000000000000000000000000000";

/// What a push is measured against. `None` means nothing exists on the other side to compare
/// with (the first push to an empty remote): the push sets the baseline, so there is nothing to
/// hold it back against.
fn base_for_push(top: &Path, remote_sha: &str, local_sha: &str) -> Option<String> {
    if remote_sha != ZERO {
        if let Some(c) = git::resolve_commit(top, remote_sha) {
            return Some(c);
        }
    }
    if git::list_refs(top, &["refs/remotes/"]).is_empty() {
        return None;
    }
    git::fork_from_remote(top, local_sha).filter(|b| b != local_sha).or_else(|| git::resolve_commit(top, &format!("{local_sha}^")))
}

/// Tell event extensions what the gate decided: the verdict and its finding codes, nothing more.
fn announce(listeners: &[crate::extend::Listener], top: &Path, place: &str, tree: &str, task: Option<&use05_core::task::Task>, r: &GateResult) {
    let codes: Vec<&str> = r.findings.iter().map(|f| f.code).collect();
    let id = task.map(|t| t.id.as_str());
    let mut events = vec![("gate", serde_json::json!({ "where": place, "tree": tree, "task": id, "decision": r.decision.word(), "findings": codes }))];
    events.extend(crate::extend::approval_needed(id, tree, task.and_then(|t| t.intent_sha256.as_deref()), r).map(|f| ("approval_needed", f)));
    crate::extend::emit_all(listeners, top, &events);
}

/// What breaks glass for one held ref, if anything does. A promotion's rules are bypassed one at
/// a time, for that promotion, and never while something built in also holds it; a deletion of a
/// kept branch never; a task's change by a tree bypass.
fn break_glass(r: &GateResult, promotion: Option<&str>) -> Option<String> {
    let holding: Vec<&str> = r.findings.iter().filter(|f| f.effect >= Effect::Wait).map(|f| f.code).collect();
    if holding.contains(&"ENVIRONMENT_DELETE_HELD") {
        return None;
    }
    let Some(env) = promotion else {
        return Some("Break glass (logged): use05 bypass --reason \"<why>\"".to_string());
    };
    // A hotfix's landing has no promotion's bypass: a person's approval clears what may be cleared.
    if r.findings.iter().any(|f| f.code == "HOTFIX_LANDING") {
        return None;
    }
    let back = if r.findings.iter().any(|f| f.code == "BACK_MERGE") { " --back" } else { "" };
    let built_in = ["PROMOTE_NOT_EVALUATED_MOVE", "PROMOTE_TARGET_AHEAD", "PROMOTE_NOT_JUDGED", "PROMOTE_NOT_EVALUATED_HEAD", "AGENT_MAY_NOT_PROMOTE", "BACK_MERGE_RESOLVED"];
    let bypassable = holding.iter().any(|c| use05_core::policy::PROMOTE_RULES.iter().any(|r| use05_core::promote::rule_code(r) == Some(c)));
    (bypassable && !holding.iter().any(|c| built_in.contains(c))).then(|| format!("Break glass (logged): use05 bypass --promote {env}{back} --rule <rule> --reason \"<why>\""))
}

/// Each held ref: its name, the decision, and the environment when it is a promotion.
fn blocked_text(ui: &Ui, what: &str, results: &[(String, GateResult, Option<String>)]) -> String {
    let mut out = String::new();
    let worst = results.iter().map(|(_, r, _)| r.decision).max().unwrap_or(Decision::Allow);
    let (glyph, tone) = match worst {
        Decision::Deny => (Glyph::Bad, Tone::Bad),
        Decision::ApprovalRequired => (Glyph::Warn, Tone::Warn),
        _ => (Glyph::Pending, Tone::Info),
    };
    out.push_str(&format!("{} {}  ({})\n", ui.paint(tone, ui.glyph(glyph)), ui.bold(&format!("05 stopped this {what}")), worst.word().to_uppercase().replace('_', " ")));
    for (name, r, promotion) in results.iter().filter(|(_, r, _)| r.decision != Decision::Allow) {
        out.push_str(&format!("  {}\n", ui.paint(Tone::Dim, name)));
        for f in r.findings.iter().filter(|f| f.effect >= Effect::Wait) {
            for (i, line) in ui.wrap(&format!("{}  {}", f.code, f.message), ui.width.saturating_sub(6)).iter().enumerate() {
                out.push_str(&format!("    {}{line}\n", if i == 0 { "" } else { "  " }));
            }
            if let Some(next) = &f.next {
                out.push_str(&format!("      {} {next}\n", ui.paint(Tone::Info, "→")));
            }
        }
        if let Some(glass) = break_glass(r, promotion.as_deref()) {
            out.push_str(&format!("    {}\n", ui.paint(Tone::Dim, &glass)));
        }
    }
    out.push('\n');
    if what == "push" {
        out.push_str(&format!("  {}\n", ui.paint(Tone::Dim, "`git push --no-verify` skips this hook; 05 cannot stop that. Branch protection can.")));
    }
    ui.finish(out)
}

fn pre_push(args: &Args) -> ExitCode {
    let mut raw = String::new();
    let _ = std::io::stdin().take(1_000_000).read_to_string(&mut raw);
    let ui = Ui::stderr();
    // Read before anything of the change runs (D73).
    let listeners = crate::extend::listeners().unwrap_or_default();

    let mut outcome = gate_push(args, &raw, &listeners);
    // A person pushing at a terminal approves right here, once, instead of being sent away to
    // run another command (D91). Never under an agent or in CI: there is no terminal there. A
    // promotion is not approved this way: it has its own sign-off.
    if let Ok(results) = &outcome {
        let waits = |p: &Pushed| p.gate.decision == Decision::ApprovalRequired && p.promotion.is_none();
        let promotion_waits = results.iter().any(|p| p.promotion.is_some() && p.gate.decision != Decision::Allow);
        if !promotion_waits && results.iter().any(waits) && results.iter().all(|p| p.gate.decision != Decision::Deny) && use05_core::tty::has_tty() && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            let shown: Vec<(String, GateResult, Option<String>)> = results.iter().map(|p| (p.name.clone(), p.gate.clone(), p.promotion.clone())).collect();
            eprint!("{}", blocked_text(&ui, "push", &shown));
            let trees: Vec<(String, Option<String>)> = results.iter().filter(|p| waits(p)).map(|p| (p.sha.clone(), p.base.clone())).collect();
            if crate::cmd::land::Then::Ask.settle("Approve it now?") {
                let mut approved = true;
                for (sha, base) in trees {
                    let report = crate::cmd::approve::run_approve(crate::cmd::approve::ApproveArgs {
                        push: true, land: false, unsigned: false, signed: None, tested: false, skip_testing: false, note: None, approver: None,
                        intent: false, outcome: true, reject: false, reason: None, task: None, tree: Some(sha), base, rev: None, passphrase_stdin: false,
                        interactive: false, promote: None, answers: vec![], confirms: vec![], back: false, hotfix: false, repo: args.repo.clone(),
                    });
                    eprintln!("05: {}", report.headline);
                    approved &= report.code == "APPROVED";
                }
                if approved {
                    outcome = gate_push(args, &raw, &[]);
                }
            } else {
                eprintln!("05: not approved, so the push stays stopped. Approve later with: use05 approve");
                return ExitCode::from(1);
            }
        }
    }
    let results: Vec<(String, GateResult, Option<String>)> = match outcome {
        Ok(r) => r.into_iter().map(|p| (p.name, p.gate, p.promotion)).collect(),
        Err(e) => {
            if e.code == "ORG_LAYER_UNAVAILABLE" {
                eprintln!("{} 05 stopped this push: {}", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), e.message);
                return ExitCode::from(1);
            }
            // Fail open, loudly (D34).
            eprintln!("{} 05 could not check this push ({}). It was NOT blocked.", ui.paint(Tone::Warn, ui.glyph(Glyph::Warn)), e.message);
            return ExitCode::SUCCESS;
        }
    };
    if results.iter().all(|(_, r, _)| r.decision == Decision::Allow) {
        for (name, r, _) in &results {
            if let Some(b) = &r.bypass {
                eprintln!("{} 05 let {name} through by break-glass: {} ({})", ui.paint(Tone::Warn, ui.glyph(Glyph::Warn)), b.reason, b.by.name);
            }
        }
        return ExitCode::SUCCESS;
    }
    eprint!("{}", blocked_text(&ui, "push", &results));
    ExitCode::from(1)
}

/// A person is pushing: a controlling terminal, and no agent session. (The hook's own stdin is
/// git's list of refs, so the terminal is the one the push was typed at.) Weaker than
/// `approve::person_here`, which also wants stdin and stderr to be the terminal; a hook has pipes.
pub(crate) fn person_at_terminal() -> bool {
    // In the CI gate there is no terminal: there, whether a person acted is what the promotion's
    // record shows (a person's co-signature), set once by `ci_env.rs` before it judges.
    if let Some(recorded) = RECORDED_PERSON.get() {
        return *recorded;
    }
    use05_core::tty::has_tty() && use05_core::inbox::agent_session().is_none()
}

/// Set only by the CI gate, from the record of the push it judges: whether a person co-signed it.
pub(crate) static RECORDED_PERSON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Whether `branch` is an environment's or one the policy keeps, by every policy that may name it:
/// this checkout's, the one committed at `remote_sha` (the head of the branch, which names its own
/// environment), origin's copy of the branch, and origin's default branch. Kept if any says so.
/// `None` when none of them could be read: the caller fails closed. Reads git only, no network.
pub(crate) fn kept_anywhere(top: &Path, branch: &str, checkout: Option<&use05_core::policy::Policy>, remote_sha: Option<&str>) -> Option<bool> {
    use use05_core::policy::Policy;
    let mut read = 0;
    let mut kept = false;
    let mut judge = |p: &Policy| {
        read += 1;
        kept |= use05_core::branches::is_kept(p, branch);
    };
    if let Some(p) = checkout {
        judge(p);
    }
    let revs = remote_sha.filter(|s| *s != ZERO).map(str::to_string).into_iter().chain([format!("refs/remotes/origin/{branch}"), "refs/remotes/origin/HEAD".into(), "refs/remotes/origin/main".into(), "refs/remotes/origin/master".into()]);
    for rev in revs {
        if let Some(commit) = git::resolve_commit(top, &rev) {
            // A commit with no policy file is held to the defaults, which keep main and master.
            if let Ok(p) = Policy::load_at(top, &commit) {
                judge(&p.unwrap_or_default());
            }
        }
    }
    (read > 0).then_some(kept)
}

/// Whether an agent may push to the remote git calls `name`, at `url` (`[push] agent`, D93), by
/// every policy that may say: this checkout's and the one on origin's default branch. Held when
/// any of them lists remotes and leaves this one out; `Err` gives that list. Reads git only.
pub(crate) fn agent_may_push(top: &Path, checkout: Option<&use05_core::policy::Policy>, name: &str, url: &str) -> Result<(), Vec<String>> {
    use use05_core::policy::Policy;
    let mut policies: Vec<Policy> = checkout.cloned().into_iter().collect();
    if let Some(p) = ["refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master"].iter().find_map(|r| git::resolve_commit(top, r)).and_then(|c| Policy::load_at(top, &c).ok().flatten()) {
        policies.push(p);
    }
    let urls = |remote: &str| crate::cmd::destination::urls_of(top, remote);
    match policies.iter().find(|p| !p.push.agent_may_push(name, url, &urls)) {
        Some(p) => Err(p.push.agent.clone().unwrap_or_default()),
        None => Ok(()),
    }
}

/// An agent's push to a remote `[push] agent` leaves out: for a person. Advisory locally, as
/// every hook is.
pub(crate) fn remote_held(name: &str, listed: &[String]) -> use05_core::gate::Finding {
    let list = if listed.is_empty() { "none".to_string() } else { listed.join(", ") };
    let mut f = use05_core::gate::Finding::new("PUSH_REMOTE_NOT_ALLOWED", Effect::Deny, format!("an agent may push only to the remotes [push] agent lists ({list}), and {name} is not one of them"));
    f.next = Some("ask the person to push it, or add the remote to [push] agent".to_string());
    f
}

/// One ref a push sends, and what 05 decided about it.
struct Pushed {
    /// `3f2a1b9c0d → prod`.
    name: String,
    /// The commit pushed.
    sha: String,
    /// What it is measured from.
    base: Option<String>,
    gate: GateResult,
    /// The environment, when the branch is one that is promoted into: then the push is judged
    /// as that promotion, not as a task's change.
    promotion: Option<String>,
}

/// Gate every ref a push sends: its name, the commit, what it is measured from, and the decision.
fn gate_push(args: &Args, raw: &str, listeners: &[crate::extend::Listener]) -> Result<Vec<Pushed>, use05_core::Error> {
    let mut results = Vec::new();
    {
        // Where this push goes (git passes the remote's name and URL), and whether an agent may
        // push there (`[push] agent`, D93). The policy here names the destinations.
        let remote_name = args.remote.first().cloned().unwrap_or_default();
        let remote_url = args.remote.get(1).cloned().unwrap_or_default();
        let here = git::dirs(&args.repo)?.top;
        let checkout = Ctx::open(&args.repo, None).ok().map(|c| c.policy);
        let held_remote = if use05_core::inbox::agent_session().is_some() && !remote_name.is_empty() { agent_may_push(&here, checkout.as_ref(), &remote_name, &remote_url).err() } else { None };
        for line in raw.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [_, local_sha, remote_ref, remote_sha] = f[..] else { continue };
            let branch = remote_ref.trim_start_matches("refs/heads/");
            let destination = checkout.as_ref().filter(|_| remote_ref.starts_with("refs/heads/") && local_sha != ZERO).and_then(|p| crate::cmd::destination::pushed_to(&here, p, &remote_name, &remote_url, branch));
            // An agent pushes only where the policy lets it, except to a destination, whose own
            // rules decide (below).
            if let (Some(listed), None) = (&held_remote, destination) {
                let digest = checkout.as_ref().map(|p| p.digest()).unwrap_or_default();
                results.push(Pushed { name: format!("{} → {remote_name} {branch}", &local_sha[..10.min(local_sha.len())]), sha: local_sha.to_string(), base: None, gate: GateResult::of_findings(Decision::Deny, vec![remote_held(&remote_name, listed)], digest), promotion: None });
                continue;
            }
            // A destination's branch moves only as a promotion to it (D93), judged by its rules.
            if let Some(d) = destination {
                let gate = crate::cmd::destination::judge_push(&args.repo, &d.name, local_sha).unwrap_or_else(|r| {
                    let mut f = use05_core::gate::Finding::new("PROMOTE_NOT_JUDGED", Effect::Deny, format!("05 could not judge this push to {branch} as promoting to {}: {}", d.name, r.headline));
                    f.next = r.next.clone().or_else(|| Some(format!("see why: use05 promote {} --check", d.name)));
                    GateResult::of_findings(Decision::Deny, vec![f], checkout.as_ref().map(|p| p.digest()).unwrap_or_default())
                });
                results.push(Pushed { name: format!("{} → {} {branch}", &local_sha[..10.min(local_sha.len())], d.name), sha: local_sha.to_string(), base: None, gate, promotion: Some(d.name.clone()) });
                continue;
            }
            // Pushing receipts themselves is not a change to gate.
            if !remote_ref.starts_with("refs/heads/") || remote_ref.starts_with(&format!("refs/heads/{}/", store::BRANCH_DIR)) {
                continue;
            }
            // Deleting a branch is no change either, except an environment's or one the policy
            // keeps: that is for a person at a terminal (D93).
            if local_sha == ZERO {
                let branch = remote_ref.trim_start_matches("refs/heads/");
                // Kept by any policy that may name it; none readable at all: held, failing closed.
                let checkout = Ctx::open(&args.repo, None).ok().map(|c| c.policy);
                let kept = git::dirs(&args.repo).ok().and_then(|d| kept_anywhere(&d.top, branch, checkout.as_ref(), Some(remote_sha)));
                if kept != Some(false) && !person_at_terminal() {
                    let why = if kept.is_some() { "it is an environment's branch or one the policy keeps" } else { "05 could read no policy that says whether it is kept" };
                    let mut held = use05_core::gate::Finding::new("ENVIRONMENT_DELETE_HELD", Effect::Deny, format!("deleting {branch} is for a person at a terminal: {why}, and nothing here shows a person"));
                    held.next = Some(format!("ask a person to delete it at their terminal: git push origin --delete {branch}"));
                    let digest = checkout.as_ref().map(|p| p.digest()).unwrap_or_default();
                    results.push(Pushed { name: format!("delete {branch}"), sha: ZERO.to_string(), base: None, gate: GateResult::of_findings(Decision::Deny, vec![held], digest), promotion: None });
                }
                continue;
            }
            let top = git::dirs(&args.repo)?.top;
            let Some(base) = base_for_push(&top, remote_sha, local_sha) else {
                eprintln!("05: first push to this remote, so there is nothing to compare it with. It sets the baseline.");
                continue;
            };
            let base = Some(base);
            let ctx = Ctx::open_with(&args.repo, None, base.as_deref())?;
            let branch = remote_ref.trim_start_matches("refs/heads/");
            let name = format!("{} → {branch}", &local_sha[..10.min(local_sha.len())]);
            // An environment's branch that is promoted into moves only as a promotion (D93): the
            // push is judged by that promotion's rules, and must be exactly the move they judged.
            // The landing branch, the lowest rung, keeps the task gate.
            if let Some(env) = ctx.policy.environment.iter().find(|e| e.branch == branch && ctx.policy.source_of(e).is_some()) {
                // A push to an environment that cannot be judged is held, whatever
                // `enforce.on_error` says: failing open here would let anything onto it.
                let gate = crate::cmd::promote::judge_push(&args.repo, &env.name, local_sha).unwrap_or_else(|r| {
                    let mut f = use05_core::gate::Finding::new("PROMOTE_NOT_JUDGED", Effect::Deny, format!("05 could not judge this push to {branch} as promoting into {}: {}", env.name, r.headline));
                    f.next = r.next.clone().or_else(|| Some(format!("see why: use05 promote {} --check", env.name)));
                    GateResult::of_findings(Decision::Deny, vec![f], ctx.policy.digest())
                });
                results.push(Pushed { name, sha: local_sha.to_string(), base: base.clone(), gate, promotion: Some(env.name.clone()) });
                continue;
            }
            // The branch work lands on keeps the task gate, but a back-merge of the environment
            // above into it is judged as one (D93): by its rules but those about the source.
            if let Some(env) = ctx.policy.environment.iter().find(|e| e.branch == branch) {
                if let Some(gate) = crate::cmd::hotfix::judge_back_into(&args.repo, &env.name, local_sha) {
                    results.push(Pushed { name, sha: local_sha.to_string(), base: base.clone(), gate, promotion: Some(env.name.clone()) });
                    continue;
                }
            }
            let target = ctx.target_from(local_sha, base.as_deref())?;
            let mut gate = ctx.gate_for(&target, Some(branch))?;
            // Prove what is missing for exactly what is pushed, with this machine's key (D65).
            use use05_core::gate::CheckState;
            let missing = gate.checks.iter().any(|c| matches!(c.state, CheckState::Missing | CheckState::Stale));
            if ctx.policy.evidence.prove_at_push && missing {
                // The checks this change calls for, as before: one scoped to other paths (D97) is not run.
                let calls_for: Vec<String> = gate.checks.iter().filter(|c| !matches!(c.state, CheckState::NotRequired { .. } | CheckState::Undefined)).map(|c| c.name.clone()).collect();
                let proved = prove::run(prove::Args {
                    names: calls_for,
                    command: vec![],
                    key: None,
                    tree: local_sha.to_string(),
                    repo: args.repo.clone(),
                    out: None,
                    timeout: None,
                    env: vec![],
                    no_store: false,
                    push: false,
                    policy_rev: base.clone(),
                    task: None,
                });
                eprintln!("05: proved what was missing for {} before checking the push. {}", &local_sha[..10.min(local_sha.len())], proved.headline);
                gate = ctx.gate_for(&target, Some(branch))?;
            }
            announce(listeners, &top, "pre-push", &target.oid, ctx.task.as_ref(), &gate);
            results.push(Pushed { name, sha: local_sha.to_string(), base: base.clone(), gate, promotion: None });
        }
    }
    Ok(results)
}

/// Countersign the task's action log with the runner key, if it still matches every seal (D70).
/// With `push`, the runner's receipts branch goes to the remote so the seal outlives the job.
fn seal_log_in_ci(ctx: &Ctx, host: &dyn Host, task: &str, found: &use05_core::evidence::Found, push: bool) {
    let top = ctx.top();
    let Some(integrity) = use05_core::logseal::check(top, None, found, task) else { return };
    let Some(text) = use05_core::logseal::copy(top, None, found, task) else { return };
    // Only what a trusted signer sealed where the work happened is countersigned; never more.
    let Some(upto) = use05_core::logseal::last_trusted_seal(found, task, integrity.lines) else { return };
    if integrity.altered_at.is_some() || upto == 0 {
        return;
    }
    let Some(head) = use05_core::log::hash_at(&text, upto) else { return };
    let Some(key) = std::env::var("USE05_RUNNER_KEY").ok().and_then(|k| use05_receipt::parse_secret_key(&k).ok()) else { return };
    let signer = use05_receipt::key_id(&key.verifying_key());
    let statement = use05_receipt::Statement::new(vec![use05_receipt::log_subject(task, &head)], use05_receipt::LogSeal { task: task.to_string(), seq: upto, head, created: use05_core::time::now_rfc3339() });
    let envelope = use05_receipt::seal(&statement, &key).to_json_bytes();
    if store::put(top, task, &envelope, &signer).is_ok() && push {
        if let Err(e) = push_runner_branch(top, host, &store::branch_for(&signer)) {
            eprintln!("05: the log was sealed, but the seal could not be pushed: {e}");
        }
    }
}

/// Push only the runner's receipts branch. When the host gives a token the push goes with it, by
/// name and never from `.git/config`, so the code under test cannot find it there; otherwise the
/// plain remote is used.
fn push_runner_branch(top: &std::path::Path, host: &dyn Host, branch: &str) -> Result<(), String> {
    match host.push_remote() {
        Some(remote) => {
            let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
            let envs: Vec<(&str, &str)> = remote.envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            git::run_with(top, &["push", "--quiet", &remote.url, &refspec], &envs, None).map(|_| ()).map_err(|e| remote.redact(&e.message))
        }
        None => store::push(top, branch).map(|_| ()).map_err(|e| e.message),
    }
}

/// The one line a host shows beside the commit: what was decided and, when it was not allowed,
/// the first reason.
fn status_line(gate: &GateResult) -> String {
    let first = |effect: Effect| gate.findings.iter().find(|f| f.effect == effect).map(|f| f.message.clone()).unwrap_or_default();
    match gate.decision {
        Decision::Allow => "allowed".into(),
        Decision::ApprovalRequired => "needs a person's approval".into(),
        Decision::Wait => format!("evidence missing: {}", first(Effect::Wait)),
        Decision::Deny => format!("denied: {}", first(Effect::Deny)),
    }
}

/// The gate in CI. Under a run another run started (D94), the verdict also goes on the change's
/// commit as the host's commit status, which is what branch protection requires; a status that
/// could not be posted fails the run, since otherwise the protection would not see the verdict.
fn ci(args: &Args) -> ExitCode {
    let host = host::current();
    let event = host.event();
    let status_on = Some(event.head_sha.clone()).filter(|sha| event.kind == EventKind::WorkflowRun && !sha.is_empty());
    let mut unposted = Vec::new();
    if let Some(sha) = &status_on {
        unposted.extend(host.post_status(sha, Verdict::Pending, "checking").err());
    }
    let (exit, line) = ci_gate(args, host.as_ref(), &event);
    let Some(sha) = &status_on else { return ExitCode::from(exit) };
    unposted.extend(host.post_status(sha, if exit == 0 { Verdict::Success } else { Verdict::Failure }, &line).err());
    if unposted.is_empty() {
        // Who posted it decides whether the status can be trusted at all (D94).
        if host.status_from_app() {
            host.summary("The `05` status was posted by your 05 app.\n");
        } else {
            let said = "The `05` status was posted with the workflow token: a branch can forge this status, so only the signed receipts hold (use05 land, use05 verify). See \"Post the status as your own app\" in docs/turn-on-the-ci-gate.md";
            eprintln!("05: {said}.");
            host.summary(&format!("**{said}.**\n"));
        }
        return ExitCode::from(exit);
    }
    let said = format!(
        "05 could not post its `05` status on {}: {}. Branch protection that requires `05` does not see this verdict, so this run fails",
        &sha[..12.min(sha.len())],
        unposted.join("; ")
    );
    eprintln!("05: {said}");
    host.summary(&format!("**{said}.**\n"));
    ExitCode::from(if exit == 0 { 4 } else { exit })
}

/// Gate the change and print the brief; the exit code and the status line.
fn ci_gate(args: &Args, host: &dyn Host, event: &host::CiEvent) -> (u8, String) {
    let fail = |r: Report| {
        crate::report::emit(&r, args.json);
        (r.exit, format!("05 could not gate this change ({})", r.code))
    };
    if std::env::var("USE05_RUNNER_KEY").is_err() {
        return fail(Report::error("gate", "NO_RUNNER_KEY", "USE05_RUNNER_KEY is not set, so nothing can be proved authoritatively here".into(), Some("store the runner's secret key as a CI secret named USE05_RUNNER_KEY".into()), 6));
    }
    let top = match git::dirs(&args.repo) {
        Ok(d) => d.top,
        Err(e) => return fail(Report::from_core("gate", e)),
    };
    // Read before the change's own code runs, so that code cannot choose what runs after it (D73).
    let listeners = crate::extend::listeners().unwrap_or_default();
    // Receipts branches are not fetched by default; approvals and bypasses live there.
    let _ = git::run(&top, &["fetch", "--quiet", "origin", &format!("+refs/heads/{}/*:refs/remotes/origin/{}/*", store::BRANCH_DIR, store::BRANCH_DIR)]);

    // A run that another run started is checked out wherever its workflow says; the change is the
    // commit the event names, never what happens to be checked out (the default branch).
    let spec = match (&args.tree, event.kind) {
        (Some(t), _) => t.clone(),
        (None, EventKind::WorkflowRun) if event.head_sha.is_empty() => {
            return fail(Report::error("gate", "NO_HEAD", "the CI event names no commit to gate".into(), Some("pass the commit with --tree".into()), 6));
        }
        (None, EventKind::WorkflowRun) => event.head_sha.clone(),
        (None, _) => "HEAD".into(),
    };
    if git::resolve_commit(&top, &spec).is_none() && event.kind == EventKind::WorkflowRun {
        let _ = git::run(&top, &["fetch", "--quiet", "origin", &spec]);
    }
    let head = git::resolve_commit(&top, &spec);
    // What a change is measured from is its base branch; a merge queue's base only names the
    // branch the gate asks about, below.
    let base_ref = event.base_branch.as_ref().filter(|_| event.origin() != EventKind::MergeGroup).map(|b| format!("origin/{b}"));
    let base = base_ref
        .iter()
        .map(String::as_str)
        .chain(["origin/HEAD", "origin/main", "origin/master"])
        .find_map(|u| git::resolve_commit(&top, u))
        .and_then(|u| head.as_deref().and_then(|h| git::merge_base(&top, &u, h)))
        .filter(|b| Some(b) != head.as_ref())
        .or_else(|| git::resolve_commit(&top, &format!("{spec}^")));
    // Where the rules are read from: the base. Without one, a run another run started is checked
    // out at the change itself, so its HEAD would be the change's own rules: the default
    // branch's are read instead, or none.
    let rules = match (&base, event.kind) {
        (Some(b), _) => b.clone(),
        (None, EventKind::WorkflowRun) => {
            let default = event.default_branch.as_ref().map(|d| format!("origin/{d}"));
            match default.iter().map(String::as_str).chain(["origin/HEAD", "origin/main", "origin/master"]).find_map(|u| git::resolve_commit(&top, u)) {
                Some(c) => c,
                None => return fail(Report::error("gate", "NO_BASE", "the change has no base and the default branch cannot be found, so there are no rules to judge it by; its own are never used".into(), Some("fetch the default branch before the gate".into()), 6)),
            }
        }
        (None, _) => "HEAD".into(),
    };

    let mut ctx = match Ctx::open_with(&args.repo, None, Some(&rules)) {
        Ok(c) => c,
        Err(e) => return fail(Report::from_core("gate", e)),
    };
    let target = match ctx.target_from(&spec, base.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(Report::from_core("gate", e)),
    };
    // The agent's declaration and outcome reach CI as signed receipts, never as local state (D65).
    let mut from_receipts = Vec::new();
    if ctx.task.is_none() {
        let found = use05_core::evidence::classify(&ctx.trust, &store::find_all(ctx.top()));
        match use05_core::gate::task_from_receipts(&found, &target.oid) {
            Some((task, signer)) => {
                if signer.role == use05_core::policy::Role::Local {
                    from_receipts.push(format!("the declaration and outcome rest on a machine key ({}), not a person's or the runner's", signer.name));
                }
                from_receipts.push("late declarations and overlaps are only known on the machine where the work happened".to_string());
                seal_log_in_ci(&ctx, host, &task.id, &found, args.push);
                ctx.task = Some(task);
            }
            None => from_receipts.push("no trusted declaration was found for this tree, so scope and claims were not checked here".to_string()),
        }
    }
    // The change's own code runs only now, after the log was checked, sealed and pushed: what it
    // does cannot touch what was sealed before it ran.
    // Prove the *base's* required checks, so a change cannot swap in an easier command.
    // Only the checks this change calls for (D97): one scoped to other paths is not run, so a
    // toolchain or a package unrelated to the change cannot stop it, and its time is not spent.
    let changed: Vec<String> = match git::changed(&top, target.base_tree.as_deref(), &target.oid) {
        Ok(c) => c.into_iter().map(|c| c.path).collect(),
        Err(e) => return fail(Report::from_core("gate", e)),
    };
    let mut names: Vec<String> = ctx.policy.required_checks().filter(|c| c.applies_to(changed.iter().map(String::as_str))).map(|c| c.name.clone()).collect();
    // What the declaration asked for is required whatever the paths; one the policy does not define
    // is for the gate to report.
    for name in ctx.task.as_ref().and_then(|t| t.intent.as_ref()).map(|c| c.acceptance.clone()).unwrap_or_default() {
        if ctx.policy.check_named(&name).is_some() && !names.contains(&name) {
            names.push(name);
        }
    }
    let proved = if names.is_empty() {
        None
    } else {
        Some(prove::run(prove::Args {
            names,
            command: vec![],
            key: None,
            tree: spec.clone(),
            repo: args.repo.clone(),
            out: None,
            timeout: None,
            env: vec![],
            no_store: false,
            push: false,
            policy_rev: Some(rules.clone()),
            task: None,
        }))
    };
    let checks_ran = proved.is_some();
    if let Some(proved) = proved.filter(|p| p.exit == 6 || p.exit == 4) {
        return fail(proved);
    }

    // A push to an environment's branch is judged as the move it must be (D93): its promotion
    // record, checked against what was pushed, and its rules as of before the push. The checks
    // above still ran, so the next promotion up finds this tree's evidence.
    let moved_env = match (event.origin(), head.as_deref()) {
        (EventKind::Push, Some(h)) => crate::cmd::ci_env::environment_pushed(&top, &ctx.policy, &ctx.trust, event.lands_on(), h).cloned(),
        _ => None,
    };
    let mut gate = match (&moved_env, head.as_deref()) {
        (Some(env), Some(h)) => crate::cmd::ci_env::judge(&args.repo, &top, &ctx.policy, &ctx.trust, env, h),
        _ => match ctx.gate_on_host(&target, Some(event.lands_on()), event.default_branch.as_deref()) {
            Ok(g) => g,
            Err(e) => return fail(Report::from_core("gate", e)),
        },
    };
    // The key reached a run the change's own branch defines: say so, and how to move. It still
    // gates, since refusing would not take the key back (D94).
    if event.kind.branch_defined() {
        gate.findings.push(use05_core::gate::ci_key_exposed(&format!("use05 init --ci {}", host.name())));
        gate.findings.sort_by(|a, b| b.effect.cmp(&a.effect));
    }
    let decision = gate.decision;
    let line = status_line(&gate);
    announce(&listeners, &top, "ci", &target.oid, ctx.task.as_ref(), &gate);
    let mut brief = use05_core::brief::build(ctx.task.as_ref(), gate, &target.oid, &target.label, target.base_commit.as_deref(), target.head_commit.as_deref());
    brief.unknowns.extend(from_receipts);
    // This run is the CI gate; whether the host requires it before merging is not known here.
    brief.assurance = use05_core::brief::assurance(&brief.gate, true);
    brief.read_test_origin(&top, &ctx.policy);
    if let Some(fork) = &event.fork {
        let who = match (checks_ran, prove::check_user()) {
            (false, _) => "no check of it ran".to_string(),
            (true, Some(user)) => format!("its checks ran as {user}, which cannot read the runner key"),
            (true, None) => "its checks ran as the same user as 05, so they could have read the runner key".into(),
        };
        let pushed = if args.push { " Nothing was pushed for it but 05's own receipts." } else { "" };
        let said = format!("This change came from the fork {fork}: {who}.{pushed}");
        eprintln!("05: {said}");
        host.summary(&format!("**{said}**\n\n"));
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "v": 1, "command": "gate", "decision": decision.word(), "brief": brief })).expect("serialises"));
    } else {
        let text = brief::render(&Ui::stdout(), &brief, ctx.org.as_deref(), &[]);
        print!("{text}");
        let plain = brief::render(&Ui::fixed(100, true), &brief, ctx.org.as_deref(), &[]);
        host.summary(&format!("```text\n{plain}```\n"));
    }
    (decision.exit_code(), line)
}

pub fn run(args: Args) -> ExitCode {
    match (args.git_hook.as_deref(), args.ci) {
        (Some("pre-push"), _) => pre_push(&args),
        (Some(other), _) => {
            eprintln!("05: no gate for the git hook {other:?}");
            ExitCode::SUCCESS
        }
        (None, true) => ci(&args),
        (None, false) => crate::report::emit(
            &Report::error("gate", "NO_MODE", "choose where to gate: --git-hook pre-push, or --ci".into(), Some("to see a change's state now: use05 brief".into()), 6),
            args.json,
        ),
    }
}

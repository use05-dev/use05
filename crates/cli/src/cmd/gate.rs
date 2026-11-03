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
use crate::report::Report;
use crate::ui::{Glyph, Tone, Ui};

pub struct Args {
    pub git_hook: Option<String>,
    pub ci: bool,
    pub tree: Option<String>,
    pub push: bool,
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

fn blocked_text(ui: &Ui, what: &str, results: &[(String, GateResult)]) -> String {
    let mut out = String::new();
    let worst = results.iter().map(|(_, r)| r.decision).max().unwrap_or(Decision::Allow);
    let (glyph, tone) = match worst {
        Decision::Deny => (Glyph::Bad, Tone::Bad),
        Decision::ApprovalRequired => (Glyph::Warn, Tone::Warn),
        _ => (Glyph::Pending, Tone::Info),
    };
    out.push_str(&format!("{} {}  ({})\n", ui.paint(tone, ui.glyph(glyph)), ui.bold(&format!("05 stopped this {what}")), worst.word().to_uppercase().replace('_', " ")));
    for (name, r) in results.iter().filter(|(_, r)| r.decision != Decision::Allow) {
        out.push_str(&format!("  {}\n", ui.paint(Tone::Dim, name)));
        for f in r.findings.iter().filter(|f| f.effect >= Effect::Wait) {
            for (i, line) in ui.wrap(&format!("{}  {}", f.code, f.message), ui.width.saturating_sub(6)).iter().enumerate() {
                out.push_str(&format!("    {}{line}\n", if i == 0 { "" } else { "  " }));
            }
            if let Some(next) = &f.next {
                out.push_str(&format!("      {} {next}\n", ui.paint(Tone::Info, "→")));
            }
        }
    }
    out.push_str(&format!("\n  {}\n", ui.paint(Tone::Dim, "Break glass (logged): use05 bypass --reason \"<why>\"")));
    if what == "push" {
        out.push_str(&format!("  {}\n", ui.paint(Tone::Dim, "`git push --no-verify` skips this hook; 05 cannot stop that. Branch protection can.")));
    }
    ui.finish(out)
}

fn pre_push(args: &Args) -> ExitCode {
    let mut raw = String::new();
    let _ = std::io::stdin().take(1_000_000).read_to_string(&mut raw);
    let mut results: Vec<(String, GateResult)> = Vec::new();
    let ui = Ui::stderr();
    // Read before anything of the change runs (D73).
    let listeners = crate::extend::listeners().unwrap_or_default();

    let outcome = (|| -> Result<(), use05_core::Error> {
        for line in raw.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [_, local_sha, remote_ref, remote_sha] = f[..] else { continue };
            // Deleting a ref, or pushing receipts themselves, is not a change to gate.
            if local_sha == ZERO || !remote_ref.starts_with("refs/heads/") || remote_ref.starts_with(&format!("refs/heads/{}/", store::BRANCH_DIR)) {
                continue;
            }
            let top = git::dirs(&args.repo)?.top;
            let Some(base) = base_for_push(&top, remote_sha, local_sha) else {
                eprintln!("05: first push to this remote, so there is nothing to compare it with. It sets the baseline.");
                continue;
            };
            let base = Some(base);
            let ctx = Ctx::open_with(&args.repo, None, base.as_deref())?;
            let target = ctx.target_from(local_sha, base.as_deref())?;
            let branch = remote_ref.trim_start_matches("refs/heads/");
            let mut gate = ctx.gate_for(&target, Some(branch))?;
            // Prove what is missing for exactly what is pushed, with this machine's key (D65).
            let missing = gate.checks.iter().any(|c| matches!(c.state, use05_core::gate::CheckState::Missing | use05_core::gate::CheckState::Stale));
            if ctx.policy.evidence.prove_at_push && missing {
                let proved = prove::run(prove::Args {
                    names: vec![],
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
            announce(&listeners, &top, "pre-push", &target.oid, ctx.task.as_ref(), &gate);
            results.push((format!("{} → {}", &local_sha[..10.min(local_sha.len())], remote_ref.trim_start_matches("refs/heads/")), gate));
        }
        Ok(())
    })();

    if let Err(e) = outcome {
        if e.code == "ORG_LAYER_UNAVAILABLE" {
            eprintln!("{} 05 stopped this push: {}", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), e.message);
            return ExitCode::from(1);
        }
        // Fail open, loudly (D34).
        eprintln!("{} 05 could not check this push ({}). It was NOT blocked.", ui.paint(Tone::Warn, ui.glyph(Glyph::Warn)), e.message);
        return ExitCode::SUCCESS;
    }
    if results.iter().all(|(_, r)| r.decision == Decision::Allow) {
        for (name, r) in &results {
            if let Some(b) = &r.bypass {
                eprintln!("{} 05 let {name} through by break-glass: {} ({})", ui.paint(Tone::Warn, ui.glyph(Glyph::Warn)), b.reason, b.by.name);
            }
        }
        return ExitCode::SUCCESS;
    }
    eprint!("{}", blocked_text(&ui, "push", &results));
    ExitCode::from(1)
}

/// Countersign the task's action log with the runner key, if it still matches every seal (D70).
/// With `push`, the runner's receipts branch goes to the remote so the seal outlives the job.
fn seal_log_in_ci(ctx: &Ctx, task: &str, found: &use05_core::evidence::Found, push: bool) {
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
        if let Err(e) = push_runner_branch(top, &store::branch_for(&signer)) {
            eprintln!("05: the log was sealed, but the seal could not be pushed: {e}");
        }
    }
}

/// Push only the runner's receipts branch. In GitHub Actions the token comes by name
/// (`USE05_PUSH_TOKEN`), never from `.git/config`, so the code under test cannot find it there.
fn push_runner_branch(top: &std::path::Path, branch: &str) -> Result<(), String> {
    let token = std::env::var("USE05_PUSH_TOKEN").ok().filter(|t| !t.is_empty());
    let repo = std::env::var("GITHUB_REPOSITORY").ok().filter(|r| !r.is_empty());
    match (token, repo) {
        (Some(token), Some(repo)) => {
            let server = std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
            let host = server.trim_start_matches("https://").trim_end_matches('/');
            let url = format!("https://x-access-token:{token}@{host}/{repo}.git");
            let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
            git::run(top, &["push", "--quiet", &url, &refspec]).map(|_| ()).map_err(|e| e.message.replace(&token, "***"))
        }
        _ => store::push(top, branch).map(|_| ()).map_err(|e| e.message),
    }
}

fn ci(args: &Args) -> ExitCode {
    let fail = |r: Report| crate::report::emit(&r, args.json);
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

    let spec = args.tree.clone().unwrap_or_else(|| "HEAD".into());
    let head = git::resolve_commit(&top, &spec);
    let base_ref = std::env::var("GITHUB_BASE_REF").ok().filter(|b| !b.is_empty()).map(|b| format!("origin/{b}"));
    let base = base_ref
        .iter()
        .map(String::as_str)
        .chain(["origin/HEAD", "origin/main", "origin/master"])
        .find_map(|u| git::resolve_commit(&top, u))
        .and_then(|u| head.as_deref().and_then(|h| git::merge_base(&top, &u, h)))
        .filter(|b| Some(b) != head.as_ref())
        .or_else(|| git::resolve_commit(&top, &format!("{spec}^")));

    let mut ctx = match Ctx::open_with(&args.repo, None, base.as_deref().or(Some("HEAD"))) {
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
                seal_log_in_ci(&ctx, &task.id, &found, args.push);
                ctx.task = Some(task);
            }
            None => from_receipts.push("no trusted declaration was found for this tree, so scope and claims were not checked here".to_string()),
        }
    }
    // The change's own code runs only now, after the log was checked, sealed and pushed: what it
    // does cannot touch what was sealed before it ran.
    // Prove the *base's* required checks, so a change cannot swap in an easier command.
    let proved = prove::run(prove::Args {
        names: vec![],
        command: vec![],
        key: None,
        tree: spec.clone(),
        repo: args.repo.clone(),
        out: None,
        timeout: None,
        env: vec![],
        no_store: false,
        push: false,
        policy_rev: base.clone().or(Some("HEAD".into())),
        task: None,
    });
    if proved.exit == 6 || proved.exit == 4 {
        // No checks defined is acceptable for gating (the gate will say so); real errors are not.
        if proved.code != "NO_CHECKS" {
            return fail(proved);
        }
    }

    let (branch, default_branch) = where_ci_pushes();
    let gate = match ctx.gate_on_host(&target, Some(&branch), default_branch.as_deref()) {
        Ok(g) => g,
        Err(e) => return fail(Report::from_core("gate", e)),
    };
    let decision = gate.decision;
    announce(&listeners, &top, "ci", &target.oid, ctx.task.as_ref(), &gate);
    let mut brief = use05_core::brief::build(ctx.task.as_ref(), gate, &target.oid, &target.label, target.base_commit.as_deref(), target.head_commit.as_deref());
    brief.unknowns.extend(from_receipts);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "v": 1, "command": "gate", "decision": decision.word(), "brief": brief })).expect("serialises"));
    } else {
        let text = brief::render(&Ui::stdout(), &brief, ctx.org.as_deref(), &[]);
        print!("{text}");
        if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
            let plain = brief::render(&Ui::fixed(100, true), &brief, ctx.org.as_deref(), &[]);
            let _ = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| std::io::Write::write_all(&mut f, format!("```text\n{plain}```\n").as_bytes()));
        }
    }
    ExitCode::from(decision.exit_code())
}

/// Where CI's change goes, and the host's default branch when it says: a pull request's base, a
/// merge queue's base (its own branch is named for the queue), else the branch pushed. Empty when
/// CI names none, so that a policy asking for something before a push holds it rather than lets
/// it through.
fn where_ci_pushes() -> (String, Option<String>) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let event: serde_json::Value = var("GITHUB_EVENT_PATH").and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let default_branch = event["repository"]["default_branch"].as_str().filter(|b| !b.is_empty()).map(str::to_string);
    let queued = event["merge_group"]["base_ref"].as_str().filter(|_| var("GITHUB_EVENT_NAME").as_deref() == Some("merge_group")).map(|r| r.strip_prefix("refs/heads/").unwrap_or(r).to_string());
    let branch = var("GITHUB_BASE_REF").or(queued).or_else(|| var("GITHUB_REF_NAME").filter(|_| var("GITHUB_REF_TYPE").as_deref() == Some("branch"))).unwrap_or_default();
    (branch, default_branch)
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

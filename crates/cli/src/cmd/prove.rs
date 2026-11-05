use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use use05_core::keys;
use use05_core::policy::{CheckDef, Role};
use use05_core::store;
use use05_receipt::{Status, key_id, parse_secret_key, seal};
use use05_runner::{ProveOptions, RunnerError, prove_with_output};

use crate::ctx::Ctx;
use crate::report::{Report, Tone, command_text, duration, excerpt_lines};

pub struct Args {
    pub names: Vec<String>,
    pub command: Vec<String>,
    pub key: Option<PathBuf>,
    pub tree: String,
    pub repo: PathBuf,
    pub out: Option<PathBuf>,
    pub timeout: Option<u64>,
    pub env: Vec<String>,
    pub no_store: bool,
    pub push: bool,
    /// Read the policy from this commit instead of HEAD (CI proves the base's checks).
    pub policy_rev: Option<String>,
    /// Whose acceptance checks to include (default: the current task).
    pub task: Option<String>,
}

/// The OS user checks run as instead of the one holding the key (`USE05_CHECK_USER`; D94).
pub(crate) fn check_user() -> Option<String> {
    std::env::var("USE05_CHECK_USER").ok().filter(|u| !u.is_empty())
}

fn runner_error(e: RunnerError) -> Report {
    let code = e.code();
    let exit = if matches!(code, "GIT_MISSING" | "IO_ERROR") { 4 } else { 6 };
    let next = match code {
        "TREE_NOT_FOUND" => Some("check the revision, or leave --tree out to use the staged files".to_string()),
        "COMMAND_NOT_STARTED" if check_user().is_some() => Some(format!(
            "the checks run as {}, which cannot read this user's home: install the tool system-wide in a step before the gate (the setup-* actions install under /opt/hostedtoolcache)",
            check_user().unwrap_or_default()
        )),
        "COMMAND_NOT_STARTED" => Some("check that the command exists and is on your PATH".to_string()),
        "UNSAFE_PATH" => Some("this tree cannot be proven safely; inspect it with git ls-tree -r".to_string()),
        "LFS_UNAVAILABLE" => Some("install git-lfs (https://git-lfs.com), or turn off [evidence] lfs in the policy to check the pointers instead".to_string()),
        "LFS_FAILED" => Some("run git lfs fetch for this commit, or check that you can reach the LFS server; turn off [evidence] lfs in the policy to check the pointers instead".to_string()),
        "CHECK_USER_UNAVAILABLE" => Some("make that user first (in CI: sudo useradd --create-home --shell /bin/bash use05-check), or unset USE05_CHECK_USER".to_string()),
        _ => None,
    };
    Report::error("prove", code, e.to_string(), next, exit)
}

/// The signing key for this run: a key file, the CI secret, or this machine's own key.
fn signer(key: &Option<PathBuf>) -> Result<(use05_receipt::SigningKey, &'static str), Report> {
    if let Some(path) = key {
        return keys::read_secret_file(path).map(|k| (k, "key file")).map_err(|e| Report::from_core("prove", e));
    }
    if let Ok(text) = std::env::var("USE05_RUNNER_KEY") {
        return parse_secret_key(&text).map(|k| (k, "runner key")).map_err(|e| Report::error("prove", "KEY_UNUSABLE", format!("USE05_RUNNER_KEY: {e}"), None, 6));
    }
    keys::ensure_local().map(|(k, _)| (k, "this machine")).map_err(|e| Report::from_core("prove", e))
}

struct Run {
    check: Option<CheckDef>,
    argv: Vec<String>,
}

pub fn run(args: Args) -> Report {
    let ctx = match Ctx::open_with(&args.repo, args.task.as_deref(), args.policy_rev.as_deref()) {
        Ok(c) => c,
        Err(e) => return Report::from_core("prove", e),
    };
    let (secret, key_source) = match signer(&args.key) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let signer_id = key_id(&secret.verifying_key());
    // With no --tree: the staged files if any are staged, otherwise the working tree.
    let tree_spec = if args.tree == "auto" { use05_core::git::default_spec(ctx.top()).to_string() } else { args.tree.clone() };

    let runs: Vec<Run> = if !args.command.is_empty() {
        vec![Run { check: None, argv: args.command.clone() }]
    } else {
        let defs: Vec<&CheckDef> = if args.names.is_empty() {
            // Every required check, and the task's own acceptance checks: the gate needs both.
            let mut defs: Vec<&CheckDef> = ctx.policy.required_checks().collect();
            for name in ctx.task.as_ref().and_then(|t| t.intent.as_ref()).map(|c| c.acceptance.clone()).unwrap_or_default() {
                if let Some(def) = ctx.policy.check_named(&name).filter(|d| !defs.iter().any(|x| x.name == d.name)) {
                    defs.push(def);
                }
            }
            defs
        } else {
            let mut found = Vec::new();
            for name in &args.names {
                match ctx.policy.check_named(name) {
                    Some(def) => found.push(def),
                    None => {
                        let known = ctx.policy.check.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ");
                        return Report::error(
                            "prove",
                            "CHECK_UNDEFINED",
                            format!("the policy defines no check named {name:?}"),
                            Some(if known.is_empty() { "add a [[check]] to .05/policy.toml, or run: use05 prove -- <command>".into() } else { format!("defined checks: {known}") }),
                            6,
                        );
                    }
                }
            }
            found
        };
        if defs.is_empty() {
            return Report::error(
                "prove",
                "NO_CHECKS",
                "there is nothing to prove: the policy defines no required checks".to_string(),
                Some("run `use05 init` to propose some, or: use05 prove -- <command>".to_string()),
                6,
            );
        }
        defs.into_iter().map(|d| Run { check: Some(d.clone()), argv: d.run.clone() }).collect()
    };

    let mut explicit_env = Vec::new();
    for spec in &args.env {
        match spec.split_once('=') {
            Some((n, v)) => explicit_env.push((n.to_string(), v.to_string())),
            None => match std::env::var(spec) {
                Ok(v) => explicit_env.push((spec.clone(), v)),
                Err(_) => {
                    return Report::error("prove", "ENV_NOT_SET", format!("--env {spec}: that variable is not set in your environment"), Some(format!("set it first, or give a value: --env {spec}=<value>")), 6);
                }
            },
        }
    }

    let mut rows: Vec<(String, String)> = Vec::new();
    let mut details = Vec::new();
    let mut failed = 0usize;
    let mut timed_out = 0usize;
    let mut excerpt = Vec::new();
    let mut tree_oid = String::new();
    let mut notes = Vec::new();
    let mut lfs_files = 0usize;
    let mut stored_branch = None;
    let total = runs.len();

    for run in &runs {
        let mut pass_env = explicit_env.clone();
        if let Some(def) = &run.check {
            for name in &def.env {
                let allowed = ctx.policy.env.allow.as_ref().is_none_or(|a| a.contains(name));
                if !allowed {
                    notes.push(format!("{name} was not passed to {}: the organisation's policy does not allow it", def.name));
                } else if let Ok(v) = std::env::var(name) {
                    pass_env.push((name.clone(), v));
                }
            }
        }
        let timeout = args.timeout.or(run.check.as_ref().map(|c| c.timeout_secs)).unwrap_or(900);
        let proof = match prove_with_output(&ProveOptions {
            repo: args.repo.clone(),
            tree: tree_spec.clone(),
            argv: run.argv.clone(),
            timeout: Duration::from_secs(timeout),
            pass_env,
            check: run.check.as_ref().map(|c| c.name.clone()),
            dir: run.check.as_ref().and_then(|c| c.dir.clone()),
            // In CI the checks run as another OS user, which cannot read the runner key (D94).
            check_user: check_user(),
            lfs: ctx.policy.evidence.lfs,
        }) {
            Ok(p) => p,
            Err(e) => return runner_error(e),
        };
        let statement = proof.statement;
        let not_run = proof.not_run;
        let (oid, content) = statement.tree_subject().map(|(a, b)| (a.to_string(), b.to_string())).expect("runner writes a tree subject");
        tree_oid = oid.clone();
        let envelope = seal(&statement, &secret).to_json_bytes();
        if !args.no_store {
            match store::put(ctx.top(), &oid, &envelope, &signer_id) {
                Ok(branch) => stored_branch = Some(branch),
                Err(e) => return Report::from_core("prove", e),
            }
        }
        if let Some(path) = args.out.as_ref().filter(|_| total == 1) {
            if let Err(e) = std::fs::write(path, &envelope) {
                return Report::error("prove", "RECEIPT_NOT_WRITTEN", format!("could not write {}: {e}", path.display()), None, 4);
            }
        }

        let result = &statement.predicate.result;
        let label = run.check.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| command_text(&run.argv));
        let verdict = match (result.status, result.exit_code, result.signal) {
            (Status::Passed, _, _) => format!("passed in {}", duration(result.duration_ms)),
            (Status::Failed, Some(c), _) => format!("FAILED (exit {c}) in {}", duration(result.duration_ms)),
            (Status::Failed, None, Some(s)) => format!("FAILED (signal {s})"),
            (Status::Failed, None, None) => "FAILED".to_string(),
            (Status::TimedOut, _, _) => format!("TIMED OUT after {timeout}s"),
        };
        if total == 1 {
            rows.push((if run.check.is_some() { "check" } else { "command" }.to_string(), label.clone()));
            rows.push(("result".to_string(), verdict));
        } else {
            rows.push((label.clone(), verdict));
        }
        if result.status != Status::Passed {
            failed += 1;
            timed_out += usize::from(result.status == Status::TimedOut);
            if excerpt.is_empty() {
                let tail = if proof.stderr_tail.is_empty() { &proof.stdout_tail } else { &proof.stderr_tail };
                excerpt = excerpt_lines(tail, 12);
            }
        }
        lfs_files = lfs_files.max(statement.predicate.lfs.len());
        let mut detail = json!({
            "check": run.check.as_ref().map(|c| c.name.clone()),
            "command": run.argv,
            "status": result.status,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "tree": { "oid": oid, "sha256": content },
        });
        if !statement.predicate.lfs.is_empty() {
            detail["lfs"] = json!(statement.predicate.lfs);
        }
        if let Some(reason) = &not_run {
            // The check failed without running: say why, in words and in the data.
            detail["reason"] = json!(reason);
            notes.push(format!("{label}: {reason}"));
        }
        details.push(detail);
        if let Some(task) = &ctx.task {
            let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "prove", "check": label, "status": result.status }));
        }
    }

    let role = ctx.trust.by_id(&signer_id).map(|k| k.role);
    let short = tree_oid.chars().take(12).collect::<String>();
    let tree_label = match tree_spec.as_str() {
        "index" => "staged files".to_string(),
        "worktree" => "working tree".to_string(),
        other => other.to_string(),
    };
    rows.push(("tree".into(), format!("{short}  ({tree_label})")));
    if let Some(branch) = &stored_branch {
        rows.push(("receipts".into(), format!("branch {branch}")));
    }
    rows.push((
        "signed".into(),
        match role {
            Some(Role::Runner) => format!("{} ({key_source}, runner role: authoritative)", &signer_id[..12]),
            Some(Role::Local) => format!("{} ({key_source}, advisory)", &signer_id[..12]),
            _ => format!("{} ({key_source}, not in your trusted keys)", &signer_id[..12]),
        },
    ));
    match lfs_files {
        0 => {}
        1 => notes.push("1 LFS file was fetched, so the check ran on the real file; the receipt lists it.".to_string()),
        n => notes.push(format!("{n} LFS files were fetched, so the checks ran on the real files; the receipt lists them.")),
    }
    if let Some(branch) = &stored_branch {
        notes.extend(super::push_note(ctx.top(), branch, args.push));
    }
    if role != Some(Role::Runner) {
        notes.push("Advisory: a key on this machine can be used by an agent running as you. Authoritative evidence is produced in CI.".to_string());
    }

    let (outcome, code, tone, headline, exit) = if failed == 0 {
        (
            "passed",
            "PROVED",
            Tone::Good,
            if total == 1 { "Proved: the check passed".to_string() } else { format!("Proved: all {total} checks passed") },
            0,
        )
    } else {
        (if timed_out == failed { "timed_out" } else { "failed" }, if timed_out == failed { "RECORDED_TIMED_OUT" } else { "RECORDED_FAILED" }, Tone::Bad, format!("{failed} of {total} check{} did not pass. The receipt{} say{} so.", if total == 1 { "" } else { "s" }, if total == 1 { "" } else { "s" }, if total == 1 { "s" } else { "" }), 2)
    };

    Report {
        command: "prove",
        outcome,
        code,
        tone,
        headline,
        rows,
        notes,
        next: Some(if failed == 0 { "use05 brief".to_string() } else { "fix what failed, then: use05 prove".to_string() }),
        excerpt,
        details: json!({ "checks": details, "signer": signer_id, "role": role.map(|r| r.word()), "stored_on": stored_branch }),
        exit,
    }
}

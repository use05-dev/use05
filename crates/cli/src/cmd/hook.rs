//! Agent hooks. `use05 hook <agent> <event>` reads the agent's JSON from stdin and answers in
//! that agent's format. `generic` is for any other agent (D73): the same input fields and event
//! names, and a plain answer, `{decision, reason, context}`, or nothing when there is nothing to say. These are advisory: an agent's hooks fail open by design, so a crash
//! here never stops work. It warns loudly and records that enforcement was skipped (D34).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};
use use05_core::intent::is_protected;
use use05_core::policy::{Middle, OnError, Severity};
use use05_core::{log, task::Task};

use crate::ctx::Ctx;

fn read_stdin() -> Result<Value, String> {
    let mut raw = String::new();
    std::io::stdin().take(1_000_000).read_to_string(&mut raw).map_err(|e| format!("could not read the hook input: {e}"))?;
    serde_json::from_str(&raw).map_err(|_| "the hook input was not JSON".to_string())
}

fn deny(reason: &str) -> Value {
    json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason } })
}

fn ask(reason: &str) -> Value {
    json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": reason } })
}

/// Files a tool call is about to write: `file_path`, a notebook, or paths named in a patch.
fn paths_in(tool_input: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["file_path", "notebook_path", "path"] {
        if let Some(p) = tool_input.get(key).and_then(Value::as_str) {
            out.push(p.to_string());
        }
    }
    for key in ["input", "patch", "command"] {
        if let Some(text) = tool_input.get(key).and_then(Value::as_str) {
            for line in text.lines() {
                for marker in ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "] {
                    if let Some(p) = line.strip_prefix(marker) {
                        out.push(p.trim().to_string());
                    }
                }
            }
        }
    }
    out
}

/// Make a path relative to the repository, or `None` if it is outside it.
fn relative(top: &Path, cwd: &Path, path: &str) -> Option<String> {
    let abs = if Path::new(path).is_absolute() { PathBuf::from(path) } else { cwd.join(path) };
    let mut parts: Vec<String> = Vec::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Normal(n) => parts.push(n.to_string_lossy().to_string()),
            _ => {}
        }
    }
    // Compare real locations: a path reported through a symlink (macOS keeps /var -> /private/var)
    // must not look like it is outside the repository, or a protected file would go unguarded.
    let names = |p: &Path| -> Vec<String> { p.components().filter_map(|c| match c { std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()), _ => None }).collect() };
    let lexical = PathBuf::from("/").join(parts.join("/"));
    let candidates = [(top.to_path_buf(), lexical.clone()), (resolve(top), resolve(&lexical))];
    for (top_path, path) in candidates {
        let (top_parts, parts) = (names(&top_path), names(&path));
        if parts.len() >= top_parts.len() && parts[..top_parts.len()] == top_parts[..] {
            return Some(parts[top_parts.len()..].join("/"));
        }
    }
    None
}

/// Resolve symlinks in the deepest part of `path` that exists; the rest (a file about to be
/// created) is kept as written.
fn resolve(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&current) {
            return rest.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (current.file_name().map(|n| n.to_os_string()), current.parent().map(Path::to_path_buf)) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Split a shell command into words, honouring quotes. Pattern-based and conservative: this is a
/// guard against mistakes, not a sandbox, and it says so.
fn words(command: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let (mut current, mut word) = (Vec::new(), String::new());
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    word.push(n);
                }
            }
            (None, ' ' | '\t') => {
                if !word.is_empty() {
                    current.push(std::mem::take(&mut word));
                }
            }
            (None, ';' | '\n' | '|' | '&' | '(' | ')' | '`') => {
                if !word.is_empty() {
                    current.push(std::mem::take(&mut word));
                }
                if !current.is_empty() {
                    commands.push(std::mem::take(&mut current));
                }
            }
            (None, c) => word.push(c),
        }
    }
    if !word.is_empty() {
        current.push(word);
    }
    if !current.is_empty() {
        commands.push(current);
    }
    commands
}

/// Commands an agent should not run unobserved, with the reason and a safer alternative.
fn risky(command: &str) -> Option<String> {
    for words in words(command) {
        let w: Vec<&str> = words.iter().map(String::as_str).collect();
        let program = w.first().copied().unwrap_or("");
        let has = |s: &str| w.iter().any(|x| *x == s);
        let sub = w.get(1).copied().unwrap_or("");
        if program == "use05" && ["approve", "bypass", "uninstall"].contains(&sub) || (program == "use05" && sub == "key" && has("--approver")) {
            return Some(format!("`use05 {sub}` is for a person: it needs the approver passphrase. Ask the user to run it."));
        }
        if program == "git" {
            let has_force = w.iter().any(|x| x.starts_with("--force") || *x == "-f" || x.starts_with('+'));
            if sub == "push" && has_force {
                return Some("a force push can destroy others' work; use a normal push, or ask the user".into());
            }
            if sub == "reset" && has("--hard") {
                return Some("`git reset --hard` discards uncommitted work; use `git stash` instead".into());
            }
            if sub == "clean" && w.iter().any(|x| x.starts_with("-") && x.contains('f')) {
                return Some("`git clean -f` deletes untracked files for good; list them first with `git clean -n`".into());
            }
            if has("--no-verify") {
                return Some("skipping git hooks defeats the checks; fix what the hook reports, or ask the user".into());
            }
            if sub == "config" && w.iter().any(|x| x.contains("hooksPath")) {
                return Some("changing core.hooksPath would switch off the repository's hooks".into());
            }
        }
        // Writing to 05's own rules or git hooks through the shell.
        let writes = ["rm", "mv", "cp", "tee", "sed", "truncate", "chmod", "ln"].contains(&program) || command.contains('>');
        if writes && w.iter().any(|x| x.contains(".05/") || x.contains(".git/hooks") || x.contains("/.05")) {
            return Some("05's rules and git hooks are protected; changing them needs a person's approval".into());
        }
    }
    None
}

struct Decision {
    output: Option<Value>,
    /// What to record in the action log; `Null` records nothing (reads are not logged).
    log: Value,
}

const READ_TOOLS: [&str; 4] = ["Read", "Grep", "Glob", "NotebookRead"];

/// A path a no-read rule covers, including the folder a `dir/**` rule names.
fn unreadable(policy: &use05_core::policy::Policy, path: &str) -> bool {
    policy.protect.is_no_read(path) || policy.protect.no_read.iter().any(|p| p.strip_suffix("/**") == Some(path))
}

/// Path rules (D79) broken by a shell command: reading a no-read file, changing a locked one,
/// rewriting an existing append-only one, or deleting a no-delete one. Word-based and
/// conservative, like `risky`: a guard against mistakes, not a sandbox.
fn path_rule_in_command(ctx: &Ctx, cwd: &Path, command: &str) -> Option<String> {
    let rules = &ctx.policy.protect;
    let top = ctx.top();
    for w in words(command) {
        let program = w.first().map(String::as_str).unwrap_or("");
        let (program, args) = if program == "git" { (w.get(1).map(String::as_str).unwrap_or(""), &w[w.len().min(2)..]) } else { (program, &w[w.len().min(1)..]) };
        let reads = ["cat", "head", "tail", "less", "more", "grep", "rg", "awk", "sed", "cp", "base64", "xxd", "strings", "source", ".", "open"].contains(&program);
        let deletes = ["rm", "mv", "unlink"].contains(&program);
        let writes = deletes || ["cp", "tee", "sed", "truncate", "chmod", "ln", "touch"].contains(&program) || command.contains('>');
        for arg in args.iter().filter(|a| !a.starts_with('-')) {
            let Some(rel) = relative(top, cwd, arg.trim_start_matches('>')) else { continue };
            if reads && unreadable(&ctx.policy, &rel) {
                return Some(format!("{rel} is not to be read by agents here. Ask the user if you need something from it."));
            }
            if writes && rules.is_locked(&rel) {
                return Some(format!("{rel} is locked: it is never changed here. Leave it as it is; unlocking is a change to .05/policy.toml that a person approves first."));
            }
            if writes && rules.is_append_only(&rel) && top.join(&rel).exists() {
                return Some(format!("{rel} is in an append-only area: existing files are never edited, renamed or deleted. Add a new file instead."));
            }
            if deletes && rules.is_no_delete(&rel) {
                return Some(format!("{rel} may be edited but never deleted."));
            }
        }
    }
    None
}

fn pre_tool_use(ctx: &Ctx, task: &Task, cwd: &Path, tool: &str, input: &Value) -> Decision {
    let top = ctx.top();
    if READ_TOOLS.contains(&tool) {
        let read: Vec<String> = ["file_path", "notebook_path", "path"].iter().filter_map(|k| input.get(*k).and_then(Value::as_str)).filter_map(|p| relative(top, cwd, p)).collect();
        let output = read.iter().find(|p| unreadable(&ctx.policy, p)).map(|p| deny(&format!("05: {p} is not to be read by agents here. Ask the user if you need something from it.")));
        return Decision { output, log: Value::Null };
    }
    let mut log = json!({ "event": "tool", "tool": tool });

    if let Some(command) = input.get("command").and_then(Value::as_str) {
        if let Some(reason) = risky(command) {
            log["decision"] = json!("deny");
            log["why"] = json!("risky command");
            return Decision { output: Some(deny(&format!("05: {reason}"))), log };
        }
        if let Some(reason) = path_rule_in_command(ctx, cwd, command) {
            log["decision"] = json!("deny");
            log["why"] = json!("path rule");
            return Decision { output: Some(deny(&format!("05: {reason}"))), log };
        }
    }

    let touched: Vec<String> = paths_in(input).iter().filter_map(|p| relative(top, cwd, p)).collect();
    log["paths"] = json!(touched);
    if touched.is_empty() {
        return Decision { output: None, log };
    }

    // Path rules (D79): locks, append-only areas and files that may not be deleted. No approval
    // route is offered: a lock is lifted by changing the policy, not by asking.
    if input.get("command").is_none() {
        let rules = &ctx.policy.protect;
        let deleted: Vec<String> = ["input", "patch"]
            .iter()
            .filter_map(|k| input.get(*k).and_then(Value::as_str))
            .flat_map(|t| t.lines().filter_map(|l| l.strip_prefix("*** Delete File: ")).map(|p| p.trim().to_string()).collect::<Vec<_>>())
            .filter_map(|p| relative(top, cwd, &p))
            .collect();
        let refusal = touched.iter().find_map(|p| {
            if rules.is_locked(p) {
                Some(format!("05: {p} is locked: it is never changed here. Leave it as it is; unlocking is a change to .05/policy.toml that a person approves first."))
            } else if rules.is_append_only(p) && top.join(p).exists() {
                Some(format!("05: {p} is in an append-only area: existing files are never edited, renamed or deleted. Add a new file instead."))
            } else if rules.is_no_delete(p) && deleted.contains(p) {
                Some(format!("05: {p} may be edited but never deleted."))
            } else {
                None
            }
        });
        if let Some(reason) = refusal {
            log["decision"] = json!("deny");
            log["why"] = json!("path rule");
            return Decision { output: Some(deny(&reason)), log };
        }
    }

    // Protected paths need an approved intent that covers them.
    let protected: Vec<&String> = touched.iter().filter(|p| is_protected(&ctx.policy, p)).collect();
    if !protected.is_empty() {
        let covered = ctx.intent_approved() && task.intent.as_ref().is_some_and(|c| protected.iter().all(|p| c.allows(p) && c.has_scope()));
        if !covered {
            log["decision"] = json!("deny");
            return Decision {
                output: Some(deny(&format!(
                    "05: {} is protected. A person must approve the intent first: ask the user to run `use05 approve --intent` (it needs their approver passphrase).",
                    protected[0]
                ))),
                log,
            };
        }
    }

    // Outside the declared scope: severity comes from policy.
    if let Some(card) = task.intent.as_ref().filter(|c| c.has_scope() || !c.scope.exclude.is_empty()) {
        let outside: Vec<&String> = touched.iter().filter(|p| !card.allows(p)).collect();
        if let Some(path) = outside.first() {
            let msg = format!("05: {path} is outside the declared scope ({}). Say so to the user, or widen the intent.", card.scope.include.join(", "));
            match ctx.policy.drift.scope {
                Severity::Deny | Severity::Approval => {
                    log["decision"] = json!("deny");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Warn => {
                    log["decision"] = json!("ask");
                    return Decision { output: Some(ask(&msg)), log };
                }
                Severity::Allow => {}
            }
        }
    }
    // Inside another task's reservation, or a file another session edited lately: tell this one,
    // or ask a person.
    if ctx.policy.drift.overlap != Severity::Allow {
        let res = use05_core::overlap::reservations(&ctx.store, &task.id, ctx.policy.drift.reservation_idle_hours as u64 * 3600, use05_core::time::now_secs());
        if let Some((path, r)) = touched.iter().find_map(|p| use05_core::overlap::reserved(&res, p).map(|r| (p, r))) {
            let msg = format!("05: {}. Stay out of it, or coordinate with the user.", r.describe(path));
            log["overlap"] = json!([format!("{}:{path}", r.task)]);
            match ctx.policy.drift.overlap {
                Severity::Deny => {
                    log["decision"] = json!("deny");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Approval => {
                    log["decision"] = json!("ask");
                    return Decision { output: Some(ask(&msg)), log };
                }
                _ => {
                    log["decision"] = json!("allow");
                    return Decision { output: Some(json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "additionalContext": msg } })), log };
                }
            }
        }
        let overlaps = use05_core::overlap::recent(&ctx.store, &task.id, &touched, use05_core::overlap::WINDOW_SECS);
        if let Some(first) = overlaps.first() {
            let msg = format!(
                "05: {} was edited {} min ago by another agent session (task {}: \"{}\"). Check `git diff` for its changes before overwriting them, or coordinate with the user.",
                first.path, first.minutes_ago, first.task, first.title
            );
            log["overlap"] = json!(overlaps.iter().map(|o| format!("{}:{}", o.task, o.path)).collect::<Vec<_>>());
            match ctx.policy.drift.overlap {
                Severity::Deny => {
                    log["decision"] = json!("deny");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Approval => {
                    log["decision"] = json!("ask");
                    return Decision { output: Some(ask(&msg)), log };
                }
                _ => {
                    // Warn: the edit goes ahead, and the agent is told. No permission decision is
                    // made, so the agent's normal permission rules still apply.
                    log["decision"] = json!("allow");
                    return Decision { output: Some(json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "additionalContext": msg } })), log };
                }
            }
        }
    }
    log["decision"] = json!("allow");
    Decision { output: None, log }
}

fn session_context(ctx: &Ctx, task: &Task) -> String {
    let mut lines = vec!["05 is watching this repository's changes; what you do is recorded on this machine only.".to_string()];
    match task.intent.as_ref().filter(|c| c.has_scope()) {
        Some(card) => lines.push(format!("Declared scope for this task: {}.", card.scope.include.join(", "))),
        None => lines.push("No scope was declared for this task.".into()),
    }
    let mut protected = ctx.policy.protect.paths.clone();
    protected.push(".05/**".into());
    lines.push(format!("Protected paths need a person's approval: {}.", protected.join(", ")));
    let rules = &ctx.policy.protect;
    let mut locked = rules.locked.clone();
    locked.extend(rules.absolute.iter().cloned());
    for (list, what) in [
        (&locked, "Locked (never change these)"),
        (&rules.append_only, "Append-only (add new files; never edit, rename or delete existing ones)"),
        (&rules.no_delete, "Never delete"),
        (&rules.no_read, "Do not read"),
    ] {
        if !list.is_empty() {
            lines.push(format!("{what}: {}.", list.join(", ")));
        }
    }
    let names: Vec<&str> = ctx.policy.check.iter().map(|c| c.name.as_str()).collect();
    if !names.is_empty() {
        lines.push(format!("Checks you can name with --check: {}.", names.join(", ")));
    }
    lines.push("Before you edit, declare your plan with `use05 start \"<what you will do>\" --scope \"<paths>\"`. When you are done, `use05 finish --outcome \"<what you did>\"`; 05 runs the checks itself.".into());
    lines.join(" ")
}

/// Seal what this session's agent left in the inbox: its declarations become the task's intent,
/// its "finished" becomes the outcome. The author is this hook's agent, never what the file
/// claims (D67). Returns what to tell the agent.
fn seal_pending(ctx: &Ctx, task: &mut Task, agent: &str, session: &str) -> Vec<String> {
    let mut notes = Vec::new();
    for (path, pending) in use05_core::inbox::for_session(ctx.top(), session) {
        let state = ctx.store.state_dir();
        match pending.entry {
            use05_core::inbox::Entry::Start { title, card } => {
                task.sandbox = pending.sandbox.clone();
                if let Some(c) = card.as_ref().filter(|c| c.has_scope()) {
                    let res = use05_core::overlap::reservations(&ctx.store, &task.id, ctx.policy.drift.reservation_idle_hours as u64 * 3600, use05_core::time::now_secs());
                    if let Some((r, area)) = use05_core::overlap::conflicts(&res, &c.scope.include).first() {
                        let said = r.describe(area);
                        if ctx.policy.drift.overlap == Severity::Deny {
                            notes.push(format!("05: your declaration \"{title}\" was not sealed: {said}. Narrow your --scope or wait, then declare again."));
                            let _ = log::append(&state, &task.id, json!({ "event": "declaration_refused", "overlap": r.task }));
                            let _ = use05_core::inbox::remove(&path);
                            continue;
                        }
                        if ctx.policy.drift.overlap != Severity::Allow {
                            notes.push(format!("05: {said}. Narrow your --scope or wait."));
                        }
                    }
                }
                task.author = format!("agent:{agent}");
                if let Err(e) = ctx.store.declare(task, &title, card) {
                    notes.push(format!("05 could not seal the declaration \"{title}\": {}", e.message));
                    continue;
                }
                let _ = log::append(&state, &task.id, json!({ "event": "sealed", "title": task.title, "intent_sha256": task.intent_sha256 }));
                crate::cmd::start::publish_declaration(ctx, task);
                crate::cmd::start::publish_log_seal(ctx, task, true);
                notes.push(format!("05 sealed your declaration \"{}\" (task {}).", task.title, task.id));
            }
            use05_core::inbox::Entry::Finish { outcome } => {
                if let Err(e) = ctx.store.finish(task, outcome.as_deref()) {
                    notes.push(format!("05 could not record what you did: {}", e.message));
                    continue;
                }
                let _ = log::append(&state, &task.id, json!({ "event": "finish", "has_outcome": task.outcome.is_some() }));
                crate::cmd::start::publish_completion(ctx, task);
                crate::cmd::start::publish_log_seal(ctx, task, true);
                notes.push(format!("05 recorded what you did for task {}.", task.id));
            }
        }
        let _ = use05_core::inbox::remove(&path);
    }
    notes
}

/// When the agent stops, prove what is missing for its change from here, outside its sandbox
/// (D65): only checks that have run before and fit the policy's budget. Returns the checks that
/// failed. Everything else is left for the pre-push gate and CI, and the log says so.
fn prove_at_stop(ctx: &Ctx, task: &Task) -> Vec<String> {
    let budget_ms = ctx.policy.evidence.stop_budget_secs.saturating_mul(1000);
    if budget_ms == 0 {
        return Vec::new();
    }
    let Ok(target) = ctx.target(None) else { return Vec::new() };
    let Ok(gate) = ctx.gate(&target) else { return Vec::new() };
    let wanted: Vec<&use05_core::gate::CheckStatus> = gate.checks.iter().filter(|c| matches!(c.state, use05_core::gate::CheckState::Missing | use05_core::gate::CheckState::Stale)).collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let found = use05_core::evidence::classify(&ctx.trust, &use05_core::store::find_all(ctx.top()));
    let (mut chosen, mut left, mut spent) = (Vec::new(), Vec::new(), 0u64);
    for c in wanted {
        match use05_core::evidence::last_duration_ms(&found, &c.run) {
            Some(ms) if spent + ms <= budget_ms => {
                spent += ms;
                chosen.push(c.name.clone());
            }
            _ => left.push(c.name.clone()),
        }
    }
    let mut failed = Vec::new();
    if !chosen.is_empty() {
        let report = crate::cmd::prove::run(crate::cmd::prove::Args {
            names: chosen.clone(),
            command: vec![],
            key: None,
            tree: "auto".into(),
            repo: ctx.top().to_path_buf(),
            out: None,
            // Each check's own timeout: a cut-off here would store a failure the agent did not cause.
            timeout: None,
            env: vec![],
            no_store: false,
            push: false,
            policy_rev: None,
            task: Some(task.id.clone()),
        });
        for c in report.details["checks"].as_array().into_iter().flatten() {
            if c["status"] != "passed" {
                if let Some(name) = c["check"].as_str() {
                    failed.push(name.to_string());
                }
            }
        }
    }
    if ctx.policy.record.middle == Middle::Local {
        let _ = log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "proved_at_stop", "proved": chosen, "failed": failed, "left_for_push": left }));
    }
    failed
}

/// Remove finished working branches and worktrees whose work is in their target (D69).
fn tidy(ctx: &Ctx, including_here: bool) {
    let _ = use05_core::branches::tidy(&ctx.store, &ctx.policy, ctx.top(), including_here);
}

fn with_context(event: &str, output: Option<Value>, notes: &[String]) -> Option<Value> {
    if notes.is_empty() || !["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"].contains(&event) {
        return output;
    }
    let text = notes.join(" ");
    match output {
        None => Some(json!({ "hookSpecificOutput": { "hookEventName": event, "additionalContext": text } })),
        Some(mut v) => {
            if let Some(o) = v.get_mut("hookSpecificOutput").and_then(Value::as_object_mut) {
                let joined = match o.get("additionalContext").and_then(Value::as_str) {
                    Some(existing) => format!("{existing} {text}"),
                    None => text,
                };
                o.insert("additionalContext".into(), json!(joined));
            }
            Some(v)
        }
    }
}

fn run_inner(agent: &str, event: &str) -> Result<Option<Value>, String> {
    let payload = read_stdin()?;
    let cwd = payload.get("cwd").and_then(Value::as_str).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let session = payload.get("session_id").and_then(Value::as_str).unwrap_or("").to_string();
    let Ok(probe) = use05_core::task::Store::open(&cwd) else { return Ok(None) }; // not a repository: no opinion

    // Without a session there is no task to hold the agent to: no task is made, nothing is
    // proved, landed or cleaned up, and only the repository's own protections apply.
    if session.is_empty() {
        if event != "PreToolUse" {
            return Ok(None);
        }
        let ctx = Ctx::open(&cwd, None).map_err(|e| e.message)?;
        let unattached = probe.unattached(agent);
        let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
        let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
        return Ok(pre_tool_use(&ctx, &unattached, &cwd, tool, &input).output);
    }

    // One task per agent session, started on first sight, with the intent inferred. Everything
    // below reads the rules, approvals and base of this task, never another one's.
    let mut task = match probe.for_session(&session) {
        Some(t) => t,
        None => {
            let mut t = probe.create(&format!("{agent} session {}", session.chars().take(8).collect::<String>()), &format!("agent:{agent}"), None, Some(&session)).map_err(|e| e.message)?;
            t.agent = Some(use05_core::task::AgentId { kind: agent.to_string(), session: session.clone(), model: None });
            t.owner = use05_core::task::local_owner(&probe.dirs.top);
            probe.save(&t).map_err(|e| e.message)?;
            t
        }
    };
    // The model, when the agent's hook says which one (it may only say so on some events).
    if let Some(model) = payload.get("model").and_then(Value::as_str).filter(|m| !m.is_empty()) {
        if let Some(a) = task.agent.as_mut().filter(|a| a.model.is_none()) {
            a.model = Some(model.to_string());
            probe.save(&task).map_err(|e| e.message)?;
        }
    }
    let mut ctx = Ctx::open(&cwd, Some(&task.id)).map_err(|e| e.message)?;
    let notes = seal_pending(&ctx, &mut task, agent, &session);
    if !notes.is_empty() {
        // The intent changed: read the rules and approvals for the task as it is now.
        ctx = Ctx::open(&cwd, Some(&task.id)).map_err(|e| e.message)?;
    }
    let recording = ctx.policy.record.middle == Middle::Local;
    let state = ctx.store.state_dir();
    let note = |v: Value| {
        if recording {
            let _ = log::append(&state, &task.id, v);
        }
    };

    let output = match event {
        "UserPromptSubmit" => {
            // The person's request, kept on this machine next to the declaration. First prompt only.
            if let Some(prompt) = payload.get("prompt").and_then(Value::as_str).filter(|p| !p.trim().is_empty() && recording) {
                let mut t = ctx.store.load(&task.id).map_err(|e| e.message)?;
                if t.request.is_none() {
                    t.request = Some(prompt.trim().chars().take(2000).collect());
                    ctx.store.save(&t).map_err(|e| e.message)?;
                }
            }
            note(json!({ "event": "prompt" }));
            Ok(None)
        }
        "SessionStart" => {
            note(json!({ "event": "session_start", "agent": agent }));
            Ok(Some(json!({ "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": session_context(&ctx, &task) } })))
        }
        "PreToolUse" => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
            let d = pre_tool_use(&ctx, &task, &cwd, tool, &input);
            if !d.log.is_null() {
                note(d.log);
            }
            Ok(d.output)
        }
        "PostToolUse" => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
            let touched: Vec<String> = paths_in(&input).iter().filter_map(|p| relative(ctx.top(), &cwd, p)).collect();
            note(json!({ "event": "tool_done", "tool": tool, "paths": touched }));
            Ok(None)
        }
        "Stop" => {
            // What the agent says it did is an assertion; keep it for the claims check.
            if let Some(text) = payload.get("last_assistant_message").and_then(Value::as_str).filter(|t| !t.trim().is_empty()) {
                let mut t = ctx.store.load(&task.id).map_err(|e| e.message)?;
                if t.outcome.is_none() {
                    t.outcome = Some(text.chars().take(4000).collect());
                    ctx.store.save(&t).map_err(|e| e.message)?;
                }
            }
            note(json!({ "event": "stop" }));
            let failed = prove_at_stop(&ctx, &task);
            // With `land = "auto"`, a change the gate allows lands when its agent stops (D69).
            if failed.is_empty() && ctx.policy.branches.land == use05_core::policy::LandMode::Auto {
                if let Ok(current) = ctx.store.load(&task.id) {
                    let report = crate::cmd::land::land_task(&ctx, current);
                    note(json!({ "event": "auto_land", "code": report.code, "message": report.headline }));
                }
            }
            tidy(&ctx, false);
            if recording {
                crate::cmd::start::publish_log_seal(&ctx, &task, false);
            }
            // Claude Code can be asked to keep going; its own flag stops this from looping.
            let looping = payload.get("stop_hook_active").and_then(Value::as_bool).unwrap_or(false);
            match failed.first() {
                Some(name) if agent != "codex" && !looping => Ok(Some(json!({
                    "decision": "block",
                    "reason": format!("05: the check {name} failed on your change. Fix it before you finish, then run: use05 prove {name}"),
                }))),
                _ => Ok(None),
            }
        }
        "SessionEnd" => {
            note(json!({ "event": "session_end" }));
            // The session is over, so its task is finished; its worktree can go once its work landed.
            if let Ok(mut t) = ctx.store.load(&task.id) {
                t.ended = Some(use05_core::time::now_rfc3339());
                if t.status == use05_core::task::Status::Active {
                    let _ = ctx.store.finish(&mut t, None);
                } else {
                    let _ = ctx.store.save(&t);
                }
            }
            tidy(&ctx, true);
            Ok(None)
        }
        _ => Ok(None),
    };
    output.map(|o| with_context(event, o, &notes))
}

/// The generic agent's answer: what to do, why, and what to tell the agent. Nothing else.
fn plain(output: Value) -> Value {
    let specific = output.get("hookSpecificOutput");
    let field = |name: &str| specific.and_then(|o| o.get(name)).cloned();
    let mut out = serde_json::Map::new();
    if let Some(d) = field("permissionDecision").or_else(|| output.get("decision").cloned()) {
        out.insert("decision".into(), d);
    }
    if let Some(r) = field("permissionDecisionReason").or_else(|| output.get("reason").cloned()) {
        out.insert("reason".into(), r);
    }
    if let Some(c) = field("additionalContext") {
        out.insert("context".into(), c);
    }
    Value::Object(out)
}

pub fn run(agent: &str, event: &str) -> ExitCode {
    if !["claude-code", "codex", "generic"].contains(&agent) {
        eprintln!("05: unknown agent {agent:?}");
        return ExitCode::SUCCESS;
    }
    match run_inner(agent, event) {
        Ok(Some(mut output)) => {
            if agent == "codex" {
                // Codex does not support "ask" yet: a step that needs a person is denied, with the reason.
                if let Some(decision) = output.pointer_mut("/hookSpecificOutput/permissionDecision") {
                    if decision == "ask" {
                        *decision = json!("deny");
                    }
                }
            }
            if agent == "generic" {
                output = plain(output);
            }
            println!("{output}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(why) => {
            // Fail open, loudly: a bug in 05 must not stall the agent. Claude Code shows the first
            // line of stderr in the transcript only for a non-zero, non-2 exit (a non-blocking
            // error), so that is what a skipped check exits with. Exit 0 would hide the warning.
            eprintln!("05: skipped checking this step ({why}). Nothing was blocked.");
            let on_error = Ctx::open(Path::new("."), None).map(|c| c.policy.enforce.on_error).unwrap_or(OnError::Open);
            if on_error == OnError::Closed && event == "PreToolUse" {
                let refusal = deny("05: could not check this step, and policy is set to fail closed");
                println!("{}", if agent == "generic" { plain(refusal) } else { refusal });
                return ExitCode::SUCCESS;
            }
            // Codex documents only exit codes 0 and 2, and the generic answer is on stdout, so a
            // skipped check there exits 0.
            if agent == "claude-code" { ExitCode::from(1) } else { ExitCode::SUCCESS }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risky_commands_are_caught_and_ordinary_ones_are_not() {
        for bad in [
            "git push --force origin main", "git push origin +main", "git push -f", "git reset --hard HEAD~3", "git clean -fd", "git commit --no-verify -m x",
            "git config core.hooksPath /dev/null", "use05 approve --outcome", "use05 bypass --reason x", "echo hi && git push --force", "rm .05/policy.toml",
            "sed -i s/a/b/ .git/hooks/pre-push", "echo x > .05/policy.toml", "use05 key new --approver",
        ] {
            assert!(risky(bad).is_some(), "should be caught: {bad}");
        }
        for ok in [
            "git status", "git push origin feature", "git reset --soft HEAD~1", "cargo test", "ls .05", "cat .05/policy.toml", "git clean -n", "use05 prove", "use05 brief",
            "echo \"git push --force\"", "grep -r hooksPath docs",
        ] {
            assert!(risky(ok).is_none(), "should be allowed: {ok} -> {:?}", risky(ok));
        }
    }

    #[test]
    fn paths_are_found_in_tool_inputs_and_patches() {
        assert_eq!(paths_in(&json!({ "file_path": "src/a.rs" })), ["src/a.rs"]);
        let patch = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n*** Add File: docs/new.md\n*** End Patch";
        assert_eq!(paths_in(&json!({ "input": patch })), ["src/lib.rs", "docs/new.md"]);
        assert!(paths_in(&json!({})).is_empty());
    }

    #[test]
    fn paths_are_resolved_against_the_repository_and_cannot_escape_it() {
        let top = Path::new("/work/repo");
        assert_eq!(relative(top, Path::new("/work/repo/src"), "a.rs").as_deref(), Some("src/a.rs"));
        assert_eq!(relative(top, Path::new("/work/repo"), "/work/repo/.05/policy.toml").as_deref(), Some(".05/policy.toml"));
        assert_eq!(relative(top, Path::new("/work/repo/src"), "../.05/policy.toml").as_deref(), Some(".05/policy.toml"), "dot-dot is resolved before the check");
        assert_eq!(relative(top, Path::new("/work/repo"), "../other/x").as_deref(), None);
        assert_eq!(relative(top, Path::new("/work/repo"), "/etc/passwd").as_deref(), None);
    }
}

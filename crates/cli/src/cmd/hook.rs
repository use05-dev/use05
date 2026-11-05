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
use use05_core::{git, log, task::Task};

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

/// Every way a shell command runs `use05`, as the words after the program: `use05 …` by name or
/// by a path ending in `/use05`, after variable assignments (`FOO=1 use05`), through `command`,
/// `exec`, `env` or `npx`, and inside `sh -c '…'` or `bash -c "…"`. Word-based and conservative,
/// like the rest of this file: the hook catches mistakes. The real backstop is `use05` itself,
/// which refuses what only a person may do under an agent or without a terminal, and the
/// person's key, which an agent does not have.
fn use05_runs(command: &str) -> Vec<Vec<String>> {
    runs_of(command, "use05")
}

/// Every way a shell command runs `program`, found as [`use05_runs`] finds `use05`.
fn runs_of(command: &str, program_name: &str) -> Vec<Vec<String>> {
    fn walk(command: &str, name: &str, depth: usize, out: &mut Vec<Vec<String>>) {
        for w in words(command) {
            let mut rest: &[String] = &w;
            // After a wrapper, its own flags (`npx --yes`, `env -i`) come before the program.
            let mut wrapped = false;
            loop {
                let Some(first) = rest.first().map(String::as_str) else { break };
                let assignment = first.split_once('=').is_some_and(|(name, _)| !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
                let wrapper = ["command", "exec", "env", "npx", "sudo"].contains(&first);
                if assignment || wrapper || (wrapped && first.starts_with('-')) {
                    wrapped |= wrapper;
                    rest = &rest[1..];
                } else {
                    break;
                }
            }
            let Some(program) = rest.first().map(String::as_str) else { continue };
            let shell = ["sh", "bash", "zsh", "dash"].contains(&program.rsplit('/').next().unwrap_or(program));
            if shell && depth < 3 {
                if let Some(at) = rest.iter().position(|a| a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))) {
                    if let Some(script) = rest.get(at + 1) {
                        walk(script, name, depth + 1, out);
                    }
                }
                continue;
            }
            if program == name || program.ends_with(&format!("/{name}")) {
                out.push(rest[1..].to_vec());
            }
        }
    }
    let mut out = Vec::new();
    walk(command, program_name, 0, &mut out);
    out
}

/// Every `git push` a shell command runs, as the words after `push`. git's own options come before
/// its subcommand: `git -C dir push`, `git -c k=v push`.
fn git_pushes(command: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for args in runs_of(command, "git") {
        let mut i = 0;
        while i < args.len() && args[i].starts_with('-') {
            i += if ["-C", "-c"].contains(&args[i].as_str()) { 2 } else { 1 };
        }
        if args.get(i).map(String::as_str) == Some("push") {
            out.push(args[i + 1..].to_vec());
        }
    }
    out
}

/// The remote a `git push` names, from the words after `push`: its first word that is neither an
/// option nor an option's value, or `--repo`. `None`: it names none, so git pushes to the
/// branch's own remote.
fn push_remote(rest: &[String]) -> Option<String> {
    let mut skip = false;
    for a in rest {
        if std::mem::take(&mut skip) {
            continue;
        }
        match a.as_str() {
            "--repo" | "-o" | "--push-option" | "--receive-pack" | "--exec" => skip = true,
            a if a.starts_with("--repo=") => return Some(a["--repo=".len()..].to_string()),
            a if a.starts_with('-') => {}
            a => return Some(a.to_string()),
        }
    }
    None
}

/// The remote `git push` with none named goes to, as git chooses it: the branch's push remote,
/// the repository's, the branch's own, else origin.
fn default_push_remote(top: &Path) -> String {
    let branch = git::current_branch(top);
    let get = |key: String| git::text(top, &["config", &key]).ok().filter(|v| !v.is_empty());
    branch.as_ref().and_then(|b| get(format!("branch.{b}.pushRemote"))).or_else(|| get("remote.pushDefault".into())).or_else(|| branch.as_ref().and_then(|b| get(format!("branch.{b}.remote")))).unwrap_or_else(|| "origin".to_string())
}

/// `git push` by an agent to a remote `[push] agent` leaves out (D93): for a person. A remote is
/// matched by its name, or by its URL when the command gives one. `allowed` says whether an
/// agent may push to a remote (by name and URL); its `Err` lists those it may.
fn push_to_unlisted(command: &str, default: impl Fn() -> String, url_of: impl Fn(&str) -> String, allowed: impl Fn(&str, &str) -> Result<(), Vec<String>>) -> Option<String> {
    for rest in git_pushes(command) {
        let remote = push_remote(&rest).unwrap_or_else(&default);
        if let Err(listed) = allowed(&remote, &url_of(&remote)) {
            let f = crate::cmd::gate::remote_held(&remote, &listed);
            return Some(format!("{} ({}): {}. Locally this is advisory: the pre-push hook holds it too, and `git push --no-verify` skips that.", f.message, f.code, f.next.unwrap_or_default()));
        }
    }
    None
}

/// `git push` that deletes an environment's branch or one the policy keeps (`git push origin
/// :prod`, `git push origin --delete prod`, `-d`): that is for a person. The pre-push hook holds
/// it too, unless a person pushes at a terminal. `kept` says whether a branch is kept, by every
/// policy that may name it (see `gate::kept_anywhere`).
fn deletes_kept_branch(kept: impl Fn(&str) -> bool, command: &str) -> Option<String> {
    for rest in git_pushes(command) {
        let rest = &rest[..];
        let deleting = rest.iter().any(|a| a == "--delete" || a == "-d");
        let positional: Vec<&str> = rest.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
        let named: Vec<&str> = positional.iter().skip(1).filter_map(|r| if deleting { Some(*r) } else { r.strip_prefix(':') }).collect();
        if let Some(branch) = named.iter().map(|r| r.trim_start_matches("refs/heads/")).find(|b| kept(b)) {
            return Some(format!("deleting {branch} is for a person: it is an environment's branch or one the policy keeps. Ask the user."));
        }
    }
    None
}

/// Commands an agent should not run unobserved, with the reason and a safer alternative.
fn risky(command: &str) -> Option<String> {
    for args in use05_runs(command) {
        let sub = args.first().map(String::as_str).unwrap_or("");
        if ["approve", "bypass", "uninstall"].contains(&sub) || (sub == "key" && args.iter().any(|a| a == "--approver")) {
            return Some(format!("`use05 {sub}` is for a person: it needs the approver passphrase. Ask the user to run it."));
        }
    }
    for words in words(command) {
        let w: Vec<&str> = words.iter().map(String::as_str).collect();
        let program = w.first().copied().unwrap_or("");
        let has = |s: &str| w.iter().any(|x| *x == s);
        let sub = w.get(1).copied().unwrap_or("");
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

/// `use05 promote <env>` that would move an environment the policy keeps for people
/// (`agent = false`, by default the last rung). Checking it (`--check`) is anyone's.
fn promote_for_people(policy: &use05_core::policy::Policy, command: &str) -> Option<String> {
    for args in use05_runs(command) {
        if args.first().map(String::as_str) != Some("promote") {
            continue;
        }
        let rest = &args[1..];
        // Checking and confirming move nothing a person keeps: anyone's. (Under an agent, a
        // confirmation that fails reverts nothing where people promote.)
        if rest.iter().any(|a| ["--check", "--confirm", "--help", "-h"].contains(&a.as_str())) {
            continue;
        }
        let rolling_back = rest.iter().any(|a| a == "--rollback");
        let back = rest.iter().any(|a| a == "--back");
        // The environment: the first word that is neither a flag nor a flag's value.
        let mut name = None;
        let mut skip = false;
        for a in rest {
            if std::mem::take(&mut skip) {
                continue;
            }
            match a.as_str() {
                "--repo" => skip = true,
                a if a.starts_with('-') => {}
                a => {
                    name = Some(a);
                    break;
                }
            }
        }
        // A destination kept for people (`agent` unset or false): only a person promotes to it.
        if let Some(d) = name.and_then(|n| policy.destination_named(n)).filter(|d| !policy.agent_may_promote(*d)) {
            return Some(format!("promoting to the destination {} is for a person here (the policy keeps it for people). Check it with `use05 promote {} --check`, then ask the user to run `use05 promote {}`.", d.name, d.name, d.name));
        }
        let Some(env) = name.and_then(|n| policy.environment_named(n)) else { continue };
        if !policy.agent_may_promote(env) && back {
            return Some(format!("merging back into {} is for a person here (the policy keeps it for people). Check it with `use05 promote {} --back --check`, then ask the user to run `use05 promote {} --back`.", env.name, env.name, env.name));
        }
        if !policy.agent_may_promote(env) && rolling_back {
            return Some(format!("rolling back {} is for a person here (the policy keeps it for people). Ask the user to run `use05 promote {} --rollback`.", env.name, env.name));
        }
        if !policy.agent_may_promote(env) {
            return Some(format!("promoting into {} is for a person here (the policy keeps it for people). Check it with `use05 promote {} --check`, then ask the user to run `use05 promote {}`.", env.name, env.name, env.name));
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
        // Allowed reads are not recorded; a refused one is, with the path and not its contents.
        return match read.iter().find(|p| unreadable(&ctx.policy, p)) {
            Some(p) => Decision {
                output: Some(deny(&format!("05: {p} is not to be read by agents here. Ask the user if you need something from it."))),
                log: json!({ "event": "tool", "tool": tool, "paths": [p], "decision": "deny", "why": "do not read" }),
            },
            None => Decision { output: None, log: Value::Null },
        };
    }
    let mut log = json!({ "event": "tool", "tool": tool });

    if let Some(command) = input.get("command").and_then(Value::as_str) {
        if let Some(reason) = risky(command) {
            log["decision"] = json!("deny");
            log["why"] = json!("risky command");
            return Decision { output: Some(deny(&format!("05: {reason}"))), log };
        }
        // Kept by this checkout's policy, the branch's own or origin's default branch's (read from
        // git, no network); when none can be read, held.
        let kept = |b: &str| crate::cmd::gate::kept_anywhere(ctx.top(), b, Some(&ctx.policy), None).unwrap_or(true);
        if let Some(reason) = promote_for_people(&ctx.policy, command).or_else(|| deletes_kept_branch(kept, command)) {
            log["decision"] = json!("deny");
            log["why"] = json!("promotion for people");
            return Decision { output: Some(deny(&format!("05: {reason}"))), log };
        }
        // Where an agent may push (`[push] agent`, D93): by this checkout's policy and origin's
        // default branch's, read from git with no network.
        let url_of = |r: &str| crate::cmd::destination::urls_of(top, r).into_iter().next().unwrap_or_else(|| r.to_string());
        let allowed = |name: &str, url: &str| crate::cmd::gate::agent_may_push(top, Some(&ctx.policy), name, url);
        if let Some(reason) = push_to_unlisted(command, || default_push_remote(top), url_of, allowed) {
            log["decision"] = json!("deny");
            log["why"] = json!("remote not allowed");
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
            log["why"] = json!("protected path");
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
                    log["why"] = json!("outside scope");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Warn => {
                    log["decision"] = json!("ask");
                    log["why"] = json!("outside scope");
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
                    log["why"] = json!("overlap");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Approval => {
                    log["decision"] = json!("ask");
                    log["why"] = json!("overlap");
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
                    log["why"] = json!("overlap");
                    return Decision { output: Some(deny(&msg)), log };
                }
                Severity::Approval => {
                    log["decision"] = json!("ask");
                    log["why"] = json!("overlap");
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
    for rule in ctx.policy.require.iter().filter(|r| r.severity != Severity::Allow) {
        let why = rule.why.as_deref().map(|w| format!(" ({w})")).unwrap_or_default();
        lines.push(format!("When you change {}, also update {}{why}.", rule.when.join(", "), rule.also.join(" or ")));
    }
    let names: Vec<&str> = ctx.policy.check.iter().map(|c| c.name.as_str()).collect();
    if !names.is_empty() {
        lines.push(format!("Checks you can name with --check: {}.", names.join(", ")));
    }
    lines.push("Before you edit, declare your plan with `use05 start \"<what you will do>\" --scope \"<paths, separated by spaces>\"`. When you are done, `use05 finish --outcome \"<what you did>\"`; 05 runs the checks itself.".into());
    lines.join(" ")
}

/// Fresh base: fetch origin's copy of the target, record how far behind this work starts, and
/// say so. Off unless the policy asks. A failed fetch is said, never held against the agent.
fn fresh_base_line(ctx: &Ctx, task: &mut Task) -> Option<String> {
    let severity = ctx.policy.branches.fresh_base;
    // No origin to compare with: nothing to say at every session start.
    if severity == Severity::Allow || use05_core::git::text(ctx.top(), &["remote", "get-url", "origin"]).is_err() {
        return None;
    }
    match use05_core::fresh::check(ctx.top(), &ctx.policy, task.intent.as_ref(), use05_core::fresh::FETCH_TIMEOUT) {
        Ok(fresh) => {
            let line = if fresh.behind == 0 {
                format!("Your starting point is up to date with {}.", fresh.remote_ref)
            } else {
                let (remote, branch) = fresh.remote_ref.split_once('/').unwrap_or(("origin", fresh.remote_ref.as_str()));
                let held = match severity {
                    Severity::Deny => " 05 refuses work that does not start from it.",
                    Severity::Approval => " Until you do, a person must approve this change.",
                    _ => "",
                };
                format!(
                    "This work starts {} commit{} behind {}. Update before you edit: git pull --rebase {remote} {branch}.{held}",
                    fresh.behind,
                    if fresh.behind == 1 { "" } else { "s" },
                    fresh.remote_ref
                )
            };
            task.fresh = Some(fresh);
            Some(line)
        }
        // What was recorded earlier stands; a fetch that fails now never erases it.
        Err(why) => Some(format!("05 could not fetch origin to check your starting point is current ({why}).")),
    }
}

/// Files the policy says must change with this change, and do not yet: `(what changed, what must)`.
fn unmet_requires(ctx: &Ctx) -> Vec<(Vec<String>, String)> {
    if ctx.policy.require.is_empty() {
        return Vec::new();
    }
    // Everything the agent has done, staged or not: an update it has not staged yet still counts.
    let Ok(target) = ctx.target(Some("worktree")) else { return Vec::new() };
    let Ok(changed) = use05_core::git::changed(ctx.top(), target.base_tree.as_deref(), &target.oid) else { return Vec::new() };
    let paths: Vec<String> = changed.into_iter().map(|c| c.path).collect();
    ctx.policy
        .require
        .iter()
        .filter(|r| r.severity != Severity::Allow)
        .filter_map(|r| {
            let unmet = r.unmet(&paths);
            (!unmet.is_empty()).then(|| (unmet, r.also.join(" or ") + &r.why.as_deref().map(|w| format!(" ({w})")).unwrap_or_default()))
        })
        .collect()
}

/// Seal what this session's agent left in the inbox: its declarations become the task's intent,
/// its "finished" becomes the outcome. The author is this hook's agent, never what the file
/// claims (D67). Returns what to tell the agent.
fn seal_pending(ctx: &Ctx, task: &mut Task, agent: &str, session: &str) -> Vec<String> {
    let mut notes = Vec::new();
    for (path, pending) in use05_core::inbox::for_session(ctx.top(), session) {
        let state = ctx.store.state_dir();
        match pending.entry {
            use05_core::inbox::Entry::Start { title, card, hotfix } => {
                task.sandbox = pending.sandbox.clone();
                // A hotfix starts from its environment's branch, which `start --hotfix` checked out.
                if let Some(env) = hotfix.as_deref().and_then(|h| ctx.policy.environment_named(h)) {
                    crate::cmd::hotfix::begin_here(ctx.top(), task, env);
                }
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
        match use05_core::evidence::last_duration_ms(&found, &c.run, c.dir.as_deref()) {
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

/// The line a person reads when the agent stops (D91): what 05 decided about the work, and the
/// one command to run, if any. Nothing when the agent changed nothing.
/// `landed` is the landing's report and what the gate found for the work it landed (D101).
fn verdict_line(ctx: &Ctx, task: &use05_core::task::Task, landed: Option<(&crate::report::Report, &use05_core::gate::GateResult)>) -> Option<String> {
    use use05_core::gate::{CheckState, Decision, Effect};
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    if let Some((r, landed_gate)) = landed.filter(|(r, _)| r.code == "LANDED") {
        let target = r.details["target"].as_str().unwrap_or("its target");
        let title = &task.title;
        let a = use05_core::brief::assurance(landed_gate, false);
        // "Passed its checks" only when every required check passed: never for work that ran
        // none, nor for work a bypass let through with a check failed or missing.
        let why = if a.checks_required > 0 && a.passed == a.checks_required {
            None
        } else if landed_gate.bypass.is_some() {
            Some("allowed by a bypass")
        } else {
            Some(a.qualifier().unwrap_or("not every check passed"))
        };
        return Some(match (r.details["pushed"] == true, why) {
            (true, None) => format!("05: \"{title}\" passed its checks, landed on {target} and was pushed. Nothing needs you."),
            (true, Some(why)) => format!("05: \"{title}\" landed on {target} and was pushed ({why}). Nothing needs you."),
            (false, None) => format!("05: \"{title}\" passed its checks and landed on {target}. Push when you are ready: git push origin {target}"),
            (false, Some(why)) => format!("05: \"{title}\" landed on {target} ({why}). Push when you are ready: git push origin {target}"),
        });
    }
    let target = ctx.target(None).ok()?;
    let gate = ctx.gate(&target).ok()?;
    if gate.changed.is_empty() {
        return None;
    }
    let files = plural(gate.changed.len(), "file");
    // Checks not required for this change (D97) are left out: they say nothing either way. When no
    // check was required, that is said instead (D101).
    let assurance = use05_core::brief::assurance(&gate, false);
    let passed = assurance.checks_required > 0 && assurance.passed == assurance.checks_required;
    let checks = match assurance.qualifier() {
        Some(q) => format!("; {q}"),
        None if passed => ", checks passed".to_string(),
        None => String::new(),
    };
    let first = gate.findings.iter().find(|f| f.effect >= Effect::Wait);
    let landing = task.branch.as_deref().is_some_and(|b| !use05_core::branches::is_kept(&ctx.policy, b));
    Some(match gate.decision {
        Decision::Allow if use05_core::brief::label_of(&gate) == use05_core::brief::Label::Allow => {
            if landing {
                format!("05: allowed, nothing to read ({files}{checks}). Land it: use05 land")
            } else {
                format!("05: allowed, nothing to read ({files}{checks}). Commit and push when you are ready.")
            }
        }
        Decision::Allow => format!("05: allowed, with notes worth a look ({files}{checks}): use05 brief"),
        Decision::Wait => {
            let waiting: Vec<&str> = gate.checks.iter().filter(|c| c.required && matches!(c.state, CheckState::Missing | CheckState::Stale)).map(|c| c.name.as_str()).collect();
            if waiting.is_empty() {
                format!("05: waiting ({files}): {}", first.map_or("see use05 brief".to_string(), |f| f.message.clone()))
            } else {
                format!("05: {} still to run ({files}); they run when you push, or now: use05 prove", waiting.join(", "))
            }
        }
        Decision::ApprovalRequired => format!("05: needs you ({files}): {}. Approve: use05 approve", first.map_or("a person must approve".to_string(), |f| f.message.trim_end_matches('.').to_string())),
        Decision::Deny => format!("05: blocked ({files}): {}. See: use05 brief", first.map_or("a rule no approval clears".to_string(), |f| f.message.trim_end_matches('.').to_string())),
    })
}

/// Has this line not been said for this task yet? A turn that changes nothing says nothing.
fn said_new(ctx: &Ctx, task: &str, line: &str) -> bool {
    let path = ctx.store.state_dir().join(format!("{task}.said"));
    if std::fs::read_to_string(&path).is_ok_and(|said| said == line) {
        return false;
    }
    let _ = std::fs::write(&path, line);
    true
}

fn with_context(event: &str, output: Option<Value>, notes: &[String]) -> Option<Value> {
    if notes.is_empty() || !["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart"].contains(&event) {
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
    // The agent updated to what origin had at its start: its base moves there, so the commits
    // it pulled in are not its change.
    if ctx.policy.branches.fresh_base != Severity::Allow && use05_core::fresh::catch_up(ctx.top(), &mut task) {
        probe.save(&task).map_err(|e| e.message)?;
        ctx = Ctx::open(&cwd, Some(&task.id)).map_err(|e| e.message)?;
    }
    let notes = seal_pending(&ctx, &mut task, agent, &session);
    if !notes.is_empty() {
        // The intent changed: read the rules and approvals for the task as it is now.
        ctx = Ctx::open(&cwd, Some(&task.id)).map_err(|e| e.message)?;
    }
    let recording = ctx.policy.record.middle == Middle::Local;
    let state = ctx.store.state_dir();
    // A subagent's hook calls carry its id and type; every line they write says which subagent
    // it was. The main session's lines carry neither.
    let subagent = payload.get("agent_id").and_then(Value::as_str).filter(|a| !a.is_empty()).map(|id| {
        (id.to_string(), payload.get("agent_type").and_then(Value::as_str).unwrap_or("").to_string())
    });
    let task_id = task.id.clone();
    let note = |mut v: Value| {
        if recording {
            if let Some((id, kind)) = &subagent {
                v["agent_id"] = json!(id);
                v["agent_type"] = json!(kind);
            }
            let _ = log::append(&state, &task_id, v);
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
            let mut context = session_context(&ctx, &task);
            // Only a new session starts the work: a resume, /clear or compaction is mid-task.
            let source = payload.get("source").and_then(Value::as_str).unwrap_or("startup");
            let fresh_line = if source == "startup" { fresh_base_line(&ctx, &mut task) } else { None };
            if let Some(line) = fresh_line {
                if let Some(f) = &task.fresh {
                    note(json!({ "event": "fresh_base", "remote": f.remote_ref, "behind": f.behind }));
                }
                ctx.store.save(&task).map_err(|e| e.message)?;
                context = format!("{context} {line}");
            }
            Ok(Some(json!({ "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": context } })))
        }
        "SubagentStart" => {
            // A subagent is held to the same rules by the same hooks; tell it what they are
            // before its first tool call, as the main session is told at its start.
            note(json!({ "event": "subagent_start" }));
            Ok(Some(json!({ "hookSpecificOutput": { "hookEventName": "SubagentStart", "additionalContext": session_context(&ctx, &task) } })))
        }
        "SubagentStop" => {
            // The main session's Stop proves the change; a subagent's stop is only recorded.
            note(json!({ "event": "subagent_stop" }));
            Ok(None)
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
            crate::extend::announce_approval_needed(&ctx, &task);
            // Claude Code can be asked to keep going; its own flag stops this from looping.
            let looping = payload.get("stop_hook_active").and_then(Value::as_bool).unwrap_or(false);
            // Asked once per session. A stop that follows a failed check is a looping one, so the
            // log says whether this was asked yet; without a log, never ask while looping.
            let asked = !recording || log::read(&state, &task.id).iter().any(|e| e["event"]["event"] == "asked_to_update");
            let missing = if failed.is_empty() && agent != "codex" && (!looping || !asked) { unmet_requires(&ctx) } else { Vec::new() };
            // With `land = "auto"`, a change the gate allows lands when its agent stops (D69), and
            // with `push = "auto"` it is pushed too (D91).
            let mut landed = None;
            if failed.is_empty() && missing.is_empty() && ctx.policy.branches.land == use05_core::policy::LandMode::Auto {
                if let Ok(current) = ctx.store.load(&task.id) {
                    if let Some((_, _, gate)) = crate::cmd::land::ready(&ctx, &current) {
                        let mut report = crate::cmd::land::land_task(&ctx, current);
                        let push = crate::cmd::land::Then::choose(ctx.policy.branches.push == use05_core::policy::LandMode::Auto, false, false);
                        crate::cmd::land::push_after(&ctx, &mut report, push, true);
                        note(json!({ "event": "auto_land", "code": report.code, "message": report.headline }));
                        // What the landed work rested on, for the line the person reads (D101).
                        landed = Some((report, gate));
                    }
                }
            }
            tidy(&ctx, false);
            if recording {
                crate::cmd::start::publish_log_seal(&ctx, &task, false);
            }
            match (failed.first(), missing.first()) {
                (Some(name), _) if agent != "codex" && !looping => Ok(Some(json!({
                    "decision": "block",
                    "reason": format!("05: the check {name} failed on your change. Fix it before you finish, then run: use05 prove {name}"),
                }))),
                (None, Some((changed, also))) => {
                    note(json!({ "event": "asked_to_update", "also": also }));
                    let shown: Vec<&str> = changed.iter().take(3).map(String::as_str).collect();
                    let more = if changed.len() > 3 { format!(" and {} more", changed.len() - 3) } else { String::new() };
                    Ok(Some(json!({
                        "decision": "block",
                        "reason": format!("05: you changed {}{more}, and the policy says {also} must change with it. Update it before you finish.", shown.join(", ")),
                    })))
                }
                // Nothing for the agent to fix: tell the person, in the agent's window, where the
                // work stands and the one thing to do, if any (D91). Said again only when it changes.
                // Codex is left out until its hooks show such a line.
                _ if agent == "codex" => Ok(None),
                _ => Ok(verdict_line(&ctx, &task, landed.as_ref().map(|(r, a)| (r, a))).filter(|line| said_new(&ctx, &task.id, line)).map(|line| json!({ "systemMessage": line }))),
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
    if let Some(m) = output.get("systemMessage").cloned() {
        out.insert("message".into(), m);
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
            // However use05 is reached: a package runner, a variable, a wrapper, a path, a shell.
            "npx use05 approve", "USE05_X=1 use05 bypass --reason x", "command use05 approve", "/opt/bin/use05 approve --promote prod", "sh -c 'use05 approve'", "bash -c \"use05 bypass --promote prod --rule soak --reason x\"",
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
    fn promoting_where_the_policy_keeps_it_for_people_is_held_and_checking_is_not() {
        let ladder = "[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"uat\"\nbranch = \"uat\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n";
        let policy = use05_core::policy::Policy::parse(ladder).unwrap();
        for held in [
            "use05 promote prod", "use05 promote prod --json", "use05 promote --repo app prod", "cd app && use05 promote prod", "npx use05 promote prod", "npx --yes use05 promote prod",
            "CI=1 use05 promote prod", "command use05 promote prod", "/usr/local/bin/use05 promote prod", "sh -c 'use05 promote prod'", "bash -c \"cd app && use05 promote prod\"", "env -i FOO=1 use05 promote prod",
        ] {
            assert!(promote_for_people(&policy, held).is_some_and(|r| r.contains("use05 promote prod --check")), "should be held: {held}");
        }
        for ok in ["use05 promote prod --check", "use05 promote prod --confirm", "use05 promote uat", "use05 promote uat --rollback", "use05 brief --promote prod", "use05 promote staging", "echo use05 promote prod"] {
            assert!(promote_for_people(&policy, ok).is_none(), "should be allowed: {ok}");
        }
        for held in ["use05 promote prod --rollback", "use05 promote --rollback prod", "use05 promote prod --rollback --no-wait"] {
            assert!(promote_for_people(&policy, held).is_some_and(|r| r.contains("rolling back prod is for a person")), "should be held: {held}");
        }
        // Merging back down follows the agent rule of the environment merged into.
        let kept_uat = use05_core::policy::Policy::parse(&ladder.replace("name = \"uat\"\nbranch = \"uat\"\n", "name = \"uat\"\nbranch = \"uat\"\nagent = false\n")).unwrap();
        for held in ["use05 promote uat --back", "use05 promote --back uat"] {
            assert!(promote_for_people(&kept_uat, held).is_some_and(|r| r.contains("merging back into uat is for a person") && r.contains("use05 promote uat --back --check")), "should be held: {held}");
        }
        assert!(promote_for_people(&kept_uat, "use05 promote uat --back --check").is_none());
        assert!(promote_for_people(&policy, "use05 promote uat --back").is_none(), "uat lets an agent by default");
        assert!(promote_for_people(&policy, "use05 start --hotfix prod \"Fix it\"").is_none(), "an agent may start a hotfix");
        let solo = use05_core::policy::Policy::parse(&format!("{ladder}agent = true\n")).unwrap();
        assert!(promote_for_people(&solo, "use05 promote prod").is_none(), "agent = true lets an agent promote");
        assert!(promote_for_people(&solo, "use05 promote prod --rollback").is_none(), "and roll back");

        // Deleting an environment's branch, or one the policy keeps, is for a person.
        for held in ["git push origin :prod", "git push origin --delete uat", "git push -d origin prod", "git push --delete origin refs/heads/prod", "git -C app push origin :main", "sh -c 'git push origin :release/1.2'"] {
            assert!(deletes_kept_branch(|b| use05_core::branches::is_kept(&policy, b), held).is_some(), "should be held: {held}");
        }
        for ok in ["git push origin :agent/old-work", "git push origin --delete claude/x", "git push origin prod", "git push origin main:prod", "git status"] {
            assert!(deletes_kept_branch(|b| use05_core::branches::is_kept(&policy, b), ok).is_none(), "should be allowed: {ok}");
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

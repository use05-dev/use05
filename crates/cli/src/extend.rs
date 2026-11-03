//! Extension points (D73). 05 is extended from outside, never by loading code into it:
//!
//! - a program named `use05-<name>` on PATH is the command `use05 <name>`;
//! - `use05 hook generic <event>` lets any agent use 05's hooks, with a plain answer;
//! - programs listed in this machine's `extensions.toml` hear what happened (a declaration
//!   sealed, a change finished, a gate decision, a landing, a task waiting for a person's approval).
//!
//! Event extensions are chosen per machine, by the person, never by a repository: a repository
//! could otherwise make every hook run code its author chose. They hear identifiers and
//! verdicts, never code, prompts, titles or outcomes; for more they ask `use05 brief --json`.
//! They fail open and are cut off after their time limit, so they never hold work up.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

const PREFIX: &str = "use05-";
pub const EVENTS: [&str; 7] = ["sealed", "finished", "gate", "landed", "approval_needed", "tested", "discarded"];

/// Every `use05-<name>` program on PATH, first one wins, sorted by name.
pub fn commands() -> Vec<(String, PathBuf)> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(|e| e.ok()) {
            let file = entry.file_name().to_string_lossy().to_string();
            let Some(name) = file.strip_prefix(PREFIX).filter(|n| !n.is_empty()) else { continue };
            if executable(&entry.path()) && !found.iter().any(|(n, _)| n == name) {
                found.push((name.to_string(), entry.path()));
            }
        }
    }
    found.sort();
    found
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Run `use05 <name> <args...>` as the program `use05-<name>`, passing its exit code through.
/// It is told where this binary is (`USE05_BIN`) so it can call back.
pub fn run_command(argv: &[String]) -> ExitCode {
    let Some(name) = argv.first() else { return ExitCode::from(6) };
    let Some((_, path)) = commands().into_iter().find(|(n, _)| n == name) else {
        eprintln!("use05: no command \"{name}\". `use05 --help` lists the commands; an extension would be a program named {PREFIX}{name} on your PATH.");
        return ExitCode::from(6);
    };
    let mut cmd = Command::new(&path);
    cmd.args(&argv[1..]).env("USE05_VERSION", env!("CARGO_PKG_VERSION"));
    if let Ok(me) = std::env::current_exe() {
        cmd.env("USE05_BIN", me);
    }
    match cmd.status() {
        Ok(status) => ExitCode::from(status.code().map(|c| c.clamp(0, 255) as u8).unwrap_or(1)),
        Err(e) => {
            eprintln!("use05: could not run {}: {e}", path.display());
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub events: Vec<String>,
    pub run: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    5
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    on: Vec<Listener>,
}

pub fn config_path() -> Option<PathBuf> {
    use05_core::keys::user_dir().ok().map(|d| d.join("extensions.toml"))
}

/// This machine's event extensions. No file means none; an unreadable one is an error doctor names.
pub fn listeners() -> Result<Vec<Listener>, String> {
    let Some(path) = config_path() else { return Ok(Vec::new()) };
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(Vec::new()) };
    let file: File = toml::from_str(&text).map_err(|e| format!("{} cannot be read: {}", path.display(), e.message()))?;
    for l in &file.on {
        if l.run.is_empty() {
            return Err(format!("{}: an [[on]] entry has an empty run", path.display()));
        }
        // A relative program would be found inside whichever repository the event came from.
        if !Path::new(&l.run[0]).is_absolute() {
            return Err(format!("{}: run must start with an absolute path, not \"{}\"", path.display(), l.run[0]));
        }
        if let Some(bad) = l.events.iter().find(|e| !EVENTS.contains(&e.as_str())) {
            return Err(format!("{}: there is no event \"{bad}\"; the events are {}", path.display(), EVENTS.join(", ")));
        }
    }
    Ok(file.on)
}

/// Tell every listener for `event` what happened, as one line of JSON on its stdin. `fields` must
/// hold identifiers and verdicts only. Best effort: failures and slow listeners are ignored.
pub fn emit(event: &str, top: &Path, fields: Value) {
    if let Ok(listeners) = listeners() {
        emit_to(&listeners, event, top, fields);
    }
}

/// Like `emit`, to listeners read earlier. A gate reads them before the change's own code runs,
/// so that code cannot choose what runs after it.
pub fn emit_to(listeners: &[Listener], event: &str, top: &Path, fields: Value) {
    emit_all(listeners, top, &[(event, fields)]);
}

/// Several events at once, every delivery at the same time: the slowest listener is waited for
/// once, however many of the events it hears.
pub fn emit_all(listeners: &[Listener], top: &Path, events: &[(&str, Value)]) {
    let mut jobs: Vec<(&Listener, String)> = Vec::new();
    for (event, fields) in events {
        let mut message = json!({ "v": 1, "event": event, "at": use05_core::time::now_rfc3339(), "repo": top.to_string_lossy() });
        if let (Some(m), Some(f)) = (message.as_object_mut(), fields.as_object()) {
            m.extend(f.clone());
        }
        let line = format!("{message}\n");
        jobs.extend(listeners.iter().filter(|l| l.events.iter().any(|e| e == event)).map(|l| (l, line.clone())));
    }
    std::thread::scope(|s| {
        for (l, line) in &jobs {
            s.spawn(move || {
                let _ = deliver(l, top, line);
            });
        }
    });
}

/// This machine's listeners, if any of them wants `event`: so a caller can skip work nobody hears.
pub fn listening(event: &str) -> Option<Vec<Listener>> {
    listeners().ok().filter(|ls| ls.iter().any(|l| l.events.iter().any(|e| e == event)))
}

/// Tell listeners that a task waits for a person's approval, when the gate says so: which task,
/// which tree, whether the plan (intent) or the result (outcome) needs it, and the finding codes.
pub fn approval_needed_to(listeners: &[Listener], top: &Path, task: Option<&str>, tree: &str, intent_sha256: Option<&str>, r: &use05_core::gate::GateResult) {
    if let Some(fields) = approval_needed(task, tree, intent_sha256, r) {
        emit_to(listeners, "approval_needed", top, fields);
    }
}

/// What `approval_needed` says, if the gate waits for a person.
pub fn approval_needed(task: Option<&str>, tree: &str, intent_sha256: Option<&str>, r: &use05_core::gate::GateResult) -> Option<Value> {
    use use05_core::gate::{Decision, Effect};
    if r.decision != Decision::ApprovalRequired {
        return None;
    }
    let asking: Vec<&use05_core::gate::Finding> = r.findings.iter().filter(|f| f.effect == Effect::Approval).collect();
    let scope = if crate::pending::need_of(r) == crate::pending::Need::Plan { "intent" } else { "outcome" };
    let codes: Vec<&str> = asking.iter().map(|f| f.code).collect();
    Some(json!({ "task": task, "scope": scope, "tree": tree, "intent_sha256": intent_sha256, "findings": codes }))
}

/// A task finished: tell listeners, and in the same breath whether it now waits for a person.
pub fn announce_finished(ctx: &crate::ctx::Ctx, task: &use05_core::task::Task, agent: Option<&str>, tree: &str) {
    let Ok(listeners) = listeners() else { return };
    let mut events = vec![("finished", json!({ "task": task.id, "agent": agent, "tree": tree }))];
    if listeners.iter().any(|l| l.events.iter().any(|e| e == "approval_needed")) {
        if let Ok(target) = ctx.target(None) {
            if let Ok(r) = ctx.gate(&target) {
                if let Some(fields) = approval_needed(Some(&task.id), &target.oid, task.intent_sha256.as_deref(), &r) {
                    events.push(("approval_needed", fields));
                }
            }
        }
    }
    emit_all(&listeners, ctx.top(), &events);
}

/// After a task's decision is known outside the gate (finish, the Stop hook): work out the
/// decision only if someone listens, and tell them if it waits for a person.
pub fn announce_approval_needed(ctx: &crate::ctx::Ctx, task: &use05_core::task::Task) {
    let Some(listeners) = listening("approval_needed") else { return };
    let Ok(target) = ctx.target(None) else { return };
    if let Ok(r) = ctx.gate(&target) {
        approval_needed_to(&listeners, ctx.top(), Some(&task.id), &target.oid, task.intent_sha256.as_deref(), &r);
    }
}

fn deliver(l: &Listener, top: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    // Only a plain environment: never the runner key, a push token or anything else 05 was given.
    let mut cmd = Command::new(&l.run[0]);
    cmd.args(&l.run[1..]).current_dir(top).env_clear();
    for name in ["PATH", "HOME", "LANG", "TMPDIR", "USE05_HOME"] {
        if let Some(v) = std::env::var_os(name) {
            cmd.env(name, v);
        }
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(line.as_bytes());
    }
    let deadline = Instant::now() + Duration::from_secs(l.timeout_secs);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_told_together_wait_for_the_slowest_listener_once() {
        let slow = Listener { events: vec!["finished".into(), "approval_needed".into()], run: vec!["/bin/sh".into(), "-c".into(), "sleep 1".into()], timeout_secs: 2 };
        let started = Instant::now();
        emit_all(&[slow], Path::new("/"), &[("finished", json!({})), ("approval_needed", json!({}))]);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_millis(1800), "{took:?}");
    }
}

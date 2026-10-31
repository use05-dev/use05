//! Extension points (D73). 05 is extended from outside, never by loading code into it:
//!
//! - a program named `use05-<name>` on PATH is the command `use05 <name>`;
//! - `use05 hook generic <event>` lets any agent use 05's hooks, with a plain answer;
//! - programs listed in this machine's `extensions.toml` hear what happened (a declaration
//!   sealed, a change finished, a gate decision, a landing).
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
pub const EVENTS: [&str; 4] = ["sealed", "finished", "gate", "landed"];

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
    let wanted: Vec<&Listener> = listeners.iter().filter(|l| l.events.iter().any(|e| e == event)).collect();
    if wanted.is_empty() {
        return;
    }
    let mut message = json!({ "v": 1, "event": event, "at": use05_core::time::now_rfc3339(), "repo": top.to_string_lossy() });
    if let (Some(m), Some(f)) = (message.as_object_mut(), fields.as_object()) {
        m.extend(f.clone());
    }
    let line = format!("{message}\n");
    for l in wanted {
        let _ = deliver(l, top, &line);
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

//! `use05 doctor`: is 05 set up here, and how strongly is each control actually enforced?
//!
//! It never changes anything. Problems (something that is broken) exit 4; things that are merely
//! not set up are shown but do not fail the command.

use std::path::Path;
use std::process::{Command, ExitCode};

use serde_json::json;
use use05_core::policy::{POLICY_PATH, Role};
use use05_core::task::Status;
use use05_core::{keys, log, org, store};

use crate::cmd::init::{Hook, inspect};
use crate::ctx::Ctx;
use crate::report::{Report, emit};
use crate::ui::{Glyph, Item, Out, Tone, Ui};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Note,
    Problem,
}

pub struct Line {
    pub level: Level,
    pub text: String,
}

impl Line {
    fn ok(text: impl Into<String>) -> Line {
        Line { level: Level::Ok, text: text.into() }
    }
    fn note(text: impl Into<String>) -> Line {
        Line { level: Level::Note, text: text.into() }
    }
    fn problem(text: impl Into<String>) -> Line {
        Line { level: Level::Problem, text: text.into() }
    }
    fn item(&self) -> Item {
        match self.level {
            Level::Ok => Item::new(Glyph::Ok, Tone::Good, self.text.clone()),
            Level::Note => Item::new(Glyph::Warn, Tone::Warn, self.text.clone()),
            Level::Problem => Item::new(Glyph::Bad, Tone::Bad, self.text.clone()),
        }
    }
}

pub struct Diagnosis {
    pub repo: Option<String>,
    pub setup: Vec<Line>,
    pub keys: Vec<Line>,
    pub controls: Vec<Line>,
    pub records: Vec<Line>,
    /// Installed extensions (D73): commands on PATH and this machine's event extensions.
    pub extensions: Vec<Line>,
    pub next: Option<String>,
}

impl Diagnosis {
    pub fn problems(&self) -> usize {
        self.all().filter(|l| l.level == Level::Problem).count()
    }
    pub fn notes(&self) -> usize {
        self.all().filter(|l| l.level == Level::Note).count()
    }
    fn all(&self) -> impl Iterator<Item = &Line> {
        self.setup.iter().chain(&self.keys).chain(&self.controls).chain(&self.records).chain(&self.extensions)
    }
}

fn git_version() -> Option<String> {
    let out = Command::new("git").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    text.strip_prefix("git version ").map(str::to_string)
}

fn short(key_id: &str) -> String {
    key_id.chars().take(16).collect()
}

pub fn diagnose(repo: &Path) -> Diagnosis {
    let mut d = Diagnosis { repo: None, setup: vec![], keys: vec![], controls: vec![], records: vec![], extensions: vec![], next: None };

    match git_version() {
        Some(v) => d.setup.push(Line::ok(format!("git {v}"))),
        None => {
            d.setup.push(Line::problem("git is not installed or not on PATH; 05 needs it"));
            return d;
        }
    }

    // Keys and extensions do not depend on the repository.
    keys_section(&mut d);
    extensions_section(&mut d);

    let ctx = match Ctx::open(repo, None) {
        Ok(c) => c,
        Err(e) if e.code == "NOT_A_REPO" => {
            d.setup.push(Line::note("not inside a git repository, so there is no repository to check"));
            d.next = Some("cd into a repository, then: use05 init".into());
            return d;
        }
        Err(e) => {
            // The repository exists but its rules cannot be read: that is the thing to fix.
            d.setup.push(Line::problem(format!("{}  {}", e.code, e.message)));
            d.next = e.next;
            return d;
        }
    };
    let top = ctx.top().to_path_buf();
    d.repo = top.file_name().map(|n| n.to_string_lossy().to_string());
    d.setup.push(Line::ok(format!("repository {}", top.display())));

    let setup = inspect(&top);
    if setup.policy_file && ctx.policy_uncommitted {
        d.setup.push(Line::note(format!("{POLICY_PATH} is valid but not committed, so it is not the rules yet: a push, CI and approvals use 05's defaults until it is")));
        d.next = Some(format!("git add {POLICY_PATH} && git commit"));
    } else if setup.policy_file {
        d.setup.push(Line::ok(format!("{POLICY_PATH} is valid ({} check{})", ctx.policy.check.len(), if ctx.policy.check.len() == 1 { "" } else { "s" })));
    } else {
        d.setup.push(Line::note(format!("no {POLICY_PATH}; the defaults apply")));
        d.next = Some("use05 init".into());
    }
    match &ctx.org {
        Some(name) => d.setup.push(Line::ok(format!("organisation policy {name} is signed and applies as a floor"))),
        None => {
            if org::load().is_ok() {
                d.setup.push(Line::ok("no organisation policy pinned on this machine"));
            }
        }
    }
    if !setup.on_path {
        d.setup.push(Line::note("`use05` is not on PATH, so hooks cannot find it. They then fail open and say so."));
    }

    trusted_keys(&mut d, &ctx);
    controls_section(&mut d, &ctx, &setup);
    records_section(&mut d, &ctx);
    d
}

/// Keys the policy trusts: say which have expired (they no longer count) or will soon.
fn extensions_section(d: &mut Diagnosis) {
    for (name, path) in crate::extend::commands() {
        d.extensions.push(Line::ok(format!("command use05 {name}  ({})", path.display())));
    }
    match crate::extend::listeners() {
        Ok(listeners) => {
            for l in listeners {
                d.extensions.push(Line::ok(format!("on {}  runs {} (cut off after {}s; hears ids and verdicts only)", l.events.join(", "), l.run[0], l.timeout_secs)));
            }
        }
        Err(e) => d.extensions.push(Line::problem(format!("{e}. No event extension runs until it is fixed"))),
    }
}

fn trusted_keys(d: &mut Diagnosis, ctx: &Ctx) {
    let now = use05_core::time::now_secs();
    for k in &ctx.policy.trust.key {
        let Some(when) = &k.expires else { continue };
        match k.expires_at() {
            None => d.keys.push(Line::problem(format!("trusted key \"{}\" has an expiry that cannot be read ({when:?}), so it is not trusted. Use a date like 2027-01-31", k.name))),
            Some(t) if t < now => d.keys.push(Line::problem(format!("trusted key \"{}\" expired on {when}: what it signed no longer counts. Rotate it: make a new key, trust it in the policy, replace the CI secret", k.name))),
            Some(t) if t - now < 30 * 86_400 => d.keys.push(Line::note(format!("trusted key \"{}\" expires on {when} ({} days). Plan its rotation", k.name, (t - now) / 86_400))),
            Some(_) => d.keys.push(Line::ok(format!("trusted key \"{}\" is valid until {when}", k.name))),
        }
    }
}

fn keys_section(d: &mut Diagnosis) {
    match keys::local_paths() {
        Ok((secret, _)) if secret.exists() => {
            let id = keys::local_public().map(|k| short(&use05_receipt::key_id(&k))).unwrap_or_else(|| "unknown".into());
            d.keys.push(Line::ok(format!("local key {id}: signs evidence here. Advisory: any process you run can use it")));
        }
        Ok(_) => d.keys.push(Line::ok("no local key yet; one is made the first time you run `use05 prove`")),
        Err(e) => d.keys.push(Line::problem(e.message)),
    }
    let pinned = keys::pinned_passkeys_file();
    for (name, key) in &pinned.keys {
        d.keys.push(Line::ok(format!("passkey {name} ({}) pinned here: approves on this machine, when the machine co-signed what it approves", key.rp_id)));
    }
    if pinned.skipped > 0 {
        d.keys.push(Line::problem(format!("{} line(s) of passkeys.pub are not a passkey and are ignored", pinned.skipped)));
    }
    if keys::approver_exists() {
        let id = keys::approver_public().map(|k| short(&use05_receipt::key_id(&k))).unwrap_or_else(|| "unknown".into());
        if keys::approver_protected() {
            d.keys.push(Line::ok(format!("approver key {id}: passphrase-protected, so an agent cannot approve for you")));
        } else {
            d.keys.push(Line::note(format!("approver key {id} has no passphrase: anything that can read the file can approve. Make a new one with a passphrase")));
        }
    } else if keys::pinned_passkeys().is_empty() {
        d.keys.push(Line::note("no approver key; you cannot approve changes from this machine"));
        if d.next.is_none() {
            d.next = Some("use05 key new --approver".into());
        }
    }
}

fn controls_section(d: &mut Diagnosis, ctx: &Ctx, setup: &crate::cmd::init::Setup) {
    let on = |yes: bool| if yes { Level::Ok } else { Level::Note };
    let line = |level: Level, text: String| Line { level, text };

    d.controls.push(line(
        on(setup.claude_hooks),
        if setup.claude_hooks {
            "Claude Code hooks  on. Advisory: they guard sessions that run them; they do not stop a process that skips them".into()
        } else {
            "Claude Code hooks  off. Agent sessions are not guarded or recorded. `use05 init` adds them".into()
        },
    ));
    d.controls.push(line(
        on(setup.codex_hooks),
        if setup.codex_hooks {
            "Codex hooks  installed. Codex runs them only after you trust them (/hooks in Codex). Advisory, like the above".into()
        } else {
            "Codex hooks  off".into()
        },
    ));
    d.controls.push(match setup.pre_push {
        Hook::Ours => line(Level::Ok, "pre-push hook  on. Advisory: `git push --no-verify` skips it".into()),
        Hook::Foreign => line(Level::Note, "pre-push hook  another tool's hook is installed and 05 left it alone, so pushes are not checked here".into()),
        Hook::Missing => line(Level::Note, "pre-push hook  off. Pushes are not checked on this machine".into()),
    });
    if setup.ci_workflow {
        let runner = ctx.policy.trust.key.iter().any(|k| k.role == Role::Runner);
        d.controls.push(if runner {
            line(Level::Ok, "CI gate  workflow present and a runner key is trusted. Authoritative once your host requires the `05` check".into())
        } else {
            line(Level::Note, "CI gate  workflow present, but policy trusts no runner key yet, so its receipts do not count as authoritative".into())
        });
    } else {
        d.controls.push(line(Level::Note, "CI gate  none. Without it, nothing here is stronger than advisory. `use05 init --ci github`".into()));
    }
    let accepts_local = ctx.policy.evidence.accept.contains(&Role::Local);
    d.controls.push(line(
        Level::Ok,
        if accepts_local {
            "evidence  policy accepts local and runner receipts. Local ones are advisory".into()
        } else {
            "evidence  policy accepts only runner receipts. Local proofs are shown but do not count".into()
        },
    ));
    if setup.agents_block {
        d.controls.push(line(Level::Ok, "AGENTS.md  tells agents how 05 works in this repository".into()));
    }
}

fn records_section(d: &mut Diagnosis, ctx: &Ctx) {
    let top = ctx.top();
    let branches = store::branches(top);
    d.records.push(Line::ok(match branches.len() {
        0 => "receipts  none stored yet".to_string(),
        n => format!("receipts  on {n} branch{}  (05-receipts/<key>)", if n == 1 { "" } else { "es" }),
    }));
    if let Some(line) = crate::cmd::status::waiting_line(ctx.top()) {
        d.records.push(Line::problem(format!("inbox   {line}")));
    }
    // Nothing in the inbox vanishes silently: old and unreadable entries are named, with the way out.
    let scan = use05_core::inbox::scan(ctx.top(), use05_core::time::now_secs());
    let rel = |p: &std::path::Path| p.strip_prefix(ctx.top()).unwrap_or(p).display().to_string();
    // Short enough never to be cut off on screen; quoted, so any file name works.
    let rm = |p: &std::path::Path| format!("from the repository root, rm \"{}\"", rel(p).replace('"', "\\\""));
    for (path, p) in &scan.stale {
        d.records.push(Line::problem(format!("inbox   {} is older than 7 days (session {}); it will most likely never be sealed. Remove it: {}", rel(path), p.session, rm(path))));
    }
    for path in &scan.unreadable {
        d.records.push(Line::problem(format!("inbox   {} cannot be read as a declaration. Remove it: {}", rel(path), rm(path))));
    }
    let state = ctx.store.state_dir();
    let tasks = ctx.store.list();
    let mut broken = Vec::new();
    for t in &tasks {
        if let log::Chain::Broken(line) = log::verify(&state, &t.id) {
            broken.push(format!("{} (line {line})", t.id));
        }
    }
    if broken.is_empty() {
        let active = tasks.iter().filter(|t| t.status == Status::Active).count();
        d.records.push(Line::ok(format!("record  {} task{}, {active} active. Logs are intact. This is a forensic aid, not a seal", tasks.len(), if tasks.len() == 1 { "" } else { "s" })));
    } else {
        d.records.push(Line::problem(format!("record  the log of {} was altered or damaged. Trust the signed receipts, not this log", broken.join(", "))));
    }
}

pub fn render(ui: &Ui, d: &Diagnosis) -> String {
    let mut out = Out::new(ui, 9);
    out.title(&format!("Doctor  {}", d.repo.as_deref().unwrap_or("05")), &format!("use05 {}", env!("CARGO_PKG_VERSION")));
    let sections: [(&str, &Vec<Line>); 5] = [("Setup", &d.setup), ("Keys", &d.keys), ("Controls", &d.controls), ("Record", &d.records), ("Extend", &d.extensions)];
    for (label, lines) in sections {
        if lines.is_empty() {
            continue;
        }
        out.section(label, lines.iter().map(Line::item).collect());
        out.blank();
    }
    out.raw(&ui.rule(ui.width));
    let (problems, notes) = (d.problems(), d.notes());
    if problems > 0 {
        out.raw(&format!("{} {} problem{} to fix", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), problems, if problems == 1 { "" } else { "s" }));
    } else if notes > 0 {
        out.raw(&format!("{} working. {notes} thing{} not set up, shown above", ui.paint(Tone::Good, ui.glyph(Glyph::Ok)), if notes == 1 { " is" } else { "s are" }));
    } else {
        out.raw(&format!("{} everything is set up", ui.paint(Tone::Good, ui.glyph(Glyph::Ok))));
    }
    if let Some(next) = &d.next {
        out.raw(&format!("{} {next}", ui.paint(Tone::Info, "Next:")));
    }
    out.finish()
}

pub fn run(repo: &Path, json: bool) -> ExitCode {
    let d = diagnose(repo);
    let exit = if d.problems() > 0 { 4 } else { 0 };
    if json {
        let lines = |ls: &Vec<Line>| ls.iter().map(|l| json!({ "level": match l.level { Level::Ok => "ok", Level::Note => "note", Level::Problem => "problem" }, "text": l.text })).collect::<Vec<_>>();
        let report = Report {
            command: "doctor",
            outcome: if exit == 0 { "healthy" } else { "problems" },
            code: if exit == 0 { "DOCTOR_OK" } else { "DOCTOR_PROBLEMS" },
            tone: if exit == 0 { Tone::Good } else { Tone::Bad },
            headline: format!("{} problem(s), {} note(s)", d.problems(), d.notes()),
            rows: vec![],
            notes: vec![],
            next: d.next.clone(),
            excerpt: vec![],
            details: json!({ "setup": lines(&d.setup), "keys": lines(&d.keys), "controls": lines(&d.controls), "record": lines(&d.records), "extensions": lines(&d.extensions) }),
            exit,
        };
        return emit(&report, true);
    }
    print!("{}", render(&Ui::stdout(), &d));
    ExitCode::from(exit)
}

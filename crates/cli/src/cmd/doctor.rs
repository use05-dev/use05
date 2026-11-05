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
    /// A suggestion from the record: shown like a note, but not something that is not set up.
    Tip,
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
    fn tip(text: impl Into<String>) -> Line {
        Line { level: Level::Tip, text: text.into() }
    }
    fn problem(text: impl Into<String>) -> Line {
        Line { level: Level::Problem, text: text.into() }
    }
    fn item(&self) -> Item {
        match self.level {
            Level::Ok => Item::new(Glyph::Ok, Tone::Good, self.text.clone()),
            Level::Note | Level::Tip => Item::new(Glyph::Warn, Tone::Warn, self.text.clone()),
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
    /// How many receipts are stored here and how large they are; none when there is no repository.
    pub receipts: Option<store::Stats>,
    pub next: Option<String>,
}

impl Diagnosis {
    pub fn problems(&self) -> usize {
        self.all().filter(|l| l.level == Level::Problem).count()
    }
    pub fn notes(&self) -> usize {
        self.all().filter(|l| l.level == Level::Note).count()
    }
    pub fn tips(&self) -> usize {
        self.all().filter(|l| l.level == Level::Tip).count()
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

/// 0 B, 812 B, 1.4 KB, 3.2 MB.
fn size(bytes: u64) -> String {
    match bytes {
        0..=999 => format!("{bytes} B"),
        1000..=999_999 => format!("{:.1} KB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    }
}

fn short(key_id: &str) -> String {
    key_id.chars().take(16).collect()
}

/// A stretch of time as a person says it: `45 s`, `41 min`, `3.5 h`.
fn span(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs} s"),
        90..=7199 => format!("{} min", (secs + 30) / 60),
        _ => {
            let hours = (secs as f64 / 360.0).round() / 10.0;
            format!("{} h", if hours.fract() == 0.0 { format!("{hours:.0}") } else { format!("{hours:.1}") })
        }
    }
}

/// Fewest quiet gaps worth a suggestion.
const ENOUGH_GAPS: usize = 20;

/// The last thirty days of how long agents went quiet between edits, against how long a declared
/// area stays reserved (D98). The suggestion is the 90th percentile in whole hours, at least one;
/// 05 never changes the setting itself.
fn reservation_tip(gaps: &[u64], idle_hours: u32) -> Option<String> {
    // Zero frees an area at once: deliberate, never second-guessed.
    if gaps.len() < ENOUGH_GAPS || idle_hours == 0 {
        return None;
    }
    let mut sorted = gaps.to_vec();
    sorted.sort_unstable();
    let p90 = sorted[(sorted.len() * 9).div_ceil(10) - 1];
    let (have, quiet) = (f64::from(idle_hours), p90 as f64 / 3600.0);
    let suggested = p90.div_ceil(3600).max(1) as u32;
    if (quiet - have).abs() <= have / 2.0 || suggested == idle_hours {
        return None;
    }
    // A shorter time frees areas sooner, which is less strict: only a terminal may do it.
    let lead = if suggested < idle_hours { "Less strict, so set it at a terminal, not from the console:" } else { "To match:" };
    Some(format!(
        "Tip: agents here go quiet up to {} between edits (p90, 30 days); reservations lapse after {idle_hours} h. {lead} use05 policy set drift.reservation_idle_hours {suggested}",
        span(p90)
    ))
}

/// The Stop hook may run for this long before the agent's tool gives up on it.
const STOP_HOOK_SECS: u64 = 90;

/// Longest proof that still leaves the Stop hook room to finish.
const STOP_PROOF_MAX_MS: u64 = 80_000;

/// What the Stop hook would have to prove for one change, from the checks that have run: the
/// required checks that always apply, plus the longest of those limited to some paths (a change
/// may touch only one of them, or all, so the longest is the fair figure). Each item is whether
/// the check is limited to paths, and how long its newest run took, when it has run.
fn stop_proof_ms(checks: impl IntoIterator<Item = (bool, Option<u64>)>) -> u64 {
    let (mut always, mut longest_scoped) = (0u64, 0u64);
    for (scoped, ms) in checks {
        match (scoped, ms) {
            (_, None) => {}
            (true, Some(ms)) => longest_scoped = longest_scoped.max(ms),
            (false, Some(ms)) => always += ms,
        }
    }
    always + longest_scoped
}

/// How long the required checks took at their newest runs, against what the Stop hook may spend
/// proving (D98). `budget_secs` of 0 means it was turned off on purpose.
fn stop_budget_tip(required_ms: u64, budget_secs: u64) -> Option<String> {
    if budget_secs == 0 || required_ms == 0 || required_ms <= budget_secs.saturating_mul(1000) {
        return None;
    }
    let took = crate::report::duration(required_ms);
    Some(if required_ms <= STOP_PROOF_MAX_MS {
        format!("Tip: your checks that have run take {took}, more than the {budget_secs} s the Stop hook may spend, so they wait for the push. To prove them when an agent finishes: use05 policy set evidence.stop_budget_secs {}", required_ms.div_ceil(10_000) * 10)
    } else {
        format!("Tip: your checks that have run take {took}. The Stop hook has {STOP_HOOK_SECS} s, so CI or the pre-push hook proves them instead")
    })
}

/// On WSL, a repository under `/mnt/<letter>/` is on a Windows drive, where Git and hooks are slow
/// (D98). `proc_version` is the text of `/proc/version`.
fn windows_drive_warning(proc_version: &str, repo_path: &Path) -> Option<String> {
    if !proc_version.to_ascii_lowercase().contains("microsoft") || !repo_path.has_root() {
        return None;
    }
    let mut parts = repo_path.components().filter_map(|c| match c {
        std::path::Component::Normal(n) => n.to_str(),
        _ => None,
    });
    let (Some("mnt"), Some(drive)) = (parts.next(), parts.next()) else { return None };
    let letter = drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic());
    letter.then(|| format!("This repository is on a Windows drive (/mnt/{drive}); hooks are slow there. Clone it inside WSL (~/code)."))
}

pub fn diagnose(repo: &Path) -> Diagnosis {
    let mut d = Diagnosis { repo: None, setup: vec![], keys: vec![], controls: vec![], records: vec![], extensions: vec![], receipts: None, next: None };

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
    // With no required check, every verdict here rests on the rules alone (S5, D101). Said of the
    // file as written, committed or not: just after `use05 init` is when it helps most.
    let written = setup.policy_file.then(|| use05_core::policy::Policy::load_file(&top.join(POLICY_PATH)).ok().flatten()).flatten();
    if written.is_some_and(|p| p.required_checks().next().is_none()) {
        let add = match use05_core::policy::detect_checks(&top).first() {
            Some(c) => format!("use05 policy add check '{{ name = \"{}\", run = [{}] }}'", c.name, c.run.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ")),
            None => "use05 policy add check '{ name = \"test\", run = [\"<your test command>\"] }'".to_string(),
        };
        d.setup.push(Line::note(format!("no required checks, so 05 never runs anything here to see whether a change works: every ALLOW rests on the rules alone. Add the command that decides it: {add}")));
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

    if cfg!(target_os = "linux") {
        if let Some(warning) = std::fs::read_to_string("/proc/version").ok().and_then(|v| windows_drive_warning(&v, &top)) {
            d.setup.push(Line::note(warning));
        }
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
    if let Some(k) = keys::touch_id_public() {
        let id = short(&use05_receipt::PublicKey::Passkey(k).id());
        if crate::touchid::supported() {
            d.keys.push(Line::ok(format!("Touch ID approver key {id}: in this Mac's Secure Enclave, so only you, with {}, can approve", crate::touchid::method())));
        } else {
            d.keys.push(Line::problem(format!("Touch ID approver key {id} is here, but this build of 05 or this machine cannot use it")));
        }
    }
    if keys::passphrase_approver_exists() {
        let id = keys::approver_public().map(|k| short(&use05_receipt::key_id(&k))).unwrap_or_else(|| "unknown".into());
        if keys::approver_protected() {
            d.keys.push(Line::ok(format!("approver key {id}: passphrase-protected, so an agent cannot approve for you")));
        } else {
            d.keys.push(Line::note(format!("approver key {id} has no passphrase: anything that can read the file can approve. Make a new one with a passphrase")));
        }
    } else if keys::pinned_passkeys().is_empty() && keys::touch_id_public().is_none() {
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
    let missing = crate::cmd::init::missing_hook_events(ctx.top());
    if !missing.is_empty() {
        d.controls.push(line(Level::Note, format!("Agent hooks were installed by an older 05 and lack {}. `use05 init` brings them up to date", missing.join(", "))));
        if d.next.is_none() {
            d.next = Some("use05 init".into());
        }
    }
    d.controls.push(match setup.pre_push {
        Hook::Ours => line(Level::Ok, "pre-push hook  on. Advisory: `git push --no-verify` skips it".into()),
        Hook::Foreign => line(Level::Note, "pre-push hook  another tool's hook is installed and 05 left it alone, so pushes are not checked here".into()),
        Hook::Missing => line(Level::Note, "pre-push hook  off. Pushes are not checked on this machine".into()),
    });
    if let Some((problem, text)) = crate::cmd::init::lfs_hook_problem(ctx.top(), &setup.pre_push) {
        d.controls.push(line(if problem { Level::Problem } else { Level::Note }, text));
    }
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
    // Where the runner key goes (D94): a workflow the branch defines must not get it, and the
    // host has to keep it for the gate alone, which nothing in the repository shows.
    for h in crate::host::all() {
        let exposed = h.key_exposed_in(ctx.top());
        if !exposed.is_empty() {
            let files: Vec<String> = exposed.iter().map(|p| p.display().to_string()).collect();
            d.controls.push(line(Level::Note, format!("CI key  {} give{} the runner key to a run the branch defines, so an agent's push can read it. Move to the gate a branch cannot change: use05 init --ci {}, then rotate the key", files.join(", "), if files.len() == 1 { "s" } else { "" }, h.name())));
        }
        if h.workflows().iter().any(|(rel, _)| ctx.top().join(rel).exists()) {
            for said in h.key_custody() {
                d.controls.push(line(Level::Note, format!("CI key  {said}")));
            }
        }
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
    let stats = store::stats(top);
    d.receipts = Some(stats);
    d.records.push(Line::ok(format!(
        "receipts  {} on {} branch{}, {}. Never pruned; branches never force-pushed",
        stats.receipts,
        stats.branches,
        if stats.branches == 1 { "" } else { "es" },
        size(stats.bytes),
    )));
    if let Some(line) = crate::cmd::status::waiting_line(ctx.top()) {
        d.records.push(Line::problem(format!("inbox   {line}")));
    }
    for hint in use05_core::asked::hints(&ctx.store.state_dir(), use05_core::time::now_secs()) {
        d.records.push(Line::tip(format!("rules   {}", hint.sentence())));
    }
    // The settings the next two tips name are changed with `use05 policy set`, which edits the
    // policy file and counts once it is committed: no file, or one not committed, no command to offer.
    if top.join(POLICY_PATH).exists() && !ctx.policy_uncommitted {
        let now = use05_core::time::now_secs();
        if ctx.policy.drift.reservation_idle_hours > 0 {
            let gaps = log::quiet_gaps(&ctx.store.state_dir(), now.saturating_sub(30 * 86_400));
            if let Some(tip) = reservation_tip(&gaps, ctx.policy.drift.reservation_idle_hours) {
                d.records.push(Line::tip(tip));
            }
        }
        if ctx.policy.evidence.stop_budget_secs > 0 && ctx.policy.check.iter().any(|c| c.required) {
            let found = use05_core::evidence::classify(&ctx.trust, &store::find_all(top));
            let ms = stop_proof_ms(ctx.policy.check.iter().filter(|c| c.required).map(|c| (!c.paths.is_empty(), use05_core::evidence::last_duration_ms(&found, &c.run, c.dir.as_deref()))));
            if let Some(tip) = stop_budget_tip(ms, ctx.policy.evidence.stop_budget_secs) {
                d.records.push(Line::tip(tip));
            }
        }
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
    let (problems, notes, tips) = (d.problems(), d.notes(), d.tips());
    let tips_said = match tips {
        0 => String::new(),
        1 => ". 1 tip shown above".to_string(),
        n => format!(". {n} tips shown above"),
    };
    if problems > 0 {
        out.raw(&format!("{} {} problem{} to fix", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), problems, if problems == 1 { "" } else { "s" }));
    } else if notes > 0 {
        out.raw(&format!("{} working. {notes} thing{} not set up, shown above{tips_said}", ui.paint(Tone::Good, ui.glyph(Glyph::Ok)), if notes == 1 { " is" } else { "s are" }));
    } else {
        out.raw(&format!("{} everything is set up{tips_said}", ui.paint(Tone::Good, ui.glyph(Glyph::Ok))));
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
        let lines = |ls: &Vec<Line>| ls.iter().map(|l| json!({ "level": match l.level { Level::Ok => "ok", Level::Note => "note", Level::Tip => "tip", Level::Problem => "problem" }, "text": l.text })).collect::<Vec<_>>();
        let report = Report {
            command: "doctor",
            outcome: if exit == 0 { "healthy" } else { "problems" },
            code: if exit == 0 { "DOCTOR_OK" } else { "DOCTOR_PROBLEMS" },
            tone: if exit == 0 { Tone::Good } else { Tone::Bad },
            headline: if d.tips() == 0 { format!("{} problem(s), {} note(s)", d.problems(), d.notes()) } else { format!("{} problem(s), {} note(s), {} tip(s)", d.problems(), d.notes(), d.tips()) },
            rows: vec![],
            notes: vec![],
            next: d.next.clone(),
            excerpt: vec![],
            details: json!({ "setup": lines(&d.setup), "keys": lines(&d.keys), "controls": lines(&d.controls), "record": lines(&d.records), "extensions": lines(&d.extensions), "receipts": d.receipts.map(|s| json!({ "count": s.receipts, "branches": s.branches, "bytes": s.bytes })) }),
            exit,
        };
        return emit(&report, true);
    }
    print!("{}", render(&Ui::stdout(), &d));
    ExitCode::from(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_windows_drive_warning() {
        let wsl = "Linux version 5.15.90.1-microsoft-standard-WSL2 (root@1234) (gcc 11.2.0) #1 SMP";
        let said = windows_drive_warning(wsl, Path::new("/mnt/c/Users/alex/code/app")).unwrap();
        assert_eq!(said, "This repository is on a Windows drive (/mnt/c); hooks are slow there. Clone it inside WSL (~/code).");
        assert!(windows_drive_warning(wsl, Path::new("/mnt/d")).unwrap().contains("(/mnt/d)"));
        assert_eq!(windows_drive_warning(wsl, Path::new("/home/alex/code/app")), None, "inside WSL is fine");
        assert_eq!(windows_drive_warning(wsl, Path::new("/mnt/wsl/shared")), None, "not a drive letter");
        assert_eq!(windows_drive_warning(wsl, Path::new("mnt/c/app")), None, "only an absolute path");
        let plain = "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12) #1 SMP Debian";
        assert_eq!(windows_drive_warning(plain, Path::new("/mnt/c/app")), None, "a Linux with a drive mounted at /mnt/c is not WSL");
    }

    #[test]
    fn times_read_as_a_person_says_them() {
        assert_eq!([span(45), span(2460), span(7200), span(12_600), span(14_400)], ["45 s", "41 min", "2 h", "3.5 h", "4 h"]);
    }

    #[test]
    fn the_reservation_tip_needs_enough_gaps_and_a_real_difference() {
        let gaps = |p90: u64| -> Vec<u64> { (0..20).map(|i| if i < 17 { 60 } else { p90 }).collect() };
        let tip = reservation_tip(&gaps(2460), 2).unwrap();
        assert!(tip.starts_with("Tip: agents here go quiet up to 41 min between edits (p90, 30 days); reservations lapse after 2 h."), "{tip}");
        assert!(tip.ends_with("use05 policy set drift.reservation_idle_hours 1") && tip.contains("Less strict, so set it at a terminal, not from the console:"), "lowering is a loosening, and says so: {tip}");
        assert_eq!(reservation_tip(&gaps(2460)[1..], 2), None, "nineteen is too few");
        assert_eq!(reservation_tip(&gaps(5400), 2), None, "1.5 h against 2 h is close enough");
        let longer = reservation_tip(&gaps(5 * 3600 + 1), 2).unwrap();
        assert!(longer.ends_with("drift.reservation_idle_hours 6") && !longer.contains("Less strict"), "rounded up to a whole hour; raising is not a loosening: {longer}");
        assert_eq!(reservation_tip(&gaps(2460), 0), None, "0 is deliberate");
    }

    #[test]
    fn the_stop_proof_counts_the_checks_that_always_apply_and_only_the_longest_scoped_one() {
        assert_eq!(stop_proof_ms([(false, Some(1000)), (true, Some(2000)), (true, Some(2500)), (false, Some(500)), (false, None), (true, None)]), 1000 + 500 + 2500);
        assert_eq!(stop_proof_ms([(true, Some(3000))]), 3000);
        assert_eq!(stop_proof_ms([(false, None)]), 0);
    }

    #[test]
    fn the_stop_budget_tip_rounds_up_and_gives_way_to_ci_when_it_cannot_fit() {
        assert_eq!(stop_budget_tip(0, 60), None, "no known duration");
        assert_eq!(stop_budget_tip(45_000, 60), None, "fits");
        assert_eq!(stop_budget_tip(70_000, 0), None, "turned off on purpose");
        let fits = stop_budget_tip(71_200, 60).unwrap();
        assert!(fits.starts_with("Tip: your checks that have run take 1m11s") && fits.contains("1m11s") && fits.ends_with("use05 policy set evidence.stop_budget_secs 80"), "{fits}");
        assert!(stop_budget_tip(80_000, 60).unwrap().ends_with("evidence.stop_budget_secs 80"));
        let long = stop_budget_tip(80_001, 60).unwrap();
        assert!(long.contains("The Stop hook has 90 s, so CI or the pre-push hook proves them") && !long.contains("policy set"), "{long}");
    }
}

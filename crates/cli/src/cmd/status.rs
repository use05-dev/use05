//! Bare `use05`.
//!
//! On a terminal it shows where this repository stands and offers a short menu (D37). When
//! output is piped, or there is no terminal, it prints the same status and exits: a script
//! calling bare `use05` must never block waiting for a key.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use use05_core::gate::{Decision, Effect};
use use05_core::policy::Role;

use crate::cmd::init::{Hook, inspect};
use crate::ctx::Ctx;
use crate::ui::{Glyph, Item, Out, Tone, Ui};

struct Status {
    text: String,
    /// `(menu label, args to run)` offered on a terminal.
    menu: Vec<(&'static str, Vec<&'static str>)>,
}

fn intro(ui: &Ui) -> String {
    let mut out = Out::new(ui, 9);
    out.title("05", &format!("use05 {}", env!("CARGO_PKG_VERSION")));
    out.raw("Holds AI agents to what they declared: people own the request and the acceptance.");
    out.blank();
    out.raw("Not inside a git repository, so there is nothing to show here yet.");
    out.blank();
    out.raw(&format!("{} cd into a repository, then run: use05 init", ui.paint(Tone::Info, "Next:")));
    out.raw("       use05 --help     all commands");
    out.finish()
}

/// Declarations an agent left in the inbox that no hook has sealed yet (D65).
pub fn waiting_line(top: &Path) -> Option<String> {
    match use05_core::inbox::scan(top, use05_core::time::now_secs()).waiting.len() {
        0 => None,
        1 => Some("1 declaration is waiting for its agent's hooks (are they trusted? Codex: /hooks)".into()),
        n => Some(format!("{n} declarations are waiting for their agents' hooks (are they trusted? Codex: /hooks)")),
    }
}

fn gather(ui: &Ui, repo: &Path) -> Status {
    let ctx = match Ctx::open(repo, None) {
        Ok(c) => c,
        Err(e) if e.code == "NOT_A_REPO" => return Status { text: intro(ui), menu: vec![] },
        Err(e) => {
            let mut out = Out::new(ui, 9);
            out.title("05", "");
            out.raw(&format!("{} {}", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), e.message));
            if let Some(n) = e.next {
                out.raw(&format!("{} {n}", ui.paint(Tone::Info, "Next:")));
            }
            return Status { text: out.finish(), menu: vec![("Check the setup", vec!["doctor"])] };
        }
    };
    let top = ctx.top().to_path_buf();
    let name = top.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "repository".into());
    let setup = inspect(&top);
    let mut out = Out::new(ui, 9);
    out.title(&format!("05  {name}"), &git_branch(&top));

    // Task
    let task_items = match &ctx.task {
        Some(t) => {
            let mut v = vec![Item::plain(t.title.clone()), Item::dim(format!("task {}  by {}", t.id, crate::cmd::start::author_label(&t.author)))];
            v.push(if t.intent.is_some() {
                if ctx.intent_approved() { Item::new(Glyph::Ok, Tone::Good, "intent approved") } else { Item::new(Glyph::Pending, Tone::Info, "intent card written, not approved yet") }
            } else {
                Item::dim("no intent card; the intent is inferred from the task")
            });
            v
        }
        None => vec![Item::dim("none. `use05 start \"what you are about to do\"` begins one")],
    };
    let mut task_items = task_items;
    if let Some(line) = waiting_line(&top) {
        task_items.push(Item::new(Glyph::Warn, Tone::Warn, line));
    }
    out.section("Task", task_items);
    out.blank();

    // Change
    let mut menu: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
    let mut next: Option<String> = None;
    let change = match ctx.target(None).and_then(|t| ctx.gate(&t).map(|g| (t, g))) {
        Ok((_, g)) if g.changed.is_empty() => vec![Item::dim("nothing staged. `git add` what you want 05 to look at")],
        Ok((_, g)) => {
            let n = g.changed.len();
            let blockers: Vec<_> = g.findings.iter().filter(|f| f.effect >= Effect::Wait).collect();
            let (glyph, tone, word) = match g.decision {
                Decision::Allow => (Glyph::Ok, Tone::Good, "ALLOW"),
                Decision::Wait => (Glyph::Pending, Tone::Info, "WAIT"),
                Decision::ApprovalRequired => (Glyph::Warn, Tone::Warn, "APPROVAL REQUIRED"),
                Decision::Deny => (Glyph::Bad, Tone::Bad, "DENY"),
            };
            let notes = g.findings.iter().filter(|f| f.effect == Effect::Warn).count();
            let summary = match (blockers.len(), use05_core::brief::label_of(&g)) {
                (0, use05_core::brief::Label::Allow) => "nothing to read".to_string(),
                (0, _) => format!("read the notes: {notes}"),
                (n, _) => format!("{n} thing{} hold{} it back", if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }),
            };
            let v = vec![Item::plain(format!("{n} staged file{}", if n == 1 { "" } else { "s" })), Item { glyph: Some((glyph, tone)), text: format!("{word}  {summary}"), dim: false }];
            next = blockers.iter().find_map(|f| f.next.clone());
            menu.push(("See the full brief", vec!["brief"]));
            if blockers.iter().any(|f| f.code.starts_with("CHECK_") || f.code.starts_with("EVIDENCE_")) {
                menu.push(("Run the required checks", vec!["prove"]));
            }
            v
        }
        Err(e) if e.code == "TREE_NOT_FOUND" => vec![Item::dim("no commits yet")],
        Err(e) => vec![Item::new(Glyph::Warn, Tone::Warn, e.message)],
    };
    out.section("Change", change);
    out.blank();

    // Environments, lowest first, each with the commit its branch is at (D82).
    if !ctx.policy.environment.is_empty() {
        let head = |b: &str| {
            use05_core::git::resolve_commit(ctx.top(), &format!("refs/heads/{b}"))
                .or_else(|| use05_core::git::resolve_commit(ctx.top(), &format!("refs/remotes/origin/{b}")))
                .map_or_else(|| "no such branch yet".to_string(), |c| c.chars().take(7).collect())
        };
        // Environments on one level side by side, the levels in ladder order.
        let ladder = use05_core::policy::ladder(&ctx.policy.environment)
            .iter()
            .map(|rung| rung.iter().map(|e| format!("{}: {} ({})", e.name, e.branch, head(&e.branch))).collect::<Vec<_>>().join(", "))
            .collect::<Vec<_>>()
            .join(" → ");
        out.section("Environments", vec![Item::dim(ladder)]);
        out.blank();
    }

    // Controls
    let mark = |on: bool| if on { Item::new(Glyph::Ok, Tone::Good, "") } else { Item::new(Glyph::Pending, Tone::Dim, "") };
    let control = |on: bool, what: &str, how: &str| {
        let mut i = mark(on);
        i.text = format!("{what:<12}{how}");
        i
    };
    let runner = ctx.policy.trust.key.iter().any(|k| k.role == Role::Runner);
    out.section(
        "Controls",
        vec![
            control(setup.claude_hooks || setup.codex_hooks, "agent hooks", if setup.claude_hooks || setup.codex_hooks { "on · advisory" } else { "off" }),
            control(setup.pre_push == Hook::Ours, "pre-push", match setup.pre_push { Hook::Ours => "on · advisory (--no-verify skips it)", Hook::Foreign => "another tool's hook is installed", Hook::Missing => "off" }),
            control(setup.ci_workflow && runner, "CI gate", if setup.ci_workflow && runner { "on · authoritative once required" } else if setup.ci_workflow { "workflow present · no runner key trusted" } else { "off" }),
        ],
    );
    out.blank();
    out.raw(&ui.rule(ui.width));

    if !setup.policy_file {
        next = Some("use05 init".into());
        menu.insert(0, ("Set up 05 in this repository", vec!["init"]));
    }
    let next = next.or_else(|| ctx.task.is_none().then(|| "use05 start \"what you are about to do\"".to_string()));
    if let Some(n) = next {
        out.raw(&format!("{} {n}", ui.paint(Tone::Info, "Next:")));
    } else {
        out.raw(&format!("{} nothing needs doing", ui.paint(Tone::Good, ui.glyph(Glyph::Ok))));
    }
    menu.push(("Check the setup", vec!["doctor"]));
    menu.push(("Show the effective policy", vec!["policy"]));
    Status { text: out.finish(), menu }
}

fn git_branch(top: &Path) -> String {
    use05_core::git::current_branch(top).unwrap_or_else(|| "detached".into())
}

/// Ask for one choice. Returns the index chosen, or `None` for quit or end of input.
fn choose(ui: &Ui, menu: &[(&'static str, Vec<&'static str>)]) -> Option<usize> {
    println!();
    for (i, (label, _)) in menu.iter().enumerate() {
        println!("  {}  {label}", ui.paint(Tone::Info, &format!("{}", i + 1)));
    }
    println!("  {}  Quit", ui.paint(Tone::Dim, "q"));
    print!("\n> ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).ok()? == 0 {
        return None;
    }
    let pick: usize = line.trim().parse().ok()?;
    (1..=menu.len()).contains(&pick).then(|| pick - 1)
}

pub fn run_bare() -> ExitCode {
    run_in(&PathBuf::from("."), std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
}

pub fn run_in(repo: &Path, interactive: bool) -> ExitCode {
    let ui = Ui::stdout();
    let status = gather(&ui, repo);
    print!("{}", status.text);
    if !interactive || status.menu.is_empty() {
        return ExitCode::SUCCESS;
    }
    let Some(index) = choose(&ui, &status.menu) else { return ExitCode::SUCCESS };
    println!();
    // The menu only ever runs 05's own commands, never anything typed in.
    let Ok(exe) = std::env::current_exe() else { return ExitCode::from(4) };
    let code = Command::new(exe).args(&status.menu[index].1).current_dir(repo).status().ok().and_then(|s| s.code()).unwrap_or(4);
    ExitCode::from(code.clamp(0, 255) as u8)
}

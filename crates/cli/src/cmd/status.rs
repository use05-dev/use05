//! Bare `use05`.
//!
//! In a repository it is one page for everything in it: the tasks that need a person, the agents
//! at work, what finished, and how strongly each control is enforced; on a terminal a short menu
//! lets a person open a task. Outside a repository it lists every repository on this machine that
//! 05 has been used in, most in need of a person first, to open one (D37). When output is piped, or
//! there is no terminal, it prints the same page and exits: a script calling bare `use05` must never
//! block waiting for a key.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use use05_core::gate::{Decision, Effect};
use use05_core::policy::Role;
use use05_core::time::now_secs;

use crate::cmd::init::{Hook, inspect};
use crate::ctx::Ctx;
use crate::pending::{self, Entry, Need, Survey, Verdict};
use crate::ui::{Glyph, Item, Out, Tone, Ui, truncate_middle};

/// What a menu choice does on a terminal.
enum Action {
    /// Run one of 05's own commands.
    Run(Vec<String>),
    /// Pick a task from the page, then what to do with it.
    Task,
    /// Show the other repositories on this machine.
    Repos,
}

struct Status {
    text: String,
    menu: Vec<(String, Action)>,
    /// The tasks on the page, in the order shown, for picking one.
    tasks: Vec<Entry>,
    /// Outside a repository: the repositories listed, in the order shown, for picking one.
    repos: Vec<PathBuf>,
    /// The first menu entry is the one thing to do next, and Enter does it (D91).
    enter: bool,
}

impl Status {
    fn plain(text: String) -> Status {
        Status { text, menu: vec![], tasks: vec![], repos: vec![], enter: false }
    }
}

/// Every repository on this machine 05 has been used in, as a table: how many tasks wait for a
/// person, how many agents are working, when it was last active. `None` when none is listed.
fn machine(ui: &Ui) -> Option<Status> {
    const SHOWN: usize = 15;
    let listed = use05_core::repos::list();
    if listed.is_empty() {
        return None;
    }
    let now = now_secs();
    let mut rows: Vec<(PathBuf, usize, usize, u64)> = listed
        .iter()
        .map(|seen| match pending::survey(&seen.path, 10) {
            Ok(s) => (seen.path.clone(), s.waiting().len(), s.entries.iter().filter(|e| e.needs().is_none() && e.working(now)).count(), s.entries.iter().map(|e| e.activity).max().unwrap_or(seen.seen)),
            Err(_) => (seen.path.clone(), 0, 0, seen.seen),
        })
        .collect();
    rows.sort_by_key(|(path, waiting, working, last)| (std::cmp::Reverse(*waiting), std::cmp::Reverse(*working), std::cmp::Reverse(*last), path.clone()));
    let more = rows.len().saturating_sub(SHOWN);
    rows.truncate(SHOWN);

    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.display().to_string());
    let name_w = rows.iter().map(|(p, ..)| name(p).chars().count()).max().unwrap_or(4).clamp(4, 24);
    let when: Vec<String> = rows.iter().map(|(.., last)| pending::ago(now, *last)).collect();
    let when_w = when.iter().map(|w| w.chars().count()).max().unwrap_or(0).max("Last active".len());
    let num_w = rows.len().to_string().len();

    let mut out = Out::new(ui, 9);
    out.title("05", &format!("{} repositor{} on this machine", rows.len() + more, if rows.len() + more == 1 { "y" } else { "ies" }));
    out.raw(&ui.paint(Tone::Dim, &format!("Repositories 05 has been used in. The list stays on this machine: {}", tilde(&use05_core::keys::user_dir().unwrap_or_default().join(use05_core::repos::FILE)))));
    out.blank();
    out.raw(&ui.paint(Tone::Dim, &format!("{:>num_w$}  {:<name_w$}  {:>9}  {:>7}  {:<when_w$}  {}", "#", "Repo", "Needs you", "Working", "Last active", "Path")));
    for (i, ((path, waiting, working, _), when)) in rows.iter().zip(&when).enumerate() {
        let needs = if *waiting > 0 { ui.paint(Tone::Warn, &format!("{waiting:>9}")) } else { ui.paint(Tone::Dim, &format!("{waiting:>9}")) };
        out.raw(&format!("{:>num_w$}  {:<name_w$}  {needs}  {working:>7}  {when:<when_w$}  {}", i + 1, truncate_middle(&name(path), name_w), tilde(path)));
    }
    if more > 0 {
        out.raw(&ui.paint(Tone::Dim, &format!("{more} more not shown")));
    }
    out.blank();
    out.raw(&ui.rule(ui.width));
    let first = &rows[0].0;
    out.raw(&format!("{} cd {} && use05", ui.paint(Tone::Info, "Next:"), shell_word(&first.display().to_string())));
    Some(Status { text: out.finish(), menu: vec![], tasks: vec![], repos: rows.into_iter().map(|(p, ..)| p).collect(), enter: false })
}

/// `~/code/x` for a path under the home directory.
fn tilde(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from).filter(|h| !h.as_os_str().is_empty()) {
        if let Ok(rest) = path.strip_prefix(&home) {
            return if rest.as_os_str().is_empty() { "~".to_string() } else { format!("~/{}", rest.display()) };
        }
    }
    path.display().to_string()
}

/// A path as one shell word: quoted when it holds anything a shell would split or expand.
fn shell_word(text: &str) -> String {
    if text.chars().all(|c| c.is_ascii_alphanumeric() || "~/._-+=@:,".contains(c)) { text.to_string() } else { format!("'{}'", text.replace('\'', r"'\''")) }
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
        Err(e) if e.code == "NOT_A_REPO" => return machine(ui).unwrap_or_else(|| Status::plain(intro(ui))),
        Err(e) => {
            let mut out = Out::new(ui, 9);
            out.title("05", "");
            out.raw(&format!("{} {}", ui.paint(Tone::Bad, ui.glyph(Glyph::Bad)), e.message));
            if let Some(n) = e.next {
                out.raw(&format!("{} {n}", ui.paint(Tone::Info, "Next:")));
            }
            return Status { text: out.finish(), menu: vec![("Check the setup".into(), Action::Run(vec!["doctor".into()]))], tasks: vec![], repos: vec![], enter: false };
        }
    };
    let top = ctx.top().to_path_buf();
    let name = top.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "repository".into());
    let setup = inspect(&top);
    let mut out = Out::new(ui, 9);
    out.title(&format!("05  {name}"), &git_branch(&top));

    // Tasks: who needs you, who is working, what finished.
    let survey = pending::survey_with(&ctx, pending::MAX_TASKS);
    let now = now_secs();
    let listed = task_sections(ui, &mut out, &survey, now);
    if let Some(line) = waiting_line(&top) {
        out.section("Hooks", vec![Item::new(Glyph::Warn, Tone::Warn, line)]);
    }
    // A rule you always approve is costing you attention and catching nothing (D91).
    if let Some(hint) = use05_core::asked::hints(&ctx.store.state_dir(), now).first() {
        out.section("Tip", vec![Item::dim(hint.sentence())]);
    }
    out.blank();

    // Change
    let mut menu: Vec<(String, Action)> = Vec::new();
    if !listed.is_empty() {
        menu.push(("Open a task".into(), Action::Task));
    }
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
            let v = vec![Item::plain(format!("{n} staged file{}", if n == 1 { "" } else { "s" })), Item { glyph: Some((glyph, tone)), text: format!("{word}  {summary}"), dim: false, columns: false }];
            next = blockers.iter().find_map(|f| f.next.clone());
            menu.push(("See the full brief".into(), Action::Run(vec!["brief".into()])));
            if blockers.iter().any(|f| f.code.starts_with("CHECK_") || f.code.starts_with("EVIDENCE_")) {
                menu.push(("Run the required checks".into(), Action::Run(vec!["prove".into()])));
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
        menu.insert(0, ("Set up 05 in this repository".into(), Action::Run(vec!["init".into()])));
    }
    // What would unblock the staged change comes first (prove, say); asking for an approval is said
    // better by naming the task that waits.
    let needs_next = match survey.waiting().as_slice() {
        [] => None,
        [one] => Some(format!("use05 approve --task {}   it shows what holds it back, then asks for you", one.task.id)),
        many => Some(format!("use05 approve   to choose which of the {} tasks waiting for you", many.len())),
    };
    let next = match (next, needs_next) {
        (Some(n), Some(w)) if n.starts_with("use05 approve") => Some(w),
        (n, w) => n.or(w),
    };
    let next = next.or_else(|| survey.entries.is_empty().then(|| "use05 start \"what you are about to do\"".to_string()));
    // The one thing to do comes first in the menu, and Enter does it (D91).
    let landable = survey.entries.iter().find(|e| {
        e.verdict == pending::Verdict::Allowed && ctx.policy.branches.land == use05_core::policy::LandMode::Manual && e.task.branch.as_deref().is_some_and(|b| !use05_core::branches::is_kept(&ctx.policy, b))
    });
    let first: Option<(String, Vec<String>)> = match (setup.policy_file, survey.waiting().as_slice(), landable) {
        (false, ..) => None,
        (true, [one], _) => {
            let mut args = vec!["approve".to_string(), "--task".into(), one.task.id.clone()];
            if one.needs() == Some(Need::Plan) {
                args.push("--intent".into());
            }
            Some((format!("Approve \"{}\"", one.task.title), args))
        }
        (true, [_, _, ..], _) => Some(("Approve: choose which task".into(), vec!["approve".into()])),
        (true, [], Some(e)) => Some((format!("Land \"{}\"", e.task.title), vec!["land".into(), "--task".into(), e.task.id.clone()])),
        (true, [], None) => menu.iter().find(|(l, _)| l == "Run the required checks").map(|(l, a)| (l.clone(), match a { Action::Run(v) => v.clone(), _ => vec![] })),
    };
    let next = match &first {
        Some((_, args)) if args.first().is_some_and(|a| a == "land") => Some(format!("use05 {}   it is allowed; landing moves it to {}", args.join(" "), survey.target)),
        _ => next,
    };
    let enter = first.is_some();
    if let Some((label, args)) = first {
        menu.retain(|(l, _)| *l != label);
        menu.insert(0, (label, Action::Run(args)));
    }
    if let Some(n) = next {
        out.raw(&format!("{} {n}", ui.paint(Tone::Info, "Next:")));
    } else {
        out.raw(&format!("{} nothing needs doing", ui.paint(Tone::Good, ui.glyph(Glyph::Ok))));
    }
    menu.push(("Check the setup".into(), Action::Run(vec!["doctor".into()])));
    menu.push(("Show the effective policy".into(), Action::Run(vec!["policy".into()])));
    if use05_core::repos::list().iter().any(|r| r.path != use05_core::repos::root_of(&ctx.store.dirs)) {
        menu.push(("Other repositories on this machine".into(), Action::Repos));
    }
    Status { text: out.finish(), menu, tasks: listed, repos: vec![], enter }
}

fn git_branch(top: &Path) -> String {
    use05_core::git::current_branch(top).unwrap_or_else(|| "detached".into())
}

/// The tasks on the page, in groups, each line carrying its task id. Returns them in the order
/// shown, for picking one on a terminal.
fn task_sections(ui: &Ui, out: &mut Out, survey: &Survey, now: u64) -> Vec<Entry> {
    const RECENT: usize = 5;
    let needs: Vec<&Entry> = survey.entries.iter().filter(|e| e.needs().is_some()).collect();
    let working: Vec<&Entry> = survey.entries.iter().filter(|e| e.needs().is_none() && e.working(now)).collect();
    let recent: Vec<&Entry> = survey.entries.iter().filter(|e| e.needs().is_none() && !e.working(now)).take(RECENT).collect();
    if needs.is_empty() && working.is_empty() && recent.is_empty() {
        out.section("Tasks", vec![Item::dim("none. `use05 start \"what you are about to do\"` begins one")]);
        return vec![];
    }
    // One set of columns for all three groups, so the ids line up down the page.
    let all: Vec<&Entry> = needs.iter().chain(&working).chain(&recent).copied().collect();
    let landed_on = survey.target.clone();
    let what = |e: &Entry| match (&e.verdict, e.task.status) {
        (Verdict::Needs(n), _) => n.word().to_string(),
        (Verdict::Landed, _) => format!("landed on {}", e.task.intent.as_ref().and_then(|c| c.target.clone()).unwrap_or_else(|| landed_on.clone())),
        _ if e.working(now) => "working".to_string(),
        (_, use05_core::task::Status::Active) if e.task.ended.is_some() => "ended, not finished".to_string(),
        (_, use05_core::task::Status::Active) => "idle".to_string(),
        (Verdict::Allowed, _) => "allowed".to_string(),
        (Verdict::Waiting, _) => "waiting for checks".to_string(),
        (Verdict::Denied, _) => "denied".to_string(),
        _ => "finished".to_string(),
    };
    // The label column, a space, the glyph and its space come first.
    let rows = pending::list_rows(ui, &all, now, ui.width.saturating_sub(9 + 2 + 2), what);
    let mut rows = rows.into_iter();
    let mut group = |label: &str, entries: &[&Entry], glyph: &dyn Fn(&Entry) -> (Glyph, Tone)| {
        if !entries.is_empty() {
            out.section(label, entries.iter().map(|e| Item::columns(glyph(e).0, glyph(e).1, rows.next().unwrap_or_default())).collect());
        }
    };
    group("Needs you", &needs, &|_| (Glyph::Warn, Tone::Warn));
    group("Working", &working, &|_| (Glyph::Pending, Tone::Info));
    group("Recent", &recent, &|e| match e.verdict {
        Verdict::Landed => (Glyph::Ok, Tone::Good),
        Verdict::Denied => (Glyph::Bad, Tone::Bad),
        Verdict::Waiting => (Glyph::Pending, Tone::Info),
        _ => (Glyph::Dot, Tone::Dim),
    });
    if survey.left_out > 0 {
        out.raw(&format!("{:9}  {}", "", ui.paint(Tone::Dim, &format!("{} older task{} not shown", survey.left_out, if survey.left_out == 1 { "" } else { "s" }))));
    }
    all.into_iter().cloned().collect()
}

pub fn run_bare() -> ExitCode {
    run_in(&PathBuf::from("."), std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
}

pub fn run_in(repo: &Path, interactive: bool) -> ExitCode {
    let ui = Ui::stdout();
    let status = gather(&ui, repo);
    print!("{}", status.text);
    if !interactive {
        return ExitCode::SUCCESS;
    }
    let stdin = std::io::stdin();
    // Outside a repository: the table above is the list; pick a row to open it.
    if !status.repos.is_empty() {
        // The lock is let go before another page reads from stdin.
        let picked = crate::pick::ask(&ui, &mut stdin.lock(), &mut std::io::stdout(), status.repos.len(), "Quit");
        return match picked {
            Some(i) => {
                println!();
                run_in(&status.repos[i], true)
            }
            None => ExitCode::SUCCESS,
        };
    }
    if status.menu.is_empty() {
        return ExitCode::SUCCESS;
    }
    let labels: Vec<String> = status.menu.iter().map(|(l, _)| l.clone()).collect();
    let picked = if status.enter {
        crate::pick::choose_first(&ui, &mut stdin.lock(), &mut std::io::stdout(), &labels, "Quit")
    } else {
        crate::pick::choose(&ui, &mut stdin.lock(), &mut std::io::stdout(), None, &labels, "Quit")
    };
    let Some(index) = picked else { return ExitCode::SUCCESS };
    println!();
    match &status.menu[index].1 {
        Action::Run(args) => run_own(repo, args),
        Action::Repos => match machine(&ui) {
            Some(machine) => {
                print!("{}", machine.text);
                let picked = crate::pick::ask(&ui, &mut stdin.lock(), &mut std::io::stdout(), machine.repos.len(), "Quit");
                match picked {
                    Some(i) => {
                        println!();
                        run_in(&machine.repos[i], true)
                    }
                    None => ExitCode::SUCCESS,
                }
            }
            None => ExitCode::SUCCESS,
        },
        Action::Task => open_task(&ui, repo, &status.tasks),
    }
}

/// Pick a task from the page, then what to do with it.
fn open_task(ui: &Ui, repo: &Path, tasks: &[Entry]) -> ExitCode {
    let now = now_secs();
    let refs: Vec<&Entry> = tasks.iter().collect();
    let rows = pending::list_rows(ui, &refs, now, ui.width.saturating_sub(6), |e| e.needs().map_or(String::new(), |n| n.word().to_string()));
    let stdin = std::io::stdin();
    let Some(i) = crate::pick::choose(ui, &mut stdin.lock(), &mut std::io::stdout(), Some("Which task?"), &rows, "Quit") else { return ExitCode::SUCCESS };
    let task = &tasks[i];
    let id = task.task.id.clone();
    let mut actions: Vec<(String, Vec<String>)> = vec![("See its brief".into(), vec!["brief".into(), "--task".into(), id.clone()])];
    if let Some(need) = task.needs() {
        let mut args = vec!["approve".to_string(), "--task".into(), id.clone()];
        if need == Need::Plan {
            args.push("--intent".into());
        }
        actions.push((format!("Approve its {}", need.word()), args));
    }
    actions.push(("Discard its work".into(), vec!["discard".into(), id.clone()]));
    let labels: Vec<String> = actions.iter().map(|(l, _)| l.clone()).collect();
    let title = format!("\"{}\" ({id})", task.task.title);
    let Some(j) = crate::pick::choose(ui, &mut stdin.lock(), &mut std::io::stdout(), Some(&title), &labels, "Back out") else { return ExitCode::SUCCESS };
    println!();
    run_own(repo, &actions[j].1)
}

/// One of 05's own commands, in this repository. The menu only ever runs these, never anything typed in.
fn run_own(repo: &Path, args: &[String]) -> ExitCode {
    let Ok(exe) = std::env::current_exe() else { return ExitCode::from(4) };
    let code = Command::new(exe).args(args).current_dir(repo).status().ok().and_then(|s| s.code()).unwrap_or(4);
    ExitCode::from(code.clamp(0, 255) as u8)
}

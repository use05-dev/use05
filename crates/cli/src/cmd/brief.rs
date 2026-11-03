use std::path::Path;
use std::process::ExitCode;

use use05_core::brief::{Brief, Label, build};
use use05_core::gate::{CheckState, Decision, Effect, Finding};
use use05_core::claims::Judged;
use use05_core::policy::Role;
use use05_receipt::Decision as Vote;

use crate::ctx::Ctx;
use crate::report::{Report, command_text, duration, emit};
use crate::ui::{Glyph, Item, Out, Tone, Ui};

pub fn run(repo: &Path, task: Option<&str>, tree: Option<&str>, fetch: bool, json: bool) -> ExitCode {
    let fail = |e| emit(&Report::from_core("brief", e), json);
    // A named task is looked at where its work is, not wherever this was run.
    let (repo, located) = if tree.is_none() { crate::pending::locate(repo, task, None) } else { (repo.to_path_buf(), None) };
    let tree = tree.or(located.as_deref());
    let ctx = match Ctx::open_judging(&repo, task) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    if fetch {
        if let Err(e) = use05_core::store::fetch(ctx.top()) {
            eprintln!("05: {} Showing the receipts this machine already has.", e.message);
        }
    }
    let target = match ctx.target(tree) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let gate = match ctx.gate(&target) {
        Ok(g) => g,
        Err(e) => return fail(e),
    };
    let decision = gate.decision;
    // Other agent sessions that edited the same files in the last day (what a reviewer should know).
    let overlaps = match &ctx.task {
        Some(task) => {
            let paths: Vec<String> = gate.changed.iter().map(|c| c.path.clone()).collect();
            use05_core::overlap::recent(&ctx.store, &task.id, &paths, 24 * 3600)
        }
        None => Vec::new(),
    };
    let mut brief = build(ctx.task.as_ref(), gate, &target.oid, &target.label, target.base_commit.as_deref(), target.head_commit.as_deref());
    // The session, digested from the task's log as this machine has it, or as it travelled.
    if !ctx.policy.environment.is_empty() {
        let target = use05_core::branches::target_for(&ctx.policy, ctx.task.as_ref().and_then(|t| t.intent.as_ref()), ctx.top());
        brief.lands_on = Some(match ctx.policy.environment.iter().find(|e| e.branch == target) {
            Some(e) => format!("{target} ({})", e.name),
            None => format!("{target} (not an environment)"),
        });
    }
    brief.session = ctx.task.as_ref().zip(ctx.task_found()).and_then(|(t, found)| use05_core::logseal::copy(ctx.top(), Some(&ctx.store.state_dir()), found, &t.id)).map(|text| use05_core::session::digest(&text));
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "v": 1, "command": "brief", "decision": decision.word(), "label": brief.label, "brief": brief, "overlap": overlaps })).expect("brief serialises"));
    } else {
        print!("{}", render(&Ui::stdout(), &brief, ctx.org.as_deref(), &overlaps));
    }
    ExitCode::from(decision.exit_code())
}

/// 56602 as "56,602".
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn files(n: usize) -> String {
    format!("{} file{}", thousands(n as u64), if n == 1 { "" } else { "s" })
}

/// At most four rows, whatever the length of the session: its size, what was refused and why,
/// how the checks went along the way, and the subagents that took part.
fn session_items(sn: &use05_core::session::Session) -> Vec<Item> {
    let plural = |n: usize, one: &str, many: &str| format!("{} {}", thousands(n as u64), if n == 1 { one } else { many });
    let span = match sn.minutes {
        0 => "under a minute".to_string(),
        m if m >= 60 => format!("{} h {} min", m / 60, m % 60),
        m => format!("{m} min"),
    };
    let mut items = Vec::new();
    // A task worked by hand from the command line has no agent turns or tool calls to count.
    if sn.turns + sn.tool_calls > 0 {
        // Files are counted from edit tools; shell commands log no paths, so a zero says nothing.
        let touched = if sn.files_touched > 0 { format!(" · {} touched", plural(sn.files_touched, "file", "files")) } else { String::new() };
        items.push(Item::plain(format!("{span} · {} · {}{touched}", plural(sn.turns, "turn", "turns"), plural(sn.tool_calls, "tool call", "tool calls"))));
    }
    let total: usize = sn.refused.iter().map(|(_, n)| n).sum();
    if total > 0 || sn.asked > 0 {
        let mut parts = Vec::new();
        if total > 0 {
            let reasons: Vec<String> = sn.refused.iter().take(4).map(|(why, n)| format!("{why} {n}")).collect();
            let more = if sn.refused.len() > 4 { format!(", {} other", sn.refused[4..].iter().map(|(_, n)| n).sum::<usize>()) } else { String::new() };
            parts.push(format!("refused {total}: {}{more}", reasons.join(", ")));
        }
        if sn.asked > 0 {
            parts.push(format!("asked a person {}", sn.asked));
        }
        items.push(Item::new(Glyph::Warn, Tone::Warn, parts.join(" · ")));
    }
    if !sn.checks.is_empty() {
        let clauses: Vec<String> = sn.checks.iter().take(3).map(|c| {
            format!("{} ran {}, failed {}, {}", c.name, c.runs, c.failed, if c.last_passed { "passed last time" } else { "failed last time" })
        }).collect();
        let text = format!("checks during the session: {}", clauses.join("; "));
        items.push(if sn.checks.iter().all(|c| c.last_passed) { Item::dim(text) } else { Item::new(Glyph::Warn, Tone::Warn, text) });
    }
    if !sn.subagents.is_empty() {
        let total: usize = sn.subagents.iter().map(|(_, n)| n).sum();
        let kinds: Vec<String> = sn.subagents.iter().take(4).map(|(k, n)| format!("{k} {n}")).collect();
        items.push(Item::dim(format!("subagents {total}: {}", kinds.join(", "))));
    }
    items
}

fn effect_item(f: &Finding) -> Item {
    let (glyph, tone) = match f.effect {
        Effect::Deny => (Glyph::Bad, Tone::Bad),
        Effect::Approval => (Glyph::Warn, Tone::Warn),
        Effect::Wait => (Glyph::Pending, Tone::Info),
        Effect::Warn => (Glyph::Warn, Tone::Warn),
        Effect::Info => (Glyph::Dot, Tone::Dim),
    };
    Item::new(glyph, tone, format!("{}  {}", f.code, f.message))
}

pub fn render(ui: &Ui, b: &Brief, org: Option<&str>, overlaps: &[use05_core::overlap::Overlap]) -> String {
    let mut out = Out::new(ui, 9);
    let right = match &b.task_id {
        Some(id) => format!("task {id}"),
        None => "no task".to_string(),
    };
    out.title(&format!("Brief  {}", b.title), &right);

    // Intent
    let mut intent = Vec::new();
    if let Some(request) = &b.request {
        intent.push(Item::dim(format!("asked: {}", request.lines().next().unwrap_or(""))));
    }
    match (&b.card, &b.goal) {
        (Some(_), Some(goal)) => intent.push(Item::plain(goal.clone())),
        (Some(_), None) => intent.push(Item::dim("no goal written")),
        (None, _) => intent.push(Item::dim("inferred from the task; no card was written")),
    }
    if let Some(l) = &b.lands_on {
        intent.push(Item::dim(format!("lands on {l}")));
    }
    if let Some(a) = &b.agent {
        let model = a.model.as_deref().map(|m| format!(" · model {m}")).unwrap_or_default();
        intent.push(Item::dim(format!("agent  {} · session {}{model}", a.kind, a.session.chars().take(8).collect::<String>())));
    }
    if b.task_id.is_some() {
        intent.push(Item::dim(match (&b.owner, b.owner_confirmed) {
            (Some(o), true) => format!("owner  {}, signed", o.name),
            (Some(o), false) => format!("owner  {}, unconfirmed until they sign an approval", o.name),
            (None, _) => "owner  no owner yet (no approver key when this task started, and nobody has signed)".to_string(),
        }));
    }
    if let Some(card) = &b.card {
        if card.has_scope() {
            intent.push(Item::dim(format!("scope  {}", card.scope.include.join(", "))));
        }
        if !card.scope.exclude.is_empty() {
            intent.push(Item::dim(format!("never  {}", card.scope.exclude.join(", "))));
        }
    }
    let risk_tone = match b.risk.word() {
        "high" => Tone::Bad,
        "medium" => Tone::Warn,
        _ => Tone::Dim,
    };
    intent.push(Item { glyph: None, text: format!("risk   {}", ui.paint(risk_tone, b.risk.word())), dim: false, columns: false });
    for r in &b.gate.risk_reasons {
        let shown: Vec<&str> = r.paths.iter().take(3).map(String::as_str).collect();
        let more = if r.paths.len() > 3 { format!(" and {} more", r.paths.len() - 3) } else { String::new() };
        intent.push(Item::dim(format!("       {}: {}{more}", r.category, shown.join(", "))));
    }
    out.section("Intent", intent);
    out.blank();

    // Outcome
    let n = b.gate.changed.len();
    let mut outcome = vec![Item::plain(format!("{n} file{} changed on {} ({}) · +{} −{}", if n == 1 { "" } else { "s" }, &b.tree[..12.min(b.tree.len())], b.tree_label, thousands(b.added), thousands(b.removed)))];
    // One row per area. The renderer joins words with single spaces, so fields are separated
    // with " · " rather than padded into columns.
    for a in &b.area_summary {
        outcome.push(Item::dim(format!("{} · {} · +{} −{}", a.name, files(a.files), thousands(a.added), thousands(a.removed))));
    }
    if b.outside_scope.len() <= 5 {
        for p in &b.outside_scope {
            outcome.push(Item::new(Glyph::Warn, Tone::Warn, format!("outside scope: {p}")));
        }
    } else {
        let k = b.outside_scope.len();
        let m = b.outside_scope_areas.len();
        outcome.push(Item::new(Glyph::Warn, Tone::Warn, format!("{} outside the declared scope, in {m} area{}", files(k), if m == 1 { "" } else { "s" })));
        outcome.push(Item::dim(b.outside_scope_areas.iter().map(|a| format!("{} {}", a.name, a.files)).collect::<Vec<_>>().join(" · ")));
    }
    out.section("Outcome", outcome);
    out.blank();

    // Evidence
    let mut evidence = Vec::new();
    for c in &b.gate.checks {
        let who = |by: &use05_core::evidence::Signer| match by.role {
            Role::Runner => format!("signed by {} (authoritative)", by.name),
            _ => format!("signed by {} (advisory)", by.name),
        };
        let item = match &c.state {
            CheckState::Passed { by, ms } => Item::new(Glyph::Ok, Tone::Good, format!("{:<10} passed  {}  {}", c.name, duration(*ms), who(by))),
            CheckState::Failed { by, exit_code } => Item::new(Glyph::Bad, Tone::Bad, format!("{:<10} FAILED{}  {}", c.name, exit_code.map(|e| format!(" (exit {e})")).unwrap_or_default(), who(by))),
            CheckState::TimedOut { .. } => Item::new(Glyph::Bad, Tone::Bad, format!("{:<10} TIMED OUT", c.name)),
            CheckState::NotAuthoritative { by } => Item::new(Glyph::Warn, Tone::Warn, format!("{:<10} proved only by a {} key: policy does not accept it", c.name, by.role.word())),
            CheckState::Stale => Item::new(Glyph::Pending, Tone::Info, format!("{:<10} stale: passed on an earlier tree  →  use05 prove {}", c.name, c.name)),
            CheckState::Missing => Item::new(Glyph::Pending, Tone::Info, format!("{:<10} not run on this tree  →  use05 prove {}", c.name, c.name)),
            CheckState::Undefined => Item::new(Glyph::Warn, Tone::Warn, format!("{:<10} asked for by the intent, but not defined in the policy", c.name)),
        };
        evidence.push(item);
        let _ = command_text;
    }
    if evidence.is_empty() {
        evidence.push(Item::dim("policy requires no checks"));
    }
    out.section("Evidence", evidence);
    out.blank();

    // Drift and findings
    let findings: Vec<Item> = b.gate.findings.iter().filter(|f| !f.code.starts_with("CHECK_") && !f.code.starts_with("EVIDENCE_") && f.effect != Effect::Info || ["SCOPE_UNDECLARED", "BYPASS_NOT_ALLOWED"].contains(&f.code)).map(effect_item).collect();
    out.section("Drift", if findings.is_empty() { vec![Item::new(Glyph::Ok, Tone::Good, "nothing differs from the intent")] } else { findings });
    out.blank();

    // Overlap with other agent sessions
    if !overlaps.is_empty() {
        let items = overlaps.iter().take(6).map(|o| Item::new(Glyph::Warn, Tone::Warn, format!("{} also edited by task {} ({}: \"{}\") {} min ago", o.path, o.task, o.author, o.title, o.minutes_ago)));
        out.section("Overlap", items.collect());
        out.blank();
    }

    // Claims
    if !b.gate.claims.is_empty() {
        let items = b.gate.claims.iter().map(|c| match &c.judged {
            Judged::Supported { by } => Item::new(Glyph::Ok, Tone::Good, format!("\"{}\"  supported by {by}", c.text)),
            Judged::Unsupported => Item::new(Glyph::Warn, Tone::Warn, format!("\"{}\"  no {} check ran on this tree", c.text, c.category.word())),
            Judged::Contradicted { by } => Item::new(Glyph::Bad, Tone::Bad, format!("\"{}\"  contradicted: {by} did not pass", c.text)),
        });
        out.section("Claims", items.collect());
        out.blank();
    }

    // Approvals
    let approvals: Vec<Item> = b.gate.approvals.iter().map(|a| {
        let what = match (a.vote, a.scope) {
            (Vote::Approve, use05_receipt::ApprovalScope::Intent) => "approved the intent",
            (Vote::Approve, _) => "approved the outcome",
            (Vote::Reject, _) => "rejected the outcome",
        };
        match a.void {
            Some(why) => Item::new(Glyph::Dot, Tone::Dim, format!("{} {what}: no longer counts ({why})", a.by.name)),
            None if a.vote == Vote::Approve => Item::new(Glyph::Ok, Tone::Good, format!("{} {what}: \"{}\"", a.by.name, a.rationale)),
            None => Item::new(Glyph::Bad, Tone::Bad, format!("{} {what}: \"{}\"", a.by.name, a.rationale)),
        }
    }).collect();
    out.section("Approvals", if approvals.is_empty() { vec![Item::dim("none")] } else { approvals });
    // Tested by a person before a push (D87): their note, in their words.
    if !b.gate.testing.is_empty() || b.gate.findings.iter().any(|f| f.code.starts_with("TESTING_")) {
        let tested: Vec<Item> = b.gate.testing.iter().map(|t| {
            let what = if t.outcome == use05_receipt::Tested::Tested { "tried it" } else { "skipped testing" };
            match t.void {
                Some(why) => Item::new(Glyph::Dot, Tone::Dim, format!("{} {what}: \"{}\" (does not count: {why})", t.by.name, t.note)),
                None => Item::new(Glyph::Ok, Tone::Good, format!("{} {what}: \"{}\"", t.by.name, t.note)),
            }
        }).collect();
        out.blank();
        out.section("Tested", if tested.is_empty() { vec![Item::dim("not yet: a person tries it and signs off before it is pushed")] } else { tested });
    }
    if let Some(sn) = b.session.as_ref().filter(|sn| sn.tool_calls + sn.turns + sn.checks.len() > 0) {
        out.blank();
        out.section("Session", session_items(sn));
    }
    if let Some(l) = &b.gate.log {
        out.blank();
        let mut items = vec![match (l.altered_at, l.ci_sealed_at, l.hook_seals) {
            (Some(line), _, _) => Item::new(Glyph::Bad, Tone::Bad, format!("altered: line {line} no longer matches what was sealed")),
            (None, Some(line), n) => Item::new(Glyph::Ok, Tone::Good, format!("sealed by CI at line {line} of {} (runner key), backed by {n} seal(s) from where the work happened", l.lines)),
            (None, None, 0) => Item::dim(format!("not anchored: {} line(s), no trusted seal{}", l.lines, if l.travels { "" } else { "; kept on this machine only" })),
            (None, None, n) => Item::dim(format!("anchored by this machine at {n} point(s), last at line {} of {}; not yet sealed by CI", l.last_hook_seal.unwrap_or(0), l.lines)),
        }];
        if let Some(line) = l.tail_broken_at {
            items.push(Item::new(Glyph::Warn, Tone::Warn, format!("the unsealed lines from {line} on do not chain, so they cannot be proved")));
        }
        out.section("Log", items);
    }
    out.blank();

    // Unknowns and undo
    out.section("Unknowns", b.unknowns.iter().map(|u| Item::new(Glyph::Dot, Tone::Dim, u.clone())).collect());
    out.blank();
    out.section("Undo", b.undo.iter().map(|u| Item::plain(u.clone())).collect());
    out.blank();
    out.raw(&ui.rule(ui.width));

    // Decision
    let g = &b.gate;
    let notes: Vec<&Finding> = if b.label == Label::AllowWithNotes && g.bypass.is_none() { g.findings.iter().filter(|f| f.effect == Effect::Warn).collect() } else { Vec::new() };
    let blockers: Vec<&Finding> = if notes.is_empty() { g.findings.iter().filter(|f| f.effect >= Effect::Wait).collect() } else { notes.clone() };
    let (glyph, tone, word) = match g.decision {
        Decision::Allow => (Glyph::Ok, Tone::Good, "ALLOW"),
        Decision::Wait => (Glyph::Pending, Tone::Info, "WAIT"),
        Decision::ApprovalRequired => (Glyph::Warn, Tone::Warn, "APPROVAL REQUIRED"),
        Decision::Deny => (Glyph::Bad, Tone::Bad, "DENY"),
    };
    let summary = match (&g.bypass, blockers.len()) {
        (Some(_), _) => "let through by break-glass".to_string(),
        (None, n) if !notes.is_empty() => format!("read the notes: {n}"),
        (None, 0) => "nothing to read".to_string(),
        (None, 1) => "1 thing holds this change back".to_string(),
        (None, n) => format!("{n} things hold this change back"),
    };
    let org_note = org.map(|o| format!("   org policy: {o}")).unwrap_or_default();
    out.raw(&format!("{} {}  {}{}", ui.paint(tone, ui.glyph(glyph)), ui.paint(tone, word), summary, ui.paint(Tone::Dim, &org_note)));
    if let Some(b) = &g.bypass {
        for line in ui.wrap(&format!("by {} until {}: \"{}\"  (overrode: {})", b.by.name, b.expires, b.reason, b.suppressed.join(", ")), ui.width.saturating_sub(2)) {
            out.raw(&format!("  {}", ui.paint(Tone::Warn, &line)));
        }
    }
    for (i, f) in blockers.iter().enumerate() {
        for (j, line) in ui.wrap(&f.message, ui.width.saturating_sub(6)).iter().enumerate() {
            out.raw(&format!("  {} {line}", if j == 0 { format!("{}.", i + 1) } else { "  ".into() }));
        }
        if let Some(next) = &f.next {
            out.raw(&format!("     {} {}", ui.paint(Tone::Info, "→"), ui.wrap(next, ui.width.saturating_sub(9)).join(" ")));
        }
    }
    out.finish()
}

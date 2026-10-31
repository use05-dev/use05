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
    let ctx = match Ctx::open(repo, task) {
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
    let brief = build(ctx.task.as_ref(), gate, &target.oid, &target.label, target.base_commit.as_deref(), target.head_commit.as_deref());
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "v": 1, "command": "brief", "decision": decision.word(), "label": brief.label, "brief": brief, "overlap": overlaps })).expect("brief serialises"));
    } else {
        print!("{}", render(&Ui::stdout(), &brief, ctx.org.as_deref(), &overlaps));
    }
    ExitCode::from(decision.exit_code())
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
    intent.push(Item { glyph: None, text: format!("risk   {}", ui.paint(risk_tone, b.risk.word())), dim: false });
    for r in &b.gate.risk_reasons {
        let shown: Vec<&str> = r.paths.iter().take(3).map(String::as_str).collect();
        let more = if r.paths.len() > 3 { format!(" and {} more", r.paths.len() - 3) } else { String::new() };
        intent.push(Item::dim(format!("       {}: {}{more}", r.category, shown.join(", "))));
    }
    out.section("Intent", intent);
    out.blank();

    // Outcome
    let n = b.gate.changed.len();
    let mut outcome = vec![Item::plain(format!("{n} file{} changed on {}  ({})", if n == 1 { "" } else { "s" }, &b.tree[..12.min(b.tree.len())], b.tree_label))];
    if !b.areas.is_empty() {
        outcome.push(Item::dim(b.areas.iter().take(6).map(|(a, c)| format!("{a} ({c})")).collect::<Vec<_>>().join("  ")));
    }
    for p in b.outside_scope.iter().take(5) {
        outcome.push(Item::new(Glyph::Warn, Tone::Warn, format!("outside scope: {p}")));
    }
    if b.outside_scope.len() > 5 {
        outcome.push(Item::dim(format!("…and {} more outside scope", b.outside_scope.len() - 5)));
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

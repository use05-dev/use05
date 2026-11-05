use std::path::Path;
use std::process::ExitCode;

use use05_core::brief::{Brief, Label, build};
use use05_core::gate::{CheckState, Decision, Effect, Finding};
use use05_core::claims::Judged;
use use05_core::policy::{Role, Target};
use use05_receipt::{Decision as Vote, Status};

use crate::ctx::Ctx;
use crate::report::{Report, command_text, duration, emit};
use crate::ui::{Glyph, Item, Out, Tone, Ui};

pub fn run(repo: &Path, task: Option<&str>, tree: Option<&str>, rev: Option<&str>, fetch: bool, json: bool) -> ExitCode {
    let fail = |e| emit(&Report::from_core("brief", e), json);
    let fetch_receipts = |top: &Path| {
        if fetch {
            if let Err(e) = use05_core::store::fetch(top) {
                eprintln!("05: {} Showing the receipts this machine already has.", e.message);
            }
        }
    };
    let (ctx, target) = match rev {
        // Someone else's work, measured exactly as `approve --rev` measures what it signs.
        Some(rev) => {
            if let Ok(d) = use05_core::git::dirs(repo) {
                fetch_receipts(&d.top);
            }
            match Ctx::open_rev(repo, rev) {
                Ok(opened) => opened,
                Err(e) => return fail(e),
            }
        }
        None => {
            // A named task is looked at where its work is, not wherever this was run.
            let (repo, located) = if tree.is_none() { crate::pending::locate(repo, task, None) } else { (repo.to_path_buf(), None) };
            let tree = tree.or(located.as_deref());
            let ctx = match Ctx::open_judging(&repo, task) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            fetch_receipts(ctx.top());
            match ctx.target(tree) {
                Ok(t) => (ctx, t),
                Err(e) => return fail(e),
            }
        }
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
    // Where the tests come from (S4): read here, on demand, never in the hooks.
    brief.read_test_origin(ctx.top(), &ctx.policy);
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

/// `use05 brief --promote <env>`: the one page for a promotion (D93): what moves, each rule with
/// its result, who must sign, and the next command. Read-only, as `promote --check` is.
pub fn run_promote(repo: &Path, env: &str, json: bool) -> ExitCode {
    // A destination's page is the same page (D93).
    if crate::cmd::destination::named(repo, env).is_some() {
        return match crate::cmd::destination::prepare(repo, env) {
            Ok((p, _)) => promote_page(&p, json),
            Err(r) => emit(&r, json),
        };
    }
    match crate::cmd::promote::prepare(repo, env) {
        Ok(p) => promote_page(&p, json),
        Err(r) => emit(&r, json),
    }
}

fn promote_page<T: Target>(p: &crate::cmd::promote::Prepared<T>, json: bool) -> ExitCode {
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "v": 1, "command": "brief", "decision": p.result.decision.word(), "promotion": crate::cmd::promote::details(p) })).expect("brief serialises"));
    } else {
        print!("{}", render_promote(&Ui::stdout(), p));
    }
    ExitCode::from(p.result.decision.exit_code())
}

pub fn render_promote<T: Target>(ui: &Ui, p: &crate::cmd::promote::Prepared<T>) -> String {
    use use05_core::promote::short;
    use use05_receipt::{RuleOutcome, RuleSeverity};
    let r = &p.result;
    let mut out = Out::new(ui, 9);
    out.title(&format!("Promote  {} → {}", r.source_env, r.target_env), &format!("{} at {}", r.source_env, short(&r.source_head)));

    // What moves
    let mut moves = vec![Item::plain(crate::cmd::promote::summary(p))];
    let onto = match (&r.target_head, &p.target_ref) {
        (Some(t), Some(at)) => format!("onto {} at {} ({at})", r.target_env, short(t)),
        _ => format!("creating {}", r.target_env),
    };
    moves.push(Item::dim(format!("{} ({}) {onto}, by {}", short(&r.source_head), p.source_ref, r.how)));
    let counted: Vec<(&str, u64, u64)> = r.changed.iter().map(|f| {
        let (a, d) = p.numstat.get(f).copied().unwrap_or((0, 0));
        (f.as_str(), a, d)
    }).collect();
    for a in use05_core::brief::areas(&counted, 8) {
        moves.push(Item::dim(format!("{} · {} · +{} −{}", a.name, files(a.files), thousands(a.added), thousands(a.removed))));
    }
    // The files that move, most lines changed first.
    let mut by_size = counted.clone();
    by_size.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)).then(a.0.cmp(b.0)));
    for (f, a, d) in by_size.iter().take(8) {
        moves.push(Item::dim(format!("{f} · +{a} −{d}")));
    }
    if by_size.len() > 8 {
        moves.push(Item::dim(format!("and {} more", files(by_size.len() - 8))));
    }
    for c in p.moving.iter().rev().take(6) {
        moves.push(Item::dim(format!("{}  {}", short(&c.id), c.subject)));
    }
    if p.moving.len() > 6 {
        moves.push(Item::dim(format!("and {} earlier commit{}", p.moving.len() - 6, if p.moving.len() == 7 { "" } else { "s" })));
    }
    for n in &p.notes {
        moves.push(Item::new(Glyph::Warn, Tone::Warn, n.clone()));
    }
    out.section("Moves", moves);
    out.blank();

    // Each rule
    let mut rules = vec![Item::dim(format!("from {}", p.rules_from))];
    for rule in &r.rules {
        let severity = format!("{:?}", rule.severity).to_lowercase();
        let text = format!("{}: {} ({severity})", rule.rule, rule.detail);
        rules.push(match (rule.outcome, rule.severity) {
            (RuleOutcome::Pass, _) => Item::new(Glyph::Ok, Tone::Good, text),
            (RuleOutcome::Skipped | RuleOutcome::Unknown, _) | (RuleOutcome::Fail, RuleSeverity::Allow) => Item::new(Glyph::Dot, Tone::Dim, text),
            (RuleOutcome::Bypassed, _) => Item::new(Glyph::Warn, Tone::Warn, format!("{text}, bypassed")),
            (RuleOutcome::Fail, RuleSeverity::Deny) => Item::new(Glyph::Bad, Tone::Bad, text),
            (RuleOutcome::Fail, _) => Item::new(Glyph::Warn, Tone::Warn, text),
        });
    }
    // Each rule's own finding is its line above; every other one (built in, where the rules came
    // from, a receipt that does not match) is listed here.
    let rule_codes = ["SOURCE_CHECKS_MISSING", "SOURCE_NOT_CONFIRMED", "SOAK_NOT_DONE", "MIGRATIONS_IN_DELTA", "UNTASKED_COMMITS", "SIGNOFF_REQUIRED", "SIGNOFF_REJECTED"];
    for f in r.findings.iter().filter(|f| !rule_codes.contains(&f.code)) {
        rules.push(effect_item(f));
    }
    out.section("Rules", rules);
    out.blank();

    // Who must sign
    let needed = r.rules.iter().find(|x| x.rule == "sign_off").is_some_and(|x| x.outcome != RuleOutcome::Skipped) || r.findings.iter().any(|f| f.effect == Effect::Approval);
    let who = if r.signers.is_empty() { "a person with an approver key".to_string() } else { r.signers.join(" or ") };
    let mut sign = vec![if needed { Item::plain(format!("needed from {who}")) } else { Item::dim(format!("not needed; {who} may sign off")) }];
    for q in &p.questions {
        sign.push(Item::dim(format!("asks: {q}")));
    }
    for c in &p.confirm {
        sign.push(Item::dim(format!("confirms: {c}")));
    }
    for s in &r.signoffs {
        let what = if s.decision == Vote::Approve { "signed off" } else { "rejected it" };
        sign.push(match &s.void {
            Some(why) => Item::new(Glyph::Dot, Tone::Dim, format!("{} {what}: \"{}\" (does not count: {why})", s.person, s.text)),
            None if s.decision == Vote::Approve => Item::new(Glyph::Ok, Tone::Good, format!("{} {what}: \"{}\"", s.person, s.text)),
            None => Item::new(Glyph::Bad, Tone::Bad, format!("{} {what}: \"{}\"", s.person, s.text)),
        });
    }
    out.section("Sign-off", sign);
    out.blank();

    out.section("Rollback", vec![match &r.rollback_point {
        _ if p.env.is_destination() => Item::dim(format!("none: 05 never rolls {} back; promote a fix to it", r.target_env)),
        Some(c) => Item::plain(format!("back to {} if the deploy fails", short(c))),
        None => Item::dim(format!("none: {} is created by this promotion", r.target_env)),
    }]);
    out.blank();
    for line in ui.wrap(&crate::cmd::promote::strength(p), ui.width) {
        out.raw(&ui.paint(Tone::Dim, &line));
    }
    out.raw(&ui.rule(ui.width));

    // Decision
    let (word, tone) = crate::cmd::promote::verdict(r);
    let glyph = match r.decision {
        Decision::Allow => Glyph::Ok,
        Decision::Wait => Glyph::Pending,
        Decision::ApprovalRequired => Glyph::Warn,
        Decision::Deny => Glyph::Bad,
    };
    let blockers: Vec<&Finding> = r.findings.iter().filter(|f| f.effect >= Effect::Wait).collect();
    let org_note = p.org.as_deref().map(|o| format!("   org policy: {o}")).unwrap_or_default();
    out.raw(&format!("{} {}{}", ui.paint(tone, ui.glyph(glyph)), ui.paint(tone, &word.to_uppercase()), ui.paint(Tone::Dim, &org_note)));
    for (i, f) in blockers.iter().enumerate() {
        for (j, line) in ui.wrap(&f.message, ui.width.saturating_sub(6)).iter().enumerate() {
            out.raw(&format!("  {} {line}", if j == 0 { format!("{}.", i + 1) } else { "  ".into() }));
        }
        if let Some(next) = &f.next {
            out.raw(&format!("     {} {}", ui.paint(Tone::Info, "→"), ui.wrap(next, ui.width.saturating_sub(9)).join(" ")));
        }
    }
    if blockers.is_empty() {
        if let Some(next) = crate::cmd::promote::next_step(r) {
            out.raw(&format!("  {} {next}", ui.paint(Tone::Info, "→")));
        }
    }
    out.finish()
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

/// The story's lines (D102). Each begins with where it comes from: the person, the agent (its own
/// words, never shown as fact), 05 itself, the checks, what holds it, what nobody established.
fn story_items(s: &use05_core::brief::Story) -> Vec<Item> {
    let mut items = Vec::new();
    match &s.asked {
        Some(a) => items.push(Item::plain(format!("asked: \"{a}\""))),
        None => items.push(Item::dim("asked: not recorded")),
    }
    match &s.agent_says {
        Some(a) => items.push(Item::plain(format!("agent says: \"{a}\" (its own words)"))),
        None => items.push(Item::dim("agent says: nothing yet")),
    }
    let c = &s.claim_counts;
    if c.supported + c.unsupported + c.contradicted > 0 {
        let mut parts = Vec::new();
        if c.contradicted > 0 {
            parts.push(format!("{} contradicted by a check", c.contradicted));
        }
        if c.supported > 0 {
            parts.push(format!("{} backed by a check", c.supported));
        }
        if c.unsupported > 0 {
            parts.push(format!("{} with no check of its kind", c.unsupported));
        }
        let item = format!("agent's claims: {}", parts.join(", "));
        items.push(if c.contradicted > 0 { Item::new(Glyph::Bad, Tone::Bad, item) } else { Item::dim(item) });
    }
    for o in &s.observed {
        items.push(Item::plain(format!("05 saw: {o}")));
    }
    items.push(Item::plain(format!("checked: {}", s.checked)));
    for n in &s.needs_you {
        items.push(Item::new(Glyph::Warn, Tone::Warn, format!("needs you: {n}")));
    }
    items.push(Item::dim(format!("not known: {}", s.not_known.join("; "))));
    items
}

pub fn render(ui: &Ui, b: &Brief, org: Option<&str>, overlaps: &[use05_core::overlap::Overlap]) -> String {
    let mut out = Out::new(ui, 9);
    let right = match &b.task_id {
        Some(id) => format!("task {id}"),
        None => "no task".to_string(),
    };
    out.title(&format!("Brief  {}", b.title), &right);

    // The story first (D102): a few lines, each saying where it comes from. The sections below
    // are the detail.
    out.section("Story", story_items(&b.story));
    out.blank();

    // Intent
    let mut intent = Vec::new();
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
            CheckState::NotRequired { reason, result } => {
                // Never blocking. A receipt for it, made anyway, is shown but does not count.
                let seen = result.as_ref().map(|r| {
                    let said = match r.status {
                        Status::Passed => format!("passed in {}", duration(r.ms)),
                        Status::Failed => "failed".to_string(),
                        Status::TimedOut => "timed out".to_string(),
                    };
                    format!(" (a receipt says it {said}, {}; not counted)", who(&r.by))
                });
                Item::dim(format!("{:<10} not required: {reason}{}", c.name, seen.unwrap_or_default()))
            }
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
            // An owner's approval of someone else's work counts for what they own, and only that.
            Some(_) if !a.owner_of.is_empty() => Item::new(Glyph::Ok, Tone::Good, format!("{} {what}: counts for {} only (an owner's approval)", a.by.name, a.owner_of.join("; "))),
            Some(why) => Item::new(Glyph::Dot, Tone::Dim, format!("{} {what}: no longer counts ({why})", a.by.name)),
            None if a.vote == Vote::Approve => Item::new(Glyph::Ok, Tone::Good, format!("{} {what}: \"{}\"", a.by.name, a.rationale)),
            None => Item::new(Glyph::Bad, Tone::Bad, format!("{} {what}: \"{}\"", a.by.name, a.rationale)),
        }
    }).collect();
    out.section("Approvals", if approvals.is_empty() { vec![Item::dim("none")] } else { approvals });
    // Path owners (D92): who owns what this change touches, and which of them approved it.
    if !b.gate.owners.is_empty() {
        let owners: Vec<Item> = b.gate.owners.iter().map(|o| {
            let by = if o.approved_by.is_empty() { "nobody yet".to_string() } else { format!("approved by {}", o.approved_by.join(", ")) };
            let text = format!("{} owned by {}: {} of {}, {by}", o.paths.join(", "), o.named(), o.counted(), o.min);
            if o.met { Item::new(Glyph::Ok, Tone::Good, text) } else { Item::new(Glyph::Warn, Tone::Warn, text) }
        }).collect();
        out.blank();
        out.section("Owners", owners);
    }
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
    // How much the verdict rests on (D101), beside it: what the checks did, whether the change
    // grades its own tests, and what nobody assessed. Not a score, so never in a tone of approval.
    // Kept apart from numbered reasons, so it is not read as one of them.
    if !blockers.is_empty() || g.bypass.is_some() {
        out.blank();
    }
    for line in b.assurance.lines() {
        let tone = if line.starts_with("Note:") { Tone::Warn } else if line.starts_with("Behaviour") { Tone::Dim } else { Tone::Plain };
        for (j, part) in ui.wrap(&line, ui.width.saturating_sub(4)).iter().enumerate() {
            out.raw(&format!("  {}{}", if j == 0 { "" } else { "  " }, ui.paint(tone, part)));
        }
    }
    out.finish()
}

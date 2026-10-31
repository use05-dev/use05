use std::path::PathBuf;

use serde_json::json;
use use05_core::inbox;
use use05_core::intent::{IntentCard, Risk, Scope};
use use05_core::policy::{IntentMode, Severity};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

pub struct Args {
    pub title: String,
    pub goal: Option<String>,
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub check: Vec<String>,
    pub no_new_deps: bool,
    pub card: Option<PathBuf>,
    pub session: Option<String>,
    pub repo: PathBuf,
}

/// Sign the task's sealed declaration with this machine's key and keep it with the receipts, so
/// it travels to CI (D65). The person's request is never included. Best effort: a failure is
/// logged, never fatal.

/// `--scope "src/** docs/**"` or `--scope src/**,docs/**` is several patterns, as agents write
/// them. A path with a space in it is written with `?` or `*` for the space.
fn patterns(values: &[String]) -> Vec<String> {
    values.iter().flat_map(|v| v.split(|c: char| c == ',' || c.is_whitespace())).filter(|p| !p.is_empty()).map(str::to_string).collect()
}
pub fn publish_declaration(ctx: &Ctx, task: &use05_core::task::Task) {
    let (Some(card), Some(digest)) = (&task.intent, &task.intent_sha256) else { return };
    let predicate = use05_receipt::Declaration {
        task: task.id.clone(),
        title: task.title.clone(),
        author: task.author.clone(),
        card: serde_json::to_value(card).unwrap_or_default(),
        sealed: task.sealed.clone().unwrap_or_else(|| task.created.clone()),
        policy_sha256: ctx.policy.digest(),
        agent: task.agent.as_ref().map(|a| use05_receipt::AgentRef { kind: a.kind.clone(), session: a.session.clone(), model: a.model.clone() }),
        owner: task.owner.as_ref().map(|o| use05_receipt::OwnerRef { name: o.name.clone(), key_id: o.key_id.clone() }),
        sandbox: task.sandbox.clone(),
    };
    let statement = use05_receipt::Statement::new(vec![use05_receipt::intent_subject(digest)], predicate);
    sign_and_store(ctx, task, digest, &statement);
    crate::extend::emit("sealed", ctx.top(), json!({ "task": task.id, "agent": agent_kind(task), "intent_sha256": digest }));
}

fn agent_kind(task: &use05_core::task::Task) -> Option<&str> {
    task.agent.as_ref().map(|a| a.kind.as_str()).or_else(|| task.author.strip_prefix("agent:"))
}

/// Sign what the author said they did, for the tree they finished on.
pub fn publish_completion(ctx: &Ctx, task: &use05_core::task::Task) {
    let Ok(target) = ctx.target(None) else { return };
    let predicate = use05_receipt::Completion { task: task.id.clone(), outcome: task.outcome.clone().unwrap_or_default(), finished: task.finished.clone().unwrap_or_else(use05_core::time::now_rfc3339) };
    let statement = use05_receipt::Statement::new(vec![use05_receipt::tree_subject(&target.oid, &target.digest)], predicate);
    sign_and_store(ctx, task, &target.oid, &statement);
    crate::extend::emit("finished", ctx.top(), json!({ "task": task.id, "agent": agent_kind(task), "tree": target.oid }));
}

/// Seal the task's action log where it stands (D70): keep a copy on the receipts branch and sign
/// its position and chain hash with this machine's key. From here on, any edit to the lines it
/// covers no longer verifies. Best effort, like the other records.
pub fn publish_log_seal(ctx: &Ctx, task: &use05_core::task::Task, copy: bool) {
    // Recording off means no log, and nothing about it leaves this machine (D7).
    if ctx.policy.record.middle != use05_core::policy::Middle::Local {
        return;
    }
    let state = ctx.store.state_dir();
    let Some((seq, head)) = use05_core::log::head(&state, &task.id) else { return };
    let Ok(text) = std::fs::read(use05_core::log::path_for(&state, &task.id)) else { return };
    let result = use05_core::keys::ensure_local().and_then(|(key, _)| {
        let signer = use05_receipt::key_id(&key.verifying_key());
        // The copy travels at declarations and finishes; a stop only seals, so a long session does
        // not push a new copy of the whole log every turn.
        if copy {
            use05_core::store::put_file(ctx.top(), &format!("logs/{}.jsonl", task.id), &text, &signer)?;
        }
        let predicate = use05_receipt::LogSeal { task: task.id.clone(), seq, head: head.clone(), created: use05_core::time::now_rfc3339() };
        let statement = use05_receipt::Statement::new(vec![use05_receipt::log_subject(&task.id, &head)], predicate);
        let envelope = use05_receipt::seal(&statement, &key).to_json_bytes();
        use05_core::store::put(ctx.top(), &task.id, &envelope, &signer)
    });
    if let Err(e) = result {
        let _ = use05_core::log::append(&state, &task.id, json!({ "event": "publish_failed", "why": e.message }));
    }
}

fn sign_and_store<P: use05_receipt::Predicate>(ctx: &Ctx, task: &use05_core::task::Task, subject: &str, statement: &use05_receipt::Statement<P>) {
    let result = use05_core::keys::ensure_local().and_then(|(key, _)| {
        let envelope = use05_receipt::seal(statement, &key).to_json_bytes();
        use05_core::store::put(ctx.top(), subject, &envelope, &use05_receipt::key_id(&key.verifying_key()))
    });
    if let Err(e) = result {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "publish_failed", "why": e.message }));
    }
}

/// A `start` with no agent session behind it: 05 cannot tell who ran it (D67).
pub const UNVERIFIED: &str = "unverified";

/// How an author is shown to a person.
pub fn author_label(author: &str) -> String {
    if author == UNVERIFIED { "unverified (made at this machine)".to_string() } else { author.to_string() }
}

/// The agent session this process runs in, if that agent's hooks are installed here. Only then
/// is there a hook to seal what this process leaves in the inbox. A generic agent's hooks cannot
/// be inspected; it setting `USE05_SESSION_ID` is its statement that they are wired (D73).
fn hooked_session(top: &std::path::Path) -> Option<(String, String)> {
    let (agent, session) = inbox::agent_session()?;
    let setup = crate::cmd::init::inspect(top);
    let installed = match agent.as_str() {
        "codex" => setup.codex_hooks,
        "claude-code" => setup.claude_hooks,
        "generic" => true,
        _ => false,
    };
    installed.then_some((agent, session))
}

fn leave_in_inbox(command: &'static str, top: &std::path::Path, agent: String, session: String, entry: inbox::Entry, title: &str) -> Report {
    // What this (the agent's) process says about its sandbox; recorded as the agent's own report.
    let sandbox = std::env::var("CODEX_SANDBOX").ok().filter(|v| !v.trim().is_empty()).map(|v| format!("codex:{v}"));
    let pending = inbox::Pending { id: match use05_core::task::random_id() { Ok(i) => i, Err(e) => return Report::from_core(command, e) }, agent: agent.clone(), session, created: use05_core::time::now_rfc3339(), entry, sandbox };
    if let Err(e) = inbox::put(top, &pending) {
        return Report::from_core(command, e);
    }
    let (code, headline) = if command == "start" { ("TASK_DECLARED", format!("Declared: {title}")) } else { ("TASK_FINISH_DECLARED", "Declared what was done".to_string()) };
    Report {
        command,
        outcome: "declared",
        code,
        tone: Tone::Good,
        headline,
        rows: vec![("by".to_string(), format!("agent:{agent} (this session)"))],
        notes: vec![if command == "start" { "05 seals it before your next edit; until then it waits in .05/inbox.".into() } else { "05 records it, and checks your change when you stop; the person reads the brief.".into() }],
        next: if command == "start" { Some("do the work, then: use05 finish --outcome \"<what you did>\"".into()) } else { None },
        excerpt: vec![],
        details: json!({ "pending": pending.id, "session": pending.session, "agent": agent }),
        exit: 0,
    }
}

pub fn run(args: Args) -> Report {
    if args.title.trim().is_empty() {
        return Report::error("start", "TITLE_EMPTY", "say what you are about to do, in a few words".into(), Some("use05 start \"Cap payment retries\"".into()), 6);
    }
    let ctx = match Ctx::open(&args.repo, None) {
        Ok(c) => c,
        Err(e) => return Report::from_core("start", e),
    };

    let card = if let Some(path) = &args.card {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => return Report::error("start", "CARD_UNREADABLE", format!("cannot read {}: {e}", path.display()), None, 6),
        };
        match IntentCard::parse(&text) {
            Ok(mut c) => {
                if c.title.is_empty() {
                    c.title = args.title.clone();
                }
                Some(c)
            }
            Err(e) => return Report::from_core("start", e),
        }
    } else if !args.scope.is_empty() || !args.exclude.is_empty() || !args.check.is_empty() || args.goal.is_some() || args.no_new_deps {
        Some(IntentCard {
            title: args.title.clone(),
            goal: args.goal.clone().unwrap_or_default(),
            scope: Scope { include: patterns(&args.scope), exclude: patterns(&args.exclude) },
            acceptance: args.check.clone(),
            no_new_dependencies: args.no_new_deps,
            ..IntentCard::default()
        })
    } else {
        None
    };

    // Acceptance checks must exist in the policy, or the card promises something nobody can run.
    if let Some(card) = &card {
        for name in &card.acceptance {
            if ctx.policy.check_named(name).is_none() {
                let known = ctx.policy.check.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ");
                return Report::error("start", "CHECK_UNDEFINED", format!("the policy defines no check named {name:?}"), Some(if known.is_empty() { "define it in .05/policy.toml first".into() } else { format!("defined checks: {known}") }), 6);
            }
        }
    }

    let risk = card.as_ref().map(|c| c.risk(&ctx.policy)).unwrap_or(Risk::Low);
    // Only "always" can be enforced here. "risky" is judged once there is a change to measure,
    // and the gate asks for a card then.
    if card.is_none() && ctx.policy.intent.mode == IntentMode::Always {
        return Report::error(
            "start",
            "INTENT_REQUIRED",
            "policy requires an intent card for every task in this repository".to_string(),
            Some("give one: use05 start \"<what you are doing>\" --scope \"src/**\" --check test".into()),
            2,
        );
    }

    if let Some((agent, session)) = hooked_session(ctx.top()) {
        return leave_in_inbox("start", ctx.top(), agent, session, inbox::Entry::Start { title: args.title.clone(), card }, args.title.trim());
    }

    // Another task already holds part of this scope (D64).
    let mut overlap_note = None;
    if let Some(c) = card.as_ref().filter(|c| c.has_scope()) {
        let res = use05_core::overlap::reservations(&ctx.store, "", ctx.policy.drift.reservation_idle_hours as u64 * 3600, use05_core::time::now_secs());
        if let Some((r, area)) = use05_core::overlap::conflicts(&res, &c.scope.include).first() {
            let said = r.describe(area);
            match ctx.policy.drift.overlap {
                Severity::Deny => return Report::error("start", "OVERLAP", format!("{said}; this declaration was not made"), Some("narrow --scope, or wait for that task to finish".into()), 2),
                Severity::Allow => {}
                _ => overlap_note = Some(format!("{said}. Narrow --scope, or wait.")),
            }
        }
    }

    let task = match ctx.store.create(&args.title, UNVERIFIED, card.clone(), args.session.as_deref()) {
        Ok(t) => t,
        Err(e) => return Report::from_core("start", e),
    };
    let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "start", "title": task.title, "author": task.author }));
    let mut task = task;
    task.owner = use05_core::task::local_owner(ctx.top());
    let _ = ctx.store.save(&task);
    if task.intent.is_some() {
        task.sealed = Some(task.created.clone());
        let _ = ctx.store.save(&task);
        publish_declaration(&ctx, &task);
        publish_log_seal(&ctx, &task, true);
    }

    let mut rows = vec![
        ("task".to_string(), format!("{}  by {}", task.id, author_label(&task.author))),
        ("from".to_string(), task.base_commit.as_deref().map(|c| c.chars().take(10).collect::<String>()).unwrap_or_else(|| "no commits yet".into())),
    ];
    match &card {
        Some(c) => {
            if let Some(goal) = Some(&c.goal).filter(|g| !g.is_empty()) {
                rows.push(("goal".into(), goal.clone()));
            }
            rows.push(("scope".into(), if c.has_scope() { c.scope.include.join(", ") } else { "not declared".into() }));
            if !c.scope.exclude.is_empty() {
                rows.push(("not".into(), c.scope.exclude.join(", ")));
            }
            if !c.acceptance.is_empty() {
                rows.push(("checks".into(), c.acceptance.join(", ")));
            }
            rows.push(("risk".into(), risk.word().to_string()));
        }
        None => rows.push(("intent".into(), "inferred (no card); scope drift cannot be checked".into())),
    }

    let next = if risk == Risk::High && card.is_some() {
        "this reaches a protected area. Ask a person to approve the intent first: use05 approve --intent"
    } else {
        "do the work, then: use05 prove   and   use05 brief"
    };
    Report {
        command: "start",
        outcome: "started",
        code: "TASK_STARTED",
        tone: Tone::Good,
        headline: format!("Started: {}", task.title),
        rows,
        notes: overlap_note.into_iter().collect(),
        next: Some(next.into()),
        excerpt: vec![],
        details: json!({ "task": task.id, "author": task.author, "base_commit": task.base_commit, "risk": risk, "intent_sha256": task.intent_sha256, "card": card }),
        exit: 0,
    }
}

/// `use05 finish`: record what the author says they did. An assertion until evidence supports it.
pub fn finish(repo: &std::path::Path, task_id: Option<&str>, outcome: Option<&str>) -> Report {
    let ctx = match Ctx::open(repo, task_id) {
        Ok(c) => c,
        Err(e) => return Report::from_core("finish", e),
    };
    if task_id.is_none() {
        if let Some((agent, session)) = hooked_session(ctx.top()) {
            return leave_in_inbox("finish", ctx.top(), agent, session, inbox::Entry::Finish { outcome: outcome.map(str::to_string) }, "");
        }
    }
    let Some(mut task) = ctx.task.clone() else {
        return Report::error("finish", "NO_TASK", "there is no current task to finish".into(), Some("start one: use05 start \"what you are doing\"".into()), 6);
    };
    if let Err(e) = ctx.store.finish(&mut task, outcome) {
        return Report::from_core("finish", e);
    }
    let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "finish", "has_outcome": task.outcome.is_some() }));
    publish_completion(&ctx, &task);
    publish_log_seal(&ctx, &task, true);
    let claims = task.outcome.as_deref().map(use05_core::claims::extract).unwrap_or_default();
    let mut rows = vec![("task".to_string(), format!("{}  {}", task.id, task.title))];
    rows.push((
        "claims".into(),
        if claims.is_empty() { "none that 05 can check".into() } else { claims.iter().map(|c| format!("\"{}\" ({})", c.text, c.category.word())).collect::<Vec<_>>().join("; ") },
    ));
    Report {
        command: "finish",
        outcome: "finished",
        code: "TASK_FINISHED",
        tone: Tone::Good,
        headline: format!("Finished: {}", task.title),
        rows,
        notes: vec!["The outcome is the author's statement, not a fact. Only checks 05 ran on the exact tree count.".into()],
        next: Some("use05 brief".into()),
        excerpt: vec![],
        details: json!({ "task": task.id, "claims": claims.len() }),
        exit: 0,
    }
}

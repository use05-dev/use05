//! `use05 discard`: throw a task's abandoned work away (D89). It shows what would be lost first:
//! commits that exist nowhere else and files never committed. A person confirms at a terminal,
//! or signs with a passkey what this machine prepared (from the console); an agent can do neither.

use std::path::Path;
use std::time::Duration;

use serde_json::json;
use use05_core::discard::{self, Plan};
use use05_core::task::{Status, Task};
use use05_receipt::{Discard, Envelope, Statement, work_subject};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

/// How long origin has to delete the branch there.
const REMOTE_TIMEOUT: Duration = Duration::from_secs(20);

pub fn run(repo: &Path, task: Option<&str>, unsigned: bool, signed: Option<&Path>) -> Report {
    let ctx = match Ctx::open(repo, None) {
        Ok(c) => c,
        Err(e) => return Report::from_core("discard", e),
    };
    if let Some(file) = signed {
        return run_signed(&ctx, file);
    }
    let Some(id) = task else {
        return Report::error("discard", "NO_TASK", "say which task's work to discard".into(), Some("use05 discard <task id>".into()), 6);
    };
    let task = match discard::find(&ctx.store, id) {
        Ok(t) => t,
        Err(e) => return Report::from_core("discard", e),
    };
    if task.status == Status::Discarded {
        return already(&task);
    }
    let plan = match discard::plan(&ctx.store, &ctx.policy, &task) {
        Ok(p) => p,
        Err(e) => return Report::from_core("discard", e),
    };
    if unsigned {
        return prepared(&ctx, &task, &plan);
    }
    // A person at a terminal, who has seen what would be lost. An agent's shell has none.
    if !use05_core::tty::has_tty() {
        return Report::error(
            "discard",
            "NEEDS_A_PERSON",
            "discarding work needs a person: run it at a terminal, or from your console with your passkey".into(),
            None,
            6,
        );
    }
    let mut screen = format!("Discard \"{}\" (task {})?\n", task.title, task.id);
    for (k, v) in rows(&plan) {
        screen.push_str(&format!("  {k:<10} {v}\n"));
    }
    screen.push_str("This cannot be undone. Discard it? [y/N] ");
    match use05_core::tty::ask(&screen) {
        Ok(a) if matches!(a.trim(), "y" | "Y" | "yes") => {}
        _ => return Report::error("discard", "KEPT", "nothing was discarded".into(), None, 1),
    }
    done(&ctx, &task, plan.head.as_deref())
}

/// What a discard would remove, and what would be lost, as rows.
fn rows(plan: &Plan) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if let Some(w) = &plan.worktree {
        rows.push(("worktree".into(), w.display().to_string()));
    }
    match (&plan.branch, &plan.kept) {
        (Some(b), _) => rows.push(("branch".into(), if plan.remote { format!("{b}, here and on origin") } else { b.clone() })),
        (None, Some(k)) => rows.push(("branch".into(), format!("kept: {k}"))),
        _ => {}
    }
    let plural = |n: u32, one: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") };
    let commits = |c: u32| format!("{} that exist{} nowhere else", plural(c, "commit"), if c == 1 { "s" } else { "" });
    let lost = match (plan.unpushed, plan.uncommitted) {
        (0, 0) => "nothing that is not elsewhere".to_string(),
        (c, 0) => commits(c),
        (0, f) => format!("{} never committed", plural(f, "file")),
        (c, f) => format!("{}, and {} never committed", commits(c), plural(f, "file")),
    };
    rows.push(("lost".into(), lost));
    if plan.busy {
        rows.push(("note".into(), "an agent's session is still working on it: stop it first".into()));
    }
    rows
}

fn already(task: &Task) -> Report {
    Report {
        command: "discard",
        outcome: "discarded",
        code: "ALREADY_DISCARDED",
        tone: Tone::Info,
        headline: format!("Task {} was discarded already", task.id),
        rows: vec![],
        notes: vec![],
        next: None,
        excerpt: vec![],
        details: json!({ "task": task.id }),
        exit: 0,
    }
}

/// The statement for someone to sign elsewhere (a passkey, on the console), co-signed here.
fn prepared(ctx: &Ctx, task: &Task, plan: &Plan) -> Report {
    let by = task.owner.as_ref().map(|o| o.name.clone()).or_else(|| use05_core::git::text(ctx.top(), &["config", "user.name"]).ok().map(|n| n.trim().to_string())).unwrap_or_default();
    let d = Discard { task: task.id.clone(), branch: plan.branch.clone(), head: plan.head.clone(), unpushed: plan.unpushed, uncommitted: plan.uncommitted, by, created: use05_core::time::now_rfc3339() };
    let statement = Statement::new(vec![work_subject(&task.id, plan.head.as_deref())], d);
    let body = serde_json::to_vec(&statement).expect("serialises");
    let mut r = super::approve::unsigned_body(&body, &task.id, "", "discard this work", json!({ "task": task.id, "plan": plan, "rows": rows(plan) }));
    r.command = "discard";
    r.next = Some("use05 discard --signed <file>".into());
    r
}

/// A discard signed elsewhere: by a passkey or approver key this machine trusts, of a statement
/// this machine prepared and co-signed, for the work as it still is.
fn run_signed(ctx: &Ctx, file: &Path) -> Report {
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return Report::error("discard", "RECEIPT_NOT_FOUND", format!("cannot read {}: {e}", file.display()), None, 6),
    };
    let Ok(envelope) = serde_json::from_slice::<Envelope>(&bytes) else {
        return Report::error("discard", "RECEIPT_MALFORMED", format!("{} is not a signed envelope", file.display()), None, 6);
    };
    let raw = use05_core::store::Raw { source: file.display().to_string(), path: file.display().to_string(), bytes: envelope.to_json_bytes() };
    let found = use05_core::evidence::classify(&ctx.trust, &[raw]);
    let refuse = |why: String| Report::error("discard", "DISCARD_NOT_TRUSTED", why, Some("prepare it again on this machine, and sign it with a passkey pinned here (use05 cloud enrol)".into()), 2);
    let Some(signed) = found.discards.into_iter().next() else {
        return refuse("no key this machine trusts as an approver signed a discard in it, so nothing was discarded".into());
    };
    // Prepared here: co-signed by this machine's own key, not merely some machine the policy trusts.
    let mine = use05_core::keys::ensure_local().ok().map(|(k, _)| use05_receipt::key_id(&k.verifying_key()));
    if !signed.cosigners.iter().any(|c| Some(&c.key_id) == mine.as_ref()) {
        return refuse("this machine did not prepare it, so nothing was discarded".into());
    }
    let p = &signed.statement.predicate;
    let task = match discard::find(&ctx.store, &p.task) {
        Ok(t) if t.id == p.task => t,
        Ok(_) | Err(_) => return Report::error("discard", "TASK_NOT_FOUND", format!("no task {} in this repository", p.task), None, 6),
    };
    if task.status == Status::Discarded {
        return already(&task);
    }
    if let Some(why) = use05_core::gate::passkey_void_of(&signed.signer, &signed.cosigners, &p.by, &ctx.trust, task.owner.as_ref()) {
        return refuse(format!("it does not count: {why}; nothing was discarded"));
    }
    if signed.statement.work_subject() != Some((p.task.as_str(), p.head.as_deref().unwrap_or(""))) {
        return refuse("what it names is not one piece of work; nothing was discarded".into());
    }
    done(ctx, &task, p.head.as_deref())
}

fn done(ctx: &Ctx, task: &Task, head: Option<&str>) -> Report {
    match discard::apply(&ctx.store, &ctx.policy, task, head, REMOTE_TIMEOUT) {
        Ok(d) => {
            crate::extend::emit("discarded", ctx.top(), json!({ "task": task.id }));
            let mut rows = Vec::new();
            if let Some(w) = &d.worktree {
                rows.push(("worktree".into(), format!("removed {w}")));
            }
            if let Some(b) = &d.branch {
                rows.push(("branch".into(), format!("deleted {b}{}", d.remote.as_ref().map(|r| format!(" and {r}")).unwrap_or_default())));
            }
            Report {
                command: "discard",
                outcome: "discarded",
                code: "DISCARDED",
                tone: if d.notes.is_empty() { Tone::Good } else { Tone::Warn },
                headline: format!("Discarded \"{}\"", task.title),
                rows,
                notes: d.notes.clone(),
                next: None,
                excerpt: vec![],
                details: json!({ "task": task.id, "worktree": d.worktree, "branch": d.branch, "remote": d.remote }),
                exit: 0,
            }
        }
        Err(e) => Report::from_core("discard", e),
    }
}

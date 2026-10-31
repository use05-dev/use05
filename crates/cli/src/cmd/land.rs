//! `use05 land`: move a task's work into its target branch, only when the gate allows it and
//! only as a fast-forward, then clean up the finished working branch and worktree (D69).

use std::path::Path;

use serde_json::json;
use use05_core::branches;
use use05_core::gate::Decision;
use use05_core::task::{Status, Task};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

pub fn run(repo: &Path, task: Option<&str>) -> Report {
    let ctx = match Ctx::open(repo, task) {
        Ok(c) => c,
        Err(e) => return Report::from_core("land", e),
    };
    let Some(task) = ctx.task.clone() else {
        return Report::error("land", "NO_TASK", "there is no current task to land".into(), Some("name one: use05 land --task <id>".into()), 6);
    };
    land_task(&ctx, task)
}

/// Land `task` and tidy up. Also used by the Stop hook when the policy says `land = "auto"`.
pub fn land_task(ctx: &Ctx, mut task: Task) -> Report {
    let top = ctx.top();
    let policy = &ctx.policy;
    let Some(branch) = task.branch.clone() else {
        return Report::error("land", "NO_BRANCH", "this task was not started on a branch, so there is nothing to land".into(), None, 6);
    };
    if branches::is_kept(policy, &branch) {
        return Report::error("land", "KEPT_BRANCH", format!("{branch} is a kept branch; work lands from a working branch onto it"), Some("start the work on a branch of its own".into()), 6);
    }
    let target = branches::target_for(policy, task.intent.as_ref(), top);
    if target == branch {
        return Report::error("land", "SAME_BRANCH", format!("the task's branch is its target, {target}"), None, 6);
    }
    if let Some(dir) = branches::checked_out_at(top, &branch) {
        if !branches::is_committed(&dir) {
            return Report::error("land", "UNCOMMITTED", format!("{branch} has uncommitted changes at {}", dir.display()), Some("commit the work first; only committed work lands".into()), 6);
        }
    }

    // The gate decides, on exactly the commit that would land.
    let Some(head) = use05_core::git::resolve_commit(top, &format!("refs/heads/{branch}")) else {
        return Report::error("land", "BRANCH_NOT_FOUND", format!("there is no branch {branch}"), None, 6);
    };
    let base = use05_core::git::merge_base(top, &format!("refs/heads/{target}"), &head);
    let gate = match ctx.target_from(&head, base.as_deref()).and_then(|t| ctx.gate(&t)) {
        Ok(g) => g,
        Err(e) => return Report::from_core("land", e),
    };
    if gate.decision != Decision::Allow {
        let first = gate.findings.iter().find(|f| f.effect >= use05_core::gate::Effect::Wait);
        return Report::error(
            "land",
            "NOT_ALLOWED",
            format!("the gate holds {branch} back ({}): {}", gate.decision.word().replace('_', " "), first.map(|f| f.message.clone()).unwrap_or_default()),
            first.and_then(|f| f.next.clone()).or(Some("use05 brief".into())),
            gate.decision.exit_code(),
        );
    }

    let landed = match branches::fast_forward(top, &branch, &target, &head) {
        Ok(h) => h,
        Err(e) => {
            let next = e.next.clone();
            return Report::error("land", e.code, e.message, next, 2);
        }
    };
    if task.status == Status::Active {
        let _ = ctx.store.finish(&mut task, None);
    }
    let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "landed", "branch": branch, "target": target, "head": landed }));
    crate::extend::emit("landed", top, json!({ "task": task.id, "branch": branch, "target": target, "head": landed }));

    let removed = branches::tidy(&ctx.store, policy, top, false);
    let mut rows = vec![("landed".to_string(), format!("{branch} → {target} ({})", landed.chars().take(12).collect::<String>()))];
    let mut notes = Vec::new();
    for r in &removed {
        if let Some(w) = &r.worktree {
            rows.push(("removed".into(), format!("worktree {w}")));
        }
        rows.push(("deleted".into(), format!("branch {}", r.branch)));
    }
    if !removed.iter().any(|r| r.branch == branch) && branches::is_work(policy, &branch) {
        notes.push(format!("{branch} stays for now: its agent session is still running, it is checked out where this ran, or its worktree has uncommitted or ignored files. It is cleaned up when its session ends, or remove it yourself."));
    }
    Report {
        command: "land",
        outcome: "landed",
        code: "LANDED",
        tone: Tone::Good,
        headline: format!("Landed: {}", task.title),
        rows,
        notes,
        next: Some(format!("push {target} when you are ready: git push origin {target}")),
        excerpt: vec![],
        details: json!({ "task": task.id, "branch": branch, "target": target, "head": landed, "removed": removed }),
        exit: 0,
    }
}

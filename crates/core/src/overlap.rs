//! Two agents, one repository: who else touched this file lately?
//!
//! Every agent session is its own task, and tasks and their logs live in the repository's shared
//! state directory (shared by all worktrees). Each log records which paths a session edited, never
//! their contents, so a collision can be noticed from the logs alone.

use std::path::Path;

use serde::Serialize;

use crate::task::{Status, Store};
use crate::time::now_secs;
use crate::log;

/// How recent counts as "lately".
pub const WINDOW_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Overlap {
    pub task: String,
    pub title: String,
    pub author: String,
    pub path: String,
    /// When the other session last touched it, RFC 3339.
    pub when: String,
    pub minutes_ago: u64,
}

/// Other active tasks that edited any of `paths` within the window, newest first, one row per
/// (task, path). The caller's own task never counts.
pub fn recent(store: &Store, own_task: &str, paths: &[String], within_secs: u64) -> Vec<Overlap> {
    recent_at(store, own_task, paths, within_secs, now_secs())
}

pub fn recent_at(store: &Store, own_task: &str, paths: &[String], within_secs: u64, now: u64) -> Vec<Overlap> {
    let state: &Path = &store.state_dir();
    let mut found: Vec<(u64, Overlap)> = Vec::new();
    for task in store.list() {
        if task.id == own_task || task.status != Status::Active {
            continue;
        }
        let mut latest: std::collections::BTreeMap<String, (u64, String)> = std::collections::BTreeMap::new();
        for (at, p) in log::edited(state, &task.id) {
            if paths.iter().any(|mine| *mine == p) && now.saturating_sub(at) <= within_secs && latest.get(&p).is_none_or(|(prev, _)| at >= *prev) {
                latest.insert(p, (at, crate::time::rfc3339(at)));
            }
        }
        for (path, (at, when)) in latest {
            found.push((at, Overlap { task: task.id.clone(), title: task.title.clone(), author: task.author.clone(), path, when, minutes_ago: now.saturating_sub(at) / 60 }));
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, o)| o).collect()
}

/// A sealed declaration's scope, held while its task is active and not idle (D64).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Reservation {
    pub task: String,
    pub title: String,
    pub author: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Reservation {
    /// How an agent is told about it.
    pub fn describe(&self, area: &str) -> String {
        format!("{area} is being worked on by task {} ({}): {}", self.task, self.author.trim_start_matches("agent:"), self.title)
    }
}

/// Other active tasks' declared scopes, if they were active within `idle_secs` of `now`.
pub fn reservations(store: &Store, own_task: &str, idle_secs: u64, now: u64) -> Vec<Reservation> {
    let state = store.state_dir();
    store
        .list()
        .into_iter()
        .filter(|t| t.id != own_task && t.status == Status::Active)
        .filter_map(|t| {
            let card = t.intent.as_ref().filter(|c| c.has_scope())?;
            let sealed = t.sealed.as_deref().and_then(crate::time::parse_rfc3339).unwrap_or(0);
            let last = sealed.max(log::last_activity(&state, &t.id));
            (now.saturating_sub(last) <= idle_secs).then(|| Reservation { task: t.id.clone(), title: t.title.clone(), author: t.author.clone(), include: card.scope.include.clone(), exclude: card.scope.exclude.clone() })
        })
        .collect()
}

/// Reservations a declared scope overlaps, with the pattern of theirs it overlaps.
pub fn conflicts<'a>(res: &'a [Reservation], include: &[String]) -> Vec<(&'a Reservation, String)> {
    let mut out = Vec::new();
    for r in res {
        if let Some(theirs) = r.include.iter().find(|theirs| include.iter().any(|mine| crate::glob::overlaps(mine, theirs))) {
            out.push((r, theirs.clone()));
        }
    }
    out
}

/// The reservation a path falls inside, if any.
pub fn reserved<'a>(res: &'a [Reservation], path: &str) -> Option<&'a Reservation> {
    res.iter().find(|r| r.include.iter().any(|p| crate::glob::matches(p, path)) && !r.exclude.iter().any(|p| crate::glob::matches(p, path)))
}

/// Files in `changed` that another task also edited and whose work is not in `base_commit` yet:
/// the other task is still active, or it finished on a branch that has not been merged into the
/// base. A finished task whose branch is gone counts as merged.
pub fn unmerged(store: &Store, top: &Path, own: &crate::task::Task, changed: &[String], base_commit: Option<&str>, idle_secs: u64, now: u64) -> Vec<String> {
    /// Finished work older than this is taken to have landed or been abandoned.
    const FINISHED_WINDOW: u64 = 7 * 24 * 3600;
    let state = store.state_dir();
    let mut out: Vec<String> = Vec::new();
    for t in store.list().into_iter().filter(|t| t.id != own.id) {
        // Work on the same branch is one line of history, not a collision.
        if t.branch.is_some() && t.branch == own.branch {
            continue;
        }
        let pending = match t.status {
            // Only a session that is still busy is in the way.
            Status::Active => now.saturating_sub(log::last_activity(&state, &t.id)) <= idle_secs,
            // Thrown away: in nobody's way.
            Status::Discarded => false,
            // Finished work is in the way until its last commit is in this change's base.
            Status::Finished => {
                let recent = t.finished.as_deref().and_then(crate::time::parse_rfc3339).is_some_and(|f| now.saturating_sub(f) <= FINISHED_WINDOW);
                match (&t.head, base_commit) {
                    (Some(head), Some(base)) if recent => crate::git::run(top, &["merge-base", "--is-ancestor", head, base]).is_err(),
                    _ => false,
                }
            }
        };
        if !pending {
            continue;
        }
        for (_, p) in log::edited(&state, &t.id) {
            if changed.contains(&p) && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).arg(dir.path()).status().unwrap().success());
        dir
    }

    #[test]
    fn only_other_active_tasks_that_touched_the_path_inside_the_window_count() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        let mine = store.create("mine", "agent:a", None, None).unwrap();
        let other = store.create("other", "agent:b", None, None).unwrap();
        let finished = store.create("done", "agent:c", None, None).unwrap();
        for t in [&other, &finished] {
            log::append(&store.state_dir(), &t.id, json!({ "event": "tool_done", "tool": "Edit", "paths": ["a.rs"] })).unwrap();
        }
        log::append(&store.state_dir(), &other.id, json!({ "event": "tool", "tool": "Edit", "paths": ["denied.rs"], "decision": "deny" })).unwrap();
        log::append(&store.state_dir(), &mine.id, json!({ "event": "tool_done", "paths": ["a.rs"] })).unwrap();
        let mut f = store.load(&finished.id).unwrap();
        store.finish(&mut f, None).unwrap();

        let paths = vec!["a.rs".to_string(), "denied.rs".to_string(), "never.rs".to_string()];
        let now = now_secs();
        let hits = recent_at(&store, &mine.id, &paths, 600, now);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!((hits[0].task.as_str(), hits[0].path.as_str()), (other.id.as_str(), "a.rs"));
        assert!(recent_at(&store, &mine.id, &paths, 600, now + 3_600).is_empty(), "an hour later it is outside a ten-minute window");
        assert!(recent_at(&store, &mine.id, &["never.rs".to_string()], 600, now).is_empty());
    }

    fn card(include: &[&str]) -> crate::intent::IntentCard {
        crate::intent::IntentCard { scope: crate::intent::Scope { include: include.iter().map(|s| s.to_string()).collect(), exclude: vec![] }, ..Default::default() }
    }

    #[test]
    fn a_reservation_is_held_while_active_and_lapses_after_the_idle_time() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        let mine = store.create("mine", "agent:a", None, None).unwrap();
        let mut other = store.create("other", "agent:codex", None, None).unwrap();
        store.declare(&mut other, "Cap retries", Some(card(&["src/payments/**"]))).unwrap();
        let _undeclared = store.create("no scope", "agent:b", None, None).unwrap();
        let now = now_secs();
        let held = reservations(&store, &mine.id, 7200, now);
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].describe("src/payments/**"), format!("src/payments/** is being worked on by task {} (codex): Cap retries", other.id));
        assert!(reservations(&store, &mine.id, 7200, now + 3 * 3600).is_empty(), "idle for three hours: lapsed");
        log::append_at(&store.state_dir(), &other.id, json!({ "event": "tool_done", "paths": ["src/payments/a.rs"] }), now + 3 * 3600).unwrap();
        touch(&store, &other.id, now + 3 * 3600);
        assert_eq!(reservations(&store, &mine.id, 7200, now + 3 * 3600 + 60).len(), 1, "activity renews it");
        assert!(reservations(&store, &other.id, 7200, now).is_empty(), "a task never conflicts with itself");
        let mut done = store.load(&other.id).unwrap();
        store.finish(&mut done, None).unwrap();
        assert!(reservations(&store, &mine.id, 7200, now).is_empty(), "a finished task releases its scope");
    }

    /// Activity is read from the log file's time; set it as if the task were active at `secs`.
    fn touch(store: &Store, task: &str, secs: u64) {
        let file = std::fs::File::options().append(true).open(log::path_for(&store.state_dir(), task)).unwrap();
        file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)).unwrap();
    }

    fn on_branch(store: &Store, t: &crate::task::Task, branch: &str) -> crate::task::Task {
        let mut t = store.load(&t.id).unwrap();
        t.branch = Some(branch.into());
        store.save(&t).unwrap();
        t
    }

    fn committed_repo() -> tempfile::TempDir {
        let dir = repo();
        let git = |args: &[&str]| assert!(std::process::Command::new("git").arg("-C").arg(dir.path()).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap().status.success());
        std::fs::write(dir.path().join("a.txt"), "1\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "c"]);
        dir
    }

    #[test]
    fn finished_work_already_in_the_base_and_idle_sessions_are_not_overlaps() {
        let dir = committed_repo();
        let store = Store::open(dir.path()).unwrap();
        let base = crate::git::head_commit(dir.path()).unwrap();
        let mine = store.create("mine", "agent:a", None, Some("m")).unwrap();
        let done = store.create("done", "agent:b", None, Some("d")).unwrap();
        let mut done = on_branch(&store, &done, "claude/done");
        let now = now_secs();
        log::append_at(&store.state_dir(), &done.id, json!({ "event": "tool_done", "paths": ["a.txt"] }), now).unwrap();
        store.finish(&mut done, None).unwrap();
        assert_eq!(store.load(&done.id).unwrap().head.as_deref(), Some(base.as_str()), "finishing records the last commit");
        let changed = vec!["a.txt".to_string()];
        assert!(unmerged(&store, dir.path(), &mine, &changed, Some(&base), 7200, now).is_empty(), "its last commit is in the base");
        let idle = store.create("idle", "agent:codex", None, Some("i")).unwrap();
        let idle = on_branch(&store, &idle, "codex/idle");
        log::append_at(&store.state_dir(), &idle.id, json!({ "event": "tool_done", "paths": ["a.txt"] }), now - 3 * 3600).unwrap();
        touch(&store, &idle.id, now - 3 * 3600);
        assert!(unmerged(&store, dir.path(), &mine, &changed, Some(&base), 7200, now).is_empty(), "an active task idle for hours is not in the way");
        let busy = store.create("busy", "agent:codex", None, Some("b")).unwrap();
        let busy = on_branch(&store, &busy, "codex/busy");
        log::append_at(&store.state_dir(), &busy.id, json!({ "event": "tool_done", "paths": ["a.txt"] }), now).unwrap();
        assert_eq!(unmerged(&store, dir.path(), &mine, &changed, Some(&base), 7200, now), ["a.txt"]);
        let same = store.create("same branch", "agent:codex", None, Some("s")).unwrap();
        log::append_at(&store.state_dir(), &same.id, json!({ "event": "tool_done", "paths": ["b.txt"] }), now).unwrap();
        assert!(unmerged(&store, dir.path(), &mine, &["b.txt".to_string()], Some(&base), 7200, now).is_empty(), "work on the same branch is one line of history");
    }

    #[test]
    fn overlapping_scopes_and_paths_inside_a_reservation_are_found() {
        let res = vec![Reservation { task: "t1".into(), title: "x".into(), author: "agent:codex".into(), include: vec!["src/payments/**".into()], exclude: vec!["src/payments/ledger/**".into()] }];
        assert_eq!(conflicts(&res, &["src/payments/retry/**".to_string()]).len(), 1);
        assert!(conflicts(&res, &["docs/**".to_string()]).is_empty());
        assert!(reserved(&res, "src/payments/a.rs").is_some());
        assert!(reserved(&res, "src/payments/ledger/a.rs").is_none(), "excluded from their scope");
        assert!(reserved(&res, "src/other.rs").is_none());
    }
}

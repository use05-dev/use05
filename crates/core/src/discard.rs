//! Throw a task's work away (D89): its worktree, its branch here and on origin, and 05's record
//! of it. Planned first, so a person sees what exists nowhere else before anything goes; done
//! only for the branch head they saw.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::git;
use crate::policy::Policy;
use crate::task::{Status, Store, Task};

/// A session that did something this recently is still at work: its task is not discarded.
const BUSY_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub task: String,
    pub title: String,
    /// The task's own branch, when 05 may delete it.
    pub branch: Option<String>,
    pub head: Option<String>,
    /// Why the task's branch stays, when it does (it is where work lands, say).
    pub kept: Option<String>,
    /// Its worktree, when it has one other than the main checkout.
    pub worktree: Option<PathBuf>,
    /// The branch is on origin too.
    pub remote: bool,
    /// Commits on the branch that are on no remote branch and not in where work lands.
    pub unpushed: u32,
    /// Files changed or added in its worktree and never committed.
    pub uncommitted: u32,
    /// An agent's session is still working on it.
    pub busy: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Done {
    pub worktree: Option<String>,
    pub branch: Option<String>,
    pub remote: Option<String>,
    /// What could not be done, said plainly (origin did not answer, say).
    pub notes: Vec<String>,
}

/// A task by its id, or the start of it when only one task starts so.
pub fn find(store: &Store, id: &str) -> Result<Task> {
    if let Ok(t) = store.load(id) {
        return Ok(t);
    }
    let matching: Vec<Task> = store.list().into_iter().filter(|t| !id.is_empty() && t.id.starts_with(id)).collect();
    match matching.len() {
        1 => Ok(matching.into_iter().next().expect("one")),
        0 => Err(Error::new("TASK_NOT_FOUND", format!("no task {id} in this repository"))),
        _ => Err(Error::new("TASK_AMBIGUOUS", format!("more than one task starts with {id}; give more of its id"))),
    }
}

/// What discarding a task would remove, and lose.
pub fn plan(store: &Store, policy: &Policy, task: &Task) -> Result<Plan> {
    let top = store.dirs.top.as_path();
    let landing = crate::branches::landing_for(policy, None, top);
    let existing = task.branch.as_deref().filter(|b| git::resolve_commit(top, &format!("refs/heads/{b}")).is_some());
    let kept = existing.and_then(|b| {
        if b == landing {
            Some(format!("{b} is where work lands"))
        } else if crate::branches::is_kept(policy, b) {
            Some(format!("{b} is a branch the policy keeps"))
        } else if store.list().iter().any(|t| t.id != task.id && t.status == Status::Active && t.branch.as_deref() == Some(b)) {
            Some(format!("another task is still working on {b}"))
        } else {
            None
        }
    });
    let branch = existing.filter(|_| kept.is_none()).map(str::to_string);
    let head = branch.as_deref().and_then(|b| git::resolve_commit(top, &format!("refs/heads/{b}")));
    let main = crate::branches::main_worktree(top);
    let worktree = branch.as_deref().and_then(|b| crate::branches::checked_out_at(top, b)).filter(|w| main.as_deref().is_none_or(|m| !same(m, w)));
    let in_main = branch.as_deref().is_some_and(|b| crate::branches::checked_out_at(top, b).is_some_and(|w| main.as_deref().is_some_and(|m| same(m, &w))));
    if in_main {
        return Err(Error::new("DISCARD_CHECKED_OUT", format!("{} is checked out in your main checkout; switch it to another branch first", branch.unwrap_or_default())));
    }
    let remote = branch.as_deref().is_some_and(|b| git::resolve_commit(top, &format!("refs/remotes/origin/{b}")).is_some());
    let unpushed = match &branch {
        Some(b) => {
            let mut args = vec!["rev-list".to_string(), "--count".into(), format!("refs/heads/{b}"), "--not".into(), "--remotes".into()];
            if git::resolve_commit(top, &format!("refs/heads/{landing}")).is_some() {
                args.push(format!("refs/heads/{landing}"));
            }
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            git::text(top, &args).ok().and_then(|n| n.trim().parse().ok()).unwrap_or(0)
        }
        None => 0,
    };
    let uncommitted = worktree.as_deref().map(|w| git::text(w, &["status", "--porcelain", "--untracked-files=all"]).unwrap_or_default().lines().count() as u32).unwrap_or(0);
    let last = crate::log::last_activity(&store.state_dir(), &task.id);
    let busy = task.status == Status::Active && task.session.is_some() && task.ended.is_none() && crate::time::now_secs().saturating_sub(last) < BUSY_SECS;
    Ok(Plan { task: task.id.clone(), title: task.title.clone(), branch, head, kept, worktree, remote, unpushed, uncommitted, busy })
}

/// Discard as planned, if the branch is still at `head` (the head a person saw). Removes the
/// worktree and the branch, deletes it on origin (giving up after `timeout`), and records the task
/// as discarded.
pub fn apply(store: &Store, policy: &Policy, task: &Task, head: Option<&str>, timeout: Duration) -> Result<Done> {
    let plan = plan(store, policy, task)?;
    if plan.busy {
        return Err(Error::new("DISCARD_BUSY", "an agent's session is still working on this task; stop it first".to_string()));
    }
    if plan.head.as_deref() != head {
        return Err(Error::new("DISCARD_MOVED", "the work changed since the discard was prepared; look again and discard what is there now".to_string()));
    }
    let top = store.dirs.top.as_path();
    // Run from the main checkout: the worktree going away may be where this was called.
    let run_in = crate::branches::main_worktree(top).unwrap_or_else(|| top.to_path_buf());
    let mut done = Done::default();
    if let Some(w) = &plan.worktree {
        git::run(&run_in, &["worktree", "remove", "--force", &w.display().to_string()]).map_err(|e| Error::new("DISCARD_FAILED", format!("the worktree {} could not be removed: {}", w.display(), e.message)))?;
        done.worktree = Some(w.display().to_string());
    }
    if let (Some(b), Some(h)) = (&plan.branch, &plan.head) {
        git::run(&run_in, &["update-ref", "-d", &format!("refs/heads/{b}"), h]).map_err(|e| Error::new("DISCARD_FAILED", format!("the branch {b} could not be deleted: {}", e.message)))?;
        done.branch = Some(b.clone());
        if plan.remote {
            match crate::fresh::quiet_git(&run_in, &["push", "--quiet", "origin", "--delete", b], timeout) {
                Ok(()) => done.remote = Some(format!("origin/{b}")),
                Err(why) => done.notes.push(format!("origin/{b} is still there ({why}); delete it with: git push origin --delete {b}")),
            }
        }
    }
    if let Some(k) = &plan.kept {
        done.notes.push(format!("Kept the branch: {k}."));
    }
    let mut t = task.clone();
    t.status = Status::Discarded;
    store.save(&t)?;
    let _ = crate::log::append(&store.state_dir(), &t.id, serde_json::json!({ "event": "discarded", "branch": done.branch, "worktree": done.worktree, "remote": done.remote }));
    Ok(done)
}

fn same(a: &Path, b: &Path) -> bool {
    a.canonicalize().ok().zip(b.canonicalize().ok()).is_some_and(|(x, y)| x == y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A repository with an origin, and an agent's worktree on its own branch: one commit pushed,
    /// one not, and a file never committed.
    struct World {
        _dir: tempfile::TempDir,
        top: PathBuf,
        wt: PathBuf,
        origin: PathBuf,
    }

    fn g(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(dir).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn world() -> (World, Store, Task) {
        let dir = tempfile::tempdir().unwrap();
        let (top, origin, wt) = (dir.path().join("repo"), dir.path().join("origin.git"), dir.path().join("wt"));
        g(dir.path(), &["init", "-q", "--bare", "-b", "main", origin.to_str().unwrap()]);
        g(dir.path(), &["init", "-q", "-b", "main", top.to_str().unwrap()]);
        std::fs::write(top.join("a.txt"), "1\n").unwrap();
        g(&top, &["add", "-A"]);
        g(&top, &["commit", "-q", "-m", "base"]);
        g(&top, &["remote", "add", "origin", origin.to_str().unwrap()]);
        g(&top, &["push", "-q", "origin", "main"]);
        g(&top, &["worktree", "add", "-q", "-b", "claude/fix", wt.to_str().unwrap()]);
        let store = Store::open(&wt).unwrap();
        let task = store.create("fix it", "agent:claude-code", None, None).unwrap();
        std::fs::write(wt.join("a.txt"), "2\n").unwrap();
        g(&wt, &["commit", "-qam", "pushed"]);
        g(&wt, &["push", "-q", "origin", "claude/fix"]);
        std::fs::write(wt.join("a.txt"), "3\n").unwrap();
        g(&wt, &["commit", "-qam", "not pushed"]);
        std::fs::write(wt.join("new.txt"), "draft\n").unwrap();
        let store = Store::open(&top).unwrap();
        let task = store.load(&task.id).unwrap();
        (World { _dir: dir, top, wt, origin }, store, task)
    }

    #[test]
    fn it_says_what_would_be_lost_then_removes_the_worktree_and_the_branch_here_and_on_origin() {
        let (w, store, task) = world();
        let p = plan(&store, &Policy::default(), &task).unwrap();
        assert_eq!(p.branch.as_deref(), Some("claude/fix"));
        assert!(p.remote && p.worktree.is_some() && p.kept.is_none());
        assert_eq!((p.unpushed, p.uncommitted), (1, 1), "one commit nowhere else, one file never committed");
        let done = apply(&store, &Policy::default(), &task, p.head.as_deref(), Duration::from_secs(10)).unwrap();
        assert!(done.notes.is_empty(), "{:?}", done.notes);
        assert!(!w.wt.exists(), "the worktree is gone");
        assert!(git::resolve_commit(&w.top, "refs/heads/claude/fix").is_none(), "the branch is gone here");
        assert!(git::resolve_commit(&w.origin, "refs/heads/claude/fix").is_none(), "and on origin");
        assert_eq!(store.load(&task.id).unwrap().status, Status::Discarded);
        assert!(git::resolve_commit(&w.top, "refs/heads/main").is_some(), "main is untouched");
    }

    #[test]
    fn work_that_moved_since_it_was_shown_is_not_discarded() {
        let (w, store, task) = world();
        let p = plan(&store, &Policy::default(), &task).unwrap();
        g(&w.wt, &["add", "-A"]);
        g(&w.wt, &["commit", "-qm", "more"]);
        let err = apply(&store, &Policy::default(), &task, p.head.as_deref(), Duration::from_secs(10)).unwrap_err();
        assert_eq!(err.code, "DISCARD_MOVED");
        assert!(w.wt.exists() && git::resolve_commit(&w.top, "refs/heads/claude/fix").is_some());
    }

    #[test]
    fn the_branch_work_lands_on_is_never_deleted_and_a_busy_session_is_left_alone() {
        let (w, store, _) = world();
        // A task done straight on main, in the main checkout.
        let on_main = Store::open(&w.top).unwrap().create("on main", "agent:codex", None, None).unwrap();
        let p = plan(&store, &Policy::default(), &on_main).unwrap();
        assert_eq!((p.branch.clone(), p.worktree.clone()), (None, None));
        assert!(p.kept.as_deref().is_some_and(|k| k.contains("where work lands")), "{p:?}");
        let done = apply(&store, &Policy::default(), &on_main, None, Duration::from_secs(10)).unwrap();
        assert!(done.branch.is_none() && git::resolve_commit(&w.top, "refs/heads/main").is_some());
        // An agent still at work: its session started and logged just now.
        let mut busy = Store::open(&w.wt).unwrap().create("still going", "agent:claude-code", None, Some("s9")).unwrap();
        busy.branch = Some("claude/other".into());
        let _ = crate::log::append(&store.state_dir(), &busy.id, serde_json::json!({ "event": "edit" }));
        assert!(plan(&store, &Policy::default(), &busy).unwrap().busy);
        assert_eq!(apply(&store, &Policy::default(), &busy, None, Duration::from_secs(10)).unwrap_err().code, "DISCARD_BUSY");
    }

    #[test]
    fn a_task_is_found_by_the_start_of_its_id() {
        let (_w, store, task) = world();
        assert_eq!(find(&store, &task.id[..6]).unwrap().id, task.id);
        assert_eq!(find(&store, "zzzz").unwrap_err().code, "TASK_NOT_FOUND");
    }
}

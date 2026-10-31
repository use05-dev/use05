//! Branches: which are real and kept, which are an agent's working space, where work lands, and
//! cleaning up after it (D69). Without this a repository fills with branches and worktrees that
//! nobody will look at again.
//!
//! Nothing here forces anything: a branch moves only by fast-forward, a branch is deleted only
//! once its head is in its target, and a worktree is removed only when it has nothing uncommitted.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::git;
use crate::glob;
use crate::intent::IntentCard;
use crate::policy::Policy;
use crate::task::{Status, Store};

/// Branch patterns: `*` matches within a name segment, and a trailing `/*` also matches deeper
/// names (`claude/*` matches `claude/a/b`).
fn matches_ref(pattern: &str, name: &str) -> bool {
    glob::matches(pattern, name) || pattern.strip_suffix('*').is_some_and(|prefix| prefix.ends_with('/') && name.starts_with(prefix))
}

pub fn is_kept(policy: &Policy, name: &str) -> bool {
    policy.branches.keep.iter().any(|p| matches_ref(p, name))
}

/// An agent's working branch. A kept branch never is, whatever the patterns say.
pub fn is_work(policy: &Policy, name: &str) -> bool {
    !is_kept(policy, name) && policy.branches.work.iter().any(|p| matches_ref(p, name))
}

/// Where a task's work lands: the declaration's target, else the policy's, else the remote's
/// default branch, else `main`.
pub fn target_for(policy: &Policy, card: Option<&IntentCard>, top: &Path) -> String {
    if let Some(t) = card.and_then(|c| c.target.clone()).or_else(|| policy.branches.target.clone()) {
        return t;
    }
    git::text(top, &["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"])
        .ok()
        .and_then(|r| r.strip_prefix("origin/").map(str::to_string))
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "main".to_string())
}

fn head_of(top: &Path, branch: &str) -> Option<String> {
    git::resolve_commit(top, &format!("refs/heads/{branch}"))
}

fn is_ancestor(top: &Path, a: &str, b: &str) -> bool {
    git::run(top, &["merge-base", "--is-ancestor", a, b]).is_ok()
}

/// `(path, checked-out branch)` for every worktree of the repository; the main one first.
fn worktrees(top: &Path) -> Vec<(PathBuf, Option<String>)> {
    let mut out = Vec::new();
    for block in git::text(top, &["worktree", "list", "--porcelain"]).unwrap_or_default().split("\n\n") {
        let mut path = None;
        let mut branch = None;
        for line in block.lines() {
            if let Some(p) = line.strip_prefix("worktree ") {
                path = Some(PathBuf::from(p));
            }
            if let Some(b) = line.strip_prefix("branch refs/heads/") {
                branch = Some(b.to_string());
            }
        }
        if let Some(p) = path {
            out.push((p, branch));
        }
    }
    out
}

/// Files git ignores (an `.env`, local settings) would be deleted with the worktree. 05's own
/// empty inbox does not count.
fn has_ignored_files(dir: &Path) -> bool {
    let listed = git::text(dir, &["status", "--porcelain", "--ignored"]).unwrap_or_default();
    let pending = crate::inbox::has_any(dir);
    listed.lines().filter(|l| l.starts_with("!! ")).any(|l| pending || !l[3..].starts_with(".05/inbox"))
}

/// Where a branch is checked out, if anywhere.
pub fn checked_out_at(top: &Path, branch: &str) -> Option<PathBuf> {
    worktrees(top).into_iter().find(|(_, b)| b.as_deref() == Some(branch)).map(|(p, _)| p)
}

/// No uncommitted changes to tracked files.
pub fn is_committed(dir: &Path) -> bool {
    clean(dir, true)
}

fn same(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

fn clean(dir: &Path, tracked_only: bool) -> bool {
    let args: &[&str] = if tracked_only { &["status", "--porcelain", "--untracked-files=no"] } else { &["status", "--porcelain"] };
    git::text(dir, args).is_ok_and(|t| t.is_empty())
}

/// Is the branch's head already in its target, locally or on `origin`?
pub fn landed(top: &Path, branch: &str, target: &str) -> bool {
    let Some(head) = head_of(top, branch) else { return false };
    [format!("refs/heads/{target}"), format!("refs/remotes/origin/{target}")]
        .iter()
        .any(|t| git::resolve_commit(top, t).is_some() && is_ancestor(top, &head, t))
}

/// Move `target` forward to `branch`'s head. Fast-forward only; never forced. If the target is
/// checked out in a worktree, that worktree must be clean and is updated with it.
pub fn fast_forward(top: &Path, branch: &str, target: &str, at: &str) -> Result<String> {
    let head = head_of(top, branch).ok_or_else(|| Error::new("BRANCH_NOT_FOUND", format!("there is no branch {branch}")))?;
    // Land exactly what was gated: a commit added since was never checked.
    if head != at {
        return Err(Error::new("BRANCH_MOVED", format!("{branch} moved after it was checked")).with_next("prove it again, then: use05 land"));
    }
    let old = head_of(top, target).ok_or_else(|| Error::new("TARGET_NOT_FOUND", format!("there is no branch {target} to land on")))?;
    if old == head {
        return Ok(head);
    }
    if !is_ancestor(top, &old, &head) {
        return Err(Error::new("NOT_FAST_FORWARD", format!("{target} has moved on since {branch} started")).with_next(format!("rebase onto {target}, prove again, then: use05 land")));
    }
    match worktrees(top).into_iter().find(|(_, b)| b.as_deref() == Some(target)) {
        Some((dir, _)) => {
            if !clean(&dir, true) {
                return Err(Error::new("TARGET_DIRTY", format!("{target} is checked out at {} with uncommitted changes", dir.display())).with_next("commit or stash them there, then: use05 land"));
            }
            git::run(&dir, &["merge", "--ff-only", "-q", &head])?;
        }
        None => {
            git::run(top, &["update-ref", &format!("refs/heads/{target}"), &head, &old])?;
        }
    }
    Ok(head)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Removed {
    pub branch: String,
    pub worktree: Option<String>,
}

/// Remove finished tasks' working branches whose work is in their target, and their worktrees.
/// `here` is the worktree the caller runs in: it is kept unless `including_here` (a session that
/// has ended no longer needs its directory).
pub fn tidy(store: &Store, policy: &Policy, here: &Path, including_here: bool) -> Vec<Removed> {
    let top = store.dirs.top.as_path();
    let mut removed = Vec::new();
    let tasks = store.list();
    // Branches someone is still working on: never touched, whoever finished before them.
    let in_use: Vec<String> = tasks.iter().filter(|t| t.status == Status::Active).filter_map(|t| t.branch.clone()).collect();
    let existing: Vec<String> = git::text(top, &["for-each-ref", "--format=%(refname:short)", "refs/heads/"]).unwrap_or_default().lines().map(str::to_string).collect();
    let idle = u64::from(policy.drift.reservation_idle_hours) * 3600;
    let now = crate::time::now_secs();
    for task in tasks.iter().filter(|t| t.status == Status::Finished) {
        let Some(branch) = task.branch.clone().filter(|b| is_work(policy, b) && existing.contains(b) && !in_use.contains(b)) else { continue };
        // An agent session that has not ended may still be working there, unless it went quiet.
        if task.session.is_some() && task.ended.is_none() {
            let last = crate::log::last_activity(&store.state_dir(), &task.id).max(task.finished.as_deref().and_then(crate::time::parse_rfc3339).unwrap_or(0));
            if now.saturating_sub(last) <= idle {
                continue;
            }
        }
        let Some(head) = head_of(top, &branch) else { continue };
        // A branch with no commit of its own (made, then never worked on) is not cleaned up.
        if task.base_commit.as_deref() == Some(head.as_str()) {
            continue;
        }
        if !landed(top, &branch, &target_for(policy, task.intent.as_ref(), top)) {
            continue;
        }
        let all = worktrees(top);
        let main = all.first().map(|(p, _)| p.clone());
        let mut gone = None;
        // Run from the main checkout: the worktree being removed may be where this was called.
        let run_in = main.as_deref().unwrap_or(top);
        if let Some((dir, _)) = all.iter().find(|(_, b)| b.as_deref() == Some(branch.as_str())) {
            let is_main = main.as_deref().is_some_and(|m| same(m, dir));
            if is_main || (same(dir, here) && !including_here) || !clean(dir, false) || has_ignored_files(dir) {
                continue;
            }
            if git::run(run_in, &["worktree", "remove", &dir.display().to_string()]).is_err() {
                continue;
            }
            gone = Some(dir.display().to_string());
        }
        // Deleted only at the head that was checked: a branch that moved since is left alone.
        if git::run(run_in, &["update-ref", "-d", &format!("refs/heads/{branch}"), &head]).is_ok() {
            let _ = crate::log::append(&store.state_dir(), &task.id, serde_json::json!({ "event": "tidied", "branch": branch, "worktree": gone }));
            removed.push(Removed { branch, worktree: gone });
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct Repo {
        dir: tempfile::TempDir,
        trees: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Repo {
            let r = Repo { dir: tempfile::tempdir().unwrap(), trees: tempfile::tempdir().unwrap() };
            r.git(&["init", "-q", "-b", "main"]);
            std::fs::write(r.dir.path().join("a.txt"), "1\n").unwrap();
            r.git(&["add", "-A"]);
            r.git(&["commit", "-q", "-m", "base"]);
            r
        }
        fn top(&self) -> &Path {
            self.dir.path()
        }
        fn git(&self, args: &[&str]) -> String {
            git_in(self.dir.path(), args)
        }
        /// A worktree on a new branch, with one commit.
        fn work(&self, branch: &str) -> PathBuf {
            let path = self.trees.path().join(branch.replace('/', "-"));
            self.git(&["worktree", "add", "-q", "-b", branch, path.to_str().unwrap()]);
            std::fs::write(path.join("a.txt"), format!("{branch}\n")).unwrap();
            git_in(&path, &["commit", "-qam", "work"]);
            path
        }
        fn has_branch(&self, name: &str) -> bool {
            git::resolve_commit(self.top(), &format!("refs/heads/{name}")).is_some()
        }
    }

    fn git_in(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(dir).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn finished_task(store: &Store, worktree: &Path) {
        let s = Store::open(worktree).unwrap();
        let mut t = s.create("work", "agent:codex", None, None).unwrap();
        // A task starts before its work: its base is the commit before the branch's own.
        t.base_commit = Some(git_in(worktree, &["rev-parse", "HEAD~1"]));
        s.save(&t).unwrap();
        s.finish(&mut t, Some("done")).unwrap();
        let _ = store;
    }

    #[test]
    fn a_branch_another_session_is_still_using_is_never_removed() {
        let r = Repo::new();
        let store = Store::open(r.top()).unwrap();
        let wt = r.work("claude/shared");
        finished_task(&store, &wt);
        let s = Store::open(&wt).unwrap();
        let _still_working = s.create("another session", "agent:claude-code", None, Some("s4")).unwrap();
        r.git(&["merge", "-q", "--ff-only", "claude/shared"]);
        assert!(tidy(&store, &Policy::default(), r.top(), true).is_empty(), "an active task is on that branch");
        assert!(wt.exists() && r.has_branch("claude/shared"));
    }

    #[test]
    fn a_branch_with_no_work_of_its_own_and_a_worktree_with_ignored_files_are_kept() {
        let r = Repo::new();
        std::fs::write(r.top().join(".gitignore"), ".env\n").unwrap();
        r.git(&["add", "-A"]);
        r.git(&["commit", "-q", "-m", "ignore .env"]);
        let store = Store::open(r.top()).unwrap();
        // A branch someone made, on which a session started and ended without committing.
        let empty = r.trees.path().join("empty");
        r.git(&["worktree", "add", "-q", "-b", "claude/feature", empty.to_str().unwrap()]);
        let s = Store::open(&empty).unwrap();
        let mut t = s.create("nothing yet", "agent:codex", None, None).unwrap();
        s.finish(&mut t, None).unwrap();
        // Landed work whose worktree holds an ignored secret.
        let secret = r.work("claude/secret");
        finished_task(&store, &secret);
        r.git(&["merge", "-q", "--ff-only", "claude/secret"]);
        std::fs::write(secret.join(".env"), "TOKEN=1\n").unwrap();
        assert!(tidy(&store, &Policy::default(), r.top(), false).is_empty());
        assert!(r.has_branch("claude/feature") && empty.exists());
        assert!(secret.join(".env").exists(), "ignored files are never deleted");
    }

    #[test]
    fn a_live_agent_session_keeps_its_worktree_until_it_ends_or_goes_idle() {
        let r = Repo::new();
        let store = Store::open(r.top()).unwrap();
        let wt = r.work("codex/live");
        let s = Store::open(&wt).unwrap();
        let mut t = s.create("live", "agent:codex", None, Some("s7")).unwrap();
        t.base_commit = Some(git_in(&wt, &["rev-parse", "HEAD~1"]));
        s.save(&t).unwrap();
        s.finish(&mut t, None).unwrap();
        r.git(&["merge", "-q", "--ff-only", "codex/live"]);
        assert!(tidy(&store, &Policy::default(), r.top(), false).is_empty(), "its session has not ended");
        let mut ended = s.load(&t.id).unwrap();
        ended.ended = Some(crate::time::now_rfc3339());
        s.save(&ended).unwrap();
        assert_eq!(tidy(&store, &Policy::default(), r.top(), false).len(), 1);
    }

    #[test]
    fn a_branch_that_moved_after_it_was_gated_is_not_landed() {
        let r = Repo::new();
        let wt = r.work("claude/race");
        let gated = git_in(&wt, &["rev-parse", "HEAD"]);
        std::fs::write(wt.join("a.txt"), "later\n").unwrap();
        git_in(&wt, &["commit", "-qam", "after the gate"]);
        assert_eq!(fast_forward(r.top(), "claude/race", "main", &gated).unwrap_err().code, "BRANCH_MOVED");
        assert_ne!(r.git(&["rev-parse", "main"]), gated);
    }

    #[test]
    fn kept_branches_are_never_work_branches() {
        let mut p = Policy::default();
        assert!(is_kept(&p, "main") && !is_work(&p, "main"));
        assert!(is_work(&p, "claude/fix-login") && is_work(&p, "codex/x") && is_work(&p, "05/abc"));
        assert!(!is_work(&p, "feature/x"), "not an agent's branch");
        p.branches.work.push("release/*".into());
        assert!(is_kept(&p, "release/1.2") && !is_work(&p, "release/1.2"), "keep wins");
    }

    #[test]
    fn the_target_is_the_declarations_then_the_policys_then_main() {
        let r = Repo::new();
        let mut p = Policy::default();
        assert_eq!(target_for(&p, None, r.top()), "main");
        p.branches.target = Some("develop".into());
        assert_eq!(target_for(&p, None, r.top()), "develop");
        let card = IntentCard { target: Some("release/2".into()), ..IntentCard::default() };
        assert_eq!(target_for(&p, Some(&card), r.top()), "release/2");
    }

    #[test]
    fn a_fast_forward_moves_the_target_and_updates_its_clean_worktree() {
        let r = Repo::new();
        r.work("claude/one");
        assert!(!landed(r.top(), "claude/one", "main"));
        let at = r.git(&["rev-parse", "claude/one"]);
        let head = fast_forward(r.top(), "claude/one", "main", &at).unwrap();
        assert_eq!(r.git(&["rev-parse", "main"]), head);
        assert_eq!(std::fs::read_to_string(r.top().join("a.txt")).unwrap(), "claude/one\n", "the checked-out target was updated");
        assert!(landed(r.top(), "claude/one", "main"));
    }

    #[test]
    fn a_target_that_moved_on_or_a_dirty_target_worktree_is_refused() {
        let r = Repo::new();
        r.work("claude/one");
        std::fs::write(r.top().join("b.txt"), "x\n").unwrap();
        r.git(&["add", "-A"]);
        r.git(&["commit", "-q", "-m", "main moved"]);
        let at = r.git(&["rev-parse", "claude/one"]);
        assert_eq!(fast_forward(r.top(), "claude/one", "main", &at).unwrap_err().code, "NOT_FAST_FORWARD");
        let r = Repo::new();
        r.work("claude/two");
        std::fs::write(r.top().join("a.txt"), "uncommitted\n").unwrap();
        let at = r.git(&["rev-parse", "claude/two"]);
        assert_eq!(fast_forward(r.top(), "claude/two", "main", &at).unwrap_err().code, "TARGET_DIRTY");
    }

    #[test]
    fn tidy_removes_landed_work_and_never_what_is_dirty_unmerged_kept_or_here() {
        let r = Repo::new();
        let store = Store::open(r.top()).unwrap();
        let p = Policy::default();
        let landed_wt = r.work("claude/landed");
        let dirty_wt = r.work("claude/dirty");
        let unmerged_wt = r.work("claude/unmerged");
        for wt in [&landed_wt, &dirty_wt, &unmerged_wt] {
            finished_task(&store, wt);
        }
        let at = r.git(&["rev-parse", "claude/landed"]);
        fast_forward(r.top(), "claude/landed", "main", &at).unwrap();
        // claude/dirty's work is in main too, but its worktree has something uncommitted.
        git_in(&dirty_wt, &["reset", "-q", "--hard", "main"]);
        std::fs::write(dirty_wt.join("scratch.txt"), "notes\n").unwrap();

        let landed_real = landed_wt.canonicalize().unwrap();
        let removed = tidy(&store, &p, r.top(), false);
        assert_eq!(removed.len(), 1, "{removed:?}");
        assert_eq!(removed[0].branch, "claude/landed");
        assert_eq!(removed[0].worktree.as_deref().map(|w| Path::new(w).to_path_buf()), Some(landed_real));
        assert!(!r.has_branch("claude/landed") && !landed_wt.exists());
        assert!(r.has_branch("claude/dirty") && dirty_wt.join("scratch.txt").exists(), "uncommitted work is never removed");
        assert!(r.has_branch("claude/unmerged") && unmerged_wt.exists(), "work not in its target stays");
        assert!(r.has_branch("main"));

        // The worktree a command runs in stays, unless its session has ended.
        let here = r.work("claude/here");
        finished_task(&store, &here);
        r.git(&["merge", "-q", "--ff-only", "claude/here"]);
        assert!(tidy(&store, &p, &here, false).iter().all(|x| x.branch != "claude/here"));
        assert!(tidy(&store, &p, &here, true).iter().any(|x| x.branch == "claude/here"));
    }
}

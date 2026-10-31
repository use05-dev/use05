//! Fresh base: whether an agent's work starts from the latest code on origin. At session start
//! the hook fetches origin's copy of the target branch and records how far behind the work is;
//! the gate holds work that never caught up. Nothing here moves the person's branches.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::gate::StaleBase;
use crate::git;
use crate::intent::IntentCard;
use crate::policy::Policy;
use crate::task::Task;

/// How long the session-start hook waits for origin before it gives up and says so.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// What the hook saw when it compared a session's starting point with origin.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Fresh {
    /// `origin/main`.
    pub remote_ref: String,
    /// The commit origin's branch was on.
    pub tip: String,
    /// Commits on it the starting point did not have.
    pub behind: u32,
    /// When, RFC 3339.
    pub checked: String,
}

/// The ssh git should use so it never asks for a passphrase or a host key on the person's
/// terminal: `BatchMode`, unless the person set their own (`GIT_SSH_COMMAND`, `core.sshCommand`).
fn ssh_command(top: &Path, from_env: Option<&str>) -> Option<String> {
    if from_env.is_some_and(|c| !c.is_empty()) || git::text(top, &["config", "core.sshCommand"]).is_ok_and(|c| !c.trim().is_empty()) {
        return None;
    }
    Some("ssh -o BatchMode=yes".to_string())
}

/// Fetch one branch from a remote, never asking for a password, and give up after `timeout`.
/// The branch is fetched into `refs/remotes/<remote>/<branch>` even in a single-branch clone.
pub fn fetch(top: &Path, remote: &str, branch: &str, timeout: Duration) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let refspec = format!("+refs/heads/{branch}:refs/remotes/{remote}/{branch}");
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(top)
        .args(["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", remote, &refspec])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .env("LC_ALL", "C")
        // Its own process group, so a helper git starts (ssh) goes when git is given up on.
        .process_group(0)
        // No pipes: nothing here waits on what a helper keeps open.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if git::text(top, &["config", "--get", "core.sshCommand"]).is_err() && std::env::var_os("GIT_SSH").is_none() {
        if let Some(ssh) = ssh_command(top, std::env::var("GIT_SSH_COMMAND").ok().as_deref()) {
            cmd.env("GIT_SSH_COMMAND", ssh);
        }
    }
    let mut child = cmd.spawn().map_err(|e| format!("git could not be started ({e})"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(format!("git fetch {remote} {branch} failed{}", status.code().map(|c| format!(" (exit {c})")).unwrap_or_default())),
            Ok(None) if started.elapsed() >= timeout => {
                // The whole group: git and anything it started.
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{remote} did not answer within {} s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("waiting for git fetch failed ({e})")),
        }
    }
}

/// Kill a process group started with `process_group(0)`: its id is the leader's pid.
#[allow(unsafe_code)]
fn kill_group(leader: u32) {
    if let Ok(pid) = i32::try_from(leader) {
        // SAFETY: kill(2) with a negative pid signals that process group; no memory is touched.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
}

fn count(top: &Path, range: &str) -> u32 {
    git::text(top, &["rev-list", "--count", range]).ok().and_then(|n| n.trim().parse().ok()).unwrap_or(0)
}

/// Fetch origin's copy of where this work lands and compare the current commit with it.
pub fn check(top: &Path, policy: &Policy, card: Option<&IntentCard>, timeout: Duration) -> Result<Fresh, String> {
    let branch = crate::branches::target_for(policy, card, top);
    if git::text(top, &["remote", "get-url", "origin"]).is_err() {
        return Err("this repository has no remote named origin".into());
    }
    fetch(top, "origin", &branch, timeout)?;
    let remote_ref = format!("origin/{branch}");
    let tip = git::resolve_commit(top, &format!("refs/remotes/{remote_ref}")).ok_or_else(|| format!("{remote_ref} does not exist"))?;
    let head = git::head_commit(top).ok_or("there is no commit to compare yet")?;
    Ok(Fresh { remote_ref, behind: count(top, &format!("{head}..{tip}")), tip, checked: crate::time::now_rfc3339() })
}

fn is_ancestor(top: &Path, a: &str, b: &str) -> bool {
    git::run(top, &["merge-base", "--is-ancestor", a, b]).is_ok()
}

/// Work whose head still lacks what origin had when the session started. `None` once it caught up.
pub fn stale(top: &Path, fresh: &Fresh, head: Option<&str>) -> Option<StaleBase> {
    let head = head?;
    if fresh.behind == 0 || is_ancestor(top, &fresh.tip, head) {
        return None;
    }
    Some(StaleBase { remote_ref: fresh.remote_ref.clone(), behind: count(top, &format!("{head}..{}", fresh.tip)).max(1) })
}

/// The agent updated: its work now contains what origin had when the session started. Move the
/// task's base to the newest origin commit the work contains, so nothing it pulled in (including
/// commits pushed after the session started) counts as its own change. When the branch had
/// commits of its own that were rebased or merged, the base becomes git's merge of the old base
/// and that commit. Returns whether the base moved.
pub fn catch_up(top: &Path, task: &mut Task) -> bool {
    let (Some(fresh), Some(base), Some(head)) = (task.fresh.clone(), task.base_commit.clone(), git::head_commit(top)) else { return false };
    // Only for the work checked out here: another checkout's HEAD says nothing about this task.
    let elsewhere = task.branch.as_ref().is_some_and(|b| git::current_branch(top).as_ref() != Some(b));
    if task.status != crate::task::Status::Active || elsewhere || !is_ancestor(top, &fresh.tip, &head) {
        return false;
    }
    let now = git::resolve_commit(top, &format!("refs/remotes/{}", fresh.remote_ref)).unwrap_or_else(|| fresh.tip.clone());
    let Ok(point) = git::text(top, &["merge-base", &head, &now]).map(|t| t.trim().to_string()) else { return false };
    if point == base || is_ancestor(top, &point, &base) {
        return false;
    }
    let tree = if is_ancestor(top, &base, &point) {
        git::resolve_tree(top, &point).ok()
    } else {
        // Needs git 2.38. A conflict means no clean base exists; then the base stays.
        git::text(top, &["merge-tree", "--write-tree", "--no-messages", &base, &point]).ok().and_then(|t| t.lines().next().map(str::to_string))
    };
    let Some(tree) = tree.filter(|t| !t.is_empty()) else { return false };
    task.base_commit = Some(point.clone());
    task.base_tree = tree;
    task.fresh = Some(Fresh { tip: point, behind: 0, ..fresh });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_that_never_answers_is_given_up_on() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        git::run(top, &["init", "-q"]).unwrap();
        git::run(top, &["remote", "add", "origin", "ssh://example.invalid/repo.git"]).unwrap();
        // An ssh that hangs, as one waiting on a network that never replies would.
        git::run(top, &["config", "core.sshCommand", "sleep 30; true"]).unwrap();
        let started = Instant::now();
        let err = fetch(top, "origin", "main", Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("did not answer within 1 s"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
        // Nothing git started is left behind: an ssh that outlived git could prompt or hang on.
        std::thread::sleep(Duration::from_millis(200));
        let left = Command::new("pgrep").args(["-f", "sleep 30; true"]).output().unwrap();
        assert!(left.stdout.is_empty(), "still running: {}", String::from_utf8_lossy(&left.stdout));
    }

    #[test]
    fn ssh_is_told_never_to_prompt_unless_the_person_chose_their_own_ssh() {
        let dir = tempfile::tempdir().unwrap();
        git::run(dir.path(), &["init", "-q"]).unwrap();
        assert_eq!(ssh_command(dir.path(), None).as_deref(), Some("ssh -o BatchMode=yes"));
        assert_eq!(ssh_command(dir.path(), Some("my-ssh")), None, "GIT_SSH_COMMAND set by the person");
        git::run(dir.path(), &["config", "core.sshCommand", "ssh -i ~/.ssh/work"]).unwrap();
        assert_eq!(ssh_command(dir.path(), None), None, "core.sshCommand set by the person");
    }

    /// A repository with an `origin`, the person's clone of it, and a teammate's clone.
    struct World {
        _dir: tempfile::TempDir,
        mine: std::path::PathBuf,
        theirs: std::path::PathBuf,
    }

    fn g(dir: &Path, args: &[&str]) -> String {
        let mut all = vec!["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"];
        all.extend_from_slice(args);
        git::text(dir, &all).unwrap()
    }

    fn commit(dir: &Path, file: &str, body: &str) -> String {
        std::fs::write(dir.join(file), body).unwrap();
        g(dir, &["add", "-A"]);
        g(dir, &["commit", "-q", "-m", file]);
        g(dir, &["rev-parse", "HEAD"])
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let (origin, mine, theirs) = (dir.path().join("origin.git"), dir.path().join("mine"), dir.path().join("theirs"));
        std::fs::create_dir_all(&mine).unwrap();
        g(dir.path(), &["init", "-q", "--bare", "-b", "main", origin.to_str().unwrap()]);
        g(&mine, &["init", "-q", "-b", "main"]);
        commit(&mine, "a.txt", "a\n");
        g(&mine, &["remote", "add", "origin", origin.to_str().unwrap()]);
        g(&mine, &["push", "-q", "origin", "main"]);
        g(dir.path(), &["clone", "-q", origin.to_str().unwrap(), theirs.to_str().unwrap()]);
        World { _dir: dir, mine, theirs }
    }

    fn task_at(w: &World) -> Task {
        let store = crate::task::Store::open(&w.mine).unwrap();
        let mut t = store.create("t", "agent:test", None, Some("s")).unwrap();
        t.fresh = Some(check(&w.mine, &Policy::default(), None, FETCH_TIMEOUT).unwrap());
        t
    }

    fn changed(w: &World, t: &Task) -> Vec<String> {
        let head_tree = git::resolve_tree(&w.mine, "HEAD").unwrap();
        git::changed(&w.mine, Some(&t.base_tree), &head_tree).unwrap().into_iter().map(|c| c.path).collect()
    }

    #[test]
    fn catching_up_follows_origin_as_it_is_now_not_as_it_was_at_the_start() {
        let w = world();
        commit(&w.theirs, "t1.txt", "1\n");
        g(&w.theirs, &["push", "-q", "origin", "main"]);
        let mut t = task_at(&w);
        assert_eq!(t.fresh.as_ref().unwrap().behind, 1);
        // A teammate pushes again after the session started; the agent then pulls both.
        commit(&w.theirs, "t2.txt", "2\n");
        g(&w.theirs, &["push", "-q", "origin", "main"]);
        commit(&w.mine, "work.txt", "mine\n");
        g(&w.mine, &["pull", "-q", "--rebase", "origin", "main"]);
        assert!(catch_up(&w.mine, &mut t));
        assert_eq!(changed(&w, &t), ["work.txt"], "the teammate's later commit is not the agent's change");
        assert!(stale(&w.mine, t.fresh.as_ref().unwrap(), git::head_commit(&w.mine).as_deref()).is_none());
    }

    #[test]
    fn catching_up_works_when_the_branch_had_its_own_commits_and_was_rebased_or_merged() {
        for how in ["rebase", "merge"] {
            let w = world();
            g(&w.mine, &["checkout", "-q", "-b", "agent/x"]);
            commit(&w.mine, "earlier.txt", "from an earlier session\n");
            commit(&w.theirs, "t1.txt", "1\n");
            g(&w.theirs, &["push", "-q", "origin", "main"]);
            let mut t = task_at(&w);
            assert_eq!(t.fresh.as_ref().unwrap().behind, 1);
            commit(&w.mine, "work.txt", "mine\n");
            match how {
                "rebase" => g(&w.mine, &["rebase", "-q", "origin/main"]),
                _ => g(&w.mine, &["merge", "-q", "--no-edit", "origin/main"]),
            };
            assert!(catch_up(&w.mine, &mut t), "{how}");
            assert_eq!(changed(&w, &t), ["work.txt"], "{how}: origin's commits are not the agent's change");
        }
    }

    #[test]
    fn no_origin_is_said_plainly() {
        let dir = tempfile::tempdir().unwrap();
        git::run(dir.path(), &["init", "-q"]).unwrap();
        let err = check(dir.path(), &Policy::default(), None, FETCH_TIMEOUT).unwrap_err();
        assert_eq!(err, "this repository has no remote named origin");
    }
}

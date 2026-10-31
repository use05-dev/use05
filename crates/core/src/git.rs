//! Thin, safe wrappers over the `git` binary. Arguments are never built from untrusted text
//! without a revision check, and a leading dash is never passed through as a revision.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

pub struct Dirs {
    /// Top of the work tree.
    pub top: PathBuf,
    /// This work tree's own git dir (differs per linked worktree).
    pub git_dir: PathBuf,
    /// The shared git dir.
    pub common: PathBuf,
}

fn base(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).env("LC_ALL", "C").env("GIT_OPTIONAL_LOCKS", "0");
    cmd
}

pub fn run_with(dir: &Path, args: &[&str], envs: &[(&str, &str)], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cmd = base(dir);
    cmd.args(args).envs(envs.iter().copied());
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| Error::new("GIT_MISSING", format!("git could not be started ({e})")))?;
    if let Some(input) = stdin {
        child.stdin.take().expect("piped").write_all(input).map_err(|e| Error::io("writing to git", e))?;
    }
    let out = child.wait_with_output().map_err(|e| Error::io("waiting for git", e))?;
    if !out.status.success() {
        let what = args.first().copied().unwrap_or("git");
        return Err(Error::new(
            "GIT_FAILED",
            format!("git {what} failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
        ));
    }
    Ok(out.stdout)
}

pub fn run(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    run_with(dir, args, &[], None)
}

pub fn text(dir: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&run(dir, args)?).trim().to_string())
}

pub fn dirs(dir: &Path) -> Result<Dirs> {
    let out = base(dir)
        .args(["rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::new("GIT_MISSING", format!("git could not be started ({e})")))?;
    if !out.status.success() {
        return Err(Error::new("NOT_A_REPO", format!("{} is not inside a git work tree", dir.display()))
            .with_next("run it inside a git repository, or pass --repo <dir>"));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut lines = text.lines();
    let top = PathBuf::from(lines.next().unwrap_or(""));
    let git_dir = PathBuf::from(lines.next().unwrap_or(""));
    let common_raw = PathBuf::from(lines.next().unwrap_or(""));
    let common = if common_raw.is_absolute() { common_raw } else { top.join(common_raw) };
    let common = std::fs::canonicalize(&common).unwrap_or(common);
    Ok(Dirs { top, git_dir, common })
}

fn check_rev(rev: &str) -> Result<()> {
    if rev.is_empty() || rev.starts_with('-') {
        return Err(Error::new("TREE_NOT_FOUND", format!("{rev:?} is not a revision")));
    }
    Ok(())
}

/// The files in the working tree (tracked changes and untracked files, minus what .gitignore
/// excludes) as a tree, built in a throwaway index so the real one is untouched.
/// Agents' unsealed declarations are never part of a change (see `inbox`).
const INBOX: &str = ".05/inbox";

pub fn worktree_tree(top: &Path) -> Result<String> {
    let dirs = dirs(top)?;
    let index = dirs.git_dir.join(format!("05-wt-index-{}", std::process::id()));
    let index_str = index.to_string_lossy().to_string();
    let env = [("GIT_INDEX_FILE", index_str.as_str())];
    let result = (|| -> Result<String> {
        // Start from the real index so git's stat cache is reused and unchanged files are not
        // read again; fall back to HEAD when there is no index yet.
        if std::fs::copy(dirs.git_dir.join("index"), &index).is_err() && head_commit(top).is_some() {
            run_with(top, &["read-tree", "HEAD"], &env, None)?;
        }
        run_with(top, &["add", "-A", "--", "."], &env, None)?;
        run_with(top, &["rm", "-r", "-q", "--cached", "--ignore-unmatch", "--", INBOX], &env, None)?;
        Ok(String::from_utf8_lossy(&run_with(top, &["write-tree"], &env, None)?).trim().to_string())
    })();
    let _ = std::fs::remove_file(&index);
    result.map_err(|e| {
        let denied = e.message.contains("Operation not permitted") || e.message.contains("Permission denied");
        let err = Error::new("TREE_NOT_FOUND", e.message);
        if denied {
            // An agent sandbox (Codex's workspace-write) makes .git read-only.
            err.with_next("looking at the working tree needs to write in .git; inside an agent sandbox, leave it to 05's hooks, which check the change when the agent stops")
        } else {
            err
        }
    })
}

/// What to look at when the person did not say: the staged files if anything is staged,
/// otherwise the working tree if it differs from HEAD, otherwise the (empty) index.
pub fn default_spec(top: &Path) -> &'static str {
    let staged = run(top, &["diff", "--cached", "--quiet"]).is_err();
    if staged {
        return "index";
    }
    let dirty = run(top, &["diff", "--quiet"]).is_err() || text(top, &["ls-files", "--others", "--exclude-standard"]).is_ok_and(|o| o.lines().any(|l| !l.starts_with(".05/inbox/")));
    if dirty { "worktree" } else { "index" }
}

/// Resolve `spec` to a tree id. `"index"` writes the staged files as a tree; `"worktree"` the
/// working tree.
pub fn resolve_tree(top: &Path, spec: &str) -> Result<String> {
    if spec == "index" {
        return text(top, &["write-tree"]).map_err(|e| Error::new("TREE_NOT_FOUND", e.message));
    }
    if spec == "worktree" {
        return worktree_tree(top);
    }
    check_rev(spec)?;
    text(top, &["rev-parse", "--verify", "--quiet", &format!("{spec}^{{tree}}")])
        .map_err(|_| Error::new("TREE_NOT_FOUND", format!("cannot resolve {spec:?}: no such commit or tree")))
}

pub fn resolve_commit(top: &Path, spec: &str) -> Option<String> {
    check_rev(spec).ok()?;
    text(top, &["rev-parse", "--verify", "--quiet", &format!("{spec}^{{commit}}")]).ok()
}

pub fn head_commit(top: &Path) -> Option<String> {
    resolve_commit(top, "HEAD")
}

pub fn current_branch(top: &Path) -> Option<String> {
    text(top, &["symbolic-ref", "--quiet", "--short", "HEAD"]).ok().filter(|b| !b.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// A added, M modified, D deleted, T type changed.
    pub status: char,
    pub path: String,
}

/// Paths that differ between two trees. `base` of `None` means "from nothing".
pub fn changed(top: &Path, base: Option<&str>, target: &str) -> Result<Vec<Change>> {
    let base = base.unwrap_or(EMPTY_TREE);
    let raw = run(top, &["diff-tree", "-r", "--no-renames", "-z", "--name-status", base, target])?;
    let mut parts = raw.split(|b| *b == 0).filter(|p| !p.is_empty());
    let mut out = Vec::new();
    while let (Some(status), Some(path)) = (parts.next(), parts.next()) {
        out.push(Change { status: status[0] as char, path: String::from_utf8_lossy(path).to_string() });
    }
    Ok(out)
}

/// Paths that were moved (unchanged content) between two trees: the old paths.
pub fn renamed_from(top: &Path, base: Option<&str>, target: &str) -> Vec<String> {
    let base = base.unwrap_or(EMPTY_TREE);
    let Ok(raw) = run(top, &["diff-tree", "-r", "-M100%", "-z", "--name-status", base, target]) else { return Vec::new() };
    let parts: Vec<String> = raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).to_string()).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        if parts[i].starts_with('R') && i + 2 < parts.len() + 1 {
            out.push(parts[i + 1].clone());
            i += 3;
        } else {
            i += 2;
        }
    }
    out
}

/// Like [`diff_lines`], with each line's number: removed lines numbered in the base, added lines
/// in the target.
pub fn diff_hunks(top: &Path, base: Option<&str>, target: &str, path: &str) -> Result<(Vec<(usize, String)>, Vec<(usize, String)>)> {
    let base = base.unwrap_or(EMPTY_TREE);
    let raw = run(top, &["diff-tree", "-r", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base, target, "--", path])?;
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    let (mut old, mut new) = (0usize, 0usize);
    let start = |spec: &str| spec.split(',').next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(0);
    let mut in_header = true;
    for line in String::from_utf8_lossy(&raw).lines() {
        if line.starts_with("diff --git") {
            in_header = true;
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            in_header = false;
            let mut parts = rest.split_whitespace();
            old = parts.next().map(|p| start(p.trim_start_matches('-'))).unwrap_or(0);
            new = parts.next().map(|p| start(p.trim_start_matches('+'))).unwrap_or(0);
        } else if in_header {
            continue;
        } else if let Some(l) = line.strip_prefix('+') {
            added.push((new, l.to_string()));
            new += 1;
        } else if let Some(l) = line.strip_prefix('-') {
            removed.push((old, l.to_string()));
            old += 1;
        }
    }
    Ok((removed, added))
}

/// The lines a change removed from and added to one file: `(removed, added)`.
pub fn diff_lines(top: &Path, base: Option<&str>, target: &str, path: &str) -> Result<(Vec<String>, Vec<String>)> {
    let base = base.unwrap_or(EMPTY_TREE);
    let raw = run(top, &["diff-tree", "-r", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base, target, "--", path])?;
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    // `---`/`+++` are headers only before a file's first hunk; inside a hunk they are content.
    let mut in_header = true;
    for line in String::from_utf8_lossy(&raw).lines() {
        if line.starts_with("diff --git") {
            in_header = true;
            continue;
        }
        if line.starts_with("@@") {
            in_header = false;
            continue;
        }
        if in_header {
            continue;
        }
        if let Some(l) = line.strip_prefix('+') {
            added.push(l.to_string());
        } else if let Some(l) = line.strip_prefix('-') {
            removed.push(l.to_string());
        }
    }
    Ok((removed, added))
}

/// A file's bytes as they were in a tree or commit.
pub fn blob_at(top: &Path, rev: &str, path: &str) -> Option<Vec<u8>> {
    check_rev(rev).ok()?;
    run(top, &["cat-file", "blob", &format!("{rev}:{path}")]).ok()
}

pub fn list_refs(top: &Path, patterns: &[&str]) -> Vec<String> {
    let mut args = vec!["for-each-ref", "--format=%(refname)"];
    args.extend_from_slice(patterns);
    text(top, &args).map(|t| t.lines().map(str::to_string).collect()).unwrap_or_default()
}

/// Files under a directory in a commit or tree, as full paths.
pub fn ls_dir(top: &Path, rev: &str, dir: &str) -> Vec<String> {
    run(top, &["ls-tree", "-r", "--name-only", "-z", rev, "--", &format!("{dir}/")])
        .map(|raw| raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).to_string()).collect())
        .unwrap_or_default()
}

pub fn count_commits(top: &Path, base: &str, head: &str) -> usize {
    text(top, &["rev-list", "--count", &format!("{base}..{head}")]).ok().and_then(|n| n.parse().ok()).unwrap_or(0)
}

pub fn merge_base(top: &Path, a: &str, b: &str) -> Option<String> {
    text(top, &["merge-base", a, b]).ok().filter(|s| !s.is_empty())
}

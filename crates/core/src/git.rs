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

/// Lines added and removed per path between two trees. A binary file counts 0 and 0.
pub fn numstat(top: &Path, base: Option<&str>, target: &str) -> Result<std::collections::HashMap<String, (u64, u64)>> {
    let base = base.unwrap_or(EMPTY_TREE);
    let raw = run(top, &["diff-tree", "-r", "--no-renames", "-z", "--numstat", base, target])?;
    let mut out = std::collections::HashMap::new();
    for record in raw.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let mut fields = record.splitn(3, |b| *b == b'\t');
        let (Some(added), Some(removed), Some(path)) = (fields.next(), fields.next(), fields.next()) else { continue };
        let count = |f: &[u8]| std::str::from_utf8(f).ok().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0);
        out.insert(String::from_utf8_lossy(path).to_string(), (count(added), count(removed)));
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

/// Removed and added lines of a patch, numbered: removed lines in the base, added lines in the
/// target.
pub type Hunks = (Vec<(usize, String)>, Vec<(usize, String)>);

fn parse_hunks(patch: &str) -> Hunks {
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    let (mut old, mut new) = (0usize, 0usize);
    let start = |spec: &str| spec.split(',').next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(0);
    let mut in_header = true;
    for line in patch.lines() {
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
    (removed, added)
}

/// Like [`diff_lines`], with each line's number: removed lines numbered in the base, added lines
/// in the target.
pub fn diff_hunks(top: &Path, base: Option<&str>, target: &str, path: &str) -> Result<Hunks> {
    let base = base.unwrap_or(EMPTY_TREE);
    let raw = run(top, &["diff-tree", "-r", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base, target, "--", path])?;
    Ok(parse_hunks(&String::from_utf8_lossy(&raw)))
}

/// [`diff_hunks`] for the `wanted` files of a change, from one `git diff-tree`: a change of
/// thousands of files costs one process, not thousands. The patch is read as it streams and only
/// wanted files' lines are kept, so a huge lockfile in the same change costs no memory. A path
/// git quotes in the header (a quote, a backslash or a control character in its name) is left
/// out; ask [`diff_hunks`] for it.
pub fn hunks_by_path(top: &Path, base: Option<&str>, target: &str, wanted: &std::collections::HashSet<String>) -> Result<std::collections::HashMap<String, Hunks>> {
    use std::io::{BufRead, BufReader};
    let base_tree = base.unwrap_or(EMPTY_TREE);
    let mut cmd = self::base(top);
    cmd.args(["-c", "core.quotePath=false", "diff-tree", "-r", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base_tree, target]);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| Error::new("GIT_MISSING", format!("git could not be started ({e})")))?;
    let reader = BufReader::new(child.stdout.take().expect("piped"));
    let mut out: std::collections::HashMap<String, Hunks> = std::collections::HashMap::new();
    // The file whose section is being read, when it is wanted, and its patch so far.
    let mut current: Option<(String, String)> = None;
    let finish = |current: &mut Option<(String, String)>, out: &mut std::collections::HashMap<String, Hunks>| {
        if let Some((path, patch)) = current.take() {
            // A type change (a file replaced by a symlink, say) is two sections for one path: a
            // deletion and an addition. Keep both.
            let (removed, added) = parse_hunks(&patch);
            let entry = out.entry(path).or_default();
            entry.0.extend(removed);
            entry.1.extend(added);
        }
    };
    for raw in reader.split(b'\n') {
        let raw = raw.map_err(|e| Error::io("reading from git", e))?;
        let line = String::from_utf8_lossy(&raw);
        if let Some(header) = line.strip_prefix("diff --git ") {
            finish(&mut current, &mut out);
            current = header_path(header).filter(|p| wanted.contains(p)).map(|p| (p, String::new()));
        }
        if let Some((_, patch)) = current.as_mut() {
            patch.push_str(&line);
            patch.push('\n');
        }
    }
    finish(&mut current, &mut out);
    let status = child.wait().map_err(|e| Error::io("waiting for git", e))?;
    if !status.success() {
        return Err(Error::new("GIT_FAILED", "git diff-tree failed"));
    }
    Ok(out)
}

/// The path in a `diff --git a/P b/P` header (no renames: the same P twice, so 2P + 5
/// characters), or `None` for a quoted path.
fn header_path(header: &str) -> Option<String> {
    if header.starts_with('"') || header.len() < 5 || (header.len() - 5) % 2 != 0 {
        return None;
    }
    let n = (header.len() - 5) / 2;
    let (a, b) = (header.get(2..2 + n)?, header.get(2 + n + 3..)?);
    (header.starts_with("a/") && header.get(2 + n..2 + n + 3) == Some(" b/") && a == b).then(|| a.to_string())
}

/// The bytes of many blobs, each named `rev:path`; `None` for one that does not exist.
pub fn blobs(top: &Path, specs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    blobs_with(top, specs, |b| b.to_vec())
}

/// Each blob named `rev:path`, handed to `f` as it is read, from one `git cat-file --batch`;
/// only `f`'s answer is kept, so reading thousands of large files costs no memory. `None` for a
/// blob that does not exist. Requests are written from another thread, so a large answer cannot
/// stall git while it is still being asked. A path with a newline in it cannot be asked for in
/// batch mode and is read on its own.
pub fn blobs_with<T>(top: &Path, specs: &[String], mut f: impl FnMut(&[u8]) -> T) -> Result<Vec<Option<T>>> {
    use std::io::{BufRead, BufReader, Read};
    let batched: Vec<usize> = (0..specs.len()).filter(|&i| !specs[i].contains('\n')).collect();
    let mut out: Vec<Option<T>> = std::iter::repeat_with(|| None).take(specs.len()).collect();
    for (i, spec) in specs.iter().enumerate().filter(|(_, s)| s.contains('\n')) {
        if let Some((rev, path)) = spec.split_once(':') {
            out[i] = blob_at(top, rev, path).map(|b| f(&b));
        }
    }
    if batched.is_empty() {
        return Ok(out);
    }
    let mut cmd = base(top);
    cmd.args(["cat-file", "--batch"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| Error::new("GIT_MISSING", format!("git could not be started ({e})")))?;
    let mut stdin = child.stdin.take().expect("piped");
    let input: String = batched.iter().map(|&i| format!("{}\n", specs[i])).collect();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(input.as_bytes());
    });
    let mut reader = BufReader::new(child.stdout.take().expect("piped"));
    let mut answered = 0;
    for &i in &batched {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(|e| Error::io("reading from git", e))? == 0 {
            break;
        }
        answered += 1;
        // `<oid> <type> <size>` for an object, `<request> missing` (or `ambiguous`) otherwise. The
        // request may hold spaces; an object line never does.
        let fields: Vec<&str> = header.trim_end_matches('\n').split(' ').collect();
        let object = match fields.as_slice() {
            [oid, kind, size] if oid.len() >= 40 && oid.bytes().all(|b| b.is_ascii_hexdigit()) => size.parse::<usize>().ok().map(|n| (*kind == "blob", n)),
            _ => None,
        };
        if let Some((is_blob, size)) = object {
            let mut body = vec![0u8; size + 1];
            reader.read_exact(&mut body).map_err(|e| Error::io("reading from git", e))?;
            if is_blob {
                out[i] = Some(f(&body[..size]));
            }
        }
    }
    let _ = writer.join();
    let _ = child.wait();
    if answered != batched.len() {
        return Err(Error::new("GIT_FAILED", "git cat-file stopped before answering every request"));
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numstat_counts_lines_and_treats_binary_as_zero() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        run(top, &["init", "-q"]).unwrap();
        std::fs::write(top.join("a.txt"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(top.join("b.bin"), [0u8, 1, 2, 0, 255]).unwrap();
        run(top, &["add", "-A"]).unwrap();
        let tree = text(top, &["write-tree"]).unwrap();
        let counts = numstat(top, None, &tree).unwrap();
        assert_eq!(counts.get("a.txt"), Some(&(3, 0)));
        assert_eq!(counts.get("b.bin"), Some(&(0, 0)));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn blobs_reads_many_files_in_one_go_and_says_which_are_missing() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        run(top, &["init", "-q"]).unwrap();
        // Big enough that git's output fills a pipe while we are still asking.
        let big = "x".repeat(200_000);
        for i in 0..50 {
            std::fs::write(top.join(format!("f{i}.rs")), format!("{i}\n{big}")).unwrap();
        }
        run(top, &["add", "-A"]).unwrap();
        let tree = text(top, &["write-tree"]).unwrap();
        let mut specs: Vec<String> = (0..50).map(|i| format!("{tree}:f{i}.rs")).collect();
        specs.push(format!("{tree}:not here 12"));
        specs.push(format!("{tree}:nope.rs"));
        let got = blobs(top, &specs).unwrap();
        assert_eq!(got.len(), 52);
        assert!(got[50].is_none(), "a missing path with spaces and a number");
        assert!(got[7].as_deref().unwrap().starts_with(b"7\nxxx"));
        assert_eq!(got[7].as_ref().unwrap().len(), 2 + 200_000);
        assert!(got[51].is_none());
    }

    #[test]
    fn a_newline_in_a_file_name_reads_that_file_not_its_lookalike() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        run(top, &["init", "-q"]).unwrap();
        std::fs::write(top.join("new\nline.rs"), "with newline").unwrap();
        std::fs::write(top.join("new line.rs"), "with space").unwrap();
        run(top, &["add", "-A"]).unwrap();
        let tree = text(top, &["write-tree"]).unwrap();
        let got = blobs(top, &[format!("{tree}:new\nline.rs"), format!("{tree}:new line.rs")]).unwrap();
        assert_eq!(got[0].as_deref(), Some(&b"with newline"[..]));
        assert_eq!(got[1].as_deref(), Some(&b"with space"[..]));
    }

    #[test]
    fn blobs_with_hands_each_blob_to_a_function_and_keeps_only_its_answer() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        run(top, &["init", "-q"]).unwrap();
        std::fs::write(top.join("a.rs"), "12345").unwrap();
        run(top, &["add", "-A"]).unwrap();
        let tree = text(top, &["write-tree"]).unwrap();
        let got = blobs_with(top, &[format!("{tree}:a.rs"), format!("{tree}:gone.rs")], |b| b.len()).unwrap();
        assert_eq!(got, vec![Some(5), None]);
    }

    #[test]
    fn hunks_for_a_whole_change_match_the_per_file_answer() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        run(top, &["init", "-q"]).unwrap();
        std::fs::create_dir_all(top.join("dir with space")).unwrap();
        std::fs::write(top.join("a.rs"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(top.join("dir with space/b.rs"), "keep\n").unwrap();
        run(top, &["add", "-A"]).unwrap();
        let base = text(top, &["write-tree"]).unwrap();
        std::fs::write(top.join("a.rs"), "one\n--- not a header\nthree\nfour\n").unwrap();
        std::fs::write(top.join("dir with space/b.rs"), "keep\nmore\n").unwrap();
        std::fs::write(top.join("c.rs"), "new\n").unwrap();
        // A file replaced by a symlink: git prints a deletion and an addition for the one path.
        std::fs::remove_file(top.join("a.rs")).unwrap();
        std::os::unix::fs::symlink("c.rs", top.join("a.rs")).unwrap();
        run(top, &["add", "-A"]).unwrap();
        let target = text(top, &["write-tree"]).unwrap();
        let wanted: std::collections::HashSet<String> = ["a.rs", "dir with space/b.rs", "c.rs"].iter().map(|p| p.to_string()).collect();
        let all = hunks_by_path(top, Some(&base), &target, &wanted).unwrap();
        for path in ["a.rs", "dir with space/b.rs", "c.rs"] {
            assert_eq!(all.get(path), Some(&diff_hunks(top, Some(&base), &target, path).unwrap()), "{path}");
        }
        assert_eq!(all["a.rs"].0.len(), 3, "the deleted file's lines are kept: {:?}", all["a.rs"]);
        assert_eq!(all.len(), 3);
        // Only the files asked for are kept.
        let one: std::collections::HashSet<String> = ["c.rs".to_string()].into();
        let some = hunks_by_path(top, Some(&base), &target, &one).unwrap();
        assert_eq!(some.keys().collect::<Vec<_>>(), ["c.rs"]);
    }
}

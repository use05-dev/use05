use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::RunnerError;

fn git(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).env("LC_ALL", "C").env("GIT_OPTIONAL_LOCKS", "0");
    cmd
}

/// Run git and return stdout. `what` names the step for error messages.
pub(crate) fn output(repo: &Path, args: &[&str], what: &'static str) -> Result<Vec<u8>, RunnerError> {
    let out = git(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(RunnerError::GitMissing)?;
    if !out.status.success() {
        return Err(RunnerError::GitFailed {
            what,
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

pub(crate) fn text(repo: &Path, args: &[&str], what: &'static str) -> Result<String, RunnerError> {
    Ok(String::from_utf8_lossy(&output(repo, args, what)?).trim().to_string())
}

/// The top-level directory of the work tree that contains `dir`.
pub(crate) fn toplevel(dir: &Path) -> Result<PathBuf, RunnerError> {
    let out = git(dir)
        .args(["rev-parse", "--show-toplevel"])
        .stdin(Stdio::null())
        .output()
        .map_err(RunnerError::GitMissing)?;
    if !out.status.success() {
        // Only "not a repository" means that; anything else is git's own message (see core's `dirs`).
        let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !why.is_empty() && !why.contains("not a git repository") {
            return Err(RunnerError::GitFailed { what: "finding the repository", stderr: why });
        }
        return Err(RunnerError::NotARepo(dir.display().to_string()));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

/// Resolve `spec` to a tree object id. `"index"` means the staged content.
pub(crate) fn resolve_tree(repo: &Path, spec: &str) -> Result<String, RunnerError> {
    if spec == "index" {
        return text(repo, &["write-tree"], "writing the index as a tree").map_err(|e| match e {
            RunnerError::GitFailed { stderr, .. } => RunnerError::BadTree { spec: spec.into(), reason: stderr },
            other => other,
        });
    }
    if spec == "worktree" {
        return worktree_tree(repo);
    }
    // A leading dash would be read by git as an option.
    if spec.is_empty() || spec.starts_with('-') {
        return Err(RunnerError::BadTree { spec: spec.into(), reason: "not a revision".into() });
    }
    let rev = format!("{spec}^{{tree}}");
    text(repo, &["rev-parse", "--verify", "--quiet", &rev], "resolving the tree").map_err(|e| match e {
        RunnerError::GitFailed { .. } => RunnerError::BadTree {
            spec: spec.into(),
            reason: "no such commit or tree".into(),
        },
        other => other,
    })
}

/// The working tree as a tree object, built in a throwaway index.
fn worktree_tree(repo: &Path) -> Result<String, RunnerError> {
    let git_dir = text(repo, &["rev-parse", "--absolute-git-dir"], "finding the git directory")?;
    let index = Path::new(git_dir.trim()).join(format!("05-wt-index-{}", std::process::id()));
    let run = |args: &[&str]| -> Result<String, RunnerError> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_INDEX_FILE", &index)
            .env("LC_ALL", "C")
            .output()
            .map_err(|e| RunnerError::GitFailed { what: "starting git".into(), stderr: e.to_string() })?;
        if !out.status.success() {
            return Err(RunnerError::GitFailed { what: "building the working tree".into(), stderr: String::from_utf8_lossy(&out.stderr).trim().to_string() });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let result = (|| {
        // Reuse the real index (and its stat cache) so unchanged files are not read again.
        if std::fs::copy(Path::new(git_dir.trim()).join("index"), &index).is_err() && text(repo, &["rev-parse", "--verify", "--quiet", "HEAD"], "checking for HEAD").is_ok() {
            run(&["read-tree", "HEAD"])?;
        }
        // Agents' unsealed declarations (.05/inbox) are never part of a change.
        run(&["add", "-A", "--", "."])?;
        run(&["rm", "-r", "-q", "--cached", "--ignore-unmatch", "--", ".05/inbox"])?;
        run(&["write-tree"])
    })();
    let _ = std::fs::remove_file(&index);
    result
}

/// A long-lived `git cat-file --batch` process for reading blobs by id.
pub(crate) struct BlobReader {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl BlobReader {
    pub(crate) fn start(repo: &Path) -> Result<BlobReader, RunnerError> {
        let mut child = git(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(RunnerError::GitMissing)?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = std::io::BufReader::new(child.stdout.take().expect("piped"));
        Ok(BlobReader { child, stdin, stdout })
    }

    /// Read one blob. Requests and responses alternate, so the pipes cannot deadlock.
    pub(crate) fn read(&mut self, oid: &str) -> Result<Vec<u8>, RunnerError> {
        use std::io::{BufRead, Read, Write};
        let io = RunnerError::io("reading a blob from git");
        writeln!(self.stdin, "{oid}").map_err(RunnerError::io("asking git for a blob"))?;
        self.stdin.flush().map_err(RunnerError::io("asking git for a blob"))?;
        let mut header = String::new();
        self.stdout.read_line(&mut header).map_err(RunnerError::io("reading a blob header"))?;
        let mut parts = header.split_whitespace();
        let (_, kind, size) = (parts.next(), parts.next(), parts.next());
        let (Some(kind), Some(size)) = (kind, size) else {
            return Err(RunnerError::GitFailed {
                what: "reading a blob",
                stderr: format!("object {oid} is missing"),
            });
        };
        if kind != "blob" {
            return Err(RunnerError::GitFailed { what: "reading a blob", stderr: format!("object {oid} is a {kind}") });
        }
        let size: usize = size.parse().map_err(|_| RunnerError::GitFailed {
            what: "reading a blob",
            stderr: format!("unreadable size for {oid}"),
        })?;
        let mut data = vec![0u8; size];
        self.stdout.read_exact(&mut data).map_err(io)?;
        let mut newline = [0u8; 1];
        self.stdout.read_exact(&mut newline).map_err(RunnerError::io("reading a blob trailer"))?;
        Ok(data)
    }
}

impl Drop for BlobReader {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

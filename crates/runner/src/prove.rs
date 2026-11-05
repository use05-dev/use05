use std::path::PathBuf;
use std::time::Duration;

use use05_receipt::{Command, Evidence, Runner, Statement};

use crate::error::RunnerError;
use crate::exec;
use crate::git;
use crate::time::now_rfc3339;
use crate::tree::materialize;

/// Which tree, and the digest of its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeIdentity {
    /// The git tree object id.
    pub oid: String,
    /// SHA-256 over the tree's contents; see `tree.rs`.
    pub sha256: String,
}

pub struct ProveOptions {
    /// A directory inside the repository.
    pub repo: PathBuf,
    /// `"index"` for the staged content, or any commit or tree revision.
    pub tree: String,
    pub argv: Vec<String>,
    pub timeout: Duration,
    /// Variables to pass through to the command, as `(name, value)`. Names are recorded in the
    /// receipt; values only change its environment fingerprint.
    pub pass_env: Vec<(String, String)>,
    /// The policy check being run by name, if any; recorded in the receipt.
    pub check: Option<String>,
    /// The folder of the tree to run the command in, relative to its root (D97). Must be inside
    /// the tree; `None` runs it at the root. Recorded in the receipt.
    pub dir: Option<String>,
    /// Run the command as this OS user (through `sudo -n`) instead of the one holding the signing
    /// key, so the command cannot read the key or this process (D94). Recorded in the receipt.
    /// When it cannot run as that user, nothing runs.
    pub check_user: Option<String>,
    /// Fetch the real files for the tree's Git LFS pointers into the export, and list them in the
    /// receipt (`[evidence] lfs = true`, D96). Fails with `LFS_UNAVAILABLE` when `git lfs` is missing.
    pub lfs: bool,
}

/// The unsigned statement, plus the end of the command's output for showing to a person.
/// The output tails are never part of a receipt.
pub struct Proof {
    pub statement: Statement,
    pub stdout_tail: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    /// Why the command was not run, when the folder it was to run in is not in the tree (D97).
    /// The statement then records a failure, so the check fails by itself and the others go on.
    pub not_run: Option<String>,
}

/// Work out which tree `spec` names and digest it, without running anything.
pub fn identify(repo: &std::path::Path, spec: &str) -> Result<TreeIdentity, RunnerError> {
    let top = git::toplevel(repo)?;
    let oid = git::resolve_tree(&top, spec)?;
    let (sha256, _) = materialize(&top, &oid, None, false)?;
    Ok(TreeIdentity { oid, sha256 })
}

/// The folder `dir` of the exported tree, only if it is one: relative, with no `..`, and still
/// inside the tree once any symbolic link in it is followed.
fn folder_in(export: &std::path::Path, dir: &str) -> Result<PathBuf, RunnerError> {
    use std::path::Component;
    let relative = std::path::Path::new(dir);
    if dir.is_empty() || !relative.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir)) {
        return Err(RunnerError::DirOutside(dir.to_string()));
    }
    let root = export.canonicalize().map_err(RunnerError::io("reading the export directory"))?;
    let real = export.join(relative).canonicalize().map_err(|_| RunnerError::DirMissing(dir.to_string()))?;
    if !real.starts_with(&root) {
        return Err(RunnerError::DirOutside(dir.to_string()));
    }
    if !real.is_dir() {
        return Err(RunnerError::DirMissing(dir.to_string()));
    }
    Ok(real)
}

fn check_env_names(pass_env: &[(String, String)]) -> Result<(), RunnerError> {
    for (name, _) in pass_env {
        let ok = !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !ok {
            return Err(RunnerError::BadEnv(name.clone()));
        }
    }
    Ok(())
}

/// One exact tree, exported once, to run commands in as often as asked: a deploy's probes ask
/// again and again (D93). Each run is like a check's: no shell, a scrubbed environment with only
/// the variables passed, a time limit, and, when asked, another OS user. No statement is made.
/// The export is removed when this is dropped.
pub struct Export {
    scratch: tempfile::TempDir,
    root: PathBuf,
}

/// What one run in an [`Export`] did.
#[derive(Debug)]
pub struct Ran {
    pub status: use05_receipt::Status,
    /// The end of what it printed on stdout (the last few KB), for reading, never for storing.
    pub stdout_tail: Vec<u8>,
    /// The SHA-256 of what it printed on stdout (its first MB).
    pub stdout_sha256: String,
    pub duration_ms: u64,
}

impl Export {
    /// Export `tree` (a commit or tree revision) of the repository at `repo`; with `lfs`, Git LFS
    /// pointers are replaced by the real files, as for checks.
    pub fn new(repo: &std::path::Path, tree: &str, lfs: bool) -> Result<Export, RunnerError> {
        let top = git::toplevel(repo)?;
        let oid = git::resolve_tree(&top, tree)?;
        let scratch = tempfile::Builder::new().prefix("use05-").tempdir().map_err(RunnerError::io("creating the scratch directory"))?;
        let root = scratch.path().join("tree");
        std::fs::create_dir(&root).map_err(RunnerError::io("creating the export directory"))?;
        materialize(&top, &oid, Some(&root), lfs)?;
        Ok(Export { scratch, root })
    }

    /// Run `argv` in the folder `dir` of the export (its root when `None`). A command that fails
    /// or runs too long is a result; one that cannot be started, a folder that is not in the
    /// tree, or a check user that cannot be used is an error, and nothing ran.
    pub fn run(&self, argv: &[String], dir: Option<&str>, timeout: Duration, pass_env: &[(String, String)], check_user: Option<&str>) -> Result<Ran, RunnerError> {
        if argv.is_empty() {
            return Err(RunnerError::NoCommand);
        }
        check_env_names(pass_env)?;
        if let Some(user) = check_user {
            exec::check_user_ready(user)?;
        }
        let run_dir = match dir {
            Some(d) => folder_in(&self.root, d)?,
            None => self.root.clone(),
        };
        let (outcome, _, tails) = exec::run(argv, &self.root, &run_dir, self.scratch.path(), timeout, pass_env, check_user)?;
        Ok(Ran { status: outcome.status, stdout_tail: tails.stdout, stdout_sha256: outcome.stdout.sha256, duration_ms: outcome.duration_ms })
    }
}

/// Export the exact tree, run the command in it, and return the unsigned statement.
///
/// A command that fails is still a result: the statement records the failure. An error here
/// means no statement could be made at all.
pub fn prove(options: &ProveOptions) -> Result<Statement, RunnerError> {
    prove_with_output(options).map(|proof| proof.statement)
}

/// Like [`prove`], and also returns the end of the command's output.
pub fn prove_with_output(options: &ProveOptions) -> Result<Proof, RunnerError> {
    if options.argv.is_empty() {
        return Err(RunnerError::NoCommand);
    }
    check_env_names(&options.pass_env)?;
    if let Some(user) = &options.check_user {
        exec::check_user_ready(user)?;
    }
    let top = git::toplevel(&options.repo)?;
    let oid = git::resolve_tree(&top, &options.tree)?;

    let scratch = tempfile::Builder::new()
        .prefix("use05-")
        .tempdir()
        .map_err(RunnerError::io("creating the scratch directory"))?;
    let export = scratch.path().join("tree");
    std::fs::create_dir(&export).map_err(RunnerError::io("creating the export directory"))?;
    let (sha256, lfs) = materialize(&top, &oid, Some(&export), options.lfs)?;

    // A folder that is not in this tree (a package deleted by the change, say) fails the check: it
    // cannot pass, and the run of the other checks goes on.
    let (run_dir, not_run) = match &options.dir {
        Some(dir) => match folder_in(&export, dir) {
            Ok(real) => (real, None),
            Err(e @ (RunnerError::DirOutside(_) | RunnerError::DirMissing(_))) => (export.clone(), Some(format!("not run: {e}"))),
            Err(e) => return Err(e),
        },
        None => (export.clone(), None),
    };
    let (outcome, environment, tails) = match &not_run {
        Some(reason) => exec::not_run(scratch.path(), reason),
        None => exec::run(&options.argv, &export, &run_dir, scratch.path(), options.timeout, &options.pass_env, options.check_user.as_deref())?,
    };

    let evidence = Evidence {
        command: Command { argv: options.argv.clone(), cwd: ".".to_string(), dir: options.dir.clone() },
        environment,
        result: outcome,
        runner: Runner {
            name: "use05".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            check_user: options.check_user.clone(),
        },
        created: now_rfc3339(),
        check: options.check.clone(),
        lfs,
    };
    Ok(Proof {
        statement: Statement::for_evidence(&oid, &sha256, evidence),
        stdout_tail: tails.stdout,
        stderr_tail: tails.stderr,
        not_run,
    })
}

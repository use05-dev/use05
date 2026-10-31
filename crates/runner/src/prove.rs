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
}

/// The unsigned statement, plus the end of the command's output for showing to a person.
/// The output tails are never part of a receipt.
pub struct Proof {
    pub statement: Statement,
    pub stdout_tail: Vec<u8>,
    pub stderr_tail: Vec<u8>,
}

/// Work out which tree `spec` names and digest it, without running anything.
pub fn identify(repo: &std::path::Path, spec: &str) -> Result<TreeIdentity, RunnerError> {
    let top = git::toplevel(repo)?;
    let oid = git::resolve_tree(&top, spec)?;
    let sha256 = materialize(&top, &oid, None)?;
    Ok(TreeIdentity { oid, sha256 })
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
    for (name, _) in &options.pass_env {
        let ok = !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !ok {
            return Err(RunnerError::BadEnv(name.clone()));
        }
    }
    let top = git::toplevel(&options.repo)?;
    let oid = git::resolve_tree(&top, &options.tree)?;

    let scratch = tempfile::Builder::new()
        .prefix("use05-")
        .tempdir()
        .map_err(RunnerError::io("creating the scratch directory"))?;
    let export = scratch.path().join("tree");
    std::fs::create_dir(&export).map_err(RunnerError::io("creating the export directory"))?;
    let sha256 = materialize(&top, &oid, Some(&export))?;

    let (outcome, environment, tails) =
        exec::run(&options.argv, &export, scratch.path(), options.timeout, &options.pass_env)?;

    let evidence = Evidence {
        command: Command { argv: options.argv.clone(), cwd: ".".to_string() },
        environment,
        result: outcome,
        runner: Runner {
            name: "use05".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        },
        created: now_rfc3339(),
        check: options.check.clone(),
    };
    Ok(Proof {
        statement: Statement::for_evidence(&oid, &sha256, evidence),
        stdout_tail: tails.stdout,
        stderr_tail: tails.stderr,
    })
}

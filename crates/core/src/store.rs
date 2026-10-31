//! Receipts live on ordinary git branches, one per signer: `05-receipts/<key id>`.
//!
//! Ordinary branches travel through every git host and proxy we tried; custom refs did not.
//! One branch per signer means two people never write the same branch, so pushes do not
//! conflict. A receipt is a file at `receipts/<subject>/<hash>.json`, where the subject is a
//! tree id (evidence, outcome approvals, bypasses) or an intent digest (intent approvals).

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::git;

pub const BRANCH_DIR: &str = "05-receipts";

pub fn branch_for(signer_id: &str) -> String {
    format!("{BRANCH_DIR}/{signer_id}")
}

#[derive(Debug, Clone)]
pub struct Raw {
    /// The ref it was found on, for the audit trail.
    pub source: String,
    pub path: String,
    pub bytes: Vec<u8>,
}

fn subject_ok(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 80 && subject.chars().all(|c| c.is_ascii_hexdigit())
}

/// Store a signed receipt on the signer's branch. Returns the branch name.
pub fn put(top: &Path, subject: &str, envelope: &[u8], signer_id: &str) -> Result<String> {
    if !subject_ok(subject) || !signer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::new("STORE_BAD_KEY", "receipt subjects and key ids are hexadecimal"));
    }
    let name = format!("receipts/{subject}/{}.json", &hex::encode(Sha256::digest(envelope))[..16]);
    commit_file(top, &name, envelope, signer_id)
}

/// Keep a copy of an agent's action log on the signer's branch, at `logs/<task>.jsonl`, so it
/// travels with the receipts that seal it (D70). A newer copy replaces the older one.
pub fn put_file(top: &Path, path: &str, bytes: &[u8], signer_id: &str) -> Result<String> {
    let ok = path.strip_prefix("logs/").is_some_and(|f| f.ends_with(".jsonl") && f.trim_end_matches(".jsonl").chars().all(|c| c.is_ascii_alphanumeric()) && f.len() > ".jsonl".len());
    if !ok || !signer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::new("STORE_BAD_KEY", "only logs/<task id>.jsonl is kept on a receipts branch"));
    }
    commit_file(top, path, bytes, signer_id)
}

/// The longest copy of a file on any receipts branch (a log only ever grows).
pub fn read_file(top: &Path, path: &str) -> Option<String> {
    read_file_from(top, path, None)
}

/// The longest copy of a file on the receipts branches of these signers only. Anyone can push a
/// branch; only a signer whose seals verified is believed about a log (D70).
pub fn read_file_from(top: &Path, path: &str, signers: Option<&[String]>) -> Option<String> {
    receipt_refs(top)
        .iter()
        .filter(|r| signers.is_none_or(|ids| r.rsplit('/').next().is_some_and(|id| ids.iter().any(|s| s == id))))
        .filter_map(|r| git::blob_at(top, r, path))
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .max_by_key(String::len)
}

fn commit_file(top: &Path, name: &str, bytes: &[u8], signer_id: &str) -> Result<String> {
    let envelope = bytes;
    let branch = branch_for(signer_id);
    let full = format!("refs/heads/{branch}");
    let resolve = |r: &str| git::text(top, &["rev-parse", "--verify", "--quiet", &format!("{r}^{{commit}}")]).ok().filter(|p| !p.is_empty());
    // A fresh clone (a CI job) has only the remote's copy of this signer's branch: build on it,
    // or the next push is refused as unrelated history.
    let local = resolve(&full);
    let parent = local.clone().or_else(|| git::list_refs(top, &[&format!("refs/remotes/*/{branch}")]).first().and_then(|r| resolve(r)));

    let dirs = git::dirs(top)?;
    let index = dirs.git_dir.join(format!("05-index-{}", std::process::id()));
    let index_str = index.to_string_lossy().to_string();
    let env = [("GIT_INDEX_FILE", index_str.as_str())];
    let result = (|| -> Result<String> {
        if let Some(parent) = &parent {
            git::run_with(top, &["read-tree", parent], &env, None)?;
        }
        let blob = String::from_utf8_lossy(&git::run_with(top, &["hash-object", "-w", "--stdin"], &[], Some(envelope))?).trim().to_string();
        git::run_with(top, &["update-index", "--add", "--cacheinfo", &format!("100644,{blob},{name}")], &env, None)?;
        let tree = String::from_utf8_lossy(&git::run_with(top, &["write-tree"], &env, None)?).trim().to_string();
        if let Some(parent) = &parent {
            let parent_tree = git::text(top, &["rev-parse", &format!("{parent}^{{tree}}")])?;
            if parent_tree == tree {
                return Ok(branch.clone()); // this exact receipt is already there
            }
        }
        let commit_env = [
            ("GIT_AUTHOR_NAME", "05"), ("GIT_AUTHOR_EMAIL", "receipts@use05.dev"),
            ("GIT_COMMITTER_NAME", "05"), ("GIT_COMMITTER_EMAIL", "receipts@use05.dev"),
        ];
        let mut args = vec!["commit-tree", tree.as_str(), "-m", "05 receipt"];
        if let Some(parent) = &parent {
            args.extend(["-p", parent.as_str()]);
        }
        let commit = String::from_utf8_lossy(&git::run_with(top, &args, &commit_env, None)?).trim().to_string();
        // Compare-and-swap: if someone else moved the branch meanwhile, fail instead of losing a receipt.
        let mut update = vec!["update-ref", full.as_str(), commit.as_str()];
        // The swap compares with what the local branch held (nothing, in a fresh clone).
        update.push(local.as_deref().unwrap_or("0000000000000000000000000000000000000000"));
        git::run(top, &update)?;
        Ok(branch.clone())
    })();
    let _ = fs::remove_file(&index);
    result
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[test]
    fn a_file_put_on_the_branch_reads_back_and_a_newer_copy_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).arg(dir.path()).status().unwrap().success());
        put_file(dir.path(), "logs/9ce9a1e4.jsonl", b"one\n", "ab12").unwrap();
        assert_eq!(read_file(dir.path(), "logs/9ce9a1e4.jsonl").as_deref(), Some("one\n"));
        put_file(dir.path(), "logs/9ce9a1e4.jsonl", b"one\ntwo\n", "ab12").unwrap();
        assert_eq!(read_file(dir.path(), "logs/9ce9a1e4.jsonl").as_deref(), Some("one\ntwo\n"));
        assert!(put_file(dir.path(), "../escape", b"x", "ab12").is_err(), "only paths under logs/ are written");
    }
}

/// The remote receipts travel through: `origin` if there is one, else the only remote.
fn remote_name(top: &Path) -> Result<String> {
    let remotes = git::text(top, &["remote"])?;
    let names: Vec<&str> = remotes.lines().filter(|l| !l.is_empty()).collect();
    if names.contains(&"origin") {
        return Ok("origin".into());
    }
    match names.as_slice() {
        [only] => Ok((*only).to_string()),
        [] => Err(Error::new("NO_REMOTE", "this repository has no remote to push receipts to").with_next("git remote add origin <url>")),
        _ => Err(Error::new("NO_REMOTE", "several remotes and none is called origin").with_next("push the branch yourself: git push <remote> <branch>")),
    }
}

/// Push a receipts branch. Never forced: a receipts branch only ever grows, so a refused push
/// means the remote has receipts this machine lacks, and nothing is overwritten.
pub fn push(top: &Path, branch: &str) -> Result<String> {
    if !branch.starts_with(&format!("{BRANCH_DIR}/")) {
        return Err(Error::new("STORE_BAD_KEY", "only receipts branches are pushed by 05"));
    }
    let remote = remote_name(top)?;
    let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
    git::run(top, &["push", "--quiet", &remote, &refspec]).map_err(|e| Error::new("PUSH_FAILED", format!("could not push {branch} to {remote}: {}", e.message.lines().next().unwrap_or(""))))?;
    Ok(remote)
}

/// Fetch every signer's receipts branch from the remote into remote-tracking branches.
pub fn fetch(top: &Path) -> Result<String> {
    let remote = remote_name(top)?;
    let spec = format!("+refs/heads/{BRANCH_DIR}/*:refs/remotes/{remote}/{BRANCH_DIR}/*");
    git::run(top, &["fetch", "--quiet", &remote, &spec]).map_err(|e| Error::new("FETCH_FAILED", format!("could not fetch receipts from {remote}: {}", e.message.lines().next().unwrap_or(""))))?;
    Ok(remote)
}

fn receipt_refs(top: &Path) -> Vec<String> {
    // A pattern with a wildcard must match the whole ref name, so the remote one ends in `/*`.
    git::list_refs(top, &[&format!("refs/heads/{BRANCH_DIR}"), &format!("refs/remotes/*/{BRANCH_DIR}/*")])
}

/// Every receipt filed under `subject`, from local branches and fetched remote ones.
pub fn find(top: &Path, subject: &str) -> Vec<Raw> {
    if !subject_ok(subject) {
        return Vec::new();
    }
    let dir = format!("receipts/{subject}");
    let mut out = Vec::new();
    for source in receipt_refs(top) {
        for path in git::ls_dir(top, &source, &dir) {
            if let Some(bytes) = git::blob_at(top, &source, &path) {
                out.push(Raw { source: source.clone(), path, bytes });
            }
        }
    }
    out
}

/// Every receipt on every receipts branch. Used to spot stale evidence and changed intents.
pub fn find_all(top: &Path) -> Vec<Raw> {
    let mut out = Vec::new();
    for source in receipt_refs(top) {
        for path in git::ls_dir(top, &source, "receipts") {
            if let Some(bytes) = git::blob_at(top, &source, &path) {
                out.push(Raw { source: source.clone(), path, bytes });
            }
        }
    }
    out
}

pub fn branches(top: &Path) -> Vec<String> {
    receipt_refs(top)
}

/// Read a receipt from a file, or from a git object name such as `05-receipts/<id>:receipts/...`.
pub fn read(top: &Path, what: &str) -> Result<Vec<u8>> {
    let as_file = Path::new(what);
    if as_file.is_file() {
        return fs::read(as_file).map_err(|e| Error::io(&format!("reading {what}"), e));
    }
    if what.starts_with('-') {
        return Err(Error::new("RECEIPT_NOT_FOUND", format!("{what} is neither a file nor a receipt reference")));
    }
    git::run(top, &["cat-file", "blob", what])
        .map_err(|_| Error::new("RECEIPT_NOT_FOUND", format!("{what} is neither a file nor a receipt in this repository")))
}

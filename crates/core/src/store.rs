//! Receipts live on ordinary git branches, one per signer: `05-receipts/<key id>`.
//!
//! Ordinary branches travel through every git host and proxy we tried; custom refs did not.
//! One branch per signer means two people never write the same branch, so pushes do not
//! conflict. A receipt is a file at `receipts/<subject>/<hash>.json`, where the subject is a
//! tree id (evidence, outcome approvals, bypasses) or an intent digest (intent approvals).

use std::collections::{BTreeMap, BTreeSet};
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

/// Write one record onto this signer's receipts branch. Two sessions on one machine share the
/// branch (one key), so a write can lose the race for the ref: then it is built again on the
/// branch as the other left it and swapped again, a few times, so neither record is lost.
fn commit_file(top: &Path, name: &str, bytes: &[u8], signer_id: &str) -> Result<String> {
    let mut tries = 0u64;
    loop {
        match commit_file_once(top, name, bytes, signer_id) {
            Err(e) if tries < 40 && e.message.contains("cannot lock ref") => {
                tries += 1;
                // Jittered, so writers that collided do not collide again; at most ~2 s in all.
                let jitter = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::from(d.subsec_nanos()) % 17);
                std::thread::sleep(std::time::Duration::from_millis((3 * tries).min(40) + jitter));
            }
            other => return other,
        }
    }
}

/// Temporary index files, one per write, so writes at once in one process do not share one.
static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn commit_file_once(top: &Path, name: &str, bytes: &[u8], signer_id: &str) -> Result<String> {
    let envelope = bytes;
    let branch = branch_for(signer_id);
    let full = format!("refs/heads/{branch}");
    let resolve = |r: &str| git::text(top, &["rev-parse", "--verify", "--quiet", &format!("{r}^{{commit}}")]).ok().filter(|p| !p.is_empty());
    // A fresh clone (a CI job) has only the remote's copy of this signer's branch: build on it,
    // or the next push is refused as unrelated history.
    let local = resolve(&full);
    let parent = local.clone().or_else(|| git::list_refs(top, &[&format!("refs/remotes/*/{branch}")]).first().and_then(|r| resolve(r)));

    let dirs = git::dirs(top)?;
    let index = dirs.git_dir.join(format!("05-index-{}-{}", std::process::id(), WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
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
                // This exact record is already there. A fresh clone still needs the local branch,
                // at the remote's commit, or the push that follows has nothing to send.
                if local.is_none() {
                    git::run(top, &["update-ref", full.as_str(), parent.as_str(), "0000000000000000000000000000000000000000"])?;
                }
                return Ok(branch.clone());
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

    #[test]
    fn records_written_at_once_by_several_sessions_are_all_kept() {
        // Seen with three agents at once on one machine: they share the signer's branch.
        let dir = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).arg(dir.path()).status().unwrap().success());
        let top = dir.path().to_path_buf();
        let writers: Vec<_> = (0..8)
            .map(|i| {
                let top = top.clone();
                std::thread::spawn(move || {
                    for j in 0..4 {
                        put(&top, &format!("{i:02}{j:02}"), format!("record {i} {j}").as_bytes(), "ab12").unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let listing = git::text(&top, &["ls-tree", "-r", "--name-only", "refs/heads/05-receipts/ab12"]).unwrap();
        assert_eq!(listing.lines().count(), 32, "every record is on the branch:\n{listing}");
    }

    #[test]
    fn a_record_already_on_the_remote_copy_still_leaves_a_local_branch_to_push() {
        let git = |dir: &Path, args: &[&str]| assert!(std::process::Command::new("git").arg("-C").arg(dir).args(args).status().unwrap().success(), "git {args:?}");
        let origin = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q", "--bare"]).arg(origin.path()).status().unwrap().success());
        let first = tempfile::tempdir().unwrap();
        git(first.path(), &["init", "-q"]);
        git(first.path(), &["remote", "add", "origin", origin.path().to_str().unwrap()]);
        put(first.path(), "abcd", b"the same signed record", "ab12").unwrap();
        push(first.path(), "05-receipts/ab12").unwrap();
        // A fresh clone (the next CI job) files the identical record: nothing new to commit, but
        // the branch must still exist locally, or the push that follows has nothing to send.
        let second = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["clone", "-q"]).arg(origin.path()).arg(second.path().join("r")).status().unwrap().success());
        let clone = second.path().join("r");
        put(&clone, "abcd", b"the same signed record", "ab12").unwrap();
        push(&clone, "05-receipts/ab12").expect("the branch is there to push");
    }
}

/// The remote receipts travel through: `origin` if there is one, else the only remote.
/// The remote 05 pushes to: `origin`, or the only remote there is.
pub fn remote_name(top: &Path) -> Result<String> {
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

/// How many times a refused push is merged and tried again.
const PUSH_ATTEMPTS: u32 = 5;

/// Push a receipts branch. Never forced: a receipts branch only ever grows. A push the remote
/// refuses because it holds receipts this machine lacks (two machines of one signer, or two CI
/// jobs, pushed at once) fetches them, merges them into the local branch and tries again, up to
/// five times with a short random wait. Receipts are files with unique names, so the merge never
/// conflicts. Any other failure is returned at once.
pub fn push(top: &Path, branch: &str) -> Result<String> {
    if !branch.starts_with(&format!("{BRANCH_DIR}/")) {
        return Err(Error::new("STORE_BAD_KEY", "only receipts branches are pushed by 05"));
    }
    let remote = remote_name(top)?;
    let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
    let mut attempt = 1;
    loop {
        let refused = match git::run(top, &["push", "--quiet", &remote, &refspec]) {
            Ok(_) => return Ok(remote),
            Err(e) => e,
        };
        let fail = || Error::new("PUSH_FAILED", format!("could not push {branch} to {remote}: {}", reason(&refused.message)));
        if attempt >= PUSH_ATTEMPTS || !is_non_fast_forward(&refused.message) {
            return Err(fail());
        }
        // Merge in what the remote has. If it has nothing this branch lacks, the refusal was for
        // another reason and trying again would change nothing.
        if !matches!(merge_remote(top, &remote, branch), Ok(true)) {
            return Err(fail());
        }
        std::thread::sleep(std::time::Duration::from_millis(backoff_ms(attempt)));
        attempt += 1;
    }
}

/// The line of git's error that says why, not the "To <url>" line it starts with.
fn reason(message: &str) -> &str {
    let lines: Vec<&str> = message.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    lines
        .iter()
        .find(|l| l.starts_with("fatal:") || l.starts_with("error:") || l.starts_with('!') || l.contains("rejected"))
        .or(lines.first())
        .copied()
        .unwrap_or("")
}

/// A push refused because the remote moved, by the words git uses for it.
fn is_non_fast_forward(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    ["rejected", "non-fast-forward", "fetch first"].iter().any(|w| lower.contains(w))
}

/// 50 to 400 ms, different on each machine and each attempt, so two pushers do not collide again.
fn backoff_ms(attempt: u32) -> u64 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let seed = Sha256::digest(format!("{nanos}:{}:{attempt}", std::process::id()));
    50 + u64::from_le_bytes(seed[..8].try_into().expect("eight bytes")) % 351
}

/// Fetch the remote's copy of a receipts branch and merge it into the local one, without a work
/// tree: the merge commit is built from git objects. Returns whether the local branch changed.
fn merge_remote(top: &Path, remote: &str, branch: &str) -> Result<bool> {
    let tracking = format!("refs/remotes/{remote}/{branch}");
    git::run(top, &["fetch", "--quiet", remote, &format!("+refs/heads/{branch}:{tracking}")])?;
    let theirs = git::text(top, &["rev-parse", "--verify", &format!("{tracking}^{{commit}}")])?;
    let full = format!("refs/heads/{branch}");
    let ours = git::text(top, &["rev-parse", "--verify", &format!("{full}^{{commit}}")])?;
    let base = git::merge_base(top, &ours, &theirs);
    if ours == theirs || base.as_deref() == Some(theirs.as_str()) {
        return Ok(false);
    }
    if base.as_deref() == Some(ours.as_str()) {
        // Only the remote moved: take its commit.
        git::run(top, &["update-ref", &full, &theirs, &ours])?;
        return Ok(true);
    }
    let tree = union_tree(top, &ours, &theirs)?;
    let env = [
        ("GIT_AUTHOR_NAME", "05"), ("GIT_AUTHOR_EMAIL", "receipts@use05.dev"),
        ("GIT_COMMITTER_NAME", "05"), ("GIT_COMMITTER_EMAIL", "receipts@use05.dev"),
    ];
    let merge = git::run_with(top, &["commit-tree", &tree, "-m", "05 receipts: merge", "-p", &ours, "-p", &theirs], &env, None)?;
    // Compare-and-swap: if the branch moved meanwhile, fail instead of losing a receipt.
    git::run(top, &["update-ref", &full, String::from_utf8_lossy(&merge).trim(), &ours])?;
    Ok(true)
}

/// A tree holding every file of both commits. Receipts have unique names, so the same path has
/// the same content on both sides; the one file that grows in place, an action log, keeps its
/// longer copy.
fn union_tree(top: &Path, ours: &str, theirs: &str) -> Result<String> {
    let mut files: BTreeMap<String, (String, String, u64)> = BTreeMap::new();
    for side in [ours, theirs] {
        for (path, mode, oid, size) in ls_tree(top, side)? {
            if files.get(&path).is_none_or(|(_, _, kept)| size > *kept) {
                files.insert(path, (mode, oid, size));
            }
        }
    }
    let dirs = git::dirs(top)?;
    let index = dirs.git_dir.join(format!("05-index-{}-{}", std::process::id(), WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let index_str = index.to_string_lossy().to_string();
    let env = [("GIT_INDEX_FILE", index_str.as_str())];
    let result = (|| -> Result<String> {
        let mut entries = String::new();
        for (path, (mode, oid, _)) in &files {
            entries.push_str(&format!("{mode} {oid}\t{path}\0"));
        }
        git::run_with(top, &["update-index", "--add", "-z", "--index-info"], &env, Some(entries.as_bytes()))?;
        Ok(String::from_utf8_lossy(&git::run_with(top, &["write-tree"], &env, None)?).trim().to_string())
    })();
    let _ = fs::remove_file(&index);
    result
}

/// Every file in a commit: path, mode, object id and size.
fn ls_tree(top: &Path, rev: &str) -> Result<Vec<(String, String, String, u64)>> {
    let raw = git::run(top, &["ls-tree", "-r", "-l", "-z", rev])?;
    Ok(raw
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .filter_map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            let (meta, path) = entry.split_once('\t')?;
            let mut parts = meta.split_whitespace();
            let (mode, _kind, oid, size) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
            Some((path.to_string(), mode.to_string(), oid.to_string(), size.parse().unwrap_or(0)))
        })
        .collect())
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

/// How much is stored, for `doctor`: receipts are never pruned, so they are measured instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Distinct receipt files across every receipts branch, local and fetched.
    pub receipts: usize,
    /// Distinct signers' branches.
    pub branches: usize,
    /// The receipts' size, each counted once.
    pub bytes: u64,
}

pub fn stats(top: &Path) -> Stats {
    let mut signers = BTreeSet::new();
    // A receipt on a local branch and on its fetched copy is one receipt.
    let mut receipts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for source in receipt_refs(top) {
        if let Some((_, signer)) = source.split_once(&format!("{BRANCH_DIR}/")) {
            signers.insert(signer.to_string());
        }
        for (path, _mode, oid, size) in ls_tree(top, &source).unwrap_or_default() {
            if path.starts_with("receipts/") {
                receipts.insert((path, oid), size);
            }
        }
    }
    Stats { receipts: receipts.len(), branches: signers.len(), bytes: receipts.values().sum() }
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

#[cfg(test)]
mod retry_tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git").arg("-C").arg(dir).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn bare() -> tempfile::TempDir {
        let origin = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q", "--bare"]).arg(origin.path()).status().unwrap().success());
        origin
    }

    fn clone_of(origin: &Path) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["remote", "add", "origin", origin.to_str().unwrap()]);
        dir
    }

    fn files_on(dir: &Path, rev: &str) -> Vec<String> {
        let mut files: Vec<String> = git::text(dir, &["ls-tree", "-r", "--name-only", rev]).unwrap().lines().map(str::to_string).collect();
        files.sort();
        files
    }

    #[test]
    fn a_refused_receipts_push_merges_and_retries() {
        let origin = bare();
        let (alex, bob) = (clone_of(origin.path()), clone_of(origin.path()));
        // Two machines of one signer, neither knowing of the other's receipt.
        put(alex.path(), "abcd", b"alex's receipt", "ab12").unwrap();
        put(bob.path(), "ef01", b"bob's receipt", "ab12").unwrap();
        push(alex.path(), "05-receipts/ab12").unwrap();
        push(bob.path(), "05-receipts/ab12").expect("a refused push fetches, merges and tries again");

        let remote = files_on(origin.path(), "05-receipts/ab12");
        assert_eq!(remote.len(), 2, "the remote branch holds both receipts: {remote:?}");
        assert_eq!(files_on(bob.path(), "05-receipts/ab12"), remote, "the local branch is the merge");
        let parents = git::text(bob.path(), &["rev-list", "--parents", "-n1", "05-receipts/ab12"]).unwrap();
        assert_eq!(parents.split(' ').count(), 3, "the merge commit has both parents: {parents}");
        // Nothing was forced: Alex's commit is still in the remote branch's history.
        let alex_head = git::text(alex.path(), &["rev-parse", "05-receipts/ab12"]).unwrap();
        git::text(origin.path(), &["merge-base", "--is-ancestor", &alex_head, "05-receipts/ab12"]).unwrap();
        // The working tree and index were never touched.
        assert!(git::text(bob.path(), &["status", "--porcelain"]).unwrap().is_empty());
    }

    #[test]
    fn a_refused_push_with_a_log_changed_on_both_sides_keeps_the_longer_log() {
        let origin = bare();
        let (alex, bob) = (clone_of(origin.path()), clone_of(origin.path()));
        put_file(alex.path(), "logs/9ce9a1e4.jsonl", b"one\n", "ab12").unwrap();
        put_file(bob.path(), "logs/9ce9a1e4.jsonl", b"one\ntwo\n", "ab12").unwrap();
        push(alex.path(), "05-receipts/ab12").unwrap();
        push(bob.path(), "05-receipts/ab12").unwrap();
        assert_eq!(git::blob_at(origin.path(), "05-receipts/ab12", "logs/9ce9a1e4.jsonl").unwrap(), b"one\ntwo\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_push_the_remote_declines_for_another_reason_is_not_retried() {
        use std::os::unix::fs::PermissionsExt;
        let origin = bare();
        let hook = origin.path().join("hooks/pre-receive");
        std::fs::write(&hook, "#!/bin/sh\necho 'no receipts today' >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let clone = clone_of(origin.path());
        put(clone.path(), "abcd", b"a receipt", "ab12").unwrap();
        let started = std::time::Instant::now();
        let err = push(clone.path(), "05-receipts/ab12").unwrap_err();
        assert_eq!(err.code, "PUSH_FAILED");
        assert!(started.elapsed() < std::time::Duration::from_millis(1500), "no waiting: {:?}", started.elapsed());
    }

    #[test]
    fn a_push_to_a_missing_remote_fails_at_once() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["remote", "add", "origin", "/nonexistent/remote.git"]);
        put(dir.path(), "abcd", b"a receipt", "ab12").unwrap();
        let started = std::time::Instant::now();
        assert_eq!(push(dir.path(), "05-receipts/ab12").unwrap_err().code, "PUSH_FAILED");
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
    }

    #[test]
    fn stats_count_receipts_branches_and_bytes_once_each() {
        let origin = bare();
        let alex = clone_of(origin.path());
        assert_eq!(stats(alex.path()), Stats { receipts: 0, branches: 0, bytes: 0 });
        put(alex.path(), "abcd", b"first", "ab12").unwrap();
        put(alex.path(), "ef01", b"second!", "ab12").unwrap();
        put(alex.path(), "abcd", b"third", "cd34").unwrap();
        put_file(alex.path(), "logs/9ce9a1e4.jsonl", b"a log is not a receipt\n", "ab12").unwrap();
        assert_eq!(stats(alex.path()), Stats { receipts: 3, branches: 2, bytes: 5 + 7 + 5 });
        // The same branches fetched back are the same receipts, not more of them.
        push(alex.path(), "05-receipts/ab12").unwrap();
        push(alex.path(), "05-receipts/cd34").unwrap();
        fetch(alex.path()).unwrap();
        assert_eq!(stats(alex.path()), Stats { receipts: 3, branches: 2, bytes: 17 });
    }
}

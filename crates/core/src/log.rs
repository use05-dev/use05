//! The local record of what an agent did: an append-only, hash-chained JSON-lines file.
//!
//! It records events (which tool, which paths, which decision), never file contents or prompts.
//! The chain makes edits and deletions in the middle detectable. It cannot stop a same-user
//! process from rewriting the whole file, and it says so: this is a forensic aid, not a seal.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::time::now_rfc3339;

pub fn path_for(state_dir: &Path, task_id: &str) -> PathBuf {
    state_dir.join("log").join(format!("{task_id}.jsonl"))
}

fn line_hash(prev: &str, seq: u64, t: &str, event: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(seq.to_string().as_bytes());
    h.update(t.as_bytes());
    h.update(serde_json::to_vec(event).expect("event serialises"));
    hex::encode(h.finalize())
}

/// The last line's `(seq, hash)`, or the start of a chain.
fn tail(path: &Path) -> (u64, String) {
    let text = fs::read_to_string(path).unwrap_or_default();
    match text.lines().last().and_then(|l| serde_json::from_str::<Value>(l).ok()) {
        Some(v) => (v["seq"].as_u64().unwrap_or(0), v["hash"].as_str().unwrap_or("").to_string()),
        None => (0, String::new()),
    }
}

pub fn append(state_dir: &Path, task_id: &str, event: Value) -> Result<()> {
    append_line(state_dir, task_id, event, now_rfc3339())
}

/// Like [`append`], at a given time. For tests that need a history.
pub fn append_at(state_dir: &Path, task_id: &str, event: Value, secs: u64) -> Result<()> {
    append_line(state_dir, task_id, event, crate::time::rfc3339(secs))
}

/// When anything was last recorded for a task, from the log file's own time: no parsing, so
/// it stays cheap on the hook path however long the log grows.
pub fn last_activity(state_dir: &Path, task_id: &str) -> u64 {
    fs::metadata(path_for(state_dir, task_id)).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
}

/// Files a task's agent edited, with when: every finished edit, and every edit a hook let through.
pub fn edited(state_dir: &Path, task_id: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    for line in read(state_dir, task_id) {
        let event = &line["event"];
        let done = event["event"] == "tool_done" || (event["event"] == "tool" && event["decision"] != "deny");
        let Some(at) = line["t"].as_str().and_then(crate::time::parse_rfc3339) else { continue };
        if done {
            for p in event["paths"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                out.push((at, p.to_string()));
            }
        }
    }
    out
}

fn append_line(state_dir: &Path, task_id: &str, event: Value, t: String) -> Result<()> {
    let path = path_for(state_dir, task_id);
    fs::create_dir_all(path.parent().expect("has parent")).map_err(|e| Error::io("creating the log directory", e))?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| Error::io("opening the log", e))?;
    // Hooks for parallel tool calls run at once: read the tail and append under one lock, or two
    // lines would claim the same place in the chain. The lock goes with the file when it closes.
    lock(&file);
    let (seq, prev) = tail(&path);
    let seq = seq + 1;
    let hash = line_hash(&prev, seq, &t, &event);
    let line = json!({ "seq": seq, "t": t, "prev": prev, "event": event, "hash": hash });
    writeln!(file, "{line}").map_err(|e| Error::io("writing the log", e))
}

#[allow(unsafe_code)]
fn lock(file: &fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: flock on a descriptor this function borrows; it only blocks until the lock is ours.
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX);
        }
    }
    #[cfg(not(unix))]
    let _ = file;
}

pub fn read(state_dir: &Path, task_id: &str) -> Vec<Value> {
    fs::read_to_string(path_for(state_dir, task_id))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Chain {
    Intact(usize),
    /// The first line (1-based) that does not follow from the one before it.
    Broken(usize),
}

pub fn verify(state_dir: &Path, task_id: &str) -> Chain {
    verify_text(&fs::read_to_string(path_for(state_dir, task_id)).unwrap_or_default())
}

/// The last line's `(seq, chain hash)`: what a seal records.
pub fn head(state_dir: &Path, task_id: &str) -> Option<(u64, String)> {
    let (seq, hash) = tail(&path_for(state_dir, task_id));
    (seq > 0).then_some((seq, hash))
}

/// The chain hash of line `seq` in a copy of a log.
pub fn hash_at(text: &str, seq: u64) -> Option<String> {
    let line = text.lines().nth(seq.checked_sub(1)? as usize)?;
    serde_json::from_str::<Value>(line).ok()?["hash"].as_str().map(str::to_string)
}

/// Check a copy of a log, wherever it came from (this machine, or a receipts branch).
pub fn verify_text(text: &str) -> Chain {
    let mut prev = String::new();
    let mut count = 0;
    for (index, line) in text.lines().enumerate() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return Chain::Broken(index + 1) };
        let (seq, t) = (v["seq"].as_u64().unwrap_or(0), v["t"].as_str().unwrap_or(""));
        let ok = v["prev"].as_str() == Some(prev.as_str())
            && seq == index as u64 + 1
            && v["hash"].as_str() == Some(line_hash(&prev, seq, t, &v["event"]).as_str());
        if !ok {
            return Chain::Broken(index + 1);
        }
        prev = v["hash"].as_str().unwrap_or("").to_string();
        count += 1;
    }
    Chain::Intact(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_from_parallel_hooks_keep_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        append(&path, "t1", json!({ "tool": "Edit", "paths": [format!("f{n}-{i}")] })).unwrap();
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(verify(dir.path(), "t1"), Chain::Intact(160));
    }

    #[test]
    fn the_head_names_the_last_line_and_a_seal_can_be_checked_against_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(head(dir.path(), "t1"), None);
        for i in 0..3 {
            append(dir.path(), "t1", json!({ "tool": "Edit", "paths": [format!("f{i}")] })).unwrap();
        }
        let (seq, hash) = head(dir.path(), "t1").unwrap();
        assert_eq!(seq, 3);
        let text = std::fs::read_to_string(path_for(dir.path(), "t1")).unwrap();
        assert_eq!(verify_text(&text), Chain::Intact(3));
        assert_eq!(hash_at(&text, 3).as_deref(), Some(hash.as_str()));
        assert_eq!(hash_at(&text, 9), None);
        let edited = text.replacen("f0", "fX", 1);
        assert_eq!(verify_text(&edited), Chain::Broken(1));
    }

    #[test]
    fn the_chain_detects_edits_deletions_and_reordering() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            append(dir.path(), "t1", json!({ "tool": "Edit", "path": format!("f{i}") })).unwrap();
        }
        assert_eq!(verify(dir.path(), "t1"), Chain::Intact(5));
        assert_eq!(read(dir.path(), "t1").len(), 5);

        let path = path_for(dir.path(), "t1");
        let original = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();

        fs::write(&path, original.replace(r#""path":"f2""#, r#""path":"fX""#)).unwrap();
        assert_ne!(original, fs::read_to_string(&path).unwrap(), "the edit must actually change the file");
        assert_eq!(verify(dir.path(), "t1"), Chain::Broken(3), "an edited event");

        let mut gone = lines.clone();
        gone.remove(1);
        fs::write(&path, gone.join("\n") + "\n").unwrap();
        assert_eq!(verify(dir.path(), "t1"), Chain::Broken(2), "a deleted line");

        let mut swapped = lines.clone();
        swapped.swap(2, 3);
        fs::write(&path, swapped.join("\n") + "\n").unwrap();
        assert!(matches!(verify(dir.path(), "t1"), Chain::Broken(_)), "reordered lines");

        fs::write(&path, &original).unwrap();
        assert_eq!(verify(dir.path(), "t1"), Chain::Intact(5));
        assert_eq!(verify(dir.path(), "never-written"), Chain::Intact(0));
    }
}

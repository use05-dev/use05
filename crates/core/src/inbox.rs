//! The inbox: where an agent's own process leaves its declarations for its hooks to seal.
//!
//! An agent's sandbox may make `.git` read-only (Codex's does), so `use05 start` and `use05
//! finish`, run by the agent, cannot write 05's state. They write a small file here instead,
//! tagged with the agent's session, and the agent's next hook, which runs outside the sandbox,
//! seals it into that session's task. `.05/inbox/` is never part of a change.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::intent::IntentCard;

pub const INBOX_DIR: &str = ".05/inbox";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Start {
        title: String,
        card: Option<IntentCard>,
        /// A hotfix (D93): the environment whose branch the work started from (`start --hotfix`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hotfix: Option<String>,
    },
    Finish { outcome: Option<String> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub agent: String,
    pub session: String,
    /// RFC 3339.
    pub created: String,
    pub entry: Entry,
    /// What the agent's process reported about its sandbox, if anything.
    #[serde(default)]
    pub sandbox: Option<String>,
}

fn safe(text: &str) -> String {
    text.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(64).collect()
}

fn dir(top: &Path) -> PathBuf {
    top.join(INBOX_DIR)
}

/// Leave a declaration for the session's hook to seal.
pub fn put(top: &Path, p: &Pending) -> Result<PathBuf> {
    let dir = dir(top);
    fs::create_dir_all(&dir).map_err(|e| Error::io("creating the inbox", e))?;
    // The inbox keeps itself out of git, even where `init` never wrote .05/.gitignore.
    let ignore = dir.join(".gitignore");
    if !ignore.exists() {
        fs::write(&ignore, "*\n").map_err(|e| Error::io("writing the inbox's .gitignore", e))?;
    }
    let path = dir.join(format!("{}-{}-{}.json", safe(&p.created), safe(&p.id), crate::task::random_id()?));
    let json = serde_json::to_vec_pretty(p).expect("an inbox entry serialises");
    fs::write(&path, json).map_err(|e| Error::io(&format!("writing {}", path.display()), e))?;
    Ok(path)
}

fn read_all(top: &Path) -> Vec<(PathBuf, Pending)> {
    let mut found: Vec<(PathBuf, Pending)> = fs::read_dir(dir(top))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .filter_map(|p| fs::read(&p).ok().and_then(|b| serde_json::from_slice(&b).ok()).map(|v| (p, v)))
                .collect()
        })
        .unwrap_or_default();
    found.sort_by(|(pa, a), (pb, b)| a.created.cmp(&b.created).then(pa.cmp(pb)));
    found
}

/// Entries for one session, oldest first. An empty session matches nothing.
pub fn for_session(top: &Path, session: &str) -> Vec<(PathBuf, Pending)> {
    if session.is_empty() {
        return Vec::new();
    }
    read_all(top).into_iter().filter(|(_, p)| p.session == session).collect()
}

/// Entries older than this are reported as stale: their session is long gone.
pub const STALE_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Default)]
pub struct Scan {
    pub waiting: Vec<Pending>,
    /// Older than [`STALE_SECS`]: the declaration will most likely never be sealed.
    pub stale: Vec<(PathBuf, Pending)>,
    /// Files in the inbox that are not a readable declaration.
    pub unreadable: Vec<PathBuf>,
}

/// Everything in the inbox, sorted into waiting, stale and unreadable, so nothing vanishes.
pub fn scan(top: &Path, now: u64) -> Scan {
    let mut out = Scan::default();
    for (path, p) in read_all(top) {
        let age = crate::time::parse_rfc3339(&p.created).map_or(u64::MAX, |t| now.saturating_sub(t));
        if age > STALE_SECS { out.stale.push((path, p)) } else { out.waiting.push(p) }
    }
    out.unreadable = fs::read_dir(dir(top))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .filter(|p| fs::read(p).ok().and_then(|b| serde_json::from_slice::<Pending>(&b).ok()).is_none())
                .collect()
        })
        .unwrap_or_default();
    out
}

/// Anything at all in the inbox, readable or not.
pub fn has_any(top: &Path) -> bool {
    fs::read_dir(dir(top)).is_ok_and(|d| d.filter_map(|e| e.ok()).any(|e| e.path().extension().is_some_and(|x| x == "json")))
}

/// Every entry still waiting, oldest first.
pub fn all(top: &Path) -> Vec<Pending> {
    read_all(top).into_iter().map(|(_, p)| p).collect()
}

pub fn remove(path: &Path) -> Result<()> {
    fs::remove_file(path).map_err(|e| Error::io("removing a sealed declaration", e))
}

/// Which agent session is this process running in, if any? `USE05_SESSION_ID` comes first: an
/// agent using the generic hook sets it on purpose (and should clear it for agents it starts).
/// Codex is checked before Claude Code: a Codex process started from a Claude Code session
/// inherits Claude Code's variables.
pub fn agent_session() -> Option<(String, String)> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    var("USE05_SESSION_ID")
        .map(|id| ("generic".to_string(), id))
        .or_else(|| var("CODEX_SESSION_ID").map(|id| ("codex".to_string(), id)))
        .or_else(|| var("CLAUDE_CODE_SESSION_ID").map(|id| ("claude-code".to_string(), id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(id: &str, session: &str, created: &str) -> Pending {
        Pending { id: id.into(), agent: "codex".into(), session: session.into(), created: created.into(), entry: Entry::Finish { outcome: Some(id.into()) }, sandbox: None }
    }

    #[test]
    fn entries_are_returned_per_session_oldest_first_and_empty_session_gets_none() {
        let top = tempfile::tempdir().unwrap();
        put(top.path(), &pending("c", "s1", "2026-10-30T10:00:02Z")).unwrap();
        put(top.path(), &pending("a", "s1", "2026-10-30T10:00:00Z")).unwrap();
        put(top.path(), &pending("b", "s2", "2026-10-30T10:00:01Z")).unwrap();
        let ids: Vec<String> = for_session(top.path(), "s1").into_iter().map(|(_, p)| p.id).collect();
        assert_eq!(ids, ["a", "c"]);
        assert!(for_session(top.path(), "").is_empty());
        assert_eq!(all(top.path()).len(), 3);
    }

    #[test]
    fn a_hostile_session_or_id_cannot_write_outside_the_inbox() {
        let top = tempfile::tempdir().unwrap();
        let path = put(top.path(), &pending("../y", "../../x", "2026-10-30T10:00:00Z")).unwrap();
        assert!(path.starts_with(top.path().join(INBOX_DIR)), "{path:?}");
        assert_eq!(for_session(top.path(), "../../x").len(), 1, "the session is matched by its recorded value, not the file name");
    }

    #[test]
    fn the_inbox_ignores_itself_even_without_init() {
        let top = tempfile::tempdir().unwrap();
        put(top.path(), &pending("a", "s1", "2026-10-30T10:00:00Z")).unwrap();
        assert_eq!(std::fs::read_to_string(top.path().join(INBOX_DIR).join(".gitignore")).unwrap(), "*\n");
        assert_eq!(all(top.path()).len(), 1);
    }

    #[test]
    fn unreadable_and_stale_entries_are_reported_not_lost() {
        let top = tempfile::tempdir().unwrap();
        put(top.path(), &pending("fresh", "s1", &crate::time::now_rfc3339())).unwrap();
        put(top.path(), &pending("old", "s2", "2026-01-01T00:00:00Z")).unwrap();
        std::fs::write(top.path().join(INBOX_DIR).join("broken.json"), "{ not json").unwrap();
        let scan = scan(top.path(), crate::time::now_secs());
        assert_eq!(scan.waiting.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["fresh"]);
        assert_eq!(scan.stale.len(), 1);
        assert_eq!(scan.unreadable.len(), 1);
        assert!(scan.unreadable[0].ends_with("broken.json"));
    }

    #[test]
    fn has_any_counts_unreadable_files_too() {
        let top = tempfile::tempdir().unwrap();
        assert!(!has_any(top.path()));
        std::fs::create_dir_all(top.path().join(INBOX_DIR)).unwrap();
        std::fs::write(top.path().join(INBOX_DIR).join("broken.json"), "{").unwrap();
        assert!(has_any(top.path()));
    }

    #[test]
    fn a_removed_entry_is_gone() {
        let top = tempfile::tempdir().unwrap();
        let path = put(top.path(), &pending("a", "s1", "2026-10-30T10:00:00Z")).unwrap();
        remove(&path).unwrap();
        assert!(all(top.path()).is_empty());
    }
}

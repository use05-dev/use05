//! The statements this machine prepared itself. The console only carries signatures back: the
//! machine files an approval only for a statement it wrote, for the repository and purpose it
//! wrote it for, and only once. A compromised console that gets a passkey to sign something else
//! (say, by passing it off as a sign-in) cannot make it count here.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};


/// How long a prepared statement waits to be signed; approvals expire well before this.
const KEEP_SECS: u64 = 30 * 86_400;

/// The helper's threads share one file.
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// An approval of an agent's task, filed as it is.
    Approval,
    /// The approval of a policy edit's commit, filed only as part of applying that edit.
    PolicyEdit,
    /// A person's testing sign-off (D87), filed as it is.
    Testing,
    /// A person's word to throw a task's work away (D89), acted on here and never filed.
    Discard,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    sha256: String,
    repo: String,
    purpose: Purpose,
    at: u64,
}

/// Replace a file whole (a reader sees the old or the new, never half), readable by its owner only.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp{:08x}", rand::random::<u32>()));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub struct Prepared {
    path: PathBuf,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The statement's bytes, whatever base64 padding the envelope used.
fn digest(payload_b64: &str) -> Option<String> {
    let lenient = GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent));
    let bytes = lenient.decode(payload_b64.trim()).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

impl Prepared {
    pub fn at(path: &Path) -> Prepared {
        Prepared { path: path.to_path_buf() }
    }

    fn read(&self) -> Vec<Entry> {
        let cutoff = now().saturating_sub(KEEP_SECS);
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice::<Vec<Entry>>(&b).ok()).unwrap_or_default().into_iter().filter(|e| e.at >= cutoff).collect()
    }

    fn write(&self, entries: &[Entry]) -> Result<()> {
        write_private(&self.path, &serde_json::to_vec(entries)?)
    }

    /// Note a statement this machine just prepared.
    pub fn remember(&self, repo: &str, purpose: Purpose, payload_b64: &str) -> Result<()> {
        let sha256 = digest(payload_b64).ok_or_else(|| anyhow!("the prepared statement is not base64"))?;
        let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut entries = self.read();
        entries.retain(|e| !(e.sha256 == sha256 && e.repo == repo && e.purpose == purpose));
        entries.push(Entry { sha256, repo: repo.to_string(), purpose, at: now() });
        self.write(&entries)
    }

    /// Did this machine prepare exactly this statement, for this repository and purpose?
    pub fn knows(&self, repo: &str, purpose: Purpose, payload_b64: &str) -> bool {
        let Some(sha256) = digest(payload_b64) else { return false };
        let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        self.read().iter().any(|e| e.sha256 == sha256 && e.repo == repo && e.purpose == purpose)
    }

    /// Filed: it never counts a second time.
    pub fn forget(&self, repo: &str, purpose: Purpose, payload_b64: &str) -> Result<()> {
        let Some(sha256) = digest(payload_b64) else { return Ok(()) };
        let _held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut entries = self.read();
        entries.retain(|e| !(e.sha256 == sha256 && e.repo == repo && e.purpose == purpose));
        self.write(&entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_file_is_replaced_whole_and_only_its_owner_reads_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("use05-private-{:08x}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cloud.toml");
        std::fs::write(&path, "old").unwrap();
        write_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn store() -> (Prepared, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("prepared-test-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cloud-prepared.json");
        (Prepared::at(&path), path)
    }

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    #[test]
    fn only_what_this_machine_prepared_for_that_repo_and_purpose() {
        let (p, _) = store();
        p.remember("repo1", Purpose::Approval, &b64("statement one")).unwrap();
        assert!(p.knows("repo1", Purpose::Approval, &b64("statement one")));
        assert!(!p.knows("repo1", Purpose::Approval, &b64("statement two")), "a statement the console wrote");
        assert!(!p.knows("repo2", Purpose::Approval, &b64("statement one")), "another repository");
        assert!(!p.knows("repo1", Purpose::PolicyEdit, &b64("statement one")), "another purpose");
        assert!(!p.knows("repo1", Purpose::Approval, "not base64 at all"));
    }

    #[test]
    fn once_filed_it_is_forgotten() {
        let (p, _) = store();
        p.remember("repo1", Purpose::PolicyEdit, &b64("edit")).unwrap();
        p.forget("repo1", Purpose::PolicyEdit, &b64("edit")).unwrap();
        assert!(!p.knows("repo1", Purpose::PolicyEdit, &b64("edit")));
    }

    #[test]
    fn the_same_bytes_in_another_base64_spelling_are_the_same_statement() {
        let (p, _) = store();
        p.remember("repo1", Purpose::Approval, &b64("ab")).unwrap();
        let unpadded = b64("ab").trim_end_matches('=').to_string();
        assert_ne!(unpadded, b64("ab"));
        assert!(p.knows("repo1", Purpose::Approval, &unpadded));
    }

    #[test]
    fn kept_private_and_old_ones_dropped() {
        let (p, path) = store();
        p.remember("repo1", Purpose::Approval, &b64("new")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // An entry from 40 days ago no longer counts, and goes at the next write.
        let mut entries: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut old = entries[0].clone();
        old["sha256"] = serde_json::json!(super::digest(&b64("old")).unwrap());
        old["at"] = serde_json::json!(super::now() - 40 * 86_400);
        entries.push(old);
        std::fs::write(&path, serde_json::to_vec(&entries).unwrap()).unwrap();
        assert!(!p.knows("repo1", Purpose::Approval, &b64("old")));
        p.remember("repo1", Purpose::Approval, &b64("newer")).unwrap();
        let kept: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(kept.len(), 2);
    }
}

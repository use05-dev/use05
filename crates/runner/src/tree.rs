//! Reading a git tree exactly as stored, and digesting it.
//!
//! The content digest is SHA-256 over one line per file, sorted by path:
//!
//! ```text
//! <mode> blob <sha256 of the blob's bytes> <path length>:<path>\n
//! 160000 commit <submodule commit id> <path length>:<path>\n
//! ```
//!
//! so it does not depend on git's own object hash alone.
//!
//! Hashing every file again on each look is the slow part on a big repository, so when nothing is
//! being exported the SHA-256 of each blob is remembered by its git object id in the repository's
//! own state (`05/blob-digests`). A blob id fixes the blob's bytes inside one repository, which is
//! what git itself relies on. The digest's definition is unchanged, so receipts are unaffected.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::RunnerError;
use crate::git::{self, BlobReader};

struct Entry {
    mode: String,
    kind: String,
    oid: String,
    path: Vec<u8>,
}

fn list(repo: &Path, tree_oid: &str) -> Result<Vec<Entry>, RunnerError> {
    let raw = git::output(repo, &["ls-tree", "-r", "-z", "--full-tree", tree_oid], "listing the tree")?;
    let mut entries = Vec::new();
    for record in raw.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = record.iter().position(|b| *b == b'\t').ok_or_else(|| RunnerError::GitFailed {
            what: "listing the tree",
            stderr: "unexpected ls-tree output".into(),
        })?;
        let meta = String::from_utf8_lossy(&record[..tab]).to_string();
        let mut parts = meta.split(' ');
        let (Some(mode), Some(kind), Some(oid)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(RunnerError::GitFailed { what: "listing the tree", stderr: "unexpected ls-tree output".into() });
        };
        entries.push(Entry {
            mode: mode.to_string(),
            kind: kind.to_string(),
            oid: oid.to_string(),
            path: record[tab + 1..].to_vec(),
        });
    }
    Ok(entries)
}

/// Reject paths that could escape the scratch directory or collide with git's own data.
fn safe_relative(path: &[u8]) -> Result<PathBuf, RunnerError> {
    let shown = || String::from_utf8_lossy(path).to_string();
    if path.is_empty() || path.first() == Some(&b'/') {
        return Err(RunnerError::UnsafePath(shown()));
    }
    let mut out = PathBuf::new();
    for part in path.split(|b| *b == b'/') {
        let lower = part.to_ascii_lowercase();
        if part.is_empty() || part == b"." || part == b".." || lower == b".git" || part.contains(&0) {
            return Err(RunnerError::UnsafePath(shown()));
        }
        out.push(OsStr::from_bytes(part));
    }
    Ok(out)
}

/// Remembered blob digests: one `<blob id> <sha256>` line each, appended as they are learned.
struct DigestCache {
    path: Option<PathBuf>,
    known: HashMap<String, String>,
    added: Vec<(String, String)>,
}

impl DigestCache {
    fn load(repo: &Path) -> DigestCache {
        let path = git::text(repo, &["rev-parse", "--git-common-dir"], "finding the git directory")
            .ok()
            .map(|d| {
                let d = PathBuf::from(d.trim());
                (if d.is_absolute() { d } else { repo.join(d) }).join("05").join("blob-digests")
            });
        let mut known = HashMap::new();
        if let Some(text) = path.as_ref().and_then(|p| fs::read_to_string(p).ok()) {
            for line in text.lines() {
                // A damaged or foreign line is ignored, never trusted.
                if let Some((oid, sha)) = line.split_once(' ') {
                    let hex = |t: &str, n: &[usize]| n.contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit());
                    if hex(oid, &[40, 64]) && hex(sha, &[64]) {
                        known.insert(oid.to_string(), sha.to_string());
                    }
                }
            }
        }
        DigestCache { path, known, added: Vec::new() }
    }

    fn save(self) {
        let (Some(path), false) = (self.path, self.added.is_empty()) else { return };
        let text: String = self.added.iter().map(|(o, s)| format!("{o} {s}\n")).collect();
        // Best effort, and one append so concurrent processes cannot interleave half-lines.
        if path.parent().is_some_and(|p| fs::create_dir_all(p).is_ok()) {
            let _ = fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(text.as_bytes()));
        }
    }
}

/// Digest the tree's contents and, if `dest` is given, write it there.
///
/// Regular files keep their executable bit, symlinks stay symlinks, and submodule entries become
/// empty directories. No smudge filters or attribute conversions are applied.
pub(crate) fn materialize(repo: &Path, tree_oid: &str, dest: Option<&Path>) -> Result<String, RunnerError> {
    let entries = list(repo, tree_oid)?;
    // Reading blobs is only needed to export them or to learn a digest we have not seen.
    let mut blobs: Option<BlobReader> = None;
    let mut cache = if dest.is_none() { Some(DigestCache::load(repo)) } else { None };
    let mut manifest = Sha256::new();

    for entry in &entries {
        let relative = safe_relative(&entry.path)?;
        let path_field = |manifest: &mut Sha256| {
            manifest.update(entry.path.len().to_string().as_bytes());
            manifest.update(b":");
            manifest.update(&entry.path);
            manifest.update(b"\n");
        };

        if entry.kind == "commit" {
            manifest.update(format!("{} commit {} ", entry.mode, entry.oid).as_bytes());
            path_field(&mut manifest);
            if let Some(dest) = dest {
                fs::create_dir_all(dest.join(&relative)).map_err(RunnerError::io("creating a submodule directory"))?;
            }
            continue;
        }

        let remembered = cache.as_ref().and_then(|c| c.known.get(&entry.oid).cloned());
        let (data, sha) = match remembered {
            Some(sha) => (None, sha),
            None => {
                if blobs.is_none() {
                    blobs = Some(BlobReader::start(repo)?);
                }
                let data = blobs.as_mut().expect("started").read(&entry.oid)?;
                let sha = hex::encode(Sha256::digest(&data));
                if let Some(c) = cache.as_mut() {
                    c.known.insert(entry.oid.clone(), sha.clone());
                    c.added.push((entry.oid.clone(), sha.clone()));
                }
                (Some(data), sha)
            }
        };
        manifest.update(format!("{} blob {} ", entry.mode, sha).as_bytes());
        path_field(&mut manifest);

        let Some(dest) = dest else { continue };
        let data = data.expect("an export always reads the blob");
        let target = dest.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(RunnerError::io("creating a directory"))?;
        }
        if entry.mode == "120000" {
            symlink(OsStr::from_bytes(&data), &target).map_err(RunnerError::io("writing a symlink"))?;
        } else {
            fs::write(&target, &data).map_err(RunnerError::io("writing a file"))?;
            let executable = entry.mode == "100755";
            fs::set_permissions(&target, fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }))
                .map_err(RunnerError::io("setting file permissions"))?;
        }
    }
    if let Some(cache) = cache {
        cache.save();
    }
    Ok(hex::encode(manifest.finalize()))
}

//! The repositories on this machine that 05 has been used in, so bare `use05` can show them all.
//!
//! One small text file, `repos.tsv`, in 05's per-user directory: a line per repository, `<unix
//! seconds last seen><TAB><absolute path>`, newest first. It never leaves the machine and nothing
//! else reads it. Writing is best effort and never fails a command: hooks run on every tool call, so
//! a repository already listed within the last few minutes costs one small read and no write.
//! Two commands racing may drop each other's entry; the next use of that repository adds it again.

use std::fs;
use std::path::{Path, PathBuf};

use crate::git::Dirs;
use crate::keys::user_dir;
use crate::time::now_secs;

/// The file's name in 05's per-user directory.
pub const FILE: &str = "repos.tsv";

/// A repository is written again only when its entry is older than this.
const FRESH_SECS: u64 = 10 * 60;

/// The most repositories remembered; the least recently used are forgotten first.
const MAX: usize = 200;

/// A repository 05 has seen, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub path: PathBuf,
    pub seen: u64,
}

/// The repository's root as listed: the main checkout, whichever linked worktree ran the command
/// (tasks are shared by all of them); the git directory itself for a bare repository.
pub fn root_of(dirs: &Dirs) -> PathBuf {
    let base = if dirs.common.file_name().is_some_and(|n| n == ".git") { dirs.common.parent().map(Path::to_path_buf) } else { None };
    base.unwrap_or_else(|| dirs.common.clone())
}

/// Does 05 hold anything for this repository? Only then is it worth listing: a plain `use05 brief`
/// in some repository that never set 05 up leaves no trace.
fn in_use(dirs: &Dirs) -> bool {
    dirs.common.join("05").is_dir() || dirs.top.join(".05").is_dir()
}

/// Note that 05 was used in this repository. Best effort: errors are ignored. True when the
/// repository was not on the list before.
pub fn touch(dirs: &Dirs) -> bool {
    if !in_use(dirs) {
        return false;
    }
    user_dir().is_ok_and(|dir| touch_in(&dir, &root_of(dirs), now_secs()))
}

fn line_ok(path: &Path) -> bool {
    path.is_absolute() && !path.to_string_lossy().contains(['\t', '\n', '\r'])
}

fn read(dir: &Path) -> Vec<Seen> {
    let text = fs::read_to_string(dir.join(FILE)).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let (secs, path) = l.split_once('\t')?;
            Some(Seen { path: PathBuf::from(path), seen: secs.parse().ok()? })
        })
        .collect()
}

/// Write the list: a temporary file beside it, then a rename, so a reader never sees half of it.
fn write(dir: &Path, entries: &[Seen]) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let text: String = entries.iter().map(|e| format!("{}\t{}\n", e.seen, e.path.display())).collect();
    let tmp = dir.join(format!("{FILE}.{}.tmp", std::process::id()));
    let result = fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, dir.join(FILE)));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn exists(path: &Path) -> bool {
    path.join(".git").exists() || (path.join("HEAD").is_file() && path.join("objects").is_dir())
}

/// [`touch`], with the directory and the time given.
pub fn touch_in(dir: &Path, root: &Path, now: u64) -> bool {
    if !line_ok(root) {
        return false;
    }
    let mut entries = read(dir);
    let known = entries.iter().find(|e| e.path == root).map(|e| e.seen);
    if known.is_some_and(|seen| now.saturating_sub(seen) < FRESH_SECS) {
        return false;
    }
    entries.retain(|e| e.path != root && exists(&e.path));
    entries.insert(0, Seen { path: root.to_path_buf(), seen: now });
    entries.truncate(MAX);
    write(dir, &entries).is_ok() && known.is_none()
}

/// The repositories that are still there, most recently seen first.
pub fn list() -> Vec<Seen> {
    user_dir().map(|d| list_in(&d)).unwrap_or_default()
}

/// [`list`], from a given directory.
pub fn list_in(dir: &Path) -> Vec<Seen> {
    let mut entries: Vec<Seen> = read(dir).into_iter().filter(|e| exists(&e.path)).collect();
    entries.sort_by(|a, b| b.seen.cmp(&a.seen));
    entries
}

/// Take a repository off the list (`use05 uninstall`). Returns whether it was there. When the list
/// is empty the file goes too, so an uninstalled machine is left as it was.
pub fn forget(dirs: &Dirs) -> bool {
    user_dir().is_ok_and(|d| forget_in(&d, &root_of(dirs)))
}

/// [`forget`], from a given directory.
pub fn forget_in(dir: &Path, root: &Path) -> bool {
    let entries = read(dir);
    let kept: Vec<Seen> = entries.iter().filter(|e| e.path != root).cloned().collect();
    if kept.len() == entries.len() {
        return false;
    }
    if kept.is_empty() {
        let _ = fs::remove_file(dir.join(FILE));
    } else {
        let _ = write(dir, &kept);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(parent: &Path, name: &str) -> PathBuf {
        let p = parent.join(name);
        fs::create_dir_all(p.join(".git")).unwrap();
        p
    }

    #[test]
    fn a_repository_is_listed_once_newest_first_and_a_fresh_entry_is_not_rewritten() {
        let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (repo(work.path(), "a"), repo(work.path(), "b"));
        assert!(touch_in(home.path(), &a, 1_000), "new to the list");
        touch_in(home.path(), &b, 2_000);
        assert!(!touch_in(home.path(), &a, 2_100), "already on it");
        let seen = list_in(home.path());
        assert_eq!(seen, [Seen { path: a.clone(), seen: 2_100 }, Seen { path: b.clone(), seen: 2_000 }]);

        // Within the minutes a hook may call again, nothing is written.
        let file = home.path().join(FILE);
        let before = fs::read_to_string(&file).unwrap();
        touch_in(home.path(), &a, 2_100 + FRESH_SECS - 1);
        assert_eq!(fs::read_to_string(&file).unwrap(), before);
        touch_in(home.path(), &a, 2_100 + FRESH_SECS);
        assert_ne!(fs::read_to_string(&file).unwrap(), before);
    }

    #[test]
    fn a_deleted_repository_and_a_folder_that_is_no_longer_a_repository_are_dropped() {
        let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (gone, plain, kept) = (repo(work.path(), "gone"), repo(work.path(), "plain"), repo(work.path(), "kept"));
        for (i, r) in [&gone, &plain, &kept].into_iter().enumerate() {
            touch_in(home.path(), r, 100 + i as u64);
        }
        fs::remove_dir_all(&gone).unwrap();
        fs::remove_dir_all(plain.join(".git")).unwrap();
        assert_eq!(list_in(home.path()).into_iter().map(|s| s.path).collect::<Vec<_>>(), [kept.clone()]);
        // And the next write sweeps them out of the file.
        touch_in(home.path(), &kept, 10_000);
        assert_eq!(fs::read_to_string(home.path().join(FILE)).unwrap().lines().count(), 1);
    }

    #[test]
    fn forgetting_removes_the_entry_and_then_the_file() {
        let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (repo(work.path(), "a"), repo(work.path(), "b"));
        touch_in(home.path(), &a, 1);
        touch_in(home.path(), &b, 2);
        assert!(forget_in(home.path(), &a));
        assert!(!forget_in(home.path(), &a), "already gone");
        assert!(home.path().join(FILE).exists());
        assert!(forget_in(home.path(), &b));
        assert!(!home.path().join(FILE).exists(), "an empty list leaves no file");
    }

    #[test]
    fn a_path_that_would_break_the_file_is_not_written_and_junk_lines_are_ignored() {
        let (home, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let odd = repo(work.path(), "tab\tname");
        touch_in(home.path(), &odd, 1);
        touch_in(home.path(), Path::new("relative/repo"), 1);
        assert!(!home.path().join(FILE).exists());
        fs::write(home.path().join(FILE), "not a line\nx\t/nope\n").unwrap();
        assert!(list_in(home.path()).is_empty());
    }

    #[test]
    fn a_linked_worktree_is_listed_as_its_main_checkout() {
        let dirs = Dirs { top: PathBuf::from("/w/repo-wt"), git_dir: PathBuf::from("/w/repo/.git/worktrees/wt"), common: PathBuf::from("/w/repo/.git") };
        assert_eq!(root_of(&dirs), PathBuf::from("/w/repo"));
        let bare = Dirs { top: PathBuf::from("/w/bare.git"), git_dir: PathBuf::from("/w/bare.git"), common: PathBuf::from("/w/bare.git") };
        assert_eq!(root_of(&bare), PathBuf::from("/w/bare.git"));
    }
}

//! A task: one unit of work by a person or an agent, with its intent and its outcome.
//!
//! Tasks live in `.git/05/tasks/` (shared by every worktree). Which task a worktree is on is
//! kept in that worktree's own git dir. Nothing here is committed or uploaded.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::git::{self, Dirs};
use crate::intent::IntentCard;
use crate::time::now_rfc3339;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Finished,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    pub title: String,
    /// `human`, or `agent:<name>`.
    pub author: String,
    pub created: String,
    /// The commit the task started from, and its tree. Rules are read from here.
    pub base_commit: Option<String>,
    pub base_tree: String,
    pub branch: Option<String>,
    pub intent: Option<IntentCard>,
    pub intent_sha256: Option<String>,
    pub status: Status,
    /// What the author said they did. An assertion, never a fact.
    pub outcome: Option<String>,
    pub finished: Option<String>,
    pub session: Option<String>,
    /// When the current intent was sealed, RFC 3339. Edits before it were made undeclared.
    #[serde(default)]
    pub sealed: Option<String>,
    /// Earlier declarations of this task, oldest first.
    #[serde(default)]
    pub revisions: Vec<Revision>,
    /// The person's request (the first prompt of the agent session), kept on this machine only.
    #[serde(default)]
    pub request: Option<String>,
    /// The last commit when the task finished: its work is in a base once this commit is.
    #[serde(default)]
    pub head: Option<String>,
    /// When the agent's session ended (SessionEnd), RFC 3339.
    #[serde(default)]
    pub ended: Option<String>,
    /// Which agent did the work (D71): set by its hook, never by the agent.
    #[serde(default)]
    pub agent: Option<AgentId>,
    /// The accountable person (D71): this machine's approver, confirmed once their key signs.
    #[serde(default)]
    pub owner: Option<Owner>,
    /// What the agent's own process reported about its sandbox (`CODEX_SANDBOX`). Its own word.
    #[serde(default)]
    pub sandbox: Option<String>,
    /// How far behind origin the work started, when the policy asks (fresh base).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<crate::fresh::Fresh>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentId {
    pub kind: String,
    pub session: String,
    pub model: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub name: String,
    pub key_id: String,
}

/// This machine's approver, as the default owner of work started here (D71).
pub fn local_owner(top: &Path) -> Option<Owner> {
    let key = crate::keys::approver_public()?;
    let name = git::text(top, &["config", "user.name"]).ok().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "this machine's approver".to_string());
    Some(Owner { name: name.trim().to_string(), key_id: use05_receipt::key_id(&key) })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub intent: IntentCard,
    pub intent_sha256: String,
    pub sealed: String,
}

pub struct Store {
    pub dirs: Dirs,
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::io("reading system randomness", e))?;
    Ok(hex::encode(buf))
}

pub fn random_id() -> Result<String> {
    random_hex(4)
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        Ok(Store { dirs: git::dirs(dir)? })
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dirs.common.join("05")
    }

    fn tasks_dir(&self) -> PathBuf {
        self.state_dir().join("tasks")
    }

    fn task_path(&self, id: &str) -> PathBuf {
        self.tasks_dir().join(format!("{id}.json"))
    }

    fn current_path(&self) -> PathBuf {
        self.dirs.git_dir.join("05-current")
    }

    fn session_path(&self, session: &str) -> PathBuf {
        let safe: String = session.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(64).collect();
        self.state_dir().join("sessions").join(safe)
    }

    pub fn create(&self, title: &str, author: &str, intent: Option<IntentCard>, session: Option<&str>) -> Result<Task> {
        let base_commit = git::head_commit(&self.dirs.top);
        let base_tree = match &base_commit {
            Some(c) => git::resolve_tree(&self.dirs.top, c)?,
            None => git::EMPTY_TREE.to_string(),
        };
        let task = Task {
            id: random_id()?,
            title: title.trim().to_string(),
            author: author.to_string(),
            created: now_rfc3339(),
            base_commit,
            base_tree,
            branch: git::current_branch(&self.dirs.top),
            intent_sha256: intent.as_ref().map(IntentCard::digest),
            intent,
            status: Status::Active,
            outcome: None,
            finished: None,
            session: session.map(str::to_string),
            sealed: None,
            revisions: Vec::new(),
            request: None,
            head: None,
            ended: None,
            agent: None,
            owner: None,
            sandbox: None,
            fresh: None,
        };
        self.save(&task)?;
        self.set_current(&task.id)?;
        if let Some(session) = session {
            write(&self.session_path(session), &task.id)?;
        }
        Ok(task)
    }

    /// A task that is never saved: what a hook judges an edit against when the agent gave no
    /// session, so only the repository's own protections apply.
    pub fn unattached(&self, agent: &str) -> Task {
        Task {
            id: String::new(),
            title: format!("{agent} (no session)"),
            author: format!("agent:{agent}"),
            created: now_rfc3339(),
            base_commit: git::head_commit(&self.dirs.top),
            base_tree: String::new(),
            branch: git::current_branch(&self.dirs.top),
            intent: None,
            intent_sha256: None,
            status: Status::Active,
            outcome: None,
            finished: None,
            session: None,
            sealed: None,
            revisions: Vec::new(),
            request: None,
            head: None,
            ended: None,
            agent: None,
            owner: None,
            sandbox: None,
            fresh: None,
        }
    }

    pub fn save(&self, task: &Task) -> Result<()> {
        let json = serde_json::to_vec_pretty(task).expect("task serialises");
        write(&self.task_path(&task.id), &String::from_utf8_lossy(&json))
    }

    pub fn load(&self, id: &str) -> Result<Task> {
        if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::new("TASK_NOT_FOUND", format!("{id:?} is not a task id")));
        }
        let bytes = fs::read(self.task_path(id)).map_err(|_| {
            Error::new("TASK_NOT_FOUND", format!("no task {id} in this repository")).with_next("start one: use05 start \"what you are about to do\"")
        })?;
        serde_json::from_slice(&bytes).map_err(|e| Error::new("TASK_UNREADABLE", format!("task {id} is unreadable: {e}")))
    }

    pub fn list(&self) -> Vec<Task> {
        let mut tasks: Vec<Task> = fs::read_dir(self.tasks_dir())
            .map(|d| d.filter_map(|e| e.ok()).filter_map(|e| fs::read(e.path()).ok()).filter_map(|b| serde_json::from_slice(&b).ok()).collect())
            .unwrap_or_default();
        tasks.sort_by(|a: &Task, b: &Task| b.created.cmp(&a.created));
        tasks
    }

    pub fn set_current(&self, id: &str) -> Result<()> {
        write(&self.current_path(), id)
    }

    pub fn current(&self) -> Option<Task> {
        let id = fs::read_to_string(self.current_path()).ok()?;
        self.load(id.trim()).ok()
    }

    /// The task a given agent session is working on.
    pub fn for_session(&self, session: &str) -> Option<Task> {
        let id = fs::read_to_string(self.session_path(session)).ok()?;
        self.load(id.trim()).ok()
    }

    pub fn attach_session(&self, session: &str, task: &Task) -> Result<()> {
        write(&self.session_path(session), &task.id)
    }

    /// Seal a declaration into `task`: the title and card become its intent from now on. An
    /// earlier card is kept as a revision, so a brief can show both.
    pub fn declare(&self, task: &mut Task, title: &str, card: Option<IntentCard>) -> Result<()> {
        let now = now_rfc3339();
        if let (Some(old), Some(old_sha)) = (task.intent.take(), task.intent_sha256.take()) {
            task.revisions.push(Revision { intent: old, intent_sha256: old_sha, sealed: task.sealed.clone().unwrap_or_else(|| now.clone()) });
        }
        if !title.trim().is_empty() {
            task.title = title.trim().to_string();
        }
        task.intent_sha256 = card.as_ref().map(IntentCard::digest);
        task.intent = card;
        task.sealed = Some(now);
        self.save(task)
    }

    pub fn finish(&self, task: &mut Task, outcome: Option<&str>) -> Result<()> {
        if let Some(outcome) = outcome {
            task.outcome = Some(outcome.trim().to_string());
        }
        task.status = Status::Finished;
        task.finished = Some(now_rfc3339());
        task.head = git::head_commit(&self.dirs.top);
        self.save(task)
    }
}

/// Files inside the declared scope that the task's agent edited before the declaration was
/// sealed. A declaration written after the work cannot be trusted as a plan (D65).
pub fn declared_late(store: &Store, task: &Task) -> Vec<String> {
    let (Some(card), Some(sealed)) = (&task.intent, task.sealed.as_deref().and_then(crate::time::parse_rfc3339)) else { return Vec::new() };
    if !card.has_scope() {
        return Vec::new();
    }
    let mut late: Vec<String> = crate::log::edited(&store.state_dir(), &task.id).into_iter().filter(|(t, p)| *t < sealed && card.allows(p)).map(|(_, p)| p).collect();
    late.sort();
    late.dedup();
    late
}

fn write(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::io("creating the state directory", e))?;
    }
    fs::write(path, text).map_err(|e| Error::io(&format!("writing {}", path.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::process::Command;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| assert!(Command::new("git").arg("-C").arg(dir.path()).args(args).output().unwrap().status.success());
        run(&["init", "-q"]);
        std::fs::write(dir.path().join("a"), "x").unwrap();
        run(&["add", "-A"]);
        run(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c"]);
        dir
    }

    #[test]
    fn a_task_round_trips_and_becomes_current() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        assert!(store.current().is_none());
        let task = store.create("Cap retries", "agent:claude-code", None, Some("sess-1")).unwrap();
        assert_eq!(store.current().unwrap(), task);
        assert_eq!(store.for_session("sess-1").unwrap().id, task.id);
        assert!(task.base_commit.is_some());
        assert_ne!(task.base_tree, git::EMPTY_TREE);
        let mut loaded = store.load(&task.id).unwrap();
        store.finish(&mut loaded, Some(" tests pass ")).unwrap();
        assert_eq!(store.load(&task.id).unwrap().outcome.as_deref(), Some("tests pass"));
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn a_declaration_is_sealed_and_a_new_one_keeps_the_old_as_a_revision() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        let mut task = store.create("codex session", "agent:codex", None, Some("s1")).unwrap();
        assert!(task.sealed.is_none());
        let card = |scope: &str| IntentCard { scope: crate::intent::Scope { include: vec![scope.into()], exclude: vec![] }, ..IntentCard::default() };
        store.declare(&mut task, "Cap retries", Some(card("src/**"))).unwrap();
        let first = store.load(&task.id).unwrap();
        assert_eq!(first.title, "Cap retries");
        assert!(first.sealed.is_some() && first.intent_sha256.is_some());
        assert!(first.revisions.is_empty());
        let mut again = first.clone();
        store.declare(&mut again, "Cap retries", Some(card("src/payments/**"))).unwrap();
        let second = store.load(&task.id).unwrap();
        assert_eq!(second.revisions.len(), 1);
        assert_eq!(second.revisions[0].intent_sha256, first.intent_sha256.clone().unwrap());
        assert_ne!(second.intent_sha256, first.intent_sha256);
    }

    #[test]
    fn declared_late_ignores_edits_outside_the_scope_and_edits_after_sealing() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        let mut task = store.create("s", "agent:codex", None, Some("s1")).unwrap();
        let state = store.state_dir();
        let at = |secs: u64, path: &str| crate::log::append_at(&state, &task.id, json!({ "event": "tool_done", "tool": "Edit", "paths": [path] }), secs);
        at(100, "src/early.rs").unwrap();
        at(100, "docs/outside.md").unwrap();
        at(300, "src/after.rs").unwrap();
        let card = IntentCard { scope: crate::intent::Scope { include: vec!["src/**".into()], exclude: vec![] }, ..IntentCard::default() };
        store.declare(&mut task, "t", Some(card)).unwrap();
        task.sealed = Some(crate::time::rfc3339(200));
        assert_eq!(declared_late(&store, &task), ["src/early.rs"]);
    }

    #[test]
    fn hostile_ids_and_sessions_cannot_escape_the_state_directory() {
        let dir = repo();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.load("../../etc/passwd").unwrap_err().code, "TASK_NOT_FOUND");
        let p = store.session_path("../../evil");
        assert!(p.starts_with(store.state_dir().join("sessions")), "{p:?}");
        assert!(store.for_session("../../nope").is_none());
    }

    #[test]
    fn a_repository_with_no_commits_still_works() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Command::new("git").arg("-C").arg(dir.path()).args(["init", "-q"]).output().unwrap().status.success());
        let store = Store::open(dir.path()).unwrap();
        let task = store.create("First", "human", None, None).unwrap();
        assert_eq!(task.base_tree, git::EMPTY_TREE);
        assert!(task.base_commit.is_none());
    }
}

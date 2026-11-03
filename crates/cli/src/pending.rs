//! What is going on in a repository, for the person who owns it: which tasks wait for them, which
//! agents are working, what finished and whether it already landed. One survey serves bare
//! `use05`, the machine-wide list of repositories, and the choice `use05 approve` offers.
//!
//! Each task is judged where its work is: in the worktree its branch is checked out in, else on
//! the branch itself, else (a task with no branch) in this checkout when it is the current task.

use std::path::{Path, PathBuf};

use use05_core::branches;
use use05_core::gate::{Decision, Effect, GateResult};
use use05_core::task::{Status, Task};
use use05_core::time::now_secs;
use use05_core::{Result, git};

use crate::ctx::Ctx;
use crate::ui::{Ui, truncate_end};

/// Tasks untouched for longer than this are left out, unless they are the only ones.
const WINDOW_SECS: u64 = 14 * 86_400;
/// How many tasks a survey judges at most.
pub const MAX_TASKS: usize = 20;
/// An agent that has done nothing for this long is no longer "working now".
const WORKING_SECS: u64 = 12 * 3_600;

/// What a person is asked to approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// The plan (the intent card), before the work.
    Plan,
    /// The result.
    Change,
}

impl Need {
    pub fn word(self) -> &'static str {
        match self {
            Need::Plan => "plan",
            Need::Change => "change",
        }
    }
}

/// Which of the two the gate asks for. The plan, when a finding says to approve the intent.
pub fn need_of(g: &GateResult) -> Need {
    if g.findings.iter().any(|f| f.effect == Effect::Approval && f.next.as_deref() == Some("use05 approve --intent")) { Need::Plan } else { Need::Change }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The gate waits for a person.
    Needs(Need),
    Allowed,
    /// Checks are missing or out of date.
    Waiting,
    Denied,
    /// Already in the branch it was for.
    Landed,
    /// There is no work to judge: no branch, and not this checkout's task.
    Unknown,
}

/// Where a task's work is, as far as `approve` and the gate are concerned.
#[derive(Debug, Clone)]
pub struct Place {
    /// The checkout to judge in.
    pub dir: PathBuf,
    /// A branch to judge instead of that checkout's files, when nothing has it checked out.
    pub tree: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub task: Task,
    /// When it last changed, in seconds.
    pub activity: u64,
    pub verdict: Verdict,
    pub place: Option<Place>,
}

impl Entry {
    pub fn needs(&self) -> Option<Need> {
        match self.verdict {
            Verdict::Needs(n) => Some(n),
            _ => None,
        }
    }

    /// An agent is at work on it right now, as far as 05 can tell.
    pub fn working(&self, now: u64) -> bool {
        self.task.status == Status::Active && self.task.ended.is_none() && self.verdict != Verdict::Landed && now.saturating_sub(self.activity) < WORKING_SECS
    }

    /// Who is doing it, for a person.
    pub fn who(&self) -> String {
        let kind = self.task.agent.as_ref().map(|a| a.kind.as_str()).or_else(|| self.task.author.strip_prefix("agent:"));
        match (kind, self.task.agent.as_ref().and_then(|a| a.model.as_deref())) {
            (Some(k), Some(m)) => format!("{k} ({m})"),
            (Some(k), None) => k.to_string(),
            (None, _) => "by hand".to_string(),
        }
    }
}

pub struct Survey {
    pub entries: Vec<Entry>,
    /// Tasks left out for being old or too many.
    pub left_out: usize,
    /// Where finished work lands.
    pub target: String,
}

impl Survey {
    pub fn waiting(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.needs().is_some()).collect()
    }
}

/// Survey the repository `repo` is in.
pub fn survey(repo: &Path, limit: usize) -> Result<Survey> {
    let base = Ctx::open_judging(repo, None)?;
    Ok(survey_with(&base, limit))
}

pub fn survey_with(base: &Ctx, limit: usize) -> Survey {
    let (store, top) = (&base.store, base.top());
    let now = now_secs();
    let mut all: Vec<(Task, u64)> = store.list().into_iter().filter(|t| t.status != Status::Discarded).map(|t| { let at = store.last_activity(&t); (t, at) }).collect();
    all.sort_by_key(|(_, a)| std::cmp::Reverse(*a));
    let recent = all.iter().take_while(|(_, a)| now.saturating_sub(*a) <= WINDOW_SECS).count();
    let keep = if recent == 0 { all.len().min(1) } else { recent }.min(limit);
    let left_out = all.len() - keep;
    all.truncate(keep);
    let current = store.current().map(|t| t.id);
    let target = branches::landing_for(&base.policy, None, top);
    let entries = all
        .into_iter()
        .map(|(task, activity)| {
            let target = branches::target_for(&base.policy, task.intent.as_ref(), top);
            let place = place_of(top, &task, current.as_deref());
            let verdict = if is_landed(top, &task, &target, place.as_ref()) { Verdict::Landed } else { place.as_ref().map_or(Verdict::Unknown, |p| judge(&task, p)) };
            Entry { task, activity, verdict, place }
        })
        .collect();
    Survey { entries, left_out, target }
}

/// Where to judge a task: see the module note.
pub fn place_of(top: &Path, task: &Task, current: Option<&str>) -> Option<Place> {
    if let Some(b) = task.branch.as_deref() {
        if git::resolve_commit(top, &format!("refs/heads/{b}")).is_some() {
            return Some(match branches::checked_out_at(top, b) {
                Some(dir) => Place { dir, tree: None },
                None => Place { dir: top.to_path_buf(), tree: Some(format!("refs/heads/{b}")) },
            });
        }
    }
    (current == Some(task.id.as_str())).then(|| Place { dir: top.to_path_buf(), tree: None })
}

/// Finished, and its commits are in the branch it was for (here or on origin), with nothing more
/// left uncommitted since. A task that made no commits has nothing to have landed.
fn is_landed(top: &Path, task: &Task, target: &str, place: Option<&Place>) -> bool {
    let Some(branch) = task.branch.as_deref().filter(|b| *b != target) else { return false };
    if task.status != Status::Finished {
        return false;
    }
    let head = git::resolve_commit(top, &format!("refs/heads/{branch}")).or_else(|| task.head.clone());
    let Some(head) = head.filter(|h| task.base_commit.as_deref() != Some(h.as_str())) else { return false };
    let clean = place.filter(|p| p.tree.is_none()).is_none_or(|p| branches::is_committed(&p.dir));
    clean && branches::landed_commit(top, &head, target)
}

fn judge(task: &Task, place: &Place) -> Verdict {
    let Ok(ctx) = Ctx::open_judging(&place.dir, Some(&task.id)) else { return Verdict::Unknown };
    let Ok(target) = ctx.target(place.tree.as_deref()) else { return Verdict::Unknown };
    match ctx.gate(&target) {
        Ok(g) => match g.decision {
            Decision::Allow => Verdict::Allowed,
            Decision::Wait => Verdict::Waiting,
            Decision::ApprovalRequired => Verdict::Needs(need_of(&g)),
            Decision::Deny => Verdict::Denied,
        },
        Err(_) => Verdict::Unknown,
    }
}

/// How long ago, for a person: `just now`, `5 min ago`, `3 h ago`, `2 d ago`.
pub fn ago(now: u64, then: u64) -> String {
    match now.saturating_sub(then) {
        0..=59 => "just now".to_string(),
        s @ 60..=3_599 => format!("{} min ago", s / 60),
        s @ 3_600..=86_399 => format!("{} h ago", s / 3_600),
        s => format!("{} d ago", s / 86_400),
    }
}

/// One line per task, aligned, for a list: title, id, `what` (what it needs, how it ended), who, when.
/// A row fits in `room` columns: the title gives way first.
pub fn list_rows(ui: &Ui, entries: &[&Entry], now: u64, room: usize, what: impl Fn(&Entry) -> String) -> Vec<String> {
    let _ = ui;
    let whos: Vec<String> = entries.iter().map(|e| e.who()).collect();
    let whats: Vec<String> = entries.iter().map(|e| what(e)).collect();
    let agos: Vec<String> = entries.iter().map(|e| ago(now, e.activity)).collect();
    let widest = |v: &[String]| v.iter().map(|w| w.chars().count()).max().unwrap_or(0);
    let (who_w, what_w, ago_w) = (widest(&whos).min(24), widest(&whats), widest(&agos));
    let id_w = entries.iter().map(|e| e.task.id.chars().count()).max().unwrap_or(0);
    let rest = 2 + id_w + 2 + if what_w > 0 { what_w + 2 } else { 0 } + who_w + 2 + ago_w;
    let title_w = entries.iter().map(|e| e.task.title.chars().count()).max().unwrap_or(0).min(room.saturating_sub(rest).max(12));
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mid = if what_w > 0 { format!("{:<what_w$}  ", whats[i]) } else { String::new() };
            format!("{:<title_w$}  {:<id_w$}  {mid}{:<who_w$}  {}", truncate_end(&e.task.title, title_w), e.task.id, truncate_end(&whos[i], who_w), agos[i])
        })
        .collect()
}

/// A `--task` names a task: the repo (a checkout) and tree to look at are the task's own, wherever
/// it is checked out, unless a tree was named. Falls back to what was given.
pub fn locate(repo: &Path, task: Option<&str>, tree: Option<&str>) -> (PathBuf, Option<String>) {
    let given = (repo.to_path_buf(), tree.map(str::to_string));
    let (Some(id), Ok(store)) = (task, use05_core::task::Store::open(repo)) else { return given };
    let Ok(task) = store.load(id) else { return given };
    let current = store.current().map(|t| t.id);
    match place_of(&store.dirs.top, &task, current.as_deref()) {
        Some(place) => (place.dir, tree.map(str::to_string).or(place.tree)),
        None => given,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_naturally() {
        assert_eq!(ago(1_000, 990), "just now");
        assert_eq!(ago(10_000, 10_000 - 5 * 60), "5 min ago");
        assert_eq!(ago(100_000, 100_000 - 3 * 3_600), "3 h ago");
        assert_eq!(ago(1_000_000, 1_000_000 - 2 * 86_400), "2 d ago");
        assert_eq!(ago(5, 10), "just now", "a clock that moved back is not a negative time");
    }
}

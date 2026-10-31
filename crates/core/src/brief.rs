//! The reviewer's one page, as data. The CLI renders it; `--json` prints it as is.

use serde::Serialize;

use crate::gate::GateResult;
use crate::intent::{IntentCard, Risk};
use crate::policy::Role;
use crate::task::Task;
use use05_receipt::Decision as Vote;

/// What the verdict asks of a reader (D66). Only `Allow` means nobody needs to read the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Allow,
    /// Let through by policy, but something broke the no-review rule: read the notes.
    AllowWithNotes,
    Wait,
    ApprovalRequired,
    Deny,
}

pub fn label_of(gate: &GateResult) -> Label {
    use crate::gate::{Decision, Effect};
    match gate.decision {
        Decision::Allow if gate.bypass.is_none() && !gate.findings.iter().any(|f| f.effect == Effect::Warn) => Label::Allow,
        Decision::Allow => Label::AllowWithNotes,
        Decision::Wait => Label::Wait,
        Decision::ApprovalRequired => Label::ApprovalRequired,
        Decision::Deny => Label::Deny,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Brief {
    pub label: Label,
    pub title: String,
    pub task_id: Option<String>,
    pub author: Option<String>,
    /// The person's request, when the agent's hooks exposed it. Kept on this machine only.
    pub request: Option<String>,
    /// Which agent did the work, and who is accountable for it (D71).
    pub agent: Option<crate::task::AgentId>,
    pub owner: Option<crate::task::Owner>,
    /// The owner's key signed an approval for this work.
    pub owner_confirmed: bool,
    /// The agent's own report of its sandbox.
    pub sandbox: Option<String>,
    pub goal: Option<String>,
    pub card: Option<IntentCard>,
    pub risk: Risk,
    pub tree: String,
    pub tree_label: String,
    /// Changed files grouped by top-level area, largest first.
    pub areas: Vec<(String, usize)>,
    pub outside_scope: Vec<String>,
    pub gate: GateResult,
    pub unknowns: Vec<String>,
    pub undo: Vec<String>,
}

fn area_of(path: &str) -> String {
    match path.split_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => "(root)".to_string(),
    }
}

pub fn build(task: Option<&Task>, gate: GateResult, tree: &str, tree_label: &str, base_commit: Option<&str>, head_commit: Option<&str>) -> Brief {
    let mut areas: Vec<(String, usize)> = Vec::new();
    for change in &gate.changed {
        let area = area_of(&change.path);
        match areas.iter_mut().find(|(a, _)| *a == area) {
            Some((_, n)) => *n += 1,
            None => areas.push((area, 1)),
        }
    }
    areas.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let card = task.and_then(|t| t.intent.clone());
    let outside_scope = gate.findings.iter().find(|f| f.code == "SCOPE_EXCEEDED").map(|f| f.paths.clone()).unwrap_or_default();

    let mut unknowns = Vec::new();
    unknowns.push("05 shows what was checked. It does not judge whether the change is correct.".to_string());
    if gate.checks.is_empty() {
        unknowns.push("policy requires no checks, so nothing was verified by running anything".to_string());
    }
    let proved_by: Vec<Role> = gate.checks.iter().filter_map(|c| match &c.state {
        crate::gate::CheckState::Passed { by, .. } => Some(by.role),
        _ => None,
    }).collect();
    if !proved_by.is_empty() && proved_by.iter().all(|r| *r == Role::Local) {
        unknowns.push("every passing check was signed only by a key on this machine, so it is advisory".to_string());
    }
    if card.as_ref().is_none_or(|c| !c.has_scope()) && task.is_some() {
        unknowns.push("no scope was declared, so scope drift was not checked".to_string());
    }
    let tests: Vec<&str> = gate.changed.iter().filter(|c| c.status != 'D' && crate::weakening::classify(&c.path) == crate::weakening::Class::Tests).map(|c| c.path.as_str()).collect();
    if !tests.is_empty() {
        unknowns.push(format!("this change edited {} test file(s) ({}): the checks partly grade this change's own tests", tests.len(), tests.join(", ")));
    }
    if gate.newer_receipts > 0 {
        unknowns.push(format!("{} receipt(s) were written by a newer version of 05 and were not read; update 05 to use them", gate.newer_receipts));
    }
    if gate.foreign_receipts > 0 {
        unknowns.push(format!("{} receipt(s) of other tools' kinds were not read", gate.foreign_receipts));
    }
    if gate.unverified_receipts > 0 {
        unknowns.push(format!("{} receipt(s) were ignored because no trusted key verifies them", gate.unverified_receipts));
    }
    if gate.approvals.iter().any(|a| a.vote == Vote::Approve && a.void.is_some()) {
        unknowns.push("an approval exists but no longer counts (expired, or the policy changed)".to_string());
    }

    // The recorded owner is confirmed by their own signed approval. A task recorded without an
    // owner gets one the moment a person with an approver key signs an approval for it.
    // The earliest signature wins, whatever order the receipts were found in. `created` is chosen
    // by the signer, so an unreadable one sorts last rather than first.
    let when = |a: &crate::gate::ApprovalInfo| crate::time::parse_rfc3339(&a.created).unwrap_or(u64::MAX);
    let signed_by = |key: Option<&str>| gate.approvals.iter().filter(|a| a.vote == Vote::Approve && a.void.is_none() && a.by.role == Role::Approver && key.is_none_or(|k| a.by.key_id == k)).min_by(|a, b| when(a).cmp(&when(b)).then(a.by.key_id.cmp(&b.by.key_id)));
    let recorded = task.and_then(|t| t.owner.clone());
    let (owner, owner_confirmed) = match recorded {
        // Confirmed: the name comes from the trusted key that signed, not from what was recorded,
        // which the agent could have edited.
        Some(o) => match signed_by(Some(&o.key_id)) {
            Some(a) => (Some(crate::task::Owner { name: a.by.name.clone(), key_id: o.key_id }), true),
            None => (Some(o), false),
        },
        None => match signed_by(None) {
            Some(a) => (Some(crate::task::Owner { name: a.by.name.clone(), key_id: a.by.key_id.clone() }), true),
            None => (None, false),
        },
    };
    if let Some(s) = task.and_then(|t| t.sandbox.as_deref()) {
        unknowns.push(format!("the agent reported running in Codex's sandbox ({}), which cannot write the log; this is the agent's own report", s.trim_start_matches("codex:")));
    }
    let short = |c: &str| c.chars().take(7).collect::<String>();
    let undo = match (base_commit, head_commit) {
        (Some(base), Some(head)) if base != head => vec![format!("git revert --no-commit {}..{}", short(base), short(head))],
        _ => vec!["git stash push   (keeps your work; nothing is deleted)".to_string()],
    };

    Brief {
        label: label_of(&gate),
        title: task.map(|t| t.title.clone()).unwrap_or_else(|| "Untracked change".to_string()),
        task_id: task.map(|t| t.id.clone()),
        author: task.map(|t| t.author.clone()),
        request: task.and_then(|t| t.request.clone()),
        agent: task.and_then(|t| t.agent.clone()),
        owner,
        owner_confirmed,
        sandbox: task.and_then(|t| t.sandbox.clone()),
        goal: card.as_ref().map(|c| c.goal.clone()).filter(|g| !g.is_empty()),
        card,
        risk: gate.risk,
        tree: tree.to_string(),
        tree_label: tree_label.to_string(),
        areas,
        outside_scope,
        gate,
        unknowns,
        undo,
    }
}

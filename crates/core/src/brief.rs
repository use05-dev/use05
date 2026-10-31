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
    /// Changed files by top-level folder, `[name, files]`, most first (the 0.0.1 shape).
    pub areas: Vec<(String, usize)>,
    /// Changed files grouped into at most 8 areas with line counts, most lines changed first.
    pub area_summary: Vec<Area>,
    /// Lines added and removed over the whole change.
    pub added: u64,
    pub removed: u64,
    pub outside_scope: Vec<String>,
    /// The files outside the declared scope, grouped the same way into at most 6 areas.
    pub outside_scope_areas: Vec<Area>,
    pub gate: GateResult,
    pub unknowns: Vec<String>,
    pub undo: Vec<String>,
    /// What happened during the agent's session, from its action log; `None` without a log.
    pub session: Option<crate::session::Session>,
}

/// A part of the change: a directory (ending in `/`), `(root)` for files at the top, or
/// `(N more areas)` for the rest folded together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Area {
    pub name: String,
    pub files: usize,
    pub added: u64,
    pub removed: u64,
}

/// The directory a path falls in at `depth` segments, or `None` when the file sits above it.
fn dir_at(path: &str, depth: usize) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    (parts.len() > depth).then(|| format!("{}/", parts[..depth].join("/")))
}

/// Group changed files into at most `max` areas a person can take in. Start at the top-level
/// directories; while there is room, split the area with the most lines changed into its
/// subdirectories, folding those that do not fit into one `(N more in dir/)` row; a lone
/// subdirectory takes its area's place. Most lines changed first, then by name; anything past
/// `max - 1` areas is folded into one `(N more areas)` row. Linear in the number of files.
pub fn areas(changes: &[(&str, u64, u64)], max: usize) -> Vec<Area> {
    // A group: its name, how deep its directory is (0: never split), its files, lines changed.
    struct Group {
        name: String,
        depth: usize,
        members: Vec<usize>,
        lines: u64,
    }
    // The groups one level below `depth`; files directly at that level stay together as `parent`.
    let group_by = |members: &[usize], depth: usize, parent: &str| -> Vec<Group> {
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut out: Vec<Group> = Vec::new();
        for &i in members {
            let (name, d) = match dir_at(changes[i].0, depth + 1) {
                Some(k) => (k, depth + 1),
                None => (parent.to_string(), 0),
            };
            let at = *index.entry(name.clone()).or_insert_with(|| {
                out.push(Group { name, depth: d, members: Vec::new(), lines: 0 });
                out.len() - 1
            });
            out[at].members.push(i);
            out[at].lines += changes[i].1 + changes[i].2;
        }
        out
    };
    let by_size = |a: &Group, b: &Group| b.lines.cmp(&a.lines).then(a.name.cmp(&b.name));
    let all: Vec<usize> = (0..changes.len()).collect();
    let mut groups = group_by(&all, 0, "(root)");
    loop {
        // A group whose files all sit in one deeper directory takes that directory's name.
        for g in groups.iter_mut() {
            while g.depth > 0 {
                let mut kids = group_by(&g.members, g.depth, &g.name);
                if kids.len() == 1 && kids[0].depth > 0 {
                    *g = kids.pop().expect("one");
                } else {
                    break;
                }
            }
        }
        if groups.len() >= max {
            break;
        }
        let mut order: Vec<usize> = (0..groups.len()).filter(|&i| groups[i].depth > 0).collect();
        order.sort_by(|&a, &b| by_size(&groups[a], &groups[b]));
        let room = max - (groups.len() - 1);
        let split = order.into_iter().find_map(|i| {
            let kids = group_by(&groups[i].members, groups[i].depth, &groups[i].name);
            (kids.len() > 1 && room >= 2).then_some((i, kids))
        });
        let Some((i, mut kids)) = split else { break };
        let parent = groups.remove(i);
        if kids.len() > room {
            kids.sort_by(by_size);
            let rest = kids.split_off(room - 1);
            kids.push(Group {
                name: format!("({} more in {})", rest.len(), parent.name),
                depth: 0,
                lines: rest.iter().map(|g| g.lines).sum(),
                members: rest.into_iter().flat_map(|g| g.members).collect(),
            });
        }
        groups.extend(kids);
    }
    // Named areas first; a folded `(N more in dir/)` row comes after them, whatever its size.
    groups.sort_by(|a, b| a.name.starts_with('(').cmp(&b.name.starts_with('(')).then(by_size(a, b)));
    let mut out: Vec<Area> = groups.iter().map(|g| Area {
        name: g.name.clone(),
        files: g.members.len(),
        added: g.members.iter().map(|&i| changes[i].1).sum(),
        removed: g.members.iter().map(|&i| changes[i].2).sum(),
    }).collect();
    if out.len() > max && max > 0 {
        let rest = out.split_off(max - 1);
        out.push(Area {
            name: format!("({} more areas)", rest.len()),
            files: rest.iter().map(|a| a.files).sum(),
            added: rest.iter().map(|a| a.added).sum(),
            removed: rest.iter().map(|a| a.removed).sum(),
        });
    }
    out
}

/// Changed files by top-level folder, most first: the `areas` field `brief --json` has printed
/// since 0.0.1, kept so programs that read it keep working.
fn top_level(changes: &[(&str, u64, u64)]) -> Vec<(String, usize)> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (path, _, _) in changes {
        let area = match path.split_once('/') {
            Some((dir, _)) => dir.to_string(),
            None => "(root)".to_string(),
        };
        *counts.entry(area).or_default() += 1;
    }
    let mut out: Vec<(String, usize)> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// The unknown for a change that edits its own tests: names three, counts the rest.
fn tests_edited(tests: &[&str]) -> String {
    let shown = tests.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = if tests.len() > 3 { format!(" and {} more", tests.len() - 3) } else { String::new() };
    format!("this change edited {} test file(s) ({shown}{more}): the checks partly grade this change's own tests", tests.len())
}

pub fn build(task: Option<&Task>, gate: GateResult, tree: &str, tree_label: &str, base_commit: Option<&str>, head_commit: Option<&str>) -> Brief {
    let counted: Vec<(&str, u64, u64)> = gate.changed.iter().map(|c| (c.path.as_str(), c.added, c.removed)).collect();
    let by_area = areas(&counted, 8);
    let by_folder = top_level(&counted);
    let (added, removed) = (gate.changed.iter().map(|c| c.added).sum(), gate.changed.iter().map(|c| c.removed).sum());

    let card = task.and_then(|t| t.intent.clone());
    let outside_scope = gate.findings.iter().find(|f| f.code == "SCOPE_EXCEEDED").map(|f| f.paths.clone()).unwrap_or_default();
    let outside_set: std::collections::HashSet<&str> = outside_scope.iter().map(String::as_str).collect();
    let outside: Vec<(&str, u64, u64)> = counted.iter().filter(|(p, _, _)| outside_set.contains(p)).copied().collect();
    let outside_scope_areas = areas(&outside, 6);

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
        unknowns.push(tests_edited(&tests));
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
        areas: by_folder,
        area_summary: by_area,
        added,
        removed,
        outside_scope,
        outside_scope_areas,
        gate,
        unknowns,
        undo,
        session: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn many(dir: &str, n: usize, lines: u64) -> Vec<(String, u64, u64)> {
        (0..n).map(|i| (format!("{dir}f{i}.rs"), lines, 0)).collect()
    }

    fn view(v: &[(String, u64, u64)]) -> Vec<(&str, u64, u64)> {
        v.iter().map(|(p, a, r)| (p.as_str(), *a, *r)).collect()
    }

    #[test]
    fn areas_split_the_largest_group_until_it_is_informative() {
        let mut v = many("src/billing/", 285, 100);
        v.extend(many("src/api/", 225, 100));
        v.extend(many("src/ui/", 80, 40));
        v.extend(many("src/auth/", 40, 30));
        v.extend(many("tests/", 30, 0).into_iter().map(|(p, _, _)| (p, 0, 20)));
        v.push(("package.json".into(), 1, 1));
        let got = areas(&view(&v), 8);
        let names: Vec<&str> = got.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["src/billing/", "src/api/", "src/ui/", "src/auth/", "tests/", "(root)"]);
        let files: Vec<usize> = got.iter().map(|a| a.files).collect();
        assert_eq!(files, [285, 225, 80, 40, 30, 1]);
        assert_eq!((got[0].added, got[0].removed), (28_500, 0));
        assert_eq!((got[4].added, got[4].removed), (0, 600));
    }

    #[test]
    fn areas_terminate_for_flat_and_deep_layouts() {
        let root = many("", 10, 1);
        assert_eq!(areas(&view(&root), 8).iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["(root)"]);
        let deep = many("a/b/c/d/", 10, 1);
        let got = areas(&view(&deep), 8);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].name.as_str(), got[0].files), ("a/b/c/d/", 10));
        let wide: Vec<(String, u64, u64)> = (0..20).map(|i| (format!("d{i:02}/x.rs"), 20 - i as u64, 0)).collect();
        let got = areas(&view(&wide), 8);
        assert_eq!(got.len(), 8);
        assert_eq!(got[0].name, "d00/");
        assert_eq!(got[7].name, "(13 more areas)");
        assert_eq!(got[7].files, 13);
        assert_eq!(got[7].added, (1..=13).sum::<u64>());
    }

    #[test]
    fn a_big_area_with_many_subfolders_is_split_and_the_rest_folded() {
        let mut v: Vec<(String, u64, u64)> = (0..20).flat_map(|i| many(&format!("src/d{i:02}/"), 5, 20 + i as u64)).collect();
        v.extend(many("tests/k0/", 1, 1));
        v.extend(many("tests/k1/", 1, 1));
        let got = areas(&view(&v), 8);
        assert_eq!(got.len(), 8, "{got:?}");
        assert_eq!(got[0].name, "src/d19/", "the biggest area's own subfolders get the rows: {got:?}");
        assert!(got.iter().any(|a| a.name.starts_with("(") && a.name.contains("more in src/")), "{got:?}");
        assert_eq!(got.iter().map(|a| a.files).sum::<usize>(), 102);
    }

    #[test]
    fn areas_handle_fifty_thousand_files_quickly() {
        // Every file in a folder of its own: as many groups as files.
        let v: Vec<(String, u64, u64)> = (0..50_000).map(|i| (format!("d{i}/f.rs"), 3, 1)).collect();
        let started = std::time::Instant::now();
        let got = areas(&view(&v), 8);
        assert!(started.elapsed() < std::time::Duration::from_millis(800), "took {:?}", started.elapsed());
        assert_eq!(got.iter().map(|a| a.files).sum::<usize>(), 50_000);
    }

    #[test]
    fn the_test_file_unknown_names_at_most_three() {
        let names: Vec<String> = (0..30).map(|i| format!("tests/t{i}.rs")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let line = tests_edited(&refs);
        assert!(line.starts_with("this change edited 30 test file(s) (tests/t0.rs, tests/t1.rs, tests/t2.rs and 27 more)"), "{line}");
        assert_eq!(tests_edited(&["a_test.rs"]), "this change edited 1 test file(s) (a_test.rs): the checks partly grade this change's own tests");
    }
}

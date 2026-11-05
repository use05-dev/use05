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
    /// Where the change lands and the environment that branch is, when the policy names
    /// environments: `main (dev)`.
    pub lands_on: Option<String>,
    /// How much the decision rests on (D101), worked out from `gate`. Never changes it.
    pub assurance: Assurance,
    /// The change as a short story, each line labelled by where it comes from (D102 part 1).
    /// Derived from the rest of the brief; refresh it with [`story`] after changing the brief.
    pub story: Story,
}

/// The change told in a few lines (D102, the Change Story's first part), each labelled by where it
/// comes from: the person's words, the agent's words, what 05 saw itself, what the checks found,
/// what holds it for a person, and what nobody established. Derived from the brief alone: it
/// decides nothing, and an agent's words are never shown as a fact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Story {
    /// What the person asked, when the agent's hooks kept it: their words, first line. Kept on
    /// this machine.
    pub asked: Option<String>,
    /// What the agent says it did: its own words, first line. An assertion, not a finding.
    pub agent_says: Option<String>,
    /// The agent's claims, each with what the evidence on this tree says of it.
    pub claims: Vec<StoryClaim>,
    /// How many claims the evidence supports, has nothing to say about, and contradicts.
    pub claim_counts: ClaimCounts,
    /// What 05 observed itself, from the tree and the rules: files and areas, work outside the
    /// plan, test files edited, risk areas, other sessions on the same files.
    pub observed: Vec<String>,
    /// What the required checks found, in the assurance's own words.
    pub checked: String,
    /// What holds the change for a person or refuses it, first reasons first (at most three).
    pub needs_you: Vec<String>,
    /// What nobody established.
    pub not_known: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoryClaim {
    /// The agent's words.
    pub text: String,
    /// `supported`, `unsupported` (no check of its kind ran) or `contradicted`.
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaimCounts {
    pub supported: usize,
    pub unsupported: usize,
    pub contradicted: usize,
}

/// The first line of a text, trimmed, at most 160 characters.
fn first_line(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(if line.chars().count() > 160 { format!("{}…", line.chars().take(159).collect::<String>()) } else { line.to_string() })
}

/// The story of `b`, from what the brief holds. `outcome` is the agent's own report of what it did.
pub fn story(b: &Brief, outcome: Option<&str>) -> Story {
    use crate::claims::Judged;
    use crate::gate::Effect;
    let mut claims = Vec::new();
    let mut counts = ClaimCounts::default();
    for c in &b.gate.claims {
        let status = match c.judged {
            Judged::Supported { .. } => {
                counts.supported += 1;
                "supported"
            }
            Judged::Unsupported => {
                counts.unsupported += 1;
                "unsupported"
            }
            Judged::Contradicted { .. } => {
                counts.contradicted += 1;
                "contradicted"
            }
        };
        claims.push(StoryClaim { text: c.text.clone(), status });
    }

    let mut observed = Vec::new();
    let n = b.gate.changed.len();
    if n == 0 {
        observed.push("no files changed".to_string());
    } else {
        let names: Vec<&str> = b.area_summary.iter().take(3).map(|a| if a.name == "(root)" { "the top folder" } else { a.name.as_str() }).collect();
        let more = if b.area_summary.len() > 3 { format!(" and {} more", b.area_summary.len() - 3) } else { String::new() };
        observed.push(format!("{n} file{} changed in {}{more} · +{} −{}", if n == 1 { "" } else { "s" }, names.join(", "), b.added, b.removed));
    }
    if !b.outside_scope.is_empty() {
        let k = b.outside_scope.len();
        observed.push(format!("{k} file{} outside the plan", if k == 1 { "" } else { "s" }));
    }
    if b.assurance.tests_changed > 0 {
        let t = b.assurance.tests_changed;
        observed.push(format!("{t} test file{} edited by this change", if t == 1 { "" } else { "s" }));
    }
    if !b.gate.risk_reasons.is_empty() {
        let mut cats: Vec<String> = b.gate.risk_reasons.iter().map(|r| r.category.to_string()).collect();
        cats.dedup();
        observed.push(format!("in a risk area: {}", cats.join(", ")));
    }
    if b.gate.findings.iter().any(|f| f.code == "OVERLAP") {
        observed.push("another agent session edited some of the same files lately".to_string());
    }

    let needs_you: Vec<String> = match &b.gate.bypass {
        Some(by) => vec![format!("let through by break-glass ({}): \"{}\"", by.by.name, by.reason)],
        // What a person decides: an approval, or a refusal. A check still to run is not theirs to
        // decide; the checks line says so.
        // Testing before a push is a person's too, though the brief itself is not a push.
        None => b.gate.findings.iter().filter(|f| f.effect >= Effect::Approval || f.code == "TESTING_NOT_SIGNED").take(3).map(|f| f.message.clone()).collect(),
    };

    let mut not_known = vec!["behaviour beyond these checks".to_string()];
    if b.task_id.is_some() && b.card.as_ref().is_none_or(|c| !c.has_scope()) {
        not_known.push("whether it stayed in scope: no scope was declared".to_string());
    }
    if counts.unsupported > 0 {
        not_known.push(match counts.unsupported {
            1 => "one of the agent's claims: no check of its kind ran".to_string(),
            n => format!("{n} of the agent's claims: no check of their kind ran"),
        });
    }
    // Where the tests come from (S4): never more than the names and the rules say.
    match b.assurance.test_origin {
        Some("protected") => observed.push("the test files are under the policy's protect rules: changing them needs a person".to_string()),
        Some("not_protected") if b.assurance.checks_required > 0 => not_known.push("whether the tests stand apart from the change: no protect rule covers the test files, so a change could rewrite them".to_string()),
        Some("none_found") if b.assurance.checks_required > 0 => not_known.push("what the checks test: no file in the tree is named like a test".to_string()),
        _ => {}
    }

    Story {
        asked: b.request.as_deref().and_then(first_line),
        agent_says: outcome.and_then(first_line),
        claims,
        claim_counts: counts,
        observed,
        checked: b.assurance.summary.clone(),
        needs_you,
        not_known,
    }
}

/// Who signed the results that speak for the required checks on this tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// No required check has a result on this tree.
    None,
    /// Every result was signed by a key on a developer's machine, which an agent running as that
    /// user can reach.
    LocalAdvisory,
    /// Every result was signed by a runner key. It says who ran the check, not that a host
    /// requires it.
    RunnerSigned,
    /// Some of each.
    Mixed,
}

/// Said beside a verdict reached with no check run (D101): the agent's window and the bare page.
pub const NO_CHECKS_RAN: &str = "no checks ran, behaviour not verified";

/// How much the gate's decision rests on (D101): counts and signers of the required checks, the
/// test files the change edits itself, and what nobody assessed. Derived from a [`GateResult`]
/// alone; it is not a score, and nothing reads it to decide anything.
#[derive(Debug, Clone, Serialize)]
pub struct Assurance {
    /// Checks the policy or the declaration requires for this change.
    pub checks_required: usize,
    pub passed: usize,
    /// Failed or timed out.
    pub failed: usize,
    /// No result on this tree, or asked for by the declaration but not defined in the policy.
    pub missing: usize,
    /// Passed on an earlier tree only.
    pub stale: usize,
    /// A result exists, but only from a signer the policy does not accept.
    pub not_accepted: usize,
    /// Checks scoped to paths this change does not touch (D97).
    pub not_required: usize,
    pub evidence: EvidenceStrength,
    /// Required checks whose result was signed by a key on a developer's machine.
    pub local_only: usize,
    /// Test files this change adds or edits.
    pub tests_changed: usize,
    /// Whether anything checked behaviour beyond the checks' exit codes: `not_assessed`.
    pub behaviour: &'static str,
    /// `ci_gate` when this is the CI gate's own run; otherwise `unknown`. Whether a host requires
    /// the gate before merging is never known from here.
    pub enforcement: &'static str,
    /// The checks line, after `Checks: `.
    pub summary: String,
    /// What the decision does not rest on, in plain words.
    pub limitations: Vec<String>,
    /// Where the tests that judge the change come from (S4, see [`test_origin`]). Set by the
    /// brief and the CI gate, which read the tree's file names; absent where nothing read them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_origin: Option<&'static str>,
}

impl Assurance {
    /// The lines shown beside the verdict: the checks, a note when checks ran and the change edits
    /// its own tests, and that behaviour beyond the checks is not assessed. With no check run,
    /// that last is already in the first line, and no test graded anything.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!("Checks: {}", self.summary)];
        if self.tests_changed > 0 && self.checks_required > 0 {
            out.push(format!("Note: this change also edits {} test file(s), so it partly grades itself", self.tests_changed));
        }
        if self.checks_required > 0 {
            out.push("Behaviour beyond these checks: not assessed".to_string());
        }
        out
    }

    /// What the shortest verdicts add when no required check ran; `None` when checks ran.
    pub fn qualifier(&self) -> Option<&'static str> {
        (self.checks_required == 0).then_some(NO_CHECKS_RAN)
    }
}

/// The changed test files a change edits or adds itself (a deleted one grades nothing).
fn changed_tests(gate: &GateResult) -> Vec<&str> {
    gate.changed.iter().filter(|c| c.status != 'D' && crate::weakening::classify(&c.path) == crate::weakening::Class::Tests).map(|c| c.path.as_str()).collect()
}

/// Where the tests that judge a change come from, as far as file names and the rules tell (S4):
/// `edited_by_change` (it edits test files itself, so it partly grades itself), `protected` (every
/// test file 05 recognises in the tree is under a `[protect]` rule, so changing one needs a person
/// or is refused), `not_protected` (unchanged this time, but nothing stops a change editing them),
/// `none_found`, or `unknown` when the tree cannot be read. It does not say the tests are good or
/// that they check what was asked. Reads the tree's file names once; not for the hooks' hot path.
pub fn test_origin(top: &std::path::Path, tree: &str, policy: &crate::policy::Policy, edited: usize) -> &'static str {
    if edited > 0 {
        return "edited_by_change";
    }
    let Ok(raw) = crate::git::run(top, &["ls-tree", "-r", "--name-only", "-z", "--full-tree", tree]) else { return "unknown" };
    let tests: Vec<String> = raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).to_string()).filter(|p| crate::weakening::classify(p) == crate::weakening::Class::Tests).collect();
    if tests.is_empty() {
        return "none_found";
    }
    let p = &policy.protect;
    let rules: Vec<&String> = p.paths.iter().chain(&p.locked).chain(&p.absolute).chain(&p.append_only).collect();
    if tests.iter().all(|t| rules.iter().any(|r| crate::glob::matches(r, t))) { "protected" } else { "not_protected" }
}

/// Work out [`Assurance`] from what the gate found. `ci_gate` is true in the CI gate's own run.
pub fn assurance(gate: &GateResult, ci_gate: bool) -> Assurance {
    use crate::gate::CheckState as S;
    let required: Vec<&crate::gate::CheckStatus> = gate.checks.iter().filter(|c| c.required && !matches!(c.state, S::NotRequired { .. })).collect();
    let count = |f: fn(&S) -> bool| required.iter().filter(|c| f(&c.state)).count();
    let passed = count(|s| matches!(s, S::Passed { .. }));
    let failed = count(|s| matches!(s, S::Failed { .. } | S::TimedOut { .. }));
    let missing = count(|s| matches!(s, S::Missing | S::Undefined));
    let stale = count(|s| matches!(s, S::Stale));
    let not_accepted = count(|s| matches!(s, S::NotAuthoritative { .. }));
    let not_required = gate.checks.iter().filter(|c| matches!(c.state, S::NotRequired { .. })).count();
    // The receipts that speak for a check on this tree (D66): its result, passed or not.
    let roles: Vec<Role> = required.iter().filter_map(|c| match &c.state {
        S::Passed { by, .. } | S::Failed { by, .. } | S::TimedOut { by } => Some(by.role),
        _ => None,
    }).collect();
    let runner = roles.iter().filter(|r| **r == Role::Runner).count();
    let local_only = roles.len() - runner;
    let evidence = match (runner, local_only) {
        (0, 0) => EvidenceStrength::None,
        (0, _) => EvidenceStrength::LocalAdvisory,
        (_, 0) => EvidenceStrength::RunnerSigned,
        _ => EvidenceStrength::Mixed,
    };
    let tests_changed = changed_tests(gate).len();
    let checks_required = required.len();
    // Said the same wherever it is read (here, in CI, on the console): never "this machine".
    let local_where = "on the machine that ran it";
    let unmet = failed + missing + stale + not_accepted;
    // A check the policy defines with `required = false` is not in the gate's list at all, so
    // "none required" is what is known, never "none configured".
    let summary = if checks_required == 0 {
        if not_required > 0 { "none required for the files this change touches; behaviour not verified".to_string() } else { "none required; behaviour not verified".to_string() }
    } else if unmet > 0 {
        let parts = [
            (failed, "failed"),
            (missing, "not run on this tree"),
            (stale, "stale (passed on an earlier tree)"),
            (not_accepted, "proved only by a key the policy does not accept"),
            (passed, "passed"),
        ];
        parts.iter().filter(|(n, _)| *n > 0).map(|(n, what)| format!("{n} {what}")).collect::<Vec<_>>().join(", ")
    } else {
        match evidence {
            EvidenceStrength::RunnerSigned => format!("{passed} passed, signed by CI (merge enforcement not confirmed from here)"),
            EvidenceStrength::Mixed => format!("{passed} passed: {runner} signed by CI, {local_only} {local_where} (advisory; merge enforcement not confirmed from here)"),
            _ => format!("{passed} passed {local_where} (advisory: an agent can run as its user)"),
        }
    };
    let mut limitations = Vec::new();
    if checks_required == 0 {
        limitations.push("no check ran, so behaviour was not verified by running anything".to_string());
    } else if unmet > 0 {
        limitations.push(format!("{unmet} required check(s) have no accepted passing result on this tree"));
    }
    if local_only > 0 {
        limitations.push("a result signed on a developer's machine is advisory: an agent running as that user can sign it".to_string());
    }
    if runner > 0 {
        limitations.push("a CI signature says who ran the check, not that the host requires it before merging".to_string());
    }
    // Tests grade a change only when a check ran them.
    if tests_changed > 0 && checks_required > 0 {
        limitations.push(format!("this change also edits {tests_changed} test file(s), so it partly grades itself"));
    }
    limitations.push("behaviour beyond these checks is not assessed".to_string());
    Assurance {
        checks_required,
        passed,
        failed,
        missing,
        stale,
        not_accepted,
        not_required,
        evidence,
        local_only,
        tests_changed,
        behaviour: "not_assessed",
        enforcement: if ci_gate { "ci_gate" } else { "unknown" },
        summary,
        limitations,
        test_origin: None,
    }
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
                // Files directly in a split directory: `src/*`, so the row cannot be read as all of `src/`.
                None if parent.ends_with('/') => (format!("{parent}*"), 0),
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

/// The unknown for changed files that no check's `paths` name: names three, counts the rest.
fn uncovered_files(files: &[&str]) -> String {
    let shown = files.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = if files.len() > 3 { format!(" and {} more", files.len() - 3) } else { String::new() };
    let n = files.len();
    format!("{n} changed file{} {} outside every check's paths, so no check was required for {}: {shown}{more}", if n == 1 { "" } else { "s" }, if n == 1 { "is" } else { "are" }, if n == 1 { "it" } else { "them" })
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
    } else if gate.checks.iter().all(|c| matches!(c.state, crate::gate::CheckState::NotRequired { .. })) {
        unknowns.push("no check was required for the files this change touches, so nothing was verified by running anything".to_string());
    }
    // Checks scoped to paths (D97) cover only their paths: files in none of them, with no check that
    // is required for every change, were checked by nothing.
    let scoped: Vec<&Vec<String>> = gate.checks.iter().map(|c| &c.paths).filter(|p| !p.is_empty()).collect();
    if !scoped.is_empty() && !gate.checks.iter().any(|c| c.paths.is_empty() && c.required) {
        let uncovered: Vec<&str> = gate.changed.iter().map(|c| c.path.as_str()).filter(|f| !scoped.iter().any(|p| crate::policy::paths_cover(p, f))).collect();
        if !uncovered.is_empty() {
            unknowns.push(uncovered_files(&uncovered));
        }
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
    let tests = changed_tests(&gate);
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
    match gate.lfs_pointers {
        0 => {}
        1 => unknowns.push("1 LFS file was checked as a pointer (set [evidence] lfs = true to check the real file)".to_string()),
        n => unknowns.push(format!("{n} LFS files were checked as pointers (set [evidence] lfs = true to check the real files)")),
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

    let mut brief = Brief {
        label: label_of(&gate),
        assurance: assurance(&gate, false),
        story: Story::default(),
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
        lands_on: None,
    };
    brief.refresh_story(task.and_then(|t| t.outcome.as_deref()));
    brief
}

impl Brief {
    /// Say where the tests come from (S4), reading the tree's file names, and tell the story again.
    pub fn read_test_origin(&mut self, top: &std::path::Path, policy: &crate::policy::Policy) {
        self.assurance.test_origin = Some(test_origin(top, &self.tree, policy, self.assurance.tests_changed));
        self.refresh_story(None);
    }

    /// Work the story out again, after something it rests on changed (the assurance in CI, say).
    pub fn refresh_story(&mut self, outcome: Option<&str>) {
        let keep = self.story.agent_says.clone();
        self.story = story(self, outcome);
        if outcome.is_none() {
            self.story.agent_says = keep;
        }
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
    fn files_directly_in_a_split_folder_are_named_as_such() {
        let mut v = many("src/x/", 3, 10);
        v.extend(many("src/y/", 3, 10));
        v.extend(many("src/", 2, 1));
        let got = areas(&view(&v), 8);
        let names: Vec<&str> = got.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"src/*") && !names.contains(&"src/"), "{names:?}");
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

    // ------------------------------------------------------------- assurance (D101)

    use crate::evidence::Signer;
    use crate::gate::{ChangeInfo, CheckState, CheckStatus, Decision};

    fn signer(role: Role) -> Signer {
        Signer { name: if role == Role::Runner { "ci".into() } else { "this machine".into() }, role, key_id: format!("{role:?}") }
    }

    fn check(name: &str, required: bool, state: CheckState) -> CheckStatus {
        CheckStatus { name: name.into(), run: vec!["./test.sh".into()], dir: None, paths: Vec::new(), required, state }
    }

    fn gate_with(checks: Vec<CheckStatus>, changed: &[&str]) -> GateResult {
        let mut g = GateResult::of_findings(Decision::Allow, Vec::new(), "p".into());
        g.checks = checks;
        g.changed = changed.iter().map(|p| ChangeInfo { status: 'M', path: (*p).into(), added: 1, removed: 0 }).collect();
        g
    }

    fn passed(role: Role) -> CheckState {
        CheckState::Passed { by: signer(role), ms: 10 }
    }

    #[test]
    fn assurance_with_no_checks_says_behaviour_not_verified() {
        let a = assurance(&gate_with(Vec::new(), &["main.rs"]), false);
        assert_eq!((a.checks_required, a.passed, a.evidence), (0, 0, EvidenceStrength::None));
        assert_eq!(a.lines(), ["Checks: none required; behaviour not verified"], "folded into one line");
        assert_eq!(a.qualifier(), Some("no checks ran, behaviour not verified"));
        assert_eq!((a.behaviour, a.enforcement), ("not_assessed", "unknown"));
        // Checks scoped to other paths (D97) are listed, but none was required.
        let scoped = assurance(&gate_with(vec![check("web", false, CheckState::NotRequired { reason: crate::gate::NOT_REQUIRED_REASON, result: None })], &["main.rs"]), false);
        assert_eq!((scoped.checks_required, scoped.not_required), (0, 1));
        assert_eq!(scoped.lines(), ["Checks: none required for the files this change touches; behaviour not verified"]);
        assert!(scoped.qualifier().is_some());
        for line in a.lines().iter().chain(scoped.lines().iter()) {
            for word in ["verified correct", "proven", "score"] {
                assert!(!line.contains(word), "{line}");
            }
        }
    }

    #[test]
    fn local_only_checks_are_labelled_advisory() {
        let a = assurance(&gate_with(vec![check("test", true, passed(Role::Local)), check("lint", true, passed(Role::Local))], &["main.rs"]), false);
        assert_eq!((a.checks_required, a.passed, a.local_only, a.evidence), (2, 2, 2, EvidenceStrength::LocalAdvisory));
        assert_eq!(a.lines(), ["Checks: 2 passed on the machine that ran it (advisory: an agent can run as its user)", "Behaviour beyond these checks: not assessed"]);
        assert_eq!(a.qualifier(), None, "checks ran: the agent window keeps today's text");
        assert!(a.limitations.iter().any(|l| l.contains("advisory")), "{:?}", a.limitations);
    }

    #[test]
    fn runner_signed_checks_are_labelled_ci_signed_not_enforced() {
        let a = assurance(&gate_with(vec![check("test", true, passed(Role::Runner))], &["main.rs"]), false);
        assert_eq!((a.passed, a.local_only, a.evidence, a.enforcement), (1, 0, EvidenceStrength::RunnerSigned, "unknown"));
        assert_eq!(a.lines()[0], "Checks: 1 passed, signed by CI (merge enforcement not confirmed from here)");
        assert!(a.limitations.iter().any(|l| l.contains("not that the host requires it")), "{:?}", a.limitations);
        // The CI gate's own run knows it is the CI gate, never that the host requires it.
        let ci = assurance(&gate_with(vec![check("test", true, passed(Role::Runner))], &["main.rs"]), true);
        assert_eq!(ci.enforcement, "ci_gate");
        assert!(ci.lines()[0].contains("merge enforcement not confirmed"), "{:?}", ci.lines());
        // A machine key's result read in CI: the same words as anywhere, never "this machine".
        let ci_local = assurance(&gate_with(vec![check("test", true, passed(Role::Local))], &["main.rs"]), true);
        assert_eq!((ci_local.evidence, ci_local.enforcement), (EvidenceStrength::LocalAdvisory, "ci_gate"));
        assert_eq!(ci_local.lines()[0], "Checks: 1 passed on the machine that ran it (advisory: an agent can run as its user)");
        // Both kinds: said apart.
        let mixed = assurance(&gate_with(vec![check("test", true, passed(Role::Runner)), check("lint", true, passed(Role::Local))], &["main.rs"]), false);
        assert_eq!((mixed.evidence, mixed.local_only), (EvidenceStrength::Mixed, 1));
        assert_eq!(mixed.lines()[0], "Checks: 2 passed: 1 signed by CI, 1 on the machine that ran it (advisory; merge enforcement not confirmed from here)");
    }

    #[test]
    fn stale_and_failed_checks_never_count_as_passed() {
        let checks = vec![
            check("test", true, CheckState::Failed { by: signer(Role::Local), exit_code: Some(1) }),
            check("lint", true, CheckState::Stale),
            check("e2e", true, CheckState::Missing),
            check("fmt", true, passed(Role::Local)),
            check("slow", true, CheckState::TimedOut { by: signer(Role::Local) }),
            check("ci", true, CheckState::NotAuthoritative { by: signer(Role::Local) }),
            check("docs", false, CheckState::NotRequired { reason: crate::gate::NOT_REQUIRED_REASON, result: Some(crate::gate::SeenResult { status: use05_receipt::Status::Passed, by: signer(Role::Local), ms: 1 }) }),
        ];
        let a = assurance(&gate_with(checks, &["main.rs"]), false);
        assert_eq!((a.checks_required, a.passed, a.failed, a.stale, a.missing, a.not_accepted, a.not_required), (6, 1, 2, 1, 1, 1, 1));
        assert_eq!(a.lines()[0], "Checks: 2 failed, 1 not run on this tree, 1 stale (passed on an earlier tree), 1 proved only by a key the policy does not accept, 1 passed");
        assert_eq!(a.qualifier(), None);
        let none_passed = assurance(&gate_with(vec![check("lint", true, CheckState::Stale)], &["main.rs"]), false);
        assert_eq!(none_passed.lines()[0], "Checks: 1 stale (passed on an earlier tree)");
        assert_eq!(none_passed.evidence, EvidenceStrength::None, "a stale receipt is not evidence for this tree");
    }

    #[test]
    fn a_change_that_edits_its_tests_gets_the_caveat() {
        let a = assurance(&gate_with(vec![check("test", true, passed(Role::Local))], &["src/lib.rs", "tests/cli.rs"]), false);
        assert_eq!(a.tests_changed, 1);
        assert_eq!(a.lines(), [
            "Checks: 1 passed on the machine that ran it (advisory: an agent can run as its user)",
            "Note: this change also edits 1 test file(s), so it partly grades itself",
            "Behaviour beyond these checks: not assessed",
        ]);
        let deleted_only = {
            let mut g = gate_with(Vec::new(), &[]);
            g.changed = vec![ChangeInfo { status: 'D', path: "tests/old.rs".into(), added: 0, removed: 3 }];
            assurance(&g, false)
        };
        assert_eq!(deleted_only.tests_changed, 0, "a deleted test grades nothing; deletion is the weakening check's to judge");
        // With no check run, no test graded anything: counted, but no note.
        let unchecked = assurance(&gate_with(Vec::new(), &["tests/cli.rs"]), false);
        assert_eq!(unchecked.tests_changed, 1);
        assert_eq!(unchecked.lines(), ["Checks: none required; behaviour not verified"]);
        assert!(!unchecked.limitations.iter().any(|l| l.contains("grades itself")), "{:?}", unchecked.limitations);
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

//! Which rules ask a person most, and whether the person ever says no (D91).
//!
//! Each approval or rejection at this machine records the rules that held the change back for
//! a person: the finding code and the area (top folder) its files are in. Nothing else: no
//! paths beyond the top folder, no content. A rule that asked five times or more in thirty days
//! and was never refused is costing attention and catching nothing, and 05 says so; it never
//! changes the rule itself. Deterministic: counting, no model.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::gate::{Effect, Finding};

const FILE: &str = "asked.jsonl";
const WINDOW_SECS: u64 = 30 * 86_400;
const ENOUGH: usize = 5;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entry {
    at: u64,
    approved: bool,
    asked: Vec<Asked>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Asked {
    code: String,
    area: String,
}

/// The top folder a set of files is in, as `docs/`; a file at the top is named as it is.
fn area(paths: &[String]) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for p in paths {
        let a = match p.split_once('/') {
            Some((top, _)) => format!("{top}/"),
            None => p.clone(),
        };
        *counts.entry(a).or_default() += 1;
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(a, _)| a).unwrap_or_default()
}

/// Record what asked for a person, as they decide. Rules about 05 itself are left out: those
/// are not for loosening.
pub fn record(state_dir: &Path, approved: bool, findings: &[Finding], now: u64) {
    let mut asked: Vec<Asked> = findings
        .iter()
        .filter(|f| f.effect == Effect::Approval)
        .map(|f| Asked { code: f.code.to_string(), area: area(&f.paths) })
        .filter(|a| a.area != ".05/")
        .collect();
    asked.sort();
    asked.dedup();
    if asked.is_empty() {
        return;
    }
    let line = serde_json::to_string(&Entry { at: now, approved, asked }).expect("serialises");
    let _ = std::fs::create_dir_all(state_dir);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(state_dir.join(FILE)) {
        let _ = writeln!(f, "{line}");
    }
}

/// A rule that asked often and was never refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    pub code: String,
    pub area: String,
    pub approvals: usize,
}

impl Hint {
    pub fn sentence(&self) -> String {
        let place = if self.area.is_empty() { String::new() } else { format!(" in {}", self.area) };
        format!("{} held {} changes{place} back for you in 30 days, and you approved every one. If it asks too often, loosen it: use05 policy --edit", self.code, self.approvals)
    }
}

pub fn hints(state_dir: &Path, now: u64) -> Vec<Hint> {
    let Ok(text) = std::fs::read_to_string(state_dir.join(FILE)) else { return Vec::new() };
    let mut tally: BTreeMap<Asked, (usize, usize)> = BTreeMap::new();
    for entry in text.lines().filter_map(|l| serde_json::from_str::<Entry>(l).ok()).filter(|e| e.at + WINDOW_SECS >= now) {
        for a in entry.asked {
            let t = tally.entry(a).or_default();
            if entry.approved {
                t.0 += 1;
            } else {
                t.1 += 1;
            }
        }
    }
    let mut out: Vec<Hint> = tally.into_iter().filter(|(_, (yes, no))| *yes >= ENOUGH && *no == 0).map(|(a, (yes, _))| Hint { code: a.code, area: a.area, approvals: yes }).collect();
    out.sort_by(|a, b| b.approvals.cmp(&a.approvals).then(a.code.cmp(&b.code)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(code: &'static str, paths: &[&str]) -> Finding {
        Finding { code, effect: Effect::Approval, message: String::new(), paths: paths.iter().map(|p| p.to_string()).collect(), next: None, approvable: true }
    }

    #[test]
    fn a_rule_always_approved_five_times_gets_a_hint_and_one_refusal_takes_it_away() {
        let dir = tempfile::tempdir().unwrap();
        let now = 10 * WINDOW_SECS;
        for i in 0..4 {
            record(dir.path(), true, &[finding("PROTECTED_PATH", &["docs/a.md", "docs/b.md"])], now - i);
        }
        assert!(hints(dir.path(), now).is_empty(), "four is not enough");
        record(dir.path(), true, &[finding("PROTECTED_PATH", &["docs/c.md"])], now);
        let got = hints(dir.path(), now);
        assert_eq!(got, vec![Hint { code: "PROTECTED_PATH".into(), area: "docs/".into(), approvals: 5 }]);
        assert!(got[0].sentence().contains("in docs/") && got[0].sentence().contains("use05 policy --edit"));
        record(dir.path(), false, &[finding("PROTECTED_PATH", &["docs/d.md"])], now);
        assert!(hints(dir.path(), now).is_empty(), "a refusal means the rule catches something");
    }

    #[test]
    fn old_entries_05s_own_rules_and_non_approval_findings_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let now = 10 * WINDOW_SECS;
        for _ in 0..6 {
            record(dir.path(), true, &[finding("PROTECTED_PATH", &[".05/policy.toml"])], now);
            record(dir.path(), true, &[finding("SCOPE_EXCEEDED", &["src/x.rs"])], now - WINDOW_SECS - 1);
            record(dir.path(), true, &[Finding { effect: Effect::Warn, ..finding("TESTS_WEAKENED", &["tests/a.rs"]) }], now);
        }
        assert!(hints(dir.path(), now).is_empty());
    }
}

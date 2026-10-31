//! What happened during an agent session, digested from its action log for the brief.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

/// One check's runs during the session, in the order the log recorded them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckRuns {
    pub name: String,
    pub runs: usize,
    pub failed: usize,
    pub last_passed: bool,
}

/// The session in numbers. Counts only: no paths beyond a total, no contents, no prompts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Session {
    pub first: Option<String>,
    pub last: Option<String>,
    pub minutes: u64,
    /// Times the agent stopped to hand back to the person.
    pub turns: usize,
    pub tool_calls: usize,
    pub edits: usize,
    pub files_touched: usize,
    /// Refusals by reason, most frequent first.
    pub refused: Vec<(String, usize)>,
    /// Tool calls handed to a person to decide.
    pub asked: usize,
    pub checks: Vec<CheckRuns>,
    /// Distinct subagents by type, most frequent first.
    pub subagents: Vec<(String, usize)>,
    pub approvals: usize,
    pub bypasses: usize,
}

/// Digest a task's log. Lines that do not parse, and events this version does not know, are
/// skipped: the digest describes what it can read and never fails.
pub fn digest(text: &str) -> Session {
    let mut d = Session::default();
    let (mut first, mut last): (Option<(u64, String)>, Option<(u64, String)>) = (None, None);
    let mut touched = BTreeSet::new();
    let mut refused: BTreeMap<String, usize> = BTreeMap::new();
    let mut checks: Vec<CheckRuns> = Vec::new();
    let mut agents: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let Ok(line) = serde_json::from_str::<Value>(line) else { continue };
        if let Some(t) = line["t"].as_str() {
            if let Some(secs) = crate::time::parse_rfc3339(t) {
                if first.as_ref().is_none_or(|(f, _)| secs < *f) {
                    first = Some((secs, t.to_string()));
                }
                if last.as_ref().is_none_or(|(l, _)| secs >= *l) {
                    last = Some((secs, t.to_string()));
                }
            }
        }
        let e = &line["event"];
        if let Some(id) = e["agent_id"].as_str().filter(|i| !i.is_empty()) {
            let kind = e["agent_type"].as_str().filter(|k| !k.is_empty()).unwrap_or("subagent");
            agents.entry(id.to_string()).or_insert_with(|| kind.to_string());
        }
        match e["event"].as_str() {
            Some("tool") => {
                d.tool_calls += 1;
                match e["decision"].as_str() {
                    Some("deny") => *refused.entry(e["why"].as_str().unwrap_or("unknown").to_string()).or_default() += 1,
                    Some("ask") => d.asked += 1,
                    _ => {}
                }
            }
            Some("tool_done") => {
                d.edits += 1;
                touched.extend(e["paths"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string));
            }
            Some("stop") => d.turns += 1,
            // `prove` is written for every run, including those the Stop hook starts; the
            // Stop hook's own `proved_at_stop` summary would count them twice.
            Some("prove") => {
                let Some(name) = e["check"].as_str() else { continue };
                let passed = e["status"] == "passed";
                let at = match checks.iter().position(|c| c.name == name) {
                    Some(i) => i,
                    None => {
                        checks.push(CheckRuns { name: name.to_string(), runs: 0, failed: 0, last_passed: false });
                        checks.len() - 1
                    }
                };
                let c = &mut checks[at];
                c.runs += 1;
                c.failed += usize::from(!passed);
                c.last_passed = passed;
            }
            Some("approval") => d.approvals += 1,
            Some("bypass") => d.bypasses += 1,
            _ => {}
        }
    }
    if let (Some((f, ft)), Some((l, lt))) = (first, last) {
        d.minutes = l.saturating_sub(f) / 60;
        d.first = Some(ft);
        d.last = Some(lt);
    }
    d.files_touched = touched.len();
    let mut refused: Vec<(String, usize)> = refused.into_iter().collect();
    refused.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    d.refused = refused;
    d.checks = checks;
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for kind in agents.into_values() {
        *kinds.entry(kind).or_default() += 1;
    }
    let mut subagents: Vec<(String, usize)> = kinds.into_iter().collect();
    subagents.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    d.subagents = subagents;
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn line(t: &str, event: Value) -> String {
        json!({ "seq": 0, "t": t, "prev": "", "event": event, "hash": "" }).to_string()
    }

    #[test]
    fn digest_counts_a_long_session() {
        let mut lines = vec![line("2026-10-31T09:00:00Z", json!({ "event": "session_start", "agent": "claude-code" }))];
        let tools = [
            json!({ "event": "tool", "tool": "Edit", "paths": ["src/a.rs"], "decision": "allow" }),
            json!({ "event": "tool", "tool": "Edit", "paths": ["docs/x.md"], "decision": "deny", "why": "outside scope" }),
            json!({ "event": "tool", "tool": "Edit", "paths": ["docs/y.md"], "decision": "deny", "why": "outside scope" }),
            json!({ "event": "tool", "tool": "Edit", "paths": [".05/policy.toml"], "decision": "deny", "why": "protected path" }),
            json!({ "event": "tool", "tool": "Edit", "paths": ["src/b.rs"], "decision": "ask", "why": "overlap" }),
            json!({ "event": "tool", "tool": "Edit", "paths": ["src/b.rs"], "decision": "allow", "agent_id": "s1", "agent_type": "Explore" }),
            json!({ "event": "tool", "tool": "Bash", "paths": [], "decision": "allow", "agent_id": "s2", "agent_type": "Explore" }),
            json!({ "event": "tool", "tool": "Edit", "paths": ["src/c.rs"], "decision": "allow", "agent_id": "s3", "agent_type": "security-reviewer" }),
            json!({ "event": "tool", "tool": "Write", "paths": ["src/d.rs"], "decision": "allow" }),
            json!({ "event": "tool", "tool": "Write", "paths": ["src/e.rs"], "decision": "allow" }),
        ];
        for t in tools {
            lines.push(line("2026-10-31T10:00:00Z", t));
        }
        for p in ["src/a.rs", "src/b.rs", "src/b.rs", "src/c.rs", "src/d.rs", "src/e.rs"] {
            lines.push(line("2026-10-31T10:30:00Z", json!({ "event": "tool_done", "tool": "Edit", "paths": [p] })));
        }
        for (i, status) in ["failed", "failed", "passed"].iter().enumerate() {
            lines.push(line("2026-10-31T11:00:00Z", json!({ "event": "prove", "check": "test", "status": status })));
            lines.push(line("2026-10-31T11:00:00Z", json!({ "event": "proved_at_stop", "proved": ["test"], "failed": if i < 2 { vec!["test"] } else { vec![] }, "left_for_push": [] })));
            lines.push(line("2026-10-31T11:00:00Z", json!({ "event": "stop" })));
        }
        lines.push(line("2026-10-31T12:00:00Z", json!({ "event": "approval", "vote": "approve" })));
        lines.push(line("2026-10-31T12:12:00Z", json!({ "event": "stop" })));
        let d = digest(&lines.join("\n"));
        assert_eq!(d.first.as_deref(), Some("2026-10-31T09:00:00Z"));
        assert_eq!(d.last.as_deref(), Some("2026-10-31T12:12:00Z"));
        assert_eq!(d.minutes, 192);
        assert_eq!(d.turns, 4);
        assert_eq!(d.tool_calls, 10);
        assert_eq!(d.edits, 6);
        assert_eq!(d.files_touched, 5);
        assert_eq!(d.refused, vec![("outside scope".to_string(), 2), ("protected path".to_string(), 1)]);
        assert_eq!(d.asked, 1);
        assert_eq!(d.checks, vec![CheckRuns { name: "test".into(), runs: 3, failed: 2, last_passed: true }]);
        assert_eq!(d.subagents, vec![("Explore".to_string(), 2), ("security-reviewer".to_string(), 1)]);
        assert_eq!((d.approvals, d.bypasses), (1, 0));
    }

    #[test]
    fn digest_skips_lines_it_cannot_read() {
        let text = [
            "not json at all".to_string(),
            line("2026-10-31T09:00:00Z", json!({ "event": "something_new", "x": 1 })),
            json!({ "seq": 1, "event": { "event": "tool", "decision": "deny", "why": "risky command" } }).to_string(),
            line("2026-10-31T09:05:00Z", json!({ "event": "tool", "decision": "deny" })),
            line("2026-10-31T09:05:00Z", json!({ "event": "tool_done", "paths": "not a list" })),
        ]
        .join("\n");
        let d = digest(&text);
        assert_eq!(d.tool_calls, 2);
        assert_eq!(d.refused, vec![("risky command".to_string(), 1), ("unknown".to_string(), 1)]);
        assert_eq!(d.edits, 1);
        assert_eq!(d.files_touched, 0);
        assert_eq!(d.minutes, 5);
        assert_eq!(digest(""), Session::default());
    }
}

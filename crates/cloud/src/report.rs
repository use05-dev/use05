//! What leaves this machine, and only this: every field below is picked by name from what 05
//! reports, so a field a future 05 adds is never sent by accident. Never: the person's request,
//! the agent's outcome text (it can hold the agent's last message), file contents, diffs, command
//! output.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use serde_json::{Map, Value, json};

use crate::repo::Repo;
use crate::{Api, Config};

pub fn use05_version(c: &Config) -> Option<String> {
    let out = std::process::Command::new(&c.use05).arg("--version").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("use05 ").to_string()).filter(|v| !v.is_empty())
}

fn pick(v: &Value, keys: &[&str]) -> Value {
    let mut out = Map::new();
    for k in keys {
        if let Some(x) = v.get(*k) {
            if !x.is_null() {
                out.insert((*k).to_string(), x.clone());
            }
        }
    }
    Value::Object(out)
}

fn each(v: &Value, keys: &[&str], limit: usize) -> Value {
    Value::Array(v.as_array().into_iter().flatten().take(limit).map(|x| pick(x, keys)).collect())
}

fn strings(v: &Value, limit: usize) -> Value {
    Value::Array(v.as_array().into_iter().flatten().filter(|x| x.is_string()).take(limit).cloned().collect())
}

/// Whether a person's approval would clear anything CI holds. A missing testing sign-off is not
/// something an approval stands in for, so CI does not ask for one then.
pub fn approval_could_clear(gate: &Value) -> bool {
    gate["decision"] == "approval_required" && gate["brief"]["gate"]["findings"].as_array().is_some_and(|f| f.iter().any(|f| f["effect"] == "approval" && f["approvable"] == true))
}

/// The brief, reduced to metadata.
pub fn summary(brief: &Value) -> Value {
    let b = &brief["brief"];
    let gate = &b["gate"];
    let card = &b["card"];
    json!({
        "title": b["title"], "goal": b["goal"], "author": b["author"], "risk": b["risk"], "label": b["label"],
        "lands_on": b["lands_on"], "tree": b["tree"], "tree_label": b["tree_label"], "added": b["added"], "removed": b["removed"],
        "agent": pick(&b["agent"], &["kind", "model"]),
        "owner": pick(&b["owner"], &["name"]),
        "owner_confirmed": b["owner_confirmed"],
        "scope": { "include": strings(&card["scope"]["include"], 100), "exclude": strings(&card["scope"]["exclude"], 100) },
        "out_of_scope": strings(&card["out_of_scope"], 100),
        "acceptance": strings(&card["acceptance"], 50),
        "areas": each(&b["area_summary"], &["name", "files", "added", "removed"], 12),
        "outside_scope": strings(&b["outside_scope"], 200),
        "outside_scope_areas": each(&b["outside_scope_areas"], &["name", "files", "added", "removed"], 12),
        "session": pick(&b["session"], &["minutes", "turns", "tool_calls", "edits", "files_touched", "first", "last", "approvals", "bypasses", "refused", "subagents"]),
        // How much the decision rests on (D101): counts and 05's own words, no paths. Empty from a
        // 05 that does not print it.
        "assurance": pick(&b["assurance"], &["checks_required", "passed", "failed", "missing", "stale", "not_accepted", "not_required", "evidence", "local_only", "tests_changed", "behaviour", "enforcement", "summary", "test_origin"]),
        // The story (D102), without the person's words or the agent's: what 05 saw, what the checks
        // found, what holds it and what is not known, and only how many claims stand where.
        "story": pick(&b["story"], &["observed", "checked", "needs_you", "not_known", "claim_counts"]),
        "gate": {
            "decision": gate["decision"], "risk": gate["risk"], "policy_sha256": gate["policy_sha256"],
            "findings": each(&gate["findings"], &["code", "effect", "message", "paths", "next", "approvable"], 60),
            "checks": each(&gate["checks"], &["name", "required", "state", "status", "passed", "stale", "duration_ms"], 40),
            "approvals": each(&gate["approvals"], &["approver", "scope", "decision", "void", "expires"], 20),
            // A person's testing sign-off, with the note they wrote (D87); sealed like the rest.
            "testing": each(&gate["testing"], &["outcome", "note", "by", "created", "counts", "void"], 10),
            "changed": each(&gate["changed"], &["path", "status", "added", "removed"], 400),
            "risk_reasons": each(&gate["risk_reasons"], &["category", "level", "paths"], 20),
            "log": pick(&gate["log"], &["lines", "hook_seals", "ci_sealed_at", "travels", "altered_at", "tail_broken_at"]),
        },
    })
}

/// Identifiers and verdicts only, as 05 sends them; findings are codes.
fn event_data(ev: &Value) -> Value {
    let mut data = pick(ev, &["where", "tree", "decision", "scope", "intent_sha256", "branch", "target", "head", "agent", "outcome", "note", "by"]);
    if ev.get("findings").is_some() {
        data["findings"] = strings(&ev["findings"], 60);
    }
    data
}

fn brief(api: &Api, r: &Repo, task: &str) -> Option<Value> {
    let out = std::process::Command::new(&api.c.use05).args(["brief", "--task", task, "--json"]).current_dir(&r.top).output().ok()?;
    serde_json::from_slice(&out.stdout).ok()
}

static SEEN: Mutex<Option<HashMap<String, std::time::SystemTime>>> = Mutex::new(None);
/// Whether each task's work had landed when it was last reported: a push changes that without
/// touching the task's own file, and the console should hear of it.
static LANDED: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);

/// Report a repository and its recent tasks. With `full`, every task's brief again.
pub fn send_repo(api: &Api, r: &Repo, full: bool) -> Result<()> {
    let answer = api.record("repo", &r.id, "", r.describe())?;
    if let Some(why) = answer["waiting"].as_str() {
        anyhow::bail!("{why}");
    }
    let store = use05_core::task::Store::open(Path::new(&r.top)).map_err(|e| anyhow::anyhow!(e.message))?;
    let tasks_dir = store.state_dir().join("tasks");
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(14 * 86_400);
    let mut out = Vec::new();
    for t in store.list() {
        let modified = fs::metadata(tasks_dir.join(format!("{}.json", t.id))).and_then(|m| m.modified()).ok();
        let active = t.status == use05_core::task::Status::Active;
        if !active && modified.is_none_or(|m| m < cutoff) {
            continue;
        }
        let key = format!("{}:{}", r.id, t.id);
        let landed = t.status != use05_core::task::Status::Discarded && r.landed(&t);
        let changed = {
            let mut seen = SEEN.lock().unwrap();
            let map = seen.get_or_insert_with(HashMap::new);
            let mut moved = LANDED.lock().unwrap();
            let landed_map = moved.get_or_insert_with(HashMap::new);
            let changed = full || modified.is_some_and(|m| map.get(&key) != Some(&m)) || landed_map.get(&key) != Some(&landed);
            landed_map.insert(key.clone(), landed);
            if let Some(m) = modified {
                map.insert(key, m);
            }
            changed
        };
        if !changed {
            continue;
        }
        // Thrown away (D89): the console keeps only that, and the person's browser clears the rest.
        if t.status == use05_core::task::Status::Discarded {
            out.push(json!({ "id": t.id, "status": "discarded" }));
            continue;
        }
        let detail = brief(api, r, &t.id).map(|b| summary(&b)).unwrap_or_else(|| json!({}));
        let status = serde_json::to_value(t.status).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "active".into());
        out.push(json!({
            "id": t.id, "title": t.title, "status": status,
            "decision": detail["gate"]["decision"], "risk": detail["risk"],
            "agent": t.agent.as_ref().map(|a| a.kind.clone()).or_else(|| t.author.strip_prefix("agent:").map(str::to_string)),
            "model": t.agent.as_ref().and_then(|a| a.model.clone()),
            "created": t.created, "finished": t.finished, "ended": t.ended,
            // When the work last changed on this machine. The console shows this, not when it was
            // last sent: a resync sends every task again.
            "updated": modified.and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| use05_core::time::rfc3339(d.as_secs())),
            "landed": landed,
            "detail": detail,
        }));
    }
    let key = crate::stored_id_key()?;
    for t in out {
        let reference = cloud::seal::hmac_ref(&key, "task", t["id"].as_str().unwrap_or_default());
        api.record("task", &r.id, &reference, t)?;
    }
    Ok(())
}

pub fn sync_all(api: &Api, full: bool) -> Result<()> {
    for path in &api.c.repos {
        match Repo::open(path) {
            // One repository the console will not take yet does not stop the others.
            Ok(r) => match send_repo(api, &r, full) {
                Ok(()) if full => {
                    let _ = r.send_tree(api);
                }
                Ok(()) => {}
                Err(e) => eprintln!("{}: {e:#}", r.name),
            },
            Err(e) => eprintln!("{path}: {e:#}"),
        }
    }
    Ok(())
}

/// Forward what the event listener kept, then forget it.
pub fn drain(api: &Api, dir: &Path) -> Result<()> {
    let mut files: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json") && !p.file_name().unwrap().to_string_lossy().starts_with('.')).collect();
    files.sort();
    for file in files {
        let text = fs::read_to_string(&file).unwrap_or_default();
        let _ = fs::remove_file(&file);
        let Ok(ev) = serde_json::from_str::<Value>(&text) else { continue };
        let Some(r) = ev["repo"].as_str().and_then(|top| api.c.repos.iter().find_map(|known| Repo::open(known).ok().filter(|r| r.contains(top)))) else { continue };
        let kind = ev["event"].as_str().unwrap_or("event");
        let task = ev["task"].as_str();
        let data = event_data(&ev);
        let reference = hex::encode(rand::random::<[u8; 16]>());
        api.record("event", &r.id, &reference, json!({ "kind": kind, "task": task, "data": data }))?;
        if kind == "approval_needed" {
            if let (Some(task), Some(cwd)) = (task, ev["repo"].as_str()) {
                if let Err(e) = r.ask_for_approval(api, task, ev["scope"].as_str().unwrap_or("outcome"), ev["tree"].as_str(), cwd, None) {
                    eprintln!("approval for {task}: {e:#}");
                }
            }
        }
        let _ = send_repo(api, &r, false);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_asks_a_person_only_when_an_approval_can_clear_something() {
        let gate = |findings: Value| json!({ "decision": "approval_required", "brief": { "gate": { "findings": findings } } });
        assert!(approval_could_clear(&gate(json!([{ "code": "SCOPE_EXCEEDED", "effect": "approval", "approvable": true }]))));
        // Only a testing sign-off is missing: an approval cannot stand in for it.
        assert!(!approval_could_clear(&gate(json!([{ "code": "TESTING_REQUIRED", "effect": "approval", "approvable": false }]))));
        assert!(!approval_could_clear(&gate(json!([{ "code": "X", "effect": "info", "approvable": true }]))));
        assert!(!approval_could_clear(&json!({ "decision": "allow" })));
    }

    #[test]
    fn the_request_and_the_outcome_never_leave() {
        let brief = json!({ "brief": {
            "title": "Cap retries", "request": "my secret prompt", "outcome": "fn main() { secret }",
            "undo": ["git revert"], "gate": { "decision": "allow", "findings": [{ "code": "X", "message": "m", "secret_field": "s" }] },
            "card": { "scope": { "include": ["src/**"] } }
        }});
        let text = summary(&brief).to_string();
        assert!(text.contains("Cap retries") && text.contains("src/**"));
        for never in ["my secret prompt", "fn main", "secret_field", "git revert"] {
            assert!(!text.contains(never), "{never} leaked: {text}");
        }
    }

    #[test]
    fn the_story_travels_without_the_persons_words_or_the_agents() {
        let brief = json!({ "brief": { "story": {
            "asked": "my secret prompt", "agent_says": "I capped the retries", "claims": [{ "text": "all tests pass", "status": "contradicted" }],
            "claim_counts": { "supported": 0, "unsupported": 0, "contradicted": 1 },
            "observed": ["2 files changed in src/billing/ · +40 −10"], "checked": "1 failed", "needs_you": ["the test failed"], "not_known": ["behaviour beyond these checks"],
        }}});
        let s = &summary(&brief)["story"];
        assert_eq!(s["observed"][0], "2 files changed in src/billing/ · +40 −10");
        assert_eq!((s["checked"].as_str(), s["claim_counts"]["contradicted"].as_u64()), (Some("1 failed"), Some(1)));
        let text = s.to_string();
        for never in ["my secret prompt", "I capped", "all tests pass"] {
            assert!(!text.contains(never), "{never} left the machine: {text}");
        }
    }

    #[test]
    fn the_assurance_travels_as_counts_and_its_one_line() {
        let brief = json!({ "brief": { "assurance": { "checks_required": 0, "passed": 0, "evidence": "none", "behaviour": "not_assessed", "enforcement": "unknown", "summary": "none required; behaviour not verified", "limitations": ["x"], "later_field": "secret" } } });
        let a = &summary(&brief)["assurance"];
        assert_eq!(a["summary"], "none required; behaviour not verified");
        assert_eq!((a["checks_required"].as_u64(), a["evidence"].as_str()), (Some(0), Some("none")), "{a}");
        assert!(a.get("later_field").is_none() && a.get("limitations").is_none(), "picked by name: {a}");
        // A brief from a 05 without it sends an empty object, and the console shows nothing.
        assert_eq!(summary(&json!({ "brief": {} }))["assurance"], json!({}));
    }

    #[test]
    fn risk_reasons_and_event_findings_are_picked_by_name_too() {
        let brief = json!({ "brief": { "gate": { "risk_reasons": [{ "category": "money", "level": "high", "paths": ["src/billing/a.ts"], "excerpt": "secret line" }] } } });
        let text = summary(&brief).to_string();
        assert!(text.contains("money") && text.contains("src/billing/a.ts"), "{text}");
        assert!(!text.contains("secret line"), "{text}");
        let event = json!({ "event": "gate", "decision": "allow", "findings": ["PROTECTED_PATH", { "message": "secret" }] });
        let data = event_data(&event).to_string();
        assert!(data.contains("PROTECTED_PATH") && !data.contains("secret"), "{data}");
    }
}

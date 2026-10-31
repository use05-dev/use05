//! The public receipt format (oss/receipts.md) must describe the code as it is: every record
//! type, every subject, and every field name a receipt can carry. A change to one without the
//! other fails here.

use serde_json::Value;
use use05_receipt::*;

fn spec() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/receipts.md")).expect("docs/receipts.md exists")
}

fn keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, inner) in map {
                out.push(k.clone());
                keys(inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| keys(i, out)),
        _ => {}
    }
}

fn stream() -> Stream {
    Stream { total_bytes: 1, retained_bytes: 1, truncated: false, sha256: "00".repeat(32) }
}

#[test]
fn the_public_spec_names_every_record_type_subject_and_field() {
    let spec = spec();
    for t in [PREDICATE_TYPE, APPROVAL_TYPE, BYPASS_TYPE, ORG_TYPE, INTENT_TYPE, OUTCOME_TYPE, LOG_TYPE] {
        assert!(spec.contains(t), "oss/receipts.md does not name the record type {t}");
    }
    let samples: Vec<Value> = vec![
        serde_json::to_value(Statement::for_evidence(&"a1".repeat(20), &"b2".repeat(32), Evidence {
            command: Command { argv: vec!["x".into()], cwd: ".".into() },
            environment: Environment { fingerprint: "f".into(), names: vec![] },
            result: Outcome { status: Status::Passed, exit_code: Some(0), signal: Some(0), duration_ms: 1, stdout: stream(), stderr: stream() },
            runner: Runner { name: "use05".into(), version: "0".into(), platform: "p".into() },
            created: "c".into(),
            check: Some("test".into()),
        }))
        .unwrap(),
        serde_json::to_value(Statement::new(vec![intent_subject("ab")], Approval { decision: Decision::Approve, scope: ApprovalScope::Intent, task: "t".into(), intent_sha256: Some("ab".into()), policy_sha256: "p".into(), rationale: "r".into(), approver: "a".into(), created: "c".into(), expires: "e".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Bypass { reason: "r".into(), by: "b".into(), findings: vec![], created: "c".into(), expires: "e".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![intent_subject("ab")], Declaration {
            task: "t".into(), title: "t".into(), author: "a".into(), card: serde_json::json!({}), sealed: "s".into(), policy_sha256: "p".into(),
            agent: Some(AgentRef { kind: "codex".into(), session: "s".into(), model: Some("m".into()) }),
            owner: Some(OwnerRef { name: "n".into(), key_id: "k".into() }),
            sandbox: Some("codex:seatbelt".into()),
        })).unwrap(),
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Completion { task: "t".into(), outcome: "o".into(), finished: "f".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![log_subject("t", "h")], LogSeal { task: "t".into(), seq: 1, head: "h".into(), created: "c".into() })).unwrap(),
    ];
    let mut names = Vec::new();
    for s in &samples {
        keys(s, &mut names);
    }
    names.sort();
    names.dedup();
    for name in names {
        assert!(spec.contains(&format!("`{name}`")), "oss/receipts.md does not mention the field `{name}`");
    }
    for subject in ["`tree`", "`intent`", "`log`", "`gitTree`"] {
        assert!(spec.contains(subject), "oss/receipts.md does not describe the subject {subject}");
    }
}

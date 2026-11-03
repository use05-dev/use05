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
    for t in [PREDICATE_TYPE, APPROVAL_TYPE, BYPASS_TYPE, ORG_TYPE, INTENT_TYPE, OUTCOME_TYPE, LOG_TYPE, TESTING_TYPE] {
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
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Testing { outcome: Tested::Tested, task: "t".into(), note: "n".into(), tester: "a".into(), created: "c".into() })).unwrap(),
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

#[test]
fn the_public_spec_describes_passkey_signatures() {
    let spec = spec();
    let envelope = Envelope {
        payload: "p".into(),
        payload_type: PAYLOAD_TYPE.into(),
        signatures: vec![EnvelopeSignature { keyid: Some("k".into()), sig: "s".into(), webauthn: Some(WebAuthnSig { authenticator_data: "a".into(), client_data_json: "c".into() }) }],
    };
    let mut names = Vec::new();
    keys(&serde_json::to_value(&envelope).unwrap(), &mut names);
    for name in names {
        assert!(spec.contains(&format!("`{name}`")), "receipts.md does not mention the envelope field `{name}`");
    }
    for words in ["use05-passkey-p256-public:", "webauthn.get", "crossOrigin", "approvals"] {
        assert!(spec.contains(words), "receipts.md does not describe passkeys: missing {words}");
    }
}

#[test]
fn a_testing_sign_off_reads_back_as_its_own_kind_and_needs_a_tree() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let statement = Statement::new(vec![tree_subject(&"a1".repeat(20), &"b2".repeat(32))], Testing { outcome: Tested::Skipped, task: "t".into(), note: "no device to try it on".into(), tester: "Alex".into(), created: "c".into() });
    let envelope = seal(&statement, &key).to_json_bytes();
    match verify_any(&envelope, &key.verifying_key()).unwrap().statement {
        AnyStatement::Testing(s) => assert_eq!((s.predicate.outcome, s.predicate.note.as_str()), (Tested::Skipped, "no device to try it on")),
        other => panic!("read back as {other:?}"),
    }
    let no_tree = Statement::new(vec![intent_subject("ab")], Testing { outcome: Tested::Tested, task: "t".into(), note: "n".into(), tester: "a".into(), created: "c".into() });
    assert!(verify_any(&seal(&no_tree, &key).to_json_bytes(), &key.verifying_key()).is_err());
}

#[test]
fn a_discard_reads_back_as_its_own_kind_and_names_the_work() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let d = Discard { task: "t1".into(), branch: Some("claude/fix".into()), head: Some("c3".repeat(20)), unpushed: 2, uncommitted: 1, by: "Alex".into(), created: "c".into() };
    let statement = Statement::new(vec![work_subject("t1", d.head.as_deref())], d);
    let envelope = seal(&statement, &key).to_json_bytes();
    match verify_any(&envelope, &key.verifying_key()).unwrap().statement {
        AnyStatement::Discard(s) => {
            assert_eq!((s.predicate.task.as_str(), s.predicate.unpushed, s.predicate.uncommitted), ("t1", 2, 1));
            assert_eq!(s.work_subject(), Some(("t1", "c3".repeat(20).as_str())));
        }
        other => panic!("read back as {other:?}"),
    }
    let no_work = Statement::new(vec![tree_subject("a1", "b2")], Discard { task: "t1".into(), branch: None, head: None, unpushed: 0, uncommitted: 0, by: "a".into(), created: "c".into() });
    assert!(verify_any(&seal(&no_work, &key).to_json_bytes(), &key.verifying_key()).is_err(), "a discard names the task's work, not a tree");
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/receipts.md")).unwrap();
    assert!(spec.contains("https://use05.dev/discard/v0"), "receipts.md describes discards");
}

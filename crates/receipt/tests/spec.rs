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
    for t in [PREDICATE_TYPE, APPROVAL_TYPE, BYPASS_TYPE, ORG_TYPE, INTENT_TYPE, OUTCOME_TYPE, LOG_TYPE, TESTING_TYPE, PROMOTION_TYPE, DEPLOYMENT_TYPE, SIGNOFF_TYPE] {
        assert!(spec.contains(t), "oss/receipts.md does not name the record type {t}");
    }
    let samples: Vec<Value> = vec![
        serde_json::to_value(Statement::for_evidence(&"a1".repeat(20), &"b2".repeat(32), Evidence {
            command: Command { argv: vec!["x".into()], cwd: ".".into(), dir: None },
            environment: Environment { fingerprint: "f".into(), names: vec![] },
            result: Outcome { status: Status::Passed, exit_code: Some(0), signal: Some(0), duration_ms: 1, stdout: stream(), stderr: stream() },
            runner: Runner { name: "use05".into(), version: "0".into(), platform: "p".into(), check_user: None },
            created: "c".into(),
            check: Some("test".into()),
            lfs: vec![LfsFile { path: "assets/big.bin".into(), oid: "c3".repeat(32), size: 1 }],
        }))
        .unwrap(),
        serde_json::to_value(Statement::new(vec![intent_subject("ab")], Approval { decision: Decision::Approve, scope: ApprovalScope::Intent, task: "t".into(), intent_sha256: Some("ab".into()), policy_sha256: "p".into(), rationale: "r".into(), approver: "a".into(), created: "c".into(), expires: "e".into(), hotfix: None })).unwrap(),
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Bypass { env: None, from: None, rule: None, policy_sha256: None, reason: "r".into(), by: "b".into(), findings: vec![], created: "c".into(), expires: "e".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![intent_subject("ab")], Declaration {
            task: "t".into(), title: "t".into(), author: "a".into(), card: serde_json::json!({}), sealed: "s".into(), policy_sha256: "p".into(),
            agent: Some(AgentRef { kind: "codex".into(), session: "s".into(), model: Some("m".into()) }),
            owner: Some(OwnerRef { name: "n".into(), key_id: "k".into() }),
            sandbox: Some("codex:seatbelt".into()),
        })).unwrap(),
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Completion { task: "t".into(), outcome: "o".into(), finished: "f".into(), base: Some("c0ffee".into()) })).unwrap(),
        serde_json::to_value(Statement::new(vec![log_subject("t", "h")], LogSeal { task: "t".into(), seq: 1, head: "h".into(), created: "c".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![tree_subject("a", "b")], Testing { outcome: Tested::Tested, task: "t".into(), note: "n".into(), tester: "a".into(), created: "c".into() })).unwrap(),
        serde_json::to_value(Statement::new(vec![commit_subject("c1")], Promotion {
            env: "prod".into(), from: "uat".into(), direction: Direction::Up, source_commit: "c1".into(), target_before: Some("d2".into()), result_commit: "e3".into(),
            how: "merge".into(), rollback_point: Some("d2".into()), rules: vec![RuleResult { rule: "soak".into(), severity: RuleSeverity::Warn, outcome: RuleOutcome::Skipped, detail: "d".into() }],
            bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: "c".into(), by: "b".into(), reverts: Some("d2".into()), task: None,
        })).unwrap(),
        serde_json::to_value(Statement::new(vec![commit_subject("c1")], Deployment {
            env: "uat".into(), commit: "c1".into(), probes: vec![ProbeResult { name: "v".into(), matched: true, output_sha256: "s".into(), attempts: 1, seconds: 1 }],
            smoke: vec![SmokeResult { name: "h".into(), passed: true }], confirmed: true, created: "c".into(), action: DeployAction::None,
        })).unwrap(),
        serde_json::to_value(Statement::new(vec![commit_subject("c1")], SignOff {
            env: "prod".into(), from: "uat".into(), source_commit: "c1".into(), decision: Decision::Approve, signer_person: "Dana".into(), text: "t".into(),
            answers: vec![], confirmations: vec![], policy_sha256: "p".into(), created: "c".into(), expires: "e".into(),
        })).unwrap(),
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
    for subject in ["`tree`", "`intent`", "`log`", "`gitTree`", "`commit`", "`gitCommit`"] {
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

#[test]
fn a_value_a_newer_05_adds_to_a_list_of_words_reads_as_unknown() {
    // D95: a v0 type may gain values; an older reader keeps the record and treats the value as unknown.
    let rule: RuleResult = serde_json::from_str(r#"{"rule":"probe_latency","severity":"block","outcome":"deferred","detail":"d"}"#).unwrap();
    assert_eq!((rule.severity, rule.outcome), (RuleSeverity::Unknown, RuleOutcome::Unknown));
    assert_eq!(serde_json::from_str::<Direction>(r#""sideways""#).unwrap(), Direction::Unknown);
    assert_eq!(serde_json::from_str::<DeployAction>(r#""paged-someone""#).unwrap(), DeployAction::Unknown);
    assert_eq!(serde_json::from_str::<DeployAction>(r#""rollback-command""#).unwrap(), DeployAction::RollbackCommand, "known values read as before");
    assert!(spec().contains("treat a value they do not know as unknown"), "receipts.md states the rule");
}

#[test]
fn an_environments_records_read_back_as_their_own_kinds_and_name_a_commit() {
    let key = SigningKey::from_bytes(&[6; 32]);
    let sha = "c1".repeat(20);
    let signoff = SignOff {
        env: "prod".into(), from: "uat".into(), source_commit: sha.clone(), decision: Decision::Approve, signer_person: "Dana".into(), text: "tried it in uat".into(),
        answers: vec![], confirmations: vec![], policy_sha256: "p".into(), created: "c".into(), expires: "e".into(),
    };
    let envelope = seal(&Statement::new(vec![commit_subject(&sha)], signoff.clone()), &key).to_json_bytes();
    match verify_any(&envelope, &key.verifying_key()).unwrap().statement {
        AnyStatement::SignOff(s) => {
            assert_eq!(s.predicate, signoff);
            assert_eq!(s.commit_subject(), Some(sha.as_str()));
        }
        other => panic!("read back as {other:?}"),
    }
    let deployment = Deployment { env: "uat".into(), commit: sha.clone(), probes: vec![], smoke: vec![], confirmed: false, created: "c".into(), action: DeployAction::None };
    let envelope = seal(&Statement::new(vec![commit_subject(&sha)], deployment), &key).to_json_bytes();
    assert!(matches!(verify_any(&envelope, &key.verifying_key()).unwrap().statement, AnyStatement::Deployment(_)));
    let promotion = Promotion {
        env: "prod".into(), from: "uat".into(), direction: Direction::Up, source_commit: sha.clone(), target_before: None, result_commit: sha.clone(), how: "fast-forward".into(),
        rollback_point: None, rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: "c".into(), by: "ci".into(), reverts: None, task: None,
    };
    let envelope = seal(&Statement::new(vec![commit_subject(&sha)], promotion.clone()), &key).to_json_bytes();
    assert!(matches!(verify_any(&envelope, &key.verifying_key()).unwrap().statement, AnyStatement::Promotion(_)));
    let on_a_tree = Statement::new(vec![tree_subject("a1", "b2")], promotion);
    assert!(verify_any(&seal(&on_a_tree, &key).to_json_bytes(), &key.verifying_key()).is_err(), "a promotion names a commit, not a tree");
}

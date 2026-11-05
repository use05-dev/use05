//! Each record type has a JSON Schema in docs/receipts, and the schemas describe the code as it
//! is (D95): a statement the code writes validates against its type's schema, every field it
//! writes is in the schema, and no type is without a schema and no schema without a type.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Value, json};
use use05_receipt::*;

fn folder() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/receipts"))
}

/// `https://use05.dev/org-layer/v0` is described by `org-layer-v0.schema.json`, and a breaking
/// `https://use05.dev/org-layer/v1` (D95) by `org-layer-v1.schema.json`.
fn file_for(type_uri: &str) -> String {
    let rest = type_uri.strip_prefix("https://use05.dev/").unwrap_or_else(|| panic!("{type_uri} is not a type of use05.dev"));
    let (name, version) = rest.rsplit_once('/').unwrap_or_else(|| panic!("{type_uri} has no version"));
    assert!(version.strip_prefix('v').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())), "{type_uri}: the version should look like v0, v1, ...");
    format!("{name}-{version}.schema.json")
}

/// `org-layer-v0.schema.json`, `evidence-v1.schema.json`: a schema file of some version.
fn is_schema_file(name: &str) -> bool {
    name.strip_suffix(".schema.json").and_then(|n| n.rsplit_once("-v")).is_some_and(|(_, v)| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}

fn stream() -> Stream {
    Stream { total_bytes: 1, retained_bytes: 1, truncated: false, sha256: "00".repeat(32) }
}

/// One statement of each type as the code builds it, every optional field filled in.
fn samples() -> Vec<(&'static str, Value)> {
    let tree = || tree_subject(&"a1".repeat(20), &"b2".repeat(32));
    let to_value = |v: Result<Value, serde_json::Error>| v.unwrap();
    vec![
        (PREDICATE_TYPE, to_value(serde_json::to_value(Statement::for_evidence(&"a1".repeat(20), &"b2".repeat(32), Evidence {
            command: Command { argv: vec!["cargo".into(), "test".into()], cwd: ".".into(), dir: Some("packages/api".into()) },
            environment: Environment { fingerprint: "f".into(), names: vec!["PATH".into()] },
            result: Outcome { status: Status::TimedOut, exit_code: None, signal: Some(9), duration_ms: 1, stdout: stream(), stderr: stream() },
            runner: Runner { name: "use05".into(), version: "0".into(), platform: "p".into(), check_user: Some("use05-check".into()) },
            created: "2026-11-04T00:00:00Z".into(),
            check: Some("test".into()),
            lfs: vec![LfsFile { path: "assets/big.bin".into(), oid: "c3".repeat(32), size: 12345 }],
        })))),
        (APPROVAL_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], Approval {
            decision: Decision::Approve, scope: ApprovalScope::Intent, task: "t".into(), intent_sha256: Some("ab".into()), policy_sha256: "p".into(),
            rationale: "r".into(), approver: "Alex Rivera".into(), created: "c".into(), expires: "e".into(), hotfix: Some("prod".into()),
        })))),
        // A promotion's bypass: every optional field written, and a commit subject.
        (BYPASS_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], Bypass {
            env: Some("prod".into()), from: Some("uat".into()), rule: Some("soak".into()), policy_sha256: Some("p".into()), reason: "r".into(), by: "Dana".into(), findings: vec!["SOAK_NOT_DONE".into()], created: "c".into(), expires: "e".into(),
        })))),
        (ORG_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], OrgLayer { org: "acme".into(), floor: json!({"evidence": {"accept": ["runner"]}}), created: "c".into() })))),
        (INTENT_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], Declaration {
            task: "t".into(), title: "t".into(), author: "a".into(), card: json!({"goal": "g"}), sealed: "s".into(), policy_sha256: "p".into(),
            agent: Some(AgentRef { kind: "codex".into(), session: "s".into(), model: Some("m".into()) }),
            owner: Some(OwnerRef { name: "Sam".into(), key_id: "k".into() }),
            sandbox: Some("codex:seatbelt".into()),
        })))),
        (OUTCOME_TYPE, to_value(serde_json::to_value(Statement::new(vec![tree()], Completion { task: "t".into(), outcome: "o".into(), finished: "f".into(), base: Some("c0ffee".into()) })))),
        (LOG_TYPE, to_value(serde_json::to_value(Statement::new(vec![log_subject("t", "h")], LogSeal { task: "t".into(), seq: 1, head: "h".into(), created: "c".into() })))),
        (TESTING_TYPE, to_value(serde_json::to_value(Statement::new(vec![tree()], Testing { outcome: Tested::Skipped, task: "t".into(), note: "n".into(), tester: "Lee".into(), created: "c".into() })))),
        (DISCARD_TYPE, to_value(serde_json::to_value(Statement::new(vec![work_subject("t", Some("c0ffee"))], Discard {
            task: "t".into(), branch: None, head: Some("c0ffee".into()), unpushed: 2, uncommitted: 0, by: "Bob".into(), created: "c".into(),
        })))),
        (PROMOTION_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], Promotion {
            env: "prod".into(), from: "uat".into(), direction: Direction::Up, source_commit: "c1".repeat(20), target_before: Some("d2".repeat(20)),
            result_commit: "e3".repeat(20), how: "merge".into(), rollback_point: Some("d2".repeat(20)),
            rules: vec![RuleResult { rule: "source_checks".into(), severity: RuleSeverity::Deny, outcome: RuleOutcome::Pass, detail: "test passed".into() }],
            bypasses: vec!["receipts/c1/ab.json".into()], signoffs: vec!["receipts/c1/cd.json".into()], policy_sha256: "p".into(), created: "c".into(), by: "Dana".into(), reverts: Some("f4".repeat(20)), task: Some("1a2b3c4d".into()),
        })))),
        (DEPLOYMENT_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], Deployment {
            env: "uat".into(), commit: "c1".repeat(20),
            probes: vec![ProbeResult { name: "version".into(), matched: true, output_sha256: "00".repeat(32), attempts: 2, seconds: 30 }],
            smoke: vec![SmokeResult { name: "health".into(), passed: true }], confirmed: true, created: "c".into(), action: DeployAction::RollbackCommand,
        })))),
        (SIGNOFF_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], SignOff {
            env: "prod".into(), from: "uat".into(), source_commit: "c1".repeat(20), decision: Decision::Approve, signer_person: "Dana".into(),
            text: "Checked the payment flow in uat".into(), answers: vec!["the checkout".into()], confirmations: vec!["The release notes are published".into()],
            policy_sha256: "p".into(), created: "c".into(), expires: "e".into(),
        })))),
    ]
}

/// The same statements with every optional field left out or empty: what a writer that has
/// nothing to say for them writes. A schema that wrongly requires one fails on these.
fn minimal_samples() -> Vec<(&'static str, Value)> {
    let tree = || tree_subject(&"a1".repeat(20), &"b2".repeat(32));
    let to_value = |v: Result<Value, serde_json::Error>| v.unwrap();
    vec![
        (PREDICATE_TYPE, to_value(serde_json::to_value(Statement::for_evidence(&"a1".repeat(20), &"b2".repeat(32), Evidence {
            command: Command { argv: vec![], cwd: ".".into(), dir: None },
            environment: Environment { fingerprint: "f".into(), names: vec![] },
            result: Outcome { status: Status::Passed, exit_code: None, signal: None, duration_ms: 0, stdout: stream(), stderr: stream() },
            runner: Runner { name: "use05".into(), version: "0".into(), platform: "p".into(), check_user: None },
            created: "2026-11-04T00:00:00Z".into(),
            check: None,
            lfs: vec![],
        })))),
        (APPROVAL_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], Approval {
            decision: Decision::Reject, scope: ApprovalScope::Intent, task: "t".into(), intent_sha256: None, policy_sha256: "p".into(),
            rationale: String::new(), approver: "Alex Rivera".into(), created: "c".into(), expires: "e".into(), hotfix: None,
        })))),
        (BYPASS_TYPE, to_value(serde_json::to_value(Statement::new(vec![tree()], Bypass { env: None, from: None, rule: None, policy_sha256: None, reason: "r".into(), by: "Dana".into(), findings: vec![], created: "c".into(), expires: "e".into() })))),
        (ORG_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], OrgLayer { org: "acme".into(), floor: json!({}), created: "c".into() })))),
        (INTENT_TYPE, to_value(serde_json::to_value(Statement::new(vec![intent_subject("ab")], Declaration {
            task: "t".into(), title: "t".into(), author: "a".into(), card: json!({}), sealed: "s".into(), policy_sha256: "p".into(),
            agent: None, owner: None, sandbox: None,
        })))),
        (OUTCOME_TYPE, to_value(serde_json::to_value(Statement::new(vec![tree()], Completion { task: "t".into(), outcome: String::new(), finished: "f".into(), base: None })))),
        (LOG_TYPE, to_value(serde_json::to_value(Statement::new(vec![log_subject("t", "h")], LogSeal { task: "t".into(), seq: 0, head: "h".into(), created: "c".into() })))),
        (TESTING_TYPE, to_value(serde_json::to_value(Statement::new(vec![tree()], Testing { outcome: Tested::Tested, task: "t".into(), note: String::new(), tester: "Lee".into(), created: "c".into() })))),
        (DISCARD_TYPE, to_value(serde_json::to_value(Statement::new(vec![work_subject("t", None)], Discard {
            task: "t".into(), branch: None, head: None, unpushed: 0, uncommitted: 0, by: "Bob".into(), created: "c".into(),
        })))),
        (PROMOTION_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], Promotion {
            env: "prod".into(), from: "uat".into(), direction: Direction::Back, source_commit: "c1".repeat(20), target_before: None,
            result_commit: "c1".repeat(20), how: "fast-forward".into(), rollback_point: None,
            rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: "c".into(), by: "ci".into(), reverts: None, task: None,
        })))),
        (DEPLOYMENT_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], Deployment {
            env: "uat".into(), commit: "c1".repeat(20), probes: vec![], smoke: vec![], confirmed: false, created: "c".into(), action: DeployAction::None,
        })))),
        (SIGNOFF_TYPE, to_value(serde_json::to_value(Statement::new(vec![commit_subject(&"c1".repeat(20))], SignOff {
            env: "prod".into(), from: "uat".into(), source_commit: "c1".repeat(20), decision: Decision::Reject, signer_person: "Dana".into(),
            text: String::new(), answers: vec![], confirmations: vec![], policy_sha256: "p".into(), created: "c".into(), expires: "e".into(),
        })))),
    ]
}

/// A statement with every `null` taken out of its predicate, as a writer that skips an absent
/// field would write it.
fn without_nulls(statement: &Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(map) => {
                map.retain(|_, inner| !inner.is_null());
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut out = statement.clone();
    strip(&mut out["predicate"]);
    out
}

fn schema(type_uri: &str) -> Value {
    let path = folder().join(file_for(type_uri));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("the record type {type_uri} has no schema: expected {}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

fn keys(v: &Value) -> BTreeSet<&str> {
    v.as_object().map(|m| m.keys().map(String::as_str).collect()).unwrap_or_default()
}

/// Every field the code wrote is described, and everything the schema requires was written.
fn described(root: &Value, schema: &Value, value: &Value, at: &str) {
    let schema = match schema.get("$ref").and_then(Value::as_str).and_then(|r| r.strip_prefix('#')) {
        Some(pointer) => root.pointer(pointer).unwrap_or_else(|| panic!("{at}: {pointer} is not in the schema")),
        None => schema,
    };
    match value {
        Value::Object(map) => {
            let Some(props) = schema.get("properties") else { return };
            let known = keys(props);
            for k in map.keys() {
                assert!(known.contains(k.as_str()), "{at}.{k} is written by the code but not in the schema");
            }
            for k in schema.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                assert!(map.contains_key(k), "{at}.{k} is required by the schema but the sample does not write it");
            }
            for (k, inner) in map {
                described(root, &props[k], inner, &format!("{at}.{k}"));
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = schema.get("items") {
                items.iter().for_each(|i| described(root, item_schema, i, &format!("{at}[]")));
            }
        }
        _ => {}
    }
}

#[test]
fn an_environments_records_stay_valid_with_a_value_a_newer_05_adds() {
    let full = samples();
    let find = |t: &str| full.iter().find(|(x, _)| *x == t).unwrap().1.clone();
    let mut promotion = find(PROMOTION_TYPE);
    promotion["predicate"]["direction"] = json!("sideways");
    promotion["predicate"]["rules"][0]["severity"] = json!("block");
    promotion["predicate"]["rules"][0]["outcome"] = json!("deferred");
    let mut deployment = find(DEPLOYMENT_TYPE);
    deployment["predicate"]["action"] = json!("paged-someone");
    for (t, statement) in [(PROMOTION_TYPE, promotion), (DEPLOYMENT_TYPE, deployment)] {
        let validator = jsonschema::validator_for(&schema(t)).unwrap();
        assert!(validator.is_valid(&statement), "{t}: new values in a list of words are allowed in v0");
    }
}

#[test]
fn every_record_type_matches_its_schema() {
    let samples = samples();
    let minimal = minimal_samples();
    let known: BTreeSet<&str> = RECORD_TYPES.iter().copied().collect();
    for (which, set) in [("full", &samples), ("minimal", &minimal)] {
        let sampled: BTreeSet<&str> = set.iter().map(|(t, _)| *t).collect();
        assert_eq!(sampled, known, "every record type the code knows needs a {which} sample here (and so a schema), and none may be extra");
    }

    // Statements with the optional fields filled in, then with them left out or empty.
    for (type_uri, statement) in samples.iter().chain(minimal.iter()) {
        let schema = schema(type_uri);
        let id = schema["$id"].as_str().unwrap_or_default();
        assert!(id.ends_with(&file_for(type_uri)), "{type_uri}: $id {id:?} should end with the file name");
        assert_eq!(schema["$schema"], "https://json-schema.org/draft/2020-12/schema", "{type_uri}");
        assert_eq!(schema["properties"]["predicateType"]["const"], *type_uri, "{type_uri}: the schema names its own type");
        assert_eq!(schema["additionalProperties"], true, "{type_uri}: added fields stay valid");
        assert_eq!(schema["properties"]["predicate"]["additionalProperties"], true, "{type_uri}: added fields stay valid");

        let validator = jsonschema::validator_for(&schema).unwrap_or_else(|e| panic!("{type_uri}: the schema is not a valid schema: {e}"));
        if let Err(e) = validator.validate(statement) {
            panic!("{type_uri}: the statement the code writes does not match its schema: {e}\n{statement:#}");
        }
        described(&schema, &schema, statement, type_uri);
        let skipped = without_nulls(statement);
        if let Err(e) = validator.validate(&skipped) {
            panic!("{type_uri}: a writer that skips its absent optional fields writes a statement that does not match the schema: {e}\n{skipped:#}");
        }

        // Fields added later are optional: a statement with more in it is still valid.
        let mut richer = statement.clone();
        richer["predicate"]["a_field_added_later"] = json!({"any": ["shape"]});
        richer["a_statement_field_added_later"] = json!(1);
        assert!(validator.is_valid(&richer), "{type_uri}: an added field must stay valid");

        // The statement's own type is checked, and so is the predicate.
        let mut other = statement.clone();
        other["predicateType"] = json!("https://use05.dev/something-else/v0");
        assert!(!validator.is_valid(&other), "{type_uri}: a statement of another type is not this type");
        let mut hollow = statement.clone();
        hollow["predicate"] = json!({});
        assert!(!validator.is_valid(&hollow), "{type_uri}: an empty predicate is not valid");
        let mut no_subject = statement.clone();
        no_subject["subject"] = json!([]);
        assert!(!validator.is_valid(&no_subject), "{type_uri}: a statement needs a subject");
    }
}

#[test]
fn every_required_field_is_needed_and_every_schema_file_belongs_to_a_type() {
    let known: BTreeSet<String> = RECORD_TYPES.iter().map(|t| file_for(t)).collect();
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(folder()).expect("docs/receipts exists") {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if is_schema_file(&name) {
            found.insert(name);
        }
    }
    let orphans: Vec<_> = found.difference(&known).collect();
    assert!(orphans.is_empty(), "these schemas describe no record type the code knows: {orphans:?}");
    let missing: Vec<_> = known.difference(&found).collect();
    assert!(missing.is_empty(), "these record types have no schema in docs/receipts: {missing:?}");

    // Dropping any one required predicate field makes the statement invalid.
    for (type_uri, statement) in samples() {
        let schema = schema(type_uri);
        let validator = jsonschema::validator_for(&schema).unwrap();
        let required: Vec<&str> = schema["properties"]["predicate"]["required"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(!required.is_empty(), "{type_uri}: the predicate has required fields");
        for field in required {
            let mut cut = statement.clone();
            cut["predicate"].as_object_mut().unwrap().remove(field);
            assert!(!validator.is_valid(&cut), "{type_uri}: a statement without {field} must not be valid");
        }
    }
}

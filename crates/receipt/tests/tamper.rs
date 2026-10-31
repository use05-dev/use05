//! Tamper-evidence tests for the receipt envelope.
//!
//! Every case must fail verification with the right class and code, never a panic.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use use05_receipt::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn evidence(status: Status, exit_code: Option<i32>) -> Evidence {
    let stream = |text: &str| Stream {
        total_bytes: text.len() as u64,
        retained_bytes: text.len() as u64,
        truncated: false,
        sha256: "00".repeat(32),
    };
    Evidence {
        command: Command { argv: vec!["cargo".into(), "test".into()], cwd: ".".into() },
        environment: Environment { fingerprint: "ab".repeat(32), names: vec!["PATH".into()] },
        result: Outcome {
            status,
            exit_code,
            signal: None,
            duration_ms: 1234,
            stdout: stream("ok"),
            stderr: stream(""),
        },
        runner: Runner { name: "use05".into(), version: "0.0.1".into(), platform: "linux-x86_64".into() },
        created: "2026-10-30T12:00:00Z".into(),
        check: None,
    }
}

fn statement() -> Statement {
    Statement::for_evidence(&"a1".repeat(20), &"b2".repeat(32), evidence(Status::Failed, Some(1)))
}

fn good(k: &SigningKey) -> Vec<u8> {
    seal(&statement(), k).to_json_bytes()
}

fn as_envelope(bytes: &[u8]) -> Envelope {
    serde_json::from_slice(bytes).unwrap()
}

fn to_bytes(e: &Envelope) -> Vec<u8> {
    serde_json::to_vec(e).unwrap()
}

fn expect_invalid(bytes: &[u8], key: &SigningKey, code: &str) {
    match verify(bytes, &key.verifying_key()) {
        Err(Fault::Invalid { code: got, .. }) => assert_eq!(got, code),
        other => panic!("expected Invalid({code}), got {other:?}"),
    }
}

fn expect_malformed(bytes: &[u8], key: &SigningKey, code: &str) {
    match verify(bytes, &key.verifying_key()) {
        Err(Fault::Malformed { code: got, .. }) => assert_eq!(got, code),
        other => panic!("expected Malformed({code}), got {other:?}"),
    }
}

/// Sign arbitrary bytes under an arbitrary payload type, as a hostile or buggy signer might.
fn forge(payload_type: &str, body: &[u8], k: &SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let sig = k.sign(&pae(payload_type, body));
    let envelope = Envelope {
        payload: STANDARD.encode(body),
        payload_type: payload_type.to_string(),
        signatures: vec![EnvelopeSignature { keyid: None, sig: STANDARD.encode(sig.to_bytes()) }],
    };
    to_bytes(&envelope)
}

#[test]
fn a_good_receipt_verifies_and_returns_the_statement() {
    let k = key(1);
    let verified = verify(&good(&k), &k.verifying_key()).expect("verifies");
    assert_eq!(verified.statement, statement());
    assert_eq!(verified.key_id, key_id(&k.verifying_key()));
    assert!(!verified.hint_mismatch);
}

#[test]
fn flipping_a_bit_in_the_payload_is_detected() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    let mut body = STANDARD.decode(&e.payload).unwrap();
    body[10] ^= 0x01;
    e.payload = STANDARD.encode(body);
    expect_invalid(&to_bytes(&e), &k, "SIGNATURE_MISMATCH");
}

#[test]
fn flipping_a_bit_in_the_signature_is_detected() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    let mut sig = STANDARD.decode(&e.signatures[0].sig).unwrap();
    sig[0] ^= 0x01;
    e.signatures[0].sig = STANDARD.encode(sig);
    expect_invalid(&to_bytes(&e), &k, "SIGNATURE_MISMATCH");
}

#[test]
fn changing_the_payload_type_after_signing_is_detected() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    e.payload_type = "application/vnd.in-toto+json ".into();
    expect_invalid(&to_bytes(&e), &k, "SIGNATURE_MISMATCH");
}

#[test]
fn the_key_id_hint_is_not_trusted_and_does_not_change_the_outcome() {
    // DSSE: the key id is an unauthenticated hint and must not be used for security decisions.
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    e.signatures[0].keyid = Some("deadbeefdeadbeef".into());
    let verified = verify(&to_bytes(&e), &k.verifying_key()).expect("still verifies");
    assert!(verified.hint_mismatch, "a wrong hint is surfaced, not obeyed");

    e.signatures[0].keyid = None;
    let verified = verify(&to_bytes(&e), &k.verifying_key()).expect("still verifies");
    assert!(!verified.hint_mismatch);
}

#[test]
fn a_hint_naming_another_key_cannot_make_a_wrong_key_verify() {
    let signer = key(1);
    let other = key(2);
    let mut e = as_envelope(&good(&signer));
    e.signatures[0].keyid = Some(key_id(&other.verifying_key()));
    expect_invalid(&to_bytes(&e), &other, "SIGNATURE_MISMATCH");
}

#[test]
fn the_wrong_key_is_rejected() {
    expect_invalid(&good(&key(1)), &key(2), "SIGNATURE_MISMATCH");
}

#[test]
fn flipping_a_failed_result_to_passed_is_detected() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    let body = STANDARD.decode(&e.payload).unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"status\":\"failed\""));
    let edited = text
        .replace("\"status\":\"failed\"", "\"status\":\"passed\"")
        .replace("\"exit_code\":1", "\"exit_code\":0");
    e.payload = STANDARD.encode(edited);
    expect_invalid(&to_bytes(&e), &k, "SIGNATURE_MISMATCH");
}

#[test]
fn a_truncated_envelope_is_malformed() {
    let k = key(1);
    let bytes = good(&k);
    expect_malformed(&bytes[..bytes.len() / 2], &k, "RECEIPT_NOT_JSON");
}

#[test]
fn garbage_and_empty_input_are_malformed_not_panics() {
    let k = key(1);
    expect_malformed(b"", &k, "RECEIPT_NOT_JSON");
    expect_malformed(b"not json at all", &k, "RECEIPT_NOT_JSON");
    expect_malformed(&[0xff, 0xfe, 0x00], &k, "RECEIPT_NOT_JSON");
    expect_malformed(b"{}", &k, "RECEIPT_BAD_ENVELOPE");
    expect_malformed(b"[]", &k, "RECEIPT_BAD_ENVELOPE");
    expect_malformed(b"null", &k, "RECEIPT_BAD_ENVELOPE");
}

#[test]
fn an_envelope_with_no_signatures_is_malformed() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    e.signatures.clear();
    expect_malformed(&to_bytes(&e), &k, "RECEIPT_NO_SIGNATURES");
}

#[test]
fn bad_base64_is_malformed() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    e.payload = "!!!not base64!!!".into();
    expect_malformed(&to_bytes(&e), &k, "RECEIPT_BAD_BASE64");

    let mut e = as_envelope(&good(&k));
    e.signatures[0].sig = "***".into();
    expect_malformed(&to_bytes(&e), &k, "RECEIPT_BAD_BASE64");
}

#[test]
fn a_signature_of_the_wrong_length_is_malformed() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    e.signatures[0].sig = STANDARD.encode([0u8; 10]);
    expect_malformed(&to_bytes(&e), &k, "RECEIPT_BAD_SIGNATURE");
}

#[test]
fn a_validly_signed_but_unknown_payload_type_is_invalid() {
    let k = key(1);
    let body = serde_json::to_vec(&statement()).unwrap();
    let bytes = forge("text/plain", &body, &k);
    expect_invalid(&bytes, &k, "PAYLOAD_TYPE_UNSUPPORTED");
}

#[test]
fn a_validly_signed_but_unreadable_statement_is_malformed() {
    let k = key(1);
    let bytes = forge(PAYLOAD_TYPE, b"this is not a statement", &k);
    expect_malformed(&bytes, &k, "RECEIPT_BAD_STATEMENT");
}

#[test]
fn a_validly_signed_statement_of_an_unknown_type_is_invalid() {
    let k = key(1);
    let mut s = statement();
    s.type_ = "https://example.com/Other/v9".into();
    let bytes = forge(PAYLOAD_TYPE, &serde_json::to_vec(&s).unwrap(), &k);
    expect_invalid(&bytes, &k, "STATEMENT_TYPE_UNSUPPORTED");

    let mut s = statement();
    s.predicate_type = "https://example.com/predicate/v9".into();
    let bytes = forge(PAYLOAD_TYPE, &serde_json::to_vec(&s).unwrap(), &k);
    expect_invalid(&bytes, &k, "PREDICATE_TYPE_UNSUPPORTED");
}

#[test]
fn a_statement_with_no_tree_subject_is_malformed() {
    let k = key(1);
    let mut s = statement();
    s.subject[0].name = "something-else".into();
    let bytes = forge(PAYLOAD_TYPE, &serde_json::to_vec(&s).unwrap(), &k);
    expect_malformed(&bytes, &k, "RECEIPT_BAD_STATEMENT");
}

#[test]
fn url_safe_base64_is_accepted_as_dsse_requires() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    let body = STANDARD.decode(&e.payload).unwrap();
    let sig = STANDARD.decode(&e.signatures[0].sig).unwrap();
    e.payload = URL_SAFE_NO_PAD.encode(body);
    e.signatures[0].sig = URL_SAFE_NO_PAD.encode(sig);
    verify(&to_bytes(&e), &k.verifying_key()).expect("url-safe encoding verifies");
}

#[test]
fn a_bad_extra_signature_next_to_a_good_one_is_harmless() {
    let k = key(1);
    let mut e = as_envelope(&good(&k));
    let mut bad = e.signatures[0].clone();
    let mut raw = STANDARD.decode(&bad.sig).unwrap();
    raw[5] ^= 0xff;
    bad.sig = STANDARD.encode(raw);
    e.signatures.insert(0, bad);
    verify(&to_bytes(&e), &k.verifying_key()).expect("the genuine signature is enough");
}

#[test]
fn key_files_round_trip_and_reject_the_wrong_kind() {
    let k = key(7);
    let secret = secret_key_text(&k);
    let public = public_key_text(&k.verifying_key());
    assert_eq!(parse_secret_key(&secret).unwrap().to_bytes(), k.to_bytes());
    assert_eq!(parse_public_key(&public).unwrap(), k.verifying_key());
    assert_eq!(parse_public_key(&secret), Err(KeyError::WrongKind("public")));
    assert_eq!(parse_secret_key(&public).err(), Some(KeyError::WrongKind("secret")));
    assert_eq!(parse_public_key("use05-ed25519-public:@@@"), Err(KeyError::BadEncoding));
    assert_eq!(parse_public_key("use05-ed25519-public:AAAA"), Err(KeyError::BadLength));
}

/// The strongest check: damage every byte of a real envelope in several ways. A mutation may be
/// accepted only if it changes nothing that matters, meaning the verified statement is identical
/// (whitespace, the unauthenticated key id hint, or padding). Anything else must be rejected.
#[test]
fn no_single_byte_mutation_changes_what_a_receipt_says_and_still_verifies() {
    let k = key(1);
    let original = good(&k);
    let expected = statement();
    let (mut accepted_unchanged, mut rejected) = (0usize, 0usize);

    let mut check = |mutated: Vec<u8>, what: String| match verify(&mutated, &k.verifying_key()) {
        Err(_) => rejected += 1,
        Ok(v) => {
            assert_eq!(v.statement, expected, "a mutation was accepted AND changed the statement: {what}");
            accepted_unchanged += 1;
        }
    };

    for i in 0..original.len() {
        let mut flipped = original.clone();
        flipped[i] ^= 0x01;
        check(flipped, format!("bit flip at byte {i}"));

        if original[i] != b'X' {
            let mut replaced = original.clone();
            replaced[i] = b'X';
            check(replaced, format!("replace byte {i} with X"));
        }

        let mut deleted = original.clone();
        deleted.remove(i);
        check(deleted, format!("delete byte {i}"));

        let mut inserted = original.clone();
        inserted.insert(i, b'A');
        check(inserted, format!("insert A before byte {i}"));
    }

    eprintln!(
        "{} bytes, {} mutations: {rejected} rejected, {accepted_unchanged} accepted without changing the statement",
        original.len(),
        rejected + accepted_unchanged
    );
    assert!(rejected > accepted_unchanged * 5, "most mutations must be rejected");
}

// ----------------------------------------------------------------------------- declarations (D65)

#[test]
fn intent_and_outcome_statements_verify_and_tampering_is_caught() {
    let k = key(3);
    let declaration = Statement::new(
        vec![intent_subject(&"c3".repeat(32))],
        Declaration {
            task: "9ce9a1e4".into(),
            title: "Cap retries".into(),
            author: "agent:codex".into(),
            card: serde_json::json!({ "scope": { "include": ["src/**"] } }),
            sealed: "2026-10-30T12:00:00Z".into(),
            policy_sha256: "d4".repeat(32),
            agent: Some(AgentRef { kind: "codex".into(), session: "s1".into(), model: None }),
            owner: Some(OwnerRef { name: "Dana".into(), key_id: "ab".repeat(8) }),
            sandbox: None,
        },
    );
    let bytes = seal(&declaration, &k).to_json_bytes();
    match verify_any(&bytes, &k.verifying_key()).expect("verifies").statement {
        AnyStatement::Declaration(s) => assert_eq!(s, declaration),
        other => panic!("{other:?}"),
    }
    let completion = Statement::new(vec![tree_subject(&"a1".repeat(20), &"b2".repeat(32))], Completion { task: "9ce9a1e4".into(), outcome: "capped at 3; tests pass".into(), finished: "2026-10-30T12:30:00Z".into() });
    let bytes = seal(&completion, &k).to_json_bytes();
    assert!(matches!(verify_any(&bytes, &k.verifying_key()).unwrap().statement, AnyStatement::Completion(_)));
    let mut e = as_envelope(&bytes);
    let mut body = STANDARD.decode(&e.payload).unwrap();
    let at = body.len() - 20;
    body[at] ^= 0x01;
    e.payload = STANDARD.encode(body);
    assert!(verify_any(&to_bytes(&e), &k.verifying_key()).is_err());
    let no_subject = Statement::new(vec![tree_subject(&"a1".repeat(20), &"b2".repeat(32))], Declaration { task: "t".into(), title: "x".into(), author: "a".into(), card: serde_json::json!({}), sealed: "s".into(), policy_sha256: "p".into(), agent: None, owner: None, sandbox: None });
    assert!(verify_any(&seal(&no_subject, &k).to_json_bytes(), &k.verifying_key()).is_err(), "a declaration must name the card it declares");
}

// ----------------------------------------------------------------------------- log seals (D70)

#[test]
fn a_log_seal_verifies_names_its_task_and_head_and_tampering_is_caught() {
    let k = key(4);
    let seal_statement = Statement::new(vec![log_subject("9ce9a1e4", &"ab".repeat(32))], LogSeal { task: "9ce9a1e4".into(), seq: 7, head: "ab".repeat(32), created: "2026-10-30T12:00:00Z".into() });
    let bytes = seal(&seal_statement, &k).to_json_bytes();
    match verify_any(&bytes, &k.verifying_key()).expect("verifies").statement {
        AnyStatement::LogSeal(s) => {
            assert_eq!(s, seal_statement);
            assert_eq!(s.log_subject(), Some(("9ce9a1e4", "ab".repeat(32).as_str())));
        }
        other => panic!("{other:?}"),
    }
    let mut e = as_envelope(&bytes);
    let mut body = STANDARD.decode(&e.payload).unwrap();
    let at = body.len() - 30;
    body[at] ^= 0x01;
    e.payload = STANDARD.encode(body);
    assert!(verify_any(&to_bytes(&e), &k.verifying_key()).is_err());
    let wrong = Statement::new(vec![tree_subject(&"a1".repeat(20), &"b2".repeat(32))], LogSeal { task: "t".into(), seq: 1, head: "h".into(), created: "c".into() });
    assert!(verify_any(&seal(&wrong, &k).to_json_bytes(), &k.verifying_key()).is_err(), "a log seal must name the log it seals");
}

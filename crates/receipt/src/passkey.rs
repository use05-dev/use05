//! Passkeys as approver keys.
//!
//! A passkey (WebAuthn) does not sign arbitrary bytes: it signs its authenticator data followed
//! by the SHA-256 of a small JSON document the browser writes, which carries a challenge chosen
//! by the page. A passkey-signed receipt is an ordinary DSSE envelope whose challenge is the
//! SHA-256 of the envelope's pre-authentication encoding, so the signature still covers exactly
//! the statement, and the assertion travels in the signature entry for anyone to check.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::dsse::{self, EnvelopeSignature, Fault, Opened, WebAuthnSig, pae};
use crate::keys::KeyError;

pub(crate) const PUBLIC_PREFIX: &str = "use05-passkey-p256-public:";

/// Authenticator data flags: the person was present, and was verified (Face ID, fingerprint, PIN).
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;

/// A passkey's public key (ES256: ECDSA on P-256 with SHA-256) and the site it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyKey {
    /// The WebAuthn relying party id: the domain the passkey was made for.
    pub rp_id: String,
    sec1: [u8; 65],
}

impl PasskeyKey {
    /// From the uncompressed SEC1 point (65 bytes, as browsers report it after conversion from COSE).
    pub fn from_sec1(rp_id: &str, sec1: &[u8]) -> Result<PasskeyKey, KeyError> {
        // A relying party id is a domain name: letters, digits, dots and hyphens.
        if rp_id.is_empty() || !rp_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err(KeyError::BadEncoding);
        }
        let sec1: [u8; 65] = sec1.try_into().map_err(|_| KeyError::BadLength)?;
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| KeyError::BadEncoding)?;
        Ok(PasskeyKey { rp_id: rp_id.to_string(), sec1 })
    }

    pub fn sec1(&self) -> [u8; 65] {
        self.sec1
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_sec1_bytes(&self.sec1).expect("checked when the key was made")
    }
}

pub fn passkey_public_text(key: &PasskeyKey) -> String {
    format!("{PUBLIC_PREFIX}{}:{}\n", key.rp_id, STANDARD.encode(key.sec1))
}

pub(crate) fn parse_text(text: &str) -> Result<PasskeyKey, KeyError> {
    let rest = text.trim().strip_prefix(PUBLIC_PREFIX).ok_or(KeyError::WrongKind("passkey public"))?;
    let (rp_id, b64) = rest.rsplit_once(':').ok_or(KeyError::BadEncoding)?;
    let bytes = STANDARD.decode(b64.trim()).map_err(|_| KeyError::BadEncoding)?;
    PasskeyKey::from_sec1(rp_id, &bytes)
}

/// The WebAuthn challenge for a statement: the SHA-256 of its pre-authentication encoding.
pub fn passkey_challenge(payload_type: &str, body: &[u8]) -> [u8; 32] {
    Sha256::digest(pae(payload_type, body)).into()
}

/// The site a Touch ID approver key signs for. It is not a website: it names the Mac's Secure
/// Enclave as the authenticator, so the same checks as for any passkey apply (D91).
pub const TOUCH_ID_SITE: &str = "touch-id";

/// What a passkey on this machine signs for a statement, when no browser is involved (a Touch ID
/// key in the Mac's Secure Enclave): authenticator data that says the person was present and
/// verified, the client data naming the challenge, and the message to sign over both. The
/// signature over `message`, with the first two, is an ordinary passkey signature (D91).
pub struct LocalAssertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub message: Vec<u8>,
}

pub fn local_assertion(rp_id: &str, payload_type: &str, body: &[u8]) -> LocalAssertion {
    let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
    auth.push(USER_PRESENT | USER_VERIFIED);
    auth.extend_from_slice(&[0, 0, 0, 0]);
    let challenge = URL_SAFE_NO_PAD.encode(passkey_challenge(payload_type, body));
    let client = serde_json::json!({ "type": "webauthn.get", "challenge": challenge, "origin": format!("https://{rp_id}"), "crossOrigin": false });
    let client = serde_json::to_vec(&client).expect("serialises");
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client));
    LocalAssertion { authenticator_data: auth, client_data_json: client, message }
}

/// The envelope entry for a passkey signature (DER ECDSA) made over [`LocalAssertion::message`].
pub fn passkey_entry(key: &PasskeyKey, assertion: &LocalAssertion, der: &[u8]) -> EnvelopeSignature {
    EnvelopeSignature {
        keyid: Some(crate::PublicKey::Passkey(key.clone()).id()),
        sig: STANDARD.encode(der),
        webauthn: Some(WebAuthnSig { authenticator_data: STANDARD.encode(&assertion.authenticator_data), client_data_json: STANDARD.encode(&assertion.client_data_json) }),
    }
}

fn mismatch() -> Fault {
    Fault::invalid("SIGNATURE_MISMATCH", "the signature does not match this receipt and the key you supplied")
}

/// Verify the envelope's passkey signatures against this key. Entries without an assertion are
/// Ed25519 signatures and are left to that path.
pub(crate) fn verify(envelope_json: &[u8], key: &PasskeyKey) -> Result<Opened, Fault> {
    let (envelope, body) = dsse::open(envelope_json)?;
    let challenge = passkey_challenge(&envelope.payload_type, &body);
    let vk = key.verifying_key();
    // A signature by this key that fails a later rule says more than "not this key".
    let mut refusal: Option<Fault> = None;
    for entry in &envelope.signatures {
        let Some(assertion) = &entry.webauthn else { continue };
        match check(entry, assertion, &vk, key, &challenge) {
            Ok(()) => {
                dsse::check_type(&envelope)?;
                return Ok(Opened { payload: body, hint: entry.keyid.clone() });
            }
            Err(f) if f.is_malformed() => return Err(f),
            Err(f) if f.code() != "SIGNATURE_MISMATCH" => refusal = Some(f),
            Err(_) => {}
        }
    }
    Err(refusal.unwrap_or_else(mismatch))
}

fn check(entry: &EnvelopeSignature, assertion: &WebAuthnSig, vk: &VerifyingKey, key: &PasskeyKey, challenge: &[u8; 32]) -> Result<(), Fault> {
    let b64 = |text: &str| dsse::decode_b64(text).ok_or_else(|| Fault::malformed("RECEIPT_BAD_BASE64", "a passkey signature is not valid base64"));
    let auth = b64(&assertion.authenticator_data)?;
    let client = b64(&assertion.client_data_json)?;
    let der = b64(&entry.sig)?;
    if auth.len() < 37 {
        return Err(Fault::malformed("PASSKEY_BAD_ASSERTION", "a passkey signature's authenticator data is too short"));
    }
    let sig = Signature::from_der(&der).map_err(|_| Fault::malformed("RECEIPT_BAD_SIGNATURE", "a passkey signature is not a DER ECDSA signature"))?;
    // Authenticators do not normalise s; both halves are the same signature.
    let sig = sig.normalize_s().unwrap_or(sig);

    // First: did this key sign exactly these bytes? Only then are the bytes worth reading.
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client));
    vk.verify(&message, &sig).map_err(|_| mismatch())?;

    let wrong_site = |detail: &str| Fault::invalid("PASSKEY_WRONG_SITE", detail.to_string());
    if auth[..32] != Sha256::digest(key.rp_id.as_bytes())[..] {
        return Err(wrong_site("the passkey signed for another site"));
    }
    let flags = auth[32];
    if flags & USER_PRESENT == 0 || flags & USER_VERIFIED == 0 {
        return Err(Fault::invalid("PASSKEY_NOT_VERIFIED", "the passkey was used without verifying the person (Face ID, fingerprint or PIN)"));
    }
    let data: serde_json::Value = serde_json::from_slice(&client).map_err(|_| Fault::malformed("PASSKEY_BAD_ASSERTION", "a passkey signature's client data is not JSON"))?;
    if data["type"] != "webauthn.get" {
        return Err(Fault::invalid("PASSKEY_WRONG_CEREMONY", "the passkey data is not a signature (webauthn.get)"));
    }
    let signed_for = data["challenge"].as_str().and_then(|c| URL_SAFE_NO_PAD.decode(c.trim_end_matches('=')).ok());
    if signed_for.as_deref() != Some(&challenge[..]) {
        return Err(mismatch());
    }
    let origin = data["origin"].as_str().unwrap_or("");
    let local = key.rp_id == "localhost" && (origin == "http://localhost" || origin.starts_with("http://localhost:"));
    if !(origin == format!("https://{}", key.rp_id) || local) {
        return Err(wrong_site("the passkey was used on another site"));
    }
    if data["crossOrigin"] == true {
        return Err(wrong_site("the passkey was used from a page embedded in another site"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsse::{Envelope, EnvelopeSignature, PAYLOAD_TYPE, WebAuthnSig};
    use crate::{AnyStatement, Approval, ApprovalScope, Decision, PublicKey, Statement, parse_any_public_key, tree_subject, verify_any, verify_any_with};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use p256::ecdsa::signature::Signer;
    use sha2::{Digest, Sha256};

    #[test]
    fn a_local_assertion_verifies_as_a_passkey_signature_and_only_for_its_statement() {
        let sk = authenticator();
        let key = key_of(&sk, TOUCH_ID_SITE);
        let body = approval_body("t1");
        let a = local_assertion(TOUCH_ID_SITE, PAYLOAD_TYPE, &body);
        let sig: p256::ecdsa::Signature = sk.sign(&a.message);
        let envelope = Envelope { payload: STANDARD.encode(&body), payload_type: PAYLOAD_TYPE.into(), signatures: vec![passkey_entry(&key, &a, sig.to_der().as_bytes())] };
        assert!(verify_any_with(&envelope.to_json_bytes(), &PublicKey::Passkey(key.clone())).is_ok());
        // The same signature over another statement does not count.
        let other = Envelope { payload: STANDARD.encode(approval_body("t2")), ..envelope.clone() };
        assert!(verify_any_with(&other.to_json_bytes(), &PublicKey::Passkey(key.clone())).is_err());
        // Nor for a key made for another site.
        assert!(verify_any_with(&envelope.to_json_bytes(), &PublicKey::Passkey(key_of(&sk, "console.example"))).is_err());
    }

    const RP: &str = "console.example";
    const ORIGIN: &str = "https://console.example";
    const UP_UV: u8 = 0x05;

    fn authenticator() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn key_of(sk: &p256::ecdsa::SigningKey, rp_id: &str) -> PasskeyKey {
        PasskeyKey::from_sec1(rp_id, sk.verifying_key().to_encoded_point(false).as_bytes()).unwrap()
    }

    fn approval_body(task: &str) -> Vec<u8> {
        let statement = Statement::new(
            vec![tree_subject("1234567890abcdef1234567890abcdef12345678", "ab".repeat(32).as_str())],
            Approval {
                decision: Decision::Approve,
                scope: ApprovalScope::Outcome,
                task: task.into(),
                intent_sha256: None,
                policy_sha256: "cd".repeat(32),
                rationale: String::new(),
                approver: "owner".into(),
                created: "2026-11-01T10:00:00Z".into(),
                expires: "2026-11-08T10:00:00Z".into(),
            },
        );
        serde_json::to_vec(&statement).unwrap()
    }

    /// What a browser produces for `navigator.credentials.get` with the challenge for `signed_body`,
    /// wrapped as an envelope around `body`.
    #[allow(clippy::too_many_arguments)]
    fn fake_assertion(sk: &p256::ecdsa::SigningKey, rp_id: &str, origin: &str, flags: u8, typ: &str, signed_body: &[u8], body: &[u8], extra: &str) -> Envelope {
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&[0, 0, 0, 1]);
        let challenge = URL_SAFE_NO_PAD.encode(passkey_challenge(PAYLOAD_TYPE, signed_body));
        let client = format!(r#"{{"type":"{typ}","challenge":"{challenge}","origin":"{origin}"{extra}}}"#);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig: p256::ecdsa::Signature = sk.sign(&message);
        Envelope {
            payload: STANDARD.encode(body),
            payload_type: PAYLOAD_TYPE.into(),
            signatures: vec![EnvelopeSignature {
                keyid: None,
                sig: STANDARD.encode(sig.to_der().as_bytes()),
                webauthn: Some(WebAuthnSig { authenticator_data: STANDARD.encode(&auth), client_data_json: STANDARD.encode(client.as_bytes()) }),
            }],
        }
    }

    fn good(sk: &p256::ecdsa::SigningKey) -> Envelope {
        let body = approval_body("t1");
        fake_assertion(sk, RP, ORIGIN, UP_UV, "webauthn.get", &body, &body, "")
    }

    fn code(envelope: &Envelope, key: &PasskeyKey) -> &'static str {
        verify_any_with(&envelope.to_json_bytes(), &PublicKey::Passkey(key.clone())).unwrap_err().code()
    }

    #[test]
    fn a_passkey_signed_approval_verifies_and_reads_back() {
        let sk = authenticator();
        let key = key_of(&sk, RP);
        let verified = verify_any_with(&good(&sk).to_json_bytes(), &PublicKey::Passkey(key.clone())).unwrap();
        assert!(matches!(&verified.statement, AnyStatement::Approval(s) if s.predicate.task == "t1"));
        assert_eq!(verified.key_id, PublicKey::Passkey(key).id());
    }

    #[test]
    fn a_cosigned_envelope_verifies_with_each_signer() {
        let sk = authenticator();
        let key = key_of(&sk, RP);
        let machine = crate::SigningKey::from_bytes(&[3u8; 32]);
        let body = approval_body("t1");
        let mut envelope = fake_assertion(&sk, RP, ORIGIN, UP_UV, "webauthn.get", &body, &body, "");
        envelope.signatures.push(crate::cosignature(PAYLOAD_TYPE, &body, &machine));
        let bytes = envelope.to_json_bytes();
        assert!(verify_any_with(&bytes, &PublicKey::Passkey(key.clone())).is_ok());
        assert!(verify_any_with(&bytes, &PublicKey::Ed25519(machine.verifying_key())).is_ok());
        // Order does not matter: the co-signature first, the passkey second.
        envelope.signatures.reverse();
        let bytes = envelope.to_json_bytes();
        assert!(verify_any_with(&bytes, &PublicKey::Passkey(key)).is_ok());
        assert!(verify_any_with(&bytes, &PublicKey::Ed25519(machine.verifying_key())).is_ok());
    }

    #[test]
    fn a_site_is_a_domain_name_and_nothing_else() {
        let point = key_of(&p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(), RP).sec1;
        for ok in ["console.example", "localhost", "a-b.example.co.uk"] {
            assert!(PasskeyKey::from_sec1(ok, &point).is_ok(), "{ok}");
        }
        for bad in ["", "evil\u{1b}[2J.example", "a/b.example", "a b", "x:1", "café.example"] {
            assert!(PasskeyKey::from_sec1(bad, &point).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn wrong_rp_id_hash_is_wrong_site() {
        let sk = authenticator();
        let body = approval_body("t1");
        let envelope = fake_assertion(&sk, "evil.example", ORIGIN, UP_UV, "webauthn.get", &body, &body, "");
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "PASSKEY_WRONG_SITE");
    }

    #[test]
    fn missing_user_verification_is_refused() {
        let sk = authenticator();
        let body = approval_body("t1");
        let envelope = fake_assertion(&sk, RP, ORIGIN, 0x01, "webauthn.get", &body, &body, "");
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "PASSKEY_NOT_VERIFIED");
    }

    #[test]
    fn a_create_ceremony_is_not_a_signature() {
        let sk = authenticator();
        let body = approval_body("t1");
        let envelope = fake_assertion(&sk, RP, ORIGIN, UP_UV, "webauthn.create", &body, &body, "");
        let err = verify_any_with(&envelope.to_json_bytes(), &PublicKey::Passkey(key_of(&sk, RP))).unwrap_err();
        assert!(!err.is_malformed(), "{err:?}");
    }

    #[test]
    fn challenge_for_other_bytes_is_mismatch() {
        let sk = authenticator();
        let envelope = fake_assertion(&sk, RP, ORIGIN, UP_UV, "webauthn.get", &approval_body("other"), &approval_body("t1"), "");
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "SIGNATURE_MISMATCH");
    }

    #[test]
    fn origin_on_another_site_is_refused() {
        let sk = authenticator();
        let body = approval_body("t1");
        let envelope = fake_assertion(&sk, RP, "https://evil.example", UP_UV, "webauthn.get", &body, &body, "");
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "PASSKEY_WRONG_SITE");
    }

    #[test]
    fn a_cross_origin_assertion_is_refused() {
        let sk = authenticator();
        let body = approval_body("t1");
        let envelope = fake_assertion(&sk, RP, ORIGIN, UP_UV, "webauthn.get", &body, &body, r#","crossOrigin":true"#);
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "PASSKEY_WRONG_SITE");
    }

    #[test]
    fn localhost_origin_only_for_localhost_rp() {
        let sk = authenticator();
        let body = approval_body("t1");
        let local = fake_assertion(&sk, "localhost", "http://localhost:8080", UP_UV, "webauthn.get", &body, &body, "");
        assert!(verify_any_with(&local.to_json_bytes(), &PublicKey::Passkey(key_of(&sk, "localhost"))).is_ok());
        let plain_http = fake_assertion(&sk, RP, "http://console.example", UP_UV, "webauthn.get", &body, &body, "");
        assert_eq!(code(&plain_http, &key_of(&sk, RP)), "PASSKEY_WRONG_SITE");
    }

    #[test]
    fn tampered_payload_is_mismatch() {
        let sk = authenticator();
        let mut envelope = good(&sk);
        envelope.payload = STANDARD.encode(approval_body("t2"));
        assert_eq!(code(&envelope, &key_of(&sk, RP)), "SIGNATURE_MISMATCH");
    }

    #[test]
    fn another_passkey_does_not_verify_it() {
        let other = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        assert_eq!(code(&good(&authenticator()), &key_of(&other, RP)), "SIGNATURE_MISMATCH");
    }

    #[test]
    fn a_high_s_signature_still_verifies() {
        // Authenticators do not normalise s; either half of the curve order is a valid ECDSA signature.
        let sk = authenticator();
        let mut envelope = good(&sk);
        let der = STANDARD.decode(&envelope.signatures[0].sig).unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        let (r, s) = sig.split_scalars();
        let flipped = p256::ecdsa::Signature::from_scalars(r, -s).unwrap();
        envelope.signatures[0].sig = STANDARD.encode(flipped.to_der().as_bytes());
        assert!(verify_any_with(&envelope.to_json_bytes(), &PublicKey::Passkey(key_of(&sk, RP))).is_ok());
    }

    #[test]
    fn ed25519_key_reports_mismatch_not_malformed_for_passkey_envelope() {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
        let err = verify_any(&good(&authenticator()).to_json_bytes(), &ed).unwrap_err();
        assert_eq!(err.code(), "SIGNATURE_MISMATCH", "{err:?}");
    }

    #[test]
    fn bytes_of_any_kind_verify_with_the_passkey_that_signed_them() {
        let sk = authenticator();
        let body = br#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://example.com/other/v0","predicate":{}}"#;
        let envelope = fake_assertion(&sk, RP, ORIGIN, UP_UV, "webauthn.get", body, body, "").to_json_bytes();
        assert_eq!(crate::verify_bytes_with(&envelope, &PublicKey::Passkey(key_of(&sk, RP))).unwrap(), body.to_vec());
        let other = key_of(&p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap(), RP);
        assert_eq!(crate::verify_bytes_with(&envelope, &PublicKey::Passkey(other)).unwrap_err().code(), "SIGNATURE_MISMATCH");
    }

    #[test]
    fn public_text_round_trips() {
        let key = key_of(&authenticator(), RP);
        let text = passkey_public_text(&key);
        assert!(text.starts_with("use05-passkey-p256-public:console.example:") && text.ends_with('\n'));
        assert_eq!(parse_any_public_key(&text).unwrap(), PublicKey::Passkey(key));
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
        assert_eq!(parse_any_public_key(&crate::public_key_text(&ed)).unwrap(), PublicKey::Ed25519(ed));
        let compressed = authenticator().verifying_key().to_encoded_point(true);
        let short = format!("use05-passkey-p256-public:{RP}:{}", STANDARD.encode(compressed.as_bytes()));
        assert_eq!(parse_any_public_key(&short), Err(crate::KeyError::BadLength));
        assert_eq!(parse_any_public_key("use05-passkey-p256-public::AAAA"), Err(crate::KeyError::BadEncoding));
    }
}

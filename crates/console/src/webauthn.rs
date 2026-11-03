//! Passkey sign-in and registration, verified here with no third-party WebAuthn library.
//!
//! Only ES256 (ECDSA on P-256) passkeys are accepted, the kind 05's receipts can verify, so the
//! passkey that signs you in is the same one that signs approvals. Attestation is not checked
//! ("none"): a passkey is trusted because a signed-in owner (or the one-time setup secret) added it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// SubjectPublicKeyInfo header for an uncompressed P-256 key: everything before the 65-byte point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const ATTESTED: u8 = 0x40;

pub struct Site {
    pub rp_id: String,
    pub origin: String,
}

#[derive(Deserialize)]
pub struct Registration {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct Assertion {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
}

pub fn b64(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).map_err(|_| "not base64url".to_string())
}

fn client_ok(client: &[u8], typ: &str, challenge: &[u8], site: &Site) -> Result<(), String> {
    let data: serde_json::Value = serde_json::from_slice(client).map_err(|_| "the browser's data is not JSON")?;
    if data["type"] != typ {
        return Err(format!("expected a {typ} ceremony"));
    }
    if data["challenge"].as_str().and_then(|c| b64(c).ok()).as_deref() != Some(challenge) {
        return Err("the challenge does not match".into());
    }
    if data["origin"] != site.origin.as_str() {
        return Err("the passkey was used on another site".into());
    }
    if data["crossOrigin"] == true {
        return Err("the passkey was used from an embedded page".into());
    }
    Ok(())
}

fn auth_ok(auth: &[u8], site: &Site) -> Result<u8, String> {
    if auth.len() < 37 {
        return Err("the authenticator data is too short".into());
    }
    if auth[..32] != Sha256::digest(site.rp_id.as_bytes())[..] {
        return Err("the passkey belongs to another site".into());
    }
    let flags = auth[32];
    if flags & USER_PRESENT == 0 || flags & USER_VERIFIED == 0 {
        return Err("Face ID, a fingerprint or a PIN is required".into());
    }
    Ok(flags)
}

/// Check a new passkey and return its credential id and P-256 point.
pub fn register(r: &Registration, challenge: &[u8], site: &Site) -> Result<(String, Vec<u8>), String> {
    let client = b64(&r.client_data_json)?;
    let auth = b64(&r.authenticator_data)?;
    client_ok(&client, "webauthn.create", challenge, site)?;
    let flags = auth_ok(&auth, site)?;
    let spki = b64(&r.public_key)?;
    if spki.len() != P256_SPKI_PREFIX.len() + 65 || spki[..P256_SPKI_PREFIX.len()] != P256_SPKI_PREFIX {
        return Err("only P-256 passkeys (ES256) can approve 05 changes; this one is another kind".into());
    }
    let sec1 = spki[P256_SPKI_PREFIX.len()..].to_vec();
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| "the passkey's public key is not a valid P-256 point")?;
    // The credential id inside the authenticator data must be the one the browser reported.
    if flags & ATTESTED != 0 && auth.len() >= 55 {
        let len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        if auth.len() < 55 + len || auth[55..55 + len] != b64(&r.id)?[..] {
            return Err("the credential id does not match the authenticator data".into());
        }
    }
    Ok((r.id.clone(), sec1))
}

/// Check a sign-in assertion against the stored public key.
pub fn assert(a: &Assertion, sec1: &[u8], challenge: &[u8], site: &Site) -> Result<(), String> {
    let client = b64(&a.client_data_json)?;
    let auth = b64(&a.authenticator_data)?;
    let der = b64(&a.signature)?;
    let key = VerifyingKey::from_sec1_bytes(sec1).map_err(|_| "stored key unusable")?;
    let sig = Signature::from_der(&der).map_err(|_| "the signature is not DER")?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client));
    key.verify(&message, &sig).map_err(|_| "the signature does not match this passkey")?;
    auth_ok(&auth, site)?;
    client_ok(&client, "webauthn.get", challenge, site)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    fn site() -> Site {
        Site { rp_id: "localhost".into(), origin: "http://localhost:8080".into() }
    }

    fn sign_in(sk: &p256::ecdsa::SigningKey, challenge: &[u8], origin: &str, flags: u8) -> Assertion {
        let mut auth = Sha256::digest(b"localhost").to_vec();
        auth.extend_from_slice(&[flags, 0, 0, 0, 1]);
        let client = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}"}}"#, URL_SAFE_NO_PAD.encode(challenge));
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig: Signature = sk.sign(&message);
        Assertion { id: "x".into(), client_data_json: URL_SAFE_NO_PAD.encode(&client), authenticator_data: URL_SAFE_NO_PAD.encode(&auth), signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()) }
    }

    #[test]
    fn a_sign_in_verifies_and_every_rule_is_enforced() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let sec1 = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert!(assert(&sign_in(&sk, b"chal", "http://localhost:8080", 0x05), &sec1, b"chal", &site()).is_ok());
        assert!(assert(&sign_in(&sk, b"chal", "http://localhost:8080", 0x05), &sec1, b"other", &site()).is_err(), "challenge");
        assert!(assert(&sign_in(&sk, b"chal", "https://evil.example", 0x05), &sec1, b"chal", &site()).is_err(), "origin");
        assert!(assert(&sign_in(&sk, b"chal", "http://localhost:8080", 0x01), &sec1, b"chal", &site()).is_err(), "user verification");
        let other = p256::ecdsa::SigningKey::from_slice(&[4; 32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert!(assert(&sign_in(&sk, b"chal", "http://localhost:8080", 0x05), &other, b"chal", &site()).is_err(), "key");
    }

    #[test]
    fn registration_takes_only_p256_keys() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
        let mut auth = Sha256::digest(b"localhost").to_vec();
        auth.extend_from_slice(&[0x05, 0, 0, 0, 1]);
        let client = format!(r#"{{"type":"webauthn.create","challenge":"{}","origin":"http://localhost:8080"}}"#, URL_SAFE_NO_PAD.encode(b"c"));
        let mut r = Registration { id: "aWQ".into(), client_data_json: URL_SAFE_NO_PAD.encode(&client), authenticator_data: URL_SAFE_NO_PAD.encode(&auth), public_key: URL_SAFE_NO_PAD.encode(&spki) };
        assert_eq!(register(&r, b"c", &site()).unwrap().1.len(), 65);
        r.public_key = URL_SAFE_NO_PAD.encode([0u8; 44]);
        assert!(register(&r, b"c", &site()).is_err());
    }
}

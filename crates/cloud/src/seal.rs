//! Sealing for the console (D86): what machines send can be read only by the team, what the team
//! sends a machine only by that machine. One format, the same in Rust and in the browser
//! (console-web/src/crypto.ts), versioned by its first byte.
//!
//! seal: 0x01 ‖ ephemeral X25519 public (32) ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad),
//!       key = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub ‖ recipient_pub, "use05 seal v1").
//! wrap: 0x01 ‖ nonce (12) ‖ AES-256-GCM(key, nonce, plaintext, aad), for a key both sides hold.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const V1: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// Too short, or not a version this build reads.
    Malformed,
    /// The wrong key, other associated data, or tampered bytes.
    Rejected,
}

/// The X25519 public key of a secret.
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// A fresh X25519 secret.
pub fn new_secret() -> [u8; 32] {
    rand::random()
}

/// 32 bytes from input key material, for one purpose.
pub fn derive(ikm: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm).expand(info.as_bytes(), &mut out).expect("32 bytes is a valid length");
    out
}

fn gcm(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("a 32-byte key")
}

fn seal_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared).expand(b"use05 seal v1", &mut out).expect("32 bytes is a valid length");
    out
}

/// Seal for the holder of `recipient`'s secret.
pub fn seal(recipient: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    seal_with(&new_secret(), &rand::random(), recipient, plaintext, aad)
}

/// `seal` with a given ephemeral secret and nonce: for test vectors only.
pub fn seal_with(eph: &[u8; 32], nonce: &[u8; 12], recipient: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let eph = StaticSecret::from(*eph);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient)).to_bytes();
    let ct = gcm(&seal_key(&shared, &eph_pub, recipient)).encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad }).expect("AES-GCM encrypts");
    let mut out = Vec::with_capacity(1 + 32 + 12 + ct.len());
    out.push(V1);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(secret: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < 1 + 32 + 12 + 16 || sealed[0] != V1 {
        return Err(SealError::Malformed);
    }
    let eph_pub: [u8; 32] = sealed[1..33].try_into().expect("32 bytes");
    let secret = StaticSecret::from(*secret);
    let recipient = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub)).to_bytes();
    gcm(&seal_key(&shared, &eph_pub, &recipient)).decrypt(Nonce::from_slice(&sealed[33..45]), Payload { msg: &sealed[45..], aad }).map_err(|_| SealError::Rejected)
}

/// Encrypt with a key both sides hold.
pub fn wrap(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    wrap_with(key, &rand::random(), plaintext, aad)
}

/// `wrap` with a given nonce: for test vectors only.
pub fn wrap_with(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let ct = gcm(key).encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad }).expect("AES-GCM encrypts");
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(V1);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn unwrap(key: &[u8; 32], wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
    if wrapped.len() < 1 + 12 + 16 || wrapped[0] != V1 {
        return Err(SealError::Malformed);
    }
    gcm(key).decrypt(Nonce::from_slice(&wrapped[1..13]), Payload { msg: &wrapped[13..], aad }).map_err(|_| SealError::Rejected)
}

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn code_of(d: &[u8]) -> String {
    let bits = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) >> 2; // the first 30 bits
    let c: Vec<char> = (0..6).map(|i| ALPHABET[((bits >> (25 - 5 * i)) & 31) as usize] as char).collect();
    format!("{}{}{}-{}{}{}", c[0], c[1], c[2], c[3], c[4], c[5])
}

/// What a machine commits to before it learns the browser's nonce: its keys and its own nonce,
/// revealed only after. Neither side can then steer the code (commit, then reveal).
pub fn pair_commit(x_pub: &[u8; 32], ed_pub: &[u8; 32], machine_nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [&b"use05 pair commit v1"[..], x_pub, ed_pub, machine_nonce] {
        h.update(part);
    }
    h.finalize().into()
}

/// The code a person compares at pairing, on the terminal and in the browser: over the team's key
/// and version, the machine's keys, and a nonce from each side. A server that swapped a key or
/// the version cannot make the two agree, and with the machine committed before the browser's
/// nonce is chosen, it cannot search for keys that would.
pub fn pairing_code(team_pub: &[u8; 32], team_version: u32, x_pub: &[u8; 32], ed_pub: &[u8; 32], machine_nonce: &[u8; 16], browser_nonce: &[u8; 16]) -> String {
    let mut h = Sha256::new();
    for part in [&b"use05 pair v2"[..], team_pub, &team_version.to_be_bytes(), x_pub, ed_pub, machine_nonce, browser_nonce] {
        h.update(part);
    }
    code_of(&h.finalize())
}

/// The word a machine shows at pairing, which only the person at its terminal can type: whoever
/// types it claims the machine, so nobody else on the team can pair (and own) it.
pub fn pairing_word() -> String {
    code_of(&rand::random::<[u8; 4]>())
}

/// A key the team and one machine share, which nobody else can make: X25519 between the team's
/// secret and the machine's public key, or the machine's secret and the team's public key. What
/// the team sends under it (the id key) is known to come from the team.
pub fn link_key(own_secret: &[u8; 32], peer_pub: &[u8; 32], team_pub: &[u8; 32], x_pub: &[u8; 32]) -> [u8; 32] {
    let shared = StaticSecret::from(*own_secret).diffie_hellman(&PublicKey::from(*peer_pub)).to_bytes();
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(team_pub);
    salt.extend_from_slice(x_pub);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &shared).expand(b"use05 link v1", &mut out).expect("32 bytes is a valid length");
    out
}

/// The team's id key, as the owner's browser sent it at pairing: wrapped under the key the team
/// shares with this machine, so the console cannot substitute one of its own.
pub fn open_id_key(x_secret: &[u8; 32], team_pub: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32], SealError> {
    let key = link_key(x_secret, team_pub, team_pub, &public_of(x_secret));
    unwrap(&key, wrapped, b"use05 id key")?.try_into().map_err(|_| SealError::Malformed)
}

/// A reference the server can route by but not read: HMAC of a name under the team's id key.
pub fn hmac_ref(id_key: &[u8; 32], what: &str, value: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(id_key).expect("any key length");
    m.update(what.as_bytes());
    m.update(&[0]);
    m.update(value.as_bytes());
    hex::encode(&m.finalize().into_bytes()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPIENT: [u8; 32] = [2; 32];

    #[test]
    fn sealed_opens_only_with_the_right_key_and_aad() {
        let public = public_of(&RECIPIENT);
        let sealed = seal(&public, b"hello 05", b"aad");
        assert_eq!(open(&RECIPIENT, &sealed, b"aad").unwrap(), b"hello 05");
        assert!(open(&[9; 32], &sealed, b"aad").is_err(), "another key");
        assert!(open(&RECIPIENT, &sealed, b"other").is_err(), "other aad");
        let mut bent = sealed.clone();
        *bent.last_mut().unwrap() ^= 1;
        assert!(open(&RECIPIENT, &bent, b"aad").is_err(), "tampered");
        assert!(open(&RECIPIENT, &sealed[..10], b"aad").is_err(), "short");
    }

    #[test]
    fn wrap_round_trips_and_detects_tampering() {
        let w = wrap(&[4; 32], b"team secret", b"v1");
        assert_eq!(unwrap(&[4; 32], &w, b"v1").unwrap(), b"team secret");
        let mut bent = w.clone();
        bent[20] ^= 1;
        assert!(unwrap(&[4; 32], &bent, b"v1").is_err());
        assert!(unwrap(&[5; 32], &w, b"v1").is_err());
    }

    #[test]
    fn pairing_code_covers_the_keys_the_version_and_both_nonces() {
        let code = pairing_code(&[6; 32], 1, &[7; 32], &[8; 32], &[10; 16], &[11; 16]);
        assert_eq!(code.len(), 7);
        assert_eq!(&code[3..4], "-");
        assert_eq!(code, pairing_code(&[6; 32], 1, &[7; 32], &[8; 32], &[10; 16], &[11; 16]));
        assert_ne!(code, pairing_code(&[6; 32], 1, &[7; 32], &[9; 32], &[10; 16], &[11; 16]), "another machine key");
        assert_ne!(code, pairing_code(&[6; 32], 2, &[7; 32], &[8; 32], &[10; 16], &[11; 16]), "another team version");
        assert_ne!(code, pairing_code(&[6; 32], 1, &[7; 32], &[8; 32], &[12; 16], &[11; 16]), "another machine nonce");
        assert_ne!(code, pairing_code(&[6; 32], 1, &[7; 32], &[8; 32], &[10; 16], &[12; 16]), "another browser nonce");
    }

    #[test]
    fn a_commitment_binds_the_keys_and_the_nonce() {
        let c = pair_commit(&[7; 32], &[8; 32], &[10; 16]);
        assert_eq!(c, pair_commit(&[7; 32], &[8; 32], &[10; 16]));
        assert_ne!(c, pair_commit(&[7; 32], &[9; 32], &[10; 16]));
        assert_ne!(c, pair_commit(&[7; 32], &[8; 32], &[11; 16]));
    }

    #[test]
    fn the_team_and_a_machine_reach_the_same_link_key() {
        let (team, machine) = ([20u8; 32], [21u8; 32]);
        let (team_pub, x_pub) = (public_of(&team), public_of(&machine));
        assert_eq!(link_key(&team, &x_pub, &team_pub, &x_pub), link_key(&machine, &team_pub, &team_pub, &x_pub));
        assert_ne!(link_key(&[22; 32], &x_pub, &public_of(&[22; 32]), &x_pub), link_key(&machine, &team_pub, &team_pub, &x_pub), "another team");
    }

    #[test]
    fn the_id_key_is_taken_only_from_the_team() {
        let (team, machine) = ([20u8; 32], [21u8; 32]);
        let (team_pub, x_pub) = (public_of(&team), public_of(&machine));
        let from_team = wrap(&link_key(&team, &x_pub, &team_pub, &x_pub), &[9; 32], b"use05 id key");
        assert_eq!(open_id_key(&machine, &team_pub, &from_team).unwrap(), [9; 32]);
        // Anyone with the machine's public key could seal it one; that is not the team's.
        assert!(open_id_key(&machine, &team_pub, &seal(&x_pub, &[8; 32], b"use05 id key")).is_err());
        let other = [22u8; 32];
        let from_other = wrap(&link_key(&other, &x_pub, &public_of(&other), &x_pub), &[8; 32], b"use05 id key");
        assert!(open_id_key(&machine, &team_pub, &from_other).is_err());
    }

    #[test]
    fn a_pairing_word_is_six_letters_from_the_alphabet() {
        let w = pairing_word();
        assert_eq!(w.len(), 7);
        assert!(w.chars().filter(|c| *c != '-').all(|c| ALPHABET.contains(&(c as u8))));
        assert_ne!(w, pairing_word());
    }

    /// Fixed inputs, written for the browser's test to read: the two implementations agree.
    #[test]
    fn writes_vectors() {
        let recipient_pub = public_of(&RECIPIENT);
        let v = serde_json::json!({
            "recipient_secret": hex::encode(RECIPIENT),
            "recipient_public": hex::encode(recipient_pub),
            "sealed": hex::encode(seal_with(&[1; 32], &[3; 12], &recipient_pub, b"hello 05", b"aad")),
            "wrap_key": hex::encode([4u8; 32]),
            "wrapped": hex::encode(wrap_with(&[4; 32], &[5; 12], b"team secret", b"v1")),
            "derived": hex::encode(derive(b"ikm", "use05 wrap v1")),
            "pairing_code": pairing_code(&[6; 32], 3, &[7; 32], &[8; 32], &[10; 16], &[11; 16]),
            "pair_commit": hex::encode(pair_commit(&[7; 32], &[8; 32], &[10; 16])),
            "link_team_secret": hex::encode([20u8; 32]),
            "link_machine_public": hex::encode(public_of(&[21; 32])),
            "link_key": hex::encode(link_key(&[21; 32], &public_of(&[20; 32]), &public_of(&[20; 32]), &public_of(&[21; 32]))),
            "hmac_ref": hmac_ref(&[9; 32], "repo", "github.com/acme/billing"),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors.json");
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            std::fs::write(&path, &text).unwrap();
        }
    }

    /// What the browser sealed (console-web/test/from-browser.json, made by its test) opens here.
    #[test]
    fn opens_what_the_browser_sealed() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../console-web/test/from-browser.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).expect("run the browser crypto test once to make it")).unwrap();
        let sealed = hex::decode(v["sealed"].as_str().unwrap()).unwrap();
        assert_eq!(open(&RECIPIENT, &sealed, b"from the browser").unwrap(), b"sealed in a browser");
    }
}

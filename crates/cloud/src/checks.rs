//! Small checks the helper makes on what it is told: where the console is, and what it offers to
//! have pinned. The console may be compromised; these keep it from talking a person into trusting
//! something else.

/// The scheme and host of a URL, refusing credentials in it (`user@host` hides the real host).
fn scheme_host(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let host = authority.rsplit_once(':').filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit())).map_or(authority, |(h, _)| h);
    Some((scheme, host))
}

/// The console is reached over https, or over plain http only on this machine (for trying it out).
pub fn console_url_ok(url: &str) -> bool {
    match scheme_host(url) {
        Some(("https", host)) => !host.is_empty(),
        Some(("http", host)) => host == "localhost" || host == "127.0.0.1",
        _ => false,
    }
}

/// A passkey the console offers to pin must be a passkey key made for the console's own site.
/// Returns the site it was made for.
pub fn offered_passkey(public: &str, console_url: &str) -> Result<String, &'static str> {
    let Ok(use05_receipt::PublicKey::Passkey(key)) = use05_receipt::parse_any_public_key(public) else {
        return Err("it is not a passkey key");
    };
    match scheme_host(console_url) {
        Some((_, host)) if host.eq_ignore_ascii_case(&key.rp_id) => Ok(key.rp_id),
        _ => Err("it belongs to another site"),
    }
}

/// Text from the console, as one plain line: no escape sequences that could redraw the terminal.
pub fn plain(text: &str, max: usize) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(max).collect()
}

/// Which field names what an instruction is for, for each kind that must come sealed.
fn sealed_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "file_approval" => Some("request"),
        "prepare_policy_edit" | "apply_policy_edit" => Some("edit"),
        "prepare_testing" | "file_testing" => Some("signoff"),
        "prepare_discard" | "discard" => Some("discard"),
        "ask_approval" => Some("ask"),
        _ => None,
    }
}

/// An instruction as this machine acts on it: what the team sealed to it decides, and the
/// console's routing must agree with it. The sealed part names the repository and the request or
/// edit it is for, so the console cannot replay it as another.
pub fn bind_instruction(kind: &str, routed: &serde_json::Value, opened: Option<serde_json::Value>) -> Result<serde_json::Value, String> {
    let Some(id_field) = sealed_kind(kind) else { return Ok(routed.clone()) };
    let Some(serde_json::Value::Object(inner)) = opened else { return Err(format!("a {kind} must come sealed to this machine")) };
    for field in [id_field, "repo"] {
        let said = inner.get(field).and_then(|v| v.as_str()).filter(|v| !v.is_empty()).ok_or_else(|| format!("the sealed part does not say which {field} it is for"))?;
        if routed[field].as_str() != Some(said) {
            return Err(format!("the console routed it as another {field}"));
        }
    }
    let mut out = routed.clone();
    if let Some(o) = out.as_object_mut() {
        o.remove("sealed");
        o.extend(inner);
    }
    Ok(out)
}

/// What a member's passkey signs so their machines seal to the team's new key (D86).
pub const TEAM_KEY: &str = "https://use05.dev/team-key/v0";

pub struct TeamKey {
    pub public: String,
    pub version: i64,
    /// The pinned passkey that signed it.
    pub by: String,
}

/// A new team key, taken only on the word of a passkey pinned on this machine, naming this
/// machine (by its signing key, which only it knows is its own), and newer than the key in use.
/// The console relays it and could not have made it.
pub fn team_key_change(envelope: &[u8], pinned: &[(String, use05_receipt::PasskeyKey)], machine: &str, current: i64) -> Result<TeamKey, String> {
    use base64::Engine;
    let (by, body) = pinned
        .iter()
        .find_map(|(name, key)| use05_receipt::verify_bytes_with(envelope, &use05_receipt::PublicKey::Passkey(key.clone())).ok().map(|b| (name.clone(), b)))
        .ok_or("no passkey pinned on this machine signed it (pin yours: use05 cloud enrol)")?;
    let statement: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "what was signed is not a statement")?;
    let what = &statement["predicate"];
    if statement["predicateType"] != TEAM_KEY {
        return Err("what was signed is not a team key".into());
    }
    if !what["machines"].as_array().is_some_and(|m| m.iter().any(|m| m == machine)) {
        return Err("it does not name this machine".into());
    }
    let version = what["version"].as_i64().filter(|v| *v > current).ok_or("it is not newer than the key in use")?;
    let public = what["team_pub"].as_str().filter(|k| base64::engine::general_purpose::STANDARD.decode(k).is_ok_and(|b| b.len() == 32)).ok_or("it is not a key")?;
    Ok(TeamKey { public: public.to_string(), version, by })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The P-256 generator point, uncompressed: a valid public key for tests.
    const POINT: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    fn passkey(rp: &str) -> String {
        let key = use05_receipt::PasskeyKey::from_sec1(rp, &hex::decode(POINT).unwrap()).unwrap();
        use05_receipt::passkey_public_text(&key).trim().to_string()
    }

    /// A member's passkey signing `predicate` as a team key statement, as a browser would.
    fn signed(sk: &p256::ecdsa::SigningKey, predicate: serde_json::Value) -> Vec<u8> {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::to_vec(&serde_json::json!({ "_type": "https://in-toto.io/Statement/v1", "subject": [], "predicateType": TEAM_KEY, "predicate": predicate })).unwrap();
        let mut auth = sha2::Sha256::digest(b"console.example").to_vec();
        auth.extend_from_slice(&[0x05, 0, 0, 0, 1]);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(use05_receipt::passkey_challenge(use05_receipt::PAYLOAD_TYPE, &body));
        let client = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://console.example"}}"#);
        let mut message = auth.clone();
        message.extend_from_slice(&sha2::Sha256::digest(client.as_bytes()));
        let sig: p256::ecdsa::Signature = sk.sign(&message);
        serde_json::to_vec(&serde_json::json!({ "payload": b64.encode(&body), "payloadType": use05_receipt::PAYLOAD_TYPE, "signatures": [{ "sig": b64.encode(sig.to_der().as_bytes()), "webauthn": { "authenticatorData": b64.encode(&auth), "clientDataJSON": b64.encode(client) } }] })).unwrap()
    }

    fn pinned(sk: &p256::ecdsa::SigningKey) -> Vec<(String, use05_receipt::PasskeyKey)> {
        vec![("iPhone".into(), use05_receipt::PasskeyKey::from_sec1("console.example", sk.verifying_key().to_encoded_point(false).as_bytes()).unwrap())]
    }

    const NEW_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

    #[test]
    fn a_new_team_key_is_taken_on_a_pinned_passkey_for_this_machine() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let envelope = signed(&sk, serde_json::json!({ "machines": ["m1", "m2"], "team_pub": NEW_KEY, "version": 2 }));
        let change = team_key_change(&envelope, &pinned(&sk), "m2", 1).unwrap();
        assert_eq!((change.public.as_str(), change.version, change.by.as_str()), (NEW_KEY, 2, "iPhone"));
    }

    #[test]
    fn a_new_team_key_is_refused_unless_all_holds() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let other = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let ok = serde_json::json!({ "machines": ["m1"], "team_pub": NEW_KEY, "version": 2 });
        // A passkey not pinned here, perhaps the console's own.
        assert!(team_key_change(&signed(&other, ok.clone()), &pinned(&sk), "m1", 1).is_err());
        assert!(team_key_change(&signed(&sk, ok.clone()), &[], "m1", 1).is_err());
        // Another machine's word, or an old key again.
        assert!(team_key_change(&signed(&sk, ok.clone()), &pinned(&sk), "m9", 1).is_err());
        assert!(team_key_change(&signed(&sk, ok), &pinned(&sk), "m1", 2).is_err());
        // Not a key.
        assert!(team_key_change(&signed(&sk, serde_json::json!({ "machines": ["m1"], "team_pub": "AAAA", "version": 2 })), &pinned(&sk), "m1", 1).is_err());
        // Changed after it was signed.
        let mut envelope: serde_json::Value = serde_json::from_slice(&signed(&sk, serde_json::json!({}))).unwrap();
        envelope["payload"] = serde_json::json!("e30=");
        assert!(team_key_change(&serde_json::to_vec(&envelope).unwrap(), &pinned(&sk), "m1", 1).is_err());
    }

    #[test]
    fn an_instruction_is_what_its_sealed_part_says() {
        let routed = serde_json::json!({ "request": "r1", "repo": "p1", "sealed": "…" });
        let bound = bind_instruction("file_approval", &routed, Some(serde_json::json!({ "request": "r1", "repo": "p1", "envelope": {} }))).unwrap();
        assert_eq!(bound["envelope"], serde_json::json!({}));
        assert!(bound.get("sealed").is_none());
        // The console routed it as another request, or to another repository.
        assert!(bind_instruction("file_approval", &serde_json::json!({ "request": "r2", "repo": "p1" }), Some(serde_json::json!({ "request": "r1", "repo": "p1", "envelope": {} }))).is_err());
        assert!(bind_instruction("file_approval", &serde_json::json!({ "request": "r1", "repo": "p2" }), Some(serde_json::json!({ "request": "r1", "repo": "p1", "envelope": {} }))).is_err());
        // A sealed part that does not say what it is for.
        assert!(bind_instruction("apply_policy_edit", &serde_json::json!({ "edit": "e1", "repo": "p1" }), Some(serde_json::json!({ "repo": "p1", "commit": "c" }))).is_err());
        // What must come sealed, unsealed.
        assert!(bind_instruction("prepare_policy_edit", &serde_json::json!({ "edit": "e1", "repo": "p1", "toml": "" }), None).is_err());
        // An ask for an approval must come sealed, naming the ask and the repository, with the task inside.
        let asked = bind_instruction("ask_approval", &serde_json::json!({ "ask": "a1", "repo": "p1" }), Some(serde_json::json!({ "ask": "a1", "repo": "p1", "task": "t1", "scope": "intent" }))).unwrap();
        assert_eq!(asked["task"], "t1");
        assert!(bind_instruction("ask_approval", &serde_json::json!({ "ask": "a1", "repo": "p1" }), None).is_err());
        assert!(bind_instruction("ask_approval", &serde_json::json!({ "ask": "a2", "repo": "p1" }), Some(serde_json::json!({ "ask": "a1", "repo": "p1", "task": "t1" }))).is_err());
        // What needs no seal passes as routed.
        assert_eq!(bind_instruction("send_tree", &serde_json::json!({ "repo": "p1" }), None).unwrap(), serde_json::json!({ "repo": "p1" }));
    }

    #[test]
    fn the_console_is_on_https_or_this_machine() {
        assert!(console_url_ok("https://console.example.com"));
        assert!(console_url_ok("http://localhost:8080"));
        assert!(console_url_ok("http://127.0.0.1:8080/"));
        assert!(!console_url_ok("http://localhost.evil.example"));
        assert!(!console_url_ok("http://localhost@evil.example"));
        assert!(!console_url_ok("http://console.example.com"));
        assert!(!console_url_ok("ftp://console.example.com"));
    }

    #[test]
    fn only_passkeys_of_the_consoles_own_site_are_offered() {
        assert!(offered_passkey(&passkey("console.example.com"), "https://console.example.com").is_ok());
        assert!(offered_passkey(&passkey("localhost"), "http://localhost:8080").is_ok());
        assert_eq!(offered_passkey(&passkey("evil.example"), "https://console.example.com").err(), Some("it belongs to another site"));
        assert_eq!(offered_passkey("not a key", "https://console.example.com").err(), Some("it is not a passkey key"));
    }

    #[test]
    fn what_the_console_says_is_printed_as_plain_text() {
        assert_eq!(plain("My \u{1b}[2Jphone\nKey", 40), "My  [2Jphone Key");
        assert_eq!(plain("abcdef", 3), "abc");
    }
}

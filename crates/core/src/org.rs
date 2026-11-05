//! The organisation layer: a policy floor, signed by the organisation.
//!
//! It is verified against a key pinned in the user's config directory (or CI), never against
//! anything inside the repository, so a repository cannot edit, swap or drop it. If a key is
//! pinned and the layer is missing or does not verify, that is an error, not a quiet fallback.

use std::collections::BTreeMap;
use std::fs;

use sha2::{Digest, Sha256};
use use05_receipt::{OrgLayer, SigningKey, Statement, Subject, VerifyingKey, parse_public_key, seal, verify_as};

use crate::error::{Error, Result};
use crate::keys::user_dir;
use crate::policy::Floor;
use crate::time::now_rfc3339;

pub fn sign(org: &str, floor: &Floor, key: &SigningKey) -> Vec<u8> {
    let value = serde_json::to_value(floor).expect("floor serialises");
    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), hex::encode(Sha256::digest(serde_json::to_vec(&value).expect("serialises"))));
    let statement = Statement::new(
        vec![Subject { name: "org".into(), digest }],
        OrgLayer { org: org.to_string(), floor: value, created: now_rfc3339() },
    );
    seal(&statement, key).to_json_bytes()
}

pub fn verify(bytes: &[u8], key: &VerifyingKey) -> Result<(String, Floor)> {
    let verified = verify_as::<OrgLayer>(bytes, key).map_err(|f| {
        Error::new("ORG_LAYER_UNAVAILABLE", format!("the organisation policy does not verify: {f}"))
    })?;
    let layer = verified.statement.predicate;
    let floor: Floor = serde_json::from_value(layer.floor)
        .map_err(|e| Error::new("ORG_LAYER_UNAVAILABLE", format!("the organisation policy is not readable: {e}")))?;
    // A floor signed by a 05 that did not check it: its owner rules must name only its own people.
    floor.validate().map_err(|e| Error::new("ORG_LAYER_UNAVAILABLE", format!("the organisation policy is not usable: {}", e.message)))?;
    Ok((layer.org, floor))
}

/// The organisation floor for this machine, if one is pinned.
pub fn load() -> Result<Option<(String, Floor)>> {
    // No home directory means no pinned key, so there is no layer to require.
    let Ok(dir) = user_dir() else { return Ok(None) };
    let pinned = dir.join("org.pub");
    let Ok(pub_text) = fs::read_to_string(&pinned) else { return Ok(None) };
    let key = parse_public_key(&pub_text).map_err(|e| Error::new("ORG_LAYER_UNAVAILABLE", format!("the pinned organisation key is unusable: {e}")))?;
    let layer = fs::read(dir.join("org.json")).map_err(|_| {
        Error::new("ORG_LAYER_UNAVAILABLE", "an organisation key is pinned but its policy is missing")
            .with_next("restore org.json in 05's config directory, or remove org.pub to stop requiring it")
    })?;
    verify(&layer, &key).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IntentMode, Severity};

    #[test]
    fn a_signed_layer_verifies_only_under_its_key_and_only_untampered() {
        let org = SigningKey::from_bytes(&[9; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let floor = Floor { intent_mode: Some(IntentMode::Risky), drift_scope: Some(Severity::Deny), ..Floor::default() };
        let bytes = sign("acme", &floor, &org);
        let (name, got) = verify(&bytes, &org.verifying_key()).unwrap();
        assert_eq!((name.as_str(), got), ("acme", floor.clone()));
        assert_eq!(verify(&bytes, &other.verifying_key()).unwrap_err().code, "ORG_LAYER_UNAVAILABLE");

        let text = String::from_utf8(bytes.clone()).unwrap();
        let tampered = text.replacen("\"payload\": \"", "\"payload\": \"AAAA", 1);
        assert!(verify(tampered.as_bytes(), &org.verifying_key()).is_err());
        assert!(verify(b"{}", &org.verifying_key()).is_err());
    }
}

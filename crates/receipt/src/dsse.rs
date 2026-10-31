//! DSSE envelope: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
//!
//! The signature covers PAE(payloadType, payload), where
//! `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::keys::key_id;

/// The only payload type 05 accepts.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Base64 of the exact bytes that were signed.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSignature {
    /// An unauthenticated hint. Never used to make a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    pub sig: String,
}

impl Envelope {
    /// Pretty JSON with a trailing newline. Verification does not depend on this formatting,
    /// only on the decoded payload bytes.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).expect("envelope serialises");
        out.push(b'\n');
        out
    }
}

/// Why a receipt did not verify. `Malformed` means it could not be read as a receipt at all;
/// `Invalid` means it was readable but does not check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    Malformed { code: &'static str, detail: String },
    Invalid { code: &'static str, detail: String },
}

impl Fault {
    pub(crate) fn malformed(code: &'static str, detail: impl Into<String>) -> Fault {
        Fault::Malformed { code, detail: detail.into() }
    }

    pub(crate) fn invalid(code: &'static str, detail: impl Into<String>) -> Fault {
        Fault::Invalid { code, detail: detail.into() }
    }

    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Fault::Malformed { code, .. } | Fault::Invalid { code, .. } => code,
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Fault::Malformed { detail, .. } | Fault::Invalid { detail, .. } => detail,
        }
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Fault::Malformed { .. })
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail())
    }
}

impl std::error::Error for Fault {}

/// A parser error without its "at line N column M" tail. The position depends on the exact bytes
/// and means nothing to a person reading the message.
pub(crate) fn without_position(error: &serde_json::Error) -> String {
    let text = error.to_string();
    match text.rfind(" at line ") {
        Some(cut) => text[..cut].to_string(),
        None => text,
    }
}

/// Pre-authentication encoding.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + body.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

pub(crate) fn sign(payload_type: &str, body: &[u8], key: &SigningKey) -> Envelope {
    let signature = key.sign(&pae(payload_type, body));
    Envelope {
        payload: STANDARD.encode(body),
        payload_type: payload_type.to_string(),
        signatures: vec![EnvelopeSignature {
            keyid: Some(key_id(&key.verifying_key())),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    }
}

/// DSSE verifiers must accept standard or URL-safe base64.
fn decode_b64(text: &str) -> Option<Vec<u8>> {
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok())
}

/// What a successful DSSE verification yields.
pub(crate) struct Opened {
    /// The exact payload bytes that were verified.
    pub payload: Vec<u8>,
    /// The key id hint carried by the signature that verified, if any.
    pub hint: Option<String>,
}

/// Verify the signature and the payload type.
pub(crate) fn verify(envelope_json: &[u8], key: &VerifyingKey) -> Result<Opened, Fault> {
    let envelope: Envelope = serde_json::from_slice(envelope_json).map_err(|e| {
        use serde_json::error::Category;
        match e.classify() {
            Category::Eof => Fault::malformed("RECEIPT_NOT_JSON", "the receipt ends too soon; it looks cut short"),
            Category::Syntax | Category::Io => Fault::malformed("RECEIPT_NOT_JSON", "the receipt is not valid JSON"),
            Category::Data => Fault::malformed(
                "RECEIPT_BAD_ENVELOPE",
                format!("not a DSSE envelope ({})", without_position(&e)),
            ),
        }
    })?;

    let body = decode_b64(&envelope.payload)
        .ok_or_else(|| Fault::malformed("RECEIPT_BAD_BASE64", "the payload is not valid base64"))?;

    if envelope.signatures.is_empty() {
        return Err(Fault::malformed("RECEIPT_NO_SIGNATURES", "the envelope carries no signature"));
    }

    let signed_input = pae(&envelope.payload_type, &body);
    let mut verified_hint: Option<Option<String>> = None;
    for entry in &envelope.signatures {
        let raw = decode_b64(&entry.sig)
            .ok_or_else(|| Fault::malformed("RECEIPT_BAD_BASE64", "a signature is not valid base64"))?;
        let signature = Signature::from_slice(&raw).map_err(|_| {
            Fault::malformed("RECEIPT_BAD_SIGNATURE", "a signature has the wrong length for Ed25519")
        })?;
        if verified_hint.is_none() && key.verify_strict(&signed_input, &signature).is_ok() {
            verified_hint = Some(entry.keyid.clone());
        }
    }
    let Some(hint) = verified_hint else {
        return Err(Fault::invalid(
            "SIGNATURE_MISMATCH",
            "the signature does not match this receipt and the key you supplied",
        ));
    };

    // Only trust the type after the signature covering it has been checked.
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(Fault::invalid(
            "PAYLOAD_TYPE_UNSUPPORTED",
            format!("signed payload type {:?} is not supported", envelope.payload_type),
        ));
    }
    Ok(Opened { payload: body, hint })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_published_example() {
        // From the DSSE protocol document.
        let out = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(out, b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
    }

    #[test]
    fn pae_uses_byte_lengths_not_character_counts() {
        let out = pae("t", "é".as_bytes());
        assert_eq!(out, "DSSEv1 1 t 2 é".as_bytes());
    }
}

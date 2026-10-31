use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const SECRET_PREFIX: &str = "use05-ed25519-secret:";
const PUBLIC_PREFIX: &str = "use05-ed25519-public:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The text does not start with the expected prefix.
    WrongKind(&'static str),
    BadEncoding,
    BadLength,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::WrongKind(want) => write!(f, "not a {want} key file"),
            KeyError::BadEncoding => write!(f, "key is not valid base64"),
            KeyError::BadLength => write!(f, "key has the wrong length"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Short, stable identifier for a public key: the first 8 bytes of its SHA-256, in hex.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(key.as_bytes())[..8])
}

pub fn secret_key_text(key: &SigningKey) -> String {
    format!("{SECRET_PREFIX}{}\n", STANDARD.encode(key.to_bytes()))
}

pub fn public_key_text(key: &VerifyingKey) -> String {
    format!("{PUBLIC_PREFIX}{}\n", STANDARD.encode(key.as_bytes()))
}

fn decode32(text: &str, prefix: &str, kind: &'static str) -> Result<[u8; 32], KeyError> {
    let rest = text.trim().strip_prefix(prefix).ok_or(KeyError::WrongKind(kind))?;
    let bytes = STANDARD.decode(rest.trim()).map_err(|_| KeyError::BadEncoding)?;
    bytes.try_into().map_err(|_| KeyError::BadLength)
}

pub fn parse_secret_key(text: &str) -> Result<SigningKey, KeyError> {
    Ok(SigningKey::from_bytes(&decode32(text, SECRET_PREFIX, "secret")?))
}

pub fn parse_public_key(text: &str) -> Result<VerifyingKey, KeyError> {
    let bytes = decode32(text, PUBLIC_PREFIX, "public")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::BadEncoding)
}

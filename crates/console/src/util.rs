use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// An API error: a status and one plain sentence.
#[derive(Debug)]
pub struct Fail(pub StatusCode, pub String);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for Fail {
    fn from(e: sqlx::Error) -> Fail {
        tracing::error!("database: {e}");
        Fail(StatusCode::INTERNAL_SERVER_ERROR, "the console's database did not answer".into())
    }
}

pub fn bad(message: impl Into<String>) -> Fail {
    Fail(StatusCode::BAD_REQUEST, message.into())
}

pub fn denied(message: impl Into<String>) -> Fail {
    Fail(StatusCode::UNAUTHORIZED, message.into())
}

pub fn missing(message: impl Into<String>) -> Fail {
    Fail(StatusCode::NOT_FOUND, message.into())
}

pub fn forbidden(message: impl Into<String>) -> Fail {
    Fail(StatusCode::FORBIDDEN, message.into())
}

pub fn too_many(message: impl Into<String>) -> Fail {
    Fail(StatusCode::TOO_MANY_REQUESTS, message.into())
}

pub type Res<T = Value> = Result<Json<T>, Fail>;

pub fn ok() -> Res {
    Ok(Json(json!({ "ok": true })))
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(32))
}

pub fn hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compare secrets without leaking where they differ.
pub fn same_secret(a: &str, b: &str) -> bool {
    let (x, y) = (Sha256::digest(a.as_bytes()), Sha256::digest(b.as_bytes()));
    x.iter().zip(y.iter()).fold(0u8, |acc, (p, q)| acc | (p ^ q)) == 0
}


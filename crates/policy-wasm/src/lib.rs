//! The policy editor's checks in the browser (D86): the console never sees a team's policy, so the
//! web app previews an edit itself, with the same Rust the helper runs again before it commits.
//! Strings in, JSON strings out.

use serde_json::{Value, json};
use use05_policy_edit::edit::{self, Change};
use wasm_bindgen::prelude::*;

/// What an edit would write and change, and what in it a browser may not do.
#[wasm_bindgen]
pub fn preview(current: &str, changes: &str, detected: &str) -> String {
    let changes: Vec<Change> = match serde_json::from_str(changes) {
        Ok(c) => c,
        Err(e) => return json!({ "ok": false, "error": format!("changes: {e}") }).to_string(),
    };
    let detected: Vec<use05_core::policy::CheckDef> = serde_json::from_str(detected).unwrap_or_default();
    match edit::preview(current, &changes, &detected) {
        Ok(p) => json!({ "ok": true, "toml": p.toml, "policy": p.policy, "changed": p.changed, "terminal_only": p.terminal_only, "loosens": p.loosens }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
    .to_string()
}

/// A policy file, read.
#[wasm_bindgen]
pub fn view(text: &str) -> String {
    edit::view(text).to_string()
}

/// The changes that copy a template's editable settings into a repository's policy.
#[wasm_bindgen]
pub fn from_base(text: &str) -> String {
    match edit::from_base(text) {
        Ok(changes) => json!({ "ok": true, "changes": changes.iter().map(|c| json!({ "path": c.path, "value": c.value })).collect::<Vec<Value>>() }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
    .to_string()
}

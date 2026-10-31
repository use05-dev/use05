use std::path::Path;

use serde_json::json;
use use05_core::keys::user_dir;
use use05_core::org;
use use05_core::policy::{Floor, POLICY_PATH, Policy, explain};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

pub fn run(repo: &Path) -> Report {
    let ctx = match Ctx::open(repo, None) {
        Ok(c) => c,
        Err(e) => return Report::from_core("policy", e),
    };
    let rows = explain(&ctx.repo_policy, &ctx.policy);
    let mut out_rows: Vec<(String, String)> = Vec::new();
    for r in &rows {
        let value = if r.value.is_empty() { "none".to_string() } else { r.value.clone() };
        out_rows.push((r.key.to_string(), format!("{value}   [{}]", r.source.word())));
    }
    let working = ctx.top().join(POLICY_PATH);
    let mut notes = Vec::new();
    match Policy::load_file(&working) {
        Ok(Some(w)) if w != ctx.repo_policy => notes.push("The working .05/policy.toml differs from the committed one. A change is held to the rules at its base; edits take effect once committed (and editing .05/ needs approval).".to_string()),
        Ok(None) if !working.exists() => notes.push("No .05/policy.toml yet. These are the defaults. Run `use05 init` to create one.".to_string()),
        Err(e) => notes.push(format!("The working policy file does not parse: {e}")),
        _ => {}
    }
    Report {
        command: "policy",
        outcome: "shown",
        code: "POLICY",
        tone: Tone::Plain,
        headline: match &ctx.org {
            Some(o) => format!("Effective policy  (organisation: {o}; it can tighten, never loosen)"),
            None => "Effective policy  (no organisation layer)".to_string(),
        },
        rows: out_rows,
        notes,
        next: None,
        excerpt: vec![],
        details: json!({ "org": ctx.org, "policy": ctx.policy, "digest": ctx.policy.digest(), "sources": rows.iter().map(|r| json!({"key": r.key, "value": r.value, "source": r.source.word()})).collect::<Vec<_>>() }),
        exit: 0,
    }
}

/// Sign an organisation floor. The cloud app will do this; locally it is for testing and CI.
pub fn org_sign(floor_path: &Path, org_name: &str, key_path: &Path, out: &Path) -> Report {
    let fail = |code: &'static str, msg: String| Report::error("policy", code, msg, None, 6);
    let text = match std::fs::read_to_string(floor_path) {
        Ok(t) => t,
        Err(e) => return fail("FLOOR_UNREADABLE", format!("cannot read {}: {e}", floor_path.display())),
    };
    let floor: Floor = match toml::from_str(&text) {
        Ok(f) => f,
        Err(e) => return fail("FLOOR_INVALID", format!("the floor is not valid: {e}")),
    };
    let key = match use05_core::keys::read_secret_file(key_path) {
        Ok(k) => k,
        Err(e) => return Report::from_core("policy", e),
    };
    if let Err(e) = std::fs::write(out, org::sign(org_name, &floor, &key)) {
        return fail("IO_ERROR", format!("cannot write {}: {e}", out.display()));
    }
    let dir = user_dir().map(|d| d.display().to_string()).unwrap_or_else(|_| "05's config directory".into());
    Report {
        command: "policy",
        outcome: "signed",
        code: "ORG_SIGNED",
        tone: Tone::Good,
        headline: format!("Signed the organisation policy for {org_name}"),
        rows: vec![("written".into(), out.display().to_string())],
        notes: vec![],
        next: Some(format!("install it on a machine: copy it to {dir}/org.json and the public key to {dir}/org.pub")),
        excerpt: vec![],
        details: serde_json::Value::Null,
        exit: 0,
    }
}

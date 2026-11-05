use std::path::Path;

use serde_json::json;
use use05_core::keys::user_dir;
use use05_core::org;
use use05_core::policy::{Floor, POLICY_PATH, Policy, explain};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

/// One rule at a time (D88): change a single setting of this repository's policy file, keeping
/// everything else in the file as it was, and say what it was and becomes.
pub fn one_rule(repo: &Path, op: use05_policy_edit::edit::Op, setting: &str, value: &str) -> Report {
    let top = match use05_core::git::dirs(repo) {
        Ok(d) => d.top,
        Err(e) => return Report::from_core("policy", e),
    };
    let path = top.join(POLICY_PATH);
    let current = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Report::error("policy", "NO_POLICY", format!("this repository has no {POLICY_PATH}"), Some("use05 init".into()), 6),
    };
    let one = match use05_policy_edit::edit::one_rule(&current, op, setting, value) {
        Ok(o) => o,
        Err(e) => return Report::error("policy", "POLICY_INVALID", format!("{setting}: {e}"), Some("use05 policy   (shows every setting and its value)".into()), 6),
    };
    if let Err(e) = std::fs::write(&path, &one.preview.toml) {
        return Report::error("policy", "IO_ERROR", format!("cannot write {}: {e}", path.display()), None, 4);
    }
    let show = |v: &serde_json::Value| match v {
        serde_json::Value::Null => "(not set)".to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut notes = vec![format!("This changes {POLICY_PATH}, which 05 protects: commit it, and a person approves the change. It counts once merged, since a change is held to the rules at its base.")];
    if !one.preview.loosens.is_empty() {
        notes.insert(0, format!("This makes the rules less strict: {}. Only a terminal can do that; the console only tightens.", one.preview.loosens.join(", ")));
    }
    Report {
        command: "policy",
        outcome: "changed",
        code: "POLICY_CHANGED",
        tone: if one.preview.loosens.is_empty() { Tone::Good } else { Tone::Warn },
        headline: format!("Changed {setting}"),
        rows: vec![("before".into(), show(&one.before)), ("after".into(), show(&one.after))],
        notes,
        next: Some(format!("git add {POLICY_PATH} && git commit -m \"policy: {setting}\"")),
        excerpt: vec![],
        details: json!({ "setting": setting, "before": one.before, "after": one.after, "loosens": one.preview.loosens, "file": path }),
        exit: 0,
    }
}

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
    if let Err(e) = floor.validate() {
        return Report::error("policy", e.code, e.message, e.next, 6);
    }
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

/// `use05 policy --edit`: the guided setup's questions on the existing policy file.
pub fn edit(repo: &Path, interactive: bool, flags: &crate::cmd::setup::Flags) -> Report {
    use crate::cmd::setup::{AFTER_EDIT, Outcome, run_on};
    let store = match use05_core::task::Store::open(repo) {
        Ok(s) => s,
        Err(e) => return Report::from_core("policy", e),
    };
    let top = store.dirs.top.clone();
    let path = top.join(POLICY_PATH);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Report::error("policy", "NO_POLICY", format!("there is no {POLICY_PATH} here yet"), Some("use05 init   sets up this repository, with the same questions".into()), 6);
    };
    if !interactive && !flags.any() {
        return Report::error("policy", "NOT_INTERACTIVE", "use05 policy --edit asks its questions on a terminal".into(), Some("run it in a terminal, add --guided to answer on stdin, or pass --team, --target and --env".into()), 6);
    }
    match run_on(&text, &top, true, interactive, flags) {
        Err(e) => Report::error("policy", "POLICY_INVALID", format!("{POLICY_PATH}: {e}"), None, 3),
        Ok((Outcome::Stopped, _)) => Report::error("policy", "SETUP_STOPPED", "Stopped; nothing was changed.".into(), None, 1),
        Ok((Outcome::NoAnswer, _)) => Report::error("policy", "POLICY_NO_ANSWER", crate::prompt::no_answer_message(), Some("use05 policy set <setting> <value>   changes one setting and asks nothing".into()), 1),
        Ok((Outcome::Unchanged, notes)) => Report { command: "policy", outcome: "unchanged", code: "POLICY_UNCHANGED", tone: Tone::Plain, headline: format!("No change to {POLICY_PATH}"), rows: vec![], notes, next: None, excerpt: vec![], details: json!({ "changed": false }), exit: 0 },
        Ok((Outcome::Written(new), notes)) => match std::fs::write(&path, &new) {
            Err(e) => Report::error("policy", "IO_ERROR", format!("cannot write {POLICY_PATH}: {e}"), None, 4),
            Ok(()) => Report {
                command: "policy",
                outcome: "updated",
                code: "POLICY_UPDATED",
                tone: Tone::Good,
                headline: format!("Updated {POLICY_PATH}"),
                rows: vec![],
                notes: notes.into_iter().chain([AFTER_EDIT.to_string()]).collect(),
                next: Some("git diff .05/policy.toml   to see exactly what changed".into()),
                excerpt: vec![],
                details: json!({ "changed": true }),
                exit: 0,
            },
        },
    }
}

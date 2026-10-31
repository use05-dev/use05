use std::path::{Path, PathBuf};

use serde_json::json;
use use05_core::policy::Role;
use use05_core::store;
use use05_receipt::{AnyStatement, Fault, Status, VerifyingKey, key_id, parse_public_key, verify_any};
use use05_runner::identify;

use crate::ctx::Ctx;
use crate::report::{Report, Tone, command_text, duration};

pub struct Args {
    pub receipt: String,
    pub key: Option<PathBuf>,
    pub tree: Option<String>,
    pub repo: PathBuf,
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(12)]
}

fn load_public(path: &Path) -> Result<VerifyingKey, Report> {
    let text = std::fs::read_to_string(path).map_err(|e| Report::error("verify", "KEY_UNUSABLE", format!("cannot read the key file {}: {e}", path.display()), None, 6))?;
    parse_public_key(&text).map_err(|e| {
        if text.trim_start().starts_with("use05-ed25519-secret") {
            Report::error("verify", "KEY_IS_SECRET", format!("{} is a secret key; verification needs the public key", path.display()), Some(format!("use {}.pub", path.display())), 6)
        } else {
            Report::error("verify", "KEY_UNUSABLE", format!("cannot use the key file {}: {e}", path.display()), None, 6)
        }
    })
}

fn fault_report(receipt: &str, fault: Fault) -> Report {
    let (outcome, exit, label) = if fault.is_malformed() { ("malformed", 6, "Malformed") } else { ("invalid", 2, "Invalid") };
    let code = fault.code();
    let mut report = Report::error("verify", code, format!("{label}: {fault}"), None, exit);
    report.outcome = outcome;
    report.rows = vec![("receipt".into(), receipt.to_string())];
    report.next = Some(match (fault.is_malformed(), code) {
        (true, _) => "check you passed the receipt file or ref, and that it was not cut short".into(),
        (false, "SIGNATURE_MISMATCH") => "do not trust this receipt; ask for a fresh one, and check you are using the right public key".into(),
        _ => "do not trust this receipt".into(),
    });
    report.details = json!({ "receipt": receipt, "reason": fault.detail() });
    report
}

pub fn run(args: Args) -> Report {
    // Keys to try: the one given, or every key the policy and this machine trust.
    let ctx = Ctx::open(&args.repo, None).ok();
    let candidates: Vec<(String, Option<Role>, VerifyingKey)> = match &args.key {
        Some(path) => match load_public(path) {
            Ok(k) => vec![("the key you supplied".to_string(), None, k)],
            Err(r) => return r,
        },
        None => match &ctx {
            Some(c) if !c.trust.keys.is_empty() => c.trust.keys.iter().map(|k| (k.name.clone(), Some(k.role), k.key)).collect(),
            _ => {
                return Report::error(
                    "verify",
                    "NO_KEY",
                    "there is no key to verify against".to_string(),
                    Some("pass --key <public key>, or add trusted keys to .05/policy.toml".to_string()),
                    6,
                );
            }
        },
    };

    let top = ctx.as_ref().map(|c| c.top().to_path_buf()).unwrap_or_else(|| args.repo.clone());
    let bytes = match store::read(&top, &args.receipt) {
        Ok(b) => b,
        Err(e) => return Report::from_core("verify", e),
    };

    let mut last_fault = None;
    let mut verified = None;
    for (name, role, key) in &candidates {
        match verify_any(&bytes, key) {
            Ok(v) => {
                verified = Some((name.clone(), *role, v));
                break;
            }
            Err(f) => {
                // Prefer a structural complaint over "wrong key" when trying many keys.
                if last_fault.as_ref().is_none_or(|l: &Fault| !l.is_malformed()) {
                    last_fault = Some(f);
                }
            }
        }
    }
    let Some((signer_name, role, verified)) = verified else {
        return fault_report(&args.receipt, last_fault.expect("at least one key was tried"));
    };

    let signer = {
        let id = &verified.key_id[..12];
        match role {
            Some(Role::Runner) => format!("{} ({id}, runner: authoritative)", signer_name),
            Some(Role::Local) => format!("{} ({id}, advisory)", signer_name),
            Some(Role::Approver) => format!("{} ({id}, approver)", signer_name),
            None => format!("key {id} ({signer_name})"),
        }
    };
    let mut notes = Vec::new();
    if verified.hint_mismatch {
        notes.push("The receipt names a different key id. The signature still verified against yours; the hint is never trusted.".to_string());
    }

    let evidence = match &verified.statement {
        AnyStatement::Evidence(s) => s,
        AnyStatement::Approval(s) => {
            let p = &s.predicate;
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Good,
                headline: format!("Valid: a {:?} {:?} approval", p.decision, p.scope).to_lowercase(),
                rows: vec![("signed".into(), signer), ("approver".into(), p.approver.clone()), ("rationale".into(), p.rationale.clone()), ("expires".into(), p.expires.clone())],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "approval", "approver": p.approver, "scope": p.scope, "decision": p.decision, "expires": p.expires }),
                exit: 0,
            };
        }
        AnyStatement::Bypass(s) => {
            let p = &s.predicate;
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Warn,
                headline: "Valid: a break-glass bypass".to_string(),
                rows: vec![("signed".into(), signer), ("by".into(), p.by.clone()), ("reason".into(), p.reason.clone()), ("expires".into(), p.expires.clone())],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "bypass", "by": p.by, "reason": p.reason, "expires": p.expires }),
                exit: 0,
            };
        }
        AnyStatement::Declaration(s) => {
            let p = &s.predicate;
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Good,
                headline: format!("Valid: a declaration by {}", p.author),
                rows: vec![("signed".into(), signer), ("task".into(), format!("{}  {}", p.task, p.title)), ("sealed".into(), p.sealed.clone())],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "declaration", "task": p.task, "author": p.author, "sealed": p.sealed, "card": p.card }),
                exit: 0,
            };
        }
        AnyStatement::LogSeal(s) => {
            let p = &s.predicate;
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Good,
                headline: format!("Valid: a seal on the action log of task {}", p.task),
                rows: vec![("signed".into(), signer), ("sealed".into(), format!("{} line(s), ending {}", p.seq, p.head.chars().take(12).collect::<String>())), ("at".into(), p.created.clone())],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "log_seal", "task": p.task, "seq": p.seq, "head": p.head, "created": p.created }),
                exit: 0,
            };
        }
        AnyStatement::Completion(s) => {
            let p = &s.predicate;
            notes.push("The outcome is the author's statement, not a fact.".into());
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Good,
                headline: "Valid: a statement of what was done".to_string(),
                rows: vec![("signed".into(), signer), ("task".into(), p.task.clone()), ("said".into(), p.outcome.clone())],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "outcome", "task": p.task, "outcome": p.outcome, "finished": p.finished }),
                exit: 0,
            };
        }
        AnyStatement::OrgLayer(s) => {
            return Report {
                command: "verify",
                outcome: "valid",
                code: "VALID",
                tone: Tone::Good,
                headline: format!("Valid: an organisation policy for {}", s.predicate.org),
                rows: vec![("signed".into(), signer)],
                notes,
                next: None,
                excerpt: vec![],
                details: json!({ "kind": "org_layer", "org": s.predicate.org }),
                exit: 0,
            };
        }
    };

    let e = &evidence.predicate;
    let (receipt_oid, receipt_digest) = evidence.tree_subject().map(|(a, b)| (a.to_string(), b.to_string())).expect("checked by verify");
    let result_text = match (e.result.status, e.result.exit_code) {
        (Status::Passed, _) => format!("passed in {}", duration(e.result.duration_ms)),
        (Status::Failed, Some(c)) => format!("FAILED (exit {c}) in {}", duration(e.result.duration_ms)),
        (Status::Failed, None) => format!("FAILED in {}", duration(e.result.duration_ms)),
        (Status::TimedOut, _) => "TIMED OUT".to_string(),
    };
    let mut rows = vec![
        ("receipt".to_string(), args.receipt.clone()),
        ("signed".to_string(), signer),
        ("command".to_string(), command_text(&e.command.argv)),
        ("result".to_string(), result_text.clone()),
    ];

    let mut tree_detail = json!({ "checked": false, "oid": receipt_oid });
    match &args.tree {
        None => {
            rows.push(("tree".into(), format!("{}  (not checked)", short(&receipt_oid))));
            notes.push("Pass --tree <revision> to check the receipt against a tree.".to_string());
        }
        Some(spec) => {
            let current = match identify(&args.repo, spec) {
                Ok(c) => c,
                Err(err) => return Report::error("verify", err.code(), err.to_string(), None, 6),
            };
            if current.oid != receipt_oid {
                return Report {
                    command: "verify",
                    outcome: "stale",
                    code: "STALE",
                    tone: Tone::Warn,
                    headline: "Stale: the signature is good, but it is for a different tree".to_string(),
                    rows: vec![
                        ("receipt".into(), args.receipt.clone()),
                        ("covers".into(), short(&receipt_oid).to_string()),
                        ("you have".into(), format!("{}  ({spec})", short(&current.oid))),
                        ("result".into(), result_text),
                    ],
                    notes,
                    next: Some("use05 prove   to prove the tree you have".to_string()),
                    excerpt: vec![],
                    details: json!({ "tree": { "checked": true, "matches": false, "receipt_oid": receipt_oid, "current_oid": current.oid }, "key_id": verified.key_id }),
                    exit: 5,
                };
            }
            if current.sha256 != receipt_digest {
                let mut r = Report::error("verify", "TREE_DIGEST_MISMATCH", "Invalid: the tree id matches but its contents do not hash to what the receipt recorded".into(), Some("do not trust this receipt or this repository's objects".into()), 2);
                r.outcome = "invalid";
                return r;
            }
            rows.push(("tree".into(), format!("{}  matches {spec}", short(&receipt_oid))));
            tree_detail = json!({ "checked": true, "matches": true, "oid": receipt_oid });
        }
    }
    rows.push(("created".into(), format!("{}  (the signer's clock; not trusted)", e.created)));

    // A genuine receipt of a failed check is still a failure for `use05 verify ... && merge`.
    let passed = e.result.status == Status::Passed;
    Report {
        command: "verify",
        outcome: if passed { "valid" } else { "check_failed" },
        code: if passed { "VALID" } else { "CHECK_DID_NOT_PASS" },
        tone: if passed { Tone::Good } else { Tone::Bad },
        headline: if passed { "Valid: the signature checks out".into() } else { "Valid receipt, but the check it records did not pass".into() },
        rows,
        notes,
        next: None,
        excerpt: vec![],
        details: json!({
            "signature_valid": true,
            "key_id": verified.key_id,
            "tree": tree_detail,
            "command": e.command.argv,
            "check": e.check,
            "result": { "status": e.result.status, "exit_code": e.result.exit_code, "duration_ms": e.result.duration_ms },
            "created": e.created,
        }),
        exit: if passed { 0 } else { 2 },
    }
}

#[allow(dead_code)]
fn _id(k: &VerifyingKey) -> String {
    key_id(k)
}

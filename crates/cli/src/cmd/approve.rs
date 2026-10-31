use std::io::BufRead;
use std::path::PathBuf;

use serde_json::json;
use use05_core::gate::Effect;
use use05_core::keys;
use use05_core::store;
use use05_core::time::{now_rfc3339, now_secs, rfc3339};
use use05_core::{git, tty};
use use05_receipt::{Approval, ApprovalScope, Bypass, Decision, Statement, intent_subject, key_id, public_key_text, secret_key_text, seal, tree_subject};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

pub struct ApproveArgs {
    pub push: bool,
    pub intent: bool,
    pub reject: bool,
    pub reason: Option<String>,
    pub task: Option<String>,
    pub tree: Option<String>,
    pub passphrase_stdin: bool,
    pub repo: PathBuf,
}

pub struct BypassArgs {
    pub push: bool,
    pub reason: String,
    pub hours: u32,
    pub tree: Option<String>,
    pub passphrase_stdin: bool,
    pub repo: PathBuf,
}

/// The passphrase must come from a person: the terminal, or (for scripts that already know it)
/// the first line of stdin. Under an agent's shell there is neither, and that is the point.
fn passphrase(prompt: &str, from_stdin: bool, command: &'static str) -> Result<String, Report> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map_err(|e| Report::error(command, "IO_ERROR", format!("cannot read the passphrase: {e}"), None, 4))?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    tty::prompt_secret(prompt).map_err(|_| {
        Report::error(
            command,
            "NEEDS_A_PERSON",
            "this needs a person at a terminal to enter the approver passphrase".to_string(),
            Some("run it yourself in a terminal; an agent cannot approve its own work".to_string()),
            3,
        )
    })
}

fn approver_name(top: &std::path::Path) -> String {
    git::text(top, &["config", "user.name"]).ok().filter(|n| !n.is_empty()).unwrap_or_else(|| "approver".to_string())
}

/// Open the approver key, asking for the passphrase only if the key has one.
fn open_approver(from_stdin: bool, command: &'static str) -> Result<use05_receipt::SigningKey, Report> {
    if !keys::approver_exists() {
        return Err(Report::error(command, "NO_APPROVER_KEY", "there is no approver key on this machine".into(), Some("create one: use05 key new --approver".into()), 6));
    }
    let pass = if keys::approver_protected() { passphrase("Approver passphrase: ", from_stdin, command)? } else { String::new() };
    keys::load_approver(&pass).map_err(|e| Report::error(command, e.code, e.message, e.next, 2))
}

fn expiry(days: u32, hours: u32) -> String {
    rfc3339(now_secs() + days as u64 * 86_400 + hours as u64 * 3_600)
}

pub fn run_approve(args: ApproveArgs) -> Report {
    let ctx = match Ctx::open(&args.repo, args.task.as_deref()) {
        Ok(c) => c,
        Err(e) => return Report::from_core("approve", e),
    };
    let scope = if args.intent { ApprovalScope::Intent } else { ApprovalScope::Outcome };
    let vote = if args.reject { Decision::Reject } else { Decision::Approve };
    if vote == Decision::Reject && args.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
        return Report::error("approve", "REASON_REQUIRED", "say why you are rejecting it".into(), Some("use05 approve --reject --reason \"…\"".into()), 6);
    }
    if scope == ApprovalScope::Intent && vote == Decision::Reject {
        return Report::error("approve", "NOT_SUPPORTED", "an intent is approved or left unapproved; reject the outcome instead".into(), None, 6);
    }

    let target = match ctx.target(args.tree.as_deref()) {
        Ok(t) => t,
        Err(e) => return Report::from_core("approve", e),
    };
    let (subject, store_key, what) = match scope {
        ApprovalScope::Intent => {
            let Some(task) = &ctx.task else {
                return Report::error("approve", "NO_TASK", "there is no task whose intent could be approved".into(), Some("use05 start \"…\" --scope \"…\"".into()), 6);
            };
            let Some(digest) = &task.intent_sha256 else {
                return Report::error("approve", "NO_CARD", "this task has no intent card; there is nothing to approve".into(), Some("start it with --scope or --card".into()), 6);
            };
            (intent_subject(digest), digest.clone(), format!("the intent of \"{}\" (card {})", task.title, &digest[..12]))
        }
        ApprovalScope::Outcome => (tree_subject(&target.oid, &target.digest), target.oid.clone(), format!("the outcome on {} ({})", &target.oid[..12], target.label)),
    };

    // Show exactly what is being signed before asking for the secret.
    let gate = ctx.gate(&target).ok();
    eprintln!("You are about to {} {what}.", if vote == Decision::Approve { "approve" } else { "reject" });
    if let Some(g) = &gate {
        eprintln!("  {} file(s) changed, risk {}.", g.changed.len(), g.risk.word());
        for f in g.findings.iter().filter(|f| f.effect >= Effect::Warn).take(6) {
            eprintln!("  - {}: {}", f.code, f.message);
        }
    }
    eprintln!("  The approval is bound to this exact content and expires in {} days.", ctx.policy.approvals.expire_days);

    let key = match open_approver(args.passphrase_stdin, "approve") {
        Ok(k) => k,
        Err(r) => return r,
    };
    let signer_id = key_id(&key.verifying_key());
    let approver = approver_name(ctx.top());
    let statement = Statement::new(
        vec![subject],
        Approval {
            decision: vote,
            scope,
            task: ctx.task.as_ref().map(|t| t.id.clone()).unwrap_or_else(|| "-".into()),
            intent_sha256: ctx.task.as_ref().and_then(|t| t.intent_sha256.clone()).filter(|_| scope == ApprovalScope::Intent),
            policy_sha256: ctx.policy.digest(),
            rationale: args.reason.clone().unwrap_or_default().trim().to_string(),
            approver: approver.clone(),
            created: now_rfc3339(),
            expires: expiry(ctx.policy.approvals.expire_days, 0),
        },
    );
    let envelope = seal(&statement, &key).to_json_bytes();
    let branch = match store::put(ctx.top(), &store_key, &envelope, &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    if let Some(task) = &ctx.task {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "approval", "vote": vote, "scope": scope, "by": approver }));
    }

    let counts = ctx.trust.by_id(&signer_id).is_some_and(|k| k.role == use05_core::policy::Role::Approver);
    let mut notes = vec![format!("Signed by approver key {} and stored on branch {branch}.", &signer_id[..12])];
    notes.extend(super::push_note(ctx.top(), &branch, args.push));
    if !counts {
        notes.push("Warning: this key is not in the policy's trusted keys, so the gate will not count this approval. Add it under [[trust.key]] with role = \"approver\".".to_string());
    }
    Report {
        command: "approve",
        outcome: if vote == Decision::Approve { "approved" } else { "rejected" },
        code: if vote == Decision::Approve { "APPROVED" } else { "REJECTED" },
        tone: if vote == Decision::Approve { Tone::Good } else { Tone::Bad },
        headline: format!("{} {what}", if vote == Decision::Approve { "Approved" } else { "Rejected" }),
        rows: vec![("by".into(), approver), ("reason".into(), args.reason.unwrap_or_else(|| "(none given)".into())), ("expires".into(), expiry(ctx.policy.approvals.expire_days, 0))],
        notes,
        next: Some(format!("use05 brief   (share it: git push origin {branch})")),
        excerpt: vec![],
        details: json!({ "scope": scope, "vote": vote, "key_id": signer_id, "branch": branch, "counts": counts }),
        exit: 0,
    }
}

pub fn run_bypass(args: BypassArgs) -> Report {
    if args.reason.trim().is_empty() {
        return Report::error("bypass", "REASON_REQUIRED", "say why you are overriding the block".into(), None, 6);
    }
    if args.hours == 0 || args.hours > 72 {
        return Report::error("bypass", "HOURS_INVALID", "a bypass lasts between 1 and 72 hours".into(), None, 6);
    }
    let ctx = match Ctx::open(&args.repo, None) {
        Ok(c) => c,
        Err(e) => return Report::from_core("bypass", e),
    };
    let target = match ctx.target(args.tree.as_deref()) {
        Ok(t) => t,
        Err(e) => return Report::from_core("bypass", e),
    };
    let gate = match ctx.gate(&target) {
        Ok(g) => g,
        Err(e) => return Report::from_core("bypass", e),
    };
    let blocking: Vec<String> = gate.findings.iter().filter(|f| f.effect >= Effect::Wait).map(|f| f.code.to_string()).collect();
    if blocking.is_empty() {
        return Report::error("bypass", "NOTHING_TO_BYPASS", "nothing is blocking this tree".into(), Some("use05 brief".into()), 6);
    }
    eprintln!("You are about to override these blocks on {}: {}", &target.oid[..12], blocking.join(", "));
    eprintln!("  Reason: {}", args.reason.trim());
    eprintln!("  It covers this exact tree only, lasts {} hour(s), and is recorded in the audit trail and the brief.", args.hours);

    let key = match open_approver(args.passphrase_stdin, "bypass") {
        Ok(k) => k,
        Err(r) => return r,
    };
    let signer_id = key_id(&key.verifying_key());
    let by = approver_name(ctx.top());
    let statement = Statement::new(
        vec![tree_subject(&target.oid, &target.digest)],
        Bypass { reason: args.reason.trim().to_string(), by: by.clone(), findings: blocking.clone(), created: now_rfc3339(), expires: expiry(0, args.hours) },
    );
    let branch = match store::put(ctx.top(), &target.oid, &seal(&statement, &key).to_json_bytes(), &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("bypass", e),
    };
    if let Some(task) = &ctx.task {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "bypass", "by": by, "reason": args.reason.trim(), "overrode": blocking }));
    }
    Report {
        command: "bypass",
        outcome: "bypassed",
        code: "BYPASSED",
        tone: Tone::Warn,
        headline: format!("Break-glass: let {} through", &target.oid[..12]),
        rows: vec![("by".into(), by), ("reason".into(), args.reason.trim().to_string()), ("overrode".into(), blocking.join(", ")), ("lasts".into(), format!("{} hour(s), this exact tree only", args.hours))],
        notes: {
            let mut n = vec![format!("Recorded on branch {branch}. It shows in the brief, so reviewers can see it was used.")];
            n.extend(super::push_note(ctx.top(), &branch, args.push));
            n
        },
        next: Some("push now; the next change is held to the rules again".into()),
        excerpt: vec![],
        details: json!({ "branch": branch, "overrode": blocking, "expires_in_hours": args.hours }),
        exit: 0,
    }
}

pub fn key_new(path: Option<PathBuf>, approver: bool, passphrase_stdin: bool) -> Report {
    if approver {
        if keys::approver_exists() {
            return Report::error("key", "KEY_EXISTS", "an approver key already exists on this machine".into(), Some("use05 key show".into()), 6);
        }
        let first = match passphrase("New approver passphrase (empty for none): ", passphrase_stdin, "key") {
            Ok(p) => p,
            Err(r) => return r,
        };
        if !passphrase_stdin && !first.is_empty() {
            match passphrase("Again: ", false, "key") {
                Ok(again) if again == first => {}
                Ok(_) => return Report::error("key", "PASSPHRASE_MISMATCH", "the two passphrases differ; nothing was created".into(), None, 6),
                Err(r) => return r,
            }
        }
        let public = match keys::create_approver(&first) {
            Ok(p) => p,
            Err(e) => return Report::from_core("key", e),
        };
        let mut notes = vec!["To make others trust it, add to .05/policy.toml:".to_string(), format!("[[trust.key]]  name = \"you\"  role = \"approver\"  public = \"{}\"", public_key_text(&public).trim())];
        if first.is_empty() {
            notes.insert(0, "No passphrase: anyone who can read this file can approve as you. Prefer one.".to_string());
        }
        return Report {
            command: "key",
            outcome: "created",
            code: "KEY_CREATED",
            tone: if first.is_empty() { Tone::Warn } else { Tone::Good },
            headline: format!("Created your approver key {}", &key_id(&public)[..12]),
            rows: vec![("protected".into(), if first.is_empty() { "no".into() } else { "yes: it opens only with your passphrase".into() })],
            notes,
            next: Some("use05 approve".into()),
            excerpt: vec![],
            details: json!({ "key_id": key_id(&public), "protected": !first.is_empty() }),
            exit: 0,
        };
    }
    match path {
        // A plain key pair at PATH: for a CI runner key, whose secret goes in a CI secret.
        Some(path) => {
            let public_path = PathBuf::from(format!("{}.pub", path.display()));
            if path.exists() || public_path.exists() {
                return Report::error("key", "KEY_NOT_CREATED", format!("{} already exists; refusing to overwrite it", path.display()), None, 4);
            }
            let mut seed = [0u8; 32];
            use std::io::Read;
            if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)).is_err() {
                return Report::error("key", "KEY_NOT_CREATED", "no system randomness available".into(), None, 4);
            }
            let key = use05_receipt::SigningKey::from_bytes(&seed);
            use std::os::unix::fs::OpenOptionsExt;
            use std::io::Write;
            let written = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).and_then(|mut f| f.write_all(secret_key_text(&key).as_bytes()));
            if let Err(e) = written.and_then(|_| std::fs::write(&public_path, public_key_text(&key.verifying_key()))) {
                return Report::error("key", "KEY_NOT_CREATED", format!("could not write the key files: {e}"), None, 4);
            }
            let id = key_id(&key.verifying_key());
            Report {
                command: "key",
                outcome: "created",
                code: "KEY_CREATED",
                tone: Tone::Good,
                headline: format!("Created key {id}"),
                rows: vec![("secret".into(), format!("{}  (keep this private)", path.display())), ("public".into(), format!("{}  (share this)", public_path.display()))],
                notes: vec!["For CI: store the secret as USE05_RUNNER_KEY, then trust the public key with role = \"runner\" in .05/policy.toml.".into()],
                next: None,
                excerpt: vec![],
                details: json!({ "key_id": id }),
                exit: 0,
            }
        }
        None => match keys::ensure_local() {
            Ok((key, created)) => Report {
                command: "key",
                outcome: "ok",
                code: "KEY_LOCAL",
                tone: Tone::Good,
                headline: if created { "Created this machine's key".into() } else { "This machine's key already exists".into() },
                rows: vec![("key".into(), key_id(&key.verifying_key()))],
                notes: vec![],
                next: None,
                excerpt: vec![],
                details: json!({ "key_id": key_id(&key.verifying_key()), "created": created }),
                exit: 0,
            },
            Err(e) => Report::from_core("key", e),
        },
    }
}

pub fn key_show() -> Report {
    let mut rows = Vec::new();
    let mut details = json!({});
    if let Some(k) = keys::local_public() {
        rows.push(("machine".to_string(), format!("{}   (advisory)\n{}", key_id(&k), public_key_text(&k).trim())));
        details["local"] = json!(public_key_text(&k).trim());
    }
    if let Some(k) = keys::approver_public() {
        rows.push(("approver".to_string(), format!("{}   ({})\n{}", key_id(&k), if keys::approver_protected() { "passphrase-protected" } else { "NO passphrase" }, public_key_text(&k).trim())));
        details["approver"] = json!(public_key_text(&k).trim());
    }
    if rows.is_empty() {
        return Report::error("key", "NO_KEYS", "no keys on this machine yet".into(), Some("use05 init".into()), 6);
    }
    Report { command: "key", outcome: "ok", code: "KEYS", tone: Tone::Plain, headline: "Public keys on this machine".into(), rows, notes: vec![], next: None, excerpt: vec![], details, exit: 0 }
}

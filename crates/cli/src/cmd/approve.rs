use std::io::BufRead;
use std::path::PathBuf;

use serde_json::json;
use use05_core::gate::Effect;
use use05_core::keys;
use use05_core::{evidence, store};
use use05_core::time::{now_rfc3339, now_secs, rfc3339};
use use05_core::{git, tty};
use use05_receipt::{Approval, ApprovalScope, Bypass, Decision, Envelope, PAYLOAD_TYPE, Statement, cosignature, intent_subject, key_id, passkey_challenge, public_key_text, secret_key_text, seal, tree_subject};

use crate::ctx::Ctx;
use crate::report::{Report, Tone};

pub struct ApproveArgs {
    pub push: bool,
    /// Land the approved change straight away, without asking (D91).
    pub land: bool,
    /// Print the statement for a signer elsewhere (a passkey) instead of signing it here.
    pub unsigned: bool,
    /// File an approval a signer elsewhere already signed.
    pub signed: Option<PathBuf>,
    /// A testing sign-off (D87): tried it, with `note`; or skipped it, with `reason`.
    pub tested: bool,
    pub skip_testing: bool,
    pub note: Option<String>,
    /// With `unsigned`: the person the statement is for, when someone else signs it (CI).
    pub approver: Option<String>,
    pub intent: bool,
    /// Asked for the outcome by name: with no `--task`, only tasks whose result waits are offered.
    pub outcome: bool,
    pub reject: bool,
    pub reason: Option<String>,
    pub task: Option<String>,
    pub tree: Option<String>,
    /// With `tree`: the commit the change is measured from. A push approved at its own prompt
    /// passes what the remote already has, so the person sees what the push holds, as the gate does.
    pub base: Option<String>,
    /// The outcome of an exact revision that is not a task here, such as someone else's branch
    /// fetched from origin (D92): measured and judged as a push of it would be.
    pub rev: Option<String>,
    pub passphrase_stdin: bool,
    /// A person at a terminal, who may be asked which task: never under an agent, CI or a pipe.
    pub interactive: bool,
    /// A sign-off on promoting into this environment (D93), with `note`, `answers`, `confirms`.
    pub promote: Option<String>,
    /// Answers to the environment's sign-off questions, in order.
    pub answers: Vec<String>,
    /// The environment's `confirm` statements the person confirms, word for word.
    pub confirms: Vec<String>,
    /// With `promote`: a sign-off on merging the environment above back down into it.
    pub back: bool,
    /// With `promote`: a sign-off on landing the current hotfix task on it.
    pub hotfix: bool,
    pub repo: PathBuf,
}

pub struct BypassArgs {
    pub push: bool,
    pub reason: String,
    pub hours: u32,
    pub tree: Option<String>,
    pub passphrase_stdin: bool,
    /// One rule of promoting into this environment (D93), with `rule`.
    pub promote: Option<String>,
    pub rule: Option<String>,
    /// With `promote`: a rule of merging the environment above back down into it.
    pub back: bool,
    /// A person at a terminal: never under an agent, CI, a pipe or `--json`.
    pub interactive: bool,
    pub repo: PathBuf,
}

/// Positive proof that a person is here, for what only a person may do (D93): a terminal (stdin,
/// stderr and the controlling terminal) and no agent session. Without a terminal (CI, a pipe,
/// `--json`) it fails closed: an agent's session variable being absent proves nothing by itself.
pub(crate) fn person_here(command: &'static str, interactive: bool, what: &str) -> Result<(), Report> {
    if let Some((kind, _)) = use05_core::inbox::agent_session() {
        return Err(Report::error(command, "NEEDS_A_PERSON", format!("{what} is for a person, and this runs under an agent ({kind})"), Some("ask the person to run it in their own terminal".into()), 3));
    }
    if !interactive || !tty::has_tty() {
        return Err(Report::error(command, "NEEDS_A_PERSON", format!("{what} needs a person at a terminal, and there is none here (CI, a pipe, or --json)"), Some("run it yourself in a terminal".into()), 3));
    }
    Ok(())
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

pub(crate) fn approver_name(top: &std::path::Path) -> String {
    git::text(top, &["config", "user.name"]).ok().filter(|n| !n.is_empty()).unwrap_or_else(|| "approver".to_string())
}

/// Open the approver key, asking for the passphrase only if the key has one.
pub(crate) fn open_approver(from_stdin: bool, command: &'static str) -> Result<use05_receipt::SigningKey, Report> {
    if !keys::passphrase_approver_exists() {
        if keys::touch_id_public().is_some() {
            return Err(Report::error(command, "NEEDS_PASSPHRASE_KEY", "this needs the passphrase approver key; your Touch ID key cannot sign it".into(), Some("make one as well: use05 key new --approver --passphrase".into()), 6));
        }
        return Err(Report::error(command, "NO_APPROVER_KEY", "there is no approver key on this machine".into(), Some("create one: use05 key new --approver".into()), 6));
    }
    let pass = if keys::approver_protected() { passphrase("Approver passphrase: ", from_stdin, command)? } else { String::new() };
    keys::load_approver(&pass).map_err(|e| Report::error(command, e.code, e.message, e.next, 2))
}

/// A person's statement, signed: with the Touch ID key when this Mac has one (D91), else with the
/// passphrase key. Either way it needs a person at a terminal; under an agent there is none.
/// Returns the envelope and the id of the person's key that signed it.
pub(crate) fn sign_as_person<P: use05_receipt::Predicate>(statement: &Statement<P>, reason: &str, from_stdin: bool, command: &'static str) -> Result<(Envelope, String), Report> {
    if !from_stdin && crate::touchid::supported() {
        if let Some(key) = keys::touch_id_public() {
            if !tty::has_tty() {
                return Err(Report::error(command, "NEEDS_A_PERSON", "this needs a person at a terminal to confirm with Touch ID".into(), Some("run it yourself in a terminal; an agent cannot approve its own work".into()), 3));
            }
            let body = serde_json::to_vec(statement).expect("statement serialises");
            eprintln!("Confirm with {}.", crate::touchid::method());
            match crate::touchid::seal(&body, reason) {
                Ok(envelope) => return Ok((envelope, use05_receipt::PublicKey::Passkey(key).id())),
                Err(crate::touchid::Failure::Cancelled) => return Err(Report::error(command, "CANCELLED", "cancelled; nothing was signed".into(), None, 1)),
                // Over SSH, or a key from another Mac: the passphrase key, if there is one.
                Err(f) if keys::passphrase_approver_exists() => eprintln!("05: {}; using your passphrase key instead.", f.message()),
                Err(f) => return Err(Report::error(command, "TOUCH_ID_FAILED", f.message(), Some("make a passphrase key for these times: use05 key new --approver --passphrase".into()), 2)),
            }
        }
    }
    let key = open_approver(from_stdin, command)?;
    Ok((seal(statement, &key), key_id(&key.verifying_key())))
}

/// The id of the key [`sign_as_person`] will sign with: the Touch ID key where this Mac has one,
/// else the passphrase key. `None` when there is neither.
pub(crate) fn person_key_id() -> Option<String> {
    if crate::touchid::supported() {
        if let Some(key) = keys::touch_id_public() {
            return Some(use05_receipt::PublicKey::Passkey(key).id());
        }
    }
    keys::approver_public().filter(|_| keys::passphrase_approver_exists()).map(|k| key_id(&k))
}

pub(crate) fn expiry(days: u32, hours: u32) -> String {
    rfc3339(now_secs() + days as u64 * 86_400 + hours as u64 * 3_600)
}

/// Which task an approval is for, when `--task` did not say. Every task in this repository that
/// waits for a person is found; one is named and used, several are offered to a person at a
/// terminal, and under an agent, CI or a pipe several are an error that lists them. The task's own
/// checkout (or branch) is what gets approved, not whatever this directory happens to hold.
fn choose_task(args: &mut ApproveArgs) -> Result<(), Report> {
    use crate::pending::{self, Need};
    let survey = pending::survey(&args.repo, pending::MAX_TASKS).map_err(|e| Report::from_core("approve", e))?;
    let (plan_only, change_only) = (args.intent, args.outcome);
    let waiting: Vec<&pending::Entry> = survey.waiting().into_iter().filter(|e| e.needs().is_some_and(|n| (!plan_only || n == Need::Plan) && (!change_only || n == Need::Change))).collect();
    let now = now_secs();
    let ui = crate::ui::Ui::stderr();
    let chosen = match waiting.as_slice() {
        [] => return nothing_waits(args),
        [one] => {
            eprintln!("Approving \"{}\" (task {}, its {}): the only task waiting here.", one.task.title, one.task.id, one.needs().map_or("", Need::word));
            *one
        }
        many if args.interactive => {
            let rows = pending::list_rows(&ui, many, now, ui.width.saturating_sub(6), |e| e.needs().map_or(String::new(), |n| n.word().to_string()));
            let title = format!("{} tasks wait for you in {}. Which one?", many.len(), repo_name(&args.repo));
            match crate::pick::choose_here(&ui, Some(&title), &rows, "Quit, approve nothing") {
                Some(i) => {
                    eprintln!("Approving \"{}\" (task {}, its {}).", many[i].task.title, many[i].task.id, many[i].needs().map_or("", Need::word));
                    many[i]
                }
                None => return Err(Report::error("approve", "NOTHING_CHOSEN", "no task was chosen; nothing was approved".into(), None, 1)),
            }
        }
        many => {
            let listed: Vec<String> = many.iter().map(|e| format!("{} \"{}\" ({})", e.task.id, e.task.title, e.needs().map_or("", Need::word))).collect();
            let mut r = Report::error("approve", "TASK_AMBIGUOUS", format!("{} tasks wait for approval here, so say which: {}", many.len(), listed.join(", ")), Some("use05 approve --task <id>".into()), 6);
            r.details = json!({ "candidates": many.iter().map(|e| json!({ "task": e.task.id, "title": e.task.title, "needs": e.needs().map(Need::word), "agent": e.who(), "last_activity": rfc3339(e.activity) })).collect::<Vec<_>>() });
            return Err(r);
        }
    };
    args.task = Some(chosen.task.id.clone());
    if let Some(place) = &chosen.place {
        args.repo = place.dir.clone();
        args.tree = place.tree.clone();
    }
    // What the person was asked for is what they sign: a task whose plan waits gets its plan approved.
    args.intent = args.intent || chosen.needs() == Some(Need::Plan);
    Ok(())
}

fn repo_name(repo: &std::path::Path) -> String {
    git::dirs(repo).ok().and_then(|d| d.top.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| "this repository".into())
}

/// No task waits. A change nobody started a task for (a person's own, to a protected file) still
/// can be approved, as can an intent asked for by name or a statement prepared for someone else
/// to sign; anything else has nothing to approve.
fn nothing_waits(args: &ApproveArgs) -> Result<(), Report> {
    if args.intent || args.unsigned {
        return Ok(());
    }
    let asks = Ctx::open_judging(&args.repo, None).and_then(|ctx| ctx.target(args.tree.as_deref()).and_then(|t| ctx.gate(&t))).is_ok_and(|g| g.decision == use05_core::gate::Decision::ApprovalRequired);
    if asks {
        return Ok(());
    }
    Err(Report::error("approve", "NOTHING_WAITS", "nothing is waiting for your approval in this repository".into(), Some("use05   shows every task; approve a particular one with: use05 approve --task <id>".into()), 6))
}

/// `--task` names a task: approve its own work, wherever it is checked out.
fn locate_task(args: &mut ApproveArgs) {
    let (repo, tree) = crate::pending::locate(&args.repo, args.task.as_deref(), args.tree.as_deref());
    args.repo = repo;
    args.tree = tree;
}

pub fn run_approve(mut args: ApproveArgs) -> Report {
    // Where the person ran it: landing from there can also clean up the task's own checkout.
    let asked_from = args.repo.clone();
    if let Some(file) = &args.signed {
        let mut report = run_signed(file, args.push, &args.repo);
        // An approval from a phone lands the work when the policy lands on its own (D91).
        if report.code == "APPROVED" && report.details["counts"] == true && report.details["scope"] == "outcome" {
            if let Some(task) = report.details["task"].as_str().map(str::to_string) {
                land_after(&args.repo, &task, &mut report, args.land, false);
            }
        }
        return report;
    }
    // A sign-off on a promotion (D93): a statement of its own, bound to the environment, the
    // source commit and the policy.
    if let Some(env) = args.promote.clone() {
        return crate::cmd::signoff::run(args, &env);
    }
    // Someone else's work, named by its revision: no task here is chosen or touched.
    let (ctx, of_rev) = match &args.rev {
        Some(rev) => match Ctx::open_rev(&args.repo, rev) {
            Ok((ctx, target)) => (ctx, Some(target)),
            Err(e) => return Report::from_core("approve", e),
        },
        None => {
            if args.task.is_none() && args.tree.is_none() && !args.tested && !args.skip_testing {
                if let Err(r) = choose_task(&mut args) {
                    return r;
                }
            } else if args.tree.is_none() {
                locate_task(&mut args);
            }
            match Ctx::open_judging(&args.repo, args.task.as_deref()) {
                Ok(c) => (c, None),
                Err(e) => return Report::from_core("approve", e),
            }
        }
    };
    if args.tested || args.skip_testing {
        return run_testing(&ctx, args);
    }
    let scope = if args.intent { ApprovalScope::Intent } else { ApprovalScope::Outcome };
    let vote = if args.reject { Decision::Reject } else { Decision::Approve };
    if vote == Decision::Reject && args.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
        return Report::error("approve", "REASON_REQUIRED", "say why you are rejecting it".into(), Some("use05 approve --reject --reason \"…\"".into()), 6);
    }
    if scope == ApprovalScope::Intent && vote == Decision::Reject {
        return Report::error("approve", "NOT_SUPPORTED", "an intent is approved or left unapproved; reject the outcome instead".into(), None, 6);
    }

    let target = match (of_rev, &args.tree, &args.base) {
        (Some(t), _, _) => Ok(t),
        (None, Some(tree), Some(base)) => ctx.target_from(tree, Some(base)),
        _ => ctx.target(args.tree.as_deref()),
    };
    let target = match target {
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
    // A hotfix's outcome is approved for landing on its environment, and for nothing else; the
    // approval is what lands it there, past every rung below (D93).
    let hotfix = ctx.task.as_ref().and_then(|t| t.hotfix.clone()).filter(|_| scope == ApprovalScope::Outcome && args.rev.is_none());
    let what = match (&hotfix, vote) {
        (Some(env), Decision::Approve) => format!("{what}, a hotfix this approval lands straight on {env}"),
        _ => what,
    };

    // Show exactly what is being signed before asking for the secret.
    let gate = ctx.gate(&target).ok();
    eprintln!("You are about to {} {what}.", if vote == Decision::Approve { "approve" } else { "reject" });
    if let Some(env) = hotfix.as_deref().filter(|_| vote == Decision::Approve) {
        let branch = ctx.policy.environment_named(env).map_or(env, |e| e.branch.as_str());
        // The environment's sign-off asks for words of a person's own: said before anything is
        // signed, never as an approval that silently does not count.
        if let Some(e) = ctx.policy.environment_named(env) {
            let words = args.reason.as_deref().unwrap_or_default();
            if let Some(why) = use05_core::promote::words_void(words, e) {
                let min = e.sign_off.as_ref().map_or(0, |s| s.min_length);
                return Report::error("approve", "HOTFIX_WORDS_TOO_SHORT", format!("this approval lands a hotfix straight on {env}, whose sign-off asks for at least {min} characters of your own words of what you checked: {why}; nothing was signed"), Some(format!("use05 approve --outcome --reason \"<what you checked, at least {min} characters>\"")), 6);
            }
        }
        eprintln!("  This approval lands the hotfix straight on {env} (the {branch} branch), past the environments below it.");
    }
    // Someone else's work: the exact commit this binds, so it is the one the brief showed.
    if let Some(commit) = target.head_commit.as_deref().filter(|_| args.rev.is_some()) {
        eprintln!("  Commit {commit}.");
    }
    if let Some(g) = &gate {
        eprintln!("  {} file(s) changed, risk {}.", g.changed.len(), g.risk.word());
        for o in &g.owners {
            eprintln!("  Owned by {} ({}): {}.", o.named(), o.paths.join(", "), o.changed.join(", "));
        }
        for f in g.findings.iter().filter(|f| f.effect >= Effect::Warn).take(6) {
            eprintln!("  - {}: {}", f.code, f.message);
        }
    }
    eprintln!("  The approval is bound to this exact content and expires in {} days.", ctx.policy.approvals.expire_days);

    let approver = args.approver.clone().filter(|_| args.unsigned).unwrap_or_else(|| approver_name(ctx.top()));
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
            hotfix: hotfix.clone(),
        },
    );
    if args.unsigned {
        return unsigned(&statement, &store_key, &target.oid, &what);
    }
    let reason = format!("{} \"{}\"", if vote == Decision::Approve { "approve" } else { "reject" }, ctx.task.as_ref().map_or_else(|| target.oid[..12].to_string(), |t| t.title.clone()));
    let (envelope, signer_id) = match sign_as_person(&statement, &reason, args.passphrase_stdin, "approve") {
        Ok(signed) => signed,
        Err(r) => return r,
    };
    let envelope = envelope.to_json_bytes();
    let branch = match store::put(ctx.top(), &store_key, &envelope, &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    // Someone else's task is logged where it ran, not here.
    if let Some(task) = ctx.task.as_ref().filter(|_| args.rev.is_none()) {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "approval", "vote": vote, "scope": scope, "by": approver }));
    }
    // Which rules asked for this person, so a rule that is always approved can be pointed out (D91).
    if let Some(g) = &gate {
        use05_core::asked::record(&ctx.store.state_dir(), vote == Decision::Approve, &g.findings, now_secs());
    }

    let counts = ctx.trust.by_id(&signer_id).is_some_and(|k| k.role == use05_core::policy::Role::Approver);
    let mut notes = vec![format!("Signed by approver key {} and stored on branch {branch}.", &signer_id[..12])];
    notes.extend(super::push_note(ctx.top(), &branch, args.push));
    if !counts {
        notes.push("Warning: this key is not in the policy's trusted keys, so the gate will not count this approval. Add it under [[trust.key]] with role = \"approver\".".to_string());
    }
    let mut report = Report {
        command: "approve",
        outcome: if vote == Decision::Approve { "approved" } else { "rejected" },
        code: if vote == Decision::Approve { "APPROVED" } else { "REJECTED" },
        tone: if vote == Decision::Approve { Tone::Good } else { Tone::Bad },
        headline: format!("{} {what}", if vote == Decision::Approve { "Approved" } else { "Rejected" }),
        rows: vec![("by".into(), approver), ("reason".into(), args.reason.clone().unwrap_or_else(|| "(none given)".into())), ("expires".into(), expiry(ctx.policy.approvals.expire_days, 0))],
        notes,
        next: Some(format!("use05 brief   (share it: git push origin {branch})")),
        excerpt: vec![],
        details: json!({ "scope": scope, "vote": vote, "key_id": signer_id, "branch": branch, "counts": counts }),
        exit: 0,
    };
    if vote == Decision::Approve && scope == ApprovalScope::Outcome && counts && args.rev.is_none() {
        if let Some(task) = ctx.task.as_ref().map(|t| t.id.clone()) {
            land_after(&asked_from, &task, &mut report, args.land, args.interactive);
        }
    }
    if args.rev.is_some() && vote == Decision::Approve {
        owner_notes(&ctx, &target, &mut report);
    }
    report
}

/// After an approval by revision: which owned paths it now counts for (D92), read back from the
/// gate with the approval filed.
fn owner_notes(ctx: &Ctx, target: &crate::ctx::Target, report: &mut Report) {
    let Ok(gate) = ctx.gate(target) else { return };
    if gate.owners.is_empty() {
        return;
    }
    let key = report.details["key_id"].as_str().unwrap_or_default().to_string();
    let me = ctx.trust.person_of(&key);
    let mine: Vec<&use05_core::gate::OwnerStatus> = gate.owners.iter().filter(|o| me.as_deref().is_some_and(|m| o.approved_by.iter().any(|p| use05_core::policy::same_person(p, m)))).collect();
    let owned: Vec<String> = mine.iter().map(|o| o.paths.join(", ")).collect();
    if owned.is_empty() {
        let commit = target.head_commit.as_deref().map_or(target.oid.as_str(), |c| &c[..12.min(c.len())]);
        report.notes.push(format!("It does not count as an owner's approval for any path this change touches; use05 brief --rev {commit} says why."));
    } else {
        report.notes.push(format!("It counts as an owner's approval for {}.", owned.join("; ")));
    }
    report.details["owner_of"] = json!(owned);
}

/// Approving is the last thing a person does (D91): once the gate allows the task's work, it
/// lands, when the policy lands on its own, `--land` said so, or the person says yes at the
/// terminal; then it is pushed the same way. Otherwise the next step says how to land it.
fn land_after(repo: &std::path::Path, task: &str, report: &mut Report, flag: bool, interactive: bool) {
    use crate::cmd::land::{self, Then};
    use use05_core::policy::LandMode;
    // Opened again, so the approval just filed is part of what the gate reads.
    let Ok(ctx) = Ctx::open_judging(repo, Some(task)) else { return };
    let Some(current) = ctx.task.clone().filter(|t| t.id == task) else { return };
    let Some((_, target, _)) = land::ready(&ctx, &current) else { return };
    let then = Then::choose(ctx.policy.branches.land == LandMode::Auto, flag, interactive);
    if !then.settle(&format!("Land \"{}\" on {target} now?", current.title)) {
        report.next = Some(format!("use05 land --task {task}   it is allowed now"));
        return;
    }
    let mut landed = land::land_task(&ctx, current);
    land::push_after(&ctx, &mut landed, Then::choose(ctx.policy.branches.push == LandMode::Auto, false, interactive), !interactive);
    report.rows.extend(landed.rows);
    report.notes.extend(landed.notes);
    report.next = landed.next;
    report.details["landed"] = json!(landed.code == "LANDED");
    if landed.code == "LANDED" {
        report.headline = format!("{}, and landed it on {target}", report.headline);
    } else {
        report.notes.push(format!("It did not land: {}", landed.headline));
    }
}

/// The exact statement `approve` would sign, for a signer elsewhere: the bytes, the WebAuthn
/// challenge a passkey signs for them, and this machine's co-signature, which the signer puts in
/// the envelope beside its own (D86). Nothing is stored, except this machine's key the first time.
fn unsigned(statement: &Statement<Approval>, subject: &str, tree: &str, what: &str) -> Report {
    let body = serde_json::to_vec(statement).expect("statement serialises");
    let a = &statement.predicate;
    let verb = if a.decision == Decision::Approve { "approve" } else { "reject" };
    let mut r = unsigned_body(&body, subject, tree, &format!("{verb} {what}"), json!({ "scope": a.scope, "vote": a.decision, "task": a.task, "expires": a.expires }));
    r.rows = vec![("expires".into(), a.expires.clone())];
    r
}

/// Any person's statement, for a signer elsewhere: the bytes, the WebAuthn challenge, and this
/// machine's co-signature. `extra` adds what kind of statement it is to the details.
pub(crate) fn unsigned_body(body: &[u8], subject: &str, tree: &str, what: &str, extra: serde_json::Value) -> Report {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    // In CI the runner key co-signs: the key the policy already trusts there (D86).
    let runner = std::env::var("USE05_RUNNER_KEY").ok().and_then(|k| use05_receipt::parse_secret_key(&k).ok());
    let local = if runner.is_some() { None } else { use05_core::keys::ensure_local().ok() };
    let machine = runner.as_ref().or(local.as_ref().map(|(key, _)| key)).map(|key| cosignature(PAYLOAD_TYPE, body, key));
    let mut notes = vec!["The statement was not stored. Have it signed elsewhere, then file it here.".to_string()];
    if let Some((key, true)) = &local {
        notes.push(format!("This machine had no key of its own, so one was made to co-sign it ({}); list it in the policy for CI to trust what it prepares.", key_id(&key.verifying_key())));
    }
    if runner.is_some() {
        notes.push("Co-signed with the CI runner key.".into());
    }
    if machine.is_none() {
        notes.push("This machine's key could not be read, so it did not co-sign: a passkey's signature on this will not count.".into());
    }
    let mut details = json!({
        "payload_type": PAYLOAD_TYPE,
        "payload": STANDARD.encode(body),
        "challenge": URL_SAFE_NO_PAD.encode(passkey_challenge(PAYLOAD_TYPE, body)),
        "subject": subject,
        "tree": tree,
        "cosignature": machine,
    });
    if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    Report {
        command: "approve",
        outcome: "unsigned",
        code: "UNSIGNED",
        tone: Tone::Info,
        headline: format!("Ready to {what}, not signed"),
        rows: vec![],
        notes,
        next: Some("use05 approve --signed <file>".into()),
        excerpt: vec![],
        details,
        exit: 0,
    }
}

/// The longest testing note: a few sentences, not a report.
const NOTE_MAX: usize = 500;

/// A person's word that they tried this exact tree themselves, or skipped it (D87). Signed with
/// the approver key, as an approval is, so an agent cannot make one; never an approval.
fn run_testing(ctx: &Ctx, args: ApproveArgs) -> Report {
    use use05_core::policy::LocalTesting;
    use use05_receipt::{Tested, Testing};
    let (outcome, text, flag) = if args.tested { (Tested::Tested, args.note.clone(), "--note") } else { (Tested::Skipped, args.reason.clone(), "--reason") };
    let note = text.unwrap_or_default().trim().to_string();
    if note.is_empty() {
        let next = if args.tested { "use05 approve --tested --note \"<what you tried>\"" } else { "use05 approve --skip-testing --reason \"<why>\"" };
        return Report::error("approve", "NOTE_REQUIRED", format!("say {} in {flag}", if args.tested { "what you tried" } else { "why you skip it" }), Some(next.into()), 6);
    }
    if note.chars().count() > NOTE_MAX {
        return Report::error("approve", "NOTE_TOO_LONG", format!("keep it under {NOTE_MAX} characters: a few sentences"), None, 6);
    }
    if outcome == Tested::Skipped && ctx.policy.testing.local == LocalTesting::Required {
        return Report::error("approve", "TESTING_NOT_SKIPPABLE", "the policy requires testing, so a skip would not count; nothing was signed".into(), Some("use05 approve --tested --note \"<what you tried>\"".into()), 2);
    }
    let target = match ctx.target(args.tree.as_deref()) {
        Ok(t) => t,
        Err(e) => return Report::from_core("approve", e),
    };
    let tester = args.approver.clone().filter(|_| args.unsigned).unwrap_or_else(|| approver_name(ctx.top()));
    let statement = Statement::new(
        vec![tree_subject(&target.oid, &target.digest)],
        Testing { outcome, task: ctx.task.as_ref().map(|t| t.id.clone()).unwrap_or_else(|| "-".into()), note: note.clone(), tester: tester.clone(), created: now_rfc3339() },
    );
    let what = format!("{} on {} ({})", if outcome == Tested::Tested { "tried it" } else { "skipped testing" }, &target.oid[..12], target.label);
    if args.unsigned {
        let body = serde_json::to_vec(&statement).expect("statement serialises");
        return unsigned_body(&body, &target.oid, &target.oid, &format!("sign that you {what}"), json!({ "kind": "testing", "outcome": outcome, "note": note, "task": statement.predicate.task }));
    }
    eprintln!("You are about to sign that you {what}: \"{note}\".");
    let (envelope, signer_id) = match sign_as_person(&statement, &format!("sign that you {what}"), args.passphrase_stdin, "approve") {
        Ok(signed) => signed,
        Err(r) => return r,
    };
    let envelope = envelope.to_json_bytes();
    let branch = match store::put(ctx.top(), &target.oid, &envelope, &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    filed_testing(ctx, &statement.predicate, &target.oid, &signer_id, &branch, args.push)
}

/// After a testing sign-off is filed: the task's log, listeners, and what to say.
fn filed_testing(ctx: &Ctx, t: &use05_receipt::Testing, tree: &str, signer_id: &str, branch: &str, push: bool) -> Report {
    use use05_receipt::Tested;
    if let Some(task) = ctx.task.as_ref().filter(|task| task.id == t.task) {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "tested", "outcome": t.outcome, "by": t.tester }));
    }
    crate::extend::emit("tested", ctx.top(), json!({ "task": t.task, "tree": tree, "outcome": t.outcome, "note": t.note, "by": t.tester }));
    let counts = ctx.trust.by_id(signer_id).is_some_and(|k| k.role == use05_core::policy::Role::Approver);
    let mut notes = vec![format!("Signed by key {} and stored on branch {branch}. It counts for this exact code only: change it, and sign off again.", &signer_id[..12])];
    notes.extend(super::push_note(ctx.top(), branch, push));
    if !counts {
        notes.push("Warning: this key is not in the policy's trusted keys, so the gate will not count this sign-off. Add it under [[trust.key]] with role = \"approver\".".to_string());
    }
    let tested = t.outcome == Tested::Tested;
    Report {
        command: "approve",
        outcome: if tested { "tested" } else { "testing_skipped" },
        code: if tested { "TESTED" } else { "TESTING_SKIPPED" },
        tone: if tested { Tone::Good } else { Tone::Warn },
        headline: format!("{} {}", if tested { "Signed off: you tried" } else { "Testing skipped for" }, &tree[..12]),
        rows: vec![("by".into(), t.tester.clone()), (if tested { "note" } else { "reason" }.into(), t.note.clone())],
        notes,
        next: Some("git push".into()),
        excerpt: vec![],
        details: json!({ "kind": "testing", "outcome": t.outcome, "note": t.note, "tree": tree, "key_id": signer_id, "branch": branch, "counts": counts }),
        exit: 0,
    }
}

/// File an approval signed elsewhere. It counts only if a key this machine or the base policy
/// trusts as an approver signed it, and it is filed under its own subject, whatever task is current.
fn run_signed(file: &std::path::Path, push: bool, repo: &std::path::Path) -> Report {
    let ctx = match Ctx::open_judging(repo, None) {
        Ok(c) => c,
        Err(e) => return Report::from_core("approve", e),
    };
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return Report::error("approve", "RECEIPT_NOT_FOUND", format!("cannot read {}: {e}", file.display()), None, 6),
    };
    let Ok(envelope) = serde_json::from_slice::<Envelope>(&bytes) else {
        return Report::error("approve", "RECEIPT_MALFORMED", format!("{} is not a signed envelope", file.display()), None, 6);
    };
    let bytes = envelope.to_json_bytes();
    let raw = store::Raw { source: file.display().to_string(), path: file.display().to_string(), bytes: bytes.clone() };
    let mut found = evidence::classify(&ctx.trust, &[raw]);
    // A testing sign-off signed elsewhere (a passkey on a phone): filed under its tree (D87).
    if found.approvals.is_empty() {
        if let Some(t) = found.testing.pop() {
            let Some(tree) = t.statement.tree_subject().map(|(oid, _)| oid.to_string()) else {
                return Report::error("approve", "NOT_AN_APPROVAL", "the sign-off names no tree".into(), None, 2);
            };
            let branch = match store::put(ctx.top(), &tree, &bytes, &t.signer.key_id) {
                Ok(b) => b,
                Err(e) => return Report::from_core("approve", e),
            };
            let driver = ctx.store.load(&t.statement.predicate.task).ok().and_then(|task| task.owner);
            let void = use05_core::gate::passkey_void_of(&t.signer, &t.cosigners, &t.statement.predicate.tester, &ctx.trust, driver.as_ref());
            let mut r = filed_testing(&ctx, &t.statement.predicate, &tree, &t.signer.key_id, &branch, push);
            if let Some(why) = void {
                r.notes.push(format!("It will not count: {why}. Prepare and sign a new one."));
                r.details["counts"] = json!(false);
                r.details["void"] = json!(why);
            }
            return r;
        }
        // A promotion's sign-off signed elsewhere (a passkey on the console): filed under its
        // source commit (D93).
        if let Some(s) = found.signoffs.pop() {
            return crate::cmd::signoff::filed_signed(&ctx, s, &bytes, push);
        }
    }
    let Some(signed) = found.approvals.into_iter().next() else {
        // Whoever signed it, a statement of another kind is not an approval; say that first.
        let kind = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.payload).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).and_then(|v| v["predicateType"].as_str().map(str::to_string));
        let other = kind.is_some_and(|k| k != use05_receipt::APPROVAL_TYPE) || !found.evidence.is_empty() || !found.bypasses.is_empty() || !found.declarations.is_empty() || !found.completions.is_empty() || !found.log_seals.is_empty();
        return if other {
            Report::error("approve", "NOT_AN_APPROVAL", "it is signed, but it is not an approval".into(), None, 2)
        } else {
            Report::error(
                "approve",
                "APPROVAL_NOT_TRUSTED",
                "no key this machine or the policy trusts as an approver signed it, so it was not filed".into(),
                Some("pin the signer's passkey in passkeys.pub, or list it under [[trust.key]] with role = \"approver\"".into()),
                2,
            )
        };
    };
    let statement = &signed.statement;
    let Some(subject) = statement.tree_subject().map(|(oid, _)| oid).or_else(|| statement.intent_subject()) else {
        return Report::error("approve", "NOT_AN_APPROVAL", "the approval names no tree or intent".into(), None, 2);
    };
    let branch = match store::put(ctx.top(), subject, &bytes, &signed.signer.key_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    let a = &statement.predicate;
    if let Some(task) = ctx.task.as_ref().filter(|t| t.id == a.task) {
        let _ = use05_core::log::append(&ctx.store.state_dir(), &task.id, json!({ "event": "approval", "vote": a.decision, "scope": a.scope, "by": a.approver }));
    }
    let approved = a.decision == Decision::Approve;
    // Filed either way, as the gate would read it; but say now if the gate will not count it.
    let driver = ctx.store.load(&a.task).ok().and_then(|t| t.owner);
    let void = use05_core::gate::approval_void(a, &ctx.policy, now_secs())
        .map(|why| match why {
            "expired" => "it has expired",
            "it was given under a different policy" => "it was prepared under a different policy",
            other => other,
        })
        .or_else(|| use05_core::gate::passkey_void(&signed, &ctx.trust, driver.as_ref()));
    let mut notes = vec![format!("Signed by {} (key {}) and stored on branch {branch}.", signed.signer.name, &signed.signer.key_id[..12])];
    if let Some(why) = void {
        notes.push(format!("It will not count: {why}. Prepare and sign a new one."));
    }
    notes.extend(super::push_note(ctx.top(), &branch, push));
    Report {
        command: "approve",
        outcome: if approved { "approved" } else { "rejected" },
        code: if approved { "APPROVED" } else { "REJECTED" },
        tone: if void.is_some() { Tone::Warn } else if approved { Tone::Good } else { Tone::Bad },
        headline: format!("Filed {} for task {}", if approved { "an approval" } else { "a rejection" }, a.task),
        rows: vec![("by".into(), a.approver.clone()), ("reason".into(), if a.rationale.is_empty() { "(none given)".into() } else { a.rationale.clone() }), ("expires".into(), a.expires.clone())],
        notes,
        next: Some(format!("use05 brief   (share it: git push origin {branch})")),
        excerpt: vec![],
        details: json!({ "scope": a.scope, "vote": a.decision, "task": a.task, "key_id": signed.signer.key_id, "branch": branch, "counts": void.is_none(), "void": void }),
        exit: 0,
    }
}

pub fn run_bypass(args: BypassArgs) -> Report {
    // One rule of one promotion (D93).
    if args.promote.is_some() {
        return crate::cmd::signoff::run_bypass(args);
    }
    if args.reason.trim().is_empty() {
        return Report::error("bypass", "REASON_REQUIRED", "say why you are overriding the block".into(), None, 6);
    }
    if args.hours == 0 || args.hours > use05_core::promote::BYPASS_MAX_HOURS {
        return Report::error("bypass", "HOURS_INVALID", "a bypass lasts between 1 and 72 hours".into(), None, 6);
    }
    let ctx = match Ctx::open_judging(&args.repo, None) {
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
        Bypass { env: None, from: None, rule: None, policy_sha256: None, reason: args.reason.trim().to_string(), by: by.clone(), findings: blocking.clone(), created: now_rfc3339(), expires: expiry(0, args.hours) },
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

/// How the approver key is protected: `Some(true)` Touch ID, `Some(false)` a passphrase, `None`
/// Touch ID where this Mac has it (asked first at a terminal), else a passphrase.
pub fn key_new(path: Option<PathBuf>, approver: bool, passphrase_stdin: bool, touch_id: Option<bool>) -> Report {
    if approver {
        let wants_touch_id = match touch_id {
            Some(choice) => choice,
            None if passphrase_stdin || !crate::touchid::supported() => false,
            None if tty::has_tty() && std::io::IsTerminal::is_terminal(&std::io::stdin()) => !matches!(tty::ask(&format!("Protect it with {} instead of a passphrase? [Y/n] ", crate::touchid::method())).map(|a| a.trim().to_ascii_lowercase()), Ok(ref a) if a == "n" || a == "no"),
            None => true,
        };
        if wants_touch_id {
            return touch_id_key_new();
        }
        if keys::passphrase_approver_exists() {
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

/// Make the Touch ID approver key (D91).
fn touch_id_key_new() -> Report {
    if !crate::touchid::supported() {
        return Report::error("key", "TOUCH_ID_UNAVAILABLE", "Touch ID keys need a Mac with a Secure Enclave and a build of 05 that has them".into(), Some("use a passphrase: use05 key new --approver --passphrase".into()), 6);
    }
    if keys::touch_id_public().is_some() {
        return Report::error("key", "KEY_EXISTS", "a Touch ID approver key already exists on this Mac".into(), Some("use05 key show".into()), 6);
    }
    let key = match crate::touchid::create() {
        Ok(k) => k,
        Err(e) => return Report::error("key", "KEY_NOT_CREATED", e, None, 4),
    };
    let id = use05_receipt::PublicKey::Passkey(key.clone()).id();
    let public = use05_receipt::passkey_public_text(&key);
    let mut notes = vec![format!("Approving now asks for {}: the Secure Enclave signs, and only with you there. The key never leaves this Mac.", crate::touchid::method())];
    if !keys::passphrase_approver_exists() {
        notes.push("Break glass (use05 bypass) still needs a passphrase key: use05 key new --approver --passphrase, if you ever want it.".into());
    }
    notes.push("For CI to count your approvals, trust this key and this machine's key in the policy (see the guide: Phone approvals in CI):".into());
    notes.push(format!("[[trust.key]]  name = \"you (Touch ID)\"  role = \"approver\"  person = \"<your git user.name>\"  public = \"{}\"", public.trim()));
    Report {
        command: "key",
        outcome: "created",
        code: "KEY_CREATED",
        tone: Tone::Good,
        headline: format!("Created your Touch ID approver key {}", &id[..12]),
        rows: vec![("protected".into(), format!("yes: by the Secure Enclave, with {}", crate::touchid::method()))],
        notes,
        next: Some("use05 approve".into()),
        excerpt: vec![],
        details: json!({ "key_id": id, "protected": true, "touch_id": true, "public": public.trim() }),
        exit: 0,
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
    if let Some(k) = keys::touch_id_public() {
        let public = use05_receipt::passkey_public_text(&k);
        rows.push(("Touch ID".to_string(), format!("{}   (Secure Enclave)\n{}", use05_receipt::PublicKey::Passkey(k).id(), public.trim())));
        details["touch_id"] = json!(public.trim());
    }
    if rows.is_empty() {
        return Report::error("key", "NO_KEYS", "no keys on this machine yet".into(), Some("use05 init".into()), 6);
    }
    Report { command: "key", outcome: "ok", code: "KEYS", tone: Tone::Plain, headline: "Public keys on this machine".into(), rows, notes: vec![], next: None, excerpt: vec![], details, exit: 0 }
}

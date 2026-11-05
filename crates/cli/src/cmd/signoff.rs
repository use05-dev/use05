//! What only a person does about a promotion (D93): sign off on it (`use05 approve --promote
//! <env>`), or bypass one of its rules (`use05 bypass --promote <env> --rule <name>`). Each is
//! bound to the environment, the environment it comes from and the exact source commit, and each
//! needs positive proof of a person: a terminal, no agent session, and their key.

use serde_json::json;
use use05_core::evidence::{Signed, Trust};
use use05_core::policy::{PROMOTE_RULES, Target};
use use05_core::promote::{self, short};
use use05_core::time::{now_rfc3339, now_secs};
use use05_core::{store, tty};
use use05_receipt::{Bypass, Decision, SignOff, Statement, commit_subject, key_id, seal};

use crate::cmd::approve::{ApproveArgs, BypassArgs, approver_name, expiry, open_approver, person_here, person_key_id, sign_as_person, unsigned_body};
use crate::cmd::promote::{self as promotion, Prepared};
use crate::ctx::Ctx;
use crate::report::{Report, Tone};

/// Ask a person at the terminal; closing the input cancels.
fn ask(question: &str) -> Result<String, Report> {
    tty::ask(question).map(|a| a.trim().to_string()).map_err(|_| Report::error("approve", "CANCELLED", "cancelled; nothing was signed".into(), None, 1))
}

/// What a promotion is, for a person: `promoting 3f2a1b9c0d4e from uat into prod`.
fn what<T: Target>(p: &Prepared<T>) -> String {
    if p.result.direction == use05_receipt::Direction::Hotfix {
        return format!("landing the hotfix {} on {}", short(&p.result.source_head), p.result.target_env);
    }
    if p.result.direction == use05_receipt::Direction::Back {
        return format!("merging {} from {} back into {}", short(&p.result.source_head), p.result.source_env, p.result.target_env);
    }
    let into = if p.env.is_destination() { "to" } else { "into" };
    format!("promoting {} from {} {into} {}", short(&p.result.source_head), p.result.source_env, p.result.target_env)
}

/// A destination has no hotfix, no back-merge and no merge resolved by hand to sign off on.
fn destination_flags(args: &ApproveArgs, name: &str) -> Option<Report> {
    let flag = [(args.back, "--back"), (args.hotfix, "--hotfix"), (args.rev.is_some(), "--rev")].into_iter().find(|(on, _)| *on)?.1;
    Some(crate::cmd::destination::not_for_a_destination(name, flag))
}

/// `use05 approve --promote <env>`: a person's sign-off (or, with `--reject`, their no) on promoting
/// the source's exact head into `env`. At a terminal each question and statement to confirm is
/// asked unless a flag gave it; `--unsigned` prepares the statement for a passkey elsewhere.
pub fn run(args: ApproveArgs, name: &str) -> Report {
    let vote = if args.reject { Decision::Reject } else { Decision::Approve };
    if vote == Decision::Reject && args.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
        return Report::error("approve", "REASON_REQUIRED", "say why you are rejecting it".into(), Some(format!("use05 approve --promote {name} --reject --reason \"…\"")), 6);
    }
    // Preparing a statement for a passkey elsewhere signs nothing; anything else needs a person.
    let person = !args.unsigned;
    if person {
        if let Err(r) = person_here("approve", args.interactive, &format!("signing off on promoting into {name}")) {
            return r;
        }
    }
    // A destination is signed off on as an environment is (D93).
    if crate::cmd::destination::named(&args.repo, name).is_some() {
        if let Some(refused) = destination_flags(&args, name) {
            return refused;
        }
        return match crate::cmd::destination::prepare(&args.repo, name) {
            Ok((p, _)) => sign(args, name, vote, person, p),
            Err(r) => r,
        };
    }
    let prepared = match (args.back, args.hotfix, args.rev.as_deref()) {
        (true, _, Some(merge)) => crate::cmd::hotfix::prepare_resolved(&args.repo, name, merge),
        (true, _, None) => crate::cmd::hotfix::prepare_back(&args.repo, name),
        (_, true, _) => crate::cmd::hotfix::prepare_landing(&args.repo, name),
        (_, _, Some(_)) => return Report::error("approve", "REV_NEEDS_BACK", "--rev with --promote names a merge resolved by hand, so it needs --back".into(), Some(format!("use05 approve --promote {name} --back --rev <merge commit>")), 6),
        _ => promotion::prepare(&args.repo, name),
    };
    match prepared {
        Ok(p) => sign(args, name, vote, person, p),
        Err(r) => r,
    }
}

/// The sign-off itself, on what `p` judged: asked for, checked, signed and filed.
fn sign<T: Target>(args: ApproveArgs, name: &str, vote: Decision, person: bool, p: Prepared<T>) -> Report {
    let r = &p.result;
    if r.delta.is_empty() {
        return Report::error("approve", "NOTHING_TO_PROMOTE", format!("{} already has {}'s head ({}): there is nothing to sign off on", r.target_env, r.source_env, short(&r.source_head)), None, 6);
    }
    let rules = p.env.sign_off().cloned().unwrap_or_default();
    let confirm: Vec<String> = p.env.confirm().iter().map(|c| c.text.trim().to_string()).collect();

    let (text, answers, confirmations) = if vote == Decision::Reject {
        (args.reason.clone().unwrap_or_default().trim().to_string(), Vec::new(), Vec::new())
    } else {
        if args.answers.len() > rules.questions.len() {
            return Report::error("approve", "TOO_MANY_ANSWERS", format!("{} asks {} question(s), and {} answers were given", name, rules.questions.len(), args.answers.len()), None, 6);
        }
        if let Some(c) = args.confirms.iter().find(|c| !confirm.iter().any(|x| x == c.trim())) {
            let known = if confirm.is_empty() { "none".to_string() } else { confirm.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ") };
            return Report::error("approve", "UNKNOWN_CONFIRM", format!("{name} asks no one to confirm \"{}\"; it asks: {known}", c.trim()), None, 6);
        }
        if person {
            eprintln!("You are signing off on {}: {}.", what(&p), promotion::summary(&p));
        }
        let text = match (&args.note, person) {
            (Some(n), _) => n.trim().to_string(),
            (None, true) => match ask("In your own words, what did you check? ") {
                Ok(t) => t,
                Err(r) => return r,
            },
            (None, false) => String::new(),
        };
        let mut answers = args.answers.iter().map(|a| a.trim().to_string()).collect::<Vec<_>>();
        for q in &rules.questions[answers.len()..] {
            if !person {
                return Report::error("approve", "ANSWER_REQUIRED", format!("{name} asks: {q}"), Some("give each answer, in order: --answer \"…\"".into()), 6);
            }
            match ask(&format!("{q} ")) {
                Ok(a) => answers.push(a),
                Err(r) => return r,
            }
        }
        let mut confirmations = Vec::new();
        for c in &confirm {
            if args.confirms.iter().any(|x| x.trim() == c) {
                confirmations.push(c.clone());
                continue;
            }
            if !person {
                return Report::error("approve", "CONFIRM_REQUIRED", format!("{name} asks you to confirm: \"{c}\""), Some(format!("--confirm \"{c}\"")), 6);
            }
            match ask(&format!("Confirm: {c}? [y/N] ")) {
                Ok(a) if matches!(a.as_str(), "y" | "Y" | "yes") => confirmations.push(c.clone()),
                Ok(_) => return Report::error("approve", "NOT_CONFIRMED", format!("a sign-off on {name} must confirm \"{c}\"; nothing was signed"), None, 1),
                Err(r) => return r,
            }
        }
        (text, answers, confirmations)
    };
    let needed = rules.min_length as usize;
    if vote == Decision::Approve && text.chars().count() < needed {
        return Report::error(
            "approve",
            "SIGNOFF_TOO_SHORT",
            format!("your words are {} characters; {name} asks for at least {needed}, in your own words, of what you checked", text.chars().count()),
            Some(format!("use05 approve --promote {name} --note \"<what you checked>\"")),
            6,
        );
    }

    let top = p.top.clone();
    let trust = Trust::new(&p.policy, true);
    let key = person_key_id();
    let signer_person = match (&args.approver, args.unsigned, &key) {
        (Some(a), true, _) => a.clone(),
        (_, true, _) => approver_name(&top),
        (_, false, Some(id)) => trust.person_of(id).unwrap_or_else(|| approver_name(&top)),
        (_, false, None) => return Report::error("approve", "NO_APPROVER_KEY", "there is no approver key on this machine".into(), Some("create one: use05 key new --approver".into()), 6),
    };
    let now = now_secs();
    let statement = Statement::new(
        vec![commit_subject(&r.source_head)],
        SignOff {
            env: r.target_env.clone(),
            from: r.source_env.clone(),
            source_commit: r.source_head.clone(),
            decision: vote,
            signer_person,
            text,
            answers,
            confirmations,
            policy_sha256: r.policy_sha256.clone(),
            created: now_rfc3339(),
            expires: expiry(p.policy.approvals.expire_days, 0),
        },
    );
    let verb = if vote == Decision::Approve { "sign off on" } else { "reject" };
    if args.unsigned {
        let body = serde_json::to_vec(&statement).expect("statement serialises");
        let s = &statement.predicate;
        let mut report = unsigned_body(&body, &r.source_head, &r.source_head, &format!("{verb} {}", what(&p)), json!({ "kind": "signoff", "env": s.env, "from": s.from, "source_commit": s.source_commit, "vote": s.decision, "expires": s.expires }));
        report.rows = vec![("expires".into(), s.expires.clone())];
        return report;
    }
    // Said before anything is signed: one that would not count is not signed at all.
    let id = key.unwrap_or_default();
    if let Some(why) = promote::signoff_void(&statement.predicate, trust.person_of(&id).as_deref(), trust.is_this_machines(&id), &p.policy, &p.env, now) {
        return Report::error("approve", "SIGNOFF_NOT_COUNTED", format!("a sign-off from you would not count: {why}; nothing was signed"), Some(format!("use05 brief --promote {name}   names who may sign")), 2);
    }
    eprintln!("You are about to {verb} {}.", what(&p));
    eprintln!("  It is bound to this exact commit, {} as it comes from {}, and this policy, and expires in {} days.", r.target_env, r.source_env, p.policy.approvals.expire_days);
    let (envelope, signer_id) = match sign_as_person(&statement, &format!("{verb} {}", what(&p)), false, "approve") {
        Ok(signed) => signed,
        Err(r) => return r,
    };
    let branch = match store::put(&top, &r.source_head, &envelope.to_json_bytes(), &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    // Read back as the promotion will read it: a fallback to another key may not be the signer's.
    let void = promote::signoff_void(&statement.predicate, trust.person_of(&signer_id).as_deref(), trust.is_this_machines(&signer_id), &p.policy, &p.env, now);
    filed(&top, &statement.predicate, &signer_id, &branch, args.push, void)
}

/// What to say once a sign-off is filed.
fn filed(top: &std::path::Path, s: &SignOff, signer_id: &str, branch: &str, push: bool, void: Option<String>) -> Report {
    let approved = s.decision == Decision::Approve;
    let mut rows = vec![("by".to_string(), s.signer_person.clone()), (if approved { "words" } else { "reason" }.to_string(), s.text.clone())];
    rows.extend(s.answers.iter().map(|a| ("answer".to_string(), a.clone())));
    rows.extend(s.confirmations.iter().map(|c| ("confirms".to_string(), c.clone())));
    rows.push(("expires".into(), s.expires.clone()));
    let mut notes = vec![format!("Signed by key {} and stored on branch {branch}. It counts for promoting {} from {} into {} under this policy only.", &signer_id[..12.min(signer_id.len())], short(&s.source_commit), s.from, s.env)];
    notes.extend(super::push_note(top, branch, push));
    if let Some(why) = &void {
        notes.push(format!("It will not count: {why}."));
    }
    Report {
        command: "approve",
        outcome: if approved { "signed_off" } else { "rejected" },
        code: if approved { "SIGNED_OFF" } else { "REJECTED" },
        tone: if void.is_some() { Tone::Warn } else if approved { Tone::Good } else { Tone::Bad },
        headline: format!("{} promoting {} from {} into {}", if approved { "Signed off on" } else { "Rejected" }, short(&s.source_commit), s.from, s.env),
        rows,
        notes,
        next: Some(if approved { format!("use05 promote {}", s.env) } else { format!("use05 brief --promote {}", s.env) }),
        excerpt: vec![],
        details: json!({ "kind": "signoff", "env": s.env, "from": s.from, "source_commit": s.source_commit, "vote": s.decision, "key_id": signer_id, "branch": branch, "counts": void.is_none(), "void": void }),
        exit: 0,
    }
}

/// File a sign-off signed elsewhere (a passkey on the console, D86), under its source commit, and
/// say now whether the promotion will count it.
pub fn filed_signed(ctx: &Ctx, s: Signed<Statement<SignOff>>, bytes: &[u8], push: bool) -> Report {
    let top = ctx.top();
    let pred = &s.statement.predicate;
    let Some(subject) = s.statement.commit_subject() else {
        return Report::error("approve", "NOT_AN_APPROVAL", "the sign-off names no commit".into(), None, 2);
    };
    let branch = match store::put(top, subject, bytes, &s.signer.key_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("approve", e),
    };
    let void = if crate::cmd::destination::named(top, &pred.env).is_some() {
        crate::cmd::destination::prepare(top, &pred.env).map(|(p, _)| p).map_or_else(|r| Some(format!("it could not be judged here ({})", r.headline)), |p| signed_void(&s, &p))
    } else {
        promotion::prepare(top, &pred.env).map_or_else(|r| Some(format!("it could not be judged here ({})", r.headline)), |p| signed_void(&s, &p))
    };
    filed(top, pred, &s.signer.key_id, &branch, push, void)
}

/// Why a sign-off signed elsewhere does not count for the promotion `p` judges now, if it does not.
fn signed_void<T: Target>(s: &Signed<Statement<SignOff>>, p: &Prepared<T>) -> Option<String> {
    let pred = &s.statement.predicate;
    if p.result.source_head != pred.source_commit || p.result.source_env != pred.from {
        return Some(format!("it is for {} from {}, and {} is now at {} from {}", short(&pred.source_commit), pred.from, p.result.target_env, short(&p.result.source_head), p.result.source_env));
    }
    let trust = Trust::new(&p.policy, true);
    let id = &s.signer.key_id;
    promote::signoff_void(pred, trust.person_of(id).as_deref(), trust.is_this_machines(id), &p.policy, &p.env, now_secs()).or_else(|| use05_core::gate::passkey_void_of(&s.signer, &s.cosigners, &pred.signer_person, &trust, None).map(str::to_string))
}

/// `use05 bypass --promote <env> --rule <name> --reason "<why>"`: break glass for one rule of one
/// exact promotion, signed with the person's passphrase key, logged, shown and carried in the
/// promotion's record and trailers. What is built in is never bypassed.
pub fn run_bypass(args: BypassArgs) -> Report {
    let name = args.promote.clone().unwrap_or_default();
    let rule = args.rule.as_deref().map(str::trim).unwrap_or_default().to_string();
    if let Err(r) = person_here("bypass", args.interactive, &format!("bypassing a rule of promoting into {name}")) {
        return r;
    }
    // By its name, or by the code its finding has.
    let lower = rule.to_ascii_lowercase();
    if promote::BUILT_IN.contains(&lower.as_str()) || ["promote_target_ahead", "promote_not_evaluated_head", "agent_may_not_promote"].contains(&lower.as_str()) {
        return Report::error("bypass", "BYPASS_NOT_ALLOWED", format!("{rule} is built in and never bypassed: only the evaluated commit moves, never past commits {name} has and its source lacks, never by an agent where people promote, never by force"), None, 2);
    }
    if !PROMOTE_RULES.contains(&rule.as_str()) {
        return Report::error("bypass", "UNKNOWN_RULE", format!("{rule:?} is not a promotion rule; the rules are {}", PROMOTE_RULES.join(", ")), Some(format!("use05 bypass --promote {name} --rule <rule> --reason \"…\"")), 6);
    }
    if args.hours == 0 || args.hours > use05_core::promote::BYPASS_MAX_HOURS {
        return Report::error("bypass", "HOURS_INVALID", "a bypass lasts between 1 and 72 hours".into(), None, 6);
    }
    // A destination's rules are bypassed as an environment's are (D93); it has no back-merge.
    if crate::cmd::destination::named(&args.repo, &name).is_some() {
        if args.back {
            return crate::cmd::destination::not_for_a_destination(&name, "--back");
        }
        return match crate::cmd::destination::prepare(&args.repo, &name) {
            Ok((p, _)) => bypass(args, &name, rule, p),
            Err(r) => r,
        };
    }
    let prepared = if args.back { crate::cmd::hotfix::prepare_back(&args.repo, &name) } else { promotion::prepare(&args.repo, &name) };
    match prepared {
        Ok(p) => bypass(args, &name, rule, p),
        Err(r) => r,
    }
}

/// The bypass itself, of `rule` in what `p` judged: checked, signed and filed.
fn bypass<T: Target>(args: BypassArgs, name: &str, rule: String, p: Prepared<T>) -> Report {
    let r = &p.result;
    let allowed = p.env.bypass();
    let table = if p.env.is_destination() { "destination" } else { "environment" };
    if !allowed.allowed {
        return Report::error("bypass", "BYPASS_NOT_ALLOWED", format!("{name} allows no bypass ([{table}.bypass] allowed = false)"), Some(format!("meet the rule, or ask a person to sign off: use05 brief --promote {name}")), 2);
    }
    if allowed.never.iter().any(|n| *n == rule) {
        return Report::error("bypass", "BYPASS_NOT_ALLOWED", format!("{name} never lets a bypass clear {rule} ([{table}.bypass] never)"), Some(format!("meet it: use05 brief --promote {name}")), 2);
    }
    let reason = args.reason.trim().to_string();
    if reason.chars().count() < allowed.reason_min as usize {
        return Report::error("bypass", "REASON_TOO_SHORT", format!("say why in at least {} characters; {} were given", allowed.reason_min, reason.chars().count()), None, 6);
    }
    if rule == "sign_off" && r.findings.iter().any(|f| f.code == "SIGNOFF_REJECTED") {
        return Report::error("bypass", "BYPASS_NOT_ALLOWED", "a person rejected this promotion, and a rejection is never bypassed".into(), Some(format!("use05 brief --promote {name}")), 2);
    }
    let holds = r.rules.iter().find(|x| x.rule == rule).is_none_or(|x| x.outcome != use05_receipt::RuleOutcome::Fail || x.severity == use05_receipt::RuleSeverity::Allow);
    if holds {
        return Report::error("bypass", "NOTHING_TO_BYPASS", format!("{rule} holds nothing back in {}: there is nothing to bypass", what(&p)), Some(format!("use05 brief --promote {name}")), 6);
    }
    eprintln!("You are about to bypass {rule} for {}.", what(&p));
    eprintln!("  Reason: {reason}");
    eprintln!("  It covers this exact commit only, lasts {} hour(s), and is recorded in the promotion's record, its trailers and the brief.", args.hours);
    let key = match open_approver(false, "bypass") {
        Ok(k) => k,
        Err(r) => return r,
    };
    let signer_id = key_id(&key.verifying_key());
    let by = Trust::new(&p.policy, true).person_of(&signer_id).unwrap_or_else(|| approver_name(&p.top));
    let statement = Statement::new(
        vec![commit_subject(&r.source_head)],
        Bypass { reason: reason.clone(), by: by.clone(), findings: promote::rule_code(&rule).map(str::to_string).into_iter().collect(), created: now_rfc3339(), expires: expiry(0, args.hours), env: Some(r.target_env.clone()), from: Some(r.source_env.clone()), rule: Some(rule.clone()), policy_sha256: Some(r.policy_sha256.clone()) },
    );
    let branch = match store::put(&p.top, &r.source_head, &seal(&statement, &key).to_json_bytes(), &signer_id) {
        Ok(b) => b,
        Err(e) => return Report::from_core("bypass", e),
    };
    let mut notes = vec![format!("Recorded on branch {branch}. The promotion's record and its trailers carry it, and the brief shows it.")];
    notes.extend(super::push_note(&p.top, &branch, args.push));
    Report {
        command: "bypass",
        outcome: "bypassed",
        code: "BYPASSED",
        tone: Tone::Warn,
        headline: format!("Break-glass: {rule} bypassed for {}", what(&p)),
        rows: vec![("by".into(), by), ("reason".into(), reason), ("rule".into(), rule.clone()), ("lasts".into(), format!("{} hour(s), this exact commit only", args.hours))],
        notes,
        next: Some(if args.back { format!("use05 promote {name} --back") } else { format!("use05 promote {name}") }),
        excerpt: vec![],
        details: json!({ "kind": "promotion", "env": r.target_env, "from": r.source_env, "source_commit": r.source_head, "rule": rule, "branch": branch, "expires_in_hours": args.hours }),
        exit: 0,
    }
}

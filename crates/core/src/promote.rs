//! Promotion (D93): may one exact commit move from one environment into the next, under the rules
//! the target environment's own branch holds?
//!
//! [`evaluate`] is pure: it decides from facts gathered elsewhere (the commits that would move, the
//! receipts on the source head, sign-offs, deployments), so the command line, the CI gate and the
//! console decide alike. The helpers below it read git and the receipts to gather those facts and
//! never write anything.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;
use use05_receipt::{Decision as Vote, Direction, RuleOutcome, RuleResult, RuleSeverity, SignOff};

use crate::evidence::Found;
use crate::gate::{CheckState, CheckStatus, Decision, Effect, Finding};
use crate::git;
use crate::policy::{Environment, Policy, Severity, Target, same_person};
use crate::time::parse_rfc3339;

/// A deployment record of the source environment for the source head, as it bears on the rules.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentSeen {
    pub confirmed: bool,
    /// RFC 3339.
    pub created: String,
    /// Who signed the record.
    pub by: String,
    /// How many probes it ran. None: it could not say what the environment runs.
    pub probes: usize,
}

/// A sign-off for this exact promotion (environment, source environment, source commit), and
/// whether it counts.
#[derive(Debug, Clone, Serialize)]
pub struct SignOffSeen {
    /// The person it names.
    pub person: String,
    pub decision: Vote,
    pub text: String,
    pub confirmations: Vec<String>,
    /// The receipt, by path.
    pub path: String,
    /// `None` when it counts; otherwise why not.
    pub void: Option<String>,
}

/// A person's bypass of one rule for this exact promotion (environment, source environment,
/// source commit), and whether it counts.
#[derive(Debug, Clone, Serialize)]
pub struct BypassSeen {
    pub rule: String,
    /// Who it says bypassed it.
    pub person: String,
    pub reason: String,
    /// The receipt, by path.
    pub path: String,
    /// `None` when it counts; otherwise why not.
    pub void: Option<String>,
}

/// What can never be bypassed, by the names a person might give `--rule`: promote only the
/// evaluated head, never past commits the target has and the source lacks, never by an agent
/// where people promote, never by force.
pub const BUILT_IN: [&str; 4] = ["evaluated_head", "target_ahead", "agent", "force_push"];

/// The longest a bypass lasts, a tree's or a promotion's.
pub const BYPASS_MAX_HOURS: u32 = 72;

/// The finding a rule's failure gives, as the page and a bypass record name it.
pub fn rule_code(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "source_checks" => "SOURCE_CHECKS_MISSING",
        "source_confirmed" => "SOURCE_NOT_CONFIRMED",
        "soak" => "SOAK_NOT_DONE",
        "migrations" => "MIGRATIONS_IN_DELTA",
        "untasked" => "UNTASKED_COMMITS",
        "sign_off" => "SIGNOFF_REQUIRED",
        _ => return None,
    })
}

/// Why a bypass of a promotion rule does not count, if it does not: it is bound to the policy
/// judging the promotion, which says whether a person may bypass here, which rules never, and how
/// long a reason must be; and it lasts no longer than a bypass may. Its subject (environment,
/// source and commit) is the caller's to match.
pub fn bypass_void(b: &use05_receipt::Bypass, policy: &Policy, env: &dyn Target, now: u64) -> Option<String> {
    let rule = b.rule.as_deref().unwrap_or_default();
    let rules = env.bypass();
    if !crate::policy::PROMOTE_RULES.contains(&rule) {
        return Some(format!("{rule:?} is not a promotion rule a bypass can clear"));
    }
    if b.policy_sha256.as_deref() != Some(policy.digest().as_str()) {
        return Some("it was given under a different policy".into());
    }
    if !rules.allowed {
        return Some(format!("{} allows no bypass", env.name()));
    }
    if rules.never.iter().any(|r| r == rule) {
        return Some(format!("{} never lets a bypass clear {rule}", env.name()));
    }
    if b.reason.trim().chars().count() < rules.reason_min as usize {
        return Some(format!("its reason is shorter than the {} characters the policy asks", rules.reason_min));
    }
    let (Some(created), Some(expires)) = (parse_rfc3339(&b.created), parse_rfc3339(&b.expires)) else {
        return Some("it is not dated".into());
    };
    if expires <= now {
        return Some("expired".into());
    }
    if created > now + CLOCK_SKEW_SECS {
        return Some("it is dated in the future".into());
    }
    if expires.saturating_sub(created) > u64::from(BYPASS_MAX_HOURS) * 3600 + CLOCK_SKEW_SECS {
        return Some(format!("it lasts longer than the {BYPASS_MAX_HOURS} hours a bypass may"));
    }
    None
}

/// Everything a promotion is judged on.
pub struct PromoteInput<'a> {
    /// The rules: the policy committed on the target environment's branch, or for a destination
    /// the policy at the source's head.
    pub policy: &'a Policy,
    /// An environment, or a destination in another repository.
    pub target: &'a dyn Target,
    /// Where it comes from, as the records name it: an environment, or for a destination the
    /// environment its source branch is, else that branch.
    pub source: &'a str,
    /// The source is an environment, whose deployments are recorded. A destination's source
    /// branch may be none: then nothing deploys it, and `source_confirmed` and `soak` are not
    /// judged.
    pub source_deployed: bool,
    pub source_head: String,
    /// `None` when the target branch does not exist yet: promoting creates it.
    pub target_head: Option<String>,
    /// The head an earlier evaluation saw. A promotion moves only that one: if the source moved
    /// since, it is refused.
    pub expected_source: Option<String>,
    /// The commits that would move: on the source head, not on the target. Oldest first.
    pub delta: Vec<String>,
    /// Commits on the target the source lacks (see [`target_ahead`]).
    pub target_only: Vec<String>,
    /// The files that differ between the target and the source head.
    pub changed: Vec<String>,
    /// The judging policy's required checks on the source head's exact tree, as the gate reads
    /// them (`gate::checks_at`).
    pub checks: Vec<CheckStatus>,
    /// The source environment's deployment records of the source head, newest last.
    pub deployments: Vec<DeploymentSeen>,
    /// Commits in the delta that belong to no task (see [`untasked`]).
    pub untasked: Vec<String>,
    pub signoffs: Vec<SignOffSeen>,
    /// People's bypasses of single rules for this exact promotion.
    pub bypasses: Vec<BypassSeen>,
    /// Settings the source's policy loosens against the judging one: the rules after the
    /// promotion, since the policy file moves with it.
    pub loosened: Vec<String>,
    /// The one promoting is an agent.
    pub agent: bool,
    pub now: u64,
    /// Findings from gathering the facts (where the rules came from, a branch to be created).
    pub notes: Vec<Finding>,
    /// Which way it moves: up the ladder (a promotion), back down one rung (a back-merge of the
    /// environment above into `target`), or a hotfix task's work landing on `target`'s branch.
    pub direction: Direction,
    /// The hotfix task, for a hotfix.
    pub task: Option<String>,
    /// The hotfix tasks whose landing is among `target_only`, by counted records: why the target
    /// is ahead, and what merges it back.
    pub hotfixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromoteResult {
    pub decision: Decision,
    pub findings: Vec<Finding>,
    pub source_env: String,
    pub target_env: String,
    pub source_head: String,
    pub target_head: Option<String>,
    /// The commits that would move, oldest first.
    pub delta: Vec<String>,
    pub rules: Vec<RuleResult>,
    /// `fast-forward` or `merge`.
    pub how: &'static str,
    /// What to go back to if the deploy fails: the target's head now. `None` when the promotion
    /// creates the branch.
    pub rollback_point: Option<String>,
    pub changed: Vec<String>,
    pub checks: Vec<CheckStatus>,
    pub signoffs: Vec<SignOffSeen>,
    pub bypasses: Vec<BypassSeen>,
    /// The people who may sign off. Empty: any person with an approver key.
    pub signers: Vec<String>,
    /// Whether an agent may promote here.
    pub agent_allowed: bool,
    pub policy_sha256: String,
    /// Up, back or hotfix.
    pub direction: Direction,
    /// The hotfix task, for a hotfix.
    pub task: Option<String>,
}

/// The rule severity as the records write it.
pub fn severity_word(s: Severity) -> RuleSeverity {
    match s {
        Severity::Allow => RuleSeverity::Allow,
        Severity::Warn => RuleSeverity::Warn,
        Severity::Approval => RuleSeverity::Approval,
        Severity::Deny => RuleSeverity::Deny,
    }
}

fn effect_for(severity: Severity) -> Option<Effect> {
    match severity {
        Severity::Allow => None,
        Severity::Warn => Some(Effect::Warn),
        Severity::Approval => Some(Effect::Approval),
        Severity::Deny => Some(Effect::Deny),
    }
}

/// The first 12 characters of a commit id.
pub fn short(id: &str) -> &str {
    &id[..12.min(id.len())]
}

/// `a, b, c and 4 more`.
fn some(items: &[String], at_most: usize) -> String {
    let shown: Vec<&str> = items.iter().take(at_most).map(String::as_str).collect();
    let more = if items.len() > at_most { format!(" and {} more", items.len() - at_most) } else { String::new() };
    format!("{}{more}", shown.join(", "))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The people who may sign off on promoting into `env`. Empty: any person with an approver key.
pub fn signers(policy: &Policy, env: &dyn Target) -> Vec<String> {
    env.sign_off().map(|s| policy.people_of(&s.signers)).unwrap_or_default()
}

/// Who may sign, for a person: `eng-managers (Dana, Lee)`, or "a person with an approver key".
fn who_signs(policy: &Policy, env: &dyn Target) -> String {
    let named = env.sign_off().map(|s| s.signers.clone()).unwrap_or_default();
    let people = signers(policy, env);
    if named.is_empty() {
        return "a person with an approver key".to_string();
    }
    let plain = named.len() == people.len() && named.iter().zip(&people).all(|(a, b)| same_person(a, b));
    if plain { people.join(" or ") } else { format!("{} ({})", named.join(", "), people.join(", ")) }
}

/// Clocks differ a little between the machine that signed and the one reading.
const CLOCK_SKEW_SECS: u64 = 300;

/// Why a sign-off for this promotion does not count, if it does not. `key_person` is the person
/// the policy names on the key that signed it; `own_key` says it is this machine's own approver
/// key, which counts where the policy names no signers. Its subject (environment, source and
/// commit) is the caller's to match: a sign-off for another promotion is not about this one.
pub fn signoff_void(s: &SignOff, key_person: Option<&str>, own_key: bool, policy: &Policy, env: &dyn Target, now: u64) -> Option<String> {
    if s.policy_sha256 != policy.digest() {
        return Some("it was given under a different policy".into());
    }
    let (Some(created), Some(expires)) = (parse_rfc3339(&s.created), parse_rfc3339(&s.expires)) else {
        return Some("it is not dated".into());
    };
    if expires <= now {
        return Some("expired".into());
    }
    if created > now + CLOCK_SKEW_SECS {
        return Some("it is dated in the future".into());
    }
    if expires.saturating_sub(created) > policy.approvals.expire_days as u64 * 86_400 + CLOCK_SKEW_SECS {
        return Some("it lasts longer than the policy allows".into());
    }
    if let Some(p) = key_person.filter(|p| !same_person(p, &s.signer_person)) {
        return Some(format!("it names {}, but {p}'s key signed it", s.signer_person));
    }
    if let Some(why) = signer_void(key_person, own_key, policy, env) {
        return Some(why);
    }
    if s.decision == Vote::Approve {
        if let Some(why) = words_void(&s.text, env) {
            return Some(why);
        }
        if let Some(c) = env.confirm().iter().find(|c| !s.confirmations.iter().any(|x| x.trim() == c.text.trim())) {
            return Some(format!("it does not confirm \"{}\"", c.text));
        }
    }
    None
}

/// Why this person may not sign off on moving into `env`, if they may not: the policy names who may
/// (`[environment.sign_off] signers`) and the key's person is not among them, or the key names no
/// person where it must. `own_key`: this machine's own approver key, which signs where no signers
/// are named. The same for a sign-off and for an approval of a hotfix's outcome (D93).
pub fn signer_void(key_person: Option<&str>, own_key: bool, policy: &Policy, env: &dyn Target) -> Option<String> {
    let named = env.sign_off().map(|s| s.signers.clone()).unwrap_or_default();
    match key_person {
        Some(p) if !named.is_empty() && !signers(policy, env).iter().any(|q| same_person(q, p)) => Some(format!("{p} is not among those who may sign ({})", who_signs(policy, env))),
        Some(_) => None,
        None if named.is_empty() && own_key => None,
        None => Some("its key names no person in the policy".into()),
    }
}

/// Why a person's words are too few for `env`'s `[environment.sign_off] min_length`, if they are.
pub fn words_void(text: &str, env: &dyn Target) -> Option<String> {
    let min = env.sign_off().map_or(0, |o| o.min_length) as usize;
    (text.trim().chars().count() < min).then(|| format!("its words are shorter than the {min} characters the policy asks"))
}

fn finding(code: &'static str, effect: Effect, message: String, next: Option<String>) -> Finding {
    Finding { code, effect, message, paths: Vec::new(), next, approvable: false }
}

/// One rule's verdict before its severity is applied: the outcome, the detail for the record, and
/// what a failure says (code, message, next step, paths).
struct Verdict {
    outcome: RuleOutcome,
    detail: String,
    fail: Option<(&'static str, String, Option<String>, Vec<String>)>,
}

fn pass(detail: String) -> Verdict {
    Verdict { outcome: RuleOutcome::Pass, detail, fail: None }
}

fn skipped(detail: &str) -> Verdict {
    Verdict { outcome: RuleOutcome::Skipped, detail: detail.to_string(), fail: None }
}

fn fail(detail: String, code: &'static str, message: String, next: Option<String>, paths: Vec<String>) -> Verdict {
    Verdict { outcome: RuleOutcome::Fail, detail, fail: Some((code, message, next, paths)) }
}

fn check_word(state: &CheckState) -> &'static str {
    match state {
        CheckState::Passed { .. } => "passed",
        CheckState::Failed { .. } => "failed",
        CheckState::TimedOut { .. } => "timed out",
        CheckState::NotAuthoritative { .. } => "proved only by a key the policy does not accept",
        CheckState::Stale => "passed only on an earlier tree",
        CheckState::Missing => "not proved",
        CheckState::Undefined => "not defined",
        CheckState::NotRequired { .. } => "not required",
    }
}

/// How strongly `rule` holds this move back, and whether it is judged at all: a back-merge never
/// judges the rules about the source environment (it brings down what is already there); a
/// hotfix judges them only where `[environment.hotfix.rules]` asks.
fn severity_of(env: &dyn Target, direction: Direction, rule: &str) -> (Severity, bool) {
    let source_rule = crate::policy::SOURCE_RULES.contains(&rule);
    match direction {
        Direction::Back => (env.rules().get(rule).expect("a known rule"), !source_rule),
        Direction::Hotfix => {
            let s = env.hotfix_rule(rule).expect("a known rule");
            (s, !(source_rule && s == Severity::Allow))
        }
        Direction::Up | Direction::Unknown => (env.rules().get(rule).expect("a known rule"), true),
    }
}

pub fn evaluate(input: &PromoteInput<'_>) -> PromoteResult {
    let policy = input.policy;
    let env = input.target;
    let (to_name, from_name) = (env.name(), input.source);
    let head = short(&input.source_head).to_string();
    let direction = input.direction;
    let mut findings: Vec<Finding> = input.notes.clone();
    // The command that makes this move, and what its source is called.
    let (command, source_label) = match direction {
        Direction::Back => (format!("use05 promote {to_name} --back"), format!("{from_name}'s head")),
        Direction::Hotfix => ("use05 land".to_string(), "the hotfix".to_string()),
        _ => (format!("use05 promote {to_name}"), format!("{from_name}'s head")),
    };

    // ------------------------------------------------------------- built in, never bypassed
    if let Some(expected) = input.expected_source.as_deref().filter(|e| *e != input.source_head) {
        findings.push(finding(
            "PROMOTE_NOT_EVALUATED_HEAD",
            Effect::Deny,
            format!("{from_name} moved from {} to {head} since it was evaluated; only the evaluated commit is promoted", short(expected)),
            Some(format!("evaluate it again: {command} --check")),
        ));
    }
    // A hotfix is a task's work, which an agent may do; its landing needs a person's approval anyway.
    if input.agent && !policy.agent_may_promote(env) && direction != Direction::Hotfix {
        let what = if direction == Direction::Back { "merge back into" } else { "promote into" };
        findings.push(finding("AGENT_MAY_NOT_PROMOTE", Effect::Deny, format!("an agent may not {what} {to_name}: the policy keeps it for people"), Some(format!("ask a person to run: {command}"))));
    }
    if !input.target_only.is_empty() {
        let n = input.target_only.len();
        let it = if n == 1 { "it" } else { "them" };
        let mut message = format!("{to_name} has {} that {from_name} lacks ({}); promoting would leave {it} behind or mix {it} in unseen", plural(n, "commit", "commits"), some(&input.target_only.iter().map(|c| short(c).to_string()).collect::<Vec<_>>(), 3));
        // A hotfix landed there: merge it down one rung at a time, then promote again.
        let next = if input.hotfixes.is_empty() {
            format!("bring {to_name}'s commits into {from_name} first, then promote again")
        } else {
            message.push_str(&format!("; they come from {}", if input.hotfixes.len() == 1 { format!("the hotfix task {}", input.hotfixes[0]) } else { format!("the hotfix tasks {}", input.hotfixes.join(", ")) }));
            format!("merge it down into {from_name} first: use05 promote {from_name} --back")
        };
        findings.push(finding("PROMOTE_TARGET_AHEAD", Effect::Deny, message, Some(next)));
    }

    // ------------------------------------------------------------- the rules
    let nothing = input.delta.is_empty();
    if nothing {
        let (code, message) = match direction {
            Direction::Back => ("NOTHING_TO_MERGE_BACK", format!("{to_name} already has everything {from_name} has ({head}); nothing would be merged back")),
            _ => ("NOTHING_TO_PROMOTE", format!("{to_name} already has {from_name}'s head ({head}); nothing would move")),
        };
        findings.push(finding(code, Effect::Info, message, None));
    }
    let counted: Vec<&SignOffSeen> = input.signoffs.iter().filter(|s| s.void.is_none()).collect();
    let signed_by: Vec<String> = counted.iter().filter(|s| s.decision == Vote::Approve).map(|s| s.person.clone()).collect();
    // A hotfix's approvals are its sign-off, unless the environment asks questions or statements
    // only a person gives: then a sign-off receipt (`approve --promote <env> --hotfix`) gives them.
    let hotfix_asks = direction == Direction::Hotfix && (!env.confirm().is_empty() || env.sign_off().is_some_and(|s| !s.questions.is_empty()));
    let real_signed_by: Vec<String> = counted.iter().filter(|s| s.decision == Vote::Approve && !s.path.is_empty()).map(|s| s.person.clone()).collect();
    let ask = match direction {
        // A hotfix's sign-off is a person's approval of its outcome.
        Direction::Hotfix => "ask a person to approve it: use05 approve --outcome".to_string(),
        Direction::Back => format!("ask {} to sign off: use05 approve --promote {to_name} --back --note \"<what you checked>\"", who_signs(policy, env)),
        _ => format!("ask {} to sign off: use05 approve --promote {to_name} --note \"<what you checked>\"", who_signs(policy, env)),
    };
    // The newest record says what the source runs now; the soak counts from the first record of
    // the unbroken run of confirmations that ends with it.
    let newest = input.deployments.last();
    let run_start = newest.filter(|d| d.confirmed).and_then(|_| input.deployments.iter().rev().take_while(|d| d.confirmed).last());
    let mut results = Vec::new();
    for rule in crate::policy::PROMOTE_RULES {
        let (mut severity, judged) = severity_of(env, direction, rule);
        if rule == "sign_off" && (!env.confirm().is_empty() || hotfix_asks) {
            // A statement only a person can give needs a person's sign-off to give it.
            severity = severity.max(Severity::Approval);
        }
        let verdict = if nothing {
            skipped("nothing moves")
        } else if !judged {
            skipped(if direction == Direction::Back { "not judged when merging back down" } else { "a hotfix comes from no other environment" })
        } else if rule == "soak" && env.is_destination() {
            skipped("a destination has no soak")
        } else if !input.source_deployed && ["source_confirmed", "soak"].contains(&rule) {
            skipped(&format!("{from_name} is a branch, not an environment: nothing deploys it"))
        } else {
            match rule {
                "source_checks" => {
                    let applying: Vec<&CheckStatus> = input.checks.iter().filter(|c| !matches!(c.state, CheckState::NotRequired { .. })).collect();
                    let said = applying.iter().map(|c| format!("{} {}", c.name, check_word(&c.state))).collect::<Vec<_>>().join(", ");
                    let unproved: Vec<&str> = applying.iter().filter(|c| !matches!(c.state, CheckState::Passed { .. } | CheckState::Failed { .. } | CheckState::TimedOut { .. })).map(|c| c.name.as_str()).collect();
                    if applying.is_empty() {
                        pass("no required check applies to what moves".into())
                    } else if applying.iter().all(|c| matches!(c.state, CheckState::Passed { .. })) {
                        pass(format!("{said} on {head}"))
                    } else {
                        let next = if unproved.is_empty() {
                            format!("fix it where work lands, then promote the fix to {from_name}")
                        } else {
                            format!("prove them on {source_label}: use05 prove {} --tree {head}", unproved.join(" "))
                        };
                        fail(format!("{said} on {head}"), "SOURCE_CHECKS_MISSING", format!("the required checks have not all passed on {source_label} ({head}): {said}"), Some(next), Vec::new())
                    }
                }
                "source_confirmed" => match (run_start.and(newest), newest) {
                    (Some(d), _) => pass(format!("{from_name} was confirmed running {head} at {}", d.created)),
                    (None, Some(d)) if d.probes == 0 => fail(format!("no probes: 05 cannot tell what {from_name} runs"), "SOURCE_NOT_CONFIRMED", format!("no probes: 05 cannot tell what {from_name} runs, so nothing confirms it runs {head}"), Some(format!("give {from_name} a probe ([[environment.probe]] in the policy), then: use05 promote {from_name} --confirm")), Vec::new()),
                    (None, Some(d)) => fail(format!("{from_name}'s deploy of {head} was not confirmed"), "SOURCE_NOT_CONFIRMED", format!("{from_name} was not confirmed running {head}: its deploy at {} did not show it", d.created), Some(format!("look at {from_name}, then confirm it: use05 promote {from_name} --confirm")), Vec::new()),
                    (None, None) => fail(format!("nothing confirms {from_name} runs {head}"), "SOURCE_NOT_CONFIRMED", format!("nothing confirms {from_name} runs {head}: there is no deployment record of it"), Some(format!("confirm it: use05 promote {from_name} --confirm (with a probe for {from_name} in the policy)")), Vec::new()),
                },
                "soak" => match env.soak_minutes().filter(|m| *m > 0) {
                    None => skipped("no soak time is set"),
                    Some(minutes) => match run_start.and_then(|d| parse_rfc3339(&d.created)) {
                        Some(at) if input.now.saturating_sub(at) >= u64::from(minutes) * 60 => pass(format!("{from_name} has run {head} for {} of {minutes} minutes", input.now.saturating_sub(at) / 60)),
                        Some(at) => {
                            let ran = input.now.saturating_sub(at) / 60;
                            fail(format!("{from_name} has run {head} for {ran} of {minutes} minutes"), "SOAK_NOT_DONE", format!("{from_name} has run {head} for {ran} minutes; {to_name} asks for {minutes}"), Some(format!("wait {} more minutes, then check again", u64::from(minutes) - ran)), Vec::new())
                        }
                        None => fail(format!("the soak has not started: {from_name} is not confirmed running {head}"), "SOAK_NOT_DONE", format!("the {minutes} minutes in {from_name} have not started: nothing confirms it runs {head}"), Some(format!("confirm it first: use05 promote {from_name} --confirm")), Vec::new()),
                    },
                },
                "migrations" => {
                    let files: Vec<String> = crate::risk::of_paths(policy, &input.changed).into_iter().filter(|r| r.category == "migration").flat_map(|r| r.paths).collect();
                    if files.is_empty() {
                        pass("no migrations move".into())
                    } else {
                        fail(format!("{} move: {}", plural(files.len(), "migration file", "migration files"), some(&files, 3)), "MIGRATIONS_IN_DELTA", format!("{} {} to {to_name}: {}", plural(files.len(), "migration file", "migration files"), if files.len() == 1 { "moves" } else { "move" }, some(&files, 3)), Some(ask.clone()), files)
                    }
                }
                "untasked" => {
                    if input.untasked.is_empty() {
                        pass(format!("every commit that moves belongs to a task ({})", plural(input.delta.len(), "commit", "commits")))
                    } else {
                        let ids: Vec<String> = input.untasked.iter().map(|c| short(c).to_string()).collect();
                        let n = ids.len();
                        fail(format!("{} of {} {} to no task: {}", n, plural(input.delta.len(), "commit", "commits"), if n == 1 { "belongs" } else { "belong" }, some(&ids, 3)), "UNTASKED_COMMITS", format!("{} that would move {} to no 05 task: {}", plural(n, "commit", "commits"), if n == 1 { "belongs" } else { "belong" }, some(&ids, 3)), Some(ask.clone()), Vec::new())
                    }
                }
                _ => {
                    // A person's counted no denies, whatever the rule asks.
                    let rejected: Vec<&&SignOffSeen> = counted.iter().filter(|s| s.decision == Vote::Reject).collect();
                    if let Some(r) = rejected.first() {
                        fail(format!("{} rejected it", r.person), "SIGNOFF_REJECTED", format!("{} rejected promoting {head} into {to_name}: \"{}\"", r.person, r.text), None, Vec::new())
                    } else if severity == Severity::Allow {
                        skipped("not asked for")
                    } else if hotfix_asks && !real_signed_by.is_empty() {
                        pass(format!("signed off by {}", real_signed_by.join(", ")))
                    } else if !hotfix_asks && !signed_by.is_empty() {
                        pass(format!("signed off by {}", signed_by.join(", ")))
                    } else {
                        let mut message = match direction {
                            Direction::Hotfix if hotfix_asks => format!("landing this hotfix on {to_name} needs a person's sign-off that answers its questions and confirms its statements, besides the approval of its outcome"),
                            Direction::Hotfix => format!("landing this hotfix on {to_name} needs a person's approval of its outcome"),
                            Direction::Back => format!("merging back into {to_name} needs a sign-off from {}", who_signs(policy, env)),
                            _ => format!("promoting into {to_name} needs a sign-off from {}", who_signs(policy, env)),
                        };
                        for s in input.signoffs.iter().filter(|s| s.void.is_some() && s.decision == Vote::Approve) {
                            message.push_str(&format!("; {}'s does not count: {}", s.person, s.void.as_deref().unwrap_or_default()));
                        }
                        let next = if hotfix_asks { format!("use05 approve --promote {to_name} --hotfix --note \"<what you checked>\"") } else { ask.clone() };
                        fail("nobody has signed off".into(), "SIGNOFF_REQUIRED", message, Some(next), Vec::new())
                    }
                }
            }
        };
        // A person's bypass clears this one rule for this one promotion. A person's no stays a no.
        let mut verdict = verdict;
        let bypass = verdict.fail.as_ref().filter(|f| f.0 != "SIGNOFF_REJECTED").and_then(|_| input.bypasses.iter().find(|b| b.rule == rule && b.void.is_none()));
        if let Some(b) = bypass {
            verdict.outcome = RuleOutcome::Bypassed;
            verdict.detail = format!("{}; bypassed by {}: \"{}\"", verdict.detail, b.person, b.reason);
        }
        if let Some((code, mut message, next, paths)) = verdict.fail {
            // A rejection is a person's no, whatever the rule's own severity.
            let effect = match bypass {
                _ if code == "SIGNOFF_REJECTED" => Some(Effect::Deny),
                Some(_) => Some(Effect::Info),
                None => effect_for(severity),
            };
            match bypass {
                Some(b) => message.push_str(&format!(" (bypassed by {}: \"{}\")", b.person, b.reason)),
                None => {
                    for b in input.bypasses.iter().filter(|b| b.rule == rule && b.void.is_some()) {
                        message.push_str(&format!("; {}'s bypass does not count: {}", b.person, b.void.as_deref().unwrap_or_default()));
                    }
                }
            }
            let next = if bypass.is_some() { None } else { next };
            if let Some(effect) = effect {
                findings.push(Finding { code, effect, message, paths, next, approvable: effect == Effect::Approval && code != "SIGNOFF_REQUIRED" });
            }
        }
        results.push(RuleResult { rule: rule.to_string(), severity: severity_word(severity), outcome: verdict.outcome, detail: verdict.detail });
    }

    // ------------------------------------------------------------- the rules after it
    if !input.loosened.is_empty() && !nothing {
        findings.push(Finding {
            code: "POLICY_LOOSENED",
            effect: Effect::Approval,
            message: format!("what moves changes 05's rules, and {to_name} would then hold less: {}", input.loosened.join(", ")),
            paths: vec![crate::policy::POLICY_PATH.to_string()],
            next: Some(ask.clone()),
            approvable: true,
        });
    }

    // A person's sign-off approves what an approval can clear.
    if !signed_by.is_empty() {
        for f in findings.iter_mut().filter(|f| f.approvable && f.effect == Effect::Approval) {
            f.effect = Effect::Info;
            f.message.push_str(&format!(" (signed off by {})", signed_by.join(", ")));
        }
    }

    let worst = findings.iter().map(|f| f.effect).max().unwrap_or(Effect::Info);
    let decision = match worst {
        Effect::Deny => Decision::Deny,
        Effect::Approval => Decision::ApprovalRequired,
        Effect::Wait => Decision::Wait,
        Effect::Warn | Effect::Info => Decision::Allow,
    };
    findings.sort_by(|a, b| b.effect.cmp(&a.effect));
    PromoteResult {
        decision,
        findings,
        source_env: from_name.to_string(),
        target_env: to_name.to_string(),
        source_head: input.source_head.clone(),
        target_head: input.target_head.clone(),
        delta: input.delta.clone(),
        rules: results,
        // A back-merge is always a merge commit; a hotfix lands by fast-forward.
        how: match direction {
            Direction::Back => "merge",
            Direction::Hotfix => "fast-forward",
            _ => env.how_word(),
        },
        rollback_point: input.target_head.clone(),
        changed: input.changed.clone(),
        checks: input.checks.clone(),
        signoffs: input.signoffs.clone(),
        bypasses: input.bypasses.clone(),
        signers: signers(policy, env),
        agent_allowed: policy.agent_may_promote(env),
        policy_sha256: policy.digest(),
        direction,
        task: input.task.clone(),
    }
}

// ----------------------------------------------------------------------------- the move

/// A rule's outcome as the records and trailers write it.
pub fn outcome_word(o: RuleOutcome) -> &'static str {
    match o {
        RuleOutcome::Pass => "pass",
        RuleOutcome::Fail => "fail",
        RuleOutcome::Bypassed => "bypassed",
        RuleOutcome::Skipped => "skipped",
        RuleOutcome::Unknown => "unknown",
    }
}

/// The sign-offs that count, which a promotion goes with.
fn counted_signoffs(r: &PromoteResult) -> impl Iterator<Item = &SignOffSeen> {
    r.signoffs.iter().filter(|s| s.void.is_none() && s.decision == Vote::Approve)
}

/// The bypasses a promotion used: counted, for a rule they cleared.
fn used_bypasses(r: &PromoteResult) -> impl Iterator<Item = &BypassSeen> {
    r.bypasses.iter().filter(|b| b.void.is_none() && r.rules.iter().any(|x| x.rule == b.rule && x.outcome == RuleOutcome::Bypassed))
}

/// A promotion's summary as git trailers (D93), for the end of its commit message.
pub fn trailers(r: &PromoteResult) -> Vec<String> {
    let mut t = vec![
        format!("05-Promotion: {} from {}", r.target_env, r.source_env),
        format!("05-Source: {}", r.source_head),
        format!("05-Rules: {}", r.rules.iter().map(|x| format!("{}={}", x.rule, outcome_word(x.outcome))).collect::<Vec<_>>().join(",")),
    ];
    match r.direction {
        Direction::Back => t.insert(1, "05-Direction: back".to_string()),
        Direction::Hotfix => t.insert(1, "05-Direction: hotfix".to_string()),
        _ => {}
    }
    let mut people: Vec<&str> = Vec::new();
    for s in counted_signoffs(r) {
        if !people.iter().any(|p| same_person(p, &s.person)) {
            people.push(&s.person);
        }
    }
    t.extend(people.iter().map(|p| format!("05-Signed-off-by: {p}")));
    let mut rules: Vec<&str> = used_bypasses(r).map(|b| b.rule.as_str()).collect();
    rules.dedup();
    t.extend(rules.iter().map(|rule| format!("05-Bypass: {rule}")));
    t
}

/// The message of the merge commit a promotion with `how = "merge"` makes: what moves, each
/// sign-off in its signer's words, then the trailers.
pub fn merge_message(r: &PromoteResult) -> String {
    let mut m = if r.direction == Direction::Back {
        format!("Merge {} back into {} ({})\n\n{} down from {}.\n", r.source_env, r.target_env, short(&r.source_head), plural(r.delta.len(), "commit comes", "commits come"), r.source_env)
    } else {
        format!("Promote {} into {} ({})\n\n{} from {}.\n", r.source_env, r.target_env, short(&r.source_head), plural(r.delta.len(), "commit moves", "commits move"), r.source_env)
    };
    for s in counted_signoffs(r) {
        m.push_str(&format!("\n{} signed off: {}\n", s.person, s.text.trim()));
    }
    m.push('\n');
    m.push_str(&trailers(r).join("\n"));
    m.push('\n');
    m
}

/// The message of the commit an export to a destination makes (D93): what was copied from where,
/// each sign-off in its signer's words, then the trailers. `folder` is the folder copied, empty
/// for the whole tree.
pub fn export_message(r: &PromoteResult, folder: &str) -> String {
    let what = if folder.is_empty() { "the whole tree".to_string() } else { format!("{folder}/") };
    let mut m = format!("Sync from {}\n\n{what} as {} has it at {}: {} since the last sync.\n", short(&r.source_head), r.source_env, short(&r.source_head), plural(r.delta.len(), "commit changes it", "commits change it"));
    for s in counted_signoffs(r) {
        m.push_str(&format!("\n{} signed off: {}\n", s.person, s.text.trim()));
    }
    m.push('\n');
    m.push_str(&trailers(r).join("\n"));
    m.push('\n');
    m
}

/// The source commit an export's commit names in its `05-Source` trailer: the last sync's.
pub fn synced_from(message: &str) -> Option<String> {
    message.lines().rev().find_map(|l| l.strip_prefix("05-Source:")).map(|v| v.trim().to_string()).filter(|c| matches!(c.len(), 40 | 64) && c.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The record of a promotion that was pushed (D93): what moved, from where to where, the
/// rollback point, each rule's result, and the bypasses and sign-offs it went with. Subject: the
/// source commit.
pub fn record(r: &PromoteResult, result_commit: &str, by: &str, created: String) -> use05_receipt::Statement<use05_receipt::Promotion> {
    use05_receipt::Statement::new(
        vec![use05_receipt::commit_subject(&r.source_head)],
        use05_receipt::Promotion {
            env: r.target_env.clone(),
            from: r.source_env.clone(),
            direction: r.direction,
            source_commit: r.source_head.clone(),
            target_before: r.target_head.clone(),
            result_commit: result_commit.to_string(),
            how: r.how.to_string(),
            rollback_point: r.rollback_point.clone(),
            rules: r.rules.clone(),
            bypasses: used_bypasses(r).map(|b| b.path.clone()).collect(),
            // A hotfix's approvals are the task gate's, filed on its tree: no sign-off receipt to name.
            signoffs: counted_signoffs(r).map(|s| s.path.clone()).filter(|p| !p.is_empty()).collect(),
            policy_sha256: r.policy_sha256.clone(),
            created,
            by: by.to_string(),
            reverts: None,
            task: r.task.clone(),
        },
    )
}

// ----------------------------------------------------------------------------- confirming a deploy

/// One command a deploy's confirmation runs: one try of a probe, or a smoke check.
pub struct DeployCommand<'a> {
    /// `probe` or `smoke`.
    pub kind: &'static str,
    pub name: &'a str,
    pub run: &'a [String],
    /// The variables it is given, by name.
    pub env: &'a [String],
    pub dir: Option<&'a str>,
    pub timeout_secs: u64,
}

/// What running one such command said.
pub enum Answer {
    /// It ran: whether it exited 0 or ran out of time, the end of what it printed, and the
    /// SHA-256 of what it printed.
    Ran { passed: bool, timed_out: bool, stdout: String, stdout_sha256: String },
    /// It could not be run at all, in a few words: "could not run ./probe.sh".
    NotRun(String),
}

/// How a confirmation runs its commands and keeps time: the command line runs them like checks,
/// in an export of the deployed commit; a test answers from a script on a pretend clock.
pub trait DeployRunner {
    fn run(&mut self, command: &DeployCommand<'_>) -> Answer;
    /// Seconds, on a clock that only moves forward.
    fn now(&self) -> u64;
    fn sleep(&mut self, secs: u64);
}

/// A deploy's confirmation: its record (unsigned), and a line for each probe and smoke check.
pub struct Confirmation {
    pub deployment: use05_receipt::Deployment,
    /// `("probe version", "showed it after 2 tries in 20s")`, in the order they ran.
    pub said: Vec<(String, String)>,
}

/// The fewest leading characters of a commit id a probe must print for it to count.
pub const SHOWN_MIN: usize = 12;

/// Whether `output` names `commit`: a run of hexadecimal characters (any case) that is the whole
/// id or [`SHOWN_MIN`] or more of its first characters. A longer or different run does not count,
/// so another commit that merely contains those characters is not taken for it.
pub fn shows_commit(output: &str, commit: &str) -> bool {
    let commit = commit.to_ascii_lowercase();
    output.to_ascii_lowercase().split(|c: char| !c.is_ascii_hexdigit()).any(|run| run.len() >= SHOWN_MIN && commit.starts_with(run))
}

fn minutes(n: u32) -> String {
    plural(n as usize, "minute", "minutes")
}

/// Confirm that `env` runs `commit` (D93): ask every probe until its output names the commit
/// (exiting 0) or `wait_minutes` pass, sleeping `interval_secs` between tries; a probe that
/// cannot be run fails at once. Then run each smoke check once. Confirmed only when there is a
/// probe, every probe showed the commit and every smoke check passed: never without a probe.
/// The record is dated when the confirmation ends, by the runner's clock.
pub fn confirm(env: &Environment, commit: &str, runner: &mut dyn DeployRunner) -> Confirmation {
    let shown = short(commit).to_string();
    let mut said = Vec::new();
    let mut probes = Vec::new();
    for p in &env.probe {
        let command = DeployCommand { kind: "probe", name: &p.name, run: &p.run, env: &p.env, dir: p.dir.as_deref(), timeout_secs: p.timeout_secs };
        let start = runner.now();
        let deadline = start + u64::from(p.wait_minutes) * 60;
        let (mut attempts, mut matched, mut output_sha256) = (0u32, false, String::new());
        let last = loop {
            attempts += 1;
            let answer = runner.run(&command);
            if let Answer::Ran { passed, stdout, stdout_sha256, .. } = &answer {
                output_sha256 = stdout_sha256.clone();
                matched = *passed && shows_commit(stdout, commit);
            }
            if matched || matches!(answer, Answer::NotRun(_)) || runner.now() + u64::from(p.interval_secs) > deadline {
                break answer;
            }
            runner.sleep(u64::from(p.interval_secs));
        };
        let seconds = runner.now().saturating_sub(start);
        let tries = plural(attempts as usize, "try", "tries");
        let line = match last {
            Answer::NotRun(why) => why,
            _ if matched && attempts == 1 => "showed it on the first try".to_string(),
            _ if matched => format!("showed it after {tries} in {seconds}s"),
            last => {
                let within = if p.wait_minutes == 0 { format!("({tries})") } else { format!("in {} ({tries})", minutes(p.wait_minutes)) };
                let how = match last {
                    Answer::Ran { timed_out: true, .. } => format!("; its last try ran out of time ({}s)", p.timeout_secs),
                    Answer::Ran { passed: false, .. } => "; its last try failed".to_string(),
                    _ => String::new(),
                };
                format!("did not show {shown} {within}{how}")
            }
        };
        said.push((format!("probe {}", p.name), line));
        probes.push(use05_receipt::ProbeResult { name: p.name.clone(), matched, output_sha256, attempts, seconds });
    }
    let mut smoke = Vec::new();
    for c in &env.smoke {
        let answer = runner.run(&DeployCommand { kind: "smoke", name: &c.name, run: &c.run, env: &c.env, dir: c.dir.as_deref(), timeout_secs: c.timeout_secs });
        let (passed, line) = match answer {
            Answer::Ran { timed_out: true, .. } => (false, format!("ran out of time ({}s)", c.timeout_secs)),
            Answer::Ran { passed, .. } => (passed, if passed { "passed" } else { "failed" }.to_string()),
            Answer::NotRun(why) => (false, why),
        };
        said.push((format!("smoke {}", c.name), line));
        smoke.push(use05_receipt::SmokeResult { name: c.name.clone(), passed });
    }
    let confirmed = !probes.is_empty() && probes.iter().all(|p| p.matched) && smoke.iter().all(|s| s.passed);
    Confirmation { deployment: use05_receipt::Deployment { env: env.name.clone(), commit: commit.to_string(), probes, smoke, confirmed, created: crate::time::rfc3339(runner.now()), action: use05_receipt::DeployAction::None }, said }
}

/// Where a revert of an environment goes back to: the branch's head before the newest promotion
/// into it that counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPoint {
    /// The commit whose files a revert restores. `None`: that promotion created the branch, so
    /// there is nothing to go back to.
    pub to: Option<String>,
    /// That promotion's result, which the branch's head is or contains.
    pub result: String,
    /// The environment it was promoted from, and which way.
    pub from: String,
    pub direction: use05_receipt::Direction,
    /// Its record, by path.
    pub record: String,
}

/// The rollback point of `env`, whose branch is at `head`: the `target_before` of the newest
/// promotion record into it that counts (signed by a key of a kind `accept` takes) and that the
/// branch still holds (its result is `head` or behind it). A revert 05 made is not a promotion to
/// go back from. `None` when no such record is there, or when what it says the branch was is not
/// in the branch's history: for a merge, the result's first parent; otherwise an ancestor of the
/// result. A record is a machine's word, and a revert to its `target_before` passes no rule, so a
/// point off the branch's own history is never taken.
pub fn rollback_point(top: &Path, found: &Found, accept: &[crate::policy::Role], env: &str, head: &str) -> Option<RollbackPoint> {
    let mut records: Vec<_> = found
        .promotions
        .iter()
        .filter(|p| accept.contains(&p.signer.role))
        .filter(|p| p.statement.predicate.env == env && p.statement.predicate.reverts.is_none())
        .filter(|p| p.statement.commit_subject() == Some(p.statement.predicate.source_commit.as_str()))
        .collect();
    records.sort_by(|a, b| b.statement.predicate.created.cmp(&a.statement.predicate.created));
    let newest = records.into_iter().find(|p| {
        let result = &p.statement.predicate.result_commit;
        result == head || git::run(top, &["merge-base", "--is-ancestor", result, head]).is_ok()
    })?;
    let p = &newest.statement.predicate;
    if let Some(before) = &p.target_before {
        let in_history = if p.how == "merge" {
            git::text(top, &["rev-parse", "--verify", "--quiet", &format!("{}^1", p.result_commit)]).ok().is_some_and(|first| first.trim() == before)
        } else {
            before != &p.result_commit && git::run(top, &["merge-base", "--is-ancestor", before, &p.result_commit]).is_ok()
        };
        if !in_history {
            return None;
        }
    }
    Some(RollbackPoint { to: p.target_before.clone(), result: p.result_commit.clone(), from: p.from.clone(), direction: p.direction, record: newest.path.clone() })
}

/// The hotfix tasks that landed as one of `commits`, by the counted hotfix records (`direction =
/// "hotfix"`, signed by a key of a kind `accept` takes), each once, oldest first. On any
/// environment: a hotfix of prod merged back into uat puts uat ahead of the rung below too.
pub fn hotfixes_among(found: &Found, accept: &[crate::policy::Role], commits: &[String]) -> Vec<String> {
    let mut records: Vec<_> = found
        .promotions
        .iter()
        .filter(|p| accept.contains(&p.signer.role))
        .map(|p| &p.statement)
        .filter(|s| s.predicate.direction == Direction::Hotfix && s.commit_subject() == Some(s.predicate.source_commit.as_str()))
        .filter(|s| commits.contains(&s.predicate.result_commit))
        .collect();
    records.sort_by(|a, b| a.predicate.created.cmp(&b.predicate.created));
    let mut tasks: Vec<String> = Vec::new();
    for t in records.iter().filter_map(|s| s.predicate.task.clone()) {
        if !tasks.contains(&t) {
            tasks.push(t);
        }
    }
    tasks
}

/// The message of a revert commit 05 makes (D93): what it restores and why, then its trailers.
pub fn revert_message(env: &str, to: &str, reverts: &str, why: &str) -> String {
    format!("Revert {env} to {} ({why})\n\n{env} ran {} and goes back to the files of {}.\n\n05-Revert: {env}\n05-Reverts: {reverts}\n05-Rollback-To: {to}\n", short(to), short(reverts), short(to))
}

/// The record of a revert 05 pushed: a promotion record whose `how` is `revert` and whose
/// `reverts` names the head it undid, keeping the direction and source of the promotion it
/// undoes. Subject: the revert commit, which is what moved.
#[allow(clippy::too_many_arguments)]
pub fn revert_record(env: &str, from: &str, direction: use05_receipt::Direction, revert: &str, reverts: &str, policy_sha256: &str, by: &str, created: String) -> use05_receipt::Statement<use05_receipt::Promotion> {
    use05_receipt::Statement::new(
        vec![use05_receipt::commit_subject(revert)],
        use05_receipt::Promotion {
            env: env.to_string(),
            from: from.to_string(),
            direction,
            source_commit: revert.to_string(),
            target_before: Some(reverts.to_string()),
            result_commit: revert.to_string(),
            how: "revert".to_string(),
            rollback_point: None,
            rules: Vec::new(),
            bypasses: Vec::new(),
            signoffs: Vec::new(),
            policy_sha256: policy_sha256.to_string(),
            created,
            by: by.to_string(),
            reverts: Some(reverts.to_string()),
            task: None,
        },
    )
}

// ----------------------------------------------------------------------------- gathering

/// A commit that would move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moving {
    pub id: String,
    pub tree: String,
    /// Committer time, in seconds.
    pub time: u64,
    pub parents: Vec<String>,
    pub subject: String,
}

/// The commits on `head` that `base` lacks, oldest first; every commit of `head` when there is no
/// base (the target branch does not exist yet).
pub fn commits(top: &Path, head: &str, base: Option<&str>) -> crate::Result<Vec<Moving>> {
    commits_touching(top, head, base, &[])
}

/// As [`commits`], only those that change something under one of `paths` (all of them when
/// `paths` is empty): what an export of a folder carries.
pub fn commits_touching(top: &Path, head: &str, base: Option<&str>, paths: &[&str]) -> crate::Result<Vec<Moving>> {
    let mut args = vec!["log", "--topo-order", "--reverse", "--format=%H%x00%T%x00%ct%x00%P%x00%s", head];
    let not;
    if let Some(base) = base {
        not = format!("^{base}");
        args.push(&not);
    }
    args.push("--");
    args.extend(paths);
    let text = git::text(top, &args)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\0');
            let (id, tree, time, parents, subject) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next().unwrap_or(""));
            Some(Moving { id: id.to_string(), tree: tree.to_string(), time: time.parse().unwrap_or(0), parents: parents.split_whitespace().map(str::to_string).collect(), subject: subject.to_string() })
        })
        .collect())
}

/// A merge commit that brings nothing of its own: its tree is one of its parents' trees, as the
/// merge commits 05's promotions make are. Its parents' commits are judged on their own.
fn adds_nothing(top: &Path, c: &Moving, trees: &HashMap<&str, &str>) -> bool {
    c.parents.len() >= 2 && c.parents.iter().any(|p| trees.get(p.as_str()).map(|t| t.to_string()).or_else(|| git::resolve_tree(top, p).ok()).is_some_and(|t| t == c.tree))
}

/// The commits on the target the source lacks, which a promotion would lose or mix in unseen.
/// With `how = "merge"`, a merge commit that brings nothing of its own (an earlier promotion's)
/// is not counted: everything in it came from the source. A fast-forward has no such room.
pub fn target_ahead(top: &Path, ahead: &[Moving], how: crate::policy::PromoteHow) -> Vec<String> {
    let trees: HashMap<&str, &str> = ahead.iter().map(|c| (c.id.as_str(), c.tree.as_str())).collect();
    ahead.iter().filter(|c| how == crate::policy::PromoteHow::FastForward || !adds_nothing(top, c, &trees)).map(|c| c.id.clone()).collect()
}

/// What a finish records as its task's base: where the finished commit (`HEAD`) meets the landing
/// branch now. Both this machine's copy and origin's are asked, and the meeting point nearer
/// `HEAD` is kept: work rebased onto origin's newer branch meets it later than the local copy
/// that has not caught up. Not where the task began: work rebased since would otherwise claim
/// what it was rebased onto. `None` when there is no such branch or commit.
pub fn finish_base(top: &Path, landing: &str) -> Option<String> {
    let head = git::head_commit(top)?;
    [format!("refs/heads/{landing}"), format!("refs/remotes/origin/{landing}")]
        .iter()
        .filter(|r| git::resolve_commit(top, r).is_some())
        .filter_map(|r| git::merge_base(top, r, &head))
        .min_by_key(|base| git::count_commits(top, base, &head))
}

/// A recorded base counts only as a full commit id that is an ancestor of the finished commit.
fn valid_base(top: &Path, base: &str, finished: &str) -> bool {
    matches!(base.len(), 40 | 64) && base.bytes().all(|b| b.is_ascii_hexdigit()) && git::run(top, &["merge-base", "--is-ancestor", base, finished]).is_ok()
}

/// The commits in `delta` that belong to no 05 task, decided from the receipts alone so CI decides
/// the same (D93). Only records from a key whose kind `accept` (the policy's `evidence.accept`)
/// takes count: with `["runner"]`, only CI's. A commit belongs to a task when:
/// - its tree is one a task finished on (an `outcome/v0` record, which `use05 finish` writes, names
///   that tree);
/// - or that record names the task's base, and the commit is between the base and the finished
///   commit (on the finished commit's history, not on the base's), stopping at any other task's
///   finished commit and any promotion's result. A base counts only as a full commit id that is
///   an ancestor of the finished commit; otherwise, as with no base, only the finished commit
///   counts. This is the local reading: CI works the range out itself and never takes a
///   machine's `base`;
/// - or a promotion record names it as its result, or it is a merge commit that brings nothing of
///   its own (its tree is one of its parents' trees), as 05's promotions make.
pub fn untasked(top: &Path, delta: &[Moving], found: &Found, accept: &[crate::policy::Role]) -> Vec<String> {
    let trees: HashMap<&str, &str> = delta.iter().map(|c| (c.id.as_str(), c.tree.as_str())).collect();
    let in_delta: HashSet<&str> = delta.iter().map(|c| c.id.as_str()).collect();
    // The tree each task finished on, with the base each record names.
    let mut finished: HashMap<&str, Vec<Option<&str>>> = HashMap::new();
    for c in found.completions.iter().filter(|c| accept.contains(&c.signer.role)) {
        if let Some((tree, _)) = c.statement.tree_subject() {
            finished.entry(tree).or_default().push(c.statement.predicate.base.as_deref());
        }
    }
    let promoted: HashSet<&str> = found.promotions.iter().filter(|p| accept.contains(&p.signer.role)).map(|p| p.statement.predicate.result_commit.as_str()).collect();
    // Where every range stops: each counted task's finished commit, and each promotion's result.
    let landings: Vec<&Moving> = delta.iter().filter(|c| finished.contains_key(c.tree.as_str())).collect();
    let stops: Vec<&str> = landings.iter().map(|c| c.id.as_str()).chain(delta.iter().map(|c| c.id.as_str()).filter(|c| promoted.contains(c))).collect();
    let mut tasked: HashSet<String> = HashSet::new();
    for landing in &landings {
        tasked.insert(landing.id.clone());
        // A machine's `base` is its word. Locally it marks the range from there to the finished
        // commit, when it is a full commit id that is the finished commit's ancestor; anything else
        // is no base. CI works the range out for itself and never takes a machine's `base` (D93).
        for base in finished[landing.tree.as_str()].iter().flatten().filter(|b| valid_base(top, b, &landing.id)) {
            let mut args = vec!["rev-list".to_string(), landing.id.clone(), format!("^{base}")];
            args.extend(stops.iter().filter(|s| **s != landing.id).map(|s| format!("^{s}")));
            args.push("--".into());
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let range = git::text(top, &args).unwrap_or_default();
            tasked.extend(range.lines().filter(|c| in_delta.contains(c)).map(str::to_string));
        }
    }
    delta
        .iter()
        .filter(|c| !tasked.contains(&c.id) && !promoted.contains(c.id.as_str()) && !adds_nothing(top, c, &trees))
        .map(|c| c.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Signer;
    use crate::policy::Role;

    const LADDER: &str = "[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"uat\"\nbranch = \"uat\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n";

    fn policy(extra: &str) -> Policy {
        Policy::parse(&format!("[[check]]\nname = \"test\"\nrun = [\"true\"]\n\n{LADDER}{extra}")).unwrap()
    }

    const NOW: u64 = 1_800_000_000;

    fn passed() -> CheckStatus {
        CheckStatus { name: "test".into(), run: vec!["true".into()], dir: None, paths: Vec::new(), required: true, state: CheckState::Passed { by: Signer { name: "ci".into(), role: Role::Runner, key_id: "k".into() }, ms: 1 } }
    }

    /// Everything holds: a fast-forward of two tasked commits whose checks passed on a confirmed source.
    fn input<'a>(p: &'a Policy) -> PromoteInput<'a> {
        PromoteInput {
            policy: p,
            target: p.environment_named("prod").unwrap(),
            source: "uat",
            source_deployed: true,
            source_head: "a1".repeat(20),
            target_head: Some("b2".repeat(20)),
            expected_source: None,
            delta: vec!["c3".repeat(20), "a1".repeat(20)],
            target_only: Vec::new(),
            changed: vec!["src/lib.rs".into()],
            checks: vec![passed()],
            deployments: vec![DeploymentSeen { confirmed: true, created: crate::time::rfc3339(NOW - 7200), by: "ci".into(), probes: 1 }],
            untasked: Vec::new(),
            signoffs: Vec::new(),
            bypasses: Vec::new(),
            loosened: Vec::new(),
            agent: false,
            now: NOW,
            notes: Vec::new(),
            direction: Direction::Up,
            task: None,
            hotfixes: Vec::new(),
        }
    }

    fn rule<'r>(r: &'r PromoteResult, name: &str) -> &'r RuleResult {
        r.rules.iter().find(|x| x.rule == name).unwrap()
    }

    fn codes(r: &PromoteResult) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn a_promotion_that_holds_every_rule_is_allowed_and_lists_each_rule() {
        let p = policy("");
        let r = evaluate(&input(&p));
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.findings);
        assert_eq!(r.rules.iter().map(|x| x.rule.as_str()).collect::<Vec<_>>(), crate::policy::PROMOTE_RULES);
        assert_eq!(rule(&r, "source_checks").outcome, RuleOutcome::Pass);
        assert_eq!(rule(&r, "soak").outcome, RuleOutcome::Skipped, "no soak time set");
        assert_eq!(rule(&r, "sign_off").outcome, RuleOutcome::Skipped, "not asked for");
        assert_eq!((r.how, r.rollback_point.clone()), ("fast-forward", Some("b2".repeat(20))));
        assert!(!r.agent_allowed, "prod is the last rung");
    }

    #[test]
    fn source_checks_fail_when_a_required_check_did_not_pass_on_the_source_head() {
        let p = policy("");
        let mut i = input(&p);
        i.checks[0].state = CheckState::Missing;
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(rule(&r, "source_checks").outcome, RuleOutcome::Fail);
        let f = r.findings.iter().find(|f| f.code == "SOURCE_CHECKS_MISSING").unwrap();
        assert!(f.message.contains("test not proved") && f.next.as_deref().unwrap().contains(&format!("use05 prove test --tree {}", "a1".repeat(6))), "{f:?}");
        // A check whose paths nothing that moves touches is not asked for.
        i.checks[0].state = CheckState::NotRequired { reason: crate::gate::NOT_REQUIRED_REASON, result: None };
        assert_eq!(rule(&evaluate(&i), "source_checks").outcome, RuleOutcome::Pass);
    }

    #[test]
    fn source_confirmed_needs_a_confirmed_deployment_of_the_head() {
        let p = policy("");
        let mut i = input(&p);
        assert_eq!(rule(&evaluate(&i), "source_confirmed").outcome, RuleOutcome::Pass);
        i.deployments[0].confirmed = false;
        let r = evaluate(&i);
        assert_eq!(rule(&r, "source_confirmed").outcome, RuleOutcome::Fail);
        assert_eq!(r.findings[0].code, "SOURCE_NOT_CONFIRMED");
        assert_eq!((r.findings[0].effect, r.decision), (Effect::Warn, Decision::Allow), "warn by default");
        i.deployments.clear();
        assert!(evaluate(&i).findings[0].message.contains("no deployment record"));
    }

    #[test]
    fn soak_counts_from_the_confirmed_deployment() {
        let p = policy("soak_minutes = 60\n\n[environment.rules]\nsoak = \"deny\"\n");
        let mut i = input(&p);
        assert_eq!(rule(&evaluate(&i), "soak").outcome, RuleOutcome::Pass, "two hours in uat");
        i.deployments[0].created = crate::time::rfc3339(NOW - 600);
        let r = evaluate(&i);
        assert_eq!((rule(&r, "soak").outcome, r.decision), (RuleOutcome::Fail, Decision::Deny));
        assert!(r.findings.iter().any(|f| f.code == "SOAK_NOT_DONE" && f.message.contains("10 minutes")), "{:?}", r.findings);
        i.deployments.clear();
        assert!(evaluate(&i).findings.iter().any(|f| f.code == "SOAK_NOT_DONE" && f.message.contains("have not started")));
    }

    #[test]
    fn migrations_in_what_moves_need_a_persons_sign_off() {
        let p = policy("");
        let mut i = input(&p);
        assert_eq!(rule(&evaluate(&i), "migrations").outcome, RuleOutcome::Pass);
        i.changed.push("db/migrations/001_add.sql".into());
        let r = evaluate(&i);
        assert_eq!((rule(&r, "migrations").outcome, r.decision), (RuleOutcome::Fail, Decision::ApprovalRequired));
        let f = r.findings.iter().find(|f| f.code == "MIGRATIONS_IN_DELTA").unwrap();
        assert_eq!(f.paths, ["db/migrations/001_add.sql"]);
        // A counted sign-off is that person's approval.
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Approve, text: "ran it on a copy".into(), confirmations: vec![], path: "p".into(), void: None });
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.code == "MIGRATIONS_IN_DELTA" && f.effect == Effect::Info && f.message.ends_with("(signed off by Dana)")));
    }

    #[test]
    fn untasked_commits_are_named() {
        let p = policy("[environment.rules]\nuntasked = \"approval\"\n");
        let mut i = input(&p);
        assert_eq!(rule(&evaluate(&i), "untasked").outcome, RuleOutcome::Pass);
        i.untasked = vec!["c3".repeat(20)];
        let r = evaluate(&i);
        assert_eq!((rule(&r, "untasked").outcome, r.decision), (RuleOutcome::Fail, Decision::ApprovalRequired));
        assert!(r.findings.iter().any(|f| f.code == "UNTASKED_COMMITS" && f.message.contains(&"c3".repeat(6))));
    }

    #[test]
    fn a_sign_off_is_needed_when_the_rule_asks_and_confirmations_ask_for_one() {
        let p = policy("[environment.rules]\nsign_off = \"approval\"\n");
        let mut i = input(&p);
        let r = evaluate(&i);
        assert_eq!((rule(&r, "sign_off").outcome, r.decision), (RuleOutcome::Fail, Decision::ApprovalRequired));
        assert!(r.findings.iter().any(|f| f.code == "SIGNOFF_REQUIRED"));
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Approve, text: "t".into(), confirmations: vec![], path: "p".into(), void: Some("expired".into()) });
        let r = evaluate(&i);
        assert!(r.findings.iter().any(|f| f.code == "SIGNOFF_REQUIRED" && f.message.contains("Dana's does not count: expired")), "{:?}", r.findings);
        i.signoffs[0].void = None;
        let r = evaluate(&i);
        assert_eq!((rule(&r, "sign_off").outcome, r.decision), (RuleOutcome::Pass, Decision::Allow));
        i.signoffs[0].decision = Vote::Reject;
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Deny, "a person's no denies");
        assert!(codes(&r).contains(&"SIGNOFF_REJECTED"));
        // A statement only a person can give makes a sign-off needed, even where the rule allows.
        let confirm = policy("[[environment.confirm]]\ntext = \"The release notes are published\"\n");
        let r = evaluate(&input(&confirm));
        assert_eq!((rule(&r, "sign_off").severity, r.decision), (RuleSeverity::Approval, Decision::ApprovalRequired));
    }

    #[test]
    fn a_counted_rejection_denies_even_where_no_sign_off_is_asked() {
        let p = policy("");
        let mut i = input(&p);
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Reject, text: "not this week".into(), confirmations: vec![], path: "p".into(), void: None });
        let r = evaluate(&i);
        assert_eq!((r.decision, rule(&r, "sign_off").outcome), (Decision::Deny, RuleOutcome::Fail), "{:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.code == "SIGNOFF_REJECTED" && f.effect == Effect::Deny && f.message.contains("not this week")));
        i.signoffs[0].void = Some("expired".into());
        assert_eq!(evaluate(&i).decision, Decision::Allow, "a rejection that does not count is no rejection");
    }

    fn deployed(confirmed: bool, minutes_ago: u64) -> DeploymentSeen {
        DeploymentSeen { confirmed, created: crate::time::rfc3339(NOW - minutes_ago * 60), by: "ci".into(), probes: 1 }
    }

    #[test]
    fn source_confirmed_is_judged_from_the_newest_record() {
        let p = policy("");
        let mut i = input(&p);
        i.deployments = vec![deployed(true, 120), deployed(false, 10)];
        let r = evaluate(&i);
        assert_eq!(rule(&r, "source_confirmed").outcome, RuleOutcome::Fail, "a newer record that does not confirm it wins");
        assert!(r.findings.iter().any(|f| f.code == "SOURCE_NOT_CONFIRMED" && f.message.contains("was not confirmed")));
        i.deployments = vec![deployed(false, 120), deployed(true, 10)];
        assert_eq!(rule(&evaluate(&i), "source_confirmed").outcome, RuleOutcome::Pass);
    }

    #[test]
    fn soak_counts_from_the_start_of_the_current_run_of_confirmed_records() {
        let p = policy("soak_minutes = 60\n\n[environment.rules]\nsoak = \"deny\"\n");
        let mut i = input(&p);
        // Confirmed two hours ago, broken, then confirmed again 30 and 5 minutes ago: 30 minutes.
        i.deployments = vec![deployed(true, 120), deployed(false, 40), deployed(true, 30), deployed(true, 5)];
        let r = evaluate(&i);
        assert_eq!(rule(&r, "soak").outcome, RuleOutcome::Fail, "{:?}", r.rules);
        assert!(rule(&r, "soak").detail.contains("30 of 60"), "{}", rule(&r, "soak").detail);
        i.deployments = vec![deployed(true, 90), deployed(true, 5)];
        assert_eq!(rule(&evaluate(&i), "soak").outcome, RuleOutcome::Pass, "an unbroken run counts from its first record");
        i.deployments = vec![deployed(true, 90), deployed(false, 5)];
        assert!(rule(&evaluate(&i), "soak").detail.contains("has not started"), "the newest record does not confirm it");
    }

    #[test]
    fn a_tamper_finding_from_gathering_keeps_its_deny() {
        let p = policy("[environment.rules]\nsource_checks = \"allow\"\n");
        let mut i = input(&p);
        i.notes.push(Finding { code: "TREE_DIGEST_MISMATCH", effect: Effect::Deny, message: "m".into(), paths: vec![], next: None, approvable: false });
        assert_eq!(evaluate(&i).decision, Decision::Deny);
    }

    #[test]
    fn the_target_having_commits_the_source_lacks_is_always_denied() {
        let p = policy("[environment.rules]\nsource_checks = \"allow\"\nsource_confirmed = \"allow\"\nmigrations = \"allow\"\nuntasked = \"allow\"\n");
        let mut i = input(&p);
        i.target_only = vec!["d4".repeat(20)];
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.findings[0].code, "PROMOTE_TARGET_AHEAD");
        assert!(!r.findings[0].approvable, "never cleared by a sign-off");
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Approve, text: "t".into(), confirmations: vec![], path: "p".into(), void: None });
        assert_eq!(evaluate(&i).decision, Decision::Deny);
    }

    #[test]
    fn only_the_evaluated_head_is_promoted() {
        let p = policy("");
        let mut i = input(&p);
        i.expected_source = Some("a1".repeat(20));
        assert_eq!(evaluate(&i).decision, Decision::Allow);
        i.expected_source = Some("e5".repeat(20));
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code), (Decision::Deny, "PROMOTE_NOT_EVALUATED_HEAD"));
    }

    #[test]
    fn an_agent_may_not_promote_where_the_policy_keeps_it_for_people() {
        let p = policy("");
        let mut i = input(&p);
        i.agent = true;
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code), (Decision::Deny, "AGENT_MAY_NOT_PROMOTE"));
        i.target = p.environment_named("uat").unwrap();
        i.source = "dev";
        assert!(!codes(&evaluate(&i)).contains(&"AGENT_MAY_NOT_PROMOTE"), "below the last rung an agent may");
        let solo = policy("agent = true\n");
        let mut i = input(&solo);
        i.agent = true;
        assert_eq!(evaluate(&i).decision, Decision::Allow);
    }

    #[test]
    fn a_destination_is_judged_by_the_same_rules_and_is_kept_from_agents_unless_it_says_so() {
        let p = policy("\n[[destination]]\nname = \"public\"\nhow = \"export\"\nfrom = \"product/\"\nremote = \"/srv/public.git\"\nbranch = \"main\"\n\n[destination.rules]\nuntasked = \"deny\"\n");
        let mut i = input(&p);
        i.target = p.destination_named("public").unwrap();
        i.source = "main";
        i.source_deployed = false;
        i.deployments.clear();
        let r = evaluate(&i);
        assert_eq!((r.decision, r.how, r.target_env.as_str(), r.source_env.as_str()), (Decision::Allow, "export", "public", "main"), "{:?}", r.findings);
        assert_eq!(r.rules.iter().map(|x| x.rule.as_str()).collect::<Vec<_>>(), crate::policy::PROMOTE_RULES, "every rule is listed");
        assert_eq!((rule(&r, "source_confirmed").outcome, rule(&r, "soak").outcome), (RuleOutcome::Skipped, RuleOutcome::Skipped), "a branch is no environment: nothing deploys it");
        assert!(rule(&r, "source_confirmed").detail.contains("main is a branch, not an environment"), "{:?}", rule(&r, "source_confirmed"));
        i.untasked = vec!["c3".repeat(20)];
        assert_eq!(evaluate(&i).decision, Decision::Deny, "its own rules");
        i.untasked.clear();
        i.agent = true;
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code, r.agent_allowed), (Decision::Deny, "AGENT_MAY_NOT_PROMOTE", false), "unset, agent is false for a destination");
        // Its source an environment: source_confirmed is judged from that environment's records.
        i.agent = false;
        i.source = "dev";
        i.source_deployed = true;
        assert_eq!(rule(&evaluate(&i), "source_confirmed").outcome, RuleOutcome::Fail);
    }

    #[test]
    fn nothing_to_promote_is_said_and_skips_the_rules() {
        let p = policy("");
        let mut i = input(&p);
        i.delta.clear();
        i.checks[0].state = CheckState::Missing;
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code, r.findings[0].effect), (Decision::Allow, "NOTHING_TO_PROMOTE", Effect::Info));
        assert!(r.rules.iter().all(|x| x.outcome == RuleOutcome::Skipped));
    }

    #[test]
    fn a_target_ahead_by_a_hotfix_names_the_task_and_the_merge_back() {
        let p = policy("");
        let mut i = input(&p);
        i.target_only = vec!["d4".repeat(20)];
        i.hotfixes = vec!["1a2b3c4d".into()];
        let r = evaluate(&i);
        let f = &r.findings[0];
        assert_eq!((r.decision, f.code), (Decision::Deny, "PROMOTE_TARGET_AHEAD"));
        assert!(f.message.ends_with("; they come from the hotfix task 1a2b3c4d"), "{}", f.message);
        assert_eq!(f.next.as_deref(), Some("merge it down into uat first: use05 promote uat --back"));
    }

    #[test]
    fn a_back_merge_skips_the_source_rules_and_judges_the_rest() {
        let p = policy("[environment.rules]\nsource_checks = \"deny\"\nsoak = \"deny\"\nuntasked = \"deny\"\n");
        let mut i = input(&p);
        // prod merges back down into uat: uat's rules, with prod as the source.
        i.target = p.environment_named("uat").unwrap();
        i.source = "prod";
        i.direction = Direction::Back;
        i.checks[0].state = CheckState::Missing;
        i.deployments.clear();
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.findings);
        for rule_name in ["source_checks", "source_confirmed", "soak"] {
            assert_eq!(rule(&r, rule_name).outcome, RuleOutcome::Skipped, "{rule_name}");
            assert_eq!(rule(&r, rule_name).detail, "not judged when merging back down");
        }
        assert_eq!((r.how, r.direction), ("merge", Direction::Back), "always a merge commit");
        i.changed.push("db/migrations/001.sql".into());
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::ApprovalRequired, "uat's own migrations rule still holds");
        assert!(r.findings.iter().any(|f| f.code == "MIGRATIONS_IN_DELTA" && f.next.as_deref().is_some_and(|n| n.contains("use05 approve --promote uat --back"))), "{:?}", r.findings);
        let t = trailers(&r);
        assert_eq!(t[..2], ["05-Promotion: uat from prod".to_string(), "05-Direction: back".to_string()]);
        assert!(merge_message(&r).starts_with(&format!("Merge prod back into uat ({})\n\n2 commits come down from prod.\n", "a1".repeat(6))), "{}", merge_message(&r));
        let rec = record(&r, &"f0".repeat(20), "Dana", "2026-11-04T00:00:00Z".into());
        assert_eq!((rec.predicate.direction, rec.predicate.how.as_str(), rec.predicate.task.as_deref()), (Direction::Back, "merge", None));
        // An agent where people merge back.
        let people = Policy::parse(&format!("{LADDER}\n[[environment]]\nname = \"top\"\nbranch = \"top\"\nlevel = \"prod\"\n").replace("name = \"prod\"\nbranch = \"prod\"\n", "name = \"prod\"\nbranch = \"prod\"\nlevel = \"pre-prod\"\nagent = false\n")).unwrap();
        let mut i = input(&people);
        i.target = people.environment_named("prod").unwrap();
        i.source = "top";
        i.direction = Direction::Back;
        i.agent = true;
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code), (Decision::Deny, "AGENT_MAY_NOT_PROMOTE"));
        assert!(r.findings[0].message.contains("may not merge back into prod") && r.findings[0].next.as_deref() == Some("ask a person to run: use05 promote prod --back"), "{:?}", r.findings[0]);
        i.delta.clear();
        assert!(codes(&evaluate(&i)).contains(&"NOTHING_TO_MERGE_BACK"));
    }

    #[test]
    fn a_hotfix_is_held_to_its_own_rules_and_an_approval_is_its_sign_off() {
        let p = policy("[environment.rules]\nsource_checks = \"deny\"\nsign_off = \"approval\"\n");
        let mut i = input(&p);
        i.source = "prod";
        i.direction = Direction::Hotfix;
        i.task = Some("1a2b3c4d".into());
        i.checks[0].state = CheckState::Missing;
        i.deployments.clear();
        let r = evaluate(&i);
        assert_eq!(rule(&r, "source_checks").outcome, RuleOutcome::Skipped, "unset, the source rules allow a hotfix");
        assert_eq!(r.decision, Decision::ApprovalRequired, "prod's own sign_off rule: {:?}", r.findings);
        let f = r.findings.iter().find(|f| f.code == "SIGNOFF_REQUIRED").unwrap();
        assert!(f.message.contains("needs a person's approval of its outcome") && f.next.as_deref() == Some("ask a person to approve it: use05 approve --outcome"), "{f:?}");
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Approve, text: "fix checked".into(), confirmations: vec![], path: "p".into(), void: None });
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.findings);
        let rec = record(&r, &"a1".repeat(20), "Dana", "2026-11-04T00:00:00Z".into());
        assert_eq!((rec.predicate.direction, rec.predicate.how.as_str(), rec.predicate.from.as_str(), rec.predicate.task.as_deref()), (Direction::Hotfix, "fast-forward", "prod", Some("1a2b3c4d")));
        // [environment.hotfix.rules] can ask for more, and an agent may land one.
        let strict = policy("[environment.hotfix.rules]\nsource_checks = \"deny\"\n");
        let mut i = input(&strict);
        i.direction = Direction::Hotfix;
        i.agent = true;
        i.checks[0].state = CheckState::Missing;
        let r = evaluate(&i);
        assert_eq!(rule(&r, "source_checks").outcome, RuleOutcome::Fail);
        assert!(r.findings.iter().any(|f| f.code == "SOURCE_CHECKS_MISSING" && f.message.contains("on the hotfix")), "{:?}", r.findings);
        assert!(!codes(&r).contains(&"AGENT_MAY_NOT_PROMOTE"));
    }

    #[test]
    fn hotfixes_are_named_by_counted_records_of_what_landed() {
        let hotfix = |result: &str, task: &str, role: Role| {
            let mut p = promoted("prod", Some(&"b2".repeat(20)), result, "2026-11-01T00:00:00Z", role, None);
            p.statement.predicate.direction = Direction::Hotfix;
            p.statement.predicate.task = Some(task.into());
            p
        };
        let mut found = Found::default();
        found.promotions.push(hotfix(&"d4".repeat(20), "1a2b3c4d", Role::Local));
        found.promotions.push(hotfix(&"e5".repeat(20), "5e6f7a8b", Role::Local));
        found.promotions.push(promoted("prod", None, &"c3".repeat(20), "2026-11-02T00:00:00Z", Role::Local, None));
        let ahead = vec!["d4".repeat(20), "c3".repeat(20)];
        assert_eq!(hotfixes_among(&found, LOCAL, &ahead), ["1a2b3c4d"], "only a hotfix whose result is among them");
        assert!(hotfixes_among(&found, &[Role::Runner], &ahead).is_empty(), "a key the policy takes no evidence from");
        assert!(hotfixes_among(&found, LOCAL, &["c3".repeat(20)]).is_empty(), "an ordinary promotion is no hotfix");
    }

    #[test]
    fn a_promotion_that_loosens_the_targets_rules_needs_a_person() {
        let p = policy("");
        let mut i = input(&p);
        i.loosened = vec!["environment".into()];
        let r = evaluate(&i);
        assert_eq!((r.decision, r.findings[0].code), (Decision::ApprovalRequired, "POLICY_LOOSENED"));
    }

    fn signoff(person: &str, text: &str, confirmations: &[&str], policy: &Policy) -> SignOff {
        SignOff {
            env: "prod".into(),
            from: "uat".into(),
            source_commit: "a1".repeat(20),
            decision: Vote::Approve,
            signer_person: person.into(),
            text: text.into(),
            answers: vec![],
            confirmations: confirmations.iter().map(|c| c.to_string()).collect(),
            policy_sha256: policy.digest(),
            created: crate::time::rfc3339(NOW - 60),
            expires: crate::time::rfc3339(NOW + 3600),
        }
    }

    #[test]
    fn a_sign_off_counts_only_from_a_signer_with_enough_words_and_every_confirmation() {
        let people = "[[trust.key]]\nname = \"dana\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:AAAA\"\nperson = \"Dana\"\n\n[[trust.key]]\nname = \"sam\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:BBBB\"\nperson = \"Sam\"\n\n[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\"]\n\n";
        let p = Policy::parse(&format!("{people}{LADDER}\n[environment.sign_off]\nmin_length = 10\nsigners = [\"eng-managers\"]\n\n[[environment.confirm]]\ntext = \"The release notes are published\"\n")).unwrap();
        let prod = p.environment_named("prod").unwrap();
        let notes = ["The release notes are published"];
        assert_eq!(signoff_void(&signoff("Dana", "tried checkout in uat", &notes, &p), Some("Dana"), false, &p, prod, NOW), None);
        assert!(signoff_void(&signoff("Dana", "ok", &notes, &p), Some("Dana"), false, &p, prod, NOW).unwrap().contains("shorter than the 10"));
        assert!(signoff_void(&signoff("Dana", "tried checkout in uat", &[], &p), Some("Dana"), false, &p, prod, NOW).unwrap().contains("does not confirm"));
        assert!(signoff_void(&signoff("Sam", "tried checkout in uat", &notes, &p), Some("Sam"), false, &p, prod, NOW).unwrap().contains("not among"), "Sam is not an eng-manager");
        assert!(signoff_void(&signoff("Dana", "tried checkout in uat", &notes, &p), Some("Sam"), false, &p, prod, NOW).unwrap().contains("Sam's key"), "a key signs for its own person only");
        assert!(signoff_void(&signoff("Dana", "tried checkout in uat", &notes, &p), None, true, &p, prod, NOW).is_some(), "named signers are known by the policy only");
        let mut old = signoff("Dana", "tried checkout in uat", &notes, &p);
        old.policy_sha256 = "other".into();
        assert_eq!(signoff_void(&old, Some("Dana"), false, &p, prod, NOW).as_deref(), Some("it was given under a different policy"));
        let mut late = signoff("Dana", "tried checkout in uat", &notes, &p);
        late.expires = crate::time::rfc3339(NOW - 1);
        assert_eq!(signoff_void(&late, Some("Dana"), false, &p, prod, NOW).as_deref(), Some("expired"));
        // With no signers named, this machine's own approver key may sign.
        let open = policy("");
        assert_eq!(signoff_void(&signoff("Alex Rivera", "", &[], &open), None, true, &open, open.environment_named("prod").unwrap(), NOW), None);
        assert!(signoff_void(&signoff("Alex Rivera", "", &[], &open), None, false, &open, open.environment_named("prod").unwrap(), NOW).is_some());
    }

    // ------------------------------------------------------------------------- git

    struct Repo(tempfile::TempDir);

    impl Repo {
        fn new() -> Repo {
            let r = Repo(tempfile::tempdir().unwrap());
            r.git(&["init", "-q", "-b", "main"]);
            r
        }
        fn git(&self, args: &[&str]) -> String {
            let out = std::process::Command::new("git").arg("-C").arg(self.0.path()).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        /// Commit a file at a committer time.
        fn commit(&self, file: &str, at: u64) -> String {
            std::fs::write(self.0.path().join(file), format!("{file} {at}\n")).unwrap();
            self.git(&["add", "-A"]);
            let out = std::process::Command::new("git").arg("-C").arg(self.0.path()).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", file]).env("GIT_COMMITTER_DATE", format!("@{at} +0000")).env("GIT_AUTHOR_DATE", format!("@{at} +0000")).output().unwrap();
            assert!(out.status.success());
            self.git(&["rev-parse", "HEAD"])
        }
        fn tree(&self, rev: &str) -> String {
            self.git(&["rev-parse", &format!("{rev}^{{tree}}")])
        }
    }

    fn completion(tree: &str, task: &str, base: Option<&str>, role: Role) -> crate::evidence::Signed<use05_receipt::Statement<use05_receipt::Completion>> {
        let statement = use05_receipt::Statement::new(vec![use05_receipt::tree_subject(tree, "d")], use05_receipt::Completion { task: task.into(), outcome: String::new(), finished: "f".into(), base: base.map(str::to_string) });
        crate::evidence::Signed { statement, signer: Signer { name: "m".into(), role, key_id: "k".into() }, source: "s".into(), path: "p".into(), cosigners: vec![] }
    }

    const LOCAL: &[Role] = &[Role::Local, Role::Runner];

    #[test]
    fn a_finish_marks_only_its_own_tasks_commits() {
        let r = Repo::new();
        let base = r.commit("base", 1000);
        let direct = r.commit("direct", 2000); // committed by hand, no task's
        let a1 = r.commit("a1", 3100); // the task's work starts after `direct`
        let a2 = r.commit("a2", 3200); // the task finished here
        let stray = r.commit("stray", 4000); // after the task, never finished as a task
        let top = r.0.path();
        let delta = commits(top, &stray, Some(&base)).unwrap();
        assert_eq!(delta.iter().map(|c| c.id.clone()).collect::<Vec<_>>(), [direct.clone(), a1.clone(), a2.clone(), stray.clone()], "oldest first");
        let mut found = Found::default();
        assert_eq!(untasked(top, &delta, &found, LOCAL), [direct.clone(), a1.clone(), a2.clone(), stray.clone()], "no receipts: no task");
        // With no base recorded, a finish marks only the commit it finished on, not the stack below it.
        found.completions.push(completion(&r.tree(&a2), "t1", None, Role::Local));
        assert_eq!(untasked(top, &delta, &found, LOCAL), [direct.clone(), a1.clone(), stray.clone()]);
        // With its base recorded, the commits from there to the finished tree are the task's.
        found.completions[0] = completion(&r.tree(&a2), "t1", Some(&direct), Role::Local);
        assert_eq!(untasked(top, &delta, &found, LOCAL), [direct.clone(), stray.clone()], "the commit made before the task's base is not its work");
        // Under accept = ["runner"], a finish this machine signed is its own claim and counts for nothing.
        assert_eq!(untasked(top, &delta, &found, &[Role::Runner]).len(), 4);
        found.completions[0].signer.role = Role::Runner;
        assert_eq!(untasked(top, &delta, &found, &[Role::Runner]), [direct, stray]);
    }

    #[test]
    fn a_base_that_is_not_the_finished_commits_ancestor_or_not_a_commit_id_is_ignored() {
        let r = Repo::new();
        let base = r.commit("base", 1000);
        let a1 = r.commit("a1", 2000);
        let a2 = r.commit("a2", 3000);
        // A root with no history in common: a range from it would be the whole history.
        r.git(&["checkout", "-q", "--orphan", "elsewhere"]);
        let unrelated = r.commit("unrelated", 500);
        r.git(&["checkout", "-q", "main"]);
        let top = r.0.path();
        let delta = commits(top, &a2, Some(&base)).unwrap();
        for bad in [unrelated.as_str(), "main", &base[..12], "not a commit"] {
            let mut found = Found::default();
            found.completions.push(completion(&r.tree(&a2), "t1", Some(bad), Role::Local));
            assert_eq!(untasked(top, &delta, &found, LOCAL), [a1.clone()], "base {bad:?} is no base: only the finished commit is the task's");
        }
    }

    #[test]
    fn a_tasks_range_stops_at_another_tasks_finish_and_at_a_promotion() {
        let r = Repo::new();
        let base = r.commit("base", 1000);
        let t1a = r.commit("t1a", 2000);
        let t1b = r.commit("t1b", 2100); // task 1 finished here, with no base recorded
        let t2a = r.commit("t2a", 3000);
        let t2b = r.commit("t2b", 3100); // task 2 finished here, its base claimed far back
        let top = r.0.path();
        let delta = commits(top, &t2b, Some(&base)).unwrap();
        let mut found = Found::default();
        found.completions.push(completion(&r.tree(&t1b), "t1", None, Role::Local));
        found.completions.push(completion(&r.tree(&t2b), "t2", Some(&base), Role::Local));
        assert_eq!(untasked(top, &delta, &found, LOCAL), [t1a.clone()], "task 2's range stops at task 1's finish; t1a is no one's");
        // A promotion's result stops it too.
        let mut found = Found::default();
        found.completions.push(completion(&r.tree(&t2b), "t2", Some(&base), Role::Local));
        let statement = use05_receipt::Statement::new(vec![use05_receipt::commit_subject(&t1b)], use05_receipt::Promotion {
            env: "uat".into(), from: "dev".into(), direction: use05_receipt::Direction::Up, source_commit: t1b.clone(), target_before: None, result_commit: t1b.clone(), how: "fast-forward".into(),
            rollback_point: None, rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: "c".into(), by: "ci".into(), reverts: None, task: None,
        });
        found.promotions.push(crate::evidence::Signed { statement, signer: Signer { name: "ci".into(), role: Role::Runner, key_id: "r".into() }, source: "s".into(), path: "p".into(), cosigners: vec![] });
        assert_eq!(untasked(top, &delta, &found, LOCAL), [t1a], "t1b is a promotion's result: task 2's range stops there, and t1a behind it is no one's");
        let _ = t2a;
    }

    #[test]
    fn a_rebased_task_marks_only_its_own_commits() {
        let r = Repo::new();
        let base = r.commit("base", 1000);
        r.git(&["checkout", "-q", "-b", "task"]);
        r.commit("x1", 2000);
        r.commit("x2", 2100);
        r.git(&["checkout", "-q", "main"]);
        let direct = r.commit("direct", 3000); // someone else's commit on main, after the task began
        r.git(&["checkout", "-q", "task"]);
        r.git(&["rebase", "-q", "main"]);
        let x2 = r.git(&["rev-parse", "HEAD"]);
        let x1 = r.git(&["rev-parse", "HEAD^"]);
        let top = r.0.path();
        // At finish, the base is where the finished work meets the landing branch now: `direct`.
        assert_eq!(finish_base(top, "main").as_deref(), Some(direct.as_str()));
        let delta = commits(top, &x2, Some(&base)).unwrap();
        let mut found = Found::default();
        found.completions.push(completion(&r.tree(&x2), "t1", finish_base(top, "main").as_deref(), Role::Local));
        assert_eq!(untasked(top, &delta, &found, LOCAL), [direct.clone()], "the task's own x1 and x2, not the commit it was rebased onto");
        assert!(!untasked(top, &delta, &found, LOCAL).contains(&x1));
    }

    #[test]
    fn a_finish_base_is_where_the_work_meets_whichever_landing_branch_is_nearer() {
        let r = Repo::new();
        let old = r.commit("old", 1000);
        let newer = r.commit("newer", 2000);
        r.git(&["checkout", "-q", "-b", "task"]);
        r.commit("work", 3000);
        let top = r.0.path();
        // Origin has `newer` and the work is on it; this machine's main has not caught up.
        r.git(&["update-ref", "refs/remotes/origin/main", &newer]);
        r.git(&["branch", "-f", "main", &old]);
        assert_eq!(finish_base(top, "main").as_deref(), Some(newer.as_str()), "origin's copy is nearer");
        // And the other way round: origin behind, this machine's main up to date.
        r.git(&["update-ref", "refs/remotes/origin/main", &old]);
        r.git(&["branch", "-f", "main", &newer]);
        assert_eq!(finish_base(top, "main").as_deref(), Some(newer.as_str()), "this machine's copy is nearer");
        r.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
        assert_eq!(finish_base(top, "main").as_deref(), Some(newer.as_str()), "only one copy: that one");
    }

    #[test]
    fn a_counted_bypass_clears_its_one_rule_and_says_who() {
        let p = policy("[environment.rules]\nuntasked = \"deny\"\n");
        let mut i = input(&p);
        i.untasked = vec!["c3".repeat(20)];
        let seen = |rule: &str, void: Option<&str>| BypassSeen { rule: rule.into(), person: "Dana".into(), reason: "a hand-made fix, checked".into(), path: "receipts/x/b.json".into(), void: void.map(str::to_string) };
        i.bypasses = vec![seen("untasked", None)];
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.findings);
        assert_eq!(rule(&r, "untasked").outcome, RuleOutcome::Bypassed);
        assert!(rule(&r, "untasked").detail.contains("bypassed by Dana"), "{}", rule(&r, "untasked").detail);
        let f = r.findings.iter().find(|f| f.code == "UNTASKED_COMMITS").unwrap();
        assert_eq!((f.effect, f.next.is_none()), (Effect::Info, true), "{f:?}");
        assert_eq!(trailers(&r).last().map(String::as_str), Some("05-Bypass: untasked"));
        // Another rule's bypass, or one that does not count, clears nothing, and the page says why.
        i.bypasses = vec![seen("soak", None), seen("untasked", Some("expired"))];
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Deny);
        assert!(r.findings.iter().any(|f| f.code == "UNTASKED_COMMITS" && f.message.contains("Dana's bypass does not count: expired")), "{:?}", r.findings);
        // A person's no is never bypassed.
        i.bypasses = vec![seen("sign_off", None)];
        i.untasked.clear();
        i.signoffs.push(SignOffSeen { person: "Sam".into(), decision: Vote::Reject, text: "not this week".into(), confirmations: vec![], path: "p".into(), void: None });
        assert_eq!(evaluate(&i).decision, Decision::Deny);
    }

    #[test]
    fn a_bypass_counts_only_where_the_policy_lets_one_clear_that_rule() {
        let b = |rule: &str, reason: &str, p: &Policy| use05_receipt::Bypass {
            env: Some("prod".into()), from: Some("uat".into()), rule: Some(rule.into()), policy_sha256: Some(p.digest()), reason: reason.into(), by: "Dana".into(), findings: vec![], created: crate::time::rfc3339(NOW), expires: crate::time::rfc3339(NOW + 3600),
        };
        let open = policy("");
        let prod = open.environment_named("prod").unwrap();
        let fine = "uat was confirmed by hand";
        assert_eq!(bypass_void(&b("soak", fine, &open), &open, prod, NOW), None);
        assert!(bypass_void(&b("soak", "short", &open), &open, prod, NOW).unwrap().contains("shorter than the 10"));
        assert!(bypass_void(&b("target_ahead", fine, &open), &open, prod, NOW).unwrap().contains("not a promotion rule"));
        assert_eq!(bypass_void(&b("soak", fine, &open), &open, prod, NOW + 7200).as_deref(), Some("expired"));
        // Bound to the policy, and no longer-lived than any bypass.
        let strict = policy("[environment.bypass]\nnever = [\"source_checks\"]\nreason_min = 4\n");
        assert_eq!(bypass_void(&b("soak", fine, &strict), &open, prod, NOW).as_deref(), Some("it was given under a different policy"));
        let mut long = b("soak", fine, &open);
        long.expires = crate::time::rfc3339(NOW + 100 * 3600);
        assert!(bypass_void(&long, &open, prod, NOW).unwrap().contains("longer than the 72 hours"));
        let prod = strict.environment_named("prod").unwrap();
        assert!(bypass_void(&b("source_checks", "the tests are flaky", &strict), &strict, prod, NOW).unwrap().contains("never lets a bypass clear source_checks"));
        assert_eq!(bypass_void(&b("soak", "short", &strict), &strict, prod, NOW), None, "its own reason_min");
        let closed = policy("[environment.bypass]\nallowed = false\n");
        assert!(bypass_void(&b("soak", fine, &closed), &closed, closed.environment_named("prod").unwrap(), NOW).unwrap().contains("allows no bypass"));
    }

    #[test]
    fn a_promotion_record_and_trailers_carry_what_moved_and_who_signed() {
        let p = policy("");
        let mut i = input(&p);
        i.signoffs.push(SignOffSeen { person: "Dana".into(), decision: Vote::Approve, text: "Checked checkout in uat.".into(), confirmations: vec![], path: "receipts/a1/s.json".into(), void: None });
        i.signoffs.push(SignOffSeen { person: "Sam".into(), decision: Vote::Approve, text: "t".into(), confirmations: vec![], path: "receipts/a1/t.json".into(), void: Some("expired".into()) });
        let r = evaluate(&i);
        let t = trailers(&r);
        assert_eq!(t[0], "05-Promotion: prod from uat");
        assert_eq!(t[1], format!("05-Source: {}", "a1".repeat(20)));
        assert_eq!(t[2], "05-Rules: source_checks=pass,source_confirmed=pass,soak=skipped,migrations=pass,untasked=pass,sign_off=skipped");
        assert_eq!(t[3..], ["05-Signed-off-by: Dana"], "only a sign-off that counts");
        let message = merge_message(&r);
        assert!(message.starts_with(&format!("Promote uat into prod ({})\n\n2 commits move from uat.\n\nDana signed off: Checked checkout in uat.\n\n05-Promotion: prod from uat\n", "a1".repeat(6))), "{message}");
        assert!(message.ends_with("05-Signed-off-by: Dana\n"), "the trailers end it: {message}");
        let rec = record(&r, &"f0".repeat(20), "Dana", "2026-11-04T00:00:00Z".into());
        let pr = &rec.predicate;
        assert_eq!((pr.env.as_str(), pr.from.as_str(), pr.direction, pr.how.as_str()), ("prod", "uat", use05_receipt::Direction::Up, "fast-forward"));
        assert_eq!((pr.target_before.clone(), pr.rollback_point.clone(), pr.result_commit.clone()), (Some("b2".repeat(20)), Some("b2".repeat(20)), "f0".repeat(20)));
        assert_eq!(pr.signoffs, ["receipts/a1/s.json"]);
        assert_eq!(rec.commit_subject(), Some("a1".repeat(20).as_str()), "subject: the source commit");
        assert_eq!(pr.rules.len(), 6);
    }

    #[test]
    fn merges_that_bring_nothing_of_their_own_are_tasked_and_do_not_put_the_target_ahead() {
        let r = Repo::new();
        let base = r.commit("base", 1000);
        r.git(&["branch", "uat"]);
        let work = r.commit("work", 2000);
        // uat takes main by a merge commit, as a promotion with how = "merge" makes it.
        r.git(&["checkout", "-q", "uat"]);
        r.git(&["merge", "-q", "--no-ff", "-m", "promote", "main"]);
        let merge = r.git(&["rev-parse", "HEAD"]);
        let top = r.0.path();
        let delta = commits(top, &merge, Some(&base)).unwrap();
        let mut found = Found::default();
        found.completions.push(completion(&r.tree(&work), "t1", None, Role::Local));
        assert!(untasked(top, &delta, &found, LOCAL).is_empty(), "the merge adds nothing; the work is a task's");
        // Seen from main, uat's merge is a commit main lacks: fine for a merge, not for a fast-forward.
        let ahead = commits(top, &merge, Some(&work)).unwrap();
        assert_eq!(ahead.len(), 1);
        assert!(target_ahead(top, &ahead, crate::policy::PromoteHow::Merge).is_empty());
        assert_eq!(target_ahead(top, &ahead, crate::policy::PromoteHow::FastForward), [merge]);
        // A commit of its own on the target always counts.
        let hotfix = r.commit("hotfix", 3000);
        let ahead = commits(top, &hotfix, Some(&work)).unwrap();
        assert_eq!(target_ahead(top, &ahead, crate::policy::PromoteHow::Merge), [hotfix]);
    }

    // ------------------------------------------------------------------------- confirming a deploy

    /// Answers each command from a script, on a pretend clock that a sleep moves on.
    struct Script {
        answers: Vec<Answer>,
        ran: Vec<String>,
        clock: u64,
        slept: Vec<u64>,
    }

    impl Script {
        fn new(answers: Vec<Answer>) -> Script {
            Script { answers, ran: Vec::new(), clock: NOW, slept: Vec::new() }
        }
    }

    impl DeployRunner for Script {
        fn run(&mut self, c: &DeployCommand<'_>) -> Answer {
            self.ran.push(format!("{} {}", c.kind, c.name));
            if self.answers.is_empty() { said(true, "") } else { self.answers.remove(0) }
        }
        fn now(&self) -> u64 {
            self.clock
        }
        fn sleep(&mut self, secs: u64) {
            self.clock += secs;
            self.slept.push(secs);
        }
    }

    fn said(passed: bool, stdout: &str) -> Answer {
        Answer::Ran { passed, timed_out: false, stdout: stdout.to_string(), stdout_sha256: format!("sha of {stdout}") }
    }

    const DEPLOYED: &str = "3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345";

    fn probed(extra: &str) -> Policy {
        policy(&format!("[[environment.probe]]\nname = \"version\"\nrun = [\"./version.sh\"]\nwait_minutes = 1\n{extra}"))
    }

    #[test]
    fn the_commit_shows_in_full_or_by_twelve_or_more_of_its_first_characters() {
        for yes in [DEPLOYED, "3f2a1b9c0d4e", "version: 3F2A1B9C0D4E5F\n", "{\"sha\":\"3f2a1b9c0d4e5f60718293a4b5c6d7e8f9012345\"}", "v1.2.0-4-g3f2a1b9c0d4e5"] {
            assert!(shows_commit(yes, DEPLOYED), "{yes}");
        }
        for no in ["", "3f2a1b9", "3f2a1b9c0d4", "v1.2.0-4-g3f2a1b9c", "x3f2a1b-9c0d4e", "deadbeef", "a3f2a1b9c0d4e5", "3f2a1b9c0d4e5f60718293a4b5c6d7e8f90123456", "3f2a1b9c0d4f"] {
            assert!(!shows_commit(no, DEPLOYED), "{no}");
        }
    }

    #[test]
    fn a_probe_that_shows_the_commit_confirms() {
        let p = probed("interval_secs = 20\n");
        let env = p.environment_named("prod").unwrap();
        let mut s = Script::new(vec![said(true, "running 0123456789ab"), said(true, &format!("running {}", &DEPLOYED[..12]))]);
        let c = confirm(env, DEPLOYED, &mut s);
        let d = &c.deployment;
        assert!(d.confirmed, "{:?}", c.said);
        assert_eq!((d.env.as_str(), d.commit.as_str(), d.action), ("prod", DEPLOYED, use05_receipt::DeployAction::None));
        assert_eq!((d.probes[0].matched, d.probes[0].attempts, d.probes[0].seconds), (true, 2, 20));
        assert_eq!(d.probes[0].output_sha256, format!("sha of running {}", &DEPLOYED[..12]), "what it printed last, by its hash");
        assert_eq!(s.slept, [20], "it waits interval_secs between tries");
        assert!(c.said[0].1.contains("showed it after 2 tries"), "{:?}", c.said);
    }

    #[test]
    fn a_probe_that_never_shows_it_gives_up_when_the_wait_is_over() {
        let p = probed("");
        let mut s = Script::new(vec![]);
        let c = confirm(p.environment_named("prod").unwrap(), DEPLOYED, &mut s);
        assert!(!c.deployment.confirmed);
        assert_eq!((c.deployment.probes[0].matched, c.deployment.probes[0].attempts, c.deployment.probes[0].seconds), (false, 5, 60), "a try at 0, 15, 30, 45 and 60 seconds");
        assert!(c.said[0].1.contains("did not show 3f2a1b9c0d4e in 1 minute (5 tries)"), "{:?}", c.said);
        // wait_minutes = 0 is one try, and no wait.
        let p = policy("[[environment.probe]]\nname = \"version\"\nrun = [\"./version.sh\"]\nwait_minutes = 0\n");
        let mut s = Script::new(vec![said(false, DEPLOYED)]);
        let c = confirm(p.environment_named("prod").unwrap(), DEPLOYED, &mut s);
        assert_eq!((c.deployment.probes[0].matched, c.deployment.probes[0].attempts), (false, 1), "a probe that fails has not answered, whatever it printed");
        assert!(s.slept.is_empty());
        assert!(c.said[0].1.contains("its last try failed"), "{:?}", c.said);
    }

    #[test]
    fn a_probe_that_cannot_run_fails_at_once() {
        let p = probed("\n[[environment.probe]]\nname = \"worker\"\nrun = [\"./worker.sh\"]\nwait_minutes = 0\n");
        let mut s = Script::new(vec![Answer::NotRun("could not run ./version.sh".into()), said(true, DEPLOYED)]);
        let c = confirm(p.environment_named("prod").unwrap(), DEPLOYED, &mut s);
        assert_eq!(s.ran, ["probe version", "probe worker"], "no second try of a program that is not there, and the other probes still run");
        assert!(!c.deployment.confirmed);
        assert_eq!((c.deployment.probes[0].matched, c.deployment.probes[0].attempts, c.deployment.probes[1].matched), (false, 1, true));
        assert_eq!(c.said[0], ("probe version".to_string(), "could not run ./version.sh".to_string()));
    }

    #[test]
    fn smoke_failure_means_not_confirmed() {
        let p = probed("\n[[environment.smoke]]\nname = \"health\"\nrun = [\"./health.sh\"]\n\n[[environment.smoke]]\nname = \"login\"\nrun = [\"./login.sh\"]\n");
        let env = p.environment_named("prod").unwrap();
        let mut s = Script::new(vec![said(true, DEPLOYED), said(true, "ok"), said(false, "")]);
        let c = confirm(env, DEPLOYED, &mut s);
        assert_eq!(s.ran, ["probe version", "smoke health", "smoke login"], "every smoke check runs once, after the probes");
        assert_eq!(c.deployment.smoke.iter().map(|x| (x.name.as_str(), x.passed)).collect::<Vec<_>>(), [("health", true), ("login", false)]);
        assert!(c.deployment.probes[0].matched && !c.deployment.confirmed);
        let mut s = Script::new(vec![said(true, DEPLOYED)]);
        assert!(confirm(env, DEPLOYED, &mut s).deployment.confirmed, "all probes and smoke checks pass");
    }

    #[test]
    fn no_probes_never_claims_confirmed() {
        let p = policy("[[environment.smoke]]\nname = \"health\"\nrun = [\"./health.sh\"]\n");
        let mut s = Script::new(vec![]);
        let c = confirm(p.environment_named("prod").unwrap(), DEPLOYED, &mut s);
        assert!(c.deployment.probes.is_empty() && !c.deployment.confirmed, "smoke checks alone confirm nothing");
        assert!(c.deployment.smoke[0].passed);
        // A later promotion from it reads that plainly.
        let p = policy("");
        let mut i = input(&p);
        i.deployments = vec![DeploymentSeen { confirmed: false, created: crate::time::rfc3339(NOW - 60), by: "ci".into(), probes: 0 }];
        let r = evaluate(&i);
        assert_eq!(rule(&r, "source_confirmed").outcome, RuleOutcome::Fail);
        assert!(r.findings.iter().any(|f| f.code == "SOURCE_NOT_CONFIRMED" && f.message.contains("no probes: 05 cannot tell what uat runs")), "{:?}", r.findings);
    }

    fn promoted(env: &str, before: Option<&str>, result: &str, created: &str, role: Role, reverts: Option<&str>) -> crate::evidence::Signed<use05_receipt::Statement<use05_receipt::Promotion>> {
        let statement = use05_receipt::Statement::new(vec![use05_receipt::commit_subject(result)], use05_receipt::Promotion {
            env: env.into(), from: "uat".into(), direction: use05_receipt::Direction::Up, source_commit: result.into(), target_before: before.map(str::to_string), result_commit: result.into(), how: "fast-forward".into(),
            rollback_point: before.map(str::to_string), rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: "p".into(), created: created.into(), by: "ci".into(), reverts: reverts.map(str::to_string), task: None,
        });
        crate::evidence::Signed { statement, signer: Signer { name: "k".into(), role, key_id: "k".into() }, source: "s".into(), path: format!("receipts/{result}/{created}.json"), cosigners: vec![] }
    }

    #[test]
    fn the_rollback_point_is_where_the_newest_counted_promotion_found_the_branch() {
        let r = Repo::new();
        let a = r.commit("a", 1000);
        let b = r.commit("b", 2000);
        let c = r.commit("c", 3000);
        let top = r.0.path();
        let mut found = Found::default();
        assert!(rollback_point(top, &found, LOCAL, "prod", &c).is_none(), "no promotion into prod");
        found.promotions.push(promoted("prod", Some(&a), &b, "2026-11-01T00:00:00Z", Role::Local, None));
        found.promotions.push(promoted("prod", Some(&b), &c, "2026-11-02T00:00:00Z", Role::Local, None));
        found.promotions.push(promoted("uat", Some(&a), &c, "2026-11-03T00:00:00Z", Role::Local, None));
        let point = rollback_point(top, &found, LOCAL, "prod", &c).unwrap();
        assert_eq!((point.to.as_deref(), point.result.as_str()), (Some(b.as_str()), c.as_str()), "the newest into prod");
        // A revert is no promotion to go back from; a record whose result the branch lacks is about
        // history that is not there; a key the policy does not take evidence from does not count.
        found.promotions.push(promoted("prod", Some(&c), &"e5".repeat(20), "2026-11-04T00:00:00Z", Role::Local, None));
        found.promotions.push(promoted("prod", Some(&c), &c, "2026-11-05T00:00:00Z", Role::Local, Some(&c)));
        assert_eq!(rollback_point(top, &found, LOCAL, "prod", &c).unwrap().to.as_deref(), Some(b.as_str()));
        assert_eq!(rollback_point(top, &found, &[Role::Runner], "prod", &c).map(|p| p.result), None);
        // Promoted when the branch was created: there is no point to go back to.
        let mut created = Found::default();
        created.promotions.push(promoted("prod", None, &b, "2026-11-01T00:00:00Z", Role::Local, None));
        let point = rollback_point(top, &created, LOCAL, "prod", &c).unwrap();
        assert_eq!(point.to, None);
        // A record whose branch-before is not in the result's history is no rollback point: a
        // revert to it would put any files on the branch, past every rule.
        r.git(&["checkout", "-q", "--orphan", "elsewhere"]);
        let off = r.commit("anything", 4000);
        r.git(&["checkout", "-q", "main"]);
        let mut forged = found.clone();
        forged.promotions.push(promoted("prod", Some(&off), &c, "2026-11-06T00:00:00Z", Role::Local, None));
        assert_eq!(rollback_point(top, &forged, LOCAL, "prod", &c), None, "off the branch's history");
        let mut same = Found::default();
        same.promotions.push(promoted("prod", Some(&c), &c, "2026-11-06T00:00:00Z", Role::Local, None));
        assert_eq!(rollback_point(top, &same, LOCAL, "prod", &c), None, "a branch is not its own rollback point");
        // A merge's branch-before is its first parent, and nothing else.
        r.git(&["checkout", "-q", "-b", "side", &a]);
        let side = r.commit("side", 5000);
        r.git(&["checkout", "-q", "main"]);
        r.git(&["merge", "-q", "--no-ff", "-m", "promote", &side]);
        let merge = r.git(&["rev-parse", "HEAD"]);
        let merged = |before: &str| {
            let mut p = promoted("prod", Some(before), &merge, "2026-11-07T00:00:00Z", Role::Local, None);
            p.statement.predicate.how = "merge".into();
            let mut f = Found::default();
            f.promotions.push(p);
            rollback_point(top, &f, LOCAL, "prod", &merge).map(|p| p.to)
        };
        assert_eq!(merged(&c), Some(Some(c.clone())), "the first parent");
        assert_eq!(merged(&side), None, "the second parent is the source, not where the branch was");
        assert_eq!(merged(&a), None, "an older ancestor is not where the merge found it");
    }

    #[test]
    fn a_revert_says_what_it_restores_and_is_recorded_as_one() {
        let message = revert_message("prod", &"b2".repeat(20), DEPLOYED, "deploy not confirmed");
        assert!(message.starts_with(&format!("Revert prod to {} (deploy not confirmed)\n\n", "b2".repeat(6))), "{message}");
        assert!(message.ends_with(&format!("05-Revert: prod\n05-Reverts: {DEPLOYED}\n05-Rollback-To: {}\n", "b2".repeat(20))), "{message}");
        let rec = revert_record("prod", "uat", use05_receipt::Direction::Up, &"f0".repeat(20), DEPLOYED, "p", "CI", "2026-11-04T00:00:00Z".into());
        let pr = &rec.predicate;
        assert_eq!((pr.how.as_str(), pr.reverts.as_deref(), pr.target_before.as_deref(), pr.rollback_point.as_deref()), ("revert", Some(DEPLOYED), Some(DEPLOYED), None));
        assert_eq!((pr.source_commit.clone(), pr.result_commit.clone(), rec.commit_subject().map(str::to_string)), ("f0".repeat(20), "f0".repeat(20), Some("f0".repeat(20))));
        assert!(pr.rules.is_empty());
    }
}

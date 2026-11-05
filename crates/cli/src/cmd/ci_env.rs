//! The CI gate on a push to an environment's branch (D93, part 8): the strong control where the
//! host waits for CI before it deploys. Such a branch moves only as a promotion, a revert, a
//! hotfix's landing or a back-merge, and each files a signed promotion record once its push went
//! through. CI asks for that record, checks that the move it describes is the commit that was
//! pushed, and judges the move again as it stood before the push, with the same code the pre-push
//! hook runs, on the rules and the evidence CI counts.
//!
//! What rests on what: the record is a claim of which move was made and from where; CI checks the
//! claim against git (the parents, the tree, where the source came from) and the chain of records
//! (the move started where the last one ended), then judges the rules itself. The record counts
//! only from a key of a kind the policy takes evidence from (`evidence.accept`), so with
//! `["runner"]` a promotion made on a developer's machine is held until it is made from CI.

use std::path::Path;
use std::time::Duration;

use use05_core::evidence::{Signed, Trust, classify};
use use05_core::gate::{Decision, Effect, Finding, GateResult};
use use05_core::policy::{Environment, Policy, Role};
use use05_core::promote::short;
use use05_core::task::{Status, Store, Task};
use use05_core::{git, store};
use use05_receipt::{Direction, Promotion, Statement};

/// How often and how long CI waits for the record: the promoting side files it just after its push,
/// so the CI run the push started may begin before the record is on origin.
const RECORD_TRIES: u32 = 6;
const RECORD_WAIT: Duration = Duration::from_secs(10);

fn finding(code: &'static str, effect: Effect, message: String, next: Option<String>) -> Finding {
    let mut f = Finding::new(code, effect, message);
    f.next = next;
    f
}

fn is_ancestor(top: &Path, a: &str, b: &str) -> bool {
    git::run(top, &["merge-base", "--is-ancestor", a, b]).is_ok()
}

fn parents(top: &Path, commit: &str) -> Vec<String> {
    git::text(top, &["rev-list", "--parents", "-n", "1", commit]).unwrap_or_default().split_whitespace().skip(1).map(str::to_string).collect()
}

/// The counted promotion records of `env`, newest first.
fn records(top: &Path, trust: &Trust, accept: &[Role], env: &str) -> Vec<Signed<Statement<Promotion>>> {
    let found = classify(trust, &store::find_all(top));
    let mut all: Vec<_> = found
        .promotions
        .into_iter()
        .filter(|p| accept.contains(&p.signer.role))
        .filter(|p| p.statement.predicate.env == env && p.statement.commit_subject() == Some(p.statement.predicate.source_commit.as_str()))
        .collect();
    all.sort_by(|a, b| b.statement.predicate.created.cmp(&a.statement.predicate.created));
    all
}

/// The record whose move ended at `head`, fetching the receipts again while it has not arrived.
fn record_for(top: &Path, trust: &Trust, accept: &[Role], env: &str, head: &str) -> (Option<Signed<Statement<Promotion>>>, Vec<Signed<Statement<Promotion>>>) {
    let tries = std::env::var("USE05_RECORD_TRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(RECORD_TRIES);
    for attempt in 0..tries.max(1) {
        let all = records(top, trust, accept, env);
        if let Some(i) = all.iter().position(|p| p.statement.predicate.result_commit == head) {
            let mut rest = all;
            let found = rest.remove(i);
            return (Some(found), rest);
        }
        if attempt + 1 < tries {
            std::thread::sleep(RECORD_WAIT);
            let _ = git::run(top, &["fetch", "--quiet", "origin", &format!("+refs/heads/{0}/*:refs/remotes/origin/{0}/*", store::BRANCH_DIR)]);
        }
    }
    (None, records(top, trust, accept, env))
}

/// Puts origin's copies of branches as they stood before the push, for the judgement, and back
/// afterwards (also when dropped early).
struct AsOf<'a> {
    top: &'a Path,
    saved: Vec<(String, Option<String>)>,
}

impl<'a> AsOf<'a> {
    fn new(top: &'a Path) -> AsOf<'a> {
        AsOf { top, saved: Vec::new() }
    }

    fn set(&mut self, branch: &str, commit: Option<&str>) {
        let r = format!("refs/remotes/origin/{branch}");
        self.saved.push((r.clone(), git::resolve_commit(self.top, &r)));
        match commit {
            Some(c) => drop(git::run(self.top, &["update-ref", &r, c])),
            None => drop(git::run(self.top, &["update-ref", "-d", &r])),
        }
    }
}

impl Drop for AsOf<'_> {
    fn drop(&mut self) {
        for (r, was) in self.saved.drain(..).rev() {
            match was {
                Some(c) => drop(git::run(self.top, &["update-ref", &r, &c])),
                None => drop(git::run(self.top, &["update-ref", "-d", &r])),
            }
        }
    }
}

/// The environment `branch` is, when CI judges a push to it as a move (D93): one that is promoted
/// into, or the lowest rung (where work lands) when a counted record says `head` is a merge back
/// into it. `None`: the task gate judges the push, as for any change.
pub fn environment_pushed<'p>(top: &Path, policy: &'p Policy, trust: &Trust, branch: &str, head: &str) -> Option<&'p Environment> {
    let env = policy.environment.iter().find(|e| e.branch == branch)?;
    if policy.source_of(env).is_some() {
        return Some(env);
    }
    let back = records(top, trust, &policy.evidence.accept, &env.name).iter().any(|p| p.statement.predicate.result_commit == head && p.statement.predicate.direction == Direction::Back);
    back.then_some(env)
}

/// The CI gate's judgement of `head`, pushed to the branch of `env`, an environment that is
/// promoted into, under `policy` (the rules CI read) and `trust`. Never fails open: what cannot be
/// judged is held.
pub fn judge(repo: &Path, top: &Path, policy: &Policy, trust: &Trust, env: &Environment, head: &str) -> GateResult {
    let digest = policy.digest();
    let deny = |f: Finding| GateResult::of_findings(Decision::Deny, vec![f], digest.clone());
    let accept = &policy.evidence.accept;
    let (record, earlier) = record_for(top, trust, accept, &env.name, head);
    let Some(record) = record else {
        let local = if accept.contains(&Role::Local) { "" } else { "; under evidence.accept = [\"runner\"], a record signed on a developer's machine does not count: promote from CI" };
        return deny(finding(
            "PROMOTION_RECORD_MISSING",
            Effect::Deny,
            format!("{} moved to {} with no promotion record for it{local}: 05 moves an environment only as a promotion, a revert, a hotfix or a merge back, and files a record once each is pushed", env.branch, short(head)),
            Some(format!("promote it with 05 (use05 promote {}), or push the record the promoting machine holds: git push origin '05-receipts/*'", env.name)),
        ));
    };
    let p = &record.statement.predicate;
    let shown = format!("the record {} ({} {})", record.path, p.how, short(&p.result_commit));

    // The move the record describes is the one that was pushed.
    if let Some(before) = &p.target_before {
        let in_history = match p.how.as_str() {
            "merge" => parents(top, head).first() == Some(before),
            "revert" => parents(top, head) == [before.clone()],
            _ => before != head && is_ancestor(top, before, head),
        };
        if !in_history {
            return deny(finding("PROMOTION_RECORD_MISMATCH", Effect::Deny, format!("{shown} says {} was at {} before, which is not where this push came from", env.branch, short(before)), Some(format!("promote it with 05: use05 promote {}", env.name))));
        }
    }
    // The chain: this move started where the last counted one ended. Otherwise a record could claim
    // a later starting point and leave commits out of what is judged.
    // `earlier` is every other counted record of this environment, newest first.
    let previous = earlier.iter().find(|e| e.statement.predicate.created <= p.created && e.statement.predicate.result_commit != p.result_commit);
    let mut notes = Vec::new();
    match (previous, &p.target_before) {
        (Some(prev), Some(before)) if &prev.statement.predicate.result_commit != before => {
            return deny(finding(
                "PROMOTION_CHAIN_BROKEN",
                Effect::Deny,
                format!("{shown} starts at {}, but the last counted promotion of {} ended at {}: what moved in between was never judged", short(before), env.name, short(&prev.statement.predicate.result_commit)),
                Some(format!("promote it with 05 from where {} is: use05 promote {}", env.branch, env.name)),
            ));
        }
        (Some(prev), None) => {
            return deny(finding("PROMOTION_CHAIN_BROKEN", Effect::Deny, format!("{shown} says it created {}, but {} was promoted before (to {})", env.branch, env.name, short(&prev.statement.predicate.result_commit)), Some(format!("promote it with 05: use05 promote {}", env.name))));
        }
        (None, Some(before)) => notes.push(finding("PROMOTION_FIRST_RECORD", Effect::Info, format!("this is the first counted record for {}: that it started at {} is the record's word", env.name, short(before)), None)),
        _ => {}
    }

    // As of before the push: the environment's branch where it was, the source where the record
    // says, and no fetching that would put origin's newer copies back.
    let mut as_of = AsOf::new(top);
    as_of.set(&env.branch, p.target_before.as_deref());
    let revert = p.reverts.is_some() || p.how == "revert";
    match p.direction {
        _ if revert => {}
        Direction::Hotfix => {
            // The hotfix's task, as its record names it, for the task gate. This checkout's task
            // store is CI's own and gone after the run.
            let Some(id) = p.task.clone() else {
                return deny(finding("PROMOTION_RECORD_MISMATCH", Effect::Deny, format!("{shown} is a hotfix's and names no task"), None));
            };
            let base_tree = p.target_before.as_deref().and_then(|b| git::resolve_tree(top, b).ok()).unwrap_or_default();
            let task = Task {
                id: id.clone(),
                title: format!("hotfix {id}"),
                author: p.by.clone(),
                created: p.created.clone(),
                base_commit: p.target_before.clone(),
                base_tree,
                branch: None,
                intent: None,
                intent_sha256: None,
                status: Status::Finished,
                outcome: None,
                finished: Some(p.created.clone()),
                session: None,
                sealed: None,
                revisions: Vec::new(),
                request: None,
                head: Some(head.to_string()),
                ended: None,
                agent: None,
                owner: None,
                sandbox: None,
                fresh: None,
                hotfix: Some(env.name.clone()),
            };
            if let Err(e) = Store::open(repo).and_then(|s| s.save(&task)) {
                return deny(finding("PROMOTE_NOT_JUDGED", Effect::Deny, format!("05 could not hold the hotfix's task to judge it: {}", e.message), None));
            }
        }
        _ => {
            // The source: the environment below for a promotion up, the one above for a merge back.
            let source = match p.direction {
                Direction::Back => crate::cmd::hotfix::above(policy, env).cloned(),
                _ => policy.source_of(env).cloned(),
            };
            let Some(source) = source else {
                return deny(finding("PROMOTE_NOT_JUDGED", Effect::Deny, format!("{shown} moves {} from {}, which these rules do not promote it from", env.name, p.from), None));
            };
            // The source commit came from the source's own branch, not from anywhere.
            let Some(now) = git::resolve_commit(top, &format!("refs/remotes/origin/{}", source.branch)) else {
                return deny(finding("PROMOTE_NOT_JUDGED", Effect::Deny, format!("{} is not on origin here, so where {} came from cannot be checked", source.branch, short(&p.source_commit)), Some(format!("fetch {} before the gate", source.branch))));
            };
            if !is_ancestor(top, &p.source_commit, &now) {
                return deny(finding("PROMOTION_SOURCE_NOT_ON_BRANCH", Effect::Deny, format!("{shown} moved {} from {}, but that commit is not on {}", short(&p.source_commit), source.name, source.branch), Some(format!("promote from {} with 05: use05 promote {}", source.branch, env.name))));
            }
            as_of.set(&source.branch, Some(&p.source_commit));
        }
    }

    // Who acted: where people keep the environment, the record shows one (their co-signature).
    let person = record.cosigners.iter().any(|c| c.role == Role::Approver && trust.person_of(&c.key_id).is_some());
    let _ = crate::cmd::gate::RECORDED_PERSON.set(person);
    crate::cmd::promote::set_offline();
    let judged = crate::cmd::promote::judge_push(repo, &env.name, head);
    drop(as_of);
    let mut gate = match judged {
        Ok(g) => g,
        Err(r) => return deny(finding("PROMOTE_NOT_JUDGED", Effect::Deny, format!("05 could not judge this push to {} as of before it: {}", env.branch, r.headline), r.next.clone())),
    };
    for f in gate.findings.iter_mut().filter(|f| f.code == "AGENT_MAY_NOT_PROMOTE") {
        f.message = format!("{} is kept for people, and {shown} has no person's co-signature", env.name);
        f.next = Some(format!("a person promotes it: use05 promote {}", env.name));
    }
    gate.findings.extend(notes);
    gate.findings.push(finding("PROMOTION_RECORD", Effect::Info, format!("{shown}, {} by {}, judged as of before the push", match p.direction {
        _ if revert => "a revert",
        Direction::Hotfix => "a hotfix's landing",
        Direction::Back => "a merge back",
        _ => "a promotion",
    }, p.by), None));
    gate.findings.sort_by(|a, b| b.effect.cmp(&a.effect));
    gate
}

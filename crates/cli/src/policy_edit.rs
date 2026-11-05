//! Write a guided setup's answers into `.05/policy.toml`, changing only those settings: comments,
//! settings the questions do not cover and the order of the file are kept.

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};
use use05_core::policy::{CheckDef, Environment, IntentMode, LandMode, Policy, Require, Severity};

/// The first use05 that reads `[[environment]]`.
const ENVIRONMENTS_SINCE: &str = "0.0.4";

/// The first use05 that reads an environment's `level`.
const LEVELS_SINCE: &str = "0.0.5";

/// The first use05 that reads `fresh_base` and `[[require]]`.
const RULES_SINCE: &str = "0.0.6";

/// The first use05 that reads a check's `paths` and `dir` (D97).
const CHECK_SCOPE_SINCE: &str = "0.0.14";

/// Everything the guided setup asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub intent: IntentMode,
    pub scope: Severity,
    pub dependencies: Severity,
    pub overlap: Severity,
    pub tests: Severity,
    pub approvals_min: u32,
    pub target: Option<String>,
    pub land: LandMode,
    pub push: LandMode,
    pub environments: Vec<Environment>,
    pub checks: Vec<CheckDef>,
    pub protect_paths: Vec<String>,
    pub locked: Vec<String>,
    pub append_only: Vec<String>,
    pub no_delete: Vec<String>,
    pub no_read: Vec<String>,
    pub fresh_base: Severity,
    pub require: Vec<Require>,
}

impl Settings {
    /// The settings a policy has now: the defaults when editing it.
    pub fn from_policy(p: &Policy) -> Settings {
        Settings {
            intent: p.intent.mode,
            scope: p.drift.scope,
            dependencies: p.drift.dependencies,
            overlap: p.drift.overlap,
            tests: p.drift.tests,
            approvals_min: p.approvals.min,
            target: p.branches.target.clone(),
            land: p.branches.land,
            push: p.branches.push,
            environments: p.environment.clone(),
            checks: p.check.clone(),
            protect_paths: p.protect.paths.clone(),
            locked: p.protect.locked.clone(),
            append_only: p.protect.append_only.clone(),
            no_delete: p.protect.no_delete.clone(),
            no_read: p.protect.no_read.clone(),
            fresh_base: p.branches.fresh_base,
            require: p.require.clone(),
        }
    }
}

/// The word a setting is written as in the policy file (`warn`, `risky`, `auto`).
fn word<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn table<'a>(doc: &'a mut DocumentMut, name: &str) -> &'a mut Table {
    if !doc.contains_key(name) {
        doc.insert(name, Item::Table(Table::new()));
    }
    doc[name].as_table_mut().expect("a table")
}

/// The table `name`, with `key`'s commented example (if the file has one there) made the real line.
fn slot<'a>(doc: &'a mut DocumentMut, name: &str, key: &str) -> &'a mut Table {
    use05_policy_edit::edit::uncomment_example(doc, name, key);
    table(doc, name)
}

/// Set `key` to `value`, keeping the comments around the old value.
fn set(t: &mut Table, key: &str, mut value: Value) {
    if let Some(old) = t.get(key).and_then(Item::as_value) {
        *value.decor_mut() = old.decor().clone();
    }
    t.insert(key, Item::Value(value));
}

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(String::as_str).collect::<Array>())
}

/// Apply `s` to the policy text. Only settings whose value changes are touched. The result must
/// still be a valid policy, or nothing is returned.
pub fn apply(text: &str, s: &Settings) -> Result<String, String> {
    let before = Policy::parse(text).map_err(|e| e.message)?;
    let now = Settings::from_policy(&before);
    let mut doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
    if s.intent != now.intent {
        set(slot(&mut doc, "intent", "mode"), "mode", word(&s.intent).into());
    }
    for (key, want, have) in [("scope", s.scope, now.scope), ("dependencies", s.dependencies, now.dependencies), ("overlap", s.overlap, now.overlap), ("tests", s.tests, now.tests)] {
        if want != have {
            set(slot(&mut doc, "drift", key), key, word(&want).into());
        }
    }
    if s.approvals_min != now.approvals_min {
        set(slot(&mut doc, "approvals", "min"), "min", i64::from(s.approvals_min).into());
    }
    if s.target != now.target {
        match &s.target {
            Some(t) => set(slot(&mut doc, "branches", "target"), "target", t.as_str().into()),
            None => {
                table(&mut doc, "branches").remove("target");
            }
        }
    }
    if s.land != now.land {
        set(slot(&mut doc, "branches", "land"), "land", word(&s.land).into());
    }
    if s.push != now.push {
        set(slot(&mut doc, "branches", "push"), "push", word(&s.push).into());
    }
    if s.fresh_base != now.fresh_base {
        set(slot(&mut doc, "branches", "fresh_base"), "fresh_base", word(&s.fresh_base).into());
    }
    for (key, want, have) in [
        ("paths", &s.protect_paths, &now.protect_paths),
        ("locked", &s.locked, &now.locked),
        ("append_only", &s.append_only, &now.append_only),
        ("no_delete", &s.no_delete, &now.no_delete),
        ("no_read", &s.no_read, &now.no_read),
    ] {
        if want != have {
            set(slot(&mut doc, "protect", key), key, strings(want));
        }
    }
    if s.environments != now.environments {
        // An environment that stays keeps its own table: its promotion settings and comments
        // (D93). Only its name, branch and level are what setup asks about.
        let old: Vec<Table> = doc.get("environment").and_then(Item::as_array_of_tables).map(|a| a.iter().cloned().collect()).unwrap_or_default();
        doc.remove("environment");
        if !s.environments.is_empty() {
            let mut envs = ArrayOfTables::new();
            for e in &s.environments {
                let at = now.environments.iter().position(|o| o.name == e.name).or_else(|| now.environments.iter().position(|o| o.branch == e.branch));
                let mut t = at.and_then(|i| old.get(i)).cloned().unwrap_or_default();
                set_value(&mut t, "name", e.name.as_str().into());
                set_value(&mut t, "branch", e.branch.as_str().into());
                match &e.level {
                    Some(l) => set_value(&mut t, "level", l.as_str().into()),
                    None => {
                        t.remove("level");
                    }
                }
                // A new environment brings what the team's start gave it (who may promote into it,
                // whether a person signs off); one that stays keeps its own table as it is.
                if at.is_none() {
                    if let Some(agent) = e.agent {
                        set_value(&mut t, "agent", agent.into());
                    }
                    if e.rules != use05_core::policy::PromoteRules::default() {
                        let mut rules = Table::new();
                        let defaults = use05_core::policy::PromoteRules::default();
                        for name in ["source_checks", "source_confirmed", "soak", "migrations", "untasked", "sign_off"] {
                            if let (Some(want), Some(default)) = (e.rules.get(name), defaults.get(name)) {
                                if want != default {
                                    rules.insert(name, toml_edit::value(format!("{want:?}").to_lowercase()));
                                }
                            }
                        }
                        t.insert("rules", Item::Table(rules));
                    }
                }
                envs.push(t);
            }
            doc.insert("environment", Item::ArrayOfTables(envs));
        }
    }
    if s.require != now.require {
        // Rules that stay keep their own table and comments; the rest are written fresh.
        let old: Vec<Table> = doc.get("require").and_then(Item::as_array_of_tables).map(|a| a.iter().cloned().collect()).unwrap_or_default();
        let mut rules = ArrayOfTables::new();
        for r in &s.require {
            let kept = now.require.iter().position(|o| o == r).and_then(|at| old.get(at)).cloned();
            rules.push(kept.unwrap_or_else(|| {
                let mut t = Table::new();
                t.insert("when", Item::Value(strings(&r.when)));
                t.insert("also", Item::Value(strings(&r.also)));
                if r.severity != Severity::Approval {
                    t.insert("severity", Item::Value(word(&r.severity).into()));
                }
                if let Some(why) = &r.why {
                    t.insert("why", Item::Value(why.as_str().into()));
                }
                t
            }));
        }
        match doc.get_mut("require").and_then(Item::as_array_of_tables_mut) {
            Some(existing) if !rules.is_empty() => *existing = rules,
            _ => {
                doc.remove("require");
                if !rules.is_empty() {
                    doc.insert("require", Item::ArrayOfTables(rules));
                }
            }
        }
    }
    if s.checks != now.checks {
        // Checks that stay keep their own table, comments and extra settings; new ones are added.
        let old: Vec<Table> = doc.get("check").and_then(Item::as_array_of_tables).map(|a| a.iter().cloned().collect()).unwrap_or_default();
        let mut checks = ArrayOfTables::new();
        for c in &s.checks {
            let mut t = old.iter().find(|t| t.get("name").and_then(Item::as_str) == Some(c.name.as_str())).cloned().unwrap_or_else(|| {
                let mut t = Table::new();
                t.insert("name", Item::Value(c.name.as_str().into()));
                t
            });
            let was = now.checks.iter().find(|o| o.name == c.name);
            if was.map(|o| &o.run) != Some(&c.run) {
                set(&mut t, "run", strings(&c.run));
            }
            // A new check brings its own environment, paths and folder (D97); a kept one only what changed.
            for (key, want, have) in [("env", &c.env, was.map(|o| &o.env)), ("paths", &c.paths, was.map(|o| &o.paths))] {
                if have != Some(want) {
                    if want.is_empty() {
                        t.remove(key);
                    } else {
                        set(&mut t, key, strings(want));
                    }
                }
            }
            if was.map(|o| &o.dir) != Some(&c.dir) {
                match &c.dir {
                    Some(dir) => set(&mut t, "dir", dir.as_str().into()),
                    None => {
                        t.remove("dir");
                    }
                }
            }
            checks.push(t);
        }
        // In place, so the checks stay where they were in the file, under their comment.
        match doc.get_mut("check").and_then(Item::as_array_of_tables_mut) {
            Some(existing) if !checks.is_empty() => *existing = checks,
            _ => {
                doc.remove("check");
                if !checks.is_empty() {
                    doc.insert("check", Item::ArrayOfTables(checks));
                }
            }
        }
    }
    // Environments need 0.0.4 to be read. Raise the minimum so an older use05 is told to
    // upgrade instead of failing on a section it does not know.
    let needs = if s.checks.iter().any(|c| !c.paths.is_empty() || c.dir.is_some()) {
        // A build older than that release (a development one) cannot write a minimum it fails to read itself.
        let running = env!("CARGO_PKG_VERSION");
        Some(if use05_core::policy::version_below(running, CHECK_SCOPE_SINCE) { running } else { CHECK_SCOPE_SINCE })
    } else if s.fresh_base != Severity::Allow || !s.require.is_empty() {
        Some(RULES_SINCE)
    } else if s.environments.iter().any(|e| e.level.is_some()) {
        Some(LEVELS_SINCE)
    } else if !s.environments.is_empty() {
        Some(ENVIRONMENTS_SINCE)
    } else {
        None
    };
    if let Some(needs) = needs {
        let min = doc.get("use05").and_then(|t| t.get("min_version")).and_then(Item::as_str).unwrap_or("0.0.0").to_string();
        if use05_core::policy::version_below(&min, needs) {
            set(table(&mut doc, "use05"), "min_version", needs.into());
        }
    }
    let out = doc.to_string();
    Policy::parse(&out).map_err(|e| e.message)?;
    Ok(out)
}

/// Set `key` in a table, keeping its place and the comment after it when it is there already.
fn set_value(t: &mut Table, key: &str, value: toml_edit::Value) {
    match t.get_mut(key).and_then(Item::as_value_mut) {
        Some(v) if v.as_str() == value.as_str() => {}
        Some(v) => {
            let decor = v.decor().clone();
            *v = value;
            *v.decor_mut() = decor;
        }
        None => {
            t.insert(key, Item::Value(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use use05_core::policy::{CheckDef, Environment, IntentMode, LandMode, Policy, Severity};

    fn check(name: &str, run: &[&str]) -> CheckDef {
        CheckDef { name: name.into(), run: run.iter().map(|s| s.to_string()).collect(), ..CheckDef::default() }
    }

    fn template() -> String {
        crate::cmd::init::policy_template(&[check("test", &["npm", "run", "test", "--silent"])])
    }

    #[test]
    fn answers_are_written_and_the_comments_kept() {
        let text = template();
        let mut s = Settings::from_policy(&Policy::parse(&text).unwrap());
        s.intent = IntentMode::Risky;
        s.scope = Severity::Approval;
        s.tests = Severity::Deny;
        s.approvals_min = 2;
        s.target = Some("main".into());
        s.land = LandMode::Auto;
        s.environments = vec![Environment::new("dev", "main", None), Environment::new("prod", "production", None)];
        s.checks.push(check("lint", &["npm", "run", "lint"]));
        s.locked = vec!["LICENSE".into()];
        s.append_only = vec!["migrations/**".into()];
        let out = apply(&text, &s).unwrap();
        let p = Policy::parse(&out).unwrap();
        assert_eq!((p.intent.mode, p.drift.scope, p.drift.tests, p.approvals.min), (IntentMode::Risky, Severity::Approval, Severity::Deny, 2));
        assert_eq!((p.branches.target.as_deref(), p.branches.land), (Some("main"), LandMode::Auto));
        assert_eq!(p.environment, s.environments);
        assert_eq!(p.check.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["test", "lint"]);
        assert_eq!((p.protect.locked.clone(), p.protect.append_only.clone()), (vec!["LICENSE".to_string()], vec!["migrations/**".to_string()]));
        assert!(out.contains("# files outside the declared scope"), "a setting's comment survives:\n{out}");
        assert!(out.contains("# 05 policy."), "{out}");
        assert!(out.find("name = \"lint\"").unwrap() < out.find("[protect]").unwrap(), "checks stay where they were:\n{out}");
    }

    #[test]
    fn a_rule_replaces_its_commented_example_in_the_template() {
        let text = template();
        let mut s = Settings::from_policy(&Policy::parse(&text).unwrap());
        s.locked = vec!["LICENSE".into()];
        let out = apply(&text, &s).unwrap();
        assert!(out.contains("locked = [\"LICENSE\"]  "), "{out}");
        assert!(!out.contains("# locked = []") && out.contains("# append_only = []"), "{out}");
        assert!(out.contains("never changed; no approval clears it"), "the example's own comment stays:\n{out}");
    }

    #[test]
    fn a_new_check_is_written_with_its_paths_folder_and_environment() {
        let text = template();
        let mut s = Settings::from_policy(&Policy::parse(&text).unwrap());
        s.checks.push(CheckDef { paths: vec!["svc/**".into(), "go.work.sum".into()], dir: Some("svc".into()), env: vec!["HOME".into()], ..check("test-svc", &["go", "test", "./..."]) });
        let out = apply(&text, &s).unwrap();
        let written = Policy::parse(&out).unwrap();
        assert_eq!(written.check[1], s.checks[1], "{out}");
        assert!(out.contains("paths = [\"svc/**\", \"go.work.sum\"]") && out.contains("dir = \"svc\""), "{out}");
        // Its first check is as it was, and the policy says which version reads these settings.
        assert_eq!(written.check[0], s.checks[0]);
        assert!(written.use05.min_version.is_some(), "an older use05 is told to upgrade rather than failing on `paths`:\n{out}");
    }

    #[test]
    fn what_the_questions_do_not_cover_is_left_alone() {
        let text = format!("{}\n# our own note\n[[trust.key]]\nname = \"ci\"\nrole = \"runner\"\npublic = \"use05-ed25519-public:AAAA\"\n", template()).replace("stop_budget_secs", "x").replace("[evidence]\n", "[evidence]\nstop_budget_secs = 30\n");
        let before = Policy::parse(&text);
        let s = Settings::from_policy(before.as_ref().unwrap_or(&Policy::default()));
        let out = apply(&text, &s).unwrap();
        assert!(out.contains("# our own note") && out.contains("stop_budget_secs = 30") && out.contains("[[trust.key]]"), "{out}");
        // Unchanged answers leave the file exactly as it was.
        assert_eq!(out, text);
    }

    #[test]
    fn a_result_that_would_not_parse_is_refused() {
        let text = template();
        let mut s = Settings::from_policy(&Policy::parse(&text).unwrap());
        s.environments = vec![Environment::new("dev", "main", None), Environment::new("dev", "uat", None)];
        assert!(apply(&text, &s).is_err());
    }
}


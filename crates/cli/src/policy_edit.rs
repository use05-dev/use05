//! Write a guided setup's answers into `.05/policy.toml`, changing only those settings: comments,
//! settings the questions do not cover and the order of the file are kept.

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};
use use05_core::policy::{CheckDef, Environment, IntentMode, LandMode, Policy, Severity};

/// The first use05 that reads `[[environment]]`.
const ENVIRONMENTS_SINCE: &str = "0.0.4";

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
    pub environments: Vec<Environment>,
    pub checks: Vec<CheckDef>,
    pub protect_paths: Vec<String>,
    pub locked: Vec<String>,
    pub append_only: Vec<String>,
    pub no_delete: Vec<String>,
    pub no_read: Vec<String>,
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
            environments: p.environment.clone(),
            checks: p.check.clone(),
            protect_paths: p.protect.paths.clone(),
            locked: p.protect.locked.clone(),
            append_only: p.protect.append_only.clone(),
            no_delete: p.protect.no_delete.clone(),
            no_read: p.protect.no_read.clone(),
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
        set(table(&mut doc, "intent"), "mode", word(&s.intent).into());
    }
    for (key, want, have) in [("scope", s.scope, now.scope), ("dependencies", s.dependencies, now.dependencies), ("overlap", s.overlap, now.overlap), ("tests", s.tests, now.tests)] {
        if want != have {
            set(table(&mut doc, "drift"), key, word(&want).into());
        }
    }
    if s.approvals_min != now.approvals_min {
        set(table(&mut doc, "approvals"), "min", i64::from(s.approvals_min).into());
    }
    if s.target != now.target {
        match &s.target {
            Some(t) => set(table(&mut doc, "branches"), "target", t.as_str().into()),
            None => {
                table(&mut doc, "branches").remove("target");
            }
        }
    }
    if s.land != now.land {
        set(table(&mut doc, "branches"), "land", word(&s.land).into());
    }
    for (key, want, have) in [
        ("paths", &s.protect_paths, &now.protect_paths),
        ("locked", &s.locked, &now.locked),
        ("append_only", &s.append_only, &now.append_only),
        ("no_delete", &s.no_delete, &now.no_delete),
        ("no_read", &s.no_read, &now.no_read),
    ] {
        if want != have {
            set(table(&mut doc, "protect"), key, strings(want));
        }
    }
    if s.environments != now.environments {
        doc.remove("environment");
        if !s.environments.is_empty() {
            let mut envs = ArrayOfTables::new();
            for e in &s.environments {
                let mut t = Table::new();
                t.insert("name", Item::Value(e.name.as_str().into()));
                t.insert("branch", Item::Value(e.branch.as_str().into()));
                envs.push(t);
            }
            doc.insert("environment", Item::ArrayOfTables(envs));
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
            if now.checks.iter().find(|o| o.name == c.name).map(|o| &o.run) != Some(&c.run) {
                set(&mut t, "run", strings(&c.run));
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
    if !s.environments.is_empty() {
        let min = doc.get("use05").and_then(|t| t.get("min_version")).and_then(Item::as_str).unwrap_or("0.0.0").to_string();
        if use05_core::policy::version_below(&min, ENVIRONMENTS_SINCE) {
            set(table(&mut doc, "use05"), "min_version", ENVIRONMENTS_SINCE.into());
        }
    }
    let out = doc.to_string();
    Policy::parse(&out).map_err(|e| e.message)?;
    Ok(out)
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
        s.environments = vec![Environment { name: "dev".into(), branch: "main".into() }, Environment { name: "prod".into(), branch: "production".into() }];
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
        s.environments = vec![Environment { name: "dev".into(), branch: "main".into() }, Environment { name: "dev".into(), branch: "uat".into() }];
        assert!(apply(&text, &s).is_err());
    }
}

//! Policy edits from the browser: a list of changes applied to the repository's own
//! `.05/policy.toml` with its comments and layout kept, then checked with 05's own parser and the
//! allowlist the helper enforces again on the machine.

use crate::guard;
use serde::Deserialize;
use serde_json::{Value, json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table};
use use05_core::policy::{CheckDef, Policy};

#[derive(Deserialize, Clone, Debug)]
pub struct Change {
    /// A section (`require`) or `section.key` (`protect.paths`).
    pub path: String,
    /// The new value; `null` removes it (back to the default).
    pub value: Value,
}

fn scalar(v: &Value) -> Result<toml_edit::Value, String> {
    Ok(match v {
        Value::String(s) => s.as_str().into(),
        Value::Bool(b) => (*b).into(),
        Value::Number(n) => n.as_i64().ok_or("numbers must be whole")?.into(),
        Value::Array(items) => {
            let mut a = Array::new();
            for i in items {
                a.push(scalar(i)?);
            }
            toml_edit::Value::Array(a)
        }
        Value::Object(map) => {
            let mut t = InlineTable::new();
            for (k, v) in map {
                if !v.is_null() {
                    t.insert(k, scalar(v)?);
                }
            }
            toml_edit::Value::InlineTable(t)
        }
        Value::Null => return Err("null inside a value".into()),
    })
}

fn table(map: &serde_json::Map<String, Value>) -> Result<Table, String> {
    let mut t = Table::new();
    for (k, v) in map {
        if !v.is_null() {
            t.insert(k, Item::Value(scalar(v)?));
        }
    }
    Ok(t)
}

fn set(doc: &mut DocumentMut, change: &Change) -> Result<(), String> {
    let parts: Vec<&str> = change.path.split('.').collect();
    let ok_name = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    if !parts.iter().all(|p| ok_name(p)) {
        return Err(format!("\"{}\" is not a policy setting", change.path));
    }
    match parts.as_slice() {
        [section] => match &change.value {
            Value::Null => {
                doc.remove(section);
            }
            Value::Array(items) if items.iter().all(Value::is_object) => {
                let mut list = ArrayOfTables::new();
                for item in items {
                    list.push(table(item.as_object().expect("checked"))?);
                }
                if list.is_empty() {
                    doc.remove(section);
                } else {
                    doc.insert(section, Item::ArrayOfTables(list));
                }
            }
            _ => return Err(format!("{section} takes a list of entries")),
        },
        [section, key] => {
            if !doc.contains_key(section) {
                doc.insert(section, Item::Table(Table::new()));
            }
            let t = doc[*section].as_table_mut().ok_or(format!("[{section}] is not a table in this file"))?;
            if change.value.is_null() {
                t.remove(key);
            } else {
                t.insert(key, Item::Value(scalar(&change.value)?));
            }
        }
        _ => return Err(format!("\"{}\" is too deep", change.path)),
    }
    Ok(())
}

pub struct Preview {
    pub toml: String,
    pub policy: Policy,
    pub changed: Vec<String>,
    pub terminal_only: Vec<String>,
    /// What the edit makes less strict: refused from a browser (D86).
    pub loosens: Vec<String>,
}

pub fn parse(text: &str) -> Result<Policy, String> {
    Policy::parse(text).map_err(|e| e.message)
}

/// What the edit would write, and whether the console may make it.
pub fn preview(current: &str, changes: &[Change], detected: &[CheckDef]) -> Result<Preview, String> {
    let old = parse(current)?;
    let mut doc: DocumentMut = current.parse().map_err(|e| format!("the current policy cannot be read: {e}"))?;
    for c in changes {
        set(&mut doc, c)?;
    }
    let toml = doc.to_string();
    let policy = parse(&toml)?;
    Ok(Preview { changed: guard::changed(&old, &policy), terminal_only: guard::terminal_only(&old, &policy, detected), loosens: guard::loosens(&old, &policy), toml, policy })
}

pub fn view(text: &str) -> Value {
    match parse(text) {
        Ok(p) => json!({ "ok": true, "policy": p }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

/// The changes that copy a template's editable settings into a repository's policy.
pub fn from_base(base: &str) -> Result<Vec<Change>, String> {
    let p = serde_json::to_value(parse(base)?).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for pointer in guard::EDITABLE {
        let path = pointer.trim_start_matches('/').replace('/', ".");
        let value = p.pointer(pointer).cloned().unwrap_or(Value::Null);
        match value {
            // A whole section becomes one change per key, so the file keeps its other keys.
            Value::Object(map) if !path.contains('.') => {
                for (k, v) in map {
                    out.push(Change { path: format!("{path}.{k}"), value: v });
                }
            }
            v => out.push(Change { path, value: v }),
        }
    }
    Ok(out)
}

/// One rule at a time (D88): set a setting, add to a list, or remove from one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Set,
    Add,
    Remove,
}

pub struct OneRule {
    pub preview: Preview,
    /// The setting before and after, as the policy reads it.
    pub before: Value,
    pub after: Value,
}

/// A value as typed: TOML (`2`, `true`, `["a", "b"]`, `{ when = [...] }`), or else plain text.
fn typed(text: &str) -> Value {
    toml::from_str::<toml::Table>(&format!("v = {text}")).ok().and_then(|t| t.get("v").cloned()).and_then(|v| serde_json::to_value(v).ok()).unwrap_or_else(|| Value::String(text.to_string()))
}

fn at<'a>(policy: &'a Value, path: &str) -> &'a Value {
    path.split('.').fold(policy, |v, k| &v[k])
}

/// Change one setting of `current` and say what it was and becomes. The file's comments and
/// layout stay; the result must still be a policy 05 reads.
pub fn one_rule(current: &str, op: Op, path: &str, value: &str) -> Result<OneRule, String> {
    let old = serde_json::to_value(parse(current)?).map_err(|e| e.to_string())?;
    let before = at(&old, path).clone();
    let given = typed(value);
    let after = match op {
        Op::Set => given,
        Op::Add => {
            let mut list = match &before {
                Value::Array(items) => items.clone(),
                Value::Null => Vec::new(),
                _ => return Err(format!("{path} is not a list: use set")),
            };
            if !list.contains(&given) {
                list.push(given);
            }
            Value::Array(list)
        }
        Op::Remove => {
            let Value::Array(items) = &before else { return Err(format!("{path} is not a list")) };
            let mut list = items.clone();
            let n = list.len();
            match &given {
                // A rule by its number in the list, from 1; or by its name.
                Value::Number(k) if list.iter().all(Value::is_object) => {
                    let k = k.as_u64().filter(|k| (1..=n as u64).contains(k)).ok_or(format!("{path} has no rule {k}; there are {n}"))?;
                    list.remove(k as usize - 1);
                }
                Value::String(name) if list.iter().all(Value::is_object) => list.retain(|r| r["name"] != *name),
                v => list.retain(|x| x != v),
            }
            if list.len() == n {
                return Err(format!("{value} is not in {path}"));
            }
            Value::Array(list)
        }
    };
    let preview = preview(current, &[Change { path: path.to_string(), value: after.clone() }], &[])?;
    let new = serde_json::to_value(&preview.policy).map_err(|e| e.to_string())?;
    // An empty list is not written out, so it reads back as nothing: say [].
    let after = match at(&new, path) {
        Value::Null if op != Op::Set => Value::Array(Vec::new()),
        v => v.clone(),
    };
    Ok(OneRule { preview, before, after })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# Our rules\n[protect]\n# migrations need a person\npaths = [\"migrations/**\"]\n\n[approvals]\nmin = 1\n";

    #[test]
    fn one_rule_is_set_added_or_removed_and_the_comments_stay() {
        let set = one_rule(FILE, Op::Set, "approvals.min", "2").unwrap();
        assert_eq!((set.before.clone(), set.after.clone()), (json!(1), json!(2)));
        assert!(set.preview.toml.contains("# migrations need a person"), "{}", set.preview.toml);
        let add = one_rule(FILE, Op::Add, "protect.paths", "\"billing/**\"").unwrap();
        assert_eq!(add.after, json!(["migrations/**", "billing/**"]));
        assert!(add.preview.loosens.is_empty());
        let removed = one_rule(FILE, Op::Remove, "protect.paths", "migrations/**").unwrap();
        assert_eq!(removed.after, json!([]));
        assert_eq!(removed.preview.loosens, vec!["protect.paths".to_string()], "a terminal may loosen; it is said");
        // A rule given as an inline table, then removed by its number.
        let rule = one_rule(FILE, Op::Add, "require", "{ when = [\"src/**\"], also = [\"docs/**\"], why = \"docs follow code\" }").unwrap();
        assert_eq!(rule.after[0]["also"], json!(["docs/**"]));
        let gone = one_rule(&rule.preview.toml, Op::Remove, "require", "1").unwrap();
        assert_eq!(gone.after, json!([]));
        // Testing before a push (D87), one setting at a time.
        assert_eq!(one_rule(FILE, Op::Set, "testing.local", "required").unwrap().preview.policy.testing.local, use05_core::policy::LocalTesting::Required);
    }

    #[test]
    fn one_rule_refuses_what_is_not_a_setting_or_not_there() {
        assert!(one_rule(FILE, Op::Set, "approvals.most", "2").is_err(), "not a setting");
        assert!(one_rule(FILE, Op::Set, "approvals.min", "\"lots\"").is_err(), "not a number");
        assert!(one_rule(FILE, Op::Remove, "protect.paths", "vendor/**").is_err(), "not in the list");
        assert!(one_rule(FILE, Op::Add, "approvals.min", "3").is_err(), "not a list");
    }

    #[test]
    fn a_preview_reports_loosening() {
        let current = "[protect]\npaths = [\"migrations/**\"]\n";
        let p = preview(current, &[Change { path: "protect.paths".into(), value: json!([]) }], &[]).unwrap();
        assert_eq!(p.loosens, vec!["protect.paths".to_string()]);
        let tighter = preview(current, &[Change { path: "protect.locked".into(), value: json!(["vendor/**"]) }], &[]).unwrap();
        assert!(tighter.loosens.is_empty());
    }

    #[test]
    fn an_edit_keeps_comments_and_other_settings() {
        let current = "# our rules\n[protect]\npaths = [\"migrations/**\"] # careful\nbypass = true\n";
        let p = preview(current, &[Change { path: "protect.locked".into(), value: json!(["vendor/**"]) }], &[]).unwrap();
        assert!(p.toml.contains("# our rules") && p.toml.contains("# careful") && p.toml.contains("locked = [\"vendor/**\"]"), "{}", p.toml);
        assert_eq!(p.changed, vec!["protect.locked".to_string()]);
        assert!(p.terminal_only.is_empty());
    }

    #[test]
    fn lists_of_entries_and_removal() {
        let p = preview("", &[Change { path: "require".into(), value: json!([{ "when": ["src/**"], "also": ["docs/**"], "severity": "warn" }]) }], &[]).unwrap();
        assert_eq!(p.policy.require.len(), 1);
        let back = preview(&p.toml, &[Change { path: "require".into(), value: json!([]) }], &[]).unwrap();
        assert!(back.policy.require.is_empty());
    }

    #[test]
    fn terminal_only_settings_are_reported_and_bad_names_refused() {
        let p = preview("", &[Change { path: "approvals.min".into(), value: json!(2) }], &[]).unwrap();
        assert_eq!(p.terminal_only, vec!["approvals.min".to_string()]);
        assert!(preview("", &[Change { path: "../x".into(), value: json!(1) }], &[]).is_err());
    }

    #[test]
    fn a_template_becomes_changes_that_need_no_terminal() {
        let base = "[drift]\nscope = \"deny\"\n[protect]\nlocked = [\"vendor/**\"]\n[approvals]\nmin = 2\n";
        let changes = from_base(base).unwrap();
        let p = preview("[[check]]\nname = \"t\"\nrun = [\"true\"]\n", &changes, &[]).unwrap();
        assert!(p.terminal_only.is_empty(), "{:?}", p.terminal_only);
        assert_eq!(p.policy.approvals.min, 1, "a terminal-only setting is not copied");
        assert_eq!(p.policy.check.len(), 1, "the repository's checks are kept");
    }
}

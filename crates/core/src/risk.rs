//! Risk categories: which paths make a change risky, decided by fixed rules and never by a
//! model. Carried over from 05's predecessor project. Policy may add rules and raise levels; an
//! agent cannot lower risk. A repository may exempt a path a pattern catches by mistake, unless
//! its organisation forbids exemptions.

use serde::{Deserialize, Serialize};

use crate::glob;
use crate::intent::Risk;
use crate::policy::Policy;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub category: String,
    pub level: Risk,
    pub paths: Vec<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub category: String,
    pub level: Risk,
    pub paths: Vec<String>,
}

const BUILTIN: &[(&str, Risk, &[&str])] = &[
    ("auth", Risk::High, &["**/auth/**", "**/authn*/**", "**/authz*/**", "**/*login*", "**/*session*", "**/*oauth*", "**/*jwt*", "**/*permission*", "**/*rbac*", "**/*acl*"]),
    ("money", Risk::High, &["**/payment*/**", "**/billing/**", "**/checkout/**", "**/*invoice*", "**/*ledger*", "**/*refund*", "**/*stripe*"]),
    ("migration", Risk::High, &["**/migrations/**", "**/migrate/**", "*.sql"]),
    ("persistence", Risk::Medium, &["**/db/**", "**/database/**", "*.prisma", "**/schema.*"]),
    ("secrets", Risk::High, &["*.env", ".env*", "**/secrets*/**", "*secret*", "*credential*", "*.pem", "*.key", "id_rsa*"]),
    ("network", Risk::Medium, &["*webhook*", "**/proxy*/**", "*cors*", "**/*http*client*"]),
    ("privilege", Risk::High, &["*privilege*", "*sudo*", "*capabilit*"]),
    (
        "deployment",
        Risk::High,
        &[".github/workflows/**", "**/deploy*/**", "Dockerfile*", "k8s/**", "helm/**", "*.tf", "docker-compose*.yml", "docker-compose*.yaml", "Jenkinsfile"],
    ),
];

pub fn builtin() -> Vec<Rule> {
    BUILTIN.iter().map(|(c, l, p)| Rule { category: c.to_string(), level: *l, paths: p.iter().map(|s| s.to_string()).collect() }).collect()
}

/// The categories that changed paths fall into.
pub fn of_paths(policy: &Policy, paths: &[String]) -> Vec<Reason> {
    let exempt = |p: &str| policy.risk.exempt_allowed && policy.risk.exempt.iter().any(|e| glob::matches(e, p));
    let candidates: Vec<&String> = paths.iter().filter(|p| !exempt(p)).collect();
    let mut out = classify(builtin().into_iter().chain(policy.risk.rules.iter().cloned()), |pattern| candidates.iter().filter(|p| glob::matches(pattern, p)).map(|p| p.to_string()).collect());
    // The organisation's own rules apply to every path: a repository cannot exempt its way out.
    merge(&mut out, classify(policy.risk.locked.iter().cloned(), |pattern| paths.iter().filter(|p| glob::matches(pattern, p)).cloned().collect()));
    out
}

fn merge(into: &mut Vec<Reason>, more: Vec<Reason>) {
    for r in more {
        match into.iter_mut().find(|x| x.category == r.category) {
            Some(existing) => {
                existing.level = existing.level.max(r.level);
                existing.paths.extend(r.paths);
                existing.paths.sort();
                existing.paths.dedup();
            }
            None => into.push(r),
        }
    }
    into.sort_by(|a, b| a.category.cmp(&b.category));
}

fn classify(rules: impl Iterator<Item = Rule>, hits: impl Fn(&str) -> Vec<String>) -> Vec<Reason> {
    let mut out: Vec<Reason> = Vec::new();
    for rule in rules {
        let mut found: Vec<String> = rule.paths.iter().flat_map(|pattern| hits(pattern)).collect();
        if found.is_empty() {
            continue;
        }
        match out.iter_mut().find(|r| r.category == rule.category) {
            Some(existing) => {
                existing.level = existing.level.max(rule.level);
                existing.paths.append(&mut found);
            }
            None => out.push(Reason { category: rule.category, level: rule.level, paths: found }),
        }
    }
    for r in &mut out {
        r.paths.sort();
        r.paths.dedup();
    }
    out.sort_by(|a, b| a.category.cmp(&b.category));
    out
}

/// The categories a declared scope reaches. Each scope pattern is tested as if it were a path,
/// so `src/payments/**` is money and `src/**` is nothing in particular.
pub fn of_scope(policy: &Policy, include: &[String]) -> Vec<Reason> {
    // Exemptions apply to a declared scope as they do to changed paths; the floor's rules do not
    // take exemptions.
    let candidates: Vec<&String> = include.iter().filter(|s| !(policy.risk.exempt_allowed && policy.risk.exempt.iter().any(|e| covers(e, s)))).collect();
    let mut out = classify(builtin().into_iter().chain(policy.risk.rules.iter().cloned()), |pattern| candidates.iter().filter(|s| glob::matches(pattern, s)).map(|s| s.to_string()).collect());
    merge(&mut out, classify(policy.risk.locked.iter().cloned(), |pattern| include.iter().filter(|s| glob::matches(pattern, s)).cloned().collect()));
    out
}

/// Does exemption `e` cover every path scope pattern `s` can match? Exactly the same pattern, a
/// `dir/**` exemption over anything under `dir/`, or a plain path the exemption matches.
fn covers(e: &str, s: &str) -> bool {
    if e == s {
        return true;
    }
    if let Some(dir) = e.strip_suffix("/**") {
        return s.starts_with(&format!("{dir}/"));
    }
    !s.contains('*') && !s.contains('?') && glob::matches(e, s)
}

/// The highest level among `reasons`.
pub fn highest(reasons: &[Reason]) -> Risk {
    reasons.iter().map(|r| r.level).max().unwrap_or(Risk::Low)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Floor;

    fn paths(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    fn cats(reasons: &[Reason]) -> Vec<(String, Risk)> {
        reasons.iter().map(|r| (r.category.clone(), r.level)).collect()
    }

    #[test]
    fn builtin_categories_match_the_predecessor() {
        let p = Policy::default();
        assert_eq!(cats(&of_paths(&p, &paths(&["src/payments/retry.rs"]))), [("money".to_string(), Risk::High)]);
        assert_eq!(cats(&of_paths(&p, &paths(&["migrations/001.sql"]))), [("migration".to_string(), Risk::High)]);
        assert_eq!(cats(&of_paths(&p, &paths(&["src/db/pool.rs"]))), [("persistence".to_string(), Risk::Medium)]);
        assert!(of_paths(&p, &paths(&["README.md", "src/lib.rs"])).is_empty());
        let both = of_paths(&p, &paths(&["src/auth/login.rs", "src/auth/jwt.rs"]));
        assert_eq!(both.len(), 1, "one reason per category, listing every path");
        assert_eq!(both[0].paths, ["src/auth/jwt.rs", "src/auth/login.rs"]);
    }

    #[test]
    fn a_scope_is_judged_by_its_own_pattern() {
        let p = Policy::default();
        assert_eq!(cats(&of_scope(&p, &paths(&["src/payments/**"]))), [("money".to_string(), Risk::High)]);
        assert!(of_scope(&p, &paths(&["src/**"])).is_empty());
    }

    #[test]
    fn a_repo_exemption_works_unless_the_floor_forbids_it() {
        let mut p = Policy::default();
        p.risk.exempt = paths(&["src/session_store.rs"]);
        assert!(of_paths(&p, &paths(&["src/session_store.rs"])).is_empty());
        p.tighten(&Floor { risk_exempt_allowed: Some(false), ..Floor::default() });
        assert_eq!(cats(&of_paths(&p, &paths(&["src/session_store.rs"]))), [("auth".to_string(), Risk::High)]);
    }

    #[test]
    fn a_repo_cannot_exempt_its_way_out_of_a_category_the_floor_added() {
        let mut p = Policy::default();
        p.risk.exempt = paths(&["infra/**"]);
        p.tighten(&Floor { risk_rules: vec![Rule { category: "infra".into(), level: Risk::High, paths: paths(&["infra/**"]) }], ..Floor::default() });
        assert_eq!(cats(&of_paths(&p, &paths(&["infra/vars.txt"]))), [("infra".to_string(), Risk::High)]);
    }

    #[test]
    fn an_exempted_path_does_not_make_a_declared_scope_risky_either() {
        let mut p = Policy::default();
        p.risk.exempt = paths(&["src/session_store.rs"]);
        assert!(of_scope(&p, &paths(&["src/session_store.rs"])).is_empty());
        p.tighten(&Floor { risk_exempt_allowed: Some(false), ..Floor::default() });
        assert_eq!(cats(&of_scope(&p, &paths(&["src/session_store.rs"]))), [("auth".to_string(), Risk::High)]);
    }

    #[test]
    fn an_exemption_covers_a_scope_only_if_it_covers_all_of_it() {
        let mut p = Policy::default();
        p.risk.exempt = paths(&["src/auth/*"]);
        assert_eq!(cats(&of_scope(&p, &paths(&["src/auth/**"]))), [("auth".to_string(), Risk::High)], "one level does not cover any depth");
        p.risk.exempt = paths(&["src/auth/**"]);
        assert!(of_scope(&p, &paths(&["src/auth/**"])).is_empty());
    }

    #[test]
    fn policy_rules_add_categories_and_the_floor_adds_its_own() {
        let mut p = Policy::default();
        p.risk.rules = vec![Rule { category: "pricing".into(), level: Risk::Medium, paths: paths(&["src/pricing/**"]) }];
        assert_eq!(cats(&of_paths(&p, &paths(&["src/pricing/x.rs"]))), [("pricing".to_string(), Risk::Medium)]);
        p.tighten(&Floor { risk_rules: vec![Rule { category: "infra".into(), level: Risk::High, paths: paths(&["infra/**"]) }], ..Floor::default() });
        assert_eq!(cats(&of_paths(&p, &paths(&["infra/main.tf"]))), [("deployment".to_string(), Risk::High), ("infra".to_string(), Risk::High)]);
    }
}

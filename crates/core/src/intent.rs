//! The intent card: what a change is for and where it may touch. A screenful, in TOML.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::glob;
use crate::policy::Policy;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IntentCard {
    pub title: String,
    pub goal: String,
    pub scope: Scope,
    /// Things deliberately not part of this change, in words.
    pub out_of_scope: Vec<String>,
    /// Names of policy checks that must pass for this change.
    pub acceptance: Vec<String>,
    /// The author promises not to touch dependency files.
    pub no_new_dependencies: bool,
    /// The branch this work lands on, if not the policy's default (D69).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Scope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn word(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

const DEP_NAMES: &[&str] = &[
    "Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lockb", "bun.lock", "go.mod", "go.sum", "pyproject.toml", "poetry.lock", "uv.lock",
    "Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "gradle.lockfile", "mix.exs", "mix.lock", "Package.swift", "Package.resolved",
];

pub fn is_dependency_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    DEP_NAMES.contains(&name) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

/// Paths 05 always protects, on top of whatever the policy lists: its own rules.
pub const ALWAYS_PROTECTED: &[&str] = &[".05/**"];

pub fn is_protected(policy: &Policy, path: &str) -> bool {
    ALWAYS_PROTECTED.iter().any(|p| glob::matches(p, path))
        || policy.protect.paths.iter().any(|p| glob::matches(p, path))
}

impl IntentCard {
    pub fn parse(text: &str) -> Result<IntentCard> {
        toml::from_str(text).map_err(|e| {
            Error::new("INTENT_INVALID", format!("the intent card is not valid: {}", e.message()))
                .with_next("see `use05 start --help` for the card format")
        })
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("card serialises")
    }

    /// Stable digest. Approvals bind to it, so editing the card invalidates them.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(serde_json::to_vec(self).expect("card serialises")))
    }

    pub fn has_scope(&self) -> bool {
        !self.scope.include.is_empty()
    }

    /// Does the card's declared scope reach into a protected area or a dependency file?
    pub fn risk(&self, policy: &Policy) -> Risk {
        let mut risk = crate::risk::highest(&crate::risk::of_scope(policy, &self.scope.include));
        for pattern in &self.scope.include {
            let protected = ALWAYS_PROTECTED.iter().copied().chain(policy.protect.paths.iter().map(String::as_str));
            if protected.into_iter().any(|p| glob::overlaps(pattern, p)) {
                return Risk::High;
            }
            if DEP_NAMES.iter().any(|d| glob::overlaps(pattern, d)) {
                risk = risk.max(Risk::Medium);
            }
        }
        risk
    }

    /// Is `path` inside the declared scope? Without a declared scope everything is "inside".
    pub fn allows(&self, path: &str) -> bool {
        if self.scope.exclude.iter().any(|p| glob::matches(p, path)) {
            return false;
        }
        !self.has_scope() || self.scope.include.iter().any(|p| glob::matches(p, path))
    }
}

/// Risk of what actually changed: protected paths are high, dependency files medium.
pub fn risk_of_paths<'a>(policy: &Policy, paths: impl IntoIterator<Item = &'a str>) -> Risk {
    let mut risk = Risk::Low;
    let mut all = Vec::new();
    for path in paths {
        all.push(path.to_string());
        if is_protected(policy, path) {
            risk = Risk::High;
        }
        if is_dependency_file(path) {
            risk = risk.max(Risk::Medium);
        }
    }
    risk.max(crate::risk::highest(&crate::risk::of_paths(policy, &all)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_round_trips_and_digest_tracks_content() {
        let card = IntentCard {
            title: "Cap retries".into(),
            goal: "Stop after three".into(),
            scope: Scope { include: vec!["src/payments/**".into()], exclude: vec!["src/payments/ledger/**".into()] },
            acceptance: vec!["test".into()],
            ..Default::default()
        };
        let again = IntentCard::parse(&card.to_toml()).unwrap();
        assert_eq!(card, again);
        assert_eq!(card.digest(), again.digest());
        let mut edited = card.clone();
        edited.goal.push('!');
        assert_ne!(card.digest(), edited.digest());
    }

    #[test]
    fn scope_and_risk() {
        let policy = Policy::default();
        let card = IntentCard { scope: Scope { include: vec!["src/**".into()], exclude: vec!["src/gen/**".into()] }, ..Default::default() };
        assert!(card.allows("src/a.rs"));
        assert!(!card.allows("src/gen/x.rs"));
        assert!(!card.allows("docs/a.md"));
        assert!(IntentCard::default().allows("anything"), "no declared scope means no scope check");
        assert_eq!(card.risk(&policy), Risk::Low);
        let touches_rules = IntentCard { scope: Scope { include: vec![".05/**".into()], ..Default::default() }, ..Default::default() };
        assert_eq!(touches_rules.risk(&policy), Risk::High);
        assert_eq!(risk_of_paths(&policy, ["a.rs", "Cargo.lock"]), Risk::Medium);
        assert_eq!(risk_of_paths(&policy, ["a.rs", ".05/policy.toml"]), Risk::High);
    }

    #[test]
    fn unknown_fields_are_rejected_so_typos_do_not_silently_weaken_a_card() {
        assert!(IntentCard::parse("titel = \"x\"").is_err());
    }
}

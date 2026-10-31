//! What a guided setup needs to know about a repository: its long-lived branches, which
//! environment each probably is, and the starting rules for the kind of team working in it (D82).

use std::path::Path;

use crate::policy::{IntentMode, Policy, Severity};

/// An environment's role on the ladder, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Dev,
    Uat,
    PreProd,
    Prod,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Dev, Role::Uat, Role::PreProd, Role::Prod];

    pub fn name(self) -> &'static str {
        match self {
            Role::Dev => "dev",
            Role::Uat => "uat",
            Role::PreProd => "pre-prod",
            Role::Prod => "prod",
        }
    }

    pub fn from_name(name: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// The role a branch's name suggests, if any. Only a suggestion: the person decides.
pub fn suggest_role(branch: &str) -> Option<Role> {
    match branch.to_ascii_lowercase().as_str() {
        "main" | "master" | "develop" | "development" | "dev" | "trunk" => Some(Role::Dev),
        "qa" | "test" | "testing" | "uat" | "staging" => Some(Role::Uat),
        "preprod" | "pre-prod" | "pre-production" | "stage" => Some(Role::PreProd),
        "prod" | "production" | "live" | "release" => Some(Role::Prod),
        _ => None,
    }
}

/// A branch worth asking about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: String,
    pub local: bool,
    pub remote: bool,
}

/// Long-lived branches, here and on `origin`: not agents' working branches, not bots' branches,
/// not temporary ones. Lowest suggested role first, then branches with no suggestion, each by name.
pub fn scan(top: &Path, policy: &Policy) -> Vec<BranchInfo> {
    let refs = crate::git::text(top, &["for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes/origin"]).unwrap_or_default();
    let mut out: Vec<BranchInfo> = Vec::new();
    for r in refs.lines() {
        let (name, local) = match (r.strip_prefix("refs/heads/"), r.strip_prefix("refs/remotes/origin/")) {
            (Some(n), _) => (n, true),
            (None, Some(n)) => (n, false),
            _ => continue,
        };
        let temporary = name == "HEAD"
            || crate::branches::is_work(policy, name)
            || ["dependabot/", "renovate/", "promote-"].iter().any(|p| name.starts_with(p))
            || name.ends_with("-tmp");
        if temporary {
            continue;
        }
        match out.iter_mut().find(|b| b.name == name) {
            Some(b) if local => b.local = true,
            Some(b) => b.remote = true,
            None => out.push(BranchInfo { name: name.to_string(), local, remote: !local }),
        }
    }
    out.sort_by(|a, b| {
        let rank = |n: &str| suggest_role(n).map_or(Role::ALL.len(), |r| r as usize);
        rank(&a.name).cmp(&rank(&b.name)).then(a.name.cmp(&b.name))
    });
    out
}

/// Who works in the repository: the starting point for how strict the rules are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Team {
    Solo,
    Small,
    Regulated,
}

impl Team {
    pub fn from_name(name: &str) -> Option<Team> {
        match name {
            "solo" => Some(Team::Solo),
            "small" => Some(Team::Small),
            "regulated" => Some(Team::Regulated),
            _ => None,
        }
    }
}

/// The settings a team's preset starts from; every one can be changed afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    pub intent: IntentMode,
    pub scope: Severity,
    pub dependencies: Severity,
    pub overlap: Severity,
    pub tests: Severity,
    pub approvals_min: u32,
}

pub fn preset(team: Team) -> Preset {
    match team {
        Team::Solo => Preset { intent: IntentMode::Inferred, scope: Severity::Warn, dependencies: Severity::Warn, overlap: Severity::Warn, tests: Severity::Approval, approvals_min: 1 },
        Team::Small => Preset { intent: IntentMode::Risky, scope: Severity::Approval, dependencies: Severity::Approval, overlap: Severity::Approval, tests: Severity::Approval, approvals_min: 1 },
        Team::Regulated => Preset { intent: IntentMode::Always, scope: Severity::Deny, dependencies: Severity::Approval, overlap: Severity::Deny, tests: Severity::Deny, approvals_min: 2 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git").arg("-C").arg(dir).args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
        assert!(ok.status.success(), "{args:?}: {}", String::from_utf8_lossy(&ok.stderr));
    }

    #[test]
    fn long_lived_branches_are_found_locally_and_on_origin_and_work_branches_left_out() {
        let origin = tempfile::tempdir().unwrap();
        git(origin.path(), &["init", "-q", "-b", "main"]);
        git(origin.path(), &["commit", "-q", "--allow-empty", "-m", "first"]);
        for b in ["uat", "production", "claude/fix-1", "dependabot/npm/x", "feature-tmp"] {
            git(origin.path(), &["branch", b]);
        }
        let clone = tempfile::tempdir().unwrap();
        git(clone.path(), &["clone", "-q", origin.path().to_str().unwrap(), "."]);
        git(clone.path(), &["branch", "dev"]);
        let names: Vec<String> = scan(clone.path(), &Policy::default()).into_iter().map(|b| b.name).collect();
        assert_eq!(names, ["dev", "main", "uat", "production"], "ladder order by suggested role, then name");
    }

    #[test]
    fn roles_are_suggested_from_common_names() {
        let cases = [("main", Some(Role::Dev)), ("develop", Some(Role::Dev)), ("staging", Some(Role::Uat)), ("QA", Some(Role::Uat)), ("pre-prod", Some(Role::PreProd)), ("production", Some(Role::Prod)), ("live", Some(Role::Prod)), ("feature/x", None)];
        for (name, role) in cases {
            assert_eq!(suggest_role(name), role, "{name}");
        }
        assert_eq!(Role::PreProd.name(), "pre-prod");
        assert_eq!(Role::from_name("pre-prod"), Some(Role::PreProd));
    }

    #[test]
    fn presets_get_stricter_with_the_team() {
        let solo = preset(Team::Solo);
        assert_eq!((solo.intent, solo.scope, solo.tests, solo.approvals_min), (IntentMode::Inferred, Severity::Warn, Severity::Approval, 1));
        let small = preset(Team::Small);
        assert_eq!((small.intent, small.scope, small.dependencies, small.overlap, small.approvals_min), (IntentMode::Risky, Severity::Approval, Severity::Approval, Severity::Approval, 1));
        let reg = preset(Team::Regulated);
        assert_eq!((reg.intent, reg.scope, reg.overlap, reg.tests, reg.approvals_min), (IntentMode::Always, Severity::Deny, Severity::Deny, Severity::Deny, 2));
    }
}

//! Policy: what a repository requires, what it protects, and who it trusts.
//!
//! Layers: built-in defaults, then the repository's `.05/policy.toml`, then an organisation
//! floor. The floor can only tighten: it never loosens what a repository asked for.
//! A change's rules are read from its *base*, never from the change itself.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::git;

pub const POLICY_PATH: &str = ".05/policy.toml";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IntentMode {
    /// No card; scope is inferred. The solo default.
    Inferred,
    /// A card is required when the change is not low risk.
    Risky,
    /// A card is required for every task.
    Always,
}

/// What a finding does. Ordered by how strongly it holds the change back.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Allow,
    Warn,
    Approval,
    Deny,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A key on a developer's own machine. Advisory: an agent running as that user can use it.
    Local,
    /// A key held where the agent cannot reach, such as a CI secret. Authoritative.
    Runner,
    /// A person's passphrase-protected key. Signs approvals and bypasses.
    Approver,
}

impl Role {
    pub fn word(self) -> &'static str {
        match self {
            Role::Local => "local",
            Role::Runner => "runner",
            Role::Approver => "approver",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Middle {
    Local,
    Off,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    Open,
    Closed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct CheckDef {
    pub name: String,
    pub run: Vec<String>,
    pub required: bool,
    /// Variables the check may be given by name. Values are never stored.
    pub env: Vec<String>,
    pub timeout_secs: u64,
    /// The check is required only for a change that touches one of these paths (D97). Empty: always.
    /// Unset ones are not written, so existing digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// The folder of the exact tree the check runs in, relative to its root (D97).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

impl Default for CheckDef {
    fn default() -> CheckDef {
        CheckDef { name: String::new(), run: Vec::new(), required: true, env: Vec::new(), timeout_secs: 900, paths: Vec::new(), dir: None }
    }
}

impl CheckDef {
    /// Whether a change that touches `changed` calls for this check: always, unless it names
    /// `paths` and the change touches none of them.
    pub fn applies_to<'a>(&self, changed: impl IntoIterator<Item = &'a str>) -> bool {
        self.paths.is_empty() || changed.into_iter().any(|file| self.covers(file))
    }

    /// Whether one of this check's `paths` names `file`. A bare `**` (or `**/*`) names every file.
    pub fn covers(&self, file: &str) -> bool {
        paths_cover(&self.paths, file)
    }
}

/// A command that asks an environment which commit it runs (D93), run like a check: in an export
/// of the deployed commit's exact tree, with a scrubbed environment, the variables it names and a
/// time limit. It confirms the deploy once it exits 0 and prints the commit's id (in full, or 12
/// or more of its first characters); 05 asks again every `interval_secs` until it does or
/// `wait_minutes` pass.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Probe {
    pub name: String,
    pub run: Vec<String>,
    /// Variables the probe may be given by name. Values are never stored.
    pub env: Vec<String>,
    /// The folder of the exported tree it runs in, relative to its root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// How long one try may take.
    pub timeout_secs: u64,
    /// How long to keep asking. `0`: one try.
    pub wait_minutes: u32,
    /// How long to wait between tries.
    pub interval_secs: u32,
}

impl Default for Probe {
    fn default() -> Probe {
        Probe { name: String::new(), run: Vec::new(), env: Vec::new(), dir: None, timeout_secs: 60, wait_minutes: 10, interval_secs: 15 }
    }
}

/// Whether one of `patterns` names `file`. A bare `**` (or `**/*`) names every file, which the
/// plain matcher does not say of a pattern with no folder in it.
pub fn paths_cover(patterns: &[String], file: &str) -> bool {
    patterns.iter().any(|p| matches!(p.trim_start_matches("./"), "**" | "**/*") || crate::glob::matches(p, file))
}

/// A folder inside the exact tree: relative, not empty, and with no `..` in it. Backslashes and
/// colons (a Windows drive) are refused too, so no spelling of the path can lead out.
fn is_inside_tree(dir: &str) -> bool {
    !dir.trim().is_empty() && !dir.starts_with('/') && !dir.contains(['\\', ':']) && !dir.split('/').any(|part| part == "..")
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct TrustKey {
    pub name: String,
    pub role: Role,
    /// `use05-ed25519-public:...`
    pub public: String,
    /// After this date (`2027-01-31`, or an RFC 3339 time) the key is no longer trusted, so what
    /// it signed stops counting. A leaked CI key therefore cannot stay trusted forever.
    pub expires: Option<String>,
    /// Whose key this is, for a passkey: the person whose work it may approve (D86). Compared with
    /// the name the work's owner was recorded under, ignoring case and surrounding spaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
}

impl TrustKey {
    /// When the key stops being trusted, in seconds. A bare date means the end of that day (UTC).
    pub fn expires_at(&self) -> Option<u64> {
        let text = self.expires.as_deref()?.trim();
        let full = if text.len() == 10 { format!("{text}T23:59:59Z") } else { text.to_string() };
        crate::time::parse_rfc3339(&full)
    }
}

impl Default for TrustKey {
    fn default() -> TrustKey {
        TrustKey { name: String::new(), role: Role::Runner, public: String::new(), expires: None, person: None }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Unset in a policy that does not say; then it is not written out, so existing digests hold.
    #[serde(skip_serializing_if = "Use05Policy::is_unset")]
    pub use05: Use05Policy,
    pub intent: IntentPolicy,
    pub check: Vec<CheckDef>,
    pub protect: Protect,
    pub drift: DriftPolicy,
    pub evidence: EvidencePolicy,
    pub approvals: ApprovalPolicy,
    pub record: RecordPolicy,
    pub enforce: EnforcePolicy,
    pub env: EnvPolicy,
    pub trust: TrustPolicy,
    pub risk: RiskPolicy,
    pub branches: BranchPolicy,
    /// The environments, lowest first: which branch is dev, uat, pre-prod, prod (D77, D82).
    /// Each says how a promotion into it is judged (D93). Not written out when empty,
    /// so existing digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<Environment>,
    /// Files that must change together: when a change touches `when`, it must also touch `also`.
    /// Not written out when empty, so existing digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub require: Vec<Require>,
    /// Whether a person must have tried a change themselves before it is pushed (D87). Not written
    /// out while off, so existing digests hold.
    #[serde(skip_serializing_if = "TestingPolicy::is_off")]
    pub testing: TestingPolicy,
    /// Named groups of people (D92), for path owners and sign-offs. Not written out when empty,
    /// so existing digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signer: Vec<SignerGroup>,
    /// Places outside this repository a branch or a folder is promoted to (D93): another remote's
    /// branch, or a folder copied into another repository. Not written out when empty, so existing
    /// digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub destination: Vec<Destination>,
    /// Where an agent may push (D93). Not written out while unset, so existing digests hold.
    #[serde(skip_serializing_if = "PushPolicy::is_unset")]
    pub push: PushPolicy,
}

/// A named group of people (`[[signer]]`, D92). A person is matched, ignoring case and
/// surrounding spaces, to the `person` on a trusted key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerGroup {
    pub name: String,
    pub people: Vec<String>,
}

/// Who owns some paths (`[[protect.owner]]`, D92): a change to them needs, besides the approvals
/// it needs anyway, approvals of its outcome from `min` distinct people that `signers` name.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerRule {
    pub paths: Vec<String>,
    /// Group names or people's names.
    pub signers: Vec<String>,
    #[serde(default = "one")]
    pub min: u32,
}

fn one() -> u32 {
    1
}

/// How people's names are compared: ignoring case and surrounding spaces.
pub fn same_person(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// An owner rule with the people its signers name, as the gate reads it. A floor's rules are kept
/// in this form (`protect.floor_owner`), resolved against the floor's own groups.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedOwner {
    pub paths: Vec<String>,
    pub signers: Vec<String>,
    pub min: u32,
    pub people: Vec<String>,
    /// For a floor's rule, the only keys whose `person` counts for it: the floor's own. A key the
    /// repository lists, whatever person it names, never counts for the organisation's rule.
    /// `None` for a repository's rule, which goes by every trusted key's `person`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<TrustKey>>,
}

impl ResolvedOwner {
    /// Whose key this is, for this rule: the floor's own entry for it for a floor's rule (an
    /// expired one names nobody), else whatever person the trusted keys name.
    pub fn person_of(&self, key_id: &str, trust: &crate::evidence::Trust, now: u64) -> Option<String> {
        let Some(keys) = &self.keys else { return trust.person_of(key_id) };
        // Only an approver entry names whose signature it is: a machine key named for a person
        // (a preparer, D86) signs without them, so its `person` makes nobody an owner.
        keys.iter()
            .filter(|k| k.role == Role::Approver)
            .filter(|k| k.expires.is_none() || k.expires_at().is_some_and(|t| t >= now))
            .filter(|k| use05_receipt::parse_any_public_key(&k.public).is_ok_and(|p| p.id() == key_id))
            .find_map(|k| k.person.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(str::to_string))
    }

    /// The changed files this rule owns.
    pub fn touched(&self, changed: &[String]) -> Vec<String> {
        changed.iter().filter(|p| self.paths.iter().any(|g| crate::glob::matches(g, p))).cloned().collect()
    }

    /// `billing/** needs 1 of eng-managers`.
    pub fn describe(&self) -> String {
        format!("{} needs {} of {}", self.paths.join(", "), self.min, self.signers.join(", "))
    }
}

/// The people `signers` name in `groups`: each group's people in its place, plain names kept,
/// trimmed, each person once.
fn people_in(groups: &[SignerGroup], signers: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        let name = name.trim();
        if !name.is_empty() && !out.iter().any(|p| same_person(p, name)) {
            out.push(name.to_string());
        }
    };
    for s in signers {
        match groups.iter().find(|g| same_person(&g.name, s)) {
            Some(group) => group.people.iter().for_each(|p| add(p)),
            None => add(s),
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Whose {
    Repository,
    Floor,
}

/// No group takes the name of a person a key belongs to (or a rule naming that person would mean
/// whoever the group lists), and no key belongs to two people.
fn check_people(groups: &[SignerGroup], keys: &[TrustKey], table: &str) -> Result<()> {
    fn person(k: &TrustKey) -> Option<&str> {
        k.person.as_deref().map(str::trim).filter(|p| !p.is_empty())
    }
    for (i, k) in keys.iter().enumerate() {
        let Some(p) = person(k) else { continue };
        if let Some(q) = keys[..i].iter().filter(|o| o.public.trim() == k.public.trim()).filter_map(person).find(|q| !same_person(p, q)) {
            return Err(Error::new("POLICY_INVALID", format!("the key {:?} is listed for two people, {q} and {p}; a key belongs to one person", k.name)));
        }
    }
    if let Some(g) = groups.iter().find(|g| keys.iter().filter_map(person).any(|p| same_person(p, &g.name))) {
        return Err(Error::new("SIGNER_NAME_TAKEN", format!("the {table} group {:?} has the name of a person with a trusted key", g.name)).with_next("give the group a name no person has"));
    }
    Ok(())
}

/// Groups and owner rules name only people a trusted key belongs to (D92).
fn check_signers(groups: &[SignerGroup], rules: &[OwnerRule], keys: &[TrustKey], whose: Whose) -> Result<()> {
    let is_person = |name: &str| keys.iter().filter_map(|k| k.person.as_deref()).any(|p| !p.trim().is_empty() && same_person(p, name));
    let (group_table, rule_table, key_table) = match whose {
        Whose::Repository => ("[[signer]]", "[[protect.owner]]", "[[trust.key]]"),
        Whose::Floor => ("signer", "protect_owner", "trust_key"),
    };
    let fix = |name: &str| format!("list their key under {key_table} with person = \"{}\", or correct the name", name.trim());
    for (i, g) in groups.iter().enumerate() {
        if g.name.trim().is_empty() {
            return Err(Error::new("POLICY_INVALID", format!("every {group_table} needs a name")));
        }
        if g.people.is_empty() {
            return Err(Error::new("POLICY_INVALID", format!("the signer group {:?} names no people", g.name)));
        }
        if groups[..i].iter().any(|o| same_person(&o.name, &g.name)) {
            return Err(Error::new("POLICY_INVALID", format!("the signer group {:?} is defined twice", g.name)));
        }
        if let Some(p) = g.people.iter().find(|p| !is_person(p)) {
            return Err(Error::new("UNKNOWN_SIGNER", format!("the signer group {:?} names {p:?}, who is not the person on any {key_table}", g.name)).with_next(fix(p)));
        }
    }
    check_people(groups, keys, group_table)?;
    for r in rules {
        if r.paths.is_empty() || r.signers.is_empty() {
            return Err(Error::new("POLICY_INVALID", format!("every {rule_table} needs `paths` and `signers`: the files it owns, and the groups or people who may approve a change to them")));
        }
        let what = r.paths.join(", ");
        if r.min == 0 {
            return Err(Error::new("POLICY_INVALID", format!("the owner rule for {what} has min = 0; it must be at least 1")));
        }
        if let Some(s) = r.signers.iter().find(|s| !groups.iter().any(|g| same_person(&g.name, s)) && !is_person(s)) {
            let message = match whose {
                Whose::Repository => format!("the owner rule for {what} names {s:?}, which is neither a [[signer]] group nor the person on any [[trust.key]]"),
                Whose::Floor => format!("the organisation's owner rule for {what} names {s:?}, which is neither a group the organisation's rules define nor the person on one of its trusted keys"),
            };
            return Err(Error::new("UNKNOWN_SIGNER", message).with_next(format!("add a {group_table} named {:?}, or {}", s.trim(), fix(s))));
        }
        let people = people_in(groups, &r.signers);
        if (people.len() as u32) < r.min {
            return Err(Error::new("POLICY_INVALID", format!("the owner rule for {what} needs {} owners, but {} names only {}", r.min, r.signers.join(", "), people.len())));
        }
    }
    Ok(())
}

/// A person tries the change in their own development environment and signs off before it is
/// pushed to one of `branches` (D87). The pre-push gate and the CI gate both hold it until they do.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TestingPolicy {
    pub local: LocalTesting,
    /// Branch patterns a push to which needs the sign-off; empty means the landing branch.
    pub branches: Vec<String>,
}

impl TestingPolicy {
    pub fn is_off(&self) -> bool {
        self.local == LocalTesting::Off && self.branches.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalTesting {
    #[default]
    Off,
    /// A sign-off is asked for; a skip with a reason also counts.
    Skippable,
    /// Only a sign-off counts.
    Required,
}

/// A rule that some files change together: docs with the code they describe, say. 05 checks only
/// that an `also` file changed, never whether the change to it is any good.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Require {
    /// When the change touches any of these...
    pub when: Vec<String>,
    /// ...it must also touch at least one of these.
    pub also: Vec<String>,
    /// What a change that does not is held to.
    #[serde(default = "approval")]
    pub severity: Severity,
    /// Said to the agent and in the brief.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

fn approval() -> Severity {
    Severity::Approval
}

impl Require {
    /// The changed files that call for an update this change does not make; empty when the rule
    /// is met or nothing it watches changed. A file matching both lists counts as the update.
    pub fn unmet(&self, changed: &[String]) -> Vec<String> {
        let any = |patterns: &[String], path: &str| patterns.iter().any(|p| crate::glob::matches(p, path));
        if changed.iter().any(|p| any(&self.also, p)) {
            return Vec::new();
        }
        changed.iter().filter(|p| any(&self.when, p)).cloned().collect()
    }

    /// `src/** needs docs/** (approval)`.
    pub fn describe(&self) -> String {
        format!("{} needs {} ({})", self.when.join(", "), self.also.join(" or "), format!("{:?}", self.severity).to_lowercase())
    }
}

/// One environment: a name, the branch it lives on, its level on the ladder, and the rules for
/// promoting into it (D93). Every promotion setting is optional and not written out while unset,
/// so a policy that does not use them keeps its digest.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub name: String,
    pub branch: String,
    /// `dev`, `uat`, `pre-prod` or `prod`. Unset when the name is one of those; needed for any
    /// other name. Several environments may share a level (two dev environments, say).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// The environment it is promoted from. Unset: the first environment on the rung below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// How a promotion moves the branch. Unset: a fast-forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<PromoteHow>,
    /// Whether an agent may promote here. Unset: yes on every rung but the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<bool>,
    /// How long the source environment must have run the commit, confirmed, before it moves on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soak_minutes: Option<u32>,
    /// What to do about a deploy that is not confirmed. Unset: report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<OnFailure>,
    /// The command `on_failure = "command"` runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback: Vec<String>,
    /// Variables the rollback command may be given by name, as a check's `env`. Values are never stored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback_env: Vec<String>,
    /// How long the rollback command may run.
    #[serde(default = "rollback_timeout_default", skip_serializing_if = "is_rollback_timeout_default")]
    pub rollback_timeout_secs: u64,
    /// Commands that ask the environment which commit it runs, after a promotion into it
    /// (`[[environment.probe]]`). None: 05 cannot tell, and never says a deploy is confirmed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe: Vec<Probe>,
    /// Checks run once on the deployed commit after every probe showed it
    /// (`[[environment.smoke]]`, shaped like `[[check]]`; `paths` and `required` are not used).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub smoke: Vec<CheckDef>,
    /// How strongly each promotion rule holds a promotion back.
    #[serde(default, skip_serializing_if = "PromoteRules::is_default")]
    pub rules: PromoteRules,
    /// What a sign-off must say and who may give it.
    #[serde(default, skip_serializing_if = "none_or_default")]
    pub sign_off: Option<SignOffPolicy>,
    /// Statements only a person can give; a sign-off must confirm each, word for word.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirm: Vec<Confirm>,
    /// Whether a person may bypass a promotion rule, and which rules never.
    #[serde(default, skip_serializing_if = "none_or_default")]
    pub bypass: Option<PromoteBypass>,
    /// How a hotfix lands straight on this environment's branch (`[environment.hotfix]`).
    #[serde(default, skip_serializing_if = "none_or_default")]
    pub hotfix: Option<HotfixPolicy>,
}

/// How a hotfix task lands on an environment's branch (D93): the promotion rules' severities for
/// it, where they differ from the environment's own. A person's approval of the hotfix's outcome
/// is always needed: it is built in, and `approval = false` is refused.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HotfixPolicy {
    /// Only `true` (or unset): a hotfix always needs a person's approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<bool>,
    #[serde(skip_serializing_if = "HotfixRules::is_unset")]
    pub rules: HotfixRules,
}

/// Each promotion rule's severity for a hotfix, when set. Unset: `allow` for the rules about the
/// source environment (`source_checks`, `source_confirmed`, `soak`), which a hotfix does not come
/// from; the environment's own severity for the others.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HotfixRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_checks: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confirmed: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soak: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrations: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untasked: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_off: Option<Severity>,
}

impl HotfixRules {
    fn is_unset(&self) -> bool {
        *self == HotfixRules::default()
    }

    /// A rule's severity for a hotfix by its name, when the policy sets one.
    pub fn get(&self, rule: &str) -> Option<Severity> {
        match rule {
            "source_checks" => self.source_checks,
            "source_confirmed" => self.source_confirmed,
            "soak" => self.soak,
            "migrations" => self.migrations,
            "untasked" => self.untasked,
            "sign_off" => self.sign_off,
            _ => None,
        }
    }
}

/// The rules about the environment a promotion comes from, which a hotfix and a back-merge do
/// not judge by default.
pub const SOURCE_RULES: [&str; 3] = ["source_checks", "source_confirmed", "soak"];

/// How long a rollback command may run unless the policy says: as long as a check.
pub const ROLLBACK_TIMEOUT_SECS: u64 = 900;

fn rollback_timeout_default() -> u64 {
    ROLLBACK_TIMEOUT_SECS
}

fn is_rollback_timeout_default(secs: &u64) -> bool {
    *secs == ROLLBACK_TIMEOUT_SECS
}

/// Unset, or set to exactly its defaults: either way not written, so the digest holds.
fn none_or_default<T: Default + PartialEq>(value: &Option<T>) -> bool {
    value.as_ref().is_none_or(|v| *v == T::default())
}

/// How a promotion moves the target branch.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PromoteHow {
    /// The target branch moves to the source's head; refused when that is not a fast-forward.
    FastForward,
    /// A merge commit on the target with the source's head as its second parent.
    Merge,
}

impl PromoteHow {
    pub fn word(self) -> &'static str {
        match self {
            PromoteHow::FastForward => "fast-forward",
            PromoteHow::Merge => "merge",
        }
    }
}

/// What 05 does about a deploy that is not confirmed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Say so: the record, the brief, and the one command to roll back.
    Report,
    /// Push a new commit that restores the rollback point. Never a force-push.
    Revert,
    /// Run the environment's `rollback` command.
    Command,
}

/// The promotion rules (D93), each `allow`, `warn`, `approval` or `deny`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct PromoteRules {
    /// The required checks that apply to what moves passed, by counted receipts, on the exact source head.
    pub source_checks: Severity,
    /// The source environment's deployment record confirms it runs the source head.
    pub source_confirmed: Severity,
    /// The source environment has run it, confirmed, for at least `soak_minutes`.
    pub soak: Severity,
    /// What moves touches the `migration` risk category.
    pub migrations: Severity,
    /// Commits that move belong to no 05 task.
    pub untasked: Severity,
    /// A person's sign-off is needed.
    pub sign_off: Severity,
}

/// The rule names, as the policy and the records write them.
pub const PROMOTE_RULES: [&str; 6] = ["source_checks", "source_confirmed", "soak", "migrations", "untasked", "sign_off"];

impl Default for PromoteRules {
    fn default() -> Self {
        PromoteRules { source_checks: Severity::Deny, source_confirmed: Severity::Warn, soak: Severity::Warn, migrations: Severity::Approval, untasked: Severity::Warn, sign_off: Severity::Allow }
    }
}

impl PromoteRules {
    fn is_default(&self) -> bool {
        *self == PromoteRules::default()
    }

    /// A rule's severity by its name.
    pub fn get(&self, rule: &str) -> Option<Severity> {
        Some(match rule {
            "source_checks" => self.source_checks,
            "source_confirmed" => self.source_confirmed,
            "soak" => self.soak,
            "migrations" => self.migrations,
            "untasked" => self.untasked,
            "sign_off" => self.sign_off,
            _ => return None,
        })
    }
}

/// What a sign-off must say, and who may give one (D92 signers: groups or people).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SignOffPolicy {
    /// The fewest characters its text may have.
    pub min_length: u32,
    /// Groups or people who may sign. Empty: any person with an approver key.
    pub signers: Vec<String>,
    /// Asked at the terminal; the answers are kept in the sign-off.
    pub questions: Vec<String>,
}

/// A statement only a person can give, such as "The release notes are published".
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    pub text: String,
}

/// Whether a person may bypass a promotion rule for one exact promotion.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct PromoteBypass {
    pub allowed: bool,
    /// Rules no bypass clears.
    pub never: Vec<String>,
    /// The fewest characters a bypass's reason may have.
    pub reason_min: u32,
}

impl Default for PromoteBypass {
    fn default() -> Self {
        PromoteBypass { allowed: true, never: Vec::new(), reason_min: 10 }
    }
}

/// Environments grouped into the rungs of the ladder, lowest first; one rung's environments in
/// the order the policy lists them. An environment with no level stands on its own rung just
/// above the one listed before it.
pub fn ladder(envs: &[Environment]) -> Vec<Vec<&Environment>> {
    let keys = ladder_keys(envs);
    let mut order: Vec<usize> = (0..envs.len()).collect();
    order.sort_by_key(|&i| keys[i]);
    let mut rungs: Vec<(usize, Vec<&Environment>)> = Vec::new();
    for i in order {
        match rungs.last_mut() {
            Some((k, list)) if *k == keys[i] => list.push(&envs[i]),
            _ => rungs.push((keys[i], vec![&envs[i]])),
        }
    }
    rungs.into_iter().map(|(_, l)| l).collect()
}

/// Each environment's place for sorting: 2, 4, 6, 8 for dev to prod; one more than the
/// environment before it for one with no level.
pub fn ladder_keys(envs: &[Environment]) -> Vec<usize> {
    let mut prev = 0;
    envs.iter()
        .map(|e| {
            let key = match e.level().and_then(|l| LEVELS.iter().position(|x| *x == l)) {
                Some(r) => 2 * (r + 1),
                None => prev + 1,
            };
            prev = key;
            key
        })
        .collect()
}

/// The levels of the environment ladder, lowest first.
pub const LEVELS: [&str; 4] = ["dev", "uat", "pre-prod", "prod"];

impl Environment {
    /// The level: as written, or the name when the name is a level.
    pub fn level(&self) -> Option<&str> {
        self.level.as_deref().or_else(|| LEVELS.iter().copied().find(|l| *l == self.name))
    }

    /// Where on the ladder: 0 for dev up to 3 for prod; 4 when the level is unknown.
    pub fn rank(&self) -> usize {
        self.level().and_then(|l| LEVELS.iter().position(|x| *x == l)).unwrap_or(LEVELS.len())
    }

    /// How a promotion moves this environment's branch: as written, else a fast-forward.
    pub fn how(&self) -> PromoteHow {
        self.how.unwrap_or(PromoteHow::FastForward)
    }

    /// Each probe and smoke check has a name no other of its kind has and a command, and runs in a
    /// folder inside the tree; a probe waits at least a second between tries.
    fn validate_deploy_checks(&self) -> Result<()> {
        let invalid = |what: String| Err(Error::new("POLICY_INVALID", what));
        let mut seen: Vec<&str> = Vec::new();
        for p in &self.probe {
            if p.name.trim().is_empty() || p.run.is_empty() || p.run[0].trim().is_empty() {
                return invalid(format!("every [[environment.probe]] of {:?} needs a name and a run command", self.name));
            }
            if seen.contains(&p.name.as_str()) {
                return invalid(format!("the probe {:?} of {:?} is defined twice", p.name, self.name));
            }
            seen.push(&p.name);
            if p.interval_secs == 0 || p.timeout_secs == 0 {
                return invalid(format!("the probe {:?} of {:?} needs interval_secs and timeout_secs of at least 1", p.name, self.name));
            }
            if p.dir.as_deref().is_some_and(|d| !is_inside_tree(d)) {
                return Err(Error::new("CHECK_DIR_OUTSIDE", format!("the probe {:?} of {:?} runs in {:?}, which is not a folder inside the repository", p.name, self.name, p.dir.as_deref().unwrap_or_default())));
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for c in &self.smoke {
            if c.name.trim().is_empty() || c.run.is_empty() || c.run[0].trim().is_empty() {
                return invalid(format!("every [[environment.smoke]] of {:?} needs a name and a run command", self.name));
            }
            if seen.contains(&c.name.as_str()) {
                return invalid(format!("the smoke check {:?} of {:?} is defined twice", c.name, self.name));
            }
            seen.push(&c.name);
            if c.dir.as_deref().is_some_and(|d| !is_inside_tree(d)) {
                return Err(Error::new("CHECK_DIR_OUTSIDE", format!("the smoke check {:?} of {:?} runs in {:?}, which is not a folder inside the repository", c.name, self.name, c.dir.as_deref().unwrap_or_default())));
            }
        }
        Ok(())
    }

    /// What to do about a deploy here that is not confirmed: as written, else report it.
    pub fn on_failure(&self) -> OnFailure {
        self.on_failure.unwrap_or(OnFailure::Report)
    }

    /// Who may bypass what here: as written, else a person may bypass any rule.
    pub fn bypass(&self) -> PromoteBypass {
        self.bypass.clone().unwrap_or_default()
    }

    /// How strongly a promotion rule holds a hotfix landing here back: `[environment.hotfix.rules]`
    /// when it sets the rule; else `allow` for the source rules and this environment's own
    /// severity for the others.
    pub fn hotfix_rule(&self, rule: &str) -> Option<Severity> {
        self.hotfix.as_ref().and_then(|h| h.rules.get(rule)).or_else(|| if SOURCE_RULES.contains(&rule) { Some(Severity::Allow) } else { self.rules.get(rule) })
    }

    /// An environment with only a name, a branch and maybe a level: what every promotion setting
    /// is unset in.
    pub fn new(name: &str, branch: &str, level: Option<&str>) -> Environment {
        Environment {
            name: name.to_string(),
            branch: branch.to_string(),
            level: level.map(str::to_string),
            from: None,
            how: None,
            agent: None,
            soak_minutes: None,
            on_failure: None,
            rollback: Vec::new(),
            rollback_env: Vec::new(),
            rollback_timeout_secs: ROLLBACK_TIMEOUT_SECS,
            probe: Vec::new(),
            smoke: Vec::new(),
            rules: PromoteRules::default(),
            sign_off: None,
            confirm: Vec::new(),
            bypass: None,
            hotfix: None,
        }
    }
}

/// What a promotion moves into (D93): an environment on the ladder, or a destination in another
/// repository. Both are judged by one set of rules, sign-offs and bypasses, through this.
pub trait Target {
    /// Its name, as the policy, the records and the commands give it.
    fn name(&self) -> &str;
    fn rules(&self) -> &PromoteRules;
    fn sign_off(&self) -> Option<&SignOffPolicy>;
    /// Statements only a person can give.
    fn confirm(&self) -> &[Confirm];
    /// Who may bypass what: as written, else a person may bypass any rule.
    fn bypass(&self) -> PromoteBypass;
    /// Whether an agent may promote here, as written. Unset: see [`Policy::agent_may_promote`].
    fn agent(&self) -> Option<bool>;
    /// How long the source must have run it, confirmed. A destination has no soak.
    fn soak_minutes(&self) -> Option<u32>;
    /// How a promotion moves it: `fast-forward`, `merge`, `push` or `export`.
    fn how_word(&self) -> &'static str;
    /// How strongly a rule holds a hotfix landing here back. A destination has no hotfix, so its
    /// own rules.
    fn hotfix_rule(&self, rule: &str) -> Option<Severity>;
    /// A destination in another repository, not an environment.
    fn is_destination(&self) -> bool;
}

impl Target for Environment {
    fn name(&self) -> &str {
        &self.name
    }
    fn rules(&self) -> &PromoteRules {
        &self.rules
    }
    fn sign_off(&self) -> Option<&SignOffPolicy> {
        self.sign_off.as_ref()
    }
    fn confirm(&self) -> &[Confirm] {
        &self.confirm
    }
    fn bypass(&self) -> PromoteBypass {
        Environment::bypass(self)
    }
    fn agent(&self) -> Option<bool> {
        self.agent
    }
    fn soak_minutes(&self) -> Option<u32> {
        self.soak_minutes
    }
    fn how_word(&self) -> &'static str {
        self.how().word()
    }
    fn hotfix_rule(&self, rule: &str) -> Option<Severity> {
        Environment::hotfix_rule(self, rule)
    }
    fn is_destination(&self) -> bool {
        false
    }
}

/// A place outside this repository that is promoted to with `use05 promote <name>` (D93), under
/// the same rules, sign-offs and bypasses as an environment (`[[destination]]`). It has no probes,
/// soak, hotfix or merging back, and the policy refuses those keys on one.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub name: String,
    /// `push`: a branch goes to another remote. `export`: a folder is copied into another
    /// repository, one commit per sync.
    pub how: DestinationHow,
    /// For `push`, the branch whose head goes out (unset: the landing branch). For `export`, the
    /// folder inside the tree that is copied: relative, with no `..`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A remote's name here, or a URL.
    pub remote: String,
    /// The branch it goes to there.
    pub branch: String,
    /// Whether an agent may promote here. Unset: no.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<bool>,
    #[serde(default, skip_serializing_if = "PromoteRules::is_default")]
    pub rules: PromoteRules,
    #[serde(default, skip_serializing_if = "none_or_default")]
    pub sign_off: Option<SignOffPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirm: Vec<Confirm>,
    #[serde(default, skip_serializing_if = "none_or_default")]
    pub bypass: Option<PromoteBypass>,
}

/// How a destination is promoted to.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DestinationHow {
    /// The source branch's head is pushed to the remote's branch, by fast-forward only.
    Push,
    /// The folder's exact committed content becomes the remote branch's whole tree, as one new
    /// commit on top of it.
    Export,
}

impl DestinationHow {
    pub fn word(self) -> &'static str {
        match self {
            DestinationHow::Push => "push",
            DestinationHow::Export => "export",
        }
    }
}

/// What an environment has and a destination never does: the policy refuses these keys on one.
const ENVIRONMENT_ONLY: [&str; 9] = ["level", "soak_minutes", "on_failure", "rollback", "rollback_env", "rollback_timeout_secs", "probe", "smoke", "hotfix"];

impl Destination {
    /// The branch whose head a `push` sends: `from`, else the landing branch. `None` for an export.
    pub fn push_from<'a>(&'a self, landing: &'a str) -> Option<&'a str> {
        (self.how == DestinationHow::Push).then(|| self.from.as_deref().unwrap_or(landing))
    }

    /// The folder an `export` copies, as a path inside the tree with no leading `./` and no
    /// trailing `/`; empty for the whole tree (`"."`). `None` for a push.
    pub fn folder(&self) -> Option<String> {
        (self.how == DestinationHow::Export).then(|| {
            let f = self.from.as_deref().unwrap_or_default().trim();
            let f = f.strip_prefix("./").unwrap_or(f).trim_end_matches('/');
            if f == "." { String::new() } else { f.to_string() }
        })
    }
}

impl Target for Destination {
    fn name(&self) -> &str {
        &self.name
    }
    fn rules(&self) -> &PromoteRules {
        &self.rules
    }
    fn sign_off(&self) -> Option<&SignOffPolicy> {
        self.sign_off.as_ref()
    }
    fn confirm(&self) -> &[Confirm] {
        &self.confirm
    }
    fn bypass(&self) -> PromoteBypass {
        self.bypass.clone().unwrap_or_default()
    }
    fn agent(&self) -> Option<bool> {
        self.agent
    }
    fn soak_minutes(&self) -> Option<u32> {
        None
    }
    fn how_word(&self) -> &'static str {
        self.how.word()
    }
    fn hotfix_rule(&self, rule: &str) -> Option<Severity> {
        self.rules.get(rule)
    }
    fn is_destination(&self) -> bool {
        true
    }
}

/// A branch name as git takes it, and never as one of its options: not empty, no spaces or
/// control characters, no leading `-`, and none of what git refuses in a ref.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && !name.contains("..") && !name.chars().any(|c| c.is_whitespace() || c.is_control() || "~^:?*[\\".contains(c))
}

/// Where an agent may push (`[push]`, D93).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct PushPolicy {
    /// The remotes an agent may push to, each by its name here or its URL. Unset: any remote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Vec<String>>,
}

impl PushPolicy {
    fn is_unset(&self) -> bool {
        self.agent.is_none()
    }

    /// Whether an agent may push to the remote git calls `name`, at `url` (a push to a URL has
    /// the URL as its name). A listed entry matches by name, by URL, or as a remote here whose
    /// configured URL is `url`; `urls_of` gives a remote's configured URLs. Unset: any.
    pub fn agent_may_push(&self, name: &str, url: &str, urls_of: impl Fn(&str) -> Vec<String>) -> bool {
        let Some(list) = &self.agent else { return true };
        list.iter().any(|e| remote_matches(e, name, url, &urls_of))
    }
}

/// Whether a remote the policy names (`entry`: a remote's name here, or a URL) is the one git
/// pushes to, which it calls `name`, at `url`: by name, by URL, or as a remote here whose
/// configured URL is `url`. A URL must equal one exactly.
pub fn remote_matches(entry: &str, name: &str, url: &str, urls_of: impl Fn(&str) -> Vec<String>) -> bool {
    let entry = entry.trim();
    entry == name || (!url.is_empty() && (entry == url || urls_of(entry).iter().any(|u| u == url)))
}

/// About the policy file itself (D78).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Use05Policy {
    /// The oldest use05 that understands this file. Read before anything else in it, so an older
    /// CLI asks to be upgraded instead of failing on a section it does not know.
    pub min_version: Option<String>,
}

impl Use05Policy {
    fn is_unset(&self) -> bool {
        self.min_version.is_none()
    }
}

fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    // A pre-release or build suffix (`0.1.0-ci`) counts as its version.
    let core = text.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

/// Whether version `a` is older than `b`. Unreadable versions compare as not older.
pub fn version_below(a: &str, b: &str) -> bool {
    matches!((parse_version(a), parse_version(b)), (Some(a), Some(b)) if a < b)
}

/// Refuse a policy written for a newer use05, before reading any section this version may not know.
fn check_min_version(text: &str) -> Result<()> {
    let Ok(table) = toml::from_str::<toml::Table>(text) else { return Ok(()) };
    let Some(min) = table.get("use05").and_then(|t| t.get("min_version")) else { return Ok(()) };
    let invalid = || Error::new("POLICY_INVALID", format!("use05.min_version must be a version such as \"{}\"", env!("CARGO_PKG_VERSION")));
    let min = min.as_str().ok_or_else(invalid)?;
    parse_version(min).ok_or_else(invalid)?;
    let this = env!("CARGO_PKG_VERSION");
    if version_below(this, min) {
        // An agent that reads an install command runs it, on the person's machine (seen with
        // Codex): under an agent, the next step is the person's.
        let next = if crate::inbox::agent_session().is_some() {
            "stop and ask the user to upgrade 05 (npm i -g @use05/cli); do not install it yourself"
        } else {
            "upgrade: npm i -g @use05/cli, or curl -fsSL https://use05.dev/install.sh | sh"
        };
        return Err(Error::new("POLICY_NEEDS_NEWER", format!("this repository's policy needs use05 {min} or newer; this is use05 {this}")).with_next(next));
    }
    Ok(())
}

/// A destination has no probes, soak, hotfix or rollback (D93): say so by name, before the
/// policy is read, rather than as an unknown field.
fn check_destination_keys(text: &str) -> Result<()> {
    let Ok(table) = toml::from_str::<toml::Table>(text) else { return Ok(()) };
    let Some(list) = table.get("destination").and_then(|d| d.as_array()) else { return Ok(()) };
    for d in list.iter().filter_map(|d| d.as_table()) {
        let name = d.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        if let Some(key) = ENVIRONMENT_ONLY.iter().find(|k| d.contains_key(**k)) {
            return Err(Error::new("POLICY_INVALID", format!("the destination {name:?} sets {key}, but a destination has no probes, smoke checks, soak, hotfix, rollback or level; those belong to an [[environment]]"))
                .with_next(format!("remove {key} from the [[destination]] {name:?}")));
        }
    }
    Ok(())
}

/// Which branches are real, which are agents' working space, and where work lands (D69).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct BranchPolicy {
    pub keep: Vec<String>,
    pub work: Vec<String>,
    /// Where work lands unless a declaration names another; default: the remote's default branch.
    pub target: Option<String>,
    pub land: LandMode,
    /// After a change lands: `manual`, you push; `auto`, 05 pushes the landing branch to origin,
    /// through the pre-push hook like any push (D91). Not written out while manual, so existing
    /// digests hold.
    #[serde(skip_serializing_if = "is_manual")]
    pub push: LandMode,
    /// An agent that starts behind origin's copy of the target: at session start the hook fetches
    /// and tells it; the brief says how far behind it started. Off (`allow`) unless set, and then
    /// not written out, so existing digests hold.
    #[serde(skip_serializing_if = "is_allow")]
    pub fresh_base: Severity,
}

fn is_manual(m: &LandMode) -> bool {
    *m == LandMode::Manual
}

fn is_allow(s: &Severity) -> bool {
    *s == Severity::Allow
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LandMode {
    /// `use05 land` does it.
    Manual,
    /// The Stop hook lands a change the gate allows when the agent finishes.
    Auto,
}

impl Default for BranchPolicy {
    fn default() -> Self {
        let v = |items: &[&str]| items.iter().map(|s| s.to_string()).collect();
        BranchPolicy { keep: v(&["main", "master", "develop", "release/*"]), work: v(&["05/*", "agent/*", "claude/*", "codex/*"]), target: None, land: LandMode::Manual, push: LandMode::Manual, fresh_base: Severity::Allow }
    }
}

/// Risk categories on top of the built-in ones (D66).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct RiskPolicy {
    pub rules: Vec<crate::risk::Rule>,
    /// Paths a category pattern catches by mistake.
    pub exempt: Vec<String>,
    /// An organisation can forbid exemptions.
    pub exempt_allowed: bool,
    /// Rules the organisation added. A repository's exemptions never apply to them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locked: Vec<crate::risk::Rule>,
}

impl Default for RiskPolicy {
    fn default() -> Self {
        RiskPolicy { rules: Vec::new(), exempt: Vec::new(), exempt_allowed: true, locked: Vec::new() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IntentPolicy {
    pub mode: IntentMode,
}

/// Path rules (D79). Unset rules are not written out, so a policy that uses none of them keeps
/// its digest, and approvals bound to it still count.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Protect {
    /// A change here needs a person's approval.
    pub paths: Vec<String>,
    /// Never changed: no approval clears it; a person's bypass can, unless `bypass` is off.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locked: Vec<String>,
    /// Locks no bypass can clear.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub absolute: Vec<String>,
    /// New files only: existing ones are never edited, renamed or deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub append_only: Vec<String>,
    /// May be edited, never deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_delete: Vec<String>,
    /// Agents may not open these. Only an agent's own hooks can see a read, so this is advisory.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_read: Vec<String>,
    /// Whether a person's bypass can let a change through the rules above.
    #[serde(skip_serializing_if = "is_true")]
    pub bypass: bool,
    /// Who must approve a change to some paths (D92).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owner: Vec<OwnerRule>,
    /// The organisation floor's owner rules, resolved against the floor's own groups. Only a floor
    /// puts them here: a repository's file cannot.
    #[serde(skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    pub floor_owner: Vec<ResolvedOwner>,
}

fn is_true(b: &bool) -> bool {
    *b
}

impl Default for Protect {
    fn default() -> Self {
        Protect { paths: Vec::new(), locked: Vec::new(), absolute: Vec::new(), append_only: Vec::new(), no_delete: Vec::new(), no_read: Vec::new(), bypass: true, owner: Vec::new(), floor_owner: Vec::new() }
    }
}

impl Protect {
    fn any(patterns: &[String], path: &str) -> bool {
        patterns.iter().any(|p| crate::glob::matches(p, path))
    }
    pub fn is_locked(&self, path: &str) -> bool {
        Protect::any(&self.locked, path) || Protect::any(&self.absolute, path)
    }
    /// A lock no bypass can clear: listed as absolute, or any lock when bypass is off.
    pub fn is_absolute(&self, path: &str) -> bool {
        Protect::any(&self.absolute, path) || (!self.bypass && self.is_locked(path))
    }
    pub fn is_append_only(&self, path: &str) -> bool {
        Protect::any(&self.append_only, path)
    }
    pub fn is_no_delete(&self, path: &str) -> bool {
        Protect::any(&self.no_delete, path)
    }
    pub fn is_no_read(&self, path: &str) -> bool {
        Protect::any(&self.no_read, path)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct DriftPolicy {
    /// Files changed outside the card's declared scope.
    pub scope: Severity,
    /// Dependency manifests or lockfiles changed.
    pub dependencies: Severity,
    /// Another agent session on this repository edited the same file recently.
    pub overlap: Severity,
    /// Agent claims the evidence does not support.
    pub claims: Severity,
    /// The change weakens tests or checks (D66).
    pub tests: Severity,
    /// A declared scope stops reserving its area after this long with no activity (D64).
    pub reservation_idle_hours: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct EvidencePolicy {
    /// Which signer roles count as evidence.
    pub accept: Vec<Role>,
    /// How long the Stop hook may spend proving when an agent finishes; 0 turns it off (D65).
    pub stop_budget_secs: u64,
    /// The pre-push hook proves required checks that are missing for what is pushed (D65).
    pub prove_at_push: bool,
    /// Check the real files of Git LFS pointers, not the pointers (D96). Needs `git lfs`. Left out
    /// of the serialised policy when off, so a policy that does not use it keeps its digest.
    #[serde(skip_serializing_if = "is_false")]
    pub lfs: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalPolicy {
    pub min: u32,
    pub expire_days: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct RecordPolicy {
    pub middle: Middle,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct EnforcePolicy {
    /// What to do when 05 itself fails during an enforced check.
    pub on_error: OnError,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct EnvPolicy {
    /// If set, the only variables any check may be passed.
    pub allow: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct TrustPolicy {
    pub key: Vec<TrustKey>,
}

impl Default for IntentPolicy {
    fn default() -> Self {
        IntentPolicy { mode: IntentMode::Inferred }
    }
}
impl Default for DriftPolicy {
    fn default() -> Self {
        DriftPolicy { scope: Severity::Warn, dependencies: Severity::Warn, overlap: Severity::Warn, claims: Severity::Warn, tests: Severity::Approval, reservation_idle_hours: 2 }
    }
}
impl Default for EvidencePolicy {
    fn default() -> Self {
        EvidencePolicy { accept: vec![Role::Local, Role::Runner], stop_budget_secs: 60, prove_at_push: true, lfs: false }
    }
}
impl Default for ApprovalPolicy {
    fn default() -> Self {
        ApprovalPolicy { min: 1, expire_days: 7 }
    }
}
impl Default for RecordPolicy {
    fn default() -> Self {
        RecordPolicy { middle: Middle::Local }
    }
}
impl Default for EnforcePolicy {
    fn default() -> Self {
        EnforcePolicy { on_error: OnError::Open }
    }
}
impl Default for Policy {
    fn default() -> Self {
        Policy {
            use05: Use05Policy::default(),
            intent: IntentPolicy::default(),
            check: Vec::new(),
            protect: Protect::default(),
            drift: DriftPolicy::default(),
            evidence: EvidencePolicy::default(),
            approvals: ApprovalPolicy::default(),
            record: RecordPolicy::default(),
            enforce: EnforcePolicy::default(),
            env: EnvPolicy::default(),
            trust: TrustPolicy::default(),
            risk: RiskPolicy::default(),
            branches: BranchPolicy::default(),
            environment: Vec::new(),
            require: Vec::new(),
            testing: TestingPolicy::default(),
            signer: Vec::new(),
            destination: Vec::new(),
            push: PushPolicy::default(),
        }
    }
}

// ----------------------------------------------------------------------------- the floor

/// An organisation's minimums. Every field is optional: only what is set is imposed.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Floor {
    pub intent_mode: Option<IntentMode>,
    pub check: Vec<CheckDef>,
    pub protect_paths: Vec<String>,
    pub drift_scope: Option<Severity>,
    pub drift_dependencies: Option<Severity>,
    pub drift_overlap: Option<Severity>,
    pub drift_claims: Option<Severity>,
    pub drift_tests: Option<Severity>,
    pub evidence_accept: Option<Vec<Role>>,
    pub approvals_min: Option<u32>,
    pub approvals_expire_days_max: Option<u32>,
    pub record_middle: Option<Middle>,
    pub enforce_on_error: Option<OnError>,
    pub env_allow: Option<Vec<String>>,
    pub trust_key: Vec<TrustKey>,
    /// Risk categories every repository gets, on top of the built-in ones.
    pub risk_rules: Vec<crate::risk::Rule>,
    /// `false` forbids repositories from exempting paths.
    pub risk_exempt_allowed: Option<bool>,
    /// Path rules every repository gets (D79). Unset ones are not written, so signed floors keep their bytes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_locked: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_absolute: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_append_only: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_no_delete: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_no_read: Vec<String>,
    /// `false` forbids bypassing path rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_bypass: Option<bool>,
    /// The least an agent starting behind origin is held to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branches_fresh_base: Option<Severity>,
    /// Files that must change together, in every repository.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub require: Vec<Require>,
    /// Signer groups every repository gets (D92). A group the repository also names keeps only
    /// the people both list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signer: Vec<SignerGroup>,
    /// Path owners every repository gets (D92).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protect_owner: Vec<OwnerRule>,
}

impl Floor {
    /// What must hold before a floor is signed or used: its owner rules name only its own groups
    /// and the people on its own trusted keys (D92), so no repository can decide who they mean.
    pub fn validate(&self) -> Result<()> {
        check_signers(&self.signer, &self.protect_owner, &self.trust_key, Whose::Floor)
    }
}

impl Policy {
    /// Apply an organisation floor. Tightens only; never loosens.
    pub fn tighten(&mut self, floor: &Floor) {
        if let Some(mode) = floor.intent_mode {
            self.intent.mode = self.intent.mode.max(mode);
        }
        for required in &floor.check {
            match self.check.iter_mut().find(|c| c.name == required.name) {
                Some(existing) => {
                    existing.run = required.run.clone();
                    existing.dir = required.dir.clone();
                    existing.required = existing.required || required.required;
                    // Narrowing when a check is required would loosen the floor: either side
                    // asking for it always keeps it always.
                    if existing.paths.is_empty() || required.paths.is_empty() {
                        existing.paths.clear();
                    } else {
                        let more: Vec<String> = required.paths.iter().filter(|p| !existing.paths.contains(p)).cloned().collect();
                        existing.paths.extend(more);
                    }
                }
                None => self.check.push(required.clone()),
            }
        }
        for path in &floor.protect_paths {
            if !self.protect.paths.contains(path) {
                self.protect.paths.push(path.clone());
            }
        }
        let max_sev = |own: Severity, floor: Option<Severity>| floor.map_or(own, |f| own.max(f));
        self.drift.scope = max_sev(self.drift.scope, floor.drift_scope);
        self.drift.dependencies = max_sev(self.drift.dependencies, floor.drift_dependencies);
        self.drift.overlap = max_sev(self.drift.overlap, floor.drift_overlap);
        self.drift.claims = max_sev(self.drift.claims, floor.drift_claims);
        self.drift.tests = max_sev(self.drift.tests, floor.drift_tests);
        if let Some(accept) = &floor.evidence_accept {
            self.evidence.accept.retain(|r| accept.contains(r));
        }
        if let Some(min) = floor.approvals_min {
            self.approvals.min = self.approvals.min.max(min);
        }
        if let Some(max_days) = floor.approvals_expire_days_max {
            self.approvals.expire_days = self.approvals.expire_days.min(max_days);
        }
        if floor.record_middle == Some(Middle::Local) {
            self.record.middle = Middle::Local;
        }
        if let Some(on_error) = floor.enforce_on_error {
            self.enforce.on_error = self.enforce.on_error.max(on_error);
        }
        if let Some(allow) = &floor.env_allow {
            self.env.allow = Some(match &self.env.allow {
                Some(own) => own.iter().filter(|n| allow.contains(n)).cloned().collect(),
                None => allow.clone(),
            });
        }
        for key in &floor.trust_key {
            if !self.trust.key.iter().any(|k| k.public == key.public) {
                self.trust.key.push(key.clone());
            }
        }
        for rule in &floor.risk_rules {
            if !self.risk.locked.contains(rule) {
                self.risk.locked.push(rule.clone());
            }
        }
        if floor.risk_exempt_allowed == Some(false) {
            self.risk.exempt_allowed = false;
        }
        let add = |mine: &mut Vec<String>, theirs: &[String]| {
            for p in theirs {
                if !mine.contains(p) {
                    mine.push(p.clone());
                }
            }
        };
        add(&mut self.protect.locked, &floor.protect_locked);
        add(&mut self.protect.absolute, &floor.protect_absolute);
        add(&mut self.protect.append_only, &floor.protect_append_only);
        add(&mut self.protect.no_delete, &floor.protect_no_delete);
        add(&mut self.protect.no_read, &floor.protect_no_read);
        if floor.protect_bypass == Some(false) {
            self.protect.bypass = false;
        }
        self.branches.fresh_base = max_sev(self.branches.fresh_base, floor.branches_fresh_base);
        for rule in &floor.require {
            if !self.require.contains(rule) {
                self.require.push(rule.clone());
            }
        }
        // A floor never widens a group: one both name keeps only the people both list.
        for group in &floor.signer {
            match self.signer.iter_mut().find(|g| same_person(&g.name, &group.name)) {
                Some(mine) => mine.people.retain(|p| group.people.iter().any(|q| same_person(p, q))),
                None => self.signer.push(group.clone()),
            }
        }
        // A floor's owner rules keep the people its own groups name: the repository's groups never
        // decide who owns what the organisation asked for.
        for rule in &floor.protect_owner {
            let resolved = ResolvedOwner { paths: rule.paths.clone(), signers: rule.signers.clone(), min: rule.min, people: people_in(&floor.signer, &rule.signers), keys: Some(floor.trust_key.clone()) };
            if !self.protect.floor_owner.contains(&resolved) {
                self.protect.floor_owner.push(resolved);
            }
        }
    }

    /// The people `signers` name: each group's people in its place, plain names kept, trimmed,
    /// and each person once (compared ignoring case and surrounding spaces).
    pub fn people_of(&self, signers: &[String]) -> Vec<String> {
        people_in(&self.signer, signers)
    }

    /// Every owner rule in force, with its people: the repository's, resolved against its groups,
    /// and the organisation floor's, resolved against the floor's.
    pub fn owner_rules(&self) -> Vec<ResolvedOwner> {
        let mine = self.protect.owner.iter().map(|r| ResolvedOwner { paths: r.paths.clone(), signers: r.signers.clone(), min: r.min, people: self.people_of(&r.signers), keys: None });
        mine.chain(self.protect.floor_owner.iter().cloned()).collect()
    }

    /// The checks that must still hold once an organisation floor applied (it adds trusted keys):
    /// no group takes a trusted person's name, and no key belongs to two people. A rule left with
    /// too few people is the gate's to report, not a reason to stop loading the rules.
    pub fn check_effective(&self) -> Result<()> {
        check_people(&self.signer, &self.trust.key, "[[signer]]")
    }

    /// Signer groups and owner rules name only people a trusted key belongs to (D92).
    fn validate_signers(&self) -> Result<()> {
        check_signers(&self.signer, &self.protect.owner, &self.trust.key, Whose::Repository)?;
        // A sign-off's signers are named as an owner rule's are: groups, or people with a trusted key.
        let keys = &self.trust.key;
        let is_person = |name: &str| keys.iter().filter_map(|k| k.person.as_deref()).any(|p| !p.trim().is_empty() && same_person(p, name));
        let targets = self.environment.iter().map(|e| e as &dyn Target).chain(self.destination.iter().map(|d| d as &dyn Target));
        for e in targets {
            let Some(sign) = e.sign_off() else { continue };
            if let Some(s) = sign.signers.iter().find(|s| !self.signer.iter().any(|g| same_person(&g.name, s)) && !is_person(s)) {
                return Err(Error::new("UNKNOWN_SIGNER", format!("the sign-off for {:?} names {s:?}, which is neither a [[signer]] group nor the person on any [[trust.key]]", e.name()))
                    .with_next(format!("add a [[signer]] named {:?}, or list their key under [[trust.key]] with person = \"{}\", or correct the name", s.trim(), s.trim())));
            }
        }
        Ok(())
    }

    pub fn parse(text: &str) -> Result<Policy> {
        check_min_version(text)?;
        check_destination_keys(text)?;
        let mut policy: Policy = toml::from_str(text).map_err(|e| {
            Error::new("POLICY_INVALID", format!("the policy is not valid: {}", e.to_string().trim_end()))
                .with_next("fix the file, or run: use05 policy")
        })?;
        // A table that says only the defaults says nothing: read as if it were not there.
        for e in &mut policy.environment {
            if none_or_default(&e.sign_off) {
                e.sign_off = None;
            }
            if none_or_default(&e.bypass) {
                e.bypass = None;
            }
            // A hotfix always needs an approval: saying so says nothing.
            if let Some(h) = e.hotfix.as_mut().filter(|h| h.approval == Some(true)) {
                h.approval = None;
            }
            if none_or_default(&e.hotfix) {
                e.hotfix = None;
            }
        }
        for d in &mut policy.destination {
            if none_or_default(&d.sign_off) {
                d.sign_off = None;
            }
            if none_or_default(&d.bypass) {
                d.bypass = None;
            }
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = Vec::new();
        for check in &self.check {
            if check.name.is_empty() || check.run.is_empty() {
                return Err(Error::new("POLICY_INVALID", "every [[check]] needs a name and a run command"));
            }
            if seen.contains(&&check.name) {
                return Err(Error::new("POLICY_INVALID", format!("the check {:?} is defined twice", check.name)));
            }
            seen.push(&check.name);
            if let Some(dir) = &check.dir {
                if !is_inside_tree(dir) {
                    return Err(Error::new("CHECK_DIR_OUTSIDE", format!("the check {:?} runs in {dir:?}, which is not a folder inside the repository", check.name))
                        .with_next("give dir as a path inside the repository, such as \"packages/api\", with no .. and no leading /"));
                }
            }
        }
        if self.protect.is_absolute(POLICY_PATH) {
            return Err(Error::new("POLICY_INVALID", format!("a lock no bypass can clear covers {POLICY_PATH}, so the policy could never be changed again"))
                .with_next("leave the policy file out of `absolute`, or turn `bypass` back on"));
        }
        for (i, e) in self.environment.iter().enumerate() {
            if e.name.trim().is_empty() || e.branch.trim().is_empty() {
                return Err(Error::new("POLICY_INVALID", "every [[environment]] needs a name and a branch"));
            }
            if let Some(level) = &e.level {
                if !LEVELS.contains(&level.as_str()) {
                    return Err(Error::new("POLICY_INVALID", format!("the environment {:?} has level {level:?}; a level is one of dev, uat, pre-prod, prod", e.name)));
                }
            }
            if self.environment[..i].iter().any(|o| o.name == e.name || o.branch == e.branch) {
                return Err(Error::new("POLICY_INVALID", format!("the environment {:?} or its branch {:?} is listed twice", e.name, e.branch)));
            }
        }
        self.validate_promotion()?;
        self.validate_destinations()?;
        for r in &self.require {
            if r.when.is_empty() || r.also.is_empty() {
                return Err(Error::new("POLICY_INVALID", "every [[require]] needs `when` and `also`: the files that call for an update, and the files that must change with them"));
            }
        }
        if self.approvals.min == 0 {
            return Err(Error::new("POLICY_INVALID", "approvals.min must be at least 1"));
        }
        self.validate_signers()
    }

    /// The promotion settings name only environments, rules and people that exist (D93), and
    /// following `from` always ends at the bottom of the ladder.
    fn validate_promotion(&self) -> Result<()> {
        let names = || self.environment.iter().map(|e| format!("{:?}", e.name)).collect::<Vec<_>>().join(", ");
        for e in &self.environment {
            if let Some(from) = &e.from {
                if self.environment_named(from).is_none() {
                    return Err(Error::new("UNKNOWN_ENVIRONMENT", format!("the environment {:?} is promoted from {from:?}, which is not an environment here; the environments are {}", e.name, names()))
                        .with_next("name one of them in `from`, or add that [[environment]]"));
                }
                if *from == e.name {
                    return Err(Error::new("POLICY_INVALID", format!("the environment {:?} is promoted from itself", e.name)));
                }
            }
            if e.on_failure() == OnFailure::Command && e.rollback.is_empty() {
                return Err(Error::new("ROLLBACK_MISSING", format!("the environment {:?} runs a command when a deploy is not confirmed (on_failure = \"command\"), but names no `rollback` command", e.name))
                    .with_next("add rollback = [\"./rollback.sh\"], or set on_failure to \"report\" or \"revert\""));
            }
            let bypass = e.bypass();
            if let Some(rule) = bypass.never.iter().find(|r| !PROMOTE_RULES.contains(&r.as_str())) {
                return Err(Error::new("POLICY_INVALID", format!("the environment {:?} never lets a bypass clear {rule:?}, which is not a promotion rule; the rules are {}", e.name, PROMOTE_RULES.join(", "))));
            }
            if e.confirm.iter().any(|c| c.text.trim().is_empty()) {
                return Err(Error::new("POLICY_INVALID", format!("every [[environment.confirm]] of {:?} needs a `text`: the statement a person confirms", e.name)));
            }
            if e.rollback.first().is_some_and(|c| c.trim().is_empty()) {
                return Err(Error::new("POLICY_INVALID", format!("the rollback command of {:?} starts with an empty word", e.name)));
            }
            if e.hotfix.as_ref().and_then(|h| h.approval) == Some(false) {
                return Err(Error::new("POLICY_INVALID", format!("[environment.hotfix] of {:?} says approval = false, but a hotfix always needs a person's approval of its outcome; that is built in", e.name))
                    .with_next("remove approval = false; set the rules a hotfix is held to in [environment.hotfix.rules]"));
            }
            if e.rollback_timeout_secs == 0 {
                return Err(Error::new("POLICY_INVALID", format!("the rollback command of {:?} needs rollback_timeout_secs of at least 1", e.name)));
            }
            e.validate_deploy_checks()?;
        }
        // Each environment's sources, followed down, end at the bottom: never back where they began.
        for e in &self.environment {
            let mut seen = vec![e.name.as_str()];
            let mut at = e;
            while let Some(below) = self.source_of(at) {
                if seen.contains(&below.name.as_str()) {
                    seen.push(&below.name);
                    return Err(Error::new("POLICY_INVALID", format!("the environments are promoted from each other in a cycle: {}", seen.join(" ← "))).with_next("let `from` go down the ladder, ending at the environment work lands on"));
                }
                seen.push(&below.name);
                at = below;
            }
        }
        Ok(())
    }

    /// The environment of this name.
    pub fn environment_named(&self, name: &str) -> Option<&Environment> {
        self.environment.iter().find(|e| e.name == name)
    }

    /// The destination of this name.
    pub fn destination_named(&self, name: &str) -> Option<&Destination> {
        self.destination.iter().find(|d| d.name == name)
    }

    /// Each destination names a remote and a branch git can take, has a name no environment or
    /// other destination has, exports a folder inside the tree, and names only rules that exist;
    /// `[push] agent` lists remotes by name or URL.
    fn validate_destinations(&self) -> Result<()> {
        let invalid = |what: String| Err(Error::new("POLICY_INVALID", what));
        for (i, d) in self.destination.iter().enumerate() {
            if d.name.trim().is_empty() || d.remote.trim().is_empty() || d.branch.trim().is_empty() {
                return invalid("every [[destination]] needs a name, a remote and a branch".into());
            }
            if self.environment.iter().any(|e| e.name == d.name) || self.destination[..i].iter().any(|o| o.name == d.name) {
                return Err(Error::new("DUPLICATE_TARGET", format!("{:?} names more than one environment or destination, and `use05 promote {}` must mean one", d.name, d.name)).with_next("give each [[environment]] and [[destination]] a name of its own"));
            }
            if d.remote.starts_with('-') || d.remote.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return invalid(format!("the destination {:?} names the remote {:?}; give a remote's name here or its URL", d.name, d.remote));
            }
            if !is_plain_name(&d.branch) {
                return invalid(format!("the destination {:?} goes to the branch {:?}, which is not a branch name git takes", d.name, d.branch));
            }
            match d.how {
                DestinationHow::Push => {
                    if let Some(from) = d.from.as_deref().filter(|f| !is_plain_name(f)) {
                        return invalid(format!("the destination {:?} pushes from {from:?}, which is not a branch name git takes", d.name));
                    }
                }
                DestinationHow::Export => match d.from.as_deref().map(str::trim) {
                    None => return invalid(format!("the destination {:?} exports a folder, so it needs `from`: the folder inside the repository, such as \"product/\"", d.name)),
                    Some(f) if !(f == "." || f == "./" || is_inside_tree(f)) => {
                        return invalid(format!("the destination {:?} exports {f:?}, which is not a folder inside the repository: give a relative path with no ..", d.name));
                    }
                    Some(_) => {}
                },
            }
            let bypass = Target::bypass(d);
            if let Some(rule) = bypass.never.iter().find(|r| !PROMOTE_RULES.contains(&r.as_str())) {
                return invalid(format!("the destination {:?} never lets a bypass clear {rule:?}, which is not a promotion rule; the rules are {}", d.name, PROMOTE_RULES.join(", ")));
            }
            if d.confirm.iter().any(|c| c.text.trim().is_empty()) {
                return invalid(format!("every [[destination.confirm]] of {:?} needs a `text`: the statement a person confirms", d.name));
            }
        }
        if self.push.agent.as_ref().is_some_and(|list| list.iter().any(|r| r.trim().is_empty())) {
            return invalid("[push] agent lists an empty remote; name each by its name here (\"origin\") or its URL".into());
        }
        Ok(())
    }

    /// Where `env` is promoted from: its `from`, else the first environment on the rung below.
    /// `None` for the bottom rung, which work lands on.
    pub fn source_of(&self, env: &Environment) -> Option<&Environment> {
        if let Some(from) = &env.from {
            return self.environment_named(from);
        }
        let rungs = ladder(&self.environment);
        let at = rungs.iter().position(|rung| rung.iter().any(|e| e.name == env.name))?;
        at.checked_sub(1).and_then(|below| rungs[below].first().copied())
    }

    /// Whether an agent may promote into `target`: as written, else on every rung but the last,
    /// and never to a destination.
    pub fn agent_may_promote(&self, target: &dyn Target) -> bool {
        target.agent().unwrap_or_else(|| !target.is_destination() && !ladder(&self.environment).last().is_some_and(|top| top.iter().any(|e| e.name == target.name())))
    }

    pub fn load_file(path: &Path) -> Result<Option<Policy>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Policy::parse(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&format!("reading {}", path.display()), e)),
        }
    }

    /// The policy as it was in a tree or commit: how a change's *base* rules are read.
    pub fn load_at(top: &Path, rev: &str) -> Result<Option<Policy>> {
        match git::blob_at(top, rev, POLICY_PATH) {
            Some(bytes) => Policy::parse(&String::from_utf8_lossy(&bytes)).map(Some),
            None => Ok(None),
        }
    }

    /// Digest of this exact effective policy. Approvals bind to it.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(serde_json::to_vec(self).expect("policy serialises")))
    }

    pub fn check_named(&self, name: &str) -> Option<&CheckDef> {
        self.check.iter().find(|c| c.name == name)
    }

    pub fn required_checks(&self) -> impl Iterator<Item = &CheckDef> {
        self.check.iter().filter(|c| c.required)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("policy serialises")
    }
}

// ----------------------------------------------------------------------------- explain

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    Repo,
    Org,
}

impl Source {
    pub fn word(&self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::Repo => "repo",
            Source::Org => "org",
        }
    }
}

pub struct Row {
    pub key: &'static str,
    pub value: String,
    pub source: Source,
}

/// Every setting that matters, with where its value came from.
fn envs(p: &Policy) -> String {
    if p.environment.is_empty() {
        return "none".to_string();
    }
    // Environments on one level side by side, the levels in ladder order.
    ladder(&p.environment).iter().map(|rung| rung.iter().map(|e| format!("{}: {}", e.name, e.branch)).collect::<Vec<_>>().join(", ")).collect::<Vec<_>>().join(" → ")
}

pub fn explain(repo: &Policy, effective: &Policy) -> Vec<Row> {
    let default = Policy::default();
    let row = |key: &'static str, d: String, r: String, e: String| Row {
        key,
        source: if e != r { Source::Org } else if r != d { Source::Repo } else { Source::Default },
        value: e,
    };
    let word = |s: Severity| format!("{s:?}").to_lowercase();
    let roles = |p: &Policy| p.evidence.accept.iter().map(|r| r.word()).collect::<Vec<_>>().join(", ");
    let names = |p: &Policy| p.check.iter().map(|c| format!("{}{}", c.name, if c.required { "" } else { "?" })).collect::<Vec<_>>().join(", ");
    let paths = |p: &Policy| p.protect.paths.join(", ");
    let list = |v: &Vec<String>| if v.is_empty() { "none".to_string() } else { v.join(", ") };
    let yes = |b: bool| if b { "a person may".to_string() } else { "never".to_string() };
    let keys = |p: &Policy| p.trust.key.iter().map(|k| format!("{} ({})", k.name, k.role.word())).collect::<Vec<_>>().join(", ");
    let env = |p: &Policy| p.env.allow.as_ref().map_or("unrestricted".to_string(), |a| a.join(", "));
    let target = |p: &Policy| p.branches.target.clone().unwrap_or_else(|| "the remote's default branch".to_string());
    let land = |p: &Policy| format!("{:?}", p.branches.land).to_lowercase();
    let push = |p: &Policy| format!("{:?}", p.branches.push).to_lowercase();
    let rules = |p: &Policy| if p.risk.rules.is_empty() { "built-in only".to_string() } else { format!("built-in, plus {}", p.risk.rules.iter().map(|r| format!("{} ({})", r.category, r.level.word())).collect::<Vec<_>>().join(", ")) };
    let exempt = |p: &Policy| match (p.risk.exempt.is_empty(), p.risk.exempt_allowed) {
        (_, false) => "not allowed".to_string(),
        (true, true) => "none".to_string(),
        (false, true) => p.risk.exempt.join(", "),
    };
    let min = |p: &Policy| p.use05.min_version.clone().unwrap_or_else(|| "not set".to_string());
    let require = |p: &Policy| if p.require.is_empty() { "none".to_string() } else { p.require.iter().map(Require::describe).collect::<Vec<_>>().join("; ") };
    let signers = |p: &Policy| if p.signer.is_empty() { "none".to_string() } else { p.signer.iter().map(|g| format!("{}: {}", g.name, g.people.join(", "))).collect::<Vec<_>>().join("; ") };
    let destinations = |p: &Policy| if p.destination.is_empty() { "none".to_string() } else { p.destination.iter().map(|d| format!("{} ({} {}to {} {})", d.name, d.how.word(), d.from.as_deref().map(|f| format!("{f} ")).unwrap_or_default(), d.remote, d.branch)).collect::<Vec<_>>().join("; ") };
    let agent_push = |p: &Policy| p.push.agent.as_ref().map_or("any remote".to_string(), |l| if l.is_empty() { "none".to_string() } else { l.join(", ") });
    let owners = |p: &Policy| { let all = p.owner_rules(); if all.is_empty() { "none".to_string() } else { all.iter().map(ResolvedOwner::describe).collect::<Vec<_>>().join("; ") } };
    vec![
        row("use05.min_version", min(&default), min(repo), min(effective)),
        row("intent.mode", format!("{:?}", default.intent.mode).to_lowercase(), format!("{:?}", repo.intent.mode).to_lowercase(), format!("{:?}", effective.intent.mode).to_lowercase()),
        row("drift.scope", word(default.drift.scope), word(repo.drift.scope), word(effective.drift.scope)),
        row("drift.dependencies", word(default.drift.dependencies), word(repo.drift.dependencies), word(effective.drift.dependencies)),
        row("drift.overlap", word(default.drift.overlap), word(repo.drift.overlap), word(effective.drift.overlap)),
        row("drift.claims", word(default.drift.claims), word(repo.drift.claims), word(effective.drift.claims)),
        row("drift.tests", word(default.drift.tests), word(repo.drift.tests), word(effective.drift.tests)),
        row("evidence.accept", roles(&default), roles(repo), roles(effective)),
        row("approvals.min", default.approvals.min.to_string(), repo.approvals.min.to_string(), effective.approvals.min.to_string()),
        row("approvals.expire_days", default.approvals.expire_days.to_string(), repo.approvals.expire_days.to_string(), effective.approvals.expire_days.to_string()),
        row("record.middle", format!("{:?}", default.record.middle).to_lowercase(), format!("{:?}", repo.record.middle).to_lowercase(), format!("{:?}", effective.record.middle).to_lowercase()),
        row("enforce.on_error", format!("{:?}", default.enforce.on_error).to_lowercase(), format!("{:?}", repo.enforce.on_error).to_lowercase(), format!("{:?}", effective.enforce.on_error).to_lowercase()),
        row("protect.paths", paths(&default), paths(repo), paths(effective)),
        row("protect.locked", list(&default.protect.locked), list(&repo.protect.locked), list(&effective.protect.locked)),
        row("protect.absolute", list(&default.protect.absolute), list(&repo.protect.absolute), list(&effective.protect.absolute)),
        row("protect.append_only", list(&default.protect.append_only), list(&repo.protect.append_only), list(&effective.protect.append_only)),
        row("protect.no_delete", list(&default.protect.no_delete), list(&repo.protect.no_delete), list(&effective.protect.no_delete)),
        row("protect.no_read", list(&default.protect.no_read), list(&repo.protect.no_read), list(&effective.protect.no_read)),
        row("protect.bypass", yes(default.protect.bypass), yes(repo.protect.bypass), yes(effective.protect.bypass)),
        row("protect.owner", owners(&default), owners(repo), owners(effective)),
        row("signer", signers(&default), signers(repo), signers(effective)),
        row("checks", names(&default), names(repo), names(effective)),
        row("env.allow", env(&default), env(repo), env(effective)),
        row("trusted keys", keys(&default), keys(repo), keys(effective)),
        row("risk.rules", rules(&default), rules(repo), rules(effective)),
        row("environments", envs(&default), envs(repo), envs(effective)),
        row("destinations", destinations(&default), destinations(repo), destinations(effective)),
        row("push.agent", agent_push(&default), agent_push(repo), agent_push(effective)),
        row("branches.keep", default.branches.keep.join(", "), repo.branches.keep.join(", "), effective.branches.keep.join(", ")),
        row("branches.work", default.branches.work.join(", "), repo.branches.work.join(", "), effective.branches.work.join(", ")),
        row("branches.target", target(&default), target(repo), target(effective)),
        row("branches.land", land(&default), land(repo), land(effective)),
        row("branches.push", push(&default), push(repo), push(effective)),
        row("branches.fresh_base", word(default.branches.fresh_base), word(repo.branches.fresh_base), word(effective.branches.fresh_base)),
        row("require", require(&default), require(repo), require(effective)),
        row("risk.exempt", exempt(&default), exempt(repo), exempt(effective)),
    ]
}

// ----------------------------------------------------------------------------- detection

/// Checks worth proposing, from what is in the repository. Nothing runs until accepted.
pub fn detect_checks(top: &Path) -> Vec<CheckDef> {
    let check = |name: &str, run: &[&str], env: &[&str]| CheckDef {
        name: name.to_string(),
        run: run.iter().map(|s| s.to_string()).collect(),
        env: env.iter().map(|s| s.to_string()).collect(),
        ..CheckDef::default()
    };
    let mut found = Vec::new();
    if top.join("Cargo.toml").exists() {
        // rustup needs HOME to find its toolchains: the check is given the real one.
        found.push(check("test", &["cargo", "test"], &["HOME"]));
        found.push(check("lint", &["cargo", "clippy", "--", "-D", "warnings"], &["HOME"]));
    }
    if let Ok(text) = std::fs::read_to_string(top.join("package.json")) {
        let scripts = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("scripts").cloned())
            .unwrap_or_default();
        for name in ["test", "typecheck", "lint", "build"] {
            if scripts.get(name).is_some() {
                found.push(check(name, &["npm", "run", name, "--silent"], &[]));
            }
        }
    }
    if top.join("pyproject.toml").exists() || top.join("requirements.txt").exists() || top.join("pytest.ini").exists() {
        found.push(check("test", &["python3", "-m", "pytest", "-q"], &[]));
    }
    if top.join("go.mod").exists() {
        found.push(check("test", &["go", "test", "./..."], &["HOME"]));
    }
    // Several ecosystems can propose the same name; keep the first.
    let mut seen = Vec::new();
    found.retain(|c| {
        let new = !seen.contains(&c.name);
        seen.push(c.name.clone());
        new
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testing_before_a_push_is_off_unless_said_and_then_read() {
        let off = Policy::default();
        assert_eq!(off.testing.local, LocalTesting::Off);
        assert!(!toml::to_string(&off).unwrap().contains("[testing]"), "off is not written, so existing digests hold");
        let on = Policy::parse("[testing]\nlocal = \"required\"\nbranches = [\"main\", \"release/*\"]\n").unwrap();
        assert_eq!(on.testing.local, LocalTesting::Required);
        assert_eq!(on.testing.branches, vec!["main".to_string(), "release/*".to_string()]);
        assert_eq!(Policy::parse("[testing]\nlocal = \"skippable\"\n").unwrap().testing.local, LocalTesting::Skippable);
        assert!(Policy::parse("[testing]\nlocal = \"sometimes\"\n").is_err());
        assert_ne!(on.digest(), off.digest());
    }

    fn parse(text: &str) -> Policy {
        Policy::parse(text).unwrap()
    }

    #[test]
    fn defaults_are_solo_friendly() {
        let p = Policy::default();
        assert_eq!(p.intent.mode, IntentMode::Inferred);
        assert_eq!(p.enforce.on_error, OnError::Open);
        assert_eq!(p.record.middle, Middle::Local);
        assert!(p.evidence.accept.contains(&Role::Local));
    }

    #[test]
    fn typos_are_errors_not_silent_weakening() {
        assert!(Policy::parse("[intnt]\nmode = \"always\"").is_err());
        assert!(Policy::parse("[intent]\nmode = \"sometimes\"").is_err());
        assert!(Policy::parse("[[check]]\nname = \"t\"").is_err(), "a check needs a command");
        assert!(Policy::parse("[approvals]\nmin = 0").is_err());
    }

    #[test]
    fn a_policy_for_a_newer_use05_says_so_before_reading_sections_it_does_not_know() {
        let e = Policy::parse("[use05]\nmin_version = \"99.0.0\"\n\n[[env]]\nname = \"prod\"\n").unwrap_err();
        assert_eq!(e.code, "POLICY_NEEDS_NEWER");
        assert!(e.message.contains("99.0.0") && e.message.contains(env!("CARGO_PKG_VERSION")), "{}", e.message);
        assert!(e.next.as_deref().is_some_and(|n| n.contains("npm i -g @use05/cli")), "{:?}", e.next);
    }

    #[test]
    fn a_policy_this_version_meets_is_read_and_keeps_its_minimum() {
        let p = parse(&format!("[use05]\nmin_version = \"{}\"\n", env!("CARGO_PKG_VERSION")));
        assert_eq!(p.use05.min_version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
        assert!(parse("[use05]\nmin_version = \"0.0.0\"").use05.min_version.is_some());
        assert!(!Policy::default().to_toml().contains("[use05]"), "an unset minimum is not written out");
    }

    #[test]
    fn a_minimum_version_that_is_not_a_version_is_an_error() {
        assert_eq!(Policy::parse("[use05]\nmin_version = \"soon\"").unwrap_err().code, "POLICY_INVALID");
        assert_eq!(Policy::parse("[use05]\nmin_version = 2").unwrap_err().code, "POLICY_INVALID");
    }

    #[test]
    fn versions_compare_by_number_not_by_text() {
        assert!(version_below("0.0.9", "0.0.10"));
        assert!(version_below("0.9.0", "1.0.0"));
        assert!(!version_below("0.1.0", "0.1.0"));
        assert!(!version_below("0.1.0-ci", "0.1.0"), "a pre-release build counts as its version");
    }

    #[test]
    fn path_rules_are_read_and_an_unset_rule_changes_no_existing_digest() {
        let p = parse("[protect]\nlocked = [\"LICENSE\"]\nappend_only = [\"migrations/**\"]\nno_delete = [\"docs/**\"]\nno_read = [\".env*\"]\nabsolute = [\"NOTICE\"]\nbypass = false");
        assert!(p.protect.is_locked("LICENSE") && p.protect.is_locked("NOTICE"), "an absolute lock is a lock");
        assert!(p.protect.is_absolute("NOTICE") && p.protect.is_absolute("LICENSE"), "with bypass off, every lock is absolute");
        assert!(p.protect.is_append_only("migrations/001.sql") && p.protect.is_no_delete("docs/a.md") && p.protect.is_no_read(".env.local"));
        let open = parse("[protect]\nlocked = [\"LICENSE\"]");
        assert!(open.protect.is_locked("LICENSE") && !open.protect.is_absolute("LICENSE"), "a lock is bypassable by default");
        let text = Policy::default().to_toml();
        assert!(!text.contains("locked") && !text.contains("bypass") && !text.contains("no_read"), "unset rules are not written, so digests and approvals hold:\n{text}");
    }

    #[test]
    fn a_lock_that_would_freeze_the_policy_itself_is_refused() {
        assert_eq!(Policy::parse("[protect]\nabsolute = [\".05/**\"]").unwrap_err().code, "POLICY_INVALID");
        assert_eq!(Policy::parse("[protect]\nlocked = [\".05/policy.toml\"]\nbypass = false").unwrap_err().code, "POLICY_INVALID");
        assert!(Policy::parse("[protect]\nlocked = [\".05/policy.toml\"]").is_ok(), "a bypassable lock on the policy is the developer's choice");
    }

    #[test]
    fn a_floor_adds_path_rules_and_can_turn_bypass_off_but_never_on() {
        let mut repo = parse("[protect]\nlocked = [\"LICENSE\"]");
        repo.tighten(&Floor { protect_locked: vec!["vendor/**".into()], protect_no_read: vec!["secrets/**".into()], protect_bypass: Some(false), ..Floor::default() });
        assert!(repo.protect.is_locked("LICENSE") && repo.protect.is_locked("vendor/x.rs") && repo.protect.is_no_read("secrets/k"));
        assert!(!repo.protect.bypass);
        let mut strict = parse("[protect]\nbypass = false");
        strict.tighten(&Floor { protect_bypass: Some(true), ..Floor::default() });
        assert!(!strict.protect.bypass, "a floor never loosens");
    }

    #[test]
    fn the_floor_tightens_and_never_loosens() {
        let mut repo = parse(
            "[intent]\nmode = \"always\"\n[drift]\nscope = \"deny\"\n[evidence]\naccept = [\"local\", \"runner\"]\n[approvals]\nmin = 2\nexpire_days = 3\n[enforce]\non_error = \"closed\"",
        );
        // A weaker floor changes nothing the repository asked for.
        repo.tighten(&Floor {
            intent_mode: Some(IntentMode::Inferred),
            drift_scope: Some(Severity::Warn),
            approvals_min: Some(1),
            approvals_expire_days_max: Some(30),
            enforce_on_error: Some(OnError::Open),
            ..Floor::default()
        });
        assert_eq!(repo.intent.mode, IntentMode::Always);
        assert_eq!(repo.drift.scope, Severity::Deny);
        assert_eq!(repo.approvals.min, 2);
        assert_eq!(repo.approvals.expire_days, 3);
        assert_eq!(repo.enforce.on_error, OnError::Closed);

        // A stronger floor wins.
        let mut solo = Policy::default();
        solo.tighten(&Floor {
            intent_mode: Some(IntentMode::Risky),
            drift_dependencies: Some(Severity::Approval),
            evidence_accept: Some(vec![Role::Runner]),
            approvals_min: Some(2),
            approvals_expire_days_max: Some(2),
            record_middle: Some(Middle::Local),
            enforce_on_error: Some(OnError::Closed),
            protect_paths: vec!["infra/**".into()],
            ..Floor::default()
        });
        assert_eq!(solo.intent.mode, IntentMode::Risky);
        assert_eq!(solo.drift.dependencies, Severity::Approval);
        assert_eq!(solo.evidence.accept, vec![Role::Runner]);
        assert_eq!((solo.approvals.min, solo.approvals.expire_days), (2, 2));
        assert_eq!(solo.enforce.on_error, OnError::Closed);
        assert!(solo.protect.paths.contains(&"infra/**".to_string()));
    }

    #[test]
    fn floor_checks_are_added_and_cannot_be_made_optional_or_rerouted() {
        let mut repo = parse("[[check]]\nname = \"test\"\nrun = [\"true\"]\nrequired = false");
        repo.tighten(&Floor {
            check: vec![CheckDef { name: "test".into(), run: vec!["cargo".into(), "test".into()], ..CheckDef::default() }, CheckDef { name: "audit".into(), run: vec!["cargo".into(), "audit".into()], ..CheckDef::default() }],
            ..Floor::default()
        });
        let test = repo.check_named("test").unwrap();
        assert!(test.required, "the repo cannot make an org-required check optional");
        assert_eq!(test.run, ["cargo", "test"], "the repo cannot swap the org's command for a weaker one");
        assert!(repo.check_named("audit").is_some());
    }

    #[test]
    fn env_allow_lists_only_shrink() {
        let mut p = parse("[env]\nallow = [\"A\", \"B\"]");
        p.tighten(&Floor { env_allow: Some(vec!["B".into(), "C".into()]), ..Floor::default() });
        assert_eq!(p.env.allow, Some(vec!["B".to_string()]));
        let mut open = Policy::default();
        open.tighten(&Floor { env_allow: Some(vec!["X".into()]), ..Floor::default() });
        assert_eq!(open.env.allow, Some(vec!["X".to_string()]));
    }

    #[test]
    fn fresh_base_and_require_rules_parse_and_leave_old_digests_alone() {
        let p = parse("[branches]\nfresh_base = \"approval\"\n\n[[require]]\nwhen = [\"src/api/**\"]\nalso = [\"docs/api/**\"]\nwhy = \"the API docs\"\n\n[[require]]\nwhen = [\"**\"]\nalso = [\"CHANGELOG.md\"]\nseverity = \"warn\"");
        assert_eq!(p.branches.fresh_base, Severity::Approval);
        assert_eq!(p.require.len(), 2);
        assert_eq!(p.require[0].severity, Severity::Approval, "a rule someone wrote bites by default");
        assert_eq!(p.require[0].why.as_deref(), Some("the API docs"));
        assert_eq!(p.require[1].severity, Severity::Warn);
        // Off by default, and not written out, so every existing policy keeps its digest.
        let d = Policy::default();
        assert_eq!(d.branches.fresh_base, Severity::Allow);
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("fresh_base") && !json.contains("require"), "{json}");
    }

    #[test]
    fn a_require_rule_needs_both_lists() {
        for bad in ["[[require]]\nwhen = []\nalso = [\"docs/**\"]", "[[require]]\nwhen = [\"src/**\"]\nalso = []", "[[require]]\nwhen = [\"src/**\"]", "[[require]]\nwhen = [\"src/**\"]\nalso = [\"docs/**\"]\nunless = 1"] {
            assert_eq!(Policy::parse(bad).unwrap_err().code, "POLICY_INVALID", "{bad}");
        }
    }

    #[test]
    fn a_require_rule_is_met_only_when_an_also_path_changed() {
        let p = parse("[[require]]\nwhen = [\"src/**\"]\nalso = [\"docs/**\"]");
        let r = &p.require[0];
        let v = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(r.unmet(&v(&["src/a.rs", "README.md"])), v(&["src/a.rs"]));
        assert!(r.unmet(&v(&["src/a.rs", "docs/a.md"])).is_empty());
        assert!(r.unmet(&v(&["README.md"])).is_empty(), "nothing it watches changed");
        let all = parse("[[require]]\nwhen = [\"**\"]\nalso = [\"docs/**\"]");
        assert!(all.require[0].unmet(&v(&["docs/only.md"])).is_empty(), "a file matching both counts as the update");
    }

    #[test]
    fn a_floor_adds_require_rules_and_raises_fresh_base() {
        let mut repo = parse("[branches]\nfresh_base = \"warn\"");
        let rule = Require { when: vec!["**".into()], also: vec!["docs/**".into()], severity: Severity::Approval, why: None };
        repo.tighten(&Floor { branches_fresh_base: Some(Severity::Deny), require: vec![rule.clone()], ..Floor::default() });
        assert_eq!(repo.branches.fresh_base, Severity::Deny);
        assert_eq!(repo.require, vec![rule.clone()]);
        repo.tighten(&Floor { branches_fresh_base: Some(Severity::Allow), require: vec![rule], ..Floor::default() });
        assert_eq!(repo.branches.fresh_base, Severity::Deny, "a floor never loosens");
        assert_eq!(repo.require.len(), 1, "the same rule is not added twice");
        let floor_json = serde_json::to_string(&Floor::default()).unwrap();
        assert!(!floor_json.contains("fresh_base") && !floor_json.contains("require"), "signed floors keep their bytes: {floor_json}");
        let rows = explain(&Policy::default(), &repo);
        let row = |k: &str| rows.iter().find(|r| r.key == k).map(|r| (r.value.clone(), r.source.word())).unwrap();
        assert_eq!(row("branches.fresh_base"), ("deny".to_string(), "org"));
        assert_eq!(row("require"), ("** needs docs/** (approval)".to_string(), "org"));
    }

    #[test]
    fn asking_for_lfs_files_is_off_by_default_and_costs_a_policy_that_does_not_use_it_nothing() {
        let off = parse("[evidence]\naccept = [\"local\"]\n");
        assert!(!off.evidence.lfs);
        assert!(!serde_json::to_string(&off).unwrap().contains("lfs"), "left out when off, so existing approvals bound to the digest hold");
        assert_eq!(off.digest(), parse("[evidence]\naccept = [\"local\"]\nlfs = false\n").digest(), "saying no is saying nothing");
        let on = parse("[evidence]\naccept = [\"local\"]\nlfs = true\n");
        assert!(on.evidence.lfs);
        assert_ne!(off.digest(), on.digest(), "a policy that asks for the real files is a different policy");
        assert_eq!(Policy::parse(&on.to_toml()).unwrap(), on, "it round-trips");
    }

    #[test]
    fn digest_changes_with_any_setting() {
        let a = Policy::default();
        let mut b = a.clone();
        assert_eq!(a.digest(), b.digest());
        b.approvals.min = 2;
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn explain_names_the_source_of_each_value() {
        let repo = parse("[intent]\nmode = \"risky\"");
        let mut effective = repo.clone();
        effective.tighten(&Floor { approvals_min: Some(2), ..Floor::default() });
        let rows = explain(&repo, &effective);
        let source = |key: &str| rows.iter().find(|r| r.key == key).unwrap().source.word();
        assert_eq!(source("intent.mode"), "repo");
        assert_eq!(source("approvals.min"), "org");
        assert_eq!(source("record.middle"), "default");
    }

    #[test]
    fn detection_proposes_but_never_invents() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_checks(dir.path()).is_empty());
        std::fs::write(dir.path().join("package.json"), r#"{"scripts":{"test":"jest","build":"tsc"}}"#).unwrap();
        let names: Vec<_> = detect_checks(dir.path()).into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["test", "build"]);
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        let cargo = detect_checks(dir.path()).into_iter().find(|c| c.name == "test").unwrap();
        assert_eq!(cargo.run, ["cargo", "test"], "the first ecosystem to claim a name keeps it");
    }

    #[test]
    fn environments_are_read_in_ladder_order_kept_and_explained() {
        let p = Policy::parse("[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"production\"\n").unwrap();
        assert_eq!(p.environment.iter().map(|e| (e.name.as_str(), e.branch.as_str())).collect::<Vec<_>>(), [("dev", "main"), ("prod", "production")]);
        assert!(crate::branches::is_kept(&p, "production"), "an environment's branch is never deleted");
        let row = explain(&p, &p).into_iter().find(|r| r.key == "environments").unwrap();
        assert_eq!(row.value, "dev: main → prod: production");
        // No environments: nothing is written out, so existing policy digests do not change.
        assert!(!toml::to_string(&Policy::default()).unwrap().contains("environment"));
    }

    #[test]
    fn environments_need_a_name_and_a_branch_and_no_repeats() {
        for bad in [
            "[[environment]]\nname = \"\"\nbranch = \"main\"\n",
            "[[environment]]\nname = \"dev\"\nbranch = \"main\"\n[[environment]]\nname = \"dev\"\nbranch = \"uat\"\n",
            "[[environment]]\nname = \"dev\"\nbranch = \"main\"\n[[environment]]\nname = \"uat\"\nbranch = \"main\"\n",
        ] {
            assert_eq!(Policy::parse(bad).unwrap_err().code, "POLICY_INVALID", "{bad}");
        }
    }


    // ------------------------------------------------------------------------- promotion (D93)

    const LADDER: &str = "[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"uat\"\nbranch = \"uat\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n";

    #[test]
    fn policy_without_environments_rules_has_the_same_digest() {
        // The exact bytes a 0.0.13 policy with environments serialised to: nothing of promotion is
        // written while unused, so every approval already bound to its digest still counts.
        let p = parse(LADDER);
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""environment":[{"name":"dev","branch":"main"},{"name":"uat","branch":"uat"},{"name":"prod","branch":"prod"}]"#), "{json}");
        let toml = p.to_toml();
        let written = &toml[toml.find("[[environment]]").unwrap()..];
        for word in ["from", "how", "agent", "rules", "soak", "sign_off", "confirm", "bypass", "on_failure", "rollback", "probe", "smoke", "hotfix"] {
            assert!(!written.contains(word), "{word} is not written while unused:\n{written}");
        }
        // Saying the default is saying nothing.
        let said = parse(&LADDER.replace("name = \"prod\"\nbranch = \"prod\"\n", "name = \"prod\"\nbranch = \"prod\"\n\n[environment.rules]\nsource_checks = \"deny\"\nmigrations = \"approval\"\n"));
        assert_eq!(said.digest(), p.digest());
        let stricter = parse(&LADDER.replace("name = \"prod\"\nbranch = \"prod\"\n", "name = \"prod\"\nbranch = \"prod\"\n\n[environment.rules]\nsoak = \"deny\"\n"));
        assert_ne!(stricter.digest(), p.digest());
        for empty in ["[environment.sign_off]\n", "[environment.bypass]\n", "[environment.bypass]\nallowed = true\nreason_min = 10\n", "[environment.sign_off]\nmin_length = 0\n", "[environment.hotfix]\n", "[environment.hotfix.rules]\n", "[environment.hotfix]\napproval = true\n"] {
            assert_eq!(parse(&format!("{LADDER}\n{empty}")).digest(), p.digest(), "an empty or default table says nothing: {empty}");
        }
    }

    #[test]
    fn a_hotfix_is_held_to_the_environments_rules_but_those_about_a_source() {
        let p = parse(LADDER);
        let prod = p.environment_named("prod").unwrap();
        let got = |e: &Environment| PROMOTE_RULES.iter().map(|r| e.hotfix_rule(r).unwrap()).collect::<Vec<_>>();
        assert_eq!(got(prod), [Severity::Allow, Severity::Allow, Severity::Allow, Severity::Approval, Severity::Warn, Severity::Allow], "source rules allow; the others are prod's own");
        let set = parse(&format!("{LADDER}\n[environment.hotfix]\napproval = true\n\n[environment.hotfix.rules]\nsource_checks = \"deny\"\nmigrations = \"deny\"\n"));
        let prod = set.environment_named("prod").unwrap();
        assert_eq!(got(prod), [Severity::Deny, Severity::Allow, Severity::Allow, Severity::Deny, Severity::Warn, Severity::Allow]);
        assert_ne!(set.digest(), p.digest(), "a hotfix rule is part of the rules");
        assert_eq!(parse(&set.to_toml()), set, "it round-trips");
        let e = Policy::parse(&format!("{LADDER}\n[environment.hotfix]\napproval = false\n")).unwrap_err();
        assert!(e.message.contains("always needs a person's approval"), "{}", e.message);
    }

    #[test]
    fn probes_and_smoke_checks_are_read_with_their_defaults_and_round_trip() {
        let p = parse(&format!("{LADDER}\n[[environment.probe]]\nname = \"version\"\nrun = [\"curl\", \"-fsS\", \"https://example.com/version\"]\nenv = [\"TOKEN\"]\n\n[[environment.probe]]\nname = \"worker\"\nrun = [\"./probe.sh\"]\ndir = \"ops\"\ntimeout_secs = 5\nwait_minutes = 0\ninterval_secs = 2\n\n[[environment.smoke]]\nname = \"health\"\nrun = [\"./smoke.sh\"]\n"));
        let prod = p.environment_named("prod").unwrap();
        let (version, worker) = (&prod.probe[0], &prod.probe[1]);
        assert_eq!((version.timeout_secs, version.wait_minutes, version.interval_secs, version.env.clone()), (60, 10, 15, vec!["TOKEN".to_string()]), "the defaults");
        assert_eq!((worker.dir.as_deref(), worker.timeout_secs, worker.wait_minutes, worker.interval_secs), (Some("ops"), 5, 0, 2));
        assert_eq!((prod.smoke[0].name.as_str(), prod.smoke[0].timeout_secs), ("health", 900), "a smoke check is shaped like a check");
        assert_eq!(Policy::parse(&p.to_toml()).unwrap(), p, "it round-trips");
        assert_ne!(p.digest(), parse(LADDER).digest());
        for bad in [
            "[[environment.probe]]\nname = \"v\"\n",
            "[[environment.probe]]\nrun = [\"x\"]\n",
            "[[environment.probe]]\nname = \"v\"\nrun = [\"x\"]\n\n[[environment.probe]]\nname = \"v\"\nrun = [\"y\"]\n",
            "[[environment.probe]]\nname = \"v\"\nrun = [\"x\"]\ninterval_secs = 0\n",
            "[[environment.probe]]\nname = \"v\"\nrun = [\"x\"]\nretries = 3\n",
            "[[environment.smoke]]\nname = \"h\"\nrun = []\n",
            "[[environment.smoke]]\nname = \"h\"\nrun = [\"x\"]\n\n[[environment.smoke]]\nname = \"h\"\nrun = [\"y\"]\n",
        ] {
            assert_eq!(Policy::parse(&format!("{LADDER}\n{bad}")).unwrap_err().code, "POLICY_INVALID", "{bad}");
        }
        for outside in ["[[environment.probe]]\nname = \"v\"\nrun = [\"x\"]\ndir = \"../up\"\n", "[[environment.smoke]]\nname = \"h\"\nrun = [\"x\"]\ndir = \"/etc\"\n"] {
            assert_eq!(Policy::parse(&format!("{LADDER}\n{outside}")).unwrap_err().code, "CHECK_DIR_OUTSIDE", "{outside}");
        }
    }

    /// Every [[environment]] setting at once, as 0.0.14 reads it: its serialised form, and so its
    /// digest, is pinned, so a change to how environments are written can never void approvals.
    const FULL_ENVIRONMENT: &str = "[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n\n[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\nfrom = \"dev\"\nhow = \"merge\"\nagent = false\nsoak_minutes = 60\non_failure = \"command\"\nrollback = [\"./rollback.sh\"]\nrollback_env = [\"TOKEN\"]\nrollback_timeout_secs = 60\n\n[[environment.probe]]\nname = \"version\"\nrun = [\"./probe.sh\"]\n\n[[environment.smoke]]\nname = \"health\"\nrun = [\"./smoke.sh\"]\n\n[environment.rules]\nsoak = \"deny\"\n\n[environment.sign_off]\nmin_length = 20\nsigners = [\"eng-managers\"]\nquestions = [\"What did you check?\"]\n\n[[environment.confirm]]\ntext = \"Notes are out\"\n\n[environment.bypass]\nnever = [\"soak\"]\n\n[environment.hotfix.rules]\nmigrations = \"deny\"\n";

    #[test]
    fn an_environments_serialised_form_and_digest_never_change() {
        let p = parse(&format!("{PEOPLE}\n{FULL_ENVIRONMENT}"));
        assert_eq!(p.digest(), "49cf6ef006391d845f84d03aaf02553ab04ccf91ace66b78508dacb6c3f4c659", "{}", serde_json::to_string(&p).unwrap());
        assert_eq!(parse(LADDER).digest(), "c23294672a813fec7293482c0a22a7e14ea3fc68a79f5b6f6219b0b7e8b6fc8b", "a plain ladder too");
    }

    const PUBLIC: &str = "[[destination]]\nname = \"public\"\nhow = \"export\"\nfrom = \"product/\"\nremote = \"git@github.com:org/public.git\"\nbranch = \"main\"\n";

    #[test]
    fn destinations_are_read_with_their_defaults_and_round_trip() {
        let p = parse(&format!("{PEOPLE}\n{LADDER}\n{PUBLIC}\n[destination.rules]\nuntasked = \"deny\"\n\n[destination.sign_off]\nsigners = [\"Dana\"]\n\n[[destination.confirm]]\ntext = \"The licence is in the folder\"\n\n[[destination]]\nname = \"mirror\"\nhow = \"push\"\nremote = \"backup\"\nbranch = \"main\"\n"));
        let public = p.destination_named("public").unwrap();
        assert_eq!((public.how, public.folder().as_deref(), public.push_from("main")), (DestinationHow::Export, Some("product"), None));
        assert_eq!(public.rules.untasked, Severity::Deny);
        assert!(!p.agent_may_promote(public), "an agent may not promote to a destination unless it says so");
        let mirror = p.destination_named("mirror").unwrap();
        assert_eq!((mirror.push_from("main"), mirror.folder()), (Some("main"), None), "a push sends the landing branch by default");
        assert_eq!(Target::how_word(mirror), "push");
        assert!(p.environment_named("public").is_none() && p.destination_named("prod").is_none());
        assert_eq!(Policy::parse(&p.to_toml()).unwrap(), p, "it round-trips");
        let shown = explain(&p, &p).into_iter().find(|r| r.key == "destinations").unwrap();
        assert_eq!((shown.value.as_str(), shown.source), ("public (export product/ to git@github.com:org/public.git main); mirror (push to backup main)", Source::Repo));
        assert_eq!(explain(&p, &p).into_iter().find(|r| r.key == "push.agent").unwrap().value, "any remote");
        let agent = parse(&format!("{PUBLIC}agent = true\n"));
        assert!(agent.agent_may_promote(agent.destination_named("public").unwrap()));
        let whole = parse(&PUBLIC.replace("\"product/\"", "\".\""));
        assert_eq!(whole.destination_named("public").unwrap().folder().as_deref(), Some(""), "the whole tree");
        assert_ne!(parse(PUBLIC).digest(), Policy::default().digest());
        // A table that says only the defaults says nothing.
        assert_eq!(parse(&format!("{PUBLIC}\n[destination.bypass]\nallowed = true\n")).digest(), parse(PUBLIC).digest());
    }

    #[test]
    fn duplicate_destination_name_is_an_error() {
        let twice = Policy::parse(&format!("{PUBLIC}\n{PUBLIC}")).unwrap_err();
        assert_eq!(twice.code, "DUPLICATE_TARGET", "{}", twice.message);
        let as_env = Policy::parse(&format!("{LADDER}\n{}", PUBLIC.replace("\"public\"", "\"prod\""))).unwrap_err();
        assert_eq!(as_env.code, "DUPLICATE_TARGET", "{}", as_env.message);
        assert!(as_env.message.contains("use05 promote prod"), "{}", as_env.message);
    }

    #[test]
    fn a_destination_has_no_probes_soak_hotfix_or_rollback_and_names_what_git_takes() {
        for key in ["soak_minutes = 30\n", "level = \"prod\"\n", "on_failure = \"report\"\n", "rollback = [\"./r.sh\"]\n", "\n[[destination.probe]]\nname = \"v\"\nrun = [\"x\"]\n", "\n[[destination.smoke]]\nname = \"h\"\nrun = [\"x\"]\n", "\n[destination.hotfix]\n"] {
            let e = Policy::parse(&format!("{PUBLIC}{key}")).unwrap_err();
            assert_eq!(e.code, "POLICY_INVALID", "{key}");
            assert!(e.message.contains("a destination has no probes"), "{key}: {}", e.message);
        }
        for bad in [
            PUBLIC.replace("from = \"product/\"\n", ""),
            PUBLIC.replace("\"product/\"", "\"../up\""),
            PUBLIC.replace("\"product/\"", "\"/etc\""),
            PUBLIC.replace("branch = \"main\"", "branch = \"--force\""),
            PUBLIC.replace("branch = \"main\"", "branch = \"a b\""),
            PUBLIC.replace("remote = \"git@github.com:org/public.git\"", "remote = \"--upload-pack=x\""),
            PUBLIC.replace("remote = \"git@github.com:org/public.git\"", "remote = \"\""),
            PUBLIC.replace("how = \"export\"\nfrom = \"product/\"", "how = \"push\"\nfrom = \"-x\""),
            PUBLIC.replace("how = \"export\"", "how = \"copy\""),
            format!("{PUBLIC}\n[destination.bypass]\nnever = [\"everything\"]\n"),
            format!("{PUBLIC}\n[[destination.confirm]]\ntext = \" \"\n"),
            format!("{PUBLIC}retries = 2\n"),
        ] {
            assert_eq!(Policy::parse(&bad).unwrap_err().code, "POLICY_INVALID", "{bad}");
        }
        let e = Policy::parse(&format!("{PUBLIC}\n[destination.sign_off]\nsigners = [\"nobody\"]\n")).unwrap_err();
        assert_eq!(e.code, "UNKNOWN_SIGNER", "{}", e.message);
    }

    #[test]
    fn push_agent_lists_remotes_by_name_or_url_and_unset_lets_any() {
        let urls = |name: &str| if name == "origin" { vec!["git@github.com:org/app.git".to_string()] } else { Vec::new() };
        let any = Policy::default();
        assert!(any.push.agent_may_push("elsewhere", "https://example.com/x.git", urls), "unset: no restriction");
        assert_eq!(parse("[push]\n").digest(), any.digest(), "an empty [push] says nothing");
        let p = parse("[push]\nagent = [\"origin\", \"https://example.com/mirror.git\"]\n");
        assert!(p.push.agent_may_push("origin", "git@github.com:org/app.git", urls), "by name");
        assert!(p.push.agent_may_push("git@github.com:org/app.git", "git@github.com:org/app.git", urls), "a URL that is origin's configured URL");
        assert!(p.push.agent_may_push("mirror", "https://example.com/mirror.git", urls), "by URL, whatever the remote is called here");
        assert!(!p.push.agent_may_push("public", "git@github.com:org/public.git", urls), "anything else");
        assert!(!p.push.agent_may_push("git@github.com:org/app.git.evil", "git@github.com:org/app.git.evil", urls), "a URL must equal one, not start like one");
        let none = parse("[push]\nagent = []\n");
        assert!(!none.push.agent_may_push("origin", "git@github.com:org/app.git", urls), "an empty list lets an agent push nowhere");
        assert_ne!(none.digest(), any.digest());
        assert_eq!(Policy::parse("[push]\nagent = [\" \"]\n").unwrap_err().code, "POLICY_INVALID");
        assert_eq!(Policy::parse(&p.to_toml()).unwrap(), p, "it round-trips");
    }

    #[test]
    fn promotion_settings_are_read_and_round_trip() {
        let p = parse(&format!(
            "{PEOPLE}\n[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n\n{LADDER}from = \"uat\"\nhow = \"merge\"\nagent = false\nsoak_minutes = 60\non_failure = \"command\"\nrollback = [\"./rollback.sh\"]\n\n[environment.rules]\nsource_checks = \"deny\"\nsource_confirmed = \"approval\"\nsoak = \"warn\"\nmigrations = \"approval\"\nuntasked = \"deny\"\nsign_off = \"approval\"\n\n[environment.sign_off]\nmin_length = 20\nsigners = [\"eng-managers\"]\nquestions = [\"What did you check in uat?\"]\n\n[[environment.confirm]]\ntext = \"The release notes are published\"\n\n[environment.bypass]\nallowed = true\nnever = [\"source_checks\"]\nreason_min = 10\n"
        ));
        let prod = p.environment_named("prod").unwrap();
        assert_eq!(prod.how(), PromoteHow::Merge);
        assert_eq!(prod.on_failure(), OnFailure::Command);
        assert_eq!(prod.rollback, ["./rollback.sh"]);
        assert_eq!((prod.rollback_env.clone(), prod.rollback_timeout_secs), (Vec::<String>::new(), 900), "the defaults");
        let named = parse(&format!("{LADDER}on_failure = \"command\"\nrollback = [\"./rollback.sh\"]\nrollback_env = [\"DEPLOY_TOKEN\"]\nrollback_timeout_secs = 120\n"));
        let prod_named = named.environment_named("prod").unwrap();
        assert_eq!((prod_named.rollback_env.clone(), prod_named.rollback_timeout_secs), (vec!["DEPLOY_TOKEN".to_string()], 120));
        assert_eq!(Policy::parse(&named.to_toml()).unwrap(), named);
        assert_eq!(parse(&format!("{LADDER}rollback_timeout_secs = 900\n")).digest(), parse(LADDER).digest(), "the default says nothing");
        assert_eq!(Policy::parse(&format!("{LADDER}rollback_timeout_secs = 0\n")).unwrap_err().code, "POLICY_INVALID");
        assert_eq!(prod.soak_minutes, Some(60));
        assert_eq!(prod.rules.untasked, Severity::Deny);
        assert_eq!(prod.rules.source_confirmed, Severity::Approval);
        let sign = prod.sign_off.as_ref().unwrap();
        assert_eq!((sign.min_length, sign.signers.clone(), sign.questions.len()), (20, vec!["eng-managers".to_string()], 1));
        assert_eq!(prod.confirm[0].text, "The release notes are published");
        let bypass = prod.bypass();
        assert!(bypass.allowed && bypass.never == ["source_checks"] && bypass.reason_min == 10);
        assert!(!p.agent_may_promote(prod));
        assert_eq!(Policy::parse(&p.to_toml()).unwrap(), p, "it round-trips");
    }

    #[test]
    fn from_defaults_to_the_rung_below_and_agent_to_every_rung_but_the_last() {
        let p = parse(&LADDER.replace("name = \"dev\"\nbranch = \"main\"\n", "name = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"dev-eu\"\nbranch = \"eu-main\"\nlevel = \"dev\"\n"));
        let source = |name: &str| p.source_of(p.environment_named(name).unwrap()).map(|e| e.name.clone());
        assert_eq!(source("dev"), None, "the lowest rung is promoted into by landing, not from anywhere");
        assert_eq!(source("dev-eu"), None);
        assert_eq!(source("uat").as_deref(), Some("dev"), "the first environment on the rung below");
        assert_eq!(source("prod").as_deref(), Some("uat"));
        let agent = |name: &str| p.agent_may_promote(p.environment_named(name).unwrap());
        assert!(agent("dev") && agent("uat"), "an agent may promote below the last rung");
        assert!(!agent("prod"), "but not onto the last rung, unless the policy says so");
        let solo = parse(&format!("{LADDER}agent = true\n"));
        assert!(solo.agent_may_promote(solo.environment_named("prod").unwrap()));
        let explicit = parse(&format!("{LADDER}from = \"dev\"\n"));
        assert_eq!(explicit.source_of(explicit.environment_named("prod").unwrap()).unwrap().name, "dev");
        // Two prod environments are both the last rung.
        let two = parse(&format!("{LADDER}\n[[environment]]\nname = \"prod-eu\"\nbranch = \"prod-eu\"\nlevel = \"prod\"\n"));
        assert!(!two.agent_may_promote(two.environment_named("prod-eu").unwrap()));
        assert_eq!(two.source_of(two.environment_named("prod-eu").unwrap()).unwrap().name, "uat");
    }

    #[test]
    fn from_naming_no_environment_is_an_error() {
        let e = Policy::parse(&format!("{LADDER}from = \"staging\"\n")).unwrap_err();
        assert_eq!(e.code, "UNKNOWN_ENVIRONMENT");
        assert!(e.message.contains("\"staging\"") && e.message.contains("\"prod\""), "{}", e.message);
    }

    #[test]
    fn a_cycle_in_from_is_an_error() {
        let cycle = LADDER.replace("name = \"uat\"\nbranch = \"uat\"\n", "name = \"uat\"\nbranch = \"uat\"\nfrom = \"prod\"\n") + "from = \"uat\"\n";
        let e = Policy::parse(&cycle).unwrap_err();
        assert_eq!(e.code, "POLICY_INVALID");
        assert!(e.message.contains("cycle") || e.message.contains("round"), "{}", e.message);
        assert_eq!(Policy::parse(&format!("{LADDER}from = \"prod\"\n")).unwrap_err().code, "POLICY_INVALID", "an environment is not promoted from itself");
    }

    #[test]
    fn command_failure_needs_a_rollback_command() {
        let e = Policy::parse(&format!("{LADDER}on_failure = \"command\"\n")).unwrap_err();
        assert_eq!(e.code, "ROLLBACK_MISSING");
        assert!(e.message.contains("\"prod\""), "{}", e.message);
        assert!(Policy::parse(&format!("{LADDER}on_failure = \"revert\"\n")).is_ok());
        assert_eq!(Policy::parse(&format!("{LADDER}on_failure = \"retry\"\n")).unwrap_err().code, "POLICY_INVALID");
    }

    #[test]
    fn unknown_promotion_names_are_errors_not_silent_no_ops() {
        for bad in [
            format!("{LADDER}\n[environment.rules]\nsource_check = \"deny\"\n"),
            format!("{LADDER}\n[environment.rules]\nsoak = \"sometimes\"\n"),
            format!("{LADDER}how = \"rebase\"\n"),
            format!("{LADDER}\n[environment.bypass]\nnever = [\"sourcechecks\"]\n"),
            format!("{LADDER}\n[[environment.confirm]]\ntext = \" \"\n"),
            format!("{LADDER}\n[environment.hotfix]\napproval = false\n"),
            format!("{LADDER}\n[environment.hotfix.rules]\nsource_check = \"deny\"\n"),
            format!("{LADDER}\n[environment.hotfix]\nsign_off = \"deny\"\n"),
        ] {
            assert!(Policy::parse(&bad).is_err(), "{bad}");
        }
        let e = Policy::parse(&format!("{PEOPLE}\n{LADDER}\n[environment.sign_off]\nsigners = [\"eng-mgrs\"]\n")).unwrap_err();
        assert_eq!(e.code, "UNKNOWN_SIGNER");
        assert!(e.message.contains("\"eng-mgrs\"") && e.message.contains("\"prod\""), "{}", e.message);
        assert!(Policy::parse(&format!("{PEOPLE}\n{LADDER}\n[environment.sign_off]\nsigners = [\"lee\"]\n")).is_ok(), "a person with a trusted key");
    }

    #[test]
    fn several_environments_can_share_a_level() {
        let p = Policy::parse("[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"dev-eu\"\nbranch = \"eu-main\"\nlevel = \"dev\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"production\"\n").unwrap();
        let levels: Vec<Option<&str>> = p.environment.iter().map(|e| e.level()).collect();
        assert_eq!(levels, [Some("dev"), Some("dev"), Some("prod")]);
        let row = explain(&p, &p).into_iter().find(|r| r.key == "environments").unwrap();
        assert_eq!(row.value, "dev: main, dev-eu: eu-main → prod: production");
        assert_eq!(Policy::parse("[[environment]]\nname = \"x\"\nbranch = \"y\"\nlevel = \"staging\"\n").unwrap_err().code, "POLICY_INVALID", "a level is one of dev, uat, pre-prod, prod");
    }

    #[test]
    fn a_check_without_paths_or_dir_serialises_as_it_always_did_so_digests_hold() {
        let p = parse("[[check]]\nname = \"t\"\nrun = [\"a\"]\n");
        assert_eq!(serde_json::to_string(&p.check[0]).unwrap(), r#"{"name":"t","run":["a"],"required":true,"env":[],"timeout_secs":900}"#);
        let written = p.to_toml();
        let check_table = written.split("[[check]]").nth(1).unwrap().split("\n[").next().unwrap();
        assert!(!check_table.contains("paths") && !check_table.contains("dir"), "{check_table}");
        let scoped = parse("[[check]]\nname = \"t\"\nrun = [\"a\"]\npaths = [\"api/**\"]\ndir = \"api\"\n");
        assert_eq!(scoped.check[0].paths, ["api/**"]);
        assert_eq!(scoped.check[0].dir.as_deref(), Some("api"));
        assert_ne!(scoped.digest(), p.digest(), "a scoped check is another policy");
        assert_eq!(parse(&scoped.to_toml()), scoped, "it survives a round trip");
    }

    #[test]
    fn check_dir_cannot_leave_the_tree() {
        for bad in ["../x", "a/../../x", "/etc", "a/..", "..", "", "  ", "C:\\x", "a\\b", "c:/x"] {
            let e = Policy::parse(&format!("[[check]]\nname = \"t\"\nrun = [\"a\"]\ndir = {bad:?}\n")).unwrap_err();
            assert_eq!(e.code, "CHECK_DIR_OUTSIDE", "{bad:?}");
            assert!(e.message.contains("\"t\""), "{}", e.message);
        }
        for good in ["api", "packages/api", "./api", "a/b/c", "a..b"] {
            assert!(Policy::parse(&format!("[[check]]\nname = \"t\"\nrun = [\"a\"]\ndir = {good:?}\n")).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn a_check_applies_to_a_change_that_touches_its_paths_and_to_every_change_without_paths() {
        let check = |paths: &[&str]| CheckDef { name: "t".into(), run: vec!["a".into()], paths: paths.iter().map(|s| s.to_string()).collect(), ..CheckDef::default() };
        assert!(check(&[]).applies_to(["anything"]) && check(&[]).applies_to(Vec::<&str>::new()));
        assert!(check(&["api/**", "Cargo.lock"]).applies_to(["src/x.rs", "api/deep/x.rs"]));
        assert!(check(&["api/**", "Cargo.lock"]).applies_to(["Cargo.lock"]));
        assert!(!check(&["api/**", "Cargo.lock"]).applies_to(["src/x.rs", "apis/x.rs"]));
        assert!(!check(&["api/**"]).applies_to(Vec::<&str>::new()), "a change that touches nothing calls for nothing");
        // A bare `**` means every file, not never.
        assert!(check(&["**"]).applies_to(["src/x.rs"]) && check(&["**/*"]).applies_to(["x"]) && check(&["./**"]).applies_to(["a/b"]));
        assert!(!check(&["**"]).applies_to(Vec::<&str>::new()));
    }

    #[test]
    fn a_floor_check_keeps_its_folder_and_cannot_be_narrowed_by_a_repository() {
        let floor_check = |paths: &[&str], dir: Option<&str>| CheckDef { name: "t".into(), run: vec!["floor".into()], paths: paths.iter().map(|s| s.to_string()).collect(), dir: dir.map(str::to_string), ..CheckDef::default() };
        let mut repo = parse("[[check]]\nname = \"t\"\nrun = [\"mine\"]\npaths = [\"api/**\"]\n");
        repo.tighten(&Floor { check: vec![floor_check(&[], Some("pkg"))], ..Floor::default() });
        assert_eq!((repo.check[0].run.clone(), repo.check[0].dir.clone(), repo.check[0].paths.clone()), (vec!["floor".to_string()], Some("pkg".to_string()), Vec::<String>::new()), "required always, as the floor asks");
        let mut repo = parse("[[check]]\nname = \"t\"\nrun = [\"mine\"]\n");
        repo.tighten(&Floor { check: vec![floor_check(&["api/**"], None)], ..Floor::default() });
        assert!(repo.check[0].paths.is_empty(), "the repository asked for it always");
        let mut repo = parse("[[check]]\nname = \"t\"\nrun = [\"mine\"]\npaths = [\"web/**\"]\n");
        repo.tighten(&Floor { check: vec![floor_check(&["api/**"], None)], ..Floor::default() });
        assert_eq!(repo.check[0].paths, ["web/**", "api/**"]);
    }

    // ------------------------------------------------------------------------- signers and owners (D92)

    /// Trust keys for Dana and Lee, named as people.
    const PEOPLE: &str = "[[trust.key]]\nname = \"dana\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:AAAA\"\nperson = \"Dana\"\n\n[[trust.key]]\nname = \"lee\"\nrole = \"approver\"\npublic = \"use05-ed25519-public:BBBB\"\nperson = \" lee \"\n";

    fn owned(rest: &str) -> Policy {
        parse(&format!("{PEOPLE}\n[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n\n{rest}"))
    }

    #[test]
    fn signer_groups_and_owner_rules_are_read() {
        let p = owned("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-managers\"]\n\n[[protect.owner]]\npaths = [\"infra/**\"]\nsigners = [\"lee\", \"ENG-MANAGERS \"]\nmin = 2\n");
        assert_eq!(p.signer, vec![SignerGroup { name: "eng-managers".into(), people: vec!["Dana".into(), "Lee".into()] }]);
        assert_eq!(p.protect.owner.len(), 2);
        assert_eq!(p.protect.owner[0].min, 1, "one owner unless the rule says");
        assert_eq!(p.protect.owner[1].min, 2);
        assert_eq!(p.people_of(&p.protect.owner[0].signers), ["Dana", "Lee"]);
        assert_eq!(p.people_of(&p.protect.owner[1].signers), ["lee", "Dana"], "a person named twice, once in a group, is one person");
        assert_eq!(p.owner_rules()[0].touched(&["billing/pay.rs".into(), "README.md".into()]), ["billing/pay.rs"]);
        assert_eq!(Policy::parse(&p.to_toml()).unwrap(), p, "it round-trips");
    }

    #[test]
    fn unknown_signer_is_a_policy_error() {
        // A rule naming a group that does not exist, or a person no trusted key belongs to.
        for (bad, named) in [
            ("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-mgrs\"]\n", "eng-mgrs"),
            ("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"Sam\"]\n", "Sam"),
        ] {
            let e = Policy::parse(&format!("{PEOPLE}\n{bad}")).unwrap_err();
            assert_eq!(e.code, "UNKNOWN_SIGNER", "{bad}");
            assert!(e.message.contains(&format!("{named:?}")), "the bad name is named: {}", e.message);
        }
        // A group whose member is nobody 05 knows.
        let e = Policy::parse(&format!("{PEOPLE}\n[[signer]]\nname = \"ops\"\npeople = [\"Dana\", \"Sam\"]\n")).unwrap_err();
        assert_eq!(e.code, "UNKNOWN_SIGNER");
        assert!(e.message.contains("\"Sam\"") && e.message.contains("\"ops\""), "{}", e.message);
        // A plain person who has a trusted key is fine, matched ignoring case and spaces.
        assert!(Policy::parse(&format!("{PEOPLE}\n[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"LEE\"]\n")).is_ok());
    }

    #[test]
    fn an_owner_rule_or_a_group_with_nothing_in_it_is_a_policy_error() {
        for bad in [
            "[[protect.owner]]\npaths = []\nsigners = [\"Dana\"]\n",
            "[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = []\n",
            "[[protect.owner]]\nsigners = [\"Dana\"]\n",
            "[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"Dana\"]\nmin = 0\n",
            "[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"Dana\"]\nmin = 2\n",
            "[[signer]]\nname = \"ops\"\npeople = []\n",
            "[[signer]]\nname = \" \"\npeople = [\"Dana\"]\n",
            "[[signer]]\nname = \"ops\"\npeople = [\"Dana\"]\n\n[[signer]]\nname = \"OPS\"\npeople = [\"Lee\"]\n",
        ] {
            assert_eq!(Policy::parse(&format!("{PEOPLE}\n{bad}")).unwrap_err().code, "POLICY_INVALID", "{bad}");
        }
    }

    #[test]
    fn policy_without_owners_has_the_same_digest() {
        // The exact bytes a 0.0.13 policy serialised to: no `signer`, no `owner`, so every
        // approval already bound to its digest still counts.
        let p = parse("[protect]\npaths = [\"migrations/**\"]\n");
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("signer") && !json.contains("owner"), "{json}");
        let before = r#""protect":{"paths":["migrations/**"]},"#;
        assert!(json.contains(before), "{json}");
        let mut same = p.clone();
        same.signer = Vec::new();
        same.protect.owner = Vec::new();
        assert_eq!(same.digest(), p.digest());
        assert_eq!(Policy::default().digest(), parse("").digest());
        let floor_json = serde_json::to_string(&Floor::default()).unwrap();
        assert!(!floor_json.contains("signer") && !floor_json.contains("owner"), "signed floors keep their bytes: {floor_json}");
        assert_ne!(owned("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-managers\"]\n").digest(), parse(PEOPLE).digest());
    }

    #[test]
    fn a_floor_adds_groups_and_owner_rules_and_never_widens_a_group() {
        let mut repo = owned("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-managers\"]\n");
        let rule = OwnerRule { paths: vec!["infra/**".into()], signers: vec!["security".into()], min: 1 };
        let floor = Floor {
            signer: vec![SignerGroup { name: "security".into(), people: vec!["Lee".into()] }, SignerGroup { name: "Eng-Managers".into(), people: vec!["Lee".into(), "Sam".into()] }],
            protect_owner: vec![rule],
            ..Floor::default()
        };
        repo.tighten(&floor);
        assert_eq!(repo.people_of(&["security".into()]), ["Lee"]);
        assert_eq!(repo.people_of(&["eng-managers".into()]), ["Lee"], "a group both name keeps only the people both list");
        repo.tighten(&floor);
        assert_eq!(repo.protect.owner.len(), 1, "a floor's rules are kept apart from the repository's");
        assert_eq!(repo.protect.floor_owner.len(), 1, "the same rule is not added twice");
        assert_eq!(repo.owner_rules().len(), 2);
        assert!(!serde_json::to_string(&Policy::default()).unwrap().contains("floor_owner"));
        assert!(Policy::parse(&format!("{PEOPLE}\n[[protect.floor_owner]]\npaths = [\"x/**\"]\nsigners = [\"Dana\"]\nmin = 1\npeople = [\"Dana\"]\n")).is_err(), "a repository cannot write a floor's rule");
    }

    #[test]
    fn a_group_named_after_a_person_is_refused() {
        // Otherwise a rule naming Lee would mean whoever the group "Lee" lists.
        let e = Policy::parse(&format!("{PEOPLE}\n[[signer]]\nname = \"LEE\"\npeople = [\"Dana\"]\n")).unwrap_err();
        assert_eq!(e.code, "SIGNER_NAME_TAKEN");
        assert!(e.message.contains("\"LEE\""), "{}", e.message);
    }

    #[test]
    fn one_key_listed_for_two_people_is_a_policy_error() {
        let twice = PEOPLE.replace("public = \"use05-ed25519-public:BBBB\"", "public = \"use05-ed25519-public:AAAA\"");
        let e = Policy::parse(&twice).unwrap_err();
        assert_eq!(e.code, "POLICY_INVALID");
        assert!(e.message.contains("Dana") && e.message.contains("lee"), "{}", e.message);
        let same_person_twice = PEOPLE.replace("public = \"use05-ed25519-public:BBBB\"\nperson = \" lee \"", "public = \"use05-ed25519-public:AAAA\"\nperson = \"dana\"");
        assert!(Policy::parse(&same_person_twice).is_ok(), "the same key for the same person, twice, is one person");
    }

    fn floor_people() -> Vec<TrustKey> {
        vec![TrustKey { name: "lee".into(), role: Role::Approver, public: "use05-ed25519-public:LLLL".into(), expires: None, person: Some("Lee".into()) }]
    }

    #[test]
    fn a_floor_owner_rule_never_resolves_against_the_repositorys_groups() {
        // The repository defines a group with the name the floor uses: it must not capture the rule.
        let mut repo = parse(&format!("{PEOPLE}\n[[signer]]\nname = \"security\"\npeople = [\"Dana\"]\n"));
        let floor = Floor {
            trust_key: floor_people(),
            signer: vec![SignerGroup { name: "security".into(), people: vec!["Lee".into()] }],
            protect_owner: vec![OwnerRule { paths: vec!["infra/**".into()], signers: vec!["security".into()], min: 1 }],
            ..Floor::default()
        };
        repo.tighten(&floor);
        let rules = repo.owner_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].people, ["Lee"], "the floor's own group, not the repository's");
        assert!(repo.check_effective().is_ok());
        // A group named after a person the floor trusts is refused once the floor applies.
        let mut taken = parse(&format!("{PEOPLE}\n[[signer]]\nname = \"Lee \"\npeople = [\"Dana\"]\n").replace("person = \" lee \"", "person = \"Lee Two\""));
        taken.tighten(&Floor { trust_key: floor_people(), ..Floor::default() });
        assert_eq!(taken.check_effective().unwrap_err().code, "SIGNER_NAME_TAKEN");
    }

    #[test]
    fn a_floor_naming_a_group_it_does_not_define_is_refused() {
        let rule = |signer: &str| Floor { trust_key: floor_people(), protect_owner: vec![OwnerRule { paths: vec!["infra/**".into()], signers: vec![signer.into()], min: 1 }], ..Floor::default() };
        let e = rule("security").validate().unwrap_err();
        assert_eq!(e.code, "UNKNOWN_SIGNER");
        assert!(e.message.contains("\"security\""), "{}", e.message);
        assert!(rule("lee").validate().is_ok(), "a person the floor trusts");
        assert!(Floor::default().validate().is_ok());
    }

    #[test]
    fn an_intersection_that_leaves_too_few_owners_is_not_a_load_error() {
        // The gate reports it; loading stays possible so the brief can say why.
        let mut repo = owned("[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-managers\"]\n");
        repo.tighten(&Floor { signer: vec![SignerGroup { name: "eng-managers".into(), people: vec!["Sam".into()] }], ..Floor::default() });
        assert!(repo.owner_rules()[0].people.is_empty());
        assert!(repo.check_effective().is_ok());
    }
}

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
}

impl Default for CheckDef {
    fn default() -> CheckDef {
        CheckDef { name: String::new(), run: Vec::new(), required: true, env: Vec::new(), timeout_secs: 900 }
    }
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
        TrustKey { name: String::new(), role: Role::Runner, public: String::new(), expires: None }
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
    /// Recorded and shown; promotion between them is not built yet. Not written out when empty,
    /// so existing digests hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<Environment>,
}

/// One environment: a name and the branch it lives on.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub name: String,
    pub branch: String,
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
        return Err(Error::new("POLICY_NEEDS_NEWER", format!("this repository's policy needs use05 {min} or newer; this is use05 {this}"))
            .with_next("upgrade: npm i -g @use05/cli, or curl -fsSL https://use05.dev/install.sh | sh"));
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
        BranchPolicy { keep: v(&["main", "master", "develop", "release/*"]), work: v(&["05/*", "agent/*", "claude/*", "codex/*"]), target: None, land: LandMode::Manual }
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
}

fn is_true(b: &bool) -> bool {
    *b
}

impl Default for Protect {
    fn default() -> Self {
        Protect { paths: Vec::new(), locked: Vec::new(), absolute: Vec::new(), append_only: Vec::new(), no_delete: Vec::new(), no_read: Vec::new(), bypass: true }
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
        EvidencePolicy { accept: vec![Role::Local, Role::Runner], stop_budget_secs: 60, prove_at_push: true }
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
                    existing.required = existing.required || required.required;
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
    }

    pub fn parse(text: &str) -> Result<Policy> {
        check_min_version(text)?;
        let policy: Policy = toml::from_str(text).map_err(|e| {
            Error::new("POLICY_INVALID", format!("the policy is not valid: {}", e.to_string().trim_end()))
                .with_next("fix the file, or run: use05 policy")
        })?;
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
        }
        if self.protect.is_absolute(POLICY_PATH) {
            return Err(Error::new("POLICY_INVALID", format!("a lock no bypass can clear covers {POLICY_PATH}, so the policy could never be changed again"))
                .with_next("leave the policy file out of `absolute`, or turn `bypass` back on"));
        }
        for (i, e) in self.environment.iter().enumerate() {
            if e.name.trim().is_empty() || e.branch.trim().is_empty() {
                return Err(Error::new("POLICY_INVALID", "every [[environment]] needs a name and a branch"));
            }
            if self.environment[..i].iter().any(|o| o.name == e.name || o.branch == e.branch) {
                return Err(Error::new("POLICY_INVALID", format!("the environment {:?} or its branch {:?} is listed twice", e.name, e.branch)));
            }
        }
        if self.approvals.min == 0 {
            return Err(Error::new("POLICY_INVALID", "approvals.min must be at least 1"));
        }
        Ok(())
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
    p.environment.iter().map(|e| format!("{}: {}", e.name, e.branch)).collect::<Vec<_>>().join(" → ")
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
    let rules = |p: &Policy| if p.risk.rules.is_empty() { "built-in only".to_string() } else { format!("built-in, plus {}", p.risk.rules.iter().map(|r| format!("{} ({})", r.category, r.level.word())).collect::<Vec<_>>().join(", ")) };
    let exempt = |p: &Policy| match (p.risk.exempt.is_empty(), p.risk.exempt_allowed) {
        (_, false) => "not allowed".to_string(),
        (true, true) => "none".to_string(),
        (false, true) => p.risk.exempt.join(", "),
    };
    let min = |p: &Policy| p.use05.min_version.clone().unwrap_or_else(|| "not set".to_string());
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
        row("checks", names(&default), names(repo), names(effective)),
        row("env.allow", env(&default), env(repo), env(effective)),
        row("trusted keys", keys(&default), keys(repo), keys(effective)),
        row("risk.rules", rules(&default), rules(repo), rules(effective)),
        row("environments", envs(&default), envs(repo), envs(effective)),
        row("branches.keep", default.branches.keep.join(", "), repo.branches.keep.join(", "), effective.branches.keep.join(", ")),
        row("branches.work", default.branches.work.join(", "), repo.branches.work.join(", "), effective.branches.work.join(", ")),
        row("branches.target", target(&default), target(repo), target(effective)),
        row("branches.land", land(&default), land(repo), land(effective)),
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

}

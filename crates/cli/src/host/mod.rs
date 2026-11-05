//! Where the CI gate meets a Git host (D99). Everything the gate and `init --ci` need from a host
//! is behind `Host`: what the event was, a way to push receipts, where to post the verdict, the
//! job summary, and the workflow files `init` writes. The rest of the CLI never names a host's
//! environment variables, URLs or file formats. GitHub is the only adapter; see `docs/extending.md`
//! for how a second one fits.
//!
//! This lives in the CLI, not in core: it reads the process environment, and core stays
//! host-neutral.

use std::path::{Path, PathBuf};

mod github;

/// What kind of run CI says this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Push,
    PullRequest,
    MergeGroup,
    /// A run started by another workflow finishing: the trusted run that follows an untrusted
    /// one, from a definition the change's branch cannot alter (D94).
    WorkflowRun,
    Other,
}

impl EventKind {
    /// A run whose definition the change's own branch supplies, so the change can make it do
    /// anything, read a secret it is given included.
    pub fn branch_defined(self) -> bool {
        matches!(self, EventKind::Push | EventKind::PullRequest | EventKind::MergeGroup)
    }
}

/// The event CI is running for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiEvent {
    pub kind: EventKind,
    /// The commit the event is about, when the host says. Empty when it does not.
    pub head_sha: String,
    /// The branch the change is on: the pull request's own branch, the branch pushed, or the merge
    /// queue's temporary branch. Empty when CI names none.
    pub branch: String,
    /// The branch the change is going into, when the event has one (a pull request's base, a
    /// merge queue's base).
    pub base_branch: Option<String>,
    /// For a run started by another run: the kind of event that started the first one.
    pub triggered_by: Option<EventKind>,
    /// The repository's default branch, when the host's event says.
    pub default_branch: Option<String>,
    /// The repository the change came from, when it is not this one (a fork's pull request).
    pub fork: Option<String>,
}

impl CiEvent {
    /// What CI knows nothing about: no host, or a run with no event.
    #[cfg(test)]
    pub fn unknown() -> Self {
        CiEvent { kind: EventKind::Other, head_sha: String::new(), branch: String::new(), base_branch: None, triggered_by: None, default_branch: None, fork: None }
    }

    /// The kind of event the change arrived by: for a run another run started, that first run's.
    pub fn origin(&self) -> EventKind {
        self.triggered_by.unwrap_or(self.kind)
    }

    /// The branch this change goes to: its base when it has one, else the branch pushed. Empty
    /// when CI names none, so that a policy asking for something before a push holds the change
    /// rather than lets it through.
    pub fn lands_on(&self) -> &str {
        self.base_branch.as_deref().unwrap_or(&self.branch)
    }
}

/// A verdict as a host shows it next to a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pending,
    Success,
    Failure,
}

/// Where the runner pushes its receipts branch: a plain address, and the environment git needs to
/// authenticate there. The token is in neither the address nor git's command line, which any user
/// on the machine can read; only git's environment holds it.
pub struct PushRemote {
    pub url: String,
    pub token: String,
    /// Variables for the `git push`, holding the credential.
    pub envs: Vec<(String, String)>,
}

impl PushRemote {
    /// `text` with the token removed, as it is and in any form the credential carries it.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("x-access-token:{}", self.token));
        for t in [encoded, self.token.clone()] {
            if !self.token.is_empty() {
                out = out.replace(&t, "***");
            }
        }
        out
    }
}

pub trait Host {
    fn name(&self) -> &'static str;
    /// The event this run is for, read from the host's environment.
    fn event(&self) -> CiEvent;
    /// Where to push the runner's receipts branch. Never print its address; `PushRemote::redact`
    /// removes the token from anything that might quote it. `None` when the host gave no token
    /// or repository, and the plain remote is used.
    fn push_remote(&self) -> Option<PushRemote>;
    /// Show a verdict next to a commit (a commit status).
    fn post_status(&self, sha: &str, state: Verdict, description: &str) -> Result<(), String>;
    /// Add to the run's job summary, if the host has one.
    fn summary(&self, markdown: &str);
    /// The files `init --ci <host>` writes, as repository-relative paths with their text. The
    /// first is the gate, which holds the runner key.
    fn workflows(&self) -> Vec<(PathBuf, String)>;
    /// Whether `post_status` uses a token of its own (the person's 05 app) that no workflow a
    /// branch defines can hold. Without one, a branch can post the same status itself.
    fn status_from_app(&self) -> bool;
    /// Workflow files in the repository at `top` that hand the runner key to a run the change's
    /// own branch defines (D94).
    fn key_exposed_in(&self, top: &Path) -> Vec<PathBuf>;
    /// How the runner key and the status have to be kept on the host so only the gate has them:
    /// settings 05 cannot read from the repository. One sentence each.
    fn key_custody(&self) -> Vec<&'static str>;
}

/// The host this process is running inside, from its environment.
pub fn detect() -> Option<Box<dyn Host>> {
    (std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")).then(github::new)
}

/// The host `gate --ci` reads. Outside a recognised host it still reads the only adapter there is,
/// as it always has, so a run reproduced by hand with the host's variables set behaves the same.
pub fn current() -> Box<dyn Host> {
    detect().unwrap_or_else(github::new)
}

/// A host by the name `init --ci` is given.
pub fn by_name(name: &str) -> Option<Box<dyn Host>> {
    all().into_iter().find(|h| h.name() == name)
}

/// Every host there is an adapter for.
pub fn all() -> Vec<Box<dyn Host>> {
    vec![github::new()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_removes_the_token_from_what_git_says() {
        let remote = PushRemote { url: "https://github.com/o/r.git".into(), token: "s3cret".into(), envs: vec![] };
        assert_eq!(remote.redact("fatal: unable to access 'https://x-access-token:s3cret@github.com/o/r.git'"), "fatal: unable to access 'https://x-access-token:***@github.com/o/r.git'");
        assert_eq!(remote.redact("nothing"), "nothing");
        // Whatever the token holds, and in the form the credential header carries it.
        let odd = PushRemote { url: "https://github.com/o/r.git".into(), token: "a@b:c/d".into(), envs: vec![] };
        assert_eq!(odd.redact("token a@b:c/d, header eC1hY2Nlc3MtdG9rZW46YUBiOmMvZA=="), "token ***, header ***");
        assert_eq!(PushRemote { url: String::new(), token: String::new(), envs: vec![] }.redact("abc"), "abc");
    }

    #[test]
    fn only_runs_a_branch_defines_are_exposed() {
        let mut e = CiEvent::unknown();
        assert!(EventKind::Push.branch_defined() && EventKind::PullRequest.branch_defined() && EventKind::MergeGroup.branch_defined());
        assert!(!EventKind::WorkflowRun.branch_defined() && !EventKind::Other.branch_defined());
        e.kind = EventKind::WorkflowRun;
        e.triggered_by = Some(EventKind::PullRequest);
        assert_eq!(e.origin(), EventKind::PullRequest);
    }

    #[test]
    fn lands_on_prefers_the_base() {
        let mut e = CiEvent::unknown();
        assert_eq!(e.lands_on(), "");
        e.branch = "feature".into();
        assert_eq!(e.lands_on(), "feature");
        e.base_branch = Some("main".into());
        assert_eq!(e.lands_on(), "main");
    }
}

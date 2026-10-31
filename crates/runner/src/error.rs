use std::fmt;

/// Everything that can stop a proof from being produced. Each variant has a stable code.
#[derive(Debug)]
pub enum RunnerError {
    /// `git` could not be started.
    GitMissing(std::io::Error),
    /// The directory is not inside a git work tree.
    NotARepo(String),
    /// The tree to prove could not be resolved.
    BadTree { spec: String, reason: String },
    /// A git command failed.
    GitFailed { what: &'static str, stderr: String },
    /// The tree contains a path that would escape the scratch directory or touch `.git`.
    UnsafePath(String),
    /// The command could not be started (for example, not found).
    Spawn { program: String, source: std::io::Error },
    /// No command was given.
    NoCommand,
    /// A variable to pass through has an unusable name.
    BadEnv(String),
    Io { what: &'static str, source: std::io::Error },
}

impl RunnerError {
    pub fn code(&self) -> &'static str {
        match self {
            RunnerError::GitMissing(_) => "GIT_MISSING",
            RunnerError::NotARepo(_) => "NOT_A_REPO",
            RunnerError::BadTree { .. } => "TREE_NOT_FOUND",
            RunnerError::GitFailed { .. } => "GIT_FAILED",
            RunnerError::UnsafePath(_) => "UNSAFE_PATH",
            RunnerError::Spawn { .. } => "COMMAND_NOT_STARTED",
            RunnerError::NoCommand => "NO_COMMAND",
            RunnerError::BadEnv(_) => "BAD_ENV",
            RunnerError::Io { .. } => "IO_ERROR",
        }
    }

    pub(crate) fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> RunnerError {
        move |source| RunnerError::Io { what, source }
    }
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunnerError::GitMissing(e) => write!(f, "git could not be started ({e})"),
            RunnerError::NotARepo(dir) => write!(f, "{dir} is not inside a git work tree"),
            RunnerError::BadTree { spec, reason } => write!(f, "cannot resolve tree {spec:?}: {reason}"),
            RunnerError::GitFailed { what, stderr } => write!(f, "git failed while {what}: {stderr}"),
            RunnerError::UnsafePath(p) => write!(f, "the tree contains an unsafe path: {p}"),
            RunnerError::Spawn { program, source } => write!(f, "could not start {program:?}: {source}"),
            RunnerError::NoCommand => write!(f, "no command was given to run"),
            RunnerError::BadEnv(name) => write!(f, "{name:?} is not a usable environment variable name"),
            RunnerError::Io { what, source } => write!(f, "I/O error while {what}: {source}"),
        }
    }
}

impl std::error::Error for RunnerError {}

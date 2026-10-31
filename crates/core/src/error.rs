use std::fmt;

/// A failure with a stable code, a plain message, and an optional next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
    pub next: Option<String>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Error {
        Error { code, message: message.into(), next: None }
    }

    pub fn with_next(mut self, next: impl Into<String>) -> Error {
        self.next = Some(next.into());
        self
    }

    pub fn io(what: &str, e: std::io::Error) -> Error {
        let error = Error::new("IO_ERROR", format!("{what}: {e}"));
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            // 05 keeps its state in .git; an agent sandbox (Codex's workspace-write) makes that read-only.
            return error.with_next("if an agent sandbox is running this, allow `use05` to run outside it, or run the command yourself");
        }
        error
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

//! Running the command: no shell, a scrubbed environment, bounded output, a time limit.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use use05_receipt::{Environment, Outcome, Status, Stream};

use crate::error::RunnerError;

/// How much of each output stream is kept and digested.
pub(crate) const RETAIN_LIMIT: usize = 1024 * 1024;

/// How much of the end of each stream is handed back for display. It is never signed or stored.
const TAIL_LIMIT: usize = 4096;

/// The last bytes of each stream, for showing a person why a check failed.
pub(crate) struct Tails {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The variables the command sees: a small fixed set, plus whatever the caller passed through by
/// name. Everything else, including secrets, is dropped. Passed variables override the defaults.
fn scrubbed_env(scratch: &Path, pass: &[(String, String)]) -> BTreeMap<String, String> {
    let path = std::env::var("PATH").unwrap_or_else(|_| FALLBACK_PATH.to_string());
    let mut vars = BTreeMap::new();
    vars.insert("HOME".to_string(), scratch.join("home").display().to_string());
    vars.insert("LANG".to_string(), "C.UTF-8".to_string());
    vars.insert("PATH".to_string(), path);
    vars.insert("TMPDIR".to_string(), scratch.join("tmp").display().to_string());
    for (name, value) in pass {
        vars.insert(name.clone(), value.clone());
    }
    vars
}

/// Hash of the environment with the per-run scratch paths replaced, so the same setup gives the
/// same fingerprint every time. Values are hashed, never stored.
fn fingerprint(vars: &BTreeMap<String, String>, scratch: &Path) -> String {
    let scratch_values = [scratch.join("home").display().to_string(), scratch.join("tmp").display().to_string()];
    let mut hasher = Sha256::new();
    for (name, value) in vars {
        let value = if scratch_values.contains(value) { "<scratch>" } else { value.as_str() };
        hasher.update(format!("{name}={value}\n").as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn drain(mut source: impl Read + Send + 'static) -> JoinHandle<(Stream, Vec<u8>)> {
    thread::spawn(move || {
        let mut hasher = Sha256::new();
        let (mut total, mut retained) = (0u64, 0usize);
        let mut buf = [0u8; 16 * 1024];
        let mut tail: Vec<u8> = Vec::new();
        loop {
            let n = match source.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            total += n as u64;
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 2 * TAIL_LIMIT {
                tail.drain(..tail.len() - TAIL_LIMIT);
            }
            if retained < RETAIN_LIMIT {
                let take = n.min(RETAIN_LIMIT - retained);
                hasher.update(&buf[..take]);
                retained += take;
            }
            // Past the limit we keep reading so the command never blocks on a full pipe.
        }
        if tail.len() > TAIL_LIMIT {
            tail.drain(..tail.len() - TAIL_LIMIT);
        }
        let stream = Stream {
            total_bytes: total,
            retained_bytes: retained as u64,
            truncated: total > retained as u64,
            sha256: hex::encode(hasher.finalize()),
        };
        (stream, tail)
    })
}

#[allow(unsafe_code)]
pub(crate) fn kill_group(pgid: u32) {
    // SAFETY: killpg only sends a signal. The command was started as the leader of its own
    // process group, so this reaches it and its descendants. An already-empty group is ignored.
    unsafe {
        libc::killpg(pgid as libc::pid_t, libc::SIGKILL);
    }
}

/// The command line that runs `argv` as `user` with exactly `vars`: `sudo` that never asks for a
/// password, then `env -i`, so nothing of this process's environment (the signing key above all)
/// reaches the command.
fn as_user(user: &str, vars: &BTreeMap<String, String>, argv: &[String]) -> Vec<String> {
    let mut line: Vec<String> = ["sudo", "-n", "-u", user, "--", "env", "-i"].iter().map(|s| s.to_string()).collect();
    line.extend(vars.iter().map(|(k, v)| format!("{k}={v}")));
    line.extend(argv.iter().cloned());
    line
}

/// A helper command (`id`, `sudo`) with nothing of this process's environment but PATH: the
/// runner key and the push token never reach sudo, whatever sudoers keeps.
fn quiet(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.env("PATH", std::env::var("PATH").unwrap_or_else(|_| FALLBACK_PATH.to_string()));
    cmd
}

/// Whether the check user can find and reach `program` from `cwd` with the command's own
/// variables: a toolchain in this user's home (0750 on recent systems) is not theirs to run.
fn reachable_for(user: &str, vars: &BTreeMap<String, String>, program: &str, cwd: &Path) -> Result<(), RunnerError> {
    let probe = as_user(user, vars, &["sh".into(), "-c".into(), "command -v \"$1\" >/dev/null".into(), "sh".into(), program.to_string()]);
    let args: Vec<&str> = probe[1..].iter().map(String::as_str).collect();
    match quiet(&probe[0], &args).current_dir(cwd).status() {
        Ok(s) if s.success() => Ok(()),
        _ => Err(RunnerError::Spawn {
            program: program.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, format!("the user {user} the checks run as cannot find or reach it")),
        }),
    }
}

fn uid_of(user: Option<&str>) -> Option<u32> {
    let mut cmd = quiet("id", &["-u"]);
    cmd.args(user).stdout(Stdio::piped());
    let out = cmd.output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().parse().ok()).flatten()
}

/// Whether the command can run as `user` and that keeps the key out of its reach: the user
/// exists, is neither root nor the user this runs as, and `sudo` runs commands as it without
/// asking for a password. Checked before anything runs, so there is never a fallback.
pub(crate) fn check_user_ready(user: &str) -> Result<(), RunnerError> {
    let no = |reason: String| RunnerError::CheckUserUnavailable { user: user.to_string(), reason };
    let named = !user.is_empty() && !user.starts_with('-') && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !named {
        return Err(no("that is not a user name".into()));
    }
    let theirs = uid_of(Some(user)).ok_or_else(|| no("there is no such user on this machine".into()))?;
    if theirs == 0 {
        return Err(no("that is root, which can read everything".into()));
    }
    if Some(theirs) == uid_of(None) {
        return Err(no("that is the user 05 runs as, so the checks could read the key".into()));
    }
    let mut sudo = quiet("sudo", &["-n", "-u", user, "--", "true"]);
    match sudo.stderr(Stdio::piped()).output() {
        Err(e) => Err(no(format!("sudo could not be started ({e})"))),
        Ok(out) if !out.status.success() => {
            let said = String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or_default().trim().to_string();
            Err(no(format!("sudo cannot run commands as that user without a password ({said})")))
        }
        Ok(_) => Ok(()),
    }
}

/// The directories a check writes (its tree, home and temp), handed to the check user for the
/// run. The scratch directory above them stays this user's: the check user may pass through it,
/// not list it.
struct Handover<'a> {
    user: &'a str,
    owner: (u32, u32),
    dirs: Vec<std::path::PathBuf>,
}

impl<'a> Handover<'a> {
    fn new(user: &'a str, scratch: &Path, dirs: Vec<std::path::PathBuf>) -> Result<Handover<'a>, RunnerError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::metadata(scratch).map_err(RunnerError::io("reading the scratch directory"))?;
        std::fs::set_permissions(scratch, std::fs::Permissions::from_mode(0o711)).map_err(RunnerError::io("opening the scratch directory to the check user"))?;
        let handed = Handover { user, owner: (meta.uid(), meta.gid()), dirs };
        let mut chown = quiet("sudo", &["-n", "chown", "-R", user, "--"]);
        chown.args(&handed.dirs);
        match chown.status() {
            Ok(s) if s.success() => Ok(handed),
            _ => Err(RunnerError::CheckUserUnavailable { user: user.to_string(), reason: "sudo could not give it the directory the check runs in".into() }),
        }
    }

    /// Everything the check user still has running, which could hold the output pipes open or
    /// outlive the proof. Only ever another user than this one, and never root (`check_user_ready`).
    fn stop_its_processes(&self) {
        let _ = quiet("sudo", &["-n", "-u", self.user, "--", "kill", "-KILL", "-1"]).status();
    }
}

impl Drop for Handover<'_> {
    /// Take the directories back, so the scratch directory can be removed. Nothing of the check
    /// user's is still running by then, and `chown -R` follows no symbolic link.
    fn drop(&mut self) {
        self.stop_its_processes();
        let owner = format!("{}:{}", self.owner.0, self.owner.1);
        let _ = quiet("sudo", &["-n", "chown", "-R", &owner, "--"]).args(&self.dirs).status();
    }
}

/// The result of a command that could not be run because the folder it was to run in is not in
/// the tree: a failure with no output, and the reason (for showing, never signed) as its tail.
pub(crate) fn not_run(scratch: &Path, reason: &str) -> (Outcome, Environment, Tails) {
    let vars = scrubbed_env(scratch, &[]);
    let nothing = || Stream { total_bytes: 0, retained_bytes: 0, truncated: false, sha256: hex::encode(Sha256::digest([])) };
    let outcome = Outcome { status: Status::Failed, exit_code: None, signal: None, duration_ms: 0, stdout: nothing(), stderr: nothing() };
    let environment = Environment { fingerprint: fingerprint(&vars, scratch), names: vars.keys().cloned().collect() };
    (outcome, environment, Tails { stdout: Vec::new(), stderr: format!("{reason}\n").into_bytes() })
}

/// Runs `argv` in `dir`, a folder of the exported tree `cwd`; `cwd` as a whole is what a check
/// user is handed.
pub(crate) fn run(
    argv: &[String],
    cwd: &Path,
    dir: &Path,
    scratch: &Path,
    timeout: Duration,
    pass_env: &[(String, String)],
    check_user: Option<&str>,
) -> Result<(Outcome, Environment, Tails), RunnerError> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    if argv.is_empty() {
        return Err(RunnerError::NoCommand);
    }
    let vars = scrubbed_env(scratch, pass_env);
    for dir in ["home", "tmp"] {
        std::fs::create_dir_all(scratch.join(dir)).map_err(RunnerError::io("creating the scratch directory"))?;
    }
    let handover = match check_user {
        Some(user) => Some(Handover::new(user, scratch, vec![cwd.to_path_buf(), scratch.join("home"), scratch.join("tmp")])?),
        None => None,
    };
    // Not found is not started, as without a check user: no failure gets signed for it.
    if let Some(user) = check_user {
        reachable_for(user, &vars, &argv[0], dir)?;
    }
    let line = match check_user {
        Some(user) => as_user(user, &vars, argv),
        None => argv.to_vec(),
    };
    let (program, args) = line.split_first().expect("not empty");

    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .current_dir(dir)
        .env_clear()
        .envs(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|source| RunnerError::Spawn { program: program.clone(), source })?;

    let out = drain(child.stdout.take().expect("piped"));
    let err = drain(child.stderr.take().expect("piped"));

    let pgid = child.id();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().map_err(RunnerError::io("waiting for the command"))? {
            Some(status) => break status,
            None if started.elapsed() >= timeout => {
                timed_out = true;
                if let Some(h) = &handover {
                    h.stop_its_processes();
                }
                kill_group(pgid);
                break child.wait().map_err(RunnerError::io("waiting for the command"))?;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    // Whatever the command left running would keep the pipes open and outlive the proof.
    // The group id cannot have been reused in the microseconds since the leader was reaped.
    // The check user's processes are not this user's to signal, nor necessarily in the group.
    if let Some(h) = &handover {
        h.stop_its_processes();
    }
    kill_group(pgid);

    let (stdout, stdout_tail) = out.join().expect("reader thread");
    let (stderr, stderr_tail) = err.join().expect("reader thread");

    let exit_code = if timed_out { None } else { status.code() };
    let signal = if timed_out { Some(libc::SIGKILL) } else { status.signal() };
    let result = if timed_out {
        Status::TimedOut
    } else if exit_code == Some(0) {
        Status::Passed
    } else {
        Status::Failed
    };

    let outcome = Outcome {
        status: result,
        exit_code,
        signal,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
    };
    let environment = Environment {
        fingerprint: fingerprint(&vars, scratch),
        names: vars.keys().cloned().collect(),
    };
    Ok((outcome, environment, Tails { stdout: stdout_tail, stderr: stderr_tail }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_user_runs_the_command_through_sudo_and_env_with_only_the_scrubbed_variables() {
        let vars: BTreeMap<String, String> = [("HOME", "/s/home"), ("PATH", "/usr/bin:/bin")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let argv = vec!["cargo".to_string(), "test".to_string()];
        assert_eq!(as_user("use05-check", &vars, &argv), ["sudo", "-n", "-u", "use05-check", "--", "env", "-i", "HOME=/s/home", "PATH=/usr/bin:/bin", "cargo", "test"]);
    }

    #[test]
    fn helper_commands_get_nothing_of_this_process_environment_but_path() {
        // HOME is always set here, and the runner key would be in CI: neither may reach sudo.
        let out = quiet("env", &[]).stdout(Stdio::piped()).output().unwrap();
        let names: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string())).collect();
        assert_eq!(names, ["PATH"]);
    }
}

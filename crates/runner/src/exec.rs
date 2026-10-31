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
fn kill_group(pgid: u32) {
    // SAFETY: killpg only sends a signal. The command was started as the leader of its own
    // process group, so this reaches it and its descendants. An already-empty group is ignored.
    unsafe {
        libc::killpg(pgid as libc::pid_t, libc::SIGKILL);
    }
}

pub(crate) fn run(
    argv: &[String],
    cwd: &Path,
    scratch: &Path,
    timeout: Duration,
    pass_env: &[(String, String)],
) -> Result<(Outcome, Environment, Tails), RunnerError> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    let (program, args) = argv.split_first().ok_or(RunnerError::NoCommand)?;
    let vars = scrubbed_env(scratch, pass_env);
    for dir in ["home", "tmp"] {
        std::fs::create_dir_all(scratch.join(dir)).map_err(RunnerError::io("creating the scratch directory"))?;
    }

    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
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
                kill_group(pgid);
                break child.wait().map_err(RunnerError::io("waiting for the command"))?;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    // Whatever the command left running would keep the pipes open and outlive the proof.
    // The group id cannot have been reused in the microseconds since the leader was reaped.
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

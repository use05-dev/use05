//! End-to-end tests of the `use05` binary against throwaway git repositories.
//!
//! Human output is snapshot-tested (tests/snapshots). Run with UPDATE_SNAPSHOTS=1 to rewrite them
//! and review the diff: a change in wording or layout should always be a visible diff.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_use05");

struct Sandbox {
    dir: TempDir,
    /// Stands in for the user's config directory (keys, organisation policy), outside the repository.
    home: TempDir,
}

/// A folder holding only `use05`, for PATH: the build folder beside it also holds other `use05-*`
/// programs (the helper, the console), which would show up as extension commands.
fn bin_dir() -> &'static str {
    static DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        std::os::unix::fs::symlink(BIN, dir.join("use05")).unwrap();
        dir.display().to_string()
    })
}

impl Sandbox {
    fn new() -> Sandbox {
        let sandbox = Sandbox { dir: tempfile::tempdir().unwrap(), home: tempfile::tempdir().unwrap() };
        sandbox.git(&["init", "-q", "-b", "main"]);
        sandbox.git(&["config", "core.autocrlf", "false"]);
        sandbox.write("main.rs", "fn main() {}\n");
        sandbox.write("test.sh", "#!/bin/sh\necho all good\n");
        fs::set_permissions(sandbox.path("test.sh"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        sandbox.git(&["add", "-A"]);
        sandbox
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, body: &str) {
        fs::write(self.path(name), body).unwrap();
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.dir.path())
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.current_dir(self.dir.path())
            .args(args)
            .env_clear()
            .env("PATH", format!("{}:{}", bin_dir(), std::env::var("PATH").unwrap()))
            .env("HOME", self.home.path())
            .env("USE05_HOME", self.home.path())
            .env("LANG", "C.UTF-8")
            .env("COLUMNS", "100")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com");
        cmd
    }

    /// Run `use05` inside the sandbox with a clean environment.
    fn run(&self, args: &[&str]) -> Output {
        self.command(args).stdin(Stdio::null()).output().unwrap()
    }

    /// Run with extra environment variables, as an agent's process would have.
    fn run_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.command(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null()).output().unwrap()
    }

    /// Run with text on stdin (a passphrase, a hook payload).
    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut child = self.command(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    /// The receipts stored on branches: `(branch, path in the branch)`.
    fn stored_receipts(&self) -> Vec<(String, String)> {
        let branches = self.git(&["for-each-ref", "--format=%(refname:short)", "refs/heads/05-receipts/"]);
        let mut found = Vec::new();
        for branch in branches.lines() {
            for path in self.git(&["ls-tree", "-r", "--name-only", branch]).lines() {
                found.push((branch.to_string(), path.to_string()));
            }
        }
        found
    }

    fn key(&self, name: &str) {
        let out = self.run(&["key", "new", name]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    }
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exited normally")
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(out)))
}

// ---------------------------------------------------------------- snapshots

/// Replace everything that legitimately varies between runs with a fixed placeholder.
fn normalise(sandbox: &Sandbox, raw: &str) -> String {
    let raw = match fs::canonicalize(sandbox.dir.path()) {
        Ok(real) => raw.replace(&real.display().to_string(), "<DIR>"),
        Err(_) => raw.to_string(),
    };
    let raw = raw.replace(&sandbox.dir.path().display().to_string(), "<DIR>");
    let repo_name = sandbox.dir.path().file_name().unwrap().to_string_lossy().to_string();
    let raw = raw.replace(&repo_name, "<REPO>");
    let mut out = String::new();
    for line in raw.lines() {
        let indent = line.len() - line.trim_start().len();
        out.push_str(&line[..indent]);
        let tokens: Vec<String> = line[indent..].split(' ').map(mask).collect();
        out.push_str(&tokens.join(" "));
        out.push('\n');
    }
    // The installed git version varies by machine.
    match out.find("✓ git ") {
        Some(at) => {
            let start = at + "✓ git ".len();
            let len = out[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').count();
            out.replace_range(start..start + len, "<VERSION>");
            out
        }
        None => out,
    }
}

fn is_duration(token: &str) -> bool {
    let t = token.trim_end_matches(['.', ',']);
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if let Some(n) = t.strip_suffix("ms") {
        return digits(n);
    }
    if let Some(n) = t.strip_suffix('s') {
        if let Some((minutes, seconds)) = n.split_once('m') {
            return digits(minutes) && digits(seconds);
        }
        return n.split_once('.').is_some_and(|(whole, tenth)| digits(whole) && digits(tenth)) || digits(n);
    }
    false
}

fn is_timestamp(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() == 20 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[19] == b'Z'
}

/// Mask runs of lowercase hex of the lengths we print: 40 (tree id), 16 (key id, receipt id),
/// 12 (short tree id). Works on characters, so glyphs like the check mark are untouched.
fn mask_hex(token: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        out.push_str(match run.len() {
            40 => "<TREE>",
            16 => "<ID>",
            8 => "<TASK>",
            12 => "<TREE12>",
            _ => run.as_str(),
        });
        run.clear();
    };
    for c in token.chars() {
        if c.is_ascii_digit() || ('a'..='f').contains(&c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn mask(token: &str) -> String {
    if is_timestamp(token) {
        "<TIMESTAMP>".to_string()
    } else if is_duration(token) {
        "<TIME>".to_string()
    } else {
        mask_hex(token)
    }
}

fn snapshot(name: &str, sandbox: &Sandbox, out: &Output) {
    let actual = normalise(sandbox, &text(out));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots").join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing snapshot {name}; run with UPDATE_SNAPSHOTS=1"));
    assert_eq!(actual, expected, "snapshot {name} changed; if intended, rerun with UPDATE_SNAPSHOTS=1 and review the diff");
}

// ---------------------------------------------------------------- behaviour

#[test]
fn prove_then_verify_round_trip_with_a_tree_check() {
    let s = Sandbox::new();
    s.key("me.key");
    let prove = s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "./test.sh"]);
    assert_eq!(code(&prove), 0, "{}", text(&prove));
    snapshot("prove_pass", &s, &prove);

    let verify = s.run(&["verify", "r.json", "--key", "me.key.pub"]);
    assert_eq!(code(&verify), 0, "{}", text(&verify));
    snapshot("verify_valid", &s, &verify);

    let checked = s.run(&["verify", "r.json", "--key", "me.key.pub", "--tree", "index"]);
    assert_eq!(code(&checked), 0, "{}", text(&checked));
    snapshot("verify_valid_tree", &s, &checked);
}

#[test]
fn a_receipt_stored_on_a_branch_can_be_verified_by_its_name() {
    let s = Sandbox::new();
    s.key("me.key");
    let prove = s.run(&["prove", "--key", "me.key", "--json", "--", "./test.sh"]);
    let branch = json(&prove)["details"]["stored_on"].as_str().unwrap().to_string();
    assert!(branch.starts_with("05-receipts/"));
    let stored = s.stored_receipts();
    assert_eq!(stored.len(), 1);
    let name = format!("{}:{}", stored[0].0, stored[0].1);
    let verify = s.run(&["verify", &name, "--key", "me.key.pub", "--tree", "index"]);
    assert_eq!(code(&verify), 0, "{}", text(&verify));
}

#[test]
fn a_changed_tree_makes_the_receipt_stale_not_valid() {
    let s = Sandbox::new();
    s.key("me.key");
    s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "./test.sh"]);
    s.write("main.rs", "fn main() { println!(\"changed\"); }\n");
    s.git(&["add", "-A"]);
    let verify = s.run(&["verify", "r.json", "--key", "me.key.pub", "--tree", "index"]);
    assert_eq!(code(&verify), 5, "{}", text(&verify));
    assert_eq!(json(&s.run(&["verify", "r.json", "--key", "me.key.pub", "--tree", "index", "--json"]))["outcome"], "stale");
    snapshot("verify_stale", &s, &verify);
}

#[test]
fn a_failing_command_gets_a_receipt_and_verifying_it_does_not_exit_zero() {
    let s = Sandbox::new();
    s.key("me.key");
    let prove = s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "sh", "-c", "echo broken >&2; exit 3"]);
    assert_eq!(code(&prove), 2, "a failed check is a denial");
    snapshot("prove_fail", &s, &prove);

    // The receipt itself is genuine, but `verify && merge` must not let a failed check through.
    let verify = s.run(&["verify", "r.json", "--key", "me.key.pub"]);
    assert_eq!(code(&verify), 2, "{}", text(&verify));
    let v = json(&s.run(&["verify", "r.json", "--key", "me.key.pub", "--json"]));
    assert_eq!(v["code"], "CHECK_DID_NOT_PASS");
    assert_eq!(v["details"]["signature_valid"], true);
    assert_eq!(v["details"]["result"]["exit_code"], 3);
    snapshot("verify_check_failed", &s, &verify);
}

#[test]
fn a_timed_out_command_is_recorded_and_denied() {
    let s = Sandbox::new();
    s.key("me.key");
    let prove = s.run(&["prove", "--key", "me.key", "--timeout", "1", "--json", "--", "sleep", "30"]);
    assert_eq!(code(&prove), 2);
    assert_eq!(json(&prove)["outcome"], "timed_out");
}

#[test]
fn editing_a_receipt_makes_it_invalid_and_garbage_makes_it_malformed() {
    let s = Sandbox::new();
    s.key("me.key");
    s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "./test.sh"]);

    let original = fs::read_to_string(s.path("r.json")).unwrap();
    let payload_start = original.find("\"payload\": \"").unwrap() + "\"payload\": \"".len();
    let mut edited = original.clone().into_bytes();
    edited[payload_start + 20] = if edited[payload_start + 20] == b'A' { b'B' } else { b'A' };
    fs::write(s.path("edited.json"), &edited).unwrap();
    let invalid = s.run(&["verify", "edited.json", "--key", "me.key.pub"]);
    assert_eq!(code(&invalid), 2, "{}", text(&invalid));
    snapshot("verify_invalid", &s, &invalid);

    fs::write(s.path("cut.json"), &original.as_bytes()[..original.len() / 2]).unwrap();
    let malformed = s.run(&["verify", "cut.json", "--key", "me.key.pub"]);
    assert_eq!(code(&malformed), 6, "{}", text(&malformed));
    snapshot("verify_malformed", &s, &malformed);

    s.key("other.key");
    let wrong_key = s.run(&["verify", "r.json", "--key", "other.key.pub"]);
    assert_eq!(code(&wrong_key), 2);
}

#[test]
fn verification_needs_the_public_key_and_says_so_when_given_the_secret_one() {
    let s = Sandbox::new();
    s.key("me.key");
    s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "./test.sh"]);
    let out = s.run(&["verify", "r.json", "--key", "me.key"]);
    assert_eq!(code(&out), 6);
    snapshot("verify_secret_key_error", &s, &out);
}

#[test]
fn a_secret_key_readable_by_others_is_refused() {
    let s = Sandbox::new();
    s.key("me.key");
    fs::set_permissions(s.path("me.key"), std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let out = s.run(&["prove", "--key", "me.key", "--", "true"]);
    assert_eq!(code(&out), 6);
    assert!(text(&out).contains("chmod 600"));
}

#[test]
fn key_new_never_overwrites() {
    let s = Sandbox::new();
    s.key("me.key");
    let again = s.run(&["key", "new", "me.key"]);
    assert_eq!(code(&again), 4);
    assert!(text(&again).contains("refusing to overwrite"));
}

#[test]
fn key_new_output_is_stable() {
    let s = Sandbox::new();
    let out = s.run(&["key", "new", "me.key"]);
    snapshot("key_new", &s, &out);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(s.path("me.key")).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn usage_mistakes_exit_six_and_help_exits_zero() {
    let s = Sandbox::new();
    assert_eq!(code(&s.run(&["prove", "--key", "k"])), 6, "missing command");
    assert_eq!(code(&s.run(&["prove", "--nonsense"])), 6);
    assert_eq!(code(&s.run(&["no-such-command"])), 6);
    assert_eq!(code(&s.run(&["--help"])), 0);
    assert_eq!(code(&s.run(&["prove", "--help"])), 0);
    assert_eq!(code(&s.run(&[])), 0, "the bare command shows status and never blocks without a terminal");
}

#[test]
fn json_output_has_one_stable_shape() {
    let s = Sandbox::new();
    s.key("me.key");
    for args in [
        vec!["prove", "--key", "me.key", "--json", "--", "true"],
        vec!["prove", "--key", "me.key", "--json", "--", "false"],
        vec!["verify", "nope.json", "--key", "me.key.pub", "--json"],
        vec!["prove", "--key", "missing.key", "--json", "--", "true"],
    ] {
        let value = json(&s.run(&args));
        for field in ["v", "command", "ok", "outcome", "code", "message", "notes", "next", "details"] {
            assert!(value.get(field).is_some(), "{args:?} lacks {field}: {value}");
        }
        assert_eq!(value["v"], 1);
    }
}

#[test]
fn the_staged_tree_is_proven_by_default_and_a_revision_on_request() {
    let s = Sandbox::new();
    s.key("me.key");
    s.git(&["commit", "-q", "-m", "first"]);
    s.write("main.rs", "fn main() { /* staged edit */ }\n");
    s.git(&["add", "-A"]);

    let staged = json(&s.run(&["prove", "--key", "me.key", "--json", "--", "true"]));
    let head = json(&s.run(&["prove", "--key", "me.key", "--tree", "HEAD", "--json", "--", "true"]));
    assert_ne!(staged["details"]["checks"][0]["tree"]["oid"], head["details"]["checks"][0]["tree"]["oid"]);
    assert_eq!(head["details"]["checks"][0]["tree"]["oid"].as_str().unwrap(), s.git(&["rev-parse", "HEAD^{tree}"]));
}

#[test]
fn verification_works_with_no_network_and_no_repository() {
    let s = Sandbox::new();
    s.key("me.key");
    s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "./test.sh"]);
    let elsewhere = tempfile::tempdir().unwrap();
    for name in ["r.json", "me.key.pub"] {
        fs::copy(s.path(name), elsewhere.path().join(name)).unwrap();
    }
    // No git repository here, and every proxy points at a closed port.
    let out = Command::new(BIN)
        .current_dir(elsewhere.path())
        .args(["verify", "r.json", "--key", "me.key.pub"])
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", text(&out));
}

#[test]
fn receipts_survive_a_push_and_fetch_through_a_bare_remote() {
    let s = Sandbox::new();
    s.key("me.key");
    s.git(&["commit", "-q", "-m", "work"]);
    s.run(&["prove", "--key", "me.key", "--tree", "HEAD", "--", "./test.sh"]);
    let (branch, path) = s.stored_receipts().remove(0);

    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    // Receipts are ordinary branches, so any host accepts them and an ordinary push carries them.
    s.git(&["push", "-q", "origin", "HEAD:refs/heads/main", &format!("{branch}:{branch}")]);

    let clone = tempfile::tempdir().unwrap();
    let clone_path = clone.path().display().to_string();
    assert!(Command::new("git").args(["clone", "-q", &remote_path, &clone_path]).status().unwrap().success());
    let remote_name = format!("origin/{branch}");
    fs::copy(s.path("me.key.pub"), clone.path().join("me.key.pub")).unwrap();
    let out = Command::new(BIN)
        .current_dir(clone.path())
        .args(["verify", &format!("{remote_name}:{path}"), "--key", "me.key.pub", "--tree", "HEAD"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", text(&out));
}

#[test]
fn a_failure_shows_the_end_of_the_output_to_a_person_but_never_in_json_or_the_receipt() {
    let s = Sandbox::new();
    s.key("me.key");
    // The shell computes "reason-42", so that text is never in the command line itself.
    let script = "echo reason-$((40+2)) >&2; exit 1";
    assert!(!script.contains("reason-42"));

    let human = s.run(&["prove", "--key", "me.key", "--out", "r.json", "--", "sh", "-c", script]);
    assert_eq!(code(&human), 2);
    assert!(text(&human).contains("reason-42"), "a person is shown why it failed:\n{}", text(&human));
    assert!(text(&human).contains("not in the receipt"));

    // Not in the receipt, even decoded: the payload is base64, so check the decoded statement too.
    let receipt = fs::read(s.path("r.json")).unwrap();
    assert!(!receipt.windows(9).any(|w| w == b"reason-42"));
    let envelope: Value = serde_json::from_slice(&receipt).unwrap();
    use_base64_decode(envelope["payload"].as_str().unwrap(), |decoded| {
        assert!(!decoded.windows(9).any(|w| w == b"reason-42"), "output must never enter the signed statement");
    });

    let machine = s.run(&["prove", "--key", "me.key", "--json", "--", "sh", "-c", script]);
    assert!(!text(&machine).contains("reason-42"), "--json carries no command output");
}

/// Standard base64 decode without another dependency.
fn use_base64_decode(input: &str, check: impl FnOnce(&[u8])) {
    let table = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in input.bytes().filter_map(table) {
        buf = (buf << 6) | c as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    check(&out);
}

#[test]
fn output_from_the_command_cannot_inject_terminal_escapes() {
    let s = Sandbox::new();
    s.key("me.key");
    let out = s.run(&["prove", "--key", "me.key", "--", "sh", "-c", r"printf 'ok\n\033[2J\033]0;owned\007\rlast\n' >&2; exit 1"]);
    assert!(!out.stdout.contains(&0x1b), "no escape byte may reach the terminal");
    assert!(!out.stdout.contains(&0x07));
    assert!(text(&out).contains("last"));
}

#[test]
fn env_passes_variables_through_by_name_or_value() {
    let s = Sandbox::new();
    s.key("me.key");
    let check = |args: &[&str], env: Option<(&str, &str)>| {
        let mut cmd = s.command(args);
        cmd.stdin(Stdio::null());
        if let Some((k, v)) = env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };
    let test_flag = ["sh", "-c", r#"test "$MY_FLAG" = on"#];
    let mut base = vec!["prove", "--key", "me.key", "--no-store"];

    let none = check(&[&base[..], &["--"], &test_flag].concat(), Some(("MY_FLAG", "on")));
    assert_eq!(code(&none), 2, "not passed through, so not visible");

    let by_name = check(&[&base[..], &["--env", "MY_FLAG", "--"], &test_flag].concat(), Some(("MY_FLAG", "on")));
    assert_eq!(code(&by_name), 0, "{}", text(&by_name));

    let by_value = check(&[&base[..], &["--env", "MY_FLAG=on", "--"], &test_flag].concat(), None);
    assert_eq!(code(&by_value), 0, "{}", text(&by_value));

    base.extend(["--env", "NOT_SET_ANYWHERE", "--", "true"]);
    let unset = check(&base, None);
    assert_eq!(code(&unset), 6);
    assert!(text(&unset).contains("not set in your environment"));
}

// ---------------------------------------------------------------- the whole tool

impl Sandbox {
    fn commit_all(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
    }

    /// Files that exist, with content hashes, outside `.git/objects` and `.git/refs` noise.
    fn snapshot_files(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                if rel == ".git/objects" || rel == ".git/index" || rel.starts_with(".git/logs") || rel == ".git/refs" || rel == ".git/COMMIT_EDITMSG" || rel == ".git/05" {
                    continue;
                }
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push((rel, String::from_utf8_lossy(&fs::read(&path).unwrap()).into_owned()));
                }
            }
        }
        walk(self.dir.path(), self.dir.path(), &mut out);
        out.sort();
        out
    }

    fn approver(&self) {
        let out = self.run_with_stdin(&["key", "new", "--approver", "--passphrase-stdin"], "correct horse\n");
        assert_eq!(code(&out), 0, "{}", text(&out));
    }

    /// Initialised with Claude Code and Codex present, so their hooks are installed.
    fn with_agent_hooks() -> Sandbox {
        let s = Sandbox::new();
        fs::create_dir_all(s.path(".claude")).unwrap();
        fs::create_dir_all(s.path(".codex")).unwrap();
        s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
        s.commit_all("first");
        let init = s.run(&["init"]);
        assert_eq!(code(&init), 0, "{}", text(&init));
        s.commit_all("add 05");
        s
    }

    /// A repository that has been through `init` and a first commit.
    fn initialised() -> Sandbox {
        let s = Sandbox::new();
        s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
        s.commit_all("first");
        let init = s.run(&["init"]);
        assert_eq!(code(&init), 0, "{}", text(&init));
        s.commit_all("add 05");
        s
    }
}

#[test]
fn init_says_what_it_did_and_uninstall_puts_every_file_back() {
    let s = Sandbox::new();
    s.write("AGENTS.md", "# Our agents\n\nBe kind.\n");
    s.commit_all("first");
    let before = s.snapshot_files();

    let init = s.run(&["init"]);
    assert_eq!(code(&init), 0, "{}", text(&init));
    assert!(s.path(".05/policy.toml").exists());
    assert!(s.path(".git/hooks/pre-push").exists());
    assert!(fs::read_to_string(s.path("AGENTS.md")).unwrap().contains("Be kind."), "existing content is kept");
    assert!(text(&init).contains("not covered"), "init must say what it cannot cover");
    assert!(s.snapshot_files() != before);

    // Running it again changes nothing.
    let again = s.snapshot_files();
    assert_eq!(code(&s.run(&["init"])), 0);
    assert_eq!(s.snapshot_files(), again, "init is idempotent");

    let removed = s.run(&["uninstall"]);
    assert_eq!(code(&removed), 0, "{}", text(&removed));
    // The policy file is a decision the team may have committed: uninstall says so and leaves it.
    let mut after = s.snapshot_files();
    assert!(after.iter().any(|(p, _)| p == ".05/policy.toml"));
    after.retain(|(p, _)| p != ".05/policy.toml");
    assert_eq!(after, before, "uninstall restores everything else init changed");
    assert!(text(&removed).contains("policy"), "and it says what it left");
}

#[test]
fn init_never_overwrites_another_tools_pre_push_hook() {
    let s = Sandbox::new();
    s.commit_all("first");
    fs::create_dir_all(s.path(".git/hooks")).unwrap();
    s.write(".git/hooks/pre-push", "#!/bin/sh\necho theirs\n");
    let out = s.run(&["init"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap(), "#!/bin/sh\necho theirs\n");
    assert!(text(&out).contains("pre-push"), "and it says the push is therefore not covered:\n{}", text(&out));
    s.run(&["uninstall"]);
    assert_eq!(fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap(), "#!/bin/sh\necho theirs\n");
}

#[test]
fn bare_use05_never_waits_for_a_terminal() {
    let s = Sandbox::initialised();
    let status = s.run(&[]);
    assert_eq!(code(&status), 0);
    assert!(text(&status).contains("Next:"), "{}", text(&status));
    snapshot("status", &s, &status);

    let elsewhere = tempfile::tempdir().unwrap();
    let out = Command::new(BIN).current_dir(elsewhere.path()).env_clear().env("PATH", "/usr/bin:/bin").stdin(Stdio::null()).output().unwrap();
    assert_eq!(code(&out), 0, "outside a repository it explains instead of failing:\n{}", text(&out));
    assert!(text(&out).contains("use05 init"));
}

#[test]
fn a_protected_change_waits_for_a_person_and_their_passphrase_lets_it_through() {
    let s = Sandbox::initialised();
    s.run(&["start", "Tighten the policy", "--scope", ".05/**"]);
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.git(&["add", "-A"]);

    let proved = s.run(&["prove"]);
    assert_eq!(code(&proved), 0, "{}", text(&proved));
    let blocked = s.run(&["brief"]);
    assert_eq!(code(&blocked), 3, "{}", text(&blocked));
    assert!(text(&blocked).contains("APPROVAL REQUIRED"));
    snapshot("brief_blocked", &s, &blocked);

    // An agent has no terminal and no passphrase: it cannot approve.
    s.approver();
    let refused = s.run(&["approve", "--reason", "looks fine"]);
    assert_ne!(code(&refused), 0, "approving without a passphrase must fail:\n{}", text(&refused));
    assert_eq!(code(&s.run(&["brief"])), 3, "and nothing changed");

    let wrong = s.run_with_stdin(&["approve", "--reason", "looks fine", "--passphrase-stdin"], "wrong horse\n");
    assert_ne!(code(&wrong), 0);
    assert_eq!(code(&s.run(&["brief"])), 3);

    let approved = s.run_with_stdin(&["approve", "--reason", "reviewed the policy edit", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    let allowed = s.run(&["brief"]);
    assert_eq!(code(&allowed), 0, "{}", text(&allowed));
    snapshot("brief_allowed", &s, &allowed);

    // The approval is bound to this exact content: change a file and it no longer counts.
    s.write("main.rs", "fn main() { println!(\"later\"); }\n");
    s.git(&["add", "-A"]);
    assert_ne!(code(&s.run(&["brief"])), 0, "an approval does not carry over to different content");
}

#[test]
fn break_glass_lets_a_change_through_and_says_so_in_the_brief() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.git(&["add", "-A"]);
    s.approver();
    assert_ne!(code(&s.run(&["brief"])), 0);
    let out = s.run_with_stdin(&["bypass", "--reason", "production is down", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    let brief = s.run(&["brief"]);
    assert_eq!(code(&brief), 0, "{}", text(&brief));
    assert!(text(&brief).contains("break-glass") && text(&brief).contains("production is down"), "{}", text(&brief));
}

// ---------------------------------------------------------------- path rules (D79)

/// A repository whose committed policy carries these `[protect]` settings, with `LICENSE`,
/// `notes/001.md` and `docs/guide.md` committed.
fn with_path_rules(rules: &str) -> Sandbox {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("[protect]\n", &format!("[protect]\n{rules}\n"), 1));
    s.write("LICENSE", "Apache-2.0\n");
    fs::create_dir_all(s.path("notes")).unwrap();
    fs::create_dir_all(s.path("docs")).unwrap();
    s.write("notes/001.md", "first\n");
    s.write("docs/guide.md", "guide\n");
    s.commit_all("path rules");
    s
}

fn decision_of(out: &Output) -> String {
    json(out)["decision"].as_str().unwrap_or("").to_string()
}

fn finding_codes(out: &Output) -> Vec<String> {
    json(out)["brief"]["gate"]["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
}

#[test]
fn a_locked_file_cannot_be_changed_and_no_approval_clears_it() {
    let s = with_path_rules("locked = [\"LICENSE\"]");
    s.write("LICENSE", "MIT\n");
    s.git(&["add", "-A"]);
    let out = s.run(&["brief", "--json"]);
    assert_eq!(decision_of(&out), "deny", "{}", text(&out));
    assert!(finding_codes(&out).contains(&"LOCKED_PATH".to_string()), "{:?}", finding_codes(&out));
    assert!(!finding_codes(&out).contains(&"PROTECTED_PATH".to_string()), "a locked file is reported once, as locked");

    s.approver();
    s.run_with_stdin(&["approve", "--reason", "fine by me", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(decision_of(&s.run(&["brief", "--json"])), "deny", "an approval never clears a lock");
}

#[test]
fn a_person_can_bypass_a_lock_and_the_brief_says_so() {
    let s = with_path_rules("locked = [\"LICENSE\"]");
    s.write("LICENSE", "MIT\n");
    s.git(&["add", "-A"]);
    s.approver();
    let out = s.run_with_stdin(&["bypass", "--reason", "relicensing, agreed by everyone", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    let brief = s.run(&["brief"]);
    assert_eq!(code(&brief), 0, "{}", text(&brief));
    assert!(text(&brief).contains("break-glass") && text(&brief).contains("relicensing"), "{}", text(&brief));
}

#[test]
fn an_absolute_lock_and_a_policy_without_bypass_cannot_be_bypassed() {
    for rules in ["absolute = [\"LICENSE\"]", "locked = [\"LICENSE\"]\nbypass = false"] {
        let s = with_path_rules(rules);
        s.write("LICENSE", "MIT\n");
        s.git(&["add", "-A"]);
        s.approver();
        s.run_with_stdin(&["bypass", "--reason", "relicensing, agreed by everyone", "--passphrase-stdin"], "correct horse\n");
        let out = s.run(&["brief", "--json"]);
        assert_eq!(decision_of(&out), "deny", "{rules}: {}", text(&out));
        let brief = s.run(&["brief"]);
        assert!(text(&brief).contains("no bypass"), "{rules}: the brief says why the bypass did not count:\n{}", text(&brief));
    }
}

#[test]
fn unlocking_a_file_and_changing_it_in_one_change_is_still_denied() {
    let s = with_path_rules("locked = [\"LICENSE\"]");
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("locked = [\"LICENSE\"]\n", ""));
    s.write("LICENSE", "MIT\n");
    s.git(&["add", "-A"]);
    let out = s.run(&["brief", "--json"]);
    assert_eq!(decision_of(&out), "deny", "the base's lock still holds: {}", text(&out));
    assert!(finding_codes(&out).contains(&"LOCKED_PATH".to_string()));
}

#[test]
fn an_append_only_area_takes_new_files_and_refuses_edits_renames_and_deletions() {
    let s = with_path_rules("append_only = [\"notes/**\"]");
    s.write("notes/002.md", "second\n");
    s.git(&["add", "-A"]);
    let fine = s.run(&["brief", "--json"]);
    assert!(decision_of(&fine) != "deny" && !finding_codes(&fine).contains(&"APPEND_ONLY".to_string()), "a new file is fine: {}", text(&fine));
    s.git(&["reset", "-q"]);
    fs::remove_file(s.path("notes/002.md")).unwrap();

    for change in [&["edit"][..], &["rename"][..], &["delete"][..]] {
        match change[0] {
            "edit" => s.write("notes/001.md", "rewritten\n"),
            "rename" => {
                s.git(&["mv", "notes/001.md", "notes/001-old.md"]);
            }
            _ => fs::remove_file(s.path("notes/001.md")).unwrap(),
        }
        s.git(&["add", "-A"]);
        let out = s.run(&["brief", "--json"]);
        assert_eq!(decision_of(&out), "deny", "{change:?}: {}", text(&out));
        assert!(finding_codes(&out).contains(&"APPEND_ONLY".to_string()), "{change:?}: {:?}", finding_codes(&out));
        s.git(&["reset", "-q", "--hard"]);
    }
}

#[test]
fn a_no_delete_file_can_be_edited_but_not_deleted() {
    let s = with_path_rules("no_delete = [\"docs/**\"]");
    s.write("docs/guide.md", "better guide\n");
    s.git(&["add", "-A"]);
    let edited = s.run(&["brief", "--json"]);
    assert!(decision_of(&edited) != "deny" && !finding_codes(&edited).contains(&"NO_DELETE".to_string()), "an edit is fine: {}", text(&edited));
    s.git(&["reset", "-q", "--hard"]);
    fs::remove_file(s.path("docs/guide.md")).unwrap();
    s.git(&["add", "-A"]);
    let out = s.run(&["brief", "--json"]);
    assert_eq!(decision_of(&out), "deny", "{}", text(&out));
    assert!(finding_codes(&out).contains(&"NO_DELETE".to_string()));
}

#[test]
fn agent_hooks_refuse_locked_and_append_only_edits_deletions_and_reads_of_no_read_files() {
    let s = with_path_rules("locked = [\"LICENSE\"]\nappend_only = [\"notes/**\"]\nno_delete = [\"docs/**\"]\nno_read = [\".env*\"]");
    s.write(".env", "TOKEN=x\n");
    let hook = |tool: &str, input: Value| {
        let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input }).to_string();
        let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v["hookSpecificOutput"]["permissionDecision"].as_str().map(str::to_string), text(&out))
    };
    let (d, why) = hook("Edit", serde_json::json!({ "file_path": s.path("LICENSE"), "old_string": "a", "new_string": "b" }));
    assert_eq!(d.as_deref(), Some("deny"), "{why}");
    assert!(why.contains("locked") && !why.contains("approve --intent"), "a lock offers no approval route: {why}");

    assert_eq!(hook("Edit", serde_json::json!({ "file_path": s.path("notes/001.md"), "old_string": "a", "new_string": "b" })).0.as_deref(), Some("deny"));
    assert_eq!(hook("Write", serde_json::json!({ "file_path": s.path("notes/002.md"), "content": "new" })).0, None, "a new file in an append-only area is fine");
    assert_eq!(hook("Bash", serde_json::json!({ "command": "rm docs/guide.md" })).0.as_deref(), Some("deny"));
    assert_eq!(hook("Bash", serde_json::json!({ "command": "sed -i '' s/a/b/ LICENSE" })).0.as_deref(), Some("deny"));
    assert_eq!(hook("Read", serde_json::json!({ "file_path": s.path(".env") })).0.as_deref(), Some("deny"));
    assert_eq!(hook("Bash", serde_json::json!({ "command": "cat .env" })).0.as_deref(), Some("deny"));
    assert_eq!(hook("Read", serde_json::json!({ "file_path": s.path("LICENSE") })).0, None, "reading a locked file is fine");
    assert_eq!(hook("Edit", serde_json::json!({ "file_path": s.path("docs/guide.md"), "old_string": "a", "new_string": "b" })).0, None, "editing a no-delete file is fine");
}

#[test]
fn claude_code_hooks_see_reads_so_no_read_can_hold() {
    let s = Sandbox::with_agent_hooks();
    let settings = fs::read_to_string(s.path(".claude/settings.local.json")).unwrap();
    assert!(settings.contains("Read|Grep|Glob"), "{settings}");
}

#[test]
fn rerunning_init_brings_an_older_versions_agent_hooks_up_to_date() {
    let s = Sandbox::with_agent_hooks();
    let path = s.path(".claude/settings.local.json");
    // What an older use05 installed, next to another tool's hook that must be kept.
    let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    v["hooks"]["PreToolUse"][0]["matcher"] = serde_json::json!("Write|Edit|MultiEdit|NotebookEdit|Bash");
    v["hooks"]["PreToolUse"].as_array_mut().unwrap().push(serde_json::json!({ "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-tool check" }] }));
    fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    assert_eq!(code(&s.run(&["init"])), 0);
    let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
    let ours: Vec<&Value> = pre.iter().filter(|g| g.to_string().contains("use05 hook")).collect();
    assert_eq!(ours.len(), 1, "one 05 group, not two: {pre:?}");
    assert!(ours[0]["matcher"].as_str().unwrap().contains("Read|Grep|Glob"), "{pre:?}");
    assert!(pre.iter().any(|g| g.to_string().contains("other-tool check")), "another tool's hook is kept: {pre:?}");
    // Subagents are briefed and logged too, in Claude Code and in Codex: one 05 group each.
    let codex: Value = serde_json::from_str(&fs::read_to_string(s.path(".codex/hooks.json")).unwrap()).unwrap();
    for (name, hooks) in [("claude", &v["hooks"]), ("codex", &codex["hooks"])] {
        for event in ["SubagentStart", "SubagentStop"] {
            let groups = hooks[event].as_array().unwrap_or_else(|| panic!("{name} has no {event} hook: {hooks}"));
            assert_eq!(groups.iter().filter(|g| g.to_string().contains("use05 hook")).count(), 1, "{name} {event}: {groups:?}");
        }
    }
}

#[test]
fn the_pre_push_hook_stops_a_push_the_gate_denies_and_no_verify_is_the_stated_way_around() {
    let s = Sandbox::initialised();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["branch", "-M", "main"]);
    let push = |extra: &[&str]| {
        let bin_dir = bin_dir();
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).arg("push").args(extra).args(["origin", "main"]);
        cmd.env("PATH", format!("{bin_dir}:{}", std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("LANG", "C.UTF-8").env("COLUMNS", "100");
        cmd.output().unwrap()
    };
    // The first push sets the base: nothing to hold back yet.
    let first = push(&[]);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));

    // Now edit 05's own rules and try to push the edit.
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.commit_all("loosen the rules");
    let stopped = push(&[]);
    assert!(!stopped.status.success(), "a protected change must not push without approval");
    let message = String::from_utf8_lossy(&stopped.stderr).to_string();
    assert!(message.contains("05 stopped this push") && message.contains("--no-verify"), "{message}");

    let skipped = push(&["--no-verify"]);
    assert!(skipped.status.success(), "--no-verify skips an advisory hook, and the message said so");
}

#[test]
fn agent_hooks_deny_the_risky_and_the_protected_and_fail_open_loudly() {
    let s = Sandbox::initialised();
    let payload = |tool: &str, input: Value| {
        serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input }).to_string()
    };
    let decision = |out: &Output| -> Option<String> {
        let v: Value = serde_json::from_slice(&out.stdout).ok()?;
        v["hookSpecificOutput"]["permissionDecision"].as_str().map(str::to_string)
    };

    let force = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload("Bash", serde_json::json!({ "command": "git push --force origin main" })));
    assert_eq!(code(&force), 0, "a hook always exits 0; the decision is in its output");
    assert_eq!(decision(&force).as_deref(), Some("deny"), "{}", text(&force));

    let policy = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload("Edit", serde_json::json!({ "file_path": s.path(".05/policy.toml"), "old_string": "a", "new_string": "b" })));
    assert_eq!(decision(&policy).as_deref(), Some("deny"), "{}", text(&policy));
    assert!(text(&policy).contains("approve"), "it tells the agent what a person must do");

    let fine = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload("Edit", serde_json::json!({ "file_path": s.path("main.rs"), "old_string": "a", "new_string": "b" })));
    assert_eq!(code(&fine), 0);
    assert_eq!(decision(&fine), None, "an ordinary edit is not interfered with: {}", text(&fine));

    // 05 failing must never stall the agent, and must not stay quiet about it.
    let broken = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], "this is not json");
    assert_eq!(code(&broken), 1, "exit 1 is Claude Code's non-blocking error: the step proceeds and the first stderr line is shown");
    assert_eq!(decision(&broken), None);
    assert!(String::from_utf8_lossy(&broken.stderr).contains("Nothing was blocked"), "{}", text(&broken));
    snapshot("hook_denied", &s, &policy);
}

#[test]
fn doctor_reports_problems_with_a_nonzero_exit_and_never_changes_anything() {
    let s = Sandbox::initialised();
    let before = s.snapshot_files();
    // PATH without the folders holding extensions (use05-*) installed on this computer: they are
    // not the test's, and doctor lists them. The build folder holds use05-cloud too, so the
    // test's own use05 goes on PATH from a folder of its own.
    let own = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(BIN, own.path().join("use05")).unwrap();
    let path = std::iter::once(own.path().to_path_buf())
        .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).filter(|d| !fs::read_dir(d).into_iter().flatten().flatten().any(|e| e.file_name().to_string_lossy().starts_with("use05"))))
        .collect::<Vec<_>>();
    let path = std::env::join_paths(path).unwrap();
    let healthy = s.run_env(&["doctor"], &[("PATH", path.to_str().unwrap())]);
    assert_eq!(code(&healthy), 0, "{}", text(&healthy));
    assert!(text(&healthy).contains("advisory"), "it must be honest about enforcement strength");
    snapshot("doctor", &s, &healthy);
    assert_eq!(s.snapshot_files(), before, "doctor only reads");

    // Damage the recorded log of a task.
    s.run(&["start", "A task"]);
    let state = s.path(".git/05");
    let mut logs = Vec::new();
    fn find(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() { find(&p, out) } else if p.extension().is_some_and(|x| x == "jsonl") { out.push(p) }
        }
    }
    find(&state, &mut logs);
    if let Some(log) = logs.first() {
        fs::write(log, "{\"seq\":1,\"t\":\"x\",\"prev\":\"\",\"hash\":\"nope\",\"event\":{}}\n").unwrap();
        let broken = s.run(&["doctor"]);
        assert_eq!(code(&broken), 4, "{}", text(&broken));
        assert!(text(&broken).contains("altered or damaged"));
    }

    // A policy that does not parse is the thing to fix, and it is named.
    s.write(".05/policy.toml", "this = [is not valid");
    s.commit_all("break the policy");
    let out = s.run(&["doctor", "--json"]);
    assert_ne!(code(&out), 0);
}

#[test]
fn a_repository_needing_a_newer_use05_asks_for_an_upgrade_instead_of_a_parse_error() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(policy.contains(&format!("min_version = \"{}\"", env!("CARGO_PKG_VERSION"))), "init records the version that wrote the policy:\n{policy}");

    // A teammate's newer policy, with a section this version has never heard of.
    s.write(".05/policy.toml", &policy.replace(&format!("min_version = \"{}\"", env!("CARGO_PKG_VERSION")), "min_version = \"99.0.0\"").replace("[intent]", "[[env]]\nname = \"prod\"\n\n[intent]"));
    s.commit_all("a policy from the future");
    for args in [&["policy"][..], &[][..], &["doctor"][..]] {
        let out = s.run(args);
        // Bare `use05` is the status screen: it always exits 0 and shows the problem with its next step.
        if !args.is_empty() {
            assert_ne!(code(&out), 0, "{args:?}: {}", text(&out));
        }
        assert!(text(&out).contains("needs use05 99.0.0 or newer"), "{args:?}: {}", text(&out));
        assert!(text(&out).contains("npm i -g @use05/cli"), "{args:?}: {}", text(&out));
    }
}

#[test]
fn the_terminal_output_holds_up_when_narrow_plain_or_ascii() {
    let s = Sandbox::initialised();
    s.run(&["start", "A task with a rather long title that will certainly need to wrap on a narrow screen"]);
    s.write("main.rs", "fn main() { println!(\"x\"); }\n");
    s.git(&["add", "-A"]);

    for width in ["40", "60", "120"] {
        let mut cmd = s.command(&["brief"]);
        let out = cmd.env("COLUMNS", width).stdin(Stdio::null()).output().unwrap();
        let w: usize = width.parse().unwrap();
        for line in text(&out).lines() {
            assert!(line.chars().count() <= w, "width {w}: {line:?}\n{}", text(&out));
        }
    }

    let plain = s.command(&["brief"]).env("CLICOLOR_FORCE", "1").env("NO_COLOR", "1").output().unwrap();
    assert!(!plain.stdout.contains(&0x1b), "NO_COLOR wins even over a forced colour request");
    let piped = s.run(&["brief"]);
    assert!(!piped.stdout.contains(&0x1b), "no escape sequences when output is not a terminal");
    let coloured = s.command(&["brief"]).env("CLICOLOR_FORCE", "1").output().unwrap();
    assert!(coloured.stdout.contains(&0x1b), "colour can be forced");

    let ascii = s.command(&["brief"]).env("LANG", "C").output().unwrap();
    assert!(String::from_utf8_lossy(&ascii.stdout).is_ascii(), "a non-UTF-8 locale gets ASCII only:\n{}", text(&ascii));
    let dumb = s.command(&["brief"]).env("TERM", "dumb").env("CLICOLOR_FORCE", "1").output().unwrap();
    assert!(!dumb.stdout.contains(&0x1b), "a dumb terminal gets no colour");
}

#[test]
fn json_is_the_same_facts_as_the_words() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.git(&["add", "-A"]);
    let out = s.run(&["brief", "--json"]);
    let v = json(&out);
    assert_eq!(v["decision"], "approval_required");
    assert_eq!(code(&out), 3);
    assert!(v["brief"]["gate"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "PROTECTED_PATH"));
}

// ---------------------------------------------------------------- the CI gate

/// A repository whose base (`main`, pushed to a bare "origin") requires a `test` check proved by
/// a trusted runner key, plus a feature branch checked out. Returns the secret runner key.
fn ci_fixture() -> (Sandbox, String, TempDir) {
    ci_fixture_with("")
}

/// Like `ci_fixture`, with extra lines inside the `[[trust.key]]` table (for example an expiry).
fn ci_fixture_with(trust_extra: &str) -> (Sandbox, String, TempDir) {
    let s = Sandbox::new();
    s.key("runner.key");
    let public = fs::read_to_string(s.path("runner.key.pub")).unwrap().trim().to_string();
    let secret = fs::read_to_string(s.path("runner.key")).unwrap().trim().to_string();
    fs::remove_file(s.path("runner.key")).unwrap();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(
        ".05/policy.toml",
        &format!("[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n\n[evidence]\naccept = [\"runner\"]\n\n[[trust.key]]\nname = \"ci\"\nrole = \"runner\"\npublic = \"{public}\"\n{trust_extra}"),
    );
    fs::remove_file(s.path("runner.key.pub")).unwrap();
    s.commit_all("base");
    s.git(&["branch", "-M", "main"]);
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["push", "-q", "origin", "main"]);
    s.git(&["checkout", "-q", "-b", "feature"]);
    (s, secret, remote)
}

fn gate_ci(s: &Sandbox, secret: Option<&str>, extra: &[&str]) -> Output {
    let mut args = vec!["gate", "--ci"];
    args.extend_from_slice(extra);
    let mut cmd = s.command(&args);
    // CI runs on another machine: it has none of this developer's keys.
    let ci_home = tempfile::tempdir().unwrap();
    cmd.env("USE05_HOME", ci_home.path()).env("HOME", ci_home.path());
    cmd.env("GITHUB_BASE_REF", "main").stdin(Stdio::null());
    if let Some(secret) = secret {
        cmd.env("USE05_RUNNER_KEY", secret);
    }
    cmd.output().unwrap()
}

#[test]
fn the_ci_gate_proves_the_base_checks_with_the_runner_key_and_allows_a_good_change() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { println!(\"better\"); }\n");
    s.commit_all("improve");
    let out = gate_ci(&s, Some(&secret), &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("ALLOW"), "{}", text(&out));
    assert!(text(&out).contains("authoritative"), "the evidence is runner-signed, and says so:\n{}", text(&out));
    assert!(!s.stored_receipts().is_empty(), "the runner's receipt is stored for the brief to find");
}

#[test]
fn the_ci_gate_denies_a_change_whose_check_fails() {
    let (s, secret, _remote) = ci_fixture();
    s.write("test.sh", "#!/bin/sh\necho broken >&2\nexit 1\n");
    s.commit_all("break the tests");
    let out = gate_ci(&s, Some(&secret), &[]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(text(&out).contains("DENY"), "{}", text(&out));
}

#[test]
fn a_change_cannot_loosen_its_own_rules_in_ci() {
    let (s, secret, _remote) = ci_fixture();
    // The change swaps the required check for one that always passes, and breaks the real one.
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"true\"]\n");
    s.write("test.sh", "#!/bin/sh\nexit 1\n");
    s.commit_all("make the check easy");
    let out = gate_ci(&s, Some(&secret), &[]);
    assert_ne!(code(&out), 0, "the base's check (./test.sh) is what runs, so this must not pass:\n{}", text(&out));
    assert!(text(&out).contains("PROTECTED_PATH") || text(&out).contains("DENY"), "{}", text(&out));
}

#[test]
fn the_ci_gate_refuses_to_run_without_a_runner_key() {
    let (s, _secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() {}\n// x\n");
    s.commit_all("x");
    let out = gate_ci(&s, None, &["--json"]);
    assert_eq!(code(&out), 6, "{}", text(&out));
    assert_eq!(json(&out)["code"], "NO_RUNNER_KEY");
}

#[test]
fn the_ci_gate_writes_the_brief_to_the_github_step_summary() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { /* summary */ }\n");
    s.commit_all("change");
    let summary = s.path("summary.md");
    let out = s.command(&["gate", "--ci"]).env("GITHUB_BASE_REF", "main").env("USE05_RUNNER_KEY", &secret).env("GITHUB_STEP_SUMMARY", &summary).stdin(Stdio::null()).output().unwrap();
    assert_eq!(code(&out), 0, "{}", text(&out));
    let md = fs::read_to_string(&summary).unwrap();
    assert!(md.starts_with("```text\n") && md.contains("ALLOW"), "{md}");
}

// ---------------------------------------------------------------- sharing receipts

#[test]
fn receipts_can_be_pushed_and_fetched_with_flags_and_a_refused_push_is_reported_not_fatal() {
    let (s, _secret, remote) = ci_fixture();
    s.key("me.key");
    s.write("main.rs", "fn main() { /* shared */ }\n");
    s.commit_all("change");
    let remote_path = remote.path().display().to_string();

    // Without --push nothing leaves the machine.
    let local = s.run(&["prove", "--key", "me.key", "--tree", "HEAD", "--", "true"]);
    assert_eq!(code(&local), 0, "{}", text(&local));
    let branch = s.stored_receipts().remove(0).0;
    let on_remote = |name: &str| Command::new("git").args(["-C", &remote_path, "rev-parse", "--verify", "-q", &format!("refs/heads/{name}")]).output().unwrap().status.success();
    assert!(!on_remote(&branch), "a receipt is not pushed unless asked");

    let pushed = s.run(&["prove", "--key", "me.key", "--tree", "HEAD", "--push", "--", "true"]);
    assert_eq!(code(&pushed), 0, "{}", text(&pushed));
    assert!(text(&pushed).contains("Pushed"), "{}", text(&pushed));
    assert!(on_remote(&branch));

    // Another clone sees it with `brief --fetch`.
    let clone = tempfile::tempdir().unwrap();
    let clone_path = clone.path().display().to_string();
    assert!(Command::new("git").args(["clone", "-q", &remote_path, &clone_path]).status().unwrap().success());
    let seen = |args: &[&str]| Command::new(BIN).current_dir(clone.path()).args(args).env_clear().env("PATH", std::env::var("PATH").unwrap()).env("HOME", clone.path()).env("USE05_HOME", clone.path().join("h")).env("LANG", "C.UTF-8").stdin(Stdio::null()).output().unwrap();
    let before = text(&seen(&["brief", "--tree", "origin/main", "--json"]));
    assert!(before.contains("\"decision\""), "{before}");
    let fetched = seen(&["brief", "--fetch", "--tree", "origin/main"]);
    assert!(!text(&fetched).contains("could not fetch"), "{}", text(&fetched));
    let refs = Command::new("git").args(["-C", &clone_path, "for-each-ref", "refs/remotes/origin/05-receipts/"]).output().unwrap();
    assert!(!refs.stdout.is_empty(), "the receipts branch is fetched into remote-tracking branches");

    // No remote: the command still succeeds and says how to share it.
    let lonely = Sandbox::new();
    lonely.key("me.key");
    let out = lonely.run(&["prove", "--key", "me.key", "--push", "--", "true"]);
    assert_eq!(code(&out), 0, "a failed push must not fail the proof:\n{}", text(&out));
    assert!(text(&out).contains("no remote"), "{}", text(&out));
}

// ---------------------------------------------------------------- organisation floor and finish

#[test]
fn an_organisation_floor_tightens_a_repository_and_cannot_be_dropped_or_tampered_with() {
    let s = Sandbox::initialised();
    // The repository is permissive: local evidence counts.
    s.write(".05/policy.toml", "[evidence]\naccept = [\"local\", \"runner\"]\n");
    s.commit_all("permissive");

    // The organisation signs a floor requiring runner evidence and protecting secrets/.
    s.key("org.key");
    s.write("floor.toml", "evidence_accept = [\"runner\"]\nprotect_paths = [\"secrets/**\"]\n");
    let signed = s.run(&["policy", "org-sign", "floor.toml", "--org", "Acme", "--key", "org.key", "--out", "org.json"]);
    assert_eq!(code(&signed), 0, "{}", text(&signed));
    // Installing it on a machine is copying two files into 05's config directory.
    fs::copy(s.path("org.json"), s.home.path().join("org.json")).unwrap();
    fs::copy(s.path("org.key.pub"), s.home.path().join("org.pub")).unwrap();

    let policy = json(&s.run(&["policy", "--json"]));
    assert_eq!(policy["details"]["org"], "Acme");
    assert_eq!(policy["details"]["policy"]["evidence"]["accept"], serde_json::json!(["runner"]), "the floor tightened the repository's looser rule");
    assert!(policy["details"]["policy"]["protect"]["paths"].as_array().unwrap().iter().any(|p| p == "secrets/**"));
    assert!(text(&s.run(&["policy"])).contains("Acme"));

    // A tampered layer is an error, never a quiet fallback to the repository's own rules.
    let original = fs::read_to_string(s.home.path().join("org.json")).unwrap();
    let mut bytes = original.clone().into_bytes();
    let at = original.find("\"payload\": \"").unwrap() + 20;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    fs::write(s.home.path().join("org.json"), &bytes).unwrap();
    let bad = s.run(&["brief"]);
    assert_ne!(code(&bad), 0, "{}", text(&bad));
    assert!(text(&bad).contains("organisation policy"), "{}", text(&bad));

    // Removing the layer while its key is still pinned is also an error.
    fs::remove_file(s.home.path().join("org.json")).unwrap();
    let missing = s.run(&["brief"]);
    assert_ne!(code(&missing), 0, "{}", text(&missing));
    assert!(text(&missing).contains("organisation"), "{}", text(&missing));
}

#[test]
fn finish_records_what_the_author_claims_and_the_brief_checks_it_against_evidence() {
    let s = Sandbox::initialised();
    s.run(&["start", "Speed up the parser"]);
    s.write("main.rs", "fn main() { /* faster */ }\n");
    s.git(&["add", "-A"]);
    let finished = s.run(&["finish", "--outcome", "Made the parser faster. All tests pass."]);
    assert_eq!(code(&finished), 0, "{}", text(&finished));

    // The claim is an assertion until evidence on this exact tree supports it.
    let before = json(&s.run(&["brief", "--json"]));
    let findings = before["brief"]["gate"]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["code"] == "CLAIM_UNSUPPORTED"), "{before}");

    assert_eq!(code(&s.run(&["prove"])), 0);
    let after = json(&s.run(&["brief", "--json"]));
    let findings = after["brief"]["gate"]["findings"].as_array().unwrap();
    assert!(!findings.iter().any(|f| f["code"] == "CLAIM_UNSUPPORTED"), "proved on this tree, so the claim is supported: {after}");

    // A claim contradicted by a failing check is worse than an unsupported one.
    let s2 = Sandbox::initialised();
    s2.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"false\"]\n");
    s2.commit_all("failing check");
    s2.run(&["start", "Anything"]);
    s2.write("main.rs", "fn main() { /* x */ }\n");
    s2.git(&["add", "-A"]);
    s2.run(&["finish", "--outcome", "All tests pass."]);
    s2.run(&["prove"]);
    let contradicted = json(&s2.run(&["brief", "--json"]));
    assert!(contradicted["brief"]["gate"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "CLAIM_CONTRADICTED"), "{contradicted}");
}

#[test]
fn codex_hooks_read_apply_patch_edits_and_deny_where_claude_would_ask() {
    let s = Sandbox::initialised();
    let patch = format!("*** Begin Patch\n*** Update File: {}/.05/policy.toml\n@@\n-min = 1\n+min = 0\n*** End Patch\n", s.dir.path().display());
    let payload = serde_json::json!({ "session_id": "codex-1", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": { "command": patch } }).to_string();
    let out = s.run_with_stdin(&["hook", "codex", "PreToolUse"], &payload);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&out)));
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{v}");

    // A skipped check exits 0 for Codex (only 0 and 2 are documented), loudly on stderr.
    let broken = s.run_with_stdin(&["hook", "codex", "PreToolUse"], "not json");
    assert_eq!(code(&broken), 0);
    assert!(String::from_utf8_lossy(&broken.stderr).contains("Nothing was blocked"));
}

#[test]
fn a_protected_file_is_still_protected_when_the_agent_reports_its_path_through_a_symlink() {
    let s = Sandbox::initialised();
    let link = s.home.path().join("project-link");
    std::os::unix::fs::symlink(s.dir.path(), &link).unwrap();
    let payload = serde_json::json!({
        "session_id": "sess-link", "cwd": link, "hook_event_name": "PreToolUse", "tool_name": "Edit",
        "tool_input": { "file_path": link.join(".05/policy.toml"), "old_string": "a", "new_string": "b" }
    })
    .to_string();
    let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&out)));
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{v}");
}

// ---------------------------------------------------------------- a real terminal

/// Run `use05` on a pseudo-terminal (stdin, stdout, stderr and /dev/tty are all the terminal),
/// feed it `lines` one at a time when it is waiting, and return its exit code and screen text.
fn on_a_terminal(s: &Sandbox, args: &[&str], lines: &[&str]) -> (i32, String) {
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty fills in two descriptors we then own.
    assert_eq!(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }, 0);
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut cmd = s.command(args);
    cmd.stdin(slave.try_clone().unwrap()).stdout(slave.try_clone().unwrap()).stderr(slave.try_clone().unwrap());
    // SAFETY: only async-signal-safe calls between fork and exec: a new session whose controlling terminal is the pty.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    drop(slave);
    let mut writer = std::fs::File::from(master.try_clone().unwrap());
    let mut reader = std::fs::File::from(master);
    let reader_thread = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    });
    for line in lines {
        std::thread::sleep(std::time::Duration::from_millis(700));
        writer.write_all(format!("{line}\n").as_bytes()).unwrap();
    }
    let status = child.wait().unwrap();
    drop(writer);
    let screen = reader_thread.join().unwrap();
    (status.code().unwrap_or(-1), screen)
}

#[test]
fn the_passphrase_is_asked_for_on_the_terminal_never_echoed_and_a_wrong_one_is_refused() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edit\n"));
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0, "evidence first, so only the approval is missing");

    let (code_new, screen) = on_a_terminal(&s, &["key", "new", "--approver"], &["tr0ub4dor-secret", "tr0ub4dor-secret"]);
    assert_eq!(code_new, 0, "{screen}");
    assert!(screen.contains("passphrase"), "{screen}");
    assert!(!screen.contains("tr0ub4dor-secret"), "what is typed at a passphrase prompt must not be echoed:\\n{screen}");

    let (wrong, screen) = on_a_terminal(&s, &["approve", "--reason", "looks fine"], &["not-the-passphrase"]);
    assert_ne!(wrong, 0, "{screen}");
    assert_eq!(code(&s.run(&["brief"])), 3, "a wrong passphrase approves nothing");

    let (right, screen) = on_a_terminal(&s, &["approve", "--reason", "reviewed the edit"], &["tr0ub4dor-secret"]);
    assert_eq!(right, 0, "{screen}");
    assert!(!screen.contains("tr0ub4dor-secret"), "{screen}");
    assert_eq!(code(&s.run(&["brief"])), 0, "the right passphrase approves");
}

#[test]
fn bare_use05_on_a_terminal_offers_a_menu_runs_the_choice_and_quits_cleanly() {
    let s = Sandbox::initialised();
    let (quit, screen) = on_a_terminal(&s, &[], &["q"]);
    assert_eq!(quit, 0, "{screen}");
    assert!(screen.contains("Check the setup") && screen.contains("Quit"), "{screen}");

    let (picked, screen) = on_a_terminal(&s, &[], &["1"]);
    assert_eq!(picked, 0, "{screen}");
    assert!(screen.contains("Doctor"), "choosing 'Check the setup' runs doctor:\n{screen}");

    // End of input (Ctrl-D) is a quiet exit, not a hang or a crash.
    let (eof, _) = on_a_terminal(&s, &[], &["\x04"]);
    assert_eq!(eof, 0);
}

#[test]
fn init_lets_the_agent_run_the_safe_commands_but_never_approve_and_uninstall_removes_exactly_that() {
    let s = Sandbox::new();
    fs::create_dir_all(s.home.path().join(".claude")).unwrap();
    // The person already had their own settings; they must survive.
    fs::create_dir_all(s.path(".claude")).unwrap();
    s.write(".claude/settings.local.json", "{\n  \"permissions\": { \"allow\": [\"Bash(ls)\"] },\n  \"model\": \"sonnet\"\n}\n");
    s.commit_all("first");
    let before = fs::read_to_string(s.path(".claude/settings.local.json")).unwrap();
    let init = s.run(&["init"]);
    assert_eq!(code(&init), 0, "{}", text(&init));
    let settings: Value = serde_json::from_str(&fs::read_to_string(s.path(".claude/settings.local.json")).unwrap()).unwrap();
    let allow: Vec<&str> = settings["permissions"]["allow"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    for ok in ["Bash(ls)", "Bash(use05 prove)", "Bash(use05 prove *)", "Bash(use05 start *)", "Bash(use05 finish *)", "Bash(use05 brief)"] {
        assert!(allow.contains(&ok), "{ok} missing from {allow:?}");
    }
    for never in ["approve", "bypass", "key", "init", "uninstall", "gate"] {
        assert!(!allow.iter().any(|r| r.starts_with(&format!("Bash(use05 {never}"))), "{never} must stay a person's: {allow:?}");
    }
    assert_eq!(settings["model"], "sonnet");

    assert_eq!(code(&s.run(&["init"])), 0);
    let again: Value = serde_json::from_str(&fs::read_to_string(s.path(".claude/settings.local.json")).unwrap()).unwrap();
    assert_eq!(again, settings, "init twice changes nothing");

    assert_eq!(code(&s.run(&["uninstall"])), 0);
    let restored: Value = serde_json::from_str(&fs::read_to_string(s.path(".claude/settings.local.json")).unwrap()).unwrap();
    assert_eq!(restored, serde_json::from_str::<Value>(&before).unwrap(), "uninstall leaves the person's own settings exactly as they were");
}

#[test]
fn with_nothing_staged_the_brief_and_prove_look_at_the_working_tree() {
    let s = Sandbox::initialised();
    s.write("main.rs", "fn main() { /* edited by an agent, never staged */ }\n");
    s.write("new_file.rs", "// untracked\n");
    assert!(s.git(&["diff", "--cached", "--name-only"]).is_empty(), "nothing is staged");

    let brief = json(&s.run(&["brief", "--json"]));
    let changed: Vec<String> = brief["brief"]["gate"]["changed"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap().to_string()).collect();
    assert!(changed.contains(&"main.rs".to_string()) && changed.contains(&"new_file.rs".to_string()), "{changed:?}");
    assert!(text(&s.run(&["brief"])).contains("working tree"));

    let proved = json(&s.run(&["prove", "--json"]));
    assert_eq!(proved["outcome"], "passed", "{proved}");
    // The proof is for the working tree's content, so the brief on it is no longer "not run".
    let after = json(&s.run(&["brief", "--json"]));
    assert!(!after["brief"]["gate"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "CHECK_MISSING"), "{after}");

    // Staging something switches back to the staged files.
    s.git(&["add", "main.rs"]);
    assert!(text(&s.run(&["brief"])).contains("staged files"));
    // And a clean tree is just the empty index.
    let clean = Sandbox::initialised();
    assert!(text(&clean.run(&["brief"])).contains("staged files"));
}

#[test]
fn a_trusted_key_stops_counting_when_it_expires_and_doctor_says_so() {
    // Valid far into the future: the CI gate allows, and doctor reports the key as valid.
    let (ok, secret, _r) = ci_fixture_with("expires = \"2099-12-31\"\n");
    ok.write("main.rs", "fn main() { /* fine */ }\n");
    ok.commit_all("change");
    assert_eq!(code(&gate_ci(&ok, Some(&secret), &[])), 0);
    assert!(text(&ok.run(&["doctor"])).contains("valid until 2099-12-31"), "{}", text(&ok.run(&["doctor"])));

    // Expired: what the runner signs no longer counts, so the gate cannot allow, and doctor fails.
    let (old, secret, _r2) = ci_fixture_with("expires = \"2020-01-01\"\n");
    old.write("main.rs", "fn main() { /* fine */ }\n");
    old.commit_all("change");
    let out = gate_ci(&old, Some(&secret), &[]);
    assert_ne!(code(&out), 0, "an expired runner key must not make evidence authoritative:\n{}", text(&out));
    let doctor = old.run(&["doctor"]);
    assert_eq!(code(&doctor), 4, "{}", text(&doctor));
    assert!(text(&doctor).contains("expired on 2020-01-01"), "{}", text(&doctor));

    // An expiry nobody can read fails closed, and is reported.
    let (bad, _s, _r3) = ci_fixture_with("expires = \"next tuesday\"\n");
    let doctor = bad.run(&["doctor"]);
    assert_eq!(code(&doctor), 4, "{}", text(&doctor));
    assert!(text(&doctor).contains("cannot be read"), "{}", text(&doctor));
}

// ---------------------------------------------------------------- two agents, one repository

fn hook(s: &Sandbox, session: &str, event: &str, tool: &str, file: &str) -> Output {
    let input = serde_json::json!({ "file_path": s.path(file), "old_string": "a", "new_string": "b" });
    let payload = serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": event, "tool_name": tool, "tool_input": input }).to_string();
    s.run_with_stdin(&["hook", "claude-code", event], &payload)
}

#[test]
fn hooks_from_a_deep_subfolder_keep_their_state_in_the_repositorys_own_git_dir() {
    // An agent that cd's into apps/web/app/[account]/workspace: git names the common dir relative to
    // there, so joining it to the top escaped the repository (to `/`, read-only on macOS).
    let s = Sandbox::initialised();
    let deep = s.path("apps/web/app/[account]/workspace");
    fs::create_dir_all(&deep).unwrap();
    for event in ["PreToolUse", "PostToolUse"] {
        let payload = serde_json::json!({ "session_id": "deep-agent", "cwd": deep, "hook_event_name": event, "tool_name": "Bash", "tool_input": { "command": "ls" }, "tool_response": { "stdout": "" } }).to_string();
        let out = s.run_with_stdin(&["hook", "claude-code", event], &payload);
        assert_eq!(code(&out), 0, "{event}: {}", text(&out));
    }
    assert!(s.path(".git/05/sessions/deep-agent").exists(), "the session is recorded in the repository's .git/05");
    assert!(!s.path("apps/.git").exists() && !s.path("apps/web/.git").exists(), "nothing is written inside the work tree");
}

#[test]
fn an_agent_is_told_when_another_session_edited_the_same_file_and_policy_can_make_it_ask_or_deny() {
    let s = Sandbox::initialised();
    s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": "agent-a", "cwd": s.dir.path(), "hook_event_name": "SessionStart" }).to_string());
    s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": "agent-b", "cwd": s.dir.path(), "hook_event_name": "SessionStart" }).to_string());

    // Agent A edits main.rs; nobody else has touched it, so there is nothing to say.
    let first = hook(&s, "agent-a", "PreToolUse", "Edit", "main.rs");
    assert!(first.stdout.is_empty(), "{}", text(&first));
    hook(&s, "agent-a", "PostToolUse", "Edit", "main.rs");

    // The same agent editing again is not a collision with itself.
    assert!(hook(&s, "agent-a", "PreToolUse", "Edit", "main.rs").stdout.is_empty());

    // Agent B reaches for the same file: the edit proceeds, and B is told. No permission decision
    // is made, so B's own permission rules still apply.
    let second = hook(&s, "agent-b", "PreToolUse", "Edit", "main.rs");
    let v: Value = serde_json::from_slice(&second.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&second)));
    let context = v["hookSpecificOutput"]["additionalContext"].as_str().unwrap_or("");
    assert!(context.contains("main.rs") && context.contains("another agent session"), "{v}");
    assert!(v["hookSpecificOutput"].get("permissionDecision").is_none(), "a warning must not decide permissions: {v}");

    // A different file is not a collision.
    s.write("other.rs", "fn other() {}\n");
    assert!(hook(&s, "agent-b", "PreToolUse", "Edit", "other.rs").stdout.is_empty());

    // Policy can raise it. A task is held to the rules at its base, so each level gets fresh sessions.
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let start = |name: &str| {
        s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": name, "cwd": s.dir.path(), "hook_event_name": "SessionStart" }).to_string());
    };
    for (word, expected) in [("approval", "ask"), ("deny", "deny")] {
        s.write(".05/policy.toml", &policy.replace("overlap = \"warn\"", &format!("overlap = \"{word}\"")));
        s.commit_all(&format!("overlap = {word}"));
        let (first, second) = (format!("first-{word}"), format!("second-{word}"));
        start(&first);
        start(&second);
        hook(&s, &first, "PostToolUse", "Edit", "main.rs");
        let out = hook(&s, &second, "PreToolUse", "Edit", "main.rs");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&out)));
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], expected, "{word}: {v}");
    }
    // Codex has no "ask": with approval it is a denial there.
    s.write(".05/policy.toml", &policy.replace("overlap = \"warn\"", "overlap = \"approval\""));
    s.commit_all("approval again");
    start("codex-first");
    hook(&s, "codex-first", "PostToolUse", "Edit", "main.rs");
    let codex_payload = serde_json::json!({ "session_id": "codex-second", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": { "file_path": s.path("main.rs") } }).to_string();
    let out = s.run_with_stdin(&["hook", "codex", "PreToolUse"], &codex_payload);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&out)));
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{v}");
}

fn find_task(s: &Sandbox, session: &str) -> String {
    fs::read_to_string(s.path(&format!(".git/05/sessions/{session}"))).unwrap().trim().to_string()
}

#[test]
fn the_brief_lists_other_sessions_that_edited_the_same_changed_files() {
    let s = Sandbox::initialised();
    for session in ["agent-a", "agent-b"] {
        s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": "SessionStart" }).to_string());
    }
    hook(&s, "agent-a", "PostToolUse", "Edit", "main.rs");
    hook(&s, "agent-b", "PostToolUse", "Edit", "main.rs");
    s.write("main.rs", "fn main() { /* both agents touched this */ }\n");
    s.git(&["add", "-A"]);
    let task_b = find_task(&s, "agent-b");
    let task_a = find_task(&s, "agent-a");
    let out = s.run(&["brief", "--task", &task_b]);
    assert!(text(&out).contains("Overlap") && text(&out).contains(&task_a) && text(&out).contains("main.rs also edited"), "{}", text(&out));
    let json = json(&s.run(&["brief", "--task", &task_b, "--json"]));
    assert_eq!(json["overlap"][0]["task"], task_a.as_str());
}

// ----------------------------------------------------------------------------- declarations (D65, D67)

fn codex_hook(s: &Sandbox, session: &str, event: &str, file: &str) -> Output {
    let patch = format!("*** Begin Patch\n*** Update File: {file}\n@@\n-a\n+b\n*** End Patch");
    let payload = serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": event, "tool_name": "apply_patch", "tool_input": { "command": patch } }).to_string();
    s.run_with_stdin(&["hook", "codex", event], &payload)
}

fn task_json(s: &Sandbox, session: &str) -> Value {
    let id = find_task(s, session);
    serde_json::from_slice(&fs::read(s.path(&format!(".git/05/tasks/{id}.json"))).unwrap()).unwrap()
}

/// Declarations waiting in the inbox (its own .gitignore is not one).
fn inbox_count(s: &Sandbox) -> usize {
    fs::read_dir(s.path(".05/inbox")).map(|d| d.filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|x| x == "json")).count()).unwrap_or(0)
}

#[test]
fn an_agent_declaration_waits_in_the_inbox_and_its_own_hook_seals_it() {
    let s = Sandbox::with_agent_hooks();
    let out = s.run_env(&["start", "Cap retries", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("Declared: Cap retries"), "{}", text(&out));
    assert_eq!(inbox_count(&s), 1);
    codex_hook(&s, "s1", "PreToolUse", "src/a.rs");
    let task = task_json(&s, "s1");
    assert_eq!(task["title"], "Cap retries");
    assert_eq!(task["author"], "agent:codex");
    assert!(task["sealed"].is_string(), "{task}");
    assert_eq!(task["intent"]["scope"]["include"][0], "src/**");
    assert_eq!(inbox_count(&s), 0);
}

#[test]
fn two_sessions_in_one_worktree_each_get_their_own_declaration() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Task A", "--scope", "a/**"], &[("CODEX_SESSION_ID", "s1")]);
    s.run_env(&["start", "Task B", "--scope", "b/**"], &[("CODEX_SESSION_ID", "s2")]);
    codex_hook(&s, "s2", "PreToolUse", "b/x.rs");
    codex_hook(&s, "s1", "PreToolUse", "a/x.rs");
    assert_eq!(task_json(&s, "s1")["title"], "Task A");
    assert_eq!(task_json(&s, "s2")["title"], "Task B");
}

#[test]
fn an_unsealed_declaration_is_shown_not_lost() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Waiting", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s9")]);
    let status = text(&s.run(&[]));
    assert!(status.contains("1 declaration is waiting for its agent's hooks"), "{status}");
    let doctor = text(&s.run(&["doctor"]));
    assert!(doctor.contains("1 declaration is waiting for its agent's hooks"), "{doctor}");
}

#[test]
fn a_hook_with_no_session_id_seals_nothing() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Mine", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    codex_hook(&s, "", "PreToolUse", "src/a.rs");
    assert_eq!(inbox_count(&s), 1);
}

#[test]
fn inbox_files_are_never_part_of_the_change() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Pending", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    assert_eq!(inbox_count(&s), 1);
    assert_eq!(s.git(&["status", "--porcelain", "--", ".05"]), "", "the inbox must be ignored by git");
    s.write("main.rs", "fn main() { println!(\"hi\"); }\n");
    let brief = json(&s.run(&["brief", "--json"]));
    let changed: Vec<String> = brief["brief"]["gate"]["changed"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap().to_string()).collect();
    assert!(changed.contains(&"main.rs".to_string()) && !changed.iter().any(|p| p.starts_with(".05/")), "{brief}");
    let tree = brief["brief"]["tree"].as_str().unwrap().to_string();
    let files = s.git(&["ls-tree", "-r", "--name-only", &tree]);
    assert!(files.contains("main.rs") && !files.contains(".05/inbox"), "{files}");
}

#[test]
fn the_first_prompt_of_a_session_is_kept_locally_and_shown_in_the_brief() {
    let s = Sandbox::with_agent_hooks();
    for prompt in ["Cap retries at 3", "also tidy up"] {
        let payload = serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "UserPromptSubmit", "prompt": prompt }).to_string();
        s.run_with_stdin(&["hook", "claude-code", "UserPromptSubmit"], &payload);
    }
    assert_eq!(task_json(&s, "s1")["request"], "Cap retries at 3");
    let id = find_task(&s, "s1");
    let brief = text(&s.run(&["brief", "--task", &id]));
    assert!(brief.contains("asked: Cap retries at 3"), "{brief}");
}

#[test]
fn a_start_outside_any_agent_session_is_recorded_as_unverified() {
    let s = Sandbox::with_agent_hooks();
    let out = s.run(&["start", "By hand", "--json"]);
    assert_eq!(json(&out)["details"]["author"], "unverified", "{}", text(&out));
    let human = text(&s.run(&["start", "Again"]));
    assert!(human.contains("by unverified (made at this machine)"), "{human}");
}

#[test]
fn the_brief_says_which_risk_area_a_change_is_in_and_the_policy_template_explains_it() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("src/billing")).unwrap();
    s.write("src/billing/charge.rs", "pub fn charge() {}\n");
    let brief = text(&s.run(&["brief"]));
    assert!(brief.contains("money: src/billing/charge.rs"), "{brief}");
    assert!(brief.contains("RISK_NOT_APPROVED") || brief.contains("risk area"), "{brief}");
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(policy.contains("[risk]") && policy.contains("exempt"), "{policy}");
}

// ----------------------------------------------------------------------------- the no-review label (D66)

#[test]
fn a_clean_change_is_plain_allow_and_a_change_with_warnings_says_read_the_notes() {
    let s = Sandbox::initialised();
    s.write("main.rs", "fn main() { println!(\"hi\"); }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let clean = s.run(&["brief"]);
    assert_eq!(code(&clean), 0, "{}", text(&clean));
    assert!(text(&clean).contains("ALLOW  nothing to read"), "{}", text(&clean));
    assert_eq!(json(&s.run(&["brief", "--json"]))["label"], "allow");

    let start = s.run(&["start", "Docs only", "--scope", "docs/**"]);
    assert_eq!(code(&start), 0, "{}", text(&start));
    let noted = s.run(&["brief"]);
    assert_eq!(code(&noted), 0, "{}", text(&noted));
    assert!(text(&noted).contains("ALLOW  read the notes: 1"), "{}", text(&noted));
    assert!(text(&noted).contains("outside the declared scope"), "{}", text(&noted));
    snapshot("brief_allowed_notes", &s, &noted);
    assert_eq!(json(&s.run(&["brief", "--json"]))["label"], "allow_with_notes");
}

#[test]
fn a_break_glass_change_is_never_plain_allow() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.git(&["add", "-A"]);
    s.approver();
    let out = s.run_with_stdin(&["bypass", "--reason", "production is down", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(json(&s.run(&["brief", "--json"]))["label"], "allow_with_notes");
}

// ----------------------------------------------------------------------------- reservations (D64)

fn declare(s: &Sandbox, session: &str, title: &str, scope: &str) -> Output {
    s.run_env(&["start", title, "--scope", scope], &[("CODEX_SESSION_ID", session)]);
    let payload = serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": { "command": format!("use05 start \"{title}\" --scope \"{scope}\"") } }).to_string();
    s.run_with_stdin(&["hook", "codex", "PostToolUse"], &payload)
}

fn context_of(out: &Output) -> String {
    serde_json::from_slice::<Value>(&out.stdout).ok().and_then(|v| v["hookSpecificOutput"]["additionalContext"].as_str().map(str::to_string)).unwrap_or_default()
}

#[test]
fn overlapping_declarations_are_told_and_disjoint_ones_are_not() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "s1", "Cap retries", "src/payments/**");
    let first = find_task(&s, "s1");
    let second = declare(&s, "s2", "Retry backoff", "src/payments/retry/**");
    let told = context_of(&second);
    assert!(told.contains("is being worked on by task") && told.contains(&first) && told.contains("Cap retries"), "{told}");
    let third = declare(&s, "s3", "Docs", "docs/**");
    assert!(!context_of(&third).contains("is being worked on"), "{}", context_of(&third));
}

#[test]
fn with_overlap_deny_an_overlapping_declaration_is_not_sealed() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("overlap = \"warn\"", "overlap = \"deny\""));
    s.commit_all("overlap = deny");
    declare(&s, "s1", "Cap retries", "src/payments/**");
    let out = declare(&s, "s2", "Retry backoff", "src/payments/retry/**");
    assert!(context_of(&out).contains("not sealed"), "{}", context_of(&out));
    assert!(task_json(&s, "s2")["intent"].is_null(), "{}", task_json(&s, "s2"));
    assert_eq!(inbox_count(&s), 0, "a refused declaration does not wait forever");
}

#[test]
fn an_edit_inside_another_tasks_reservation_is_flagged_even_if_that_file_was_never_edited() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "s1", "Cap retries", "src/payments/**");
    let out = codex_hook(&s, "s2", "PreToolUse", "src/payments/new.rs");
    assert!(context_of(&out).contains("is being worked on by task"), "{}", text(&out));
}

#[test]
fn the_gate_reports_overlap_until_the_other_tasks_work_is_in_the_base() {
    let s = Sandbox::with_agent_hooks();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/other");
    let edit = |session: &str, dir: &Path| {
        let payload = serde_json::json!({ "session_id": session, "cwd": dir, "hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": { "file_path": dir.join("main.rs") } }).to_string();
        s.run_with_stdin(&["hook", "claude-code", "PostToolUse"], &payload);
    };
    let codes = |task: &str| -> Vec<String> {
        let brief = json(&s.run(&["brief", "--task", task, "--json"]));
        brief["brief"]["gate"]["findings"].as_array().unwrap().iter().filter_map(|f| f["code"].as_str().map(str::to_string)).collect()
    };
    // Another agent, on its own branch, is editing the same file right now.
    edit("s1", &wt);
    fs::write(wt.join("main.rs"), "fn main() { 13; }\n").unwrap();
    edit("s2", s.dir.path());
    s.write("main.rs", "fn main() { 14; }\n");
    assert!(codes(&find_task(&s, "s2")).contains(&"OVERLAP".to_string()));
    // It finishes and its work lands on main; a change based on that is no longer in its way.
    git_at(&wt, &["commit", "-qam", "other work"]);
    assert_eq!(code(&s.run(&["finish", "--task", &find_task(&s, "s1")])), 0);
    s.git(&["checkout", "-q", "--", "main.rs"]);
    s.git(&["merge", "-q", "--ff-only", "claude/other"]);
    edit("s3", s.dir.path());
    s.write("main.rs", "fn main() { 15; }\n");
    assert!(!codes(&find_task(&s, "s3")).contains(&"OVERLAP".to_string()), "the other task's work is in this change's base");
}

// ----------------------------------------------------------------------------- proof from trusted contexts (D65)

fn stop(s: &Sandbox, agent: &str, session: &str, active: bool) -> Output {
    let payload = serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": "Stop", "stop_hook_active": active, "last_assistant_message": "Done." }).to_string();
    s.run_with_stdin(&["hook", agent, "Stop"], &payload)
}

fn log_text(s: &Sandbox, session: &str) -> String {
    fs::read_to_string(s.path(&format!(".git/05/log/{}.jsonl", find_task(s, session)))).unwrap_or_default()
}

#[test]
fn prove_with_no_names_also_proves_the_cards_acceptance_checks() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"extra\"\nrun = [\"./test.sh\"]\nrequired = false\n"));
    s.commit_all("an optional check");
    assert_eq!(code(&s.run(&["start", "Needs extra", "--check", "extra"])), 0);
    let out = json(&s.run(&["prove", "--json"]));
    let names: Vec<&str> = out["details"]["checks"].as_array().unwrap().iter().filter_map(|c| c["check"].as_str().or(c["name"].as_str())).collect();
    assert!(names.contains(&"extra") && names.contains(&"test"), "{out}");
}

#[test]
fn the_stop_hook_proves_missing_checks_that_fit_its_budget_and_skips_unknown_ones() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"never-run\"\nrun = [\"./test.sh\"]\n"));
    s.commit_all("a check nobody ran yet");
    assert_eq!(code(&s.run(&["prove", "test"])), 0, "the test check has a known duration now");
    hook(&s, "s1", "PostToolUse", "Edit", "main.rs");
    s.write("main.rs", "fn main() { 2; }\n");
    // Check receipts only: the stop also seals the action log (D70), which is counted elsewhere.
    let checks = |s: &Sandbox| s.stored_receipts().into_iter().filter(|(_, p)| p.starts_with("receipts/") && p.split('/').nth(1).is_some_and(|subject| subject.len() == 40)).count();
    let before = checks(&s);
    let out = stop(&s, "claude-code", "s1", false);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(checks(&s), before + 1, "one fresh receipt, for the check that fits");
    let log = log_text(&s, "s1");
    assert!(log.contains("proved_at_stop") && log.contains("never-run"), "{log}");
}

#[test]
fn a_failed_check_at_stop_asks_claude_to_continue_once_and_codex_only_records_it() {
    let s = Sandbox::with_agent_hooks();
    assert_eq!(code(&s.run(&["prove", "test"])), 0);
    for session in ["s1", "s2", "s3"] {
        hook(&s, session, "PostToolUse", "Edit", "main.rs");
    }
    s.write("test.sh", "#!/bin/sh\nexit 1\n");
    let blocked = stop(&s, "claude-code", "s1", false);
    let v: Value = serde_json::from_slice(&blocked.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(&blocked)));
    assert_eq!(v["decision"], "block", "{v}");
    assert!(v["reason"].as_str().unwrap().contains("test"), "{v}");
    assert!(stop(&s, "claude-code", "s2", true).stdout.is_empty(), "the loop guard: never twice");
    s.write("main.rs", "fn main() { 4; }\n"); // a new tree, not yet proved
    let codex = s.run_with_stdin(&["hook", "codex", "Stop"], &serde_json::json!({ "session_id": "s3", "cwd": s.dir.path(), "hook_event_name": "Stop" }).to_string());
    assert!(codex.stdout.is_empty(), "{}", text(&codex));
    let log = log_text(&s, "s3");
    assert!(log.contains("proved_at_stop") && log.contains("\"failed\":[\"test\"]"), "{log}");
}

#[test]
fn the_pre_push_hook_proves_what_is_missing_before_it_gates() {
    let s = Sandbox::initialised();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["branch", "-M", "main"]);
    let push = || {
        let bin_dir = bin_dir();
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).args(["push", "origin", "main"]);
        cmd.env("PATH", format!("{bin_dir}:{}", std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("LANG", "C.UTF-8").env("COLUMNS", "100");
        cmd.output().unwrap()
    };
    assert!(push().status.success());
    s.write("main.rs", "fn main() { 3; }\n");
    s.commit_all("a change nobody proved");
    let out = push();
    assert!(out.status.success(), "the hook proves the missing check, then lets it through: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("proved"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn an_approval_counts_at_the_push_when_the_policy_file_was_never_committed() {
    // The push is held to the rules at its base. Here the base has no policy, so the push is
    // judged by 05's defaults, and an approval must be bound to those, not to the working file.
    let s = Sandbox::new();
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    s.commit_all("first");
    assert_eq!(code(&s.run(&["init"])), 0);
    let exclude = s.path(".git/info/exclude");
    fs::write(&exclude, format!("{}\n.05/policy.toml\n", fs::read_to_string(&exclude).unwrap_or_default())).unwrap();
    s.commit_all("hooks, but not the policy");
    assert!(s.git(&["ls-files", ".05"]).lines().all(|l| !l.ends_with("policy.toml")));
    let doctor = s.run(&["doctor"]);
    assert!(text(&doctor).contains("not committed"), "doctor says the policy is not the rules yet:\n{}", text(&doctor));
    s.approver();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    let push = || {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).args(["push", "origin", "main"]);
        cmd.env("PATH", format!("{}:{}", bin_dir(), std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("LANG", "C.UTF-8").env("COLUMNS", "100");
        cmd.output().unwrap()
    };
    assert!(push().status.success());
    fs::create_dir_all(s.path("migrations")).unwrap();
    s.write("migrations/001_users.sql", "create table users (id integer);\n");
    s.commit_all("a migration, which needs a person");
    let held = push();
    assert!(!held.status.success(), "a migration waits for a person: {}", String::from_utf8_lossy(&held.stderr));

    let brief = s.run(&["brief", "--tree", "HEAD"]);
    assert!(text(&brief).contains("not committed"), "the brief says the policy file is not the rules yet:\n{}", text(&brief));
    let approve = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approve), 0, "{}", text(&approve));
    let out = push();
    assert!(out.status.success(), "the approval counts at the push: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_push_held_despite_an_approval_says_why_the_approval_does_not_count() {
    // An approval given under other rules does not count. The push says so, rather than
    // claiming nobody approved.
    let s = Sandbox::initialised();
    s.approver();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    let push = || {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).args(["push", "origin", "main"]);
        cmd.env("PATH", format!("{}:{}", bin_dir(), std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("LANG", "C.UTF-8").env("COLUMNS", "100");
        cmd.output().unwrap()
    };
    assert!(push().status.success());
    // The change edits the policy and is approved here, where that edit is already the rules
    // (no task, so the base is HEAD), while the push is held to origin's.
    assert_eq!(code(&s.run(&["policy", "set", "approvals.expire_days", "3"])), 0);
    s.commit_all("shorter approvals");
    let approve = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approve), 0, "{}", text(&approve));
    let held = push();
    let said = String::from_utf8_lossy(&held.stderr).to_string();
    assert!(!held.status.success(), "{said}");
    assert!(said.contains("does not count") && said.contains("policy"), "the push says why the approval does not count:\n{said}");
}

// ----------------------------------------------------------------------------- declarations reach CI (D65)

/// A repository whose policy trusts the CI runner and this developer's machine key (role local).
fn ci_with_machine_key(trust_machine: bool) -> (Sandbox, String, TempDir) {
    let s = Sandbox::new();
    assert_eq!(code(&s.run(&["prove", "--", "./test.sh"])), 0, "creates this machine's key");
    let machine = fs::read_to_string(s.home.path().join("local.pub")).unwrap().trim().to_string();
    s.key("runner.key");
    let public = fs::read_to_string(s.path("runner.key.pub")).unwrap().trim().to_string();
    let secret = fs::read_to_string(s.path("runner.key")).unwrap().trim().to_string();
    fs::remove_file(s.path("runner.key")).unwrap();
    fs::remove_file(s.path("runner.key.pub")).unwrap();
    fs::create_dir_all(s.path(".05")).unwrap();
    let mut policy = format!("[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n\n[evidence]\naccept = [\"runner\"]\n\n[[trust.key]]\nname = \"ci\"\nrole = \"runner\"\npublic = \"{public}\"\n");
    if trust_machine {
        policy.push_str(&format!("\n[[trust.key]]\nname = \"dev laptop\"\nrole = \"local\"\npublic = \"{machine}\"\n"));
    }
    s.write(".05/policy.toml", &policy);
    s.commit_all("base");
    s.git(&["branch", "-M", "main"]);
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["push", "-q", "origin", "main"]);
    s.git(&["checkout", "-q", "-b", "feature"]);
    (s, secret, remote)
}

/// Do a declared task on this machine, then leave only what travels: commits and receipts.
fn declared_work_pushed(s: &Sandbox) {
    assert_eq!(code(&s.run(&["start", "Docs only", "--scope", "docs/**"])), 0);
    s.write("main.rs", "fn main() { 5; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["finish", "--outcome", "updated the docs"])), 0);
    s.commit_all("work");
    for branch in s.git(&["for-each-ref", "--format=%(refname:short)", "refs/heads/05-receipts/"]).lines() {
        s.git(&["push", "-q", "origin", branch]);
        s.git(&["branch", "-q", "-D", branch]);
    }
    fs::remove_dir_all(s.path(".git/05")).unwrap();
}

#[test]
fn the_ci_gate_applies_the_declaration_it_finds_for_the_tree() {
    let (s, secret, _remote) = ci_with_machine_key(true);
    declared_work_pushed(&s);
    let out = gate_ci(&s, Some(&secret), &["--json"]);
    let v = json(&out);
    assert_eq!(v["brief"]["card"]["scope"]["include"][0], "docs/**", "{v}");
    let codes: Vec<&str> = v["brief"]["gate"]["findings"].as_array().unwrap().iter().filter_map(|f| f["code"].as_str()).collect();
    assert!(codes.contains(&"SCOPE_EXCEEDED"), "{codes:?}");
    let unknowns = v["brief"]["unknowns"].to_string();
    assert!(unknowns.contains("rest on a machine key") && unknowns.contains("only known on the machine"), "{unknowns}");
}

#[test]
fn without_a_trusted_declaration_ci_says_so_under_unknowns() {
    let (s, secret, _remote) = ci_with_machine_key(false);
    declared_work_pushed(&s);
    let v = json(&gate_ci(&s, Some(&secret), &["--json"]));
    assert!(v["brief"]["card"].is_null(), "{v}");
    assert!(v["brief"]["unknowns"].to_string().contains("no trusted declaration was found for this tree"), "{v}");
}

// ----------------------------------------------------------------------------- branches, land and cleanup (D69)

/// A worktree on a new agent branch, outside the main checkout.
fn agent_worktree(s: &Sandbox, holder: &TempDir, branch: &str) -> PathBuf {
    let path = holder.path().join(branch.replace('/', "-"));
    s.git(&["worktree", "add", "-q", "-b", branch, path.to_str().unwrap()]);
    path
}

fn git_at(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(dir).args(["-c", "user.name=t", "-c", "user.email=t@example.com"]).args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn task_in(s: &Sandbox, wt: &Path, title: &str) -> String {
    let out = s.run(&["start", title, "--repo", wt.to_str().unwrap(), "--json"]);
    json(&out)["details"]["task"].as_str().unwrap_or_else(|| panic!("{}", text(&out))).to_string()
}

#[test]
fn land_fast_forwards_an_allowed_change_and_removes_its_branch_and_worktree() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/fix");
    let id = task_in(&s, &wt, "Fix it");
    fs::write(wt.join("main.rs"), "fn main() { 6; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "fix"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    let head = git_at(&wt, &["rev-parse", "HEAD"]);
    let out = s.run(&["land", "--task", &id]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(s.git(&["rev-parse", "main"]), head);
    assert!(!wt.exists(), "the worktree was removed");
    assert_eq!(s.git(&["branch", "--list", "claude/fix"]), "", "the branch was deleted");
    assert!(text(&out).contains("claude/fix → main"), "{}", text(&out));
    let holder_real = fs::canonicalize(holder.path()).unwrap().display().to_string();
    let masked = Output { status: out.status, stdout: String::from_utf8_lossy(&out.stdout).replace(&holder_real, "<WORKTREES>").into_bytes(), stderr: out.stderr.clone() };
    snapshot("land", &s, &masked);
}

#[test]
fn land_refuses_a_change_the_gate_holds_back_and_changes_nothing() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/unproved");
    let id = task_in(&s, &wt, "Unproved");
    fs::write(wt.join("main.rs"), "fn main() { 7; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "unproved"]);
    let before = s.git(&["rev-parse", "main"]);
    let out = s.run(&["land", "--task", &id]);
    assert_eq!(code(&out), 5, "{}", text(&out));
    assert_eq!(s.git(&["rev-parse", "main"]), before);
    assert!(wt.exists());
}

#[test]
fn land_refuses_when_the_target_moved_on_and_says_rebase() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/late");
    let id = task_in(&s, &wt, "Late");
    fs::write(wt.join("main.rs"), "fn main() { 8; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "late"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    s.write("other.txt", "someone else landed first\n");
    s.commit_all("main moved");
    let out = s.run(&["land", "--task", &id]);
    assert_ne!(code(&out), 0);
    assert!(text(&out).contains("rebase onto main"), "{}", text(&out));
}

#[test]
fn work_merged_elsewhere_is_cleaned_up_by_the_session_end_hook() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "codex/merged");
    let event = |name: &str| {
        let payload = serde_json::json!({ "session_id": "s1", "cwd": wt, "hook_event_name": name }).to_string();
        s.run_with_stdin(&["hook", "codex", name], &payload)
    };
    event("SessionStart");
    fs::write(wt.join("main.rs"), "fn main() { 9; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "merged elsewhere"]);
    s.git(&["merge", "-q", "--ff-only", "codex/merged"]);
    event("SessionEnd");
    assert!(!wt.exists(), "the finished session's worktree was removed");
    assert_eq!(s.git(&["branch", "--list", "codex/merged"]), "");
}

#[test]
fn with_land_auto_the_stop_hook_lands_an_allowed_change() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("land = \"manual\"", "land = \"auto\""));
    s.commit_all("land automatically");
    assert_eq!(code(&s.run(&["prove", "test"])), 0, "a known duration for the Stop hook");
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/auto");
    let payload = |event: &str| serde_json::json!({ "session_id": "s1", "cwd": wt, "hook_event_name": event, "tool_name": "Edit", "tool_input": { "file_path": wt.join("main.rs") } }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "PostToolUse"], &payload("PostToolUse"));
    fs::write(wt.join("main.rs"), "fn main() { 10; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "auto"]);
    let out = s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload("Stop"));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(s.git(&["rev-parse", "main"]), git_at(&wt, &["rev-parse", "HEAD"]), "{}", text(&out));
}

#[test]
fn policy_shows_the_branch_rules_and_the_template_explains_them() {
    let s = Sandbox::initialised();
    let shown = text(&s.run(&["policy"]));
    assert!(shown.contains("branches.keep") && shown.contains("branches.land") && shown.contains("manual"), "{shown}");
    let template = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(template.contains("[branches]") && template.contains("land = \"manual\""), "{template}");
}

#[test]
fn agents_are_told_to_declare_first_and_that_05_runs_the_checks() {
    let s = Sandbox::with_agent_hooks();
    let block = fs::read_to_string(s.path("AGENTS.md")).unwrap();
    assert!(block.contains("Before you edit, declare your plan") && block.contains("05 runs the checks itself") && block.contains("use05 land"), "{block}");
    let out = s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "SessionStart" }).to_string());
    let context = context_of(&out);
    assert!(context.contains("declare your plan") && context.contains("use05 finish") && !context.contains("run `use05 prove`"), "{context}");
    assert!(context.contains("Checks you can name with --check: test"), "the agent is told the real check names: {context}");
    assert!(block.contains("a check name from `use05 policy`"), "{block}");
}

#[test]
fn an_agent_in_a_sandbox_is_not_sent_to_commands_that_need_git_and_is_told_why_if_it_runs_one() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Sandboxed", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    let finish = s.run_env(&["finish", "--outcome", "done"], &[("CODEX_SESSION_ID", "s1")]);
    assert!(!text(&finish).contains("Next: use05 brief"), "{}", text(&finish));
    assert!(text(&finish).contains("when you stop"), "{}", text(&finish));
    // A read-only .git, as Codex's sandbox makes it: the brief cannot build the working tree.
    s.write("main.rs", "fn main() { 11; }\n");
    use std::os::unix::fs::PermissionsExt;
    let git_dir = s.path(".git");
    fs::set_permissions(&git_dir, fs::Permissions::from_mode(0o555)).unwrap();
    let brief = s.run(&["brief"]);
    fs::set_permissions(&git_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(code(&brief), 0);
    assert!(text(&brief).contains("sandbox"), "{}", text(&brief));
}

// ----------------------------------------------------------------------------- final review fixes

#[test]
fn hooks_with_no_session_id_create_no_tasks_and_never_judge_another_task() {
    let s = Sandbox::with_agent_hooks();
    assert_eq!(code(&s.run(&["start", "Someone else's task", "--scope", "docs/**"])), 0);
    let before = fs::read_dir(s.path(".git/05/tasks")).unwrap().count();
    for event in ["PreToolUse", "PostToolUse", "Stop"] {
        codex_hook(&s, "", event, "src/a.rs");
    }
    assert_eq!(fs::read_dir(s.path(".git/05/tasks")).unwrap().count(), before, "no junk tasks");
    // With no session, protection still holds.
    let out = codex_hook(&s, "", "PreToolUse", ".05/policy.toml");
    assert!(text(&out).contains("deny"), "{}", text(&out));
}

#[test]
fn the_request_is_not_kept_when_recording_is_off() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("middle = \"local\"", "middle = \"off\""));
    s.commit_all("recording off");
    let payload = serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "UserPromptSubmit", "prompt": "secret plans" }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "UserPromptSubmit"], &payload);
    assert!(task_json(&s, "s1")["request"].is_null());
}

#[test]
fn land_from_the_main_checkout_leaves_a_running_agents_worktree_alone() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/running");
    let payload = serde_json::json!({ "session_id": "live", "cwd": wt, "hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": { "file_path": wt.join("main.rs") } }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "PostToolUse"], &payload);
    fs::write(wt.join("main.rs"), "fn main() { 12; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "work"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    let id = find_task(&s, "live");
    let out = s.run(&["land", "--task", &id]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(wt.exists(), "the agent is still working there");
}

// ----------------------------------------------------------------------------- sealed action log (D70)

/// Files on the receipts branches, as `path` strings.
fn branch_files(s: &Sandbox) -> Vec<String> {
    s.stored_receipts().into_iter().map(|(_, p)| p).collect()
}

#[test]
fn the_log_is_sealed_as_the_work_happens_and_travels_with_the_receipts() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Sealed", "--scope", "main.rs"], &[("CODEX_SESSION_ID", "s1")]);
    let payload = |event: &str| serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": event, "tool_name": "Bash", "tool_input": { "command": "use05 start" } }).to_string();
    s.run_with_stdin(&["hook", "codex", "PostToolUse"], &payload("PostToolUse"));
    let id = find_task(&s, "s1");
    codex_hook(&s, "s1", "PostToolUse", "main.rs");
    s.run_with_stdin(&["hook", "codex", "Stop"], &payload("Stop"));
    let files = branch_files(&s);
    assert!(files.contains(&format!("logs/{id}.jsonl")), "{files:?}");
    let seals = files.iter().filter(|f| f.starts_with(&format!("receipts/{id}/"))).count();
    assert!(seals >= 2, "sealed at the declaration and at the stop: {files:?}");
    let branch_log = s.git(&["show", &format!("{}:logs/{id}.jsonl", s.stored_receipts()[0].0)]);
    assert!(!branch_log.contains("fn main"), "never contents");
}

fn declared_and_stopped(s: &Sandbox) -> String {
    s.run_env(&["start", "Sealed", "--scope", "main.rs"], &[("CODEX_SESSION_ID", "s1")]);
    let payload = |event: &str| serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": event, "tool_name": "Bash", "tool_input": { "command": "use05 start" } }).to_string();
    s.run_with_stdin(&["hook", "codex", "PostToolUse"], &payload("PostToolUse"));
    codex_hook(s, "s1", "PostToolUse", "main.rs");
    s.write("main.rs", "fn main() { 16; }\n");
    s.run_with_stdin(&["hook", "codex", "Stop"], &payload("Stop"));
    find_task(s, "s1")
}

#[test]
fn the_brief_says_how_strongly_the_action_log_is_sealed() {
    let s = Sandbox::with_agent_hooks();
    let id = declared_and_stopped(&s);
    let brief = text(&s.run(&["brief", "--task", &id]));
    assert!(brief.contains("anchored by this machine at"), "{brief}");
    let v = json(&s.run(&["brief", "--task", &id, "--json"]));
    assert!(v["brief"]["gate"]["log"]["hook_seals"].as_u64().unwrap() >= 2, "{v}");
}

#[test]
fn editing_a_sealed_line_of_the_log_is_caught() {
    let s = Sandbox::with_agent_hooks();
    let id = declared_and_stopped(&s);
    let path = s.path(&format!(".git/05/log/{id}.jsonl"));
    let log = fs::read_to_string(&path).unwrap();
    fs::write(&path, log.replacen("main.rs", "other.rs", 1)).unwrap();
    let brief = s.run(&["brief", "--task", &id]);
    assert!(text(&brief).contains("altered"), "{}", text(&brief));
    let v = json(&s.run(&["brief", "--task", &id, "--json"]));
    let codes: Vec<&str> = v["brief"]["gate"]["findings"].as_array().unwrap().iter().filter_map(|f| f["code"].as_str()).collect();
    assert!(codes.contains(&"LOG_ALTERED"), "{codes:?}");
    // Rewriting the whole file into a fresh, self-consistent chain does not get past the seals either.
    fs::write(&path, "").unwrap();
    use05_append_like_new(&s, &id);
    assert!(text(&s.run(&["brief", "--task", &id])).contains("altered"));
}

/// Rewrite a task's log as a brand-new chain with the same number of lines.
fn use05_append_like_new(s: &Sandbox, id: &str) {
    let mut prev = String::new();
    let mut out = String::new();
    for seq in 1..=8u64 {
        let event = serde_json::json!({ "event": "tool_done", "paths": ["innocent.rs"] });
        let t = "2026-10-30T00:00:00Z";
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, prev.as_bytes());
        sha2::Digest::update(&mut h, seq.to_string().as_bytes());
        sha2::Digest::update(&mut h, t.as_bytes());
        sha2::Digest::update(&mut h, serde_json::to_vec(&event).unwrap());
        let hash = hex::encode(sha2::Digest::finalize(h));
        out.push_str(&serde_json::json!({ "seq": seq, "t": t, "prev": prev, "event": event, "hash": hash }).to_string());
        out.push('\n');
        prev = hash;
    }
    fs::write(s.path(&format!(".git/05/log/{id}.jsonl")), out).unwrap();
}

#[test]
fn the_ci_gate_seals_the_action_log_with_the_runner_key_and_can_push_it() {
    let (s, secret, remote) = ci_with_machine_key(true);
    declared_work_pushed(&s);
    let out = gate_ci(&s, Some(&secret), &["--json", "--push"]);
    let v = json(&out);
    assert!(v["brief"]["gate"]["log"]["ci_sealed_at"].as_u64().is_some(), "{v}");
    let runner_branches = Command::new("git").arg("-C").arg(remote.path()).args(["for-each-ref", "--format=%(refname:short)", "refs/heads/05-receipts/"]).output().unwrap();
    let names = String::from_utf8_lossy(&runner_branches.stdout).to_string();
    assert!(names.lines().count() >= 2, "the developer's and the runner's receipts branches are on the remote: {names}");
}

// ----------------------------------------------------------------------------- agent identity and owner (D71)

#[test]
fn a_declaration_names_its_agent_and_an_owner_who_confirms_by_signing() {
    let s = Sandbox::with_agent_hooks();
    s.approver();
    s.run_env(&["start", "Owned", "--scope", "main.rs"], &[("CODEX_SESSION_ID", "s1"), ("CODEX_SANDBOX", "seatbelt")]);
    let payload = serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "PostToolUse", "model": "gpt-test", "tool_name": "Bash", "tool_input": { "command": "use05 start" } }).to_string();
    s.run_with_stdin(&["hook", "codex", "PostToolUse"], &payload);
    let id = find_task(&s, "s1");
    let brief = text(&s.run(&["brief", "--task", &id]));
    assert!(brief.contains("agent") && brief.contains("codex") && brief.contains("session s1") && brief.contains("model gpt-test"), "{brief}");
    assert!(brief.contains("owner") && brief.contains(", unconfirmed"), "{brief}");
    assert!(brief.contains("reported running in Codex's sandbox"), "{brief}");
    let approved = s.run_with_stdin(&["approve", "--intent", "--task", &id, "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    let brief = text(&s.run(&["brief", "--task", &id]));
    assert!(brief.contains(", signed"), "{brief}");
}

#[test]
fn without_an_approver_key_there_is_no_owner_yet() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Unowned", "--scope", "main.rs"], &[("CODEX_SESSION_ID", "s1")]);
    codex_hook(&s, "s1", "PreToolUse", "main.rs");
    let brief = text(&s.run(&["brief", "--task", &find_task(&s, "s1")]));
    assert!(brief.contains("no owner yet"), "{brief}");
}

// ----------------------------------------------------------------------------- sealed log: review fixes

/// Run the CI gate in a fresh clone of `remote`, as a CI job would.
fn ci_in_fresh_clone(remote: &Path, secret: &str) -> Output {
    let clone = tempfile::tempdir().unwrap();
    let dir = clone.path().join("repo");
    assert!(Command::new("git").args(["clone", "-q"]).arg(remote).arg(&dir).status().unwrap().success());
    assert!(Command::new("git").arg("-C").arg(&dir).args(["checkout", "-q", "feature"]).status().unwrap().success());
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(BIN)
        .current_dir(&dir)
        .args(["gate", "--ci", "--json", "--push"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.path())
        .env("USE05_HOME", home.path())
        .env("GITHUB_BASE_REF", "main")
        .env("USE05_RUNNER_KEY", secret)
        .env("GIT_AUTHOR_NAME", "ci").env("GIT_AUTHOR_EMAIL", "ci@example.com").env("GIT_COMMITTER_NAME", "ci").env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .unwrap();
    drop(clone);
    out
}

#[test]
fn every_ci_run_can_push_its_seal_not_only_the_first() {
    let (s, secret, remote) = ci_with_machine_key(true);
    declared_work_pushed(&s);
    s.git(&["push", "-q", "origin", "feature"]);
    let runner_head = || String::from_utf8_lossy(&Command::new("git").arg("-C").arg(remote.path()).args(["for-each-ref", "--format=%(objectname)", "refs/heads/05-receipts/"]).output().unwrap().stdout).to_string();
    let first = ci_in_fresh_clone(remote.path(), &secret);
    assert!(!String::from_utf8_lossy(&first.stderr).contains("could not be pushed"), "{}", text(&first));
    let after_first = runner_head();
    // A seal names the second it was made, and signatures are deterministic: within the same
    // second the second run's seal is the first one again, already on the remote. Wait, so this
    // run makes a new one that must reach the remote. (The identical case is a store unit test.)
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = ci_in_fresh_clone(remote.path(), &secret);
    assert!(!String::from_utf8_lossy(&second.stderr).contains("could not be pushed"), "{}", text(&second));
    assert_ne!(runner_head(), after_first, "the second run's seal reached the remote too: {}", text(&second));
}

#[test]
fn ci_never_countersigns_a_log_copy_nobody_trusted_wrote() {
    let (s, secret, _remote) = ci_with_machine_key(true);
    declared_work_pushed(&s);
    // Someone plants a longer, self-consistent copy of the log on a branch no trusted key signed.
    let id = s.git(&["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/05-receipts/"]);
    let _ = id;
    s.git(&["fetch", "-q", "origin", "+refs/heads/05-receipts/*:refs/remotes/origin/05-receipts/*"]);
    let branch = s.git(&["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/05-receipts/"]).lines().next().unwrap().to_string();
    let path = s.git(&["ls-tree", "-r", "--name-only", &branch]).lines().find(|l| l.starts_with("logs/")).unwrap().to_string();
    let real = s.git(&["show", &format!("{branch}:{path}")]);
    let mut prev = real.lines().last().map(|l| serde_json::from_str::<Value>(l).unwrap()["hash"].as_str().unwrap().to_string()).unwrap();
    let mut forged = format!("{real}\n");
    for seq in (real.lines().count() as u64 + 1)..=(real.lines().count() as u64 + 3) {
        let event = serde_json::json!({ "event": "tool_done", "paths": ["made-up.rs"] });
        let t = "2026-10-30T00:00:00Z";
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        for part in [prev.as_bytes(), seq.to_string().as_bytes(), t.as_bytes(), &serde_json::to_vec(&event).unwrap()] {
            sha2::Digest::update(&mut h, part);
        }
        let hash = hex::encode(sha2::Digest::finalize(h));
        forged.push_str(&format!("{}\n", serde_json::json!({ "seq": seq, "t": t, "prev": prev, "event": event, "hash": hash })));
        prev = hash;
    }
    let blob = String::from_utf8_lossy(&Command::new("git").arg("-C").arg(s.dir.path()).args(["hash-object", "-w", "--stdin"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().and_then(|mut c| { use std::io::Write; c.stdin.take().unwrap().write_all(forged.as_bytes()).unwrap(); c.wait_with_output() }).unwrap().stdout).trim().to_string();
    let index_dir = tempfile::tempdir().unwrap();
    let index = index_dir.path().join("index");
    let git_ix = |args: &[&str]| String::from_utf8_lossy(&Command::new("git").arg("-C").arg(s.dir.path()).args(args).env("GIT_INDEX_FILE", &index).output().unwrap().stdout).trim().to_string();
    git_ix(&["update-index", "--add", "--cacheinfo", &format!("100644,{blob},{path}")]);
    let tree = git_ix(&["write-tree"]);
    let commit = s.git(&["commit-tree", &tree, "-m", "planted"]);
    s.git(&["update-ref", "refs/remotes/origin/05-receipts/deadbeefdeadbeef", &commit]);
    let v = json(&gate_ci(&s, Some(&secret), &["--json"]));
    let lines = real.lines().count() as u64;
    assert!(v["brief"]["gate"]["log"]["ci_sealed_at"].as_u64().is_none_or(|n| n <= lines), "CI sealed made-up lines: {v}");
    assert!(v["brief"]["gate"]["log"]["lines"].as_u64().unwrap() <= lines, "{v}");
}

#[test]
fn the_ci_workflow_keeps_the_write_token_out_of_reach_of_the_code_it_checks() {
    let s = Sandbox::initialised();
    assert_eq!(code(&s.run(&["init", "--ci", "github"])), 0);
    let wf = fs::read_to_string(s.path(".github/workflows/05.yml")).unwrap();
    assert!(wf.contains("persist-credentials: false"), "{wf}");
    assert!(wf.contains("USE05_PUSH_TOKEN: ${{ github.token }}") && wf.contains("use05 gate --ci --push"), "{wf}");
}

#[test]
fn the_stop_hook_seals_without_copying_the_whole_log_again() {
    let s = Sandbox::with_agent_hooks();
    let id = declared_and_stopped(&s);
    let branch = s.stored_receipts()[0].0.clone();
    let before = s.git(&["rev-parse", &format!("{branch}:logs/{id}.jsonl")]);
    let payload = serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "Stop" }).to_string();
    codex_hook(&s, "s1", "PostToolUse", "main.rs");
    s.run_with_stdin(&["hook", "codex", "Stop"], &payload);
    assert_eq!(s.git(&["rev-parse", &format!("{branch}:logs/{id}.jsonl")]), before, "the copy travels at the declaration and the finish");
}

#[test]
fn a_signed_owner_is_shown_by_the_trusted_key_name_not_a_name_the_agent_wrote() {
    let s = Sandbox::with_agent_hooks();
    s.approver();
    s.run_env(&["start", "Owned", "--scope", "main.rs"], &[("CODEX_SESSION_ID", "s1")]);
    codex_hook(&s, "s1", "PreToolUse", "main.rs");
    let id = find_task(&s, "s1");
    let path = s.path(&format!(".git/05/tasks/{id}.json"));
    let mut task: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    task["owner"]["name"] = "Somebody Important".into();
    fs::write(&path, serde_json::to_vec(&task).unwrap()).unwrap();
    assert_eq!(code(&s.run_with_stdin(&["approve", "--intent", "--task", &id, "--passphrase-stdin"], "correct horse\n")), 0);
    let brief = text(&s.run(&["brief", "--task", &id]));
    assert!(!brief.contains("Somebody Important, signed"), "{brief}");
    assert!(brief.contains("you (approver)") && brief.contains(", signed"), "{brief}");
}

#[test]
fn the_ci_line_says_how_many_seals_from_where_the_work_happened_back_it() {
    let (s, secret, _remote) = ci_with_machine_key(true);
    declared_work_pushed(&s);
    let out = gate_ci(&s, Some(&secret), &[]);
    assert!(text(&out).contains("sealed by CI") && text(&out).contains("backed by 2 seal(s)"), "{}", text(&out));
}

#[test]
fn doctor_names_stale_and_unreadable_declarations_and_how_to_remove_them() {
    let s = Sandbox::with_agent_hooks();
    s.run_env(&["start", "Waiting", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s9")]);
    fs::write(s.path(".05/inbox/broken.json"), "{ not json").unwrap();
    let old = serde_json::json!({ "id": "old1", "agent": "codex", "session": "gone", "created": "2026-01-01T00:00:00Z", "entry": { "kind": "finish", "outcome": null } });
    fs::write(s.path(".05/inbox/20260101-old1.json"), old.to_string()).unwrap();
    let status = text(&s.run(&[]));
    assert!(status.contains("1 declaration is waiting"), "only the fresh one counts as waiting: {status}");
    let doctor = text(&s.run(&["doctor"]));
    assert!(doctor.contains("broken.json") && doctor.contains("cannot be read"), "{doctor}");
    assert!(doctor.contains("20260101-old1.json") && doctor.contains("older than 7 days"), "{doctor}");
    assert!(doctor.contains("\".05/inbox/broken.json\"") && doctor.contains("likely never be sealed"), "{doctor}");
}

// ----------------------------------------------------------------------------- extension points (D73)

/// A directory holding executable scripts, and a PATH that puts it first.
fn extension_bin(scripts: &[(&str, &str)]) -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in scripts {
        let path = dir.path().join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}:{}", dir.path().display(), Path::new(BIN).parent().unwrap().display(), std::env::var("PATH").unwrap());
    (dir, path)
}

#[test]
fn a_program_named_use05_dash_name_on_path_is_a_command_and_a_missing_one_says_how_to_add_it() {
    let s = Sandbox::initialised();
    let (_bin, path) = extension_bin(&[("use05-hello", "#!/bin/sh\necho \"hello $*\"\n[ -x \"$USE05_BIN\" ] && echo can-call-back\nexit 3\n")]);
    let out = s.run_env(&["hello", "a", "--b"], &[("PATH", &path)]);
    assert_eq!(code(&out), 3, "its exit code is passed through: {}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("hello a --b") && said.contains("can-call-back"), "{said}");

    let missing = s.run_env(&["nosuch"], &[("PATH", &path)]);
    assert_eq!(code(&missing), 6, "{}", text(&missing));
    assert!(text(&missing).contains("no command \"nosuch\"") && text(&missing).contains("use05-nosuch"), "{}", text(&missing));

    // A built-in command always wins over an extension of the same name.
    let (_shadow, shadow_path) = extension_bin(&[("use05-doctor", "#!/bin/sh\necho shadowed\n")]);
    assert!(!text(&s.run_env(&["doctor"], &[("PATH", &shadow_path)])).contains("shadowed"));

    let doctor = s.run_env(&["doctor"], &[("PATH", &path)]);
    assert!(text(&doctor).contains("use05 hello"), "doctor lists installed extensions:\n{}", text(&doctor));
}

#[test]
fn any_agent_can_use_the_generic_hook_and_gets_a_plain_answer() {
    let s = Sandbox::initialised();
    let hook = |event: &str, input: Value| {
        let payload = serde_json::json!({ "session_id": "g-1", "cwd": s.dir.path(), "tool_name": "edit", "tool_input": input }).to_string();
        s.run_with_stdin(&["hook", "generic", event], &payload)
    };
    let started = hook("SessionStart", Value::Null);
    assert_eq!(code(&started), 0, "{}", text(&started));
    assert!(json(&started)["context"].as_str().unwrap_or("").contains("declare your plan"), "{}", text(&started));

    let denied = hook("PreToolUse", serde_json::json!({ "path": s.path(".05/policy.toml") }));
    assert_eq!(code(&denied), 0);
    let v = json(&denied);
    assert_eq!(v["decision"], "deny", "{v}");
    assert!(v["reason"].as_str().unwrap_or("").contains("approve"), "{v}");
    assert!(v.get("hookSpecificOutput").is_none(), "no agent-specific shape: {v}");

    let fine = hook("PreToolUse", serde_json::json!({ "path": s.path("main.rs") }));
    assert!(fine.stdout.is_empty(), "nothing to say means go ahead: {}", text(&fine));

    // Its declarations are sealed by its own hook, like any agent's.
    s.run_env(&["start", "Generic work", "--scope", "src/**"], &[("USE05_SESSION_ID", "g-1")]);
    let sealed = hook("PreToolUse", serde_json::json!({ "path": s.path("src/a.rs") }));
    assert!(json(&sealed)["context"].as_str().unwrap_or("").contains("sealed your declaration"), "{}", text(&sealed));
    let task = task_json(&s, "g-1");
    assert_eq!((task["title"].as_str(), task["author"].as_str()), (Some("Generic work"), Some("agent:generic")));

    let broken = s.run_with_stdin(&["hook", "generic", "PreToolUse"], "not json");
    assert_eq!(code(&broken), 0, "it fails open");
    assert!(String::from_utf8_lossy(&broken.stderr).contains("Nothing was blocked"));
}

#[test]
fn event_extensions_hear_what_happened_without_contents_and_never_hold_it_up() {
    let s = Sandbox::with_agent_hooks();
    let heard = s.home.path().join("heard.jsonl");
    let config = format!(
        "[[on]]\nevents = [\"sealed\", \"finished\"]\nrun = [\"/bin/sh\", \"-c\", \"cat >> '{h}'; echo >> '{h}'\"]\n\n[[on]]\nevents = [\"sealed\"]\nrun = [\"/bin/sh\", \"-c\", \"sleep 30\"]\ntimeout_secs = 1\n\n[[on]]\nevents = [\"sealed\"]\nrun = [\"/nonexistent/program\"]\n",
        h = heard.display()
    );
    fs::write(s.home.path().join("extensions.toml"), config).unwrap();
    s.run_env(&["start", "Cap retries", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    let clock = std::time::Instant::now();
    let out = codex_hook(&s, "s1", "PreToolUse", "src/a.rs");
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(clock.elapsed().as_secs() < 10, "a slow extension is cut off");
    s.run_env(&["finish", "--outcome", "Raised the cap to five"], &[("CODEX_SESSION_ID", "s1")]);
    codex_hook(&s, "s1", "PreToolUse", "src/a.rs");

    let all = fs::read_to_string(&heard).unwrap();
    let events: Vec<Value> = all.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    let id = find_task(&s, "s1");
    assert_eq!(events.iter().map(|e| e["event"].as_str().unwrap()).collect::<Vec<_>>(), ["sealed", "finished"], "{all}");
    assert!(events.iter().all(|e| e["task"] == id.as_str() && e["agent"] == "codex"), "{all}");
    assert!(!all.contains("Cap retries") && !all.contains("Raised the cap"), "titles and outcomes are not sent: {all}");

    // An unreadable file is a problem doctor names; work still goes on.
    fs::write(s.home.path().join("extensions.toml"), "[[on]\n").unwrap();
    assert!(text(&s.run(&["doctor"])).contains("extensions.toml"));
}

fn listen(s: &Sandbox, events: &str) -> PathBuf {
    let heard = s.home.path().join("heard.jsonl");
    let config = format!("[[on]]\nevents = [{events}]\nrun = [\"/bin/sh\", \"-c\", \"cat >> '{h}'; echo >> '{h}'\"]\n", h = heard.display());
    fs::write(s.home.path().join("extensions.toml"), config).unwrap();
    heard
}

fn heard(path: &Path) -> Vec<Value> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn event_extensions_hear_a_landing_and_a_gate_decision() {
    let s = Sandbox::initialised();
    let heard_at = listen(&s, "\"landed\", \"gate\"");
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/fix");
    let id = task_in(&s, &wt, "Fix it");
    fs::write(wt.join("main.rs"), "fn main() { 6; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "fix"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    assert_eq!(code(&s.run(&["land", "--task", &id])), 0);
    let landed = heard(&heard_at);
    assert_eq!(landed.len(), 1, "{landed:?}");
    assert_eq!((landed[0]["event"].as_str(), landed[0]["task"].as_str(), landed[0]["target"].as_str()), (Some("landed"), Some(id.as_str()), Some("main")));

    let remote = tempfile::tempdir().unwrap();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote.path().display().to_string()]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote.path().display().to_string()]);
    let push = || {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).args(["push", "-q", "origin", "main"]);
        cmd.env("PATH", format!("{}:{}", Path::new(BIN).parent().unwrap().display(), std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path());
        cmd.output().unwrap()
    };
    push();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.commit_all("loosen the rules");
    assert!(!push().status.success());
    let gate: Vec<Value> = heard(&heard_at).into_iter().filter(|e| e["event"] == "gate").collect();
    assert_eq!(gate.len(), 1, "{gate:?}");
    assert_eq!((gate[0]["where"].as_str(), gate[0]["decision"].as_str()), (Some("pre-push"), Some("approval_required")), "{}", gate[0]);
    assert!(gate[0]["findings"].as_array().is_some_and(|f| f.iter().any(|c| c == "PROTECTED_PATH")), "{}", gate[0]);
}

#[test]
fn in_ci_the_change_under_test_cannot_choose_a_listener_and_listeners_never_see_the_runner_key() {
    let (s, secret, _remote) = ci_fixture();
    let ci_home = tempfile::tempdir().unwrap();
    let h = ci_home.path().display().to_string();
    // The runner's owner listens for gate decisions, and records the listener's environment.
    fs::write(ci_home.path().join("extensions.toml"), format!("[[on]]\nevents = [\"gate\"]\nrun = [\"/bin/sh\", \"-c\", \"env > '{h}/env.txt'\"]\n")).unwrap();
    // The change's own test tries to swap in a listener of its choosing.
    s.write("test.sh", &format!("#!/bin/sh\nprintf '[[on]]\\nevents = [\"gate\"]\\nrun = [\"/bin/sh\", \"-c\", \"touch {h}/planted\"]\\n' > '{h}/extensions.toml'\necho all good\n"));
    s.commit_all("a test that does more than test");
    let mut cmd = s.command(&["gate", "--ci"]);
    cmd.env("USE05_HOME", ci_home.path()).env("HOME", ci_home.path()).env("GITHUB_BASE_REF", "main").env("USE05_RUNNER_KEY", &secret).env("USE05_PUSH_TOKEN", "t0ken").stdin(Stdio::null());
    let out = cmd.output().unwrap();
    assert!(fs::read_to_string(ci_home.path().join("extensions.toml")).unwrap().contains("planted"), "the test did rewrite the file: {}", text(&out));
    assert!(!ci_home.path().join("planted").exists(), "the listener chosen by the change must not run");
    let env = fs::read_to_string(ci_home.path().join("env.txt")).unwrap_or_else(|_| panic!("the owner's listener ran: {}", text(&out)));
    assert!(!env.contains("USE05_RUNNER_KEY") && !env.contains("t0ken") && !env.contains(&secret), "{env}");
}

#[test]
fn an_event_extension_must_name_its_program_by_absolute_path() {
    let s = Sandbox::with_agent_hooks();
    fs::create_dir_all(s.path("bin")).unwrap();
    s.write("bin/notify", &format!("#!/bin/sh\ntouch '{}/ran'\n", s.home.path().display()));
    fs::set_permissions(s.path("bin/notify"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    fs::write(s.home.path().join("extensions.toml"), "[[on]]\nevents = [\"sealed\"]\nrun = [\"bin/notify\"]\n").unwrap();
    s.run_env(&["start", "Cap retries", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    codex_hook(&s, "s1", "PreToolUse", "src/a.rs");
    assert!(!s.home.path().join("ran").exists(), "a relative path would run the repository's own file");
    let doctor = text(&s.run(&["doctor"]));
    assert!(doctor.contains("absolute path"), "{doctor}");
}

#[test]
fn the_ci_workflow_gates_every_pushed_branch_so_a_change_can_land_without_a_pull_request() {
    let s = Sandbox::initialised();
    assert_eq!(code(&s.run(&["init", "--ci", "github"])), 0);
    let wf = fs::read_to_string(s.path(".github/workflows/05.yml")).unwrap();
    // An agent's branch is gated when it is pushed; landing fast-forwards that same, already
    // checked commit onto main, so a protected main accepts it with no pull request.
    assert!(wf.contains("  push:\n    branches-ignore: [\"05-receipts/**\"]\n"), "{wf}");
    assert!(!wf.contains("branches: [main]"), "pushes to every branch are gated, not only main: {wf}");
    assert!(wf.contains("  pull_request:\n"), "pull requests still work: {wf}");
}

/// A sandbox with agent hooks whose session `sess-big0001` has sealed a declaration with this scope.
fn with_sealed_scope(scope: &str) -> Sandbox {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "sess-big0001", "Rewrite billing", scope);
    assert_eq!(task_json(&s, "sess-big0001")["intent"]["scope"]["include"][0], scope);
    s
}

/// `n` files of `lines` lines each under `dir`.
fn write_many(s: &Sandbox, dir: &str, n: usize, lines: usize) {
    fs::create_dir_all(s.path(dir)).unwrap();
    let body: String = (0..lines).map(|i| format!("line {i}\n")).collect();
    for i in 0..n {
        s.write(&format!("{dir}/f{i}.rs"), &body);
    }
}

#[test]
fn a_large_change_gets_a_bounded_brief_grouped_by_area() {
    let s = with_sealed_scope("src/billing/**");
    write_many(&s, "src/billing", 300, 100);
    write_many(&s, "src/ui", 120, 10);
    s.git(&["add", "-A"]);
    let brief = s.run(&["brief"]);
    let out = text(&brief);
    assert!(out.lines().count() < 60, "{out}");
    assert!(out.contains("src/billing/") && out.contains("src/ui/"), "{out}");
    assert!(out.contains("120 files outside the declared scope"), "{out}");
    assert!(out.contains("+31,"), "a comma-grouped total: {out}");
    let v = json(&s.run(&["brief", "--json"]));
    assert!(v["brief"]["added"].as_u64().unwrap() > 30_000, "{v}");
    assert_eq!(v["brief"]["outside_scope_areas"][0]["name"], "src/ui/");
    // `areas` keeps the shape 0.0.2 printed, [name, files] by top-level folder; the detail is new.
    assert_eq!(v["brief"]["areas"][0], serde_json::json!(["src", 420]), "{}", v["brief"]["areas"]);
    assert_eq!(v["brief"]["area_summary"][0]["name"], "src/billing/");
}

#[test]
fn every_refusal_in_the_log_says_why() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("[protect]\n", "[protect]\nno_read = [\".env*\"]\n", 1));
    s.write(".env", "TOKEN=x\n");
    s.commit_all("do not read .env");
    declare(&s, "sess-why0001", "Billing", "src/**");
    let hook = |tool: &str, input: Value| {
        let payload = serde_json::json!({ "session_id": "sess-why0001", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input }).to_string();
        s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload)
    };
    hook("Bash", serde_json::json!({ "command": "git push --force origin main" }));
    hook("Read", serde_json::json!({ "file_path": s.path(".env") }));
    hook("Edit", serde_json::json!({ "file_path": s.path(".05/policy.toml"), "old_string": "a", "new_string": "b" }));
    hook("Edit", serde_json::json!({ "file_path": s.path("docs/x.md"), "old_string": "a", "new_string": "b" }));
    let whys: Vec<String> = log_text(&s, "sess-why0001")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|l| l["event"].clone())
        .filter(|e| e["event"] == "tool" && (e["decision"] == "deny" || e["decision"] == "ask"))
        .map(|e| e["why"].as_str().unwrap_or("(none)").to_string())
        .collect();
    assert_eq!(whys, ["risky command", "do not read", "protected path", "outside scope"]);
}

fn subagent_hook(s: &Sandbox, event: &str, extra: Value) -> Output {
    let mut payload = serde_json::json!({ "session_id": "sess-sub0001", "cwd": s.dir.path(), "hook_event_name": event });
    for (k, v) in extra.as_object().unwrap() {
        payload[k] = v.clone();
    }
    s.run_with_stdin(&["hook", "claude-code", event], &payload.to_string())
}

#[test]
fn a_subagent_is_briefed_on_the_rules_when_it_starts() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "sess-sub0001", "Billing", "src/billing/**");
    let out = subagent_hook(&s, "SubagentStart", serde_json::json!({ "agent_id": "a-1", "agent_type": "Explore" }));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SubagentStart", "{}", text(&out));
    let context = v["hookSpecificOutput"]["additionalContext"].as_str().unwrap_or("");
    assert!(context.contains("Protected paths need a person's approval") && context.contains("src/billing/**"), "{context}");
}

#[test]
fn a_codex_subagent_is_briefed_on_the_rules_too() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "sess-sub0001", "Billing", "src/billing/**");
    let payload = serde_json::json!({ "session_id": "sess-sub0001", "cwd": s.dir.path(), "hook_event_name": "SubagentStart", "agent_id": "c-1", "agent_type": "worker" }).to_string();
    let out = s.run_with_stdin(&["hook", "codex", "SubagentStart"], &payload);
    assert!(context_of(&out).contains("src/billing/**"), "{}", text(&out));
}

#[test]
fn subagent_actions_are_logged_under_the_parent_task_with_their_agent() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "sess-sub0001", "Billing", "src/**");
    let edit = |path: &str| serde_json::json!({ "tool_name": "Edit", "tool_input": { "file_path": s.path(path), "old_string": "a", "new_string": "b" } });
    subagent_hook(&s, "PreToolUse", edit("src/main.rs"));
    let mut sub = edit("src/lib.rs");
    sub["agent_id"] = serde_json::json!("a-1");
    sub["agent_type"] = serde_json::json!("Explore");
    subagent_hook(&s, "PreToolUse", sub);
    subagent_hook(&s, "SubagentStop", serde_json::json!({ "agent_id": "a-1", "agent_type": "Explore", "stop_hook_active": false, "last_assistant_message": "listed it" }));
    assert_eq!(fs::read_dir(s.path(".git/05/tasks")).unwrap().count(), 1, "one task for the session and its subagent");
    let events: Vec<Value> = log_text(&s, "sess-sub0001").lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).map(|l| l["event"].clone()).collect();
    let tool = |path: &str| events.iter().find(|e| e["event"] == "tool" && e["paths"][0] == path).cloned().unwrap_or(Value::Null);
    assert!(tool("src/main.rs")["agent_id"].is_null(), "{events:?}");
    assert_eq!(tool("src/lib.rs")["agent_id"], "a-1", "{events:?}");
    assert_eq!(tool("src/lib.rs")["agent_type"], "Explore", "{events:?}");
    let stop = events.iter().find(|e| e["event"] == "subagent_stop").unwrap_or_else(|| panic!("no subagent_stop: {events:?}"));
    assert_eq!(stop["agent_id"], "a-1");
}

#[test]
fn the_brief_digests_the_session() {
    let s = Sandbox::with_agent_hooks();
    declare(&s, "sess-dig0001", "Billing", "src/**");
    let hook = |event: &str, extra: Value| {
        let mut payload = serde_json::json!({ "session_id": "sess-dig0001", "cwd": s.dir.path(), "hook_event_name": event });
        for (k, v) in extra.as_object().unwrap() {
            payload[k] = v.clone();
        }
        s.run_with_stdin(&["hook", "claude-code", event], &payload.to_string())
    };
    hook("PreToolUse", serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": "git push --force origin main" } }));
    hook("PreToolUse", serde_json::json!({ "tool_name": "Edit", "tool_input": { "file_path": s.path("src/a.rs"), "old_string": "a", "new_string": "b" }, "agent_id": "a-1", "agent_type": "Explore" }));
    hook("Stop", serde_json::json!({ "stop_hook_active": false, "last_assistant_message": "Done." }));
    let id = find_task(&s, "sess-dig0001");
    let brief = s.run(&["brief", "--task", &id]);
    let out = text(&brief);
    assert!(out.contains("Session") && out.contains("refused 1: risky command 1") && out.contains("subagents 1: Explore 1"), "{out}");
    assert!(out.contains("under a minute") && !out.contains("0 min"), "{out}");
    // Work done through the shell has no paths in the log, so "0 files touched" would mislead.
    assert!(!out.contains("0 files touched"), "{out}");
    let v = json(&s.run(&["brief", "--task", &id, "--json"]));
    assert!(v["brief"]["session"]["tool_calls"].as_u64().unwrap_or(0) >= 2, "{v}");
}

#[test]
fn a_fifty_thousand_line_change_briefs_in_seconds_and_stays_bounded() {
    let s = with_sealed_scope("src/billing/**");
    // 700 files and 50,000 lines over six areas; 150 files land outside the declared scope.
    for (dir, n) in [("src/billing", 300), ("src/billing/retry", 100), ("src/billing/ledger", 150), ("src/ui", 80), ("src/auth", 40), ("tests", 30)] {
        write_many(&s, dir, n, 72);
    }
    s.git(&["add", "-A"]);
    let started = std::time::Instant::now();
    let brief = s.run(&["brief"]);
    let took = started.elapsed();
    let out = text(&brief);
    assert!(took < std::time::Duration::from_secs(5), "took {took:?}");
    assert!(out.lines().count() < 60, "{} lines:\n{out}", out.lines().count());
    assert!(out.contains("150 files outside the declared scope"), "{out}");
    let v = json(&s.run(&["brief", "--json"]));
    assert!(v["brief"]["added"].as_u64().unwrap() >= 50_000, "{}", v["brief"]["added"]);
}

#[test]
fn a_project_level_npm_install_writes_hooks_that_find_it() {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".claude")).unwrap();
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    // Laid out as npm does: the platform package's binary, linked from node_modules/.bin.
    let pkg = s.path("node_modules/@use05/cli-test/bin");
    fs::create_dir_all(&pkg).unwrap();
    fs::copy(BIN, pkg.join("use05")).unwrap();
    fs::create_dir_all(s.path("node_modules/.bin")).unwrap();
    std::os::unix::fs::symlink("../@use05/cli-test/bin/use05", s.path("node_modules/.bin/use05")).unwrap();
    s.write(".gitignore", "node_modules/\n");
    s.commit_all("first");
    // No use05 on PATH: only git and the shell.
    let git_dir = std::env::var("PATH").unwrap().split(':').find(|d| Path::new(d).join("git").is_file()).unwrap().to_string();
    let path = format!("/usr/bin:/bin:{git_dir}");
    let local = |program: &str, args: &[&str]| {
        let mut cmd = Command::new(program);
        cmd.current_dir(s.dir.path()).args(args).env_clear().env("PATH", &path).env("HOME", s.home.path()).env("USE05_HOME", s.home.path()).env("LANG", "C.UTF-8");
        if let Ok(d) = std::env::var("DEVELOPER_DIR") {
            cmd.env("DEVELOPER_DIR", d);
        }
        cmd
    };
    let init = local(s.path("node_modules/.bin/use05").to_str().unwrap(), &["init"]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(code(&init), 0, "{}", text(&init));

    let settings: Value = serde_json::from_str(&fs::read_to_string(s.path(".claude/settings.local.json")).unwrap()).unwrap();
    let command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"].as_str().unwrap().to_string();
    assert!(command.contains("node_modules/.bin") && command.contains("use05 hook claude-code PreToolUse"), "{command}");
    // The hook, run the way the agent runs it, finds the project's copy and refuses a force push.
    let payload = serde_json::json!({ "session_id": "sess-npm0001", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push --force origin main" } }).to_string();
    let mut child = local("/bin/sh", &["-c", &command]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), payload.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(text(&out).contains("\"deny\""), "{}", text(&out));
    // The pre-push hook finds it too.
    let pre_push = fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap();
    assert!(pre_push.contains("node_modules/.bin"), "{pre_push}");
}

#[test]
fn an_allowed_action_carries_no_refusal_reason() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("scope = \"warn\"", "scope = \"allow\"", 1));
    s.commit_all("scope drift allowed");
    declare(&s, "sess-allow001", "Billing", "src/**");
    let payload = serde_json::json!({ "session_id": "sess-allow001", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": { "file_path": s.path("docs/x.md"), "old_string": "a", "new_string": "b" } }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
    let line = log_text(&s, "sess-allow001").lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).map(|l| l["event"].clone()).find(|e| e["event"] == "tool" && e["paths"][0] == "docs/x.md").unwrap();
    assert_eq!(line["decision"], "allow", "{line}");
    assert!(line["why"].is_null(), "{line}");
}

// ----------------------------------------------------------------------------- guided setup (D82)

/// A repository with long-lived branches main, uat and production, not yet set up.
fn with_environment_branches() -> Sandbox {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".claude")).unwrap();
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    s.write("LICENSE", "Apache-2.0\n");
    s.commit_all("first");
    s.git(&["branch", "uat"]);
    s.git(&["branch", "production"]);
    s
}

fn policy_of(s: &Sandbox) -> use05_core::policy::Policy {
    use05_core::policy::Policy::parse(&fs::read_to_string(s.path(".05/policy.toml")).unwrap()).unwrap()
}

#[test]
fn guided_init_asks_about_the_team_branches_and_rules_and_writes_the_answers() {
    let s = with_environment_branches();
    // team: small; lands on: main; main=dev, uat=uat, production=prod; keep checks; add lint;
    // protected: none; locked: LICENSE; append-only: none; do-not-read: none; docs: none;
    // outside plan, weakened tests, fresh base, landing: defaults; write: yes.
    let answers = "2\n\n\n\n\n\n\nlint: npm run lint\n\n\nLICENSE\n\n\n\n\n\n\n\n\n";
    let out = s.run_with_stdin(&["init", "--guided"], answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("Who works in this repository?") && shown.contains("Which environment is"), "{shown}");
    assert!(shown.contains("created .05/policy.toml with your answers") && !shown.contains("> []"), "{shown}");
    let p = policy_of(&s);
    let envs: Vec<(String, String)> = p.environment.iter().map(|e| (e.name.clone(), e.branch.clone())).collect();
    assert_eq!(envs, [("dev".into(), "main".into()), ("uat".into(), "uat".into()), ("prod".into(), "production".into())]);
    assert_eq!(p.intent.mode, use05_core::policy::IntentMode::Risky, "the small-team preset");
    assert_eq!(p.drift.scope, use05_core::policy::Severity::Approval);
    assert_eq!(p.check.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["test", "lint"]);
    assert_eq!(p.protect.locked, ["LICENSE"]);
    assert_eq!(p.branches.target.as_deref(), Some("main"));
    assert!(fs::read_to_string(s.path(".05/policy.toml")).unwrap().contains("# files outside the declared scope"), "the template's comments stay");
}

#[test]
fn policy_edit_changes_an_existing_setup_and_says_how_the_change_takes_effect() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    s.commit_all("05");
    // keep the current rules; lands on main; environments: defaults; checks kept, none added;
    // paths and docs: defaults; outside plan: refuse; tests, fresh base: default; landing:
    // automatic; write: yes.
    let answers = "\n\n\n\n\n\n\n\n\n\n\n\n\n4\n\n\n2\n\n";
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    assert_eq!(p.drift.scope, use05_core::policy::Severity::Deny);
    assert_eq!(p.branches.land, use05_core::policy::LandMode::Auto);
    assert!(text(&out).contains("use05 approve --outcome"), "a policy change is approved like any protected change: {}", text(&out));
}

#[test]
fn stopping_part_way_through_changes_nothing() {
    let s = with_environment_branches();
    let out = s.run_with_stdin(&["init", "--guided"], "2\n");
    assert_ne!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("nothing was changed"), "{}", text(&out));
    assert!(!s.path(".05/policy.toml").exists());
}

#[test]
fn init_takes_the_answers_as_flags_without_asking() {
    let s = with_environment_branches();
    let out = s.run(&["init", "--team", "regulated", "--target", "main", "--env", "dev=main", "--env", "prod=production"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!text(&out).contains("Who works"), "{}", text(&out));
    let p = policy_of(&s);
    assert_eq!(p.environment.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["dev", "prod"]);
    assert_eq!((p.approvals.min, p.drift.tests), (2, use05_core::policy::Severity::Deny));
}

#[test]
fn environments_show_in_the_status_and_the_brief_says_where_a_change_lands() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--target", "main", "--env", "dev=main", "--env", "uat=uat", "--env", "prod=production"])), 0);
    s.commit_all("05");
    let status = text(&s.run(&[]));
    assert!(status.contains("Environments") && status.contains("dev: main (") && status.contains("prod: production ("), "{status}");
    s.write("main.rs", "fn main() { println!(\"hi\"); }\n");
    s.git(&["add", "-A"]);
    let brief = text(&s.run(&["brief"]));
    assert!(brief.contains("lands on main (dev)"), "{brief}");
}

#[test]
fn environments_added_to_an_older_policy_raise_its_minimum_version() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    let p = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let older: String = p.replace(&format!("min_version = \"{}\"", env!("CARGO_PKG_VERSION")), "min_version = \"0.0.2\"").lines().filter(|l| !l.starts_with("fresh_base")).map(|l| format!("{l}\n")).collect();
    s.write(".05/policy.toml", &older);
    assert_eq!(code(&s.run(&["policy", "--edit", "--env", "dev=main"])), 0);
    let text = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(text.contains("min_version = \"0.0.4\""), "an older use05 must be told to upgrade, not fail to parse:\n{text}");
}

#[test]
fn pressing_enter_through_an_edit_changes_nothing() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    s.git(&["branch", "qa"]);
    let p = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{}\n[[environment]]\nname = \"staging\"\nbranch = \"qa\"\n", p.replace("tests = \"approval\"", "tests = \"allow\"")));
    let before = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], &"\n".repeat(40));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(fs::read_to_string(s.path(".05/policy.toml")).unwrap(), before, "{}", text(&out));
}

#[test]
fn two_branches_never_share_a_role_without_being_told() {
    let s = with_environment_branches();
    s.git(&["branch", "develop"]);
    let out = s.run_with_stdin(&["init", "--guided"], &"\n".repeat(40));
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    let dev: Vec<&str> = p.environment.iter().filter(|e| e.name == "dev").map(|e| e.branch.as_str()).collect();
    assert_eq!(dev.len(), 1, "{:?}", p.environment);
    let skipped = if dev[0] == "main" { "develop" } else { "main" };
    assert!(!p.environment.iter().any(|e| e.branch == skipped), "{:?}", p.environment);
    // The question for the second one did not offer dev as its default.
    assert!(text(&out).contains("dev is already"), "{}", text(&out));
}

#[test]
fn with_no_remote_the_landing_branch_defaults_to_the_current_one() {
    let s = Sandbox::new();
    s.git(&["checkout", "-q", "-b", "master"]);
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    s.commit_all("first");
    let out = s.run_with_stdin(&["init", "--guided"], &"\n".repeat(40));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(policy_of(&s).branches.target.as_deref(), Some("master"));
}

#[test]
fn an_organisation_rule_stricter_than_an_answer_is_named() {
    let s = with_environment_branches();
    s.key("org.key");
    s.write("floor.toml", "drift_scope = \"deny\"\n");
    assert_eq!(code(&s.run(&["policy", "org-sign", "floor.toml", "--org", "Acme", "--key", "org.key", "--out", "org.json"])), 0);
    fs::copy(s.path("org.json"), s.home.path().join("org.json")).unwrap();
    fs::copy(s.path("org.key.pub"), s.home.path().join("org.pub")).unwrap();
    let out = s.run(&["init", "--team", "solo"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("Acme") && text(&out).contains("refuse"), "the person is told the organisation's rule applies: {}", text(&out));
}

#[test]
fn only_branches_that_look_long_lived_are_asked_about() {
    let s = with_environment_branches();
    for i in 0..30 {
        s.git(&["branch", &format!("feature/f{i}")]);
    }
    let out = s.run_with_stdin(&["init", "--guided"], &"\n".repeat(40));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!text(&out).contains("feature/f1"), "{}", text(&out));
    assert!(text(&out).contains("30 other branches"), "{}", text(&out));
}

#[test]
fn policy_answer_flags_need_edit() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    assert_ne!(code(&s.run(&["policy", "--team", "regulated"])), 0, "a flag that would be ignored is refused");
}

#[test]
fn bad_answers_to_write_this_do_not_write() {
    let s = with_environment_branches();
    let mut answers = "\n".repeat(15);
    answers.push_str("quit\nquit\nquit\n");
    let out = s.run_with_stdin(&["init", "--guided"], &answers);
    assert!(!s.path(".05/policy.toml").exists(), "{}", text(&out));
}

#[test]
fn a_level_can_hold_several_environments_and_any_branch_can_be_one() {
    let s = with_environment_branches();
    s.git(&["branch", "dev"]);
    s.git(&["branch", "eu-main"]);
    // team; landing main; dev=dev (suggested); main: dev again, named dev-main by default;
    // uat=uat; production=prod; add eu-main: name dev-eu, level dev; finish; the rest defaults.
    let answers = "\n\n\n1\n\n\n\neu-main\ndev-eu\n1\n\n".to_string() + &"\n".repeat(14);
    let out = s.run_with_stdin(&["init", "--guided"], &answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    let envs: Vec<(String, String, Option<&str>)> = p.environment.iter().map(|e| (e.name.clone(), e.branch.clone(), e.level())).collect();
    assert_eq!(envs, [
        ("dev".into(), "dev".into(), Some("dev")),
        ("dev-main".into(), "main".into(), Some("dev")),
        ("dev-eu".into(), "eu-main".into(), Some("dev")),
        ("uat".into(), "uat".into(), Some("uat")),
        ("prod".into(), "production".into(), Some("prod")),
    ], "{}", text(&out));
    let min = policy_of(&s).use05.min_version.unwrap();
    assert!(!use05_core::policy::version_below(&min, "0.0.5"), "levels need 0.0.5 or newer: {min}");
    let status = text(&s.run(&[]));
    assert!(status.contains("dev: dev (") && status.contains(", dev-eu: eu-main (") && status.contains("→ uat: uat"), "{status}");
}

#[test]
fn env_flags_take_a_level_for_names_that_are_not_one() {
    let s = with_environment_branches();
    assert_ne!(code(&s.run(&["init", "--env", "dev-eu=main"])), 0, "a name that is not a level needs one");
    let out = s.run(&["init", "--env", "dev=main", "--env", "dev-eu=uat:dev", "--env", "prod=production"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(policy_of(&s).environment[1].level.as_deref(), Some("dev"));
}

/// Press Enter through `policy --edit` and assert the file did not change.
fn enter_through_edit_keeps(s: &Sandbox) {
    let before = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], &"\n".repeat(60));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(fs::read_to_string(s.path(".05/policy.toml")).unwrap(), before, "{}", text(&out));
}

#[test]
fn an_edit_keeps_environments_that_share_a_level_in_their_order() {
    let s = with_environment_branches();
    for b in ["zeta", "alpha", "dev"] {
        s.git(&["branch", b]);
    }
    assert_eq!(code(&s.run(&["init", "--env", "dev=dev", "--env", "zeta=zeta:dev", "--env", "alpha=alpha:dev", "--env", "prod=production"])), 0);
    enter_through_edit_keeps(&s);
}

#[test]
fn an_edit_keeps_a_0_0_4_environment_with_a_custom_name_and_no_level() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    let p = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{p}\n[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"staging\"\nbranch = \"uat\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"production\"\n"));
    enter_through_edit_keeps(&s);
    s.commit_all("envs");
    let status = text(&s.run(&[]));
    let (dev, staging, prod) = (status.find("dev: main").unwrap(), status.find("staging: uat").unwrap(), status.find("prod: production").unwrap());
    assert!(dev < staging && staging < prod, "file order for a name with no level: {status}");
}

#[test]
fn an_edit_of_a_policy_without_environments_adds_none() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    enter_through_edit_keeps(&s);
}

#[test]
fn a_suggested_name_never_collides_with_an_environment_asked_about_later() {
    let s = with_environment_branches();
    s.git(&["branch", "dev"]);
    s.git(&["branch", "release"]);
    assert_eq!(code(&s.run(&["init", "--env", "dev=dev", "--env", "dev-main=release:dev"])), 0);
    // main: dev (a second dev environment, suggested name), then Enter everywhere.
    let mut answers = String::new();
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], &{
        // team, landing, then the branches in file order: dev, release; then main (new).
        answers.push_str("\n\n\n\n1\n");
        answers.push_str(&"\n".repeat(55));
        answers
    });
    assert_eq!(code(&out), 0, "{}", text(&out));
    let names: Vec<String> = policy_of(&s).environment.iter().map(|e| e.name.clone()).collect();
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "{names:?}");
}

#[test]
fn the_review_says_what_the_scope_choice_does_and_long_paths_are_not_cut() {
    let s = with_environment_branches();
    let long = "infra/terraform/environments/production-europe-west/customer-facing/**";
    // team, landing, envs x3, add none, keep checks, add none, protected = long, locked, append,
    // no-read, docs, scope = 2 (ask me), tests, fresh base, land, write.
    let answers = format!("\n\n\n\n\n\n\n\n{long}\n\n\n\n\n2\n\n\n\n\n");
    let out = s.run_with_stdin(&["init", "--guided"], &answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let review = text(&out);
    let review = &review[review.find("7/7").unwrap()..];
    let words = review.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("let it, but ask me before each edit outside the plan"), "{review}");
    let joined: String = review.split_whitespace().collect();
    assert!(joined.contains(&long.replace(' ', "")) && !review.contains('…') && !review.contains('~'), "{review}");
}

#[test]
fn env_flags_infer_a_level_from_a_common_name() {
    let s = with_environment_branches();
    let out = s.run(&["init", "--env", "dev=main", "--env", "staging=uat", "--env", "prod=production"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(policy_of(&s).environment[1].level(), Some("uat"));
}

// ---------------------------------------------------------------- fresh base and files that change together

/// A bare `origin` the sandbox pushes main to, and a way for someone else to land commits there.
struct Origin {
    bare: TempDir,
}

impl Origin {
    fn for_sandbox(s: &Sandbox) -> Origin {
        let bare = tempfile::tempdir().unwrap();
        let ok = Command::new("git").args(["init", "-q", "--bare", "-b", "main"]).arg(bare.path()).status().unwrap();
        assert!(ok.success());
        s.git(&["remote", "add", "origin", bare.path().to_str().unwrap()]);
        s.git(&["push", "-q", "origin", "main"]);
        s.git(&["remote", "set-head", "origin", "main"]);
        Origin { bare }
    }

    /// Someone else lands `n` commits on origin's main.
    fn someone_lands(&self, n: usize) {
        let clone = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let out = Command::new("git").arg("-C").arg(clone.path()).args(["-c", "user.name=o", "-c", "user.email=o@example.com", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        };
        git(&["clone", "-q", self.bare.path().to_str().unwrap(), "."]);
        let landed = fs::read_dir(clone.path()).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("upstream")).count();
        for i in landed..landed + n {
            fs::write(clone.path().join(format!("upstream{i}.txt")), format!("{i}\n")).unwrap();
            git(&["add", "-A"]);
            git(&["commit", "-q", "-m", &format!("upstream {i}")]);
        }
        git(&["push", "-q", "origin", "main"]);
    }
}

fn set_policy(s: &Sandbox, extra: &str) {
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n{extra}\n"));
    s.commit_all("policy");
}

fn start_session(s: &Sandbox, session: &str) -> Output {
    let out = s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": session, "cwd": s.dir.path(), "hook_event_name": "SessionStart", "source": "startup" }).to_string());
    assert_eq!(code(&out), 0, "{}", text(&out));
    out
}

#[test]
fn an_agent_that_starts_behind_origin_is_told_and_its_brief_says_so_until_it_updates() {
    let s = Sandbox::initialised();
    // The template tells the agent (warn); hold the change here instead.
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(policy.contains("fresh_base = \"warn\""), "{policy}");
    s.write(".05/policy.toml", &policy.replacen("fresh_base = \"warn\"", "fresh_base = \"approval\"", 1));
    s.commit_all("policy");
    let origin = Origin::for_sandbox(&s);
    origin.someone_lands(2);

    let started = context_of(&start_session(&s, "behind"));
    assert!(started.contains("2 commits behind origin/main") && started.contains("git pull --rebase origin main"), "{started}");
    let task = find_task(&s, "behind");

    s.write("main.rs", "fn main() { /* the agent's work */ }\n");
    s.git(&["add", "-A"]);
    let brief = s.run(&["brief", "--task", &task, "--json"]);
    assert!(finding_codes(&brief).contains(&"BASE_STALE".to_string()), "{}", text(&brief));
    assert_eq!(decision_of(&brief), "approval_required");

    // The agent updates. Its change is still only its own work: what it pulled is not counted.
    s.git(&["stash", "-q"]);
    s.git(&["pull", "-q", "--rebase", "origin", "main"]);
    s.git(&["stash", "pop", "-q"]);
    s.git(&["add", "-A"]);
    // No hook call in between: a person can update after the session, and the brief still knows.
    let after = s.run(&["brief", "--task", &task, "--json"]);
    assert!(!finding_codes(&after).contains(&"BASE_STALE".to_string()), "{}", text(&after));
    let changed: Vec<String> = json(&after)["brief"]["gate"]["changed"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap().to_string()).collect();
    assert_eq!(changed, vec!["main.rs".to_string()], "pulled commits are not the agent's change");
}

#[test]
fn an_agent_on_the_latest_code_is_told_so_and_a_failed_fetch_never_blocks() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("fresh_base = \"warn\"", "fresh_base = \"deny\"", 1));
    s.commit_all("policy");
    let _origin = Origin::for_sandbox(&s);
    let current = context_of(&start_session(&s, "current"));
    assert!(current.contains("up to date with origin/main"), "{current}");

    // An origin that cannot be reached: the agent is told 05 could not check, and nothing is held.
    s.git(&["remote", "set-url", "origin", "/nowhere/at/all.git"]);
    let unreachable = context_of(&start_session(&s, "offline"));
    assert!(unreachable.contains("could not fetch origin"), "{unreachable}");
    s.write("main.rs", "fn main() { /* offline work */ }\n");
    s.git(&["add", "-A"]);
    let brief = s.run(&["brief", "--task", &find_task(&s, "offline"), "--json"]);
    assert!(!finding_codes(&brief).contains(&"BASE_STALE".to_string()), "{}", text(&brief));
}

#[test]
fn with_fresh_base_off_the_hook_does_not_fetch() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("fresh_base = \"warn\"", "fresh_base = \"allow\"", 1));
    s.commit_all("policy");
    let origin = Origin::for_sandbox(&s);
    origin.someone_lands(1);
    let before = s.git(&["rev-parse", "refs/remotes/origin/main"]);
    let context = context_of(&start_session(&s, "off"));
    assert!(!context.contains("origin/main"), "{context}");
    assert_eq!(s.git(&["rev-parse", "refs/remotes/origin/main"]), before, "nothing was fetched");
}

#[test]
fn a_require_rule_is_told_at_start_and_the_agent_is_asked_to_finish_it_at_stop() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("src")).unwrap();
    fs::create_dir_all(s.path("docs")).unwrap();
    s.write("src/api.rs", "pub fn api() {}\n");
    s.write("docs/api.md", "# API\n");
    set_policy(&s, "[[require]]\nwhen = [\"src/**\"]\nalso = [\"docs/**\"]\nwhy = \"the API docs\"\n");

    let context = context_of(&start_session(&s, "docs"));
    assert!(context.contains("When you change src/**, also update docs/** (the API docs)"), "{context}");

    let stop = |looping: bool| {
        let payload = serde_json::json!({ "session_id": "docs", "cwd": s.dir.path(), "hook_event_name": "Stop", "stop_hook_active": looping }).to_string();
        s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload)
    };
    s.write("src/api.rs", "pub fn api() { /* changed */ }\n");
    let asked = stop(false);
    let v = json(&asked);
    assert_eq!(v["decision"], "block", "{v}");
    let reason = v["reason"].as_str().unwrap();
    assert!(reason.contains("src/api.rs") && reason.contains("docs/**"), "{reason}");
    assert!(stop(true).stdout.is_empty(), "asked once, never in a loop");

    s.write("docs/api.md", "# API\n\napi() changed.\n");
    assert!(stop(false).stdout.is_empty(), "the rule is met");
    let brief = s.run(&["brief", "--task", &find_task(&s, "docs"), "--json"]);
    assert!(!finding_codes(&brief).contains(&"ALSO_CHANGE_MISSING".to_string()), "{}", text(&brief));
}

#[test]
fn the_setup_asks_which_folders_change_with_code_and_how_strict_fresh_base_is() {
    let s = with_environment_branches();
    // team, landing, envs x3, add none, keep checks, add none, protected, locked, append-only,
    // no-read, docs = docs/**, scope, tests, fresh base = 4 (refuse), land, write.
    let answers = "\n\n\n\n\n\n\n\n\n\n\n\ndocs/**\n\n\n4\n\n\n";
    let out = s.run_with_stdin(&["init", "--guided"], answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("Folders that must be updated with every change") && shown.contains("starts from older code than origin has"), "{shown}");
    let words = shown.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("docs/** with every change") && words.contains("refuse the change"), "{shown}");
    let p = policy_of(&s);
    assert_eq!(p.branches.fresh_base, use05_core::policy::Severity::Deny);
    assert_eq!(p.require.len(), 1);
    assert_eq!((p.require[0].when.clone(), p.require[0].also.clone(), p.require[0].severity), (vec!["**".to_string()], vec!["docs/**".to_string()], use05_core::policy::Severity::Approval));

    // Editing: the docs answer starts from what is there; clearing it removes only that rule.
    s.commit_all("05");
    let text_now = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{text_now}\n# the API reference\n[[require]]\nwhen = [\"src/api/**\"]\nalso = [\"docs/api/**\"]\n"));
    let edit = s.run_with_stdin(&["policy", "--edit", "--guided"], &format!("{}-\n{}", "\n".repeat(12), "\n".repeat(10)));
    assert_eq!(code(&edit), 0, "{}", text(&edit));
    let after = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let p = policy_of(&s);
    assert_eq!(p.require.iter().map(|r| r.also.join(",")).collect::<Vec<_>>(), ["docs/api/**"], "{after}");
    assert!(after.contains("# the API reference"), "a rule the setup does not ask about keeps its comment:\n{after}");
}

#[test]
fn rules_from_0_0_6_raise_an_older_policys_minimum_version() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    let p = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let older: String = p.replace(&format!("min_version = \"{}\"", env!("CARGO_PKG_VERSION")), "min_version = \"0.0.2\"").lines().filter(|l| !l.starts_with("fresh_base")).map(|l| format!("{l}\n")).collect();
    s.write(".05/policy.toml", &older);
    // team, landing, envs x3, add none, keep checks, add none, paths x4, docs, scope, tests,
    // fresh base = 2 (tell the agent), land, write.
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], &format!("{}2\n\n\n", "\n".repeat(15)));
    assert_eq!(code(&out), 0, "{}", text(&out));
    let text = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(text.contains("fresh_base = \"warn\"") && text.contains("min_version = \"0.0.6\""), "{text}");
}

#[test]
fn a_scope_written_as_one_string_is_read_as_its_patterns() {
    // A real agent wrote --scope "src/** docs/** test/**": one pattern that matched nothing, so
    // every file it changed was outside its plan.
    let s = Sandbox::initialised();
    let out = s.run(&["start", "Add mul", "--scope", "src/** docs/**", "--scope", "test/**,lib/**", "--exclude", "src/gen/**, src/vendor/**"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    s.write("main.rs", "fn main() { /* edit */ }\n");
    s.git(&["add", "-A"]);
    let v = json(&s.run(&["brief", "--json"]));
    let list = |k: &str| v["brief"]["card"]["scope"][k].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(list("include"), ["src/**", "docs/**", "test/**", "lib/**"], "{v}");
    assert_eq!(list("exclude"), ["src/gen/**", "src/vendor/**"], "{v}");
}

#[test]
fn fresh_base_is_checked_once_at_startup_and_a_later_failed_fetch_never_erases_it() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("fresh_base = \"warn\"", "fresh_base = \"deny\"", 1));
    s.commit_all("policy");
    let origin = Origin::for_sandbox(&s);
    origin.someone_lands(3);
    assert!(context_of(&start_session(&s, "long")).contains("3 commits behind"));
    let task = find_task(&s, "long");
    s.write("main.rs", "fn main() { /* still on the old code */ }\n");
    s.git(&["add", "-A"]);

    // Compaction, a resume or /clear mid-task: no new fetch, no new telling-off.
    origin.someone_lands(1);
    s.git(&["remote", "set-url", "origin", "/nowhere/at/all.git"]);
    for source in ["compact", "resume", "clear"] {
        let out = s.run_with_stdin(&["hook", "claude-code", "SessionStart"], &serde_json::json!({ "session_id": "long", "cwd": s.dir.path(), "hook_event_name": "SessionStart", "source": source }).to_string());
        let context = context_of(&out);
        assert!(!context.contains("behind") && !context.contains("could not fetch"), "{source}: {context}");
    }
    let brief = s.run(&["brief", "--task", &task, "--json"]);
    assert!(finding_codes(&brief).contains(&"BASE_STALE".to_string()), "the record survives: {}", text(&brief));
    assert_eq!(decision_of(&brief), "deny");
}

#[test]
fn the_stop_reminder_sees_unstaged_updates_and_still_comes_after_a_failed_check() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("src")).unwrap();
    fs::create_dir_all(s.path("docs")).unwrap();
    s.write("src/api.rs", "pub fn api() {}\n");
    s.write("docs/api.md", "# API\n");
    set_policy(&s, "[[require]]\nwhen = [\"src/**\"]\nalso = [\"docs/**\"]\n");
    start_session(&s, "stops");
    let stop = |looping: bool| {
        let payload = serde_json::json!({ "session_id": "stops", "cwd": s.dir.path(), "hook_event_name": "Stop", "stop_hook_active": looping }).to_string();
        s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload)
    };

    // The code is staged and the docs are edited but not staged: the docs did change.
    s.write("src/api.rs", "pub fn api() { /* v2 */ }\n");
    s.git(&["add", "src/api.rs"]);
    s.write("docs/api.md", "# API\n\nv2.\n");
    assert!(stop(false).stdout.is_empty(), "{}", text(&stop(false)));

    // A failing check is reported first; the docs reminder still comes on the next stop, once.
    s.git(&["checkout", "-q", "--", "docs/api.md"]);
    s.write("test.sh", "#!/bin/sh\nexit 1\n");
    s.git(&["add", "-A"]);
    s.run(&["prove"]);
    // A new edit after that run: Stop runs the check again itself, and it fails.
    s.write("src/api.rs", "pub fn api() { /* v3 */ }\n");
    s.git(&["add", "-A"]);
    let first = json(&stop(false));
    assert!(first["reason"].as_str().unwrap().contains("the check test failed"), "{first}");
    let second = json(&stop(true));
    assert!(second["reason"].as_str().unwrap().contains("docs/** must change"), "{second}");
    assert!(stop(true).stdout.is_empty(), "never asked twice");
}

// ---------------------------------------------------------------- passkeys and outside signers

/// A test passkey made for localhost, and its public key.
fn test_passkey(seed: u8) -> (p256::ecdsa::SigningKey, use05_receipt::PasskeyKey) {
    let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let key = use05_receipt::PasskeyKey::from_sec1("localhost", sk.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
    (sk, key)
}

impl Sandbox {
    fn pin_passkey(&self, key: &use05_receipt::PasskeyKey, name: &str) {
        fs::write(self.home.path().join("passkeys.pub"), format!("{} {name}\n", use05_receipt::passkey_public_text(key).trim())).unwrap();
    }

    /// A change to a protected path, proved, waiting for a person.
    fn waiting_for_approval() -> Sandbox {
        let s = Sandbox::initialised();
        s.run(&["start", "Tighten the policy", "--scope", ".05/**"]);
        s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
        s.git(&["add", "-A"]);
        assert_eq!(code(&s.run(&["prove"])), 0);
        assert_eq!(code(&s.run(&["brief"])), 3);
        s
    }
}

/// What a browser returns for the challenge `approve --unsigned` printed, as an envelope that also
/// carries the machine's co-signature, as a signer must.
fn sign_with_passkey(unsigned: &Value, sk: &p256::ecdsa::SigningKey) -> String {
    let mut envelope: Value = serde_json::from_str(&sign_with_passkey_only(unsigned, sk)).unwrap();
    envelope["signatures"].as_array_mut().unwrap().insert(0, unsigned["details"]["cosignature"].clone());
    envelope.to_string()
}

/// The passkey's signature alone, without the machine's co-signature.
fn sign_with_passkey_only(unsigned: &Value, sk: &p256::ecdsa::SigningKey) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::signature::Signer;
    use sha2::{Digest, Sha256};
    let d = &unsigned["details"];
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let client = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"http://localhost:8080"}}"#, d["challenge"].as_str().unwrap());
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let sig: p256::ecdsa::Signature = sk.sign(&message);
    serde_json::json!({
        "payload": d["payload"],
        "payloadType": d["payload_type"],
        "signatures": [{ "sig": STANDARD.encode(sig.to_der().as_bytes()), "webauthn": { "authenticatorData": STANDARD.encode(&auth), "clientDataJSON": STANDARD.encode(client.as_bytes()) } }],
    })
    .to_string()
}

#[test]
fn approve_unsigned_prints_the_exact_statement_and_stores_nothing() {
    use base64::Engine;
    let s = Sandbox::waiting_for_approval();
    let before = s.stored_receipts();
    let out = s.run(&["approve", "--unsigned", "--reason", "from my phone", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let v = json(&out);
    assert_eq!(v["code"], "UNSIGNED");
    let d = &v["details"];
    let body = base64::engine::general_purpose::STANDARD.decode(d["payload"].as_str().unwrap()).unwrap();
    let statement: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(statement["predicate"]["scope"], "outcome");
    assert_eq!(statement["predicate"]["decision"], "approve");
    assert_eq!(statement["predicate"]["rationale"], "from my phone");
    assert_eq!(statement["predicate"]["task"], d["task"]);
    assert_eq!(d["scope"], "outcome");
    assert_eq!(d["subject"], d["tree"]);
    let challenge = use05_receipt::passkey_challenge(d["payload_type"].as_str().unwrap(), &body);
    assert_eq!(d["challenge"], base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge));
    assert_eq!(s.stored_receipts(), before, "nothing is signed or stored");
    assert_eq!(code(&s.run(&["brief"])), 3);
}

#[test]
fn approve_signed_files_a_passkey_approval_and_the_brief_allows() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(31);
    s.pin_passkey(&key, "iPhone");
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let v = json(&out);
    assert_eq!(v["code"], "APPROVED");
    let id = use05_receipt::PublicKey::Passkey(key).id();
    assert_eq!(v["details"]["branch"], format!("05-receipts/{id}"));
    let brief = s.run(&["brief"]);
    assert_eq!(code(&brief), 0, "{}", text(&brief));
}

#[test]
fn approve_unsigned_cosigns_with_this_machines_key() {
    let s = Sandbox::waiting_for_approval();
    let d = json(&s.run(&["approve", "--unsigned", "--json"]))["details"].clone();
    let machine = use05_receipt::parse_public_key(&fs::read_to_string(s.home.path().join("local.pub")).unwrap()).unwrap();
    assert_eq!(d["cosignature"]["keyid"], use05_receipt::key_id(&machine));
    assert!(d["cosignature"]["webauthn"].is_null());
    let alone = serde_json::json!({ "payload": d["payload"], "payloadType": d["payload_type"], "signatures": [d["cosignature"]] }).to_string();
    assert!(use05_receipt::verify_any(alone.as_bytes(), &machine).is_ok(), "the co-signature covers the statement");
}

#[test]
fn approve_signed_says_an_uncosigned_passkey_approval_will_not_count() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(34);
    s.pin_passkey(&key, "iPhone");
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    s.write("signed.json", &sign_with_passkey_only(&unsigned, &sk));
    let before = s.stored_receipts().len();
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let v = json(&out);
    assert_eq!(v["details"]["counts"], false);
    assert_eq!(v["details"]["void"], "no machine that prepared it co-signed it");
    assert_eq!(s.stored_receipts().len(), before + 1, "filed, as the gate would read it");
    assert_eq!(code(&s.run(&["brief"])), 3);
}

#[test]
fn approve_signed_refuses_an_untrusted_key_and_stores_nothing() {
    let s = Sandbox::waiting_for_approval();
    let (sk, _) = test_passkey(32);
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    let before = s.stored_receipts();
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["code"], "APPROVAL_NOT_TRUSTED");
    assert_eq!(s.stored_receipts(), before, "nothing is stored");
    assert_eq!(code(&s.run(&["brief"])), 3);
}

#[test]
fn approve_signed_files_under_its_own_subject() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(33);
    s.pin_passkey(&key, "iPhone");
    let unsigned = json(&s.run(&["approve", "--unsigned", "--tree", "HEAD", "--json"]));
    let subject = unsigned["details"]["subject"].as_str().unwrap().to_string();
    assert_eq!(subject, s.git(&["rev-parse", "HEAD^{tree}"]));
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    assert_eq!(code(&s.run(&["approve", "--signed", "signed.json"])), 0);
    assert!(s.stored_receipts().iter().any(|(_, p)| p.starts_with(&format!("receipts/{subject}/"))), "{:?}", s.stored_receipts());
    assert_eq!(code(&s.run(&["brief"])), 3, "an approval of another tree does not approve this one");
}

#[test]
fn verify_accepts_a_passkey_public_key() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(34);
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    s.write("phone.pub", &use05_receipt::passkey_public_text(&key));
    let out = s.run(&["verify", "signed.json", "--key", "phone.pub", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
}

/// The fields `sign_with_passkey` reads, for any statement bytes.
fn to_sign(body: &[u8]) -> Value {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let challenge = use05_receipt::passkey_challenge(use05_receipt::PAYLOAD_TYPE, body);
    serde_json::json!({ "details": { "payload": STANDARD.encode(body), "payload_type": use05_receipt::PAYLOAD_TYPE, "challenge": URL_SAFE_NO_PAD.encode(challenge) } })
}

#[test]
fn verify_refuses_a_passkey_signed_bypass() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(35);
    let tree = s.git(&["rev-parse", "HEAD^{tree}"]);
    let bypass = use05_receipt::Statement::new(
        vec![use05_receipt::tree_subject(&tree, &"ab".repeat(32))],
        use05_receipt::Bypass { reason: "r".into(), by: "b".into(), findings: vec![], created: "2026-11-01T00:00:00Z".into(), expires: "2099-01-01T00:00:00Z".into() },
    );
    s.write("bypass.json", &sign_with_passkey_only(&to_sign(&serde_json::to_vec(&bypass).unwrap()), &sk));
    s.write("phone.pub", &use05_receipt::passkey_public_text(&key));
    let out = s.run(&["verify", "bypass.json", "--key", "phone.pub", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["code"], "PASSKEY_APPROVALS_ONLY");
}

#[test]
fn approve_signed_says_when_an_approval_will_not_count() {
    use base64::Engine;
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(36);
    s.pin_passkey(&key, "iPhone");
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    let body = base64::engine::general_purpose::STANDARD.decode(unsigned["details"]["payload"].as_str().unwrap()).unwrap();
    let mut statement: Value = serde_json::from_slice(&body).unwrap();
    statement["predicate"]["policy_sha256"] = Value::String("00".repeat(32));
    s.write("signed.json", &sign_with_passkey_only(&to_sign(&serde_json::to_vec(&statement).unwrap()), &sk));
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let v = json(&out);
    assert_eq!(v["details"]["counts"], false, "{v}");
    assert!(text(&out).contains("under a different policy"), "{}", text(&out));
    assert_eq!(code(&s.run(&["brief"])), 3);
}

// ---------------------------------------------------------------- approval_needed

fn edit_policy_file(s: &Sandbox) {
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    s.git(&["add", "-A"]);
}

#[test]
fn finish_on_a_change_needing_approval_emits_approval_needed() {
    let s = Sandbox::initialised();
    let heard_at = listen(&s, "\"approval_needed\", \"finished\"");
    s.run(&["start", "Tighten the policy", "--scope", ".05/**"]);
    edit_policy_file(&s);
    assert_eq!(code(&s.run(&["prove"])), 0);
    assert_eq!(code(&s.run(&["finish", "--outcome", "Tightened it"])), 0);
    let events = heard(&heard_at);
    let finished = events.iter().find(|e| e["event"] == "finished").expect("finished");
    let needed: Vec<&Value> = events.iter().filter(|e| e["event"] == "approval_needed").collect();
    assert_eq!(needed.len(), 1, "{events:?}");
    let e = needed[0];
    assert_eq!(e["scope"], "outcome");
    assert_eq!(e["task"], finished["task"]);
    assert_eq!(e["tree"], finished["tree"]);
    assert!(e["findings"].as_array().is_some_and(|f| f.iter().any(|c| c == "PROTECTED_PATH")), "{e}");
    let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
    assert!(keys.iter().all(|k| ["v", "event", "at", "repo", "task", "scope", "tree", "intent_sha256", "findings"].contains(k)), "only identifiers and verdicts: {keys:?}");
}

#[test]
fn no_approval_needed_when_the_gate_allows() {
    let s = Sandbox::initialised();
    let heard_at = listen(&s, "\"approval_needed\", \"finished\"");
    s.run(&["start", "Say hello", "--scope", "main.rs"]);
    s.write("main.rs", "fn main() { println!(\"hi\"); }\n");
    s.git(&["add", "-A"]);
    s.run(&["prove"]);
    assert_eq!(code(&s.run(&["finish", "--outcome", "Said hello"])), 0);
    let events = heard(&heard_at);
    assert!(events.iter().any(|e| e["event"] == "finished"), "{events:?}");
    assert!(!events.iter().any(|e| e["event"] == "approval_needed"), "{events:?}");
}

#[test]
fn the_stop_hook_emits_approval_needed() {
    let s = Sandbox::initialised();
    let heard_at = listen(&s, "\"approval_needed\"");
    start_session(&s, "stops");
    edit_policy_file(&s);
    let payload = serde_json::json!({ "session_id": "stops", "cwd": s.dir.path(), "hook_event_name": "Stop", "stop_hook_active": false }).to_string();
    assert_eq!(code(&s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload)), 0);
    let events = heard(&heard_at);
    assert!(events.iter().any(|e| e["event"] == "approval_needed" && e["scope"] == "outcome"), "{events:?}");
}

#[test]
fn a_slow_approval_listener_does_not_hold_up_finish() {
    let s = Sandbox::initialised();
    fs::write(s.home.path().join("extensions.toml"), "[[on]]\nevents = [\"approval_needed\"]\nrun = [\"/bin/sh\", \"-c\", \"sleep 30\"]\ntimeout_secs = 1\n").unwrap();
    s.run(&["start", "Tighten the policy", "--scope", ".05/**"]);
    edit_policy_file(&s);
    s.run(&["prove"]);
    let clock = std::time::Instant::now();
    assert_eq!(code(&s.run(&["finish", "--outcome", "Tightened it"])), 0);
    assert!(clock.elapsed().as_secs() < 5, "took {:?}", clock.elapsed());
}

#[test]
fn doctor_accepts_approval_needed_in_extensions_toml() {
    let s = Sandbox::initialised();
    listen(&s, "\"approval_needed\"");
    // Doctor wraps long lines; compare words, not line breaks.
    let out = text(&s.run(&["doctor"])).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(!out.contains("there is no event"), "{out}");
}

#[test]
fn approve_unsigned_says_when_it_made_this_machines_key() {
    let s = Sandbox::waiting_for_approval();
    for f in ["local.key", "local.pub"] {
        let _ = fs::remove_file(s.home.path().join(f));
    }
    let v = json(&s.run(&["approve", "--unsigned", "--json"]));
    assert!(v["notes"].to_string().contains("one was made to co-sign it"), "{v}");
    assert!(!v["details"]["cosignature"].is_null());
}

#[test]
fn a_damaged_passkeys_file_keeps_its_good_passkeys_and_doctor_says_so() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(35);
    let mut bytes = format!("{} iPhone\n", use05_receipt::passkey_public_text(&key).trim()).into_bytes();
    bytes.extend_from_slice(b"\xff\xfe junk\nnot a key\n");
    fs::write(s.home.path().join("passkeys.pub"), bytes).unwrap();
    let unsigned = json(&s.run(&["approve", "--unsigned", "--json"]));
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    assert_eq!(code(&s.run(&["approve", "--signed", "signed.json"])), 0, "the good line still counts");
    let doctor = text(&s.run(&["doctor"])).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(doctor.contains("passkey iPhone (localhost) pinned here"), "{doctor}");
    assert!(doctor.contains("2 line(s) of passkeys.pub are not a passkey"), "{doctor}");
}

#[test]
fn approve_signed_files_a_passkey_approval_of_a_plan() {
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(36);
    s.pin_passkey(&key, "iPhone");
    let unsigned = json(&s.run(&["approve", "--intent", "--unsigned", "--json"]));
    assert_eq!(unsigned["details"]["scope"], "intent", "{unsigned}");
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(json(&out)["code"], "APPROVED");
    let subject = unsigned["details"]["subject"].as_str().unwrap().to_string();
    assert!(s.stored_receipts().iter().any(|(_, p)| p.starts_with(&format!("receipts/{subject}/"))), "filed under the plan: {:?}", s.stored_receipts());
}

#[test]
fn approve_signed_says_a_passkey_signed_bypass_is_not_an_approval() {
    use base64::Engine;
    let s = Sandbox::waiting_for_approval();
    let (sk, key) = test_passkey(37);
    s.pin_passkey(&key, "iPhone");
    let body = serde_json::json!({ "_type": "https://in-toto.io/Statement/v1", "subject": [], "predicateType": "https://use05.dev/bypass/v0", "predicate": { "reason": "from a page" } }).to_string();
    let challenge = use05_receipt::passkey_challenge(use05_receipt::PAYLOAD_TYPE, body.as_bytes());
    let fake = serde_json::json!({ "details": { "payload": base64::engine::general_purpose::STANDARD.encode(&body), "payload_type": use05_receipt::PAYLOAD_TYPE, "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge) } });
    s.write("signed.json", &sign_with_passkey_only(&fake, &sk));
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["code"], "NOT_AN_APPROVAL");
}

// ---------------------------------------------------------------- testing before a push (D87)

impl Sandbox {
    /// Initialised, with `[testing]` set before the first push, and a bare remote.
    fn testing(local: &str) -> (Sandbox, tempfile::TempDir) {
        let s = Sandbox::initialised();
        s.approver();
        let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
        s.write(".05/policy.toml", &format!("{policy}\n[testing]\nlocal = \"{local}\"\n"));
        s.commit_all("ask for testing");
        let remote = tempfile::tempdir().unwrap();
        assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote.path().display().to_string()]).status().unwrap().success());
        s.git(&["remote", "add", "origin", &remote.path().display().to_string()]);
        assert!(s.push("main").status.success(), "the first push sets the baseline");
        (s, remote)
    }

    fn push(&self, branch: &str) -> Output {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(self.dir.path()).args(["push", "-q", "origin", &format!("HEAD:refs/heads/{branch}")]);
        cmd.env("PATH", format!("{}:{}", Path::new(BIN).parent().unwrap().display(), std::env::var("PATH").unwrap())).env("USE05_HOME", self.home.path()).env("HOME", self.home.path());
        cmd.output().unwrap()
    }
}

#[test]
fn a_push_to_main_waits_for_the_developers_testing_sign_off() {
    let (s, _remote) = Sandbox::testing("required");
    s.write("main.rs", "fn main() { println!(\"hi\"); }\n");
    s.commit_all("say hi");
    let held = s.push("main");
    assert!(!held.status.success());
    assert!(text(&held).contains("TESTING_REQUIRED"), "{}", text(&held));
    assert!(s.push("agent/hi").status.success(), "an agent's working branch is not held");
    // A skip does not count where testing is required.
    let skip = s.run_with_stdin(&["approve", "--skip-testing", "--reason", "no time", "--tree", "HEAD", "--passphrase-stdin", "--json"], "correct horse\n");
    assert_eq!(code(&skip), 2, "{}", text(&skip));
    assert_eq!(json(&skip)["code"], "TESTING_NOT_SKIPPABLE");
    // A note is required.
    assert_eq!(code(&s.run_with_stdin(&["approve", "--tested", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n")), 6);
    let signed = s.run_with_stdin(&["approve", "--tested", "--note", "ran it, said hi", "--tree", "HEAD", "--passphrase-stdin", "--json"], "correct horse\n");
    assert_eq!(code(&signed), 0, "{}", text(&signed));
    assert_eq!(json(&signed)["code"], "TESTED");
    assert!(s.push("main").status.success(), "signed off: it goes");
    let brief = text(&s.run(&["brief", "--tree", "HEAD"]));
    assert!(brief.contains("ran it, said hi"), "{brief}");
}

#[test]
fn a_skippable_test_sign_off_can_be_skipped_with_a_reason() {
    let (s, _remote) = Sandbox::testing("skippable");
    s.write("main.rs", "fn main() { println!(\"docs\"); }\n");
    s.commit_all("words only");
    assert!(!s.push("main").status.success());
    let skip = s.run_with_stdin(&["approve", "--skip-testing", "--reason", "a comment changed, nothing to try", "--tree", "HEAD", "--passphrase-stdin", "--json"], "correct horse\n");
    assert_eq!(code(&skip), 0, "{}", text(&skip));
    assert_eq!(json(&skip)["code"], "TESTING_SKIPPED");
    assert!(s.push("main").status.success());
}

#[test]
fn the_ci_gate_reads_where_a_push_goes_from_the_host_and_holds_one_it_cannot_place() {
    let (s, secret, _remote) = ci_fixture_with("\n[testing]\nlocal = \"required\"\n");
    s.write("main.rs", "fn main() { /* tried? */ }\n");
    s.commit_all("change");
    let event = s.path("event.json");
    let ci = |vars: &[(&str, &str)]| {
        let home = tempfile::tempdir().unwrap();
        let mut cmd = s.command(&["gate", "--ci", "--json"]);
        cmd.env("USE05_HOME", home.path()).env("HOME", home.path()).env("USE05_RUNNER_KEY", &secret).stdin(Stdio::null());
        for v in ["GITHUB_BASE_REF", "GITHUB_REF_NAME", "GITHUB_REF_TYPE", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH"] {
            cmd.env_remove(v);
        }
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let held = text(&out).contains("TESTING_REQUIRED");
        held
    };
    // A pull request into another branch is not held; into main it is.
    assert!(!ci(&[("GITHUB_BASE_REF", "release")]));
    assert!(ci(&[("GITHUB_BASE_REF", "main")]));
    // A merge queue's branch is named for the queue; the event says the branch it merges into.
    fs::write(&event, r#"{"merge_group":{"base_ref":"refs/heads/main"},"repository":{"default_branch":"main"}}"#).unwrap();
    let ev = event.display().to_string();
    assert!(ci(&[("GITHUB_EVENT_NAME", "merge_group"), ("GITHUB_REF_NAME", "gh-readonly-queue/main/pr-1-abc"), ("GITHUB_REF_TYPE", "branch"), ("GITHUB_EVENT_PATH", &ev)]));
    // The host's default branch is the landing branch when the policy names none (no origin/HEAD here).
    fs::write(&event, r#"{"repository":{"default_branch":"trunk"}}"#).unwrap();
    assert!(ci(&[("GITHUB_BASE_REF", "trunk"), ("GITHUB_EVENT_PATH", &ev)]));
    assert!(!ci(&[("GITHUB_BASE_REF", "trunk")]), "without the host's word, trunk is not where work lands");
    // CI that names no branch at all: held, not let through.
    assert!(ci(&[]));
}

// ---------------------------------------------------------------- one rule at a time (D88)

#[test]
fn policy_changes_one_rule_at_a_time_and_says_what_changed() {
    let s = Sandbox::initialised();
    let file = s.path(".05/policy.toml");
    let before = fs::read_to_string(&file).unwrap();
    let set = s.run(&["policy", "set", "testing.local", "required", "--json"]);
    assert_eq!(code(&set), 0, "{}", text(&set));
    let v = json(&set);
    assert_eq!(v["code"], "POLICY_CHANGED");
    assert_eq!((v["details"]["setting"].as_str(), v["details"]["after"].as_str()), (Some("testing.local"), Some("required")));
    let after = fs::read_to_string(&file).unwrap();
    assert!(after.contains("[testing]") && after.contains("local = \"required\""), "{after}");
    // Everything else in the file, comments included, is as it was.
    for line in before.lines().filter(|l| l.starts_with('#')) {
        assert!(after.contains(line), "lost: {line}");
    }
    let add = json(&s.run(&["policy", "add", "protect.paths", "billing/**", "--json"]));
    assert!(add["details"]["after"].as_array().unwrap().iter().any(|p| p == "billing/**"), "{add}");
    let loosen = s.run(&["policy", "remove", "protect.paths", "billing/**"]);
    assert_eq!(code(&loosen), 0);
    assert!(text(&loosen).contains("less strict"), "{}", text(&loosen));
    let unchanged = fs::read_to_string(&file).unwrap();
    let bad = s.run(&["policy", "set", "testing.sometimes", "yes", "--json"]);
    assert_eq!(code(&bad), 6, "{}", text(&bad));
    assert_eq!(fs::read_to_string(&file).unwrap(), unchanged, "an invalid change writes nothing");
    let rule = s.run(&["policy", "add", "require", "{ when = [\"src/**\"], also = [\"docs/**\"], why = \"docs follow code\" }"]);
    assert_eq!(code(&rule), 0, "{}", text(&rule));
    assert!(text(&rule).contains("a person approves"), "{}", text(&rule));
}

// ---------------------------------------------------------------- 05 travels with the repository (D86)

#[test]
fn claude_code_cloud_sessions_install_05_and_report_only_in_the_cloud() {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".claude")).unwrap();
    s.commit_all("first");
    let init = s.run(&["init", "--shared-hooks"]);
    assert_eq!(code(&init), 0, "{}", text(&init));
    assert!(!s.path(".claude/settings.local.json").exists(), "the hooks are in the file that is committed");
    let settings: Value = serde_json::from_str(&fs::read_to_string(s.path(".claude/settings.json")).unwrap()).unwrap();
    let first = settings["hooks"]["SessionStart"][0]["hooks"][0]["command"].as_str().unwrap().to_string();
    assert!(first.starts_with("[ \"$CLAUDE_CODE_REMOTE\" = true ] || exit 0;"), "{first}");
    assert!(first.contains(&format!("@use05/cli@{}", env!("CARGO_PKG_VERSION"))) && first.contains("use05-cloud session --background"), "{first}");
    // On your own machine it does nothing, and says nothing.
    let out = Command::new("/bin/sh").arg("-c").arg(&first).env_remove("CLAUDE_CODE_REMOTE").output().unwrap();
    assert!(out.status.success() && out.stdout.is_empty() && out.stderr.is_empty());
}

#[test]
fn ci_prepares_a_statement_for_someone_else_co_signed_by_the_runner_key() {
    use base64::Engine;
    let s = Sandbox::waiting_for_approval();
    let runner = use05_receipt::SigningKey::from_bytes(&[42; 32]);
    let secret = use05_receipt::secret_key_text(&runner);
    let out = s.run_env(&["approve", "--unsigned", "--approver", "Alex Rivera", "--json"], &[("USE05_RUNNER_KEY", secret.trim())]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let d = &json(&out)["details"];
    assert_eq!(d["cosignature"]["keyid"], use05_receipt::key_id(&runner.verifying_key()), "the runner key co-signs, not a key made on the runner");
    let body = base64::engine::general_purpose::STANDARD.decode(d["payload"].as_str().unwrap()).unwrap();
    let statement: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(statement["predicate"]["approver"], "Alex Rivera");
    // Naming someone else is only for a statement someone else signs.
    assert_eq!(code(&s.run(&["approve", "--approver", "Alex Rivera"])), 6, "a usage error");
}

// ---------------------------------------------------------------- discarding abandoned work (D89)

/// An agent's abandoned work: a worktree on its own branch, one commit made there and a file never
/// committed.
fn abandoned(s: &Sandbox, holder: &TempDir) -> (PathBuf, String) {
    let wt = agent_worktree(s, holder, "claude/abandoned");
    let id = task_in(s, &wt, "Try a new layout");
    fs::write(wt.join("layout.txt"), "half done\n").unwrap();
    git_at(&wt, &["add", "-A"]);
    git_at(&wt, &["commit", "-qm", "half a layout"]);
    fs::write(wt.join("notes.txt"), "never committed\n").unwrap();
    (wt, id)
}

#[test]
fn discard_shows_what_is_lost_and_needs_a_person_at_the_terminal() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let (wt, id) = abandoned(&s, &holder);
    // An agent's shell has no terminal: it cannot throw work away.
    let out = s.run(&["discard", &id, "--json"]);
    assert_eq!(code(&out), 6, "{}", text(&out));
    assert_eq!(json(&out)["code"], "NEEDS_A_PERSON");
    assert!(wt.exists());
    // At a terminal, after seeing what would be lost; "no" keeps it.
    let (no, screen) = on_a_terminal(&s, &["discard", &id[..8]], &["n"]);
    assert_ne!(no, 0, "{screen}");
    assert!(screen.contains("1 commit") && screen.contains("1 file"), "it says what would be lost: {screen}");
    assert!(wt.exists());
    let (yes, screen) = on_a_terminal(&s, &["discard", &id[..8]], &["y"]);
    assert_eq!(yes, 0, "{screen}");
    assert!(!wt.exists(), "the worktree is gone");
    assert!(!s.git(&["branch", "--list", "claude/abandoned"]).contains("claude/abandoned"), "the branch is gone");
    let task: Value = serde_json::from_str(&fs::read_to_string(s.path(&format!(".git/05/tasks/{id}.json"))).unwrap()).unwrap();
    assert_eq!(task["status"], "discarded");
}

#[test]
fn discard_signed_by_a_passkey_from_the_console_counts_only_as_prepared_here() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let (wt, id) = abandoned(&s, &holder);
    let unsigned = s.run(&["discard", &id, "--unsigned", "--json"]);
    assert_eq!(code(&unsigned), 0, "{}", text(&unsigned));
    let u = json(&unsigned);
    assert_eq!((u["details"]["plan"]["unpushed"].as_u64(), u["details"]["plan"]["uncommitted"].as_u64()), (Some(1), Some(1)));
    assert!(wt.exists(), "preparing deletes nothing");
    let (sk, key) = test_passkey(41);
    // A passkey this machine does not trust: nothing happens.
    s.write("signed.json", &sign_with_passkey(&u, &sk));
    let out = s.run(&["discard", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(wt.exists());
    // Pinned, but signed without this machine's co-signature (a page made it up): nothing happens.
    s.pin_passkey(&key, "iPhone");
    s.write("alone.json", &sign_with_passkey_only(&u, &sk));
    let out = s.run(&["discard", "--signed", "alone.json", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(wt.exists());
    // Prepared and co-signed elsewhere, by a key the policy trusts (the CI runner's), and signed
    // by the pinned passkey: still not this machine's to act on.
    let runner = use05_receipt::SigningKey::from_bytes(&[43; 32]);
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[trust.key]]\nname = \"ci\"\nrole = \"runner\"\npublic = \"{}\"\n", use05_receipt::public_key_text(&runner.verifying_key()).trim()));
    s.commit_all("trust the runner");
    let elsewhere = s.run_env(&["discard", &id, "--unsigned", "--json"], &[("USE05_RUNNER_KEY", use05_receipt::secret_key_text(&runner).trim())]);
    assert_eq!(code(&elsewhere), 0, "{}", text(&elsewhere));
    s.write("elsewhere.json", &sign_with_passkey(&json(&elsewhere), &sk));
    let out = s.run(&["discard", "--signed", "elsewhere.json", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(wt.exists());
    // Prepared here and signed by the pinned passkey: discarded.
    let out = s.run(&["discard", "--signed", "signed.json", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(json(&out)["code"], "DISCARDED");
    assert!(!wt.exists());
    // Signed again: it is done already.
    let again = s.run(&["discard", "--signed", "signed.json", "--json"]);
    assert_eq!(json(&again)["code"], "ALREADY_DISCARDED", "{}", text(&again));
}

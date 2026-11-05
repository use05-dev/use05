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
        Sandbox::in_dir(tempfile::tempdir().unwrap())
    }

    fn in_dir(dir: TempDir) -> Sandbox {
        let sandbox = Sandbox { dir, home: tempfile::tempdir().unwrap() };
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
            // The Secure Enclave is this Mac's, not the sandbox's: tests use the passphrase key.
            .env("USE05_NO_TOUCH_ID", "1")
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
    let raw = mask_ago(&raw);
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

/// "just now", "5 min ago", "3 h ago", "2 d ago": how long ago varies between runs.
fn mask_ago(text: &str) -> String {
    let words: Vec<&str> = text.split(' ').collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let is_number = |w: &str| !w.is_empty() && w.chars().all(|c| c.is_ascii_digit());
        if words[i] == "just" && words.get(i + 1).is_some_and(|w| w.starts_with("now")) {
            out.push(format!("<AGO>{}", words[i + 1].trim_start_matches("now")));
            i += 2;
        } else if is_number(words[i]) && words.get(i + 1).is_some_and(|w| ["min", "h", "d"].contains(w)) && words.get(i + 2).is_some_and(|w| w.starts_with("ago")) {
            out.push(format!("<AGO>{}", words[i + 2].trim_start_matches("ago")));
            i += 3;
        } else {
            out.push(words[i].to_string());
            i += 1;
        }
    }
    out.join(" ")
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
    snapshot_text(name, &normalise(sandbox, &text(out)));
}

fn snapshot_text(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots").join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
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
    let mut bare = Command::new(BIN);
    bare.current_dir(elsewhere.path()).env_clear().env("PATH", "/usr/bin:/bin").stdin(Stdio::null());
    // Where the developer tools are is part of what lets git run on a Mac, so it is kept.
    if let Ok(d) = std::env::var("DEVELOPER_DIR") {
        bare.env("DEVELOPER_DIR", d);
    }
    let out = bare.output().unwrap();
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
fn doctor_reports_receipt_count_and_size() {
    let s = Sandbox::new();
    s.key("me.key");
    let none = text(&s.run(&["doctor"]));
    assert!(none.contains("receipts 0 on 0 branches, 0 B"), "{none}");

    assert_eq!(code(&s.run(&["prove", "--key", "me.key", "--", "./test.sh"])), 0);
    let stored = s.stored_receipts();
    assert_eq!(stored.len(), 1);
    let bytes = s.git(&["cat-file", "-s", &format!("{}:{}", stored[0].0, stored[0].1)]);
    let doctor = s.run(&["doctor"]);
    let line = text(&doctor).lines().find(|l| l.contains("receipts") && l.contains("branch")).unwrap_or_default().to_string();
    assert!(line.contains("receipts 1 on 1 branch,"), "a count and the branches: {line}");
    assert!(line.contains(" B") || line.contains("KB"), "a size: {line}");
    assert!(line.contains("Never pruned"), "it says receipts are kept for good: {line}");

    let report = json(&s.run(&["doctor", "--json"]));
    assert_eq!(report["details"]["receipts"], serde_json::json!({ "count": 1, "branches": 1, "bytes": bytes.trim().parse::<u64>().unwrap() }), "{report}");
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
    on_a_terminal_with(s, args, lines, &[])
}

/// Like `on_a_terminal`, with extra environment variables (an agent's session id, say).
fn on_a_terminal_with(s: &Sandbox, args: &[&str], lines: &[&str], envs: &[(&str, &str)]) -> (i32, String) {
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty fills in two descriptors we then own.
    assert_eq!(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }, 0);
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut cmd = s.command(args);
    cmd.envs(envs.iter().copied());
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
    assert!(brief.contains("asked: \"Cap retries at 3\""), "{brief}");
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
    assert!(no_block(&stop(&s, "claude-code", "s2", true)), "the loop guard: never twice");
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
fn init_says_to_commit_what_it_wrote_until_it_is_committed() {
    let s = Sandbox::new();
    s.commit_all("first");
    let init = s.run(&["init"]);
    assert!(text(&init).contains("Next: git add .05 AGENTS.md && git commit"), "{}", text(&init));
    s.commit_all("Set up 05");
    let again = s.run(&["init"]);
    assert!(text(&again).contains("Next: use05 doctor"), "{}", text(&again));
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
fn a_policy_edit_approved_under_the_rules_that_judge_it_goes_through() {
    // A change that edits the policy is approved under origin's rules, the ones that will judge
    // it, so a change cannot loosen its own. Before, it was approved under its own edited rules,
    // which the push then voided ("given under a different policy") however often it was approved.
    // (The message for an approval that does not count is covered by the signed-approval and
    // gate tests.)
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
    assert_eq!(code(&s.run(&["policy", "set", "approvals.expire_days", "3"])), 0);
    s.commit_all("shorter approvals");
    let held = push();
    assert!(!held.status.success(), "a change to the rules is held until a person approves it");
    let approve = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approve), 0, "{}", text(&approve));
    let landed = push();
    let said = String::from_utf8_lossy(&landed.stderr).to_string();
    assert!(!said.contains("does not count"), "the approval counts under the rules that judge the push:\n{said}");
    assert!(landed.status.success(), "the approved change goes through:\n{said}");
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
    let wf = fs::read_to_string(s.path(".github/workflows/05-gate.yml")).unwrap();
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
    let answers = "2\n\n\n\n\n\n\nlint: npm run lint\n\n\nLICENSE\n\n\n\n\n\n\n\n\n\n";
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
    let answers = "\n\n\n\n\n\n\n\n\n\n\n\n\n4\n\n\n2\n\n\n";
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], answers);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    assert_eq!(p.drift.scope, use05_core::policy::Severity::Deny);
    assert_eq!(p.branches.land, use05_core::policy::LandMode::Auto);
    assert!(text(&out).contains("use05 approve --outcome"), "a policy change is approved like any protected change: {}", text(&out));
}

/// Run with an answer typed and then silence: the input stays open, as with a person who left.
fn run_then_silence(s: &Sandbox, args: &[&str], typed: &str, envs: &[(&str, &str)]) -> (Output, std::time::Duration) {
    use std::io::Write;
    let mut cmd = s.command(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let started = std::time::Instant::now();
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(typed.as_bytes()).unwrap();
    // The input is still open while we wait: it is dropped only after the command is done.
    let child_out = child.wait_with_output().unwrap();
    drop(stdin);
    (child_out, started.elapsed())
}

#[test]
fn guided_init_gives_up_after_the_prompt_timeout() {
    let s = with_environment_branches();
    let (out, took) = run_then_silence(&s, &["init", "--guided"], "2\n", &[("USE05_PROMPT_TIMEOUT_SECS", "1")]);
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(took < std::time::Duration::from_secs(30), "it gave up, it did not wait: {took:?}");
    let shown = text(&out);
    assert!(shown.contains("No answer in 1 second; nothing was written.") && shown.contains("use05 init --defaults"), "{shown}");
    assert!(!s.path(".05/policy.toml").exists() && !s.path(".claude/settings.local.json").exists(), "nothing was written");
    let (out, _) = run_then_silence(&s, &["init", "--guided", "--json"], "2\n", &[("USE05_PROMPT_TIMEOUT_SECS", "1")]);
    assert_eq!((code(&out), json(&out)["code"].clone()), (1, serde_json::json!("INIT_NO_ANSWER")), "{}", text(&out));
    // The wait is for a person only: no questions with --defaults.
    assert_eq!(code(&s.run_env(&["init", "--defaults"], &[("USE05_PROMPT_TIMEOUT_SECS", "1")])), 0);
}

#[test]
fn policy_edit_gives_up_after_the_prompt_timeout_and_leaves_the_policy_alone() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    let before = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let (out, _) = run_then_silence(&s, &["policy", "--edit", "--guided"], "\n", &[("USE05_PROMPT_TIMEOUT_SECS", "1")]);
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("No answer in 1 second; nothing was written."), "{}", text(&out));
    assert_eq!(fs::read_to_string(s.path(".05/policy.toml")).unwrap(), before);
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
fn init_presets_set_who_may_promote_into_the_last_rung() {
    let envs = ["--target", "main", "--env", "dev=main", "--env", "uat=uat", "--env", "prod=production"];
    let prod = |team: &str| {
        let s = with_environment_branches();
        let out = s.run(&[&["init", "--team", team][..], &envs].concat());
        assert_eq!(code(&out), 0, "{}", text(&out));
        let p = policy_of(&s);
        let prod = p.environment_named("prod").unwrap().clone();
        (prod.agent, prod.rules.sign_off, p.environment_named("uat").unwrap().agent)
    };
    use use05_core::policy::Severity;
    // Just you: agents promote everywhere. A small team: prod for people (the default, unset).
    // Larger or regulated: prod for people, with a person's sign-off.
    assert_eq!(prod("solo"), (Some(true), Severity::Allow, None));
    assert_eq!(prod("small"), (None, Severity::Allow, None));
    assert_eq!(prod("regulated"), (None, Severity::Approval, None));
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
    let answers = format!("\n\n\n\n\n\n\n\n{long}\n\n\n\n\n2\n\n\n\n\n\n");
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
    assert!(no_block(&stop(true)), "asked once, never in a loop");

    s.write("docs/api.md", "# API\n\napi() changed.\n");
    assert!(no_block(&stop(false)), "the rule is met");
    let brief = s.run(&["brief", "--task", &find_task(&s, "docs"), "--json"]);
    assert!(!finding_codes(&brief).contains(&"ALSO_CHANGE_MISSING".to_string()), "{}", text(&brief));
}

#[test]
fn the_setup_asks_which_folders_change_with_code_and_how_strict_fresh_base_is() {
    let s = with_environment_branches();
    // team, landing, envs x3, add none, keep checks, add none, protected, locked, append-only,
    // no-read, docs = docs/**, scope, tests, fresh base = 4 (refuse), land, write.
    let answers = "\n\n\n\n\n\n\n\n\n\n\n\ndocs/**\n\n\n4\n\n\n\n";
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
    let out = s.run_with_stdin(&["policy", "--edit", "--guided"], &format!("{}2\n\n\n\n", "\n".repeat(15)));
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
    assert!(no_block(&stop(false)), "{}", text(&stop(false)));

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
    assert!(no_block(&stop(true)), "never asked twice");
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
        use05_receipt::Bypass { env: None, from: None, rule: None, policy_sha256: None, reason: "r".into(), by: "b".into(), findings: vec![], created: "2026-11-01T00:00:00Z".into(), expires: "2099-01-01T00:00:00Z".into() },
    );
    s.write("bypass.json", &sign_with_passkey_only(&to_sign(&serde_json::to_vec(&bypass).unwrap()), &sk));
    s.write("phone.pub", &use05_receipt::passkey_public_text(&key));
    let out = s.run(&["verify", "bypass.json", "--key", "phone.pub", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["code"], "PASSKEY_APPROVALS_ONLY");
}

/// The policy digest an unsigned approval of the current task's intent would carry.
fn approval_policy_digest(s: &Sandbox) -> String {
    use base64::Engine;
    let unsigned = json(&s.run(&["approve", "--unsigned", "--intent", "--json"]));
    let body = base64::engine::general_purpose::STANDARD.decode(unsigned["details"]["payload"].as_str().unwrap_or_else(|| panic!("an unsigned approval has a payload: {unsigned}"))).unwrap();
    let statement: Value = serde_json::from_slice(&body).unwrap();
    statement["predicate"]["policy_sha256"].as_str().unwrap().to_string()
}

#[test]
fn an_approval_is_signed_under_the_rules_a_push_will_be_judged_by() {
    // A task that began before the policy changed must still be approved under the policy on the
    // remote, which is what the pre-push gate reads. Before, the task's own start commit was used,
    // so every approval was voided ("given under a different policy") however often it was given.
    let s = Sandbox::initialised();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["push", "-q", "--no-verify", "origin", "HEAD:refs/heads/main"]);
    assert_eq!(code(&s.run(&["start", "Add a page", "--scope", "src/**"])), 0);
    let at_start = approval_policy_digest(&s);

    // The rules change and land on the remote after the task began.
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(policy.contains("expire_days = 7"), "the template this test edits has changed");
    s.write(".05/policy.toml", &policy.replace("expire_days = 7", "expire_days = 3"));
    s.commit_all("tighten approvals");
    s.git(&["push", "-q", "--no-verify", "origin", "HEAD:refs/heads/main"]);

    let after = approval_policy_digest(&s);
    assert_ne!(at_start, after, "the approval still signs under the rules the task began with");
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

// ---------------------------------------------------------------- the runner key out of a branch's reach (D94)

/// A stand-in for GitHub's statuses API: answers each request with 201 and hands back what each
/// asked, for up to `n` requests or 60 seconds.
fn statuses_api(n: usize) -> (String, std::thread::JoinHandle<Vec<(String, Value)>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut seen = Vec::new();
        while seen.len() < n && std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body) = loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                got.extend_from_slice(&chunk[..read]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                    if body.len() >= length || read == 0 {
                        break (head.to_string(), body.to_string());
                    }
                }
                assert!(read > 0, "the request ended early: {text}");
            };
            stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            seen.push((head.lines().next().unwrap_or_default().to_string(), serde_json::from_str(&body).unwrap_or(Value::Null)));
        }
        seen
    });
    (url, handle)
}

/// `gate --ci --json` as the 05 gate workflow runs it: started by the 05 workflow's run, with
/// this run's own GITHUB_SHA and ref those of the default branch.
fn gate_workflow_run(s: &Sandbox, secret: Option<&str>, event: &Value, api: &str, summary: &Path) -> Output {
    gate_workflow_run_with(s, secret, event, api, summary, &[])
}

fn gate_workflow_run_with(s: &Sandbox, secret: Option<&str>, event: &Value, api: &str, summary: &Path, extra: &[(&str, &str)]) -> Output {
    let ci_home = tempfile::tempdir().unwrap();
    let path = ci_home.path().join("event.json");
    fs::write(&path, event.to_string()).unwrap();
    let mut cmd = s.command(&["gate", "--ci", "--json"]);
    cmd.env("USE05_HOME", ci_home.path()).env("HOME", ci_home.path()).stdin(Stdio::null());
    for (k, v) in [
        ("GITHUB_EVENT_NAME", "workflow_run"),
        ("GITHUB_EVENT_PATH", path.to_str().unwrap()),
        ("GITHUB_SHA", &s.git(&["rev-parse", "main"])),
        ("GITHUB_REF_NAME", "main"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REPOSITORY", "acme/app"),
        ("GITHUB_API_URL", api),
        ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ("USE05_PUSH_TOKEN", "t0ken"),
    ] {
        cmd.env(k, v);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    if let Some(secret) = secret {
        cmd.env("USE05_RUNNER_KEY", secret);
    }
    cmd.output().unwrap()
}

fn run_event(head: &str, head_repo: &str, base: Option<&str>) -> Value {
    serde_json::json!({
        "workflow_run": {
            "event": "pull_request", "head_sha": head, "head_branch": "feature", "head_repository": { "full_name": head_repo },
            "pull_requests": base.map(|b| vec![serde_json::json!({ "base": { "ref": b } })]).unwrap_or_default(),
        },
        "repository": { "full_name": "acme/app", "default_branch": "main" },
    })
}

#[test]
fn workflow_run_event_gates_the_head_not_the_default_branch() {
    let (s, secret, _remote) = ci_fixture_with("\n[testing]\nlocal = \"required\"\n");
    s.write("main.rs", "fn main() { /* the change */ }\n");
    s.commit_all("change");
    let head = s.git(&["rev-parse", "HEAD"]);
    let tree = s.git(&["rev-parse", "HEAD^{tree}"]);
    // The gate's checkout is wherever its workflow put it: here, the default branch.
    s.git(&["checkout", "-q", "main"]);
    assert_ne!(s.git(&["rev-parse", "HEAD^{tree}"]), tree);
    let summary = s.home.path().join("summary.md");
    let posted = |server: std::thread::JoinHandle<Vec<(String, Value)>>| {
        let seen = server.join().unwrap();
        for (line, _) in &seen {
            assert_eq!(line, &format!("POST /repos/acme/app/statuses/{head} HTTP/1.1"), "the status goes on the change's head");
        }
        seen.into_iter().map(|(_, body)| (body["state"].as_str().unwrap_or_default().to_string(), body["description"].as_str().unwrap_or_default().to_string())).collect::<Vec<_>>()
    };

    // Into another branch than the one testing is asked for: allowed, on the head's tree.
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("release")), &api, &summary);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(json(&out)["brief"]["tree"], tree.as_str(), "it gated the head the event names, not what is checked out");
    assert!(!finding_codes(&out).iter().any(|c| c == "TESTING_REQUIRED" || c == "CI_KEY_EXPOSED"), "{:?}", finding_codes(&out));
    assert_eq!(posted(server), [("pending".into(), "checking".into()), ("success".into(), "allowed".into())]);

    // Into main: held for a person's testing, and the status says so.
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &summary);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert!(finding_codes(&out).contains(&"TESTING_REQUIRED".to_string()), "{:?}", finding_codes(&out));
    assert_eq!(posted(server)[1], ("failure".into(), "needs a person's approval".into()));

    // Without the key nothing is gated, and the status says that too rather than staying pending.
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, None, &run_event(&head, "acme/app", Some("release")), &api, &summary);
    assert_eq!(code(&out), 6, "{}", text(&out));
    assert_eq!(posted(server)[1], ("failure".into(), "05 could not gate this change (NO_RUNNER_KEY)".into()));
}

#[test]
fn a_status_that_cannot_be_posted_fails_the_run_and_says_so() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { /* fine */ }\n");
    s.commit_all("change");
    let head = s.git(&["rev-parse", "HEAD"]);
    let summary = s.home.path().join("summary.md");
    // Nothing listens there.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &summary);
    assert_eq!(code(&out), 4, "an allowed change whose status is missing fails the run:\n{}", text(&out));
    assert_eq!(json(&out)["decision"], "allow");
    let md = fs::read_to_string(&summary).unwrap();
    assert!(md.contains("could not post its `05` status") && md.contains("does not see this verdict"), "{md}");
    assert!(!md.contains("t0ken") && !text(&out).contains("t0ken"), "the token is never quoted");
}

#[test]
fn a_change_from_a_fork_is_gated_and_the_summary_says_where_it_came_from() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { /* from a fork */ }\n");
    s.commit_all("change");
    let head = s.git(&["rev-parse", "HEAD"]);
    let summary = s.home.path().join("summary.md");
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "someone/app", None), &api, &summary);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(server.join().unwrap().len(), 2, "its verdict is posted like any other");
    let md = fs::read_to_string(&summary).unwrap();
    assert!(md.contains("This change came from the fork someone/app") && md.contains("its checks ran as the same user as 05, so they could have read the runner key"), "without a check user it says what that means: {md}");
    assert!(!md.contains("Nothing was pushed"), "without --push it does not claim what it did not do: {md}");
}

#[test]
fn the_summary_says_who_posted_the_status() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { /* who posts */ }\n");
    s.commit_all("change");
    let head = s.git(&["rev-parse", "HEAD"]);
    let summary = s.home.path().join("workflow-token.md");
    let (api, server) = statuses_api(2);
    gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &summary);
    server.join().unwrap();
    let md = fs::read_to_string(&summary).unwrap();
    assert!(md.contains("posted with the workflow token: a branch can forge this status"), "{md}");

    let summary = s.home.path().join("app.md");
    let (api, server) = statuses_api(2);
    gate_workflow_run_with(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &summary, &[("USE05_STATUS_TOKEN", "ghs_app")]);
    assert!(server.join().unwrap().len() == 2);
    let md = fs::read_to_string(&summary).unwrap();
    assert!(md.contains("posted by your 05 app") && !md.contains("can forge"), "{md}");
}

#[test]
fn a_change_with_no_base_is_held_to_the_default_branchs_rules_never_its_own() {
    let (s, secret, _remote) = ci_fixture();
    // A commit with no history in common with main, whose own rules (the same runner key, an
    // easy check) would let it through.
    let easy = s.git(&["show", "main:.05/policy.toml"]).replace("run = [\"./test.sh\"]", "run = [\"true\"]");
    s.git(&["checkout", "-q", "--orphan", "lonely"]);
    s.write(".05/policy.toml", &easy);
    s.write("test.sh", "#!/bin/sh\nexit 1\n");
    s.commit_all("no base");
    let head = s.git(&["rev-parse", "HEAD"]);
    // The gate's checkout is the change itself, as 05-gate.yml leaves it.
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &s.home.path().join("summary.md"));
    server.join().unwrap();
    assert_eq!(code(&out), 2, "main's ./test.sh is what runs, and it fails here:\n{}", text(&out));
    assert!(finding_codes(&out).contains(&"CHECK_FAILED".to_string()), "{:?}", finding_codes(&out));
}

#[test]
fn a_runner_key_on_a_push_event_is_reported_exposed() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { /* exposed */ }\n");
    s.commit_all("change");
    let out = s
        .command(&["gate", "--ci", "--json"])
        .env("USE05_HOME", s.home.path().join("ci"))
        .env("USE05_RUNNER_KEY", &secret)
        .env("GITHUB_EVENT_NAME", "push")
        .env("GITHUB_REF_NAME", "feature")
        .env("GITHUB_REF_TYPE", "branch")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "it warns, and still gates:\n{}", text(&out));
    let v = json(&out);
    let finding = v["brief"]["gate"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "CI_KEY_EXPOSED").cloned().unwrap_or_else(|| panic!("{v}"));
    assert_eq!(finding["effect"], "warn");
    assert!(finding["message"].as_str().unwrap().contains("branch's own workflow"), "{finding}");
    assert!(finding["next"].as_str().unwrap().starts_with("use05 init --ci github"), "{finding}");

    // From the gate a branch cannot change, it is not.
    let head = s.git(&["rev-parse", "HEAD"]);
    let (api, server) = statuses_api(2);
    let out = gate_workflow_run(&s, Some(&secret), &run_event(&head, "acme/app", Some("main")), &api, &s.home.path().join("summary.md"));
    server.join().unwrap();
    assert!(!finding_codes(&out).contains(&"CI_KEY_EXPOSED".to_string()), "{}", text(&out));
}

/// The workflow files as JSON, when Ruby is there to read YAML (GitHub's runners and macOS have it).
fn yaml(path: &Path) -> Option<Value> {
    let out = Command::new("ruby").args(["-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.safe_load(File.read(ARGV[0])))"]).arg(path).output().ok()?;
    assert!(out.status.success(), "{} is not YAML: {}", path.display(), String::from_utf8_lossy(&out.stderr));
    Some(serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn init_ci_writes_two_workflows_and_only_the_gate_has_the_key() {
    let s = Sandbox::initialised();
    let out = s.run(&["init", "--ci", "github"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let (gate_path, start_path) = (s.path(".github/workflows/05-gate.yml"), s.path(".github/workflows/05.yml"));
    let (gate, start) = (fs::read_to_string(&gate_path).unwrap(), fs::read_to_string(&start_path).unwrap());
    assert!(!start.contains("secrets.") && start.contains("permissions:\n  contents: read\n"), "{start}");
    assert!(gate.contains("workflow_run:\n    workflows: [\"05\"]\n    types: [completed]\n") && gate.contains("USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}"), "{gate}");
    match (yaml(&start_path), yaml(&gate_path)) {
        (Some(start), Some(gate)) => {
            // YAML 1.1 reads the key `on` as true.
            let on = |v: &Value| v.get("on").or_else(|| v.get("true")).cloned().unwrap();
            assert_eq!(start["name"], "05", "the gate starts on the run of the workflow named 05");
            assert_eq!(start["permissions"], serde_json::json!({ "contents": "read" }));
            assert_eq!(start["jobs"].as_object().unwrap().len(), 1);
            let triggers: Vec<String> = on(&start).as_object().unwrap().keys().cloned().collect();
            assert_eq!(triggers, ["merge_group", "pull_request", "push"]);
            assert_eq!(on(&gate), serde_json::json!({ "workflow_run": { "workflows": ["05"], "types": ["completed"] } }));
            assert_eq!(gate["permissions"], serde_json::json!({ "contents": "write", "statuses": "write" }));
            let job = &gate["jobs"]["gate"];
            assert_eq!(job["environment"], "use05", "the key is an environment secret only the default branch can use");
            let steps = job["steps"].as_array().unwrap();
            let checkout = steps.iter().position(|st| st["uses"].as_str().is_some_and(|u| u.starts_with("actions/checkout@"))).unwrap();
            assert_eq!(steps[checkout]["with"], serde_json::json!({ "ref": "${{ github.event.workflow_run.head_sha }}", "fetch-depth": 0, "persist-credentials": false }));
            // Nothing runs as the key holder once the change is on disk, but the app token and the gate.
            let after: Vec<String> = steps[checkout + 1..].iter().map(|st| st["name"].as_str().unwrap_or_default().to_string()).collect();
            assert_eq!(after, ["Status token from your 05 app", "Prove and gate"]);
            assert!(steps.iter().any(|st| st["run"].as_str().is_some_and(|r| r.contains("useradd --create-home --shell /bin/bash use05-check"))));
            let gating = steps.iter().find(|st| st["run"] == "use05 gate --ci --push").unwrap();
            assert_eq!(gating["env"]["USE05_CHECK_USER"], "use05-check");
            assert_eq!(gating["env"]["USE05_RUNNER_KEY"], "${{ secrets.USE05_RUNNER_KEY }}");
        }
        _ => eprintln!("no ruby here, so the workflows were not read as YAML"),
    }
    snapshot_text("ci_gate_workflow", &gate);
    snapshot_text("ci_start_workflow", &start);

    // Nothing in the repository gives the key away; how GitHub keeps it is said, not checked.
    let doctor = text(&s.run(&["doctor"]));
    assert!(!doctor.contains("an agent's push can read it"), "{doctor}");
    assert!(doctor.contains("cannot read these settings from here"), "{doctor}");
}

#[test]
fn init_ci_locks_workflows_in_a_new_policy() {
    let s = Sandbox::new();
    s.commit_all("first");
    let out = s.run(&["init", "--ci", "github"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let policy = use05_core::policy::Policy::parse(&fs::read_to_string(s.path(".05/policy.toml")).unwrap()).unwrap();
    assert_eq!(policy.protect.locked, [".github/workflows/**"]);
    s.commit_all("set up 05");
    s.write(".github/workflows/05.yml", "name: 05\non: push\njobs: {}\n");
    s.git(&["add", "-A"]);
    let brief = s.run(&["brief", "--json"]);
    assert!(finding_codes(&brief).contains(&"LOCKED_PATH".to_string()), "a branch cannot change the gate: {:?}", finding_codes(&brief));

    // An existing policy is left as it is, and init says how to lock them.
    let t = Sandbox::initialised();
    let before = fs::read_to_string(t.path(".05/policy.toml")).unwrap();
    let out = t.run(&["init", "--ci", "github"]);
    assert!(text(&out).contains("use05 policy add protect.locked \".github/workflows/**\""), "{}", text(&out));
    assert_eq!(fs::read_to_string(t.path(".05/policy.toml")).unwrap(), before);
}

/// The workflow 0.0.13 and earlier wrote: one file, run from each branch's own copy, with the key.
const OLD_WORKFLOW: &str = "name: 05\non:\n  pull_request:\n  push:\n    branches-ignore: [\"05-receipts/**\"]\npermissions:\n  contents: write\njobs:\n  acceptance:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Prove and gate\n        env:\n          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}\n          USE05_PUSH_TOKEN: ${{ github.token }}\n        run: use05 gate --ci --push\n";

#[test]
fn doctor_says_how_to_move_an_old_workflow_that_gives_the_key_to_every_branch() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path(".github/workflows")).unwrap();
    s.write(".github/workflows/05.yml", OLD_WORKFLOW);
    let doctor = s.run(&["doctor"]);
    assert_eq!(code(&doctor), 0, "a warning, not a failure:\n{}", text(&doctor));
    let said = text(&doctor).replace("\n             ", " ");
    assert!(said.contains("! CI key .github/workflows/05.yml gives the runner key to a run the branch defines, so an agent's push can read it. Move to the gate a branch cannot change: use05 init --ci github, then rotate the key"), "{said}");

    // As an earlier use05 wrote it and nobody changed it, init brings it up to date.
    let manifest_path = s.path(".git/05/install.json");
    let mut manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    use sha2::Digest;
    let digest = hex::encode(sha2::Sha256::digest(OLD_WORKFLOW.as_bytes()));
    manifest["items"].as_array_mut().unwrap().push(serde_json::json!({ "kind": "file", "path": ".github/workflows/05.yml", "sha256": digest }));
    fs::write(&manifest_path, manifest.to_string()).unwrap();
    let init = s.run(&["init", "--ci", "github"]);
    assert!(text(&init).contains("replaced .github/workflows/05.yml"), "{}", text(&init));
    assert!(!fs::read_to_string(s.path(".github/workflows/05.yml")).unwrap().contains("secrets."));
    assert!(!text(&s.run(&["doctor"])).contains("an agent's push can read it"));

    // One a person changed is theirs: left alone, and named.
    s.write(".github/workflows/05.yml", &format!("{OLD_WORKFLOW}# ours\n"));
    let init = text(&s.run(&["init", "--ci", "github"])).replace("\n             ", " ");
    assert!(init.contains(".github/workflows/05.yml already exists; left as it is") && init.contains("still gives the runner key"), "{init}");
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
    assert_eq!(code(&out), 3, "a person is needed, as for approve: {}", text(&out));
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

// ----------------------------------------------------------------------------- choosing what to approve, and the one page for everything

/// The text a terminal shows, without its colour codes and carriage returns.
fn plain(screen: &str) -> String {
    let mut out = String::new();
    let mut chars = screen.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// The number a numbered list on `screen` gives the line that holds `title`.
fn number_of(screen: &str, title: &str) -> String {
    let screen = plain(screen);
    let line = screen.lines().find(|l| l.contains(title) && l.trim_start().starts_with(|c: char| c.is_ascii_digit())).unwrap_or_else(|| panic!("no numbered line for {title}:\n{screen}"));
    line.split_whitespace().next().unwrap().to_string()
}

/// A second task waiting for approval beside the first, in the same checkout.
fn two_waiting() -> (Sandbox, String, String) {
    let s = Sandbox::waiting_for_approval();
    let first = json(&s.run(&["approve", "--unsigned", "--json"]))["details"]["task"].as_str().unwrap().to_string();
    // Tasks are ordered by when they last changed, to the second: the second one is made a second later.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = s.run(&["start", "Second change", "--scope", ".05/**", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let second = json(&out)["details"]["task"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    (s, first, second)
}

#[test]
fn approve_names_the_one_task_waiting_before_it_asks_for_anything() {
    let s = Sandbox::waiting_for_approval();
    let out = s.run(&["approve", "--unsigned", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let id = json(&out)["details"]["task"].as_str().unwrap().to_string();
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(said.contains("Approving \"Tighten the policy\"") && said.contains(&id) && said.contains("its change") && said.contains("only task waiting"), "{said}");
}

#[test]
fn approve_with_several_tasks_waiting_fails_without_a_terminal_and_lists_them() {
    let (s, first, second) = two_waiting();
    let before = s.stored_receipts();
    let out = s.run(&["approve", "--reason", "fine", "--json"]);
    assert_eq!(code(&out), 6, "{}", text(&out));
    let v = json(&out);
    assert_eq!(v["code"], "TASK_AMBIGUOUS");
    let message = v["message"].as_str().unwrap();
    assert!(message.contains(&first) && message.contains(&second) && message.contains("Second change") && message.contains("Tighten the policy"), "{message}");
    assert_eq!(v["next"], "use05 approve --task <id>");
    assert_eq!(v["details"]["candidates"].as_array().unwrap().len(), 2, "{v}");
    assert_eq!(s.stored_receipts(), before, "nothing was signed");
    // A pipe is no terminal either: nobody is asked, even with the passphrase on stdin.
    let piped = s.run_with_stdin(&["approve", "--reason", "fine", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&piped), 6, "{}", text(&piped));
    snapshot("approve_ambiguous", &s, &s.run(&["approve", "--reason", "fine"]));
}

#[test]
fn approve_task_still_names_its_task_whatever_else_waits() {
    let (s, first, second) = two_waiting();
    for id in [&first, &second] {
        let out = s.run(&["approve", "--task", id, "--unsigned", "--json"]);
        assert_eq!(code(&out), 0, "{}", text(&out));
        assert_eq!(json(&out)["details"]["task"], *id);
    }
}

#[test]
fn a_person_at_a_terminal_picks_which_of_several_tasks_to_approve() {
    let (s, first, _second) = two_waiting();
    s.approver();
    let before = s.stored_receipts();
    // Quitting the list signs nothing, and shows it.
    let (quit, screen) = on_a_terminal(&s, &["approve", "--reason", "fine"], &["q"]);
    assert_ne!(quit, 0, "{screen}");
    assert!(plain(&screen).contains("2 tasks wait for you") && plain(&screen).contains("Quit, approve nothing"), "{screen}");
    assert_eq!(s.stored_receipts(), before, "quitting signs nothing");

    // The person types the number beside the first task, then the passphrase.
    let number = number_of(&screen, "Tighten the policy");
    let (done, screen) = on_a_terminal(&s, &["approve", "--reason", "reviewed the policy edit"], &[&number, "correct horse"]);
    assert_eq!(done, 0, "{screen}");
    let said = plain(&screen);
    assert!(said.contains("Approving \"Tighten the policy\"") && said.contains(&first), "it names what was chosen: {said}");
    assert!(!screen.contains("correct horse"), "{screen}");
    assert_eq!(s.stored_receipts().len(), before.len() + 1);
}

#[test]
fn approve_with_nothing_waiting_says_so_and_signs_nothing() {
    let s = Sandbox::initialised();
    s.approver();
    let out = s.run(&["approve", "--reason", "fine", "--json"]);
    assert_eq!(code(&out), 6, "{}", text(&out));
    assert_eq!(json(&out)["code"], "NOTHING_WAITS");
    assert!(s.stored_receipts().is_empty());
}

#[test]
fn approving_a_task_approves_its_own_checkout_not_the_one_the_command_ran_in() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/elsewhere");
    let id = task_in(&s, &wt, "Work in a worktree");
    fs::write(wt.join("main.rs"), "fn main() { /* in the worktree */ }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "work"]);
    let out = s.run(&["approve", "--task", &id, "--unsigned", "--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(json(&out)["details"]["tree"], git_at(&wt, &["rev-parse", "HEAD^{tree}"]), "the tree is the worktree's");
    assert_ne!(json(&out)["details"]["tree"], s.git(&["rev-parse", "HEAD^{tree}"]));
}

/// Bare `use05` somewhere that is no repository, with this per-user directory.
fn bare_elsewhere(home: &Path) -> Output {
    let elsewhere = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(BIN);
    cmd.current_dir(elsewhere.path()).env_clear().env("PATH", "/usr/bin:/bin").env("HOME", home).env("USE05_HOME", home).env("LANG", "C.UTF-8").env("COLUMNS", "100").stdin(Stdio::null());
    if let Ok(d) = std::env::var("DEVELOPER_DIR") {
        cmd.env("DEVELOPER_DIR", d);
    }
    cmd.output().unwrap()
}

fn dir_name(s: &Sandbox) -> String {
    s.dir.path().file_name().unwrap().to_string_lossy().to_string()
}

#[test]
fn the_machine_index_records_a_repository_once_and_drops_one_that_is_gone() {
    let a = Sandbox::initialised();
    let b = Sandbox::initialised();
    let home = a.home.path().to_path_buf();
    let index = home.join("repos.tsv");
    let real = |s: &Sandbox| fs::canonicalize(s.dir.path()).unwrap().display().to_string();
    let lists = |s: &Sandbox| fs::read_to_string(&index).unwrap().lines().any(|l| l.ends_with(&format!("\t{}", real(s))));
    assert!(lists(&a), "init lists the repository: {}", fs::read_to_string(&index).unwrap());
    // Another repository, used with the same per-user directory.
    b.run_env(&["doctor"], &[("USE05_HOME", home.to_str().unwrap())]);
    assert!(lists(&b) && lists(&a));
    assert_eq!(fs::read_to_string(&index).unwrap().lines().count(), 2);
    // A command a few minutes later does not write it again.
    let stamp = || fs::metadata(&index).unwrap().modified().unwrap();
    let written = stamp();
    a.run(&["doctor"]);
    a.run(&["brief"]);
    assert_eq!(stamp(), written, "a repository listed moments ago is not rewritten");

    let shown = text(&bare_elsewhere(&home));
    assert!(shown.contains(&dir_name(&a)) && shown.contains(&dir_name(&b)), "{shown}");
    let gone = dir_name(&b);
    drop(b);
    let after = text(&bare_elsewhere(&home));
    assert!(after.contains(&dir_name(&a)) && !after.contains(&gone), "a deleted repository drops off:\n{after}");
}

#[test]
fn a_repository_that_never_set_05_up_is_not_listed_and_uninstall_takes_its_entry_away() {
    let plain_repo = Sandbox::new();
    plain_repo.run(&["brief"]);
    assert!(!plain_repo.home.path().join("repos.tsv").exists(), "looking is not using");

    let s = Sandbox::initialised();
    assert!(s.home.path().join("repos.tsv").exists());
    let out = s.run(&["uninstall"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("list of repositories on this machine"), "{}", text(&out));
    assert!(!s.home.path().join("repos.tsv").exists(), "an empty list leaves no file");
}

#[test]
fn bare_use05_outside_a_repository_lists_the_repositories_most_in_need_first() {
    let quiet = Sandbox::initialised();
    let busy = Sandbox::waiting_for_approval();
    let home = busy.home.path().to_path_buf();
    quiet.run_env(&["doctor"], &[("USE05_HOME", home.to_str().unwrap())]);
    let out = bare_elsewhere(&home);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let shown = text(&out);
    let at = |s: &Sandbox| shown.find(&dir_name(s)).unwrap_or_else(|| panic!("{shown}"));
    assert!(at(&busy) < at(&quiet), "the repository with a task waiting comes first:\n{shown}");
    assert!(shown.contains("Needs you") && shown.contains("Working") && shown.contains("Last active"), "{shown}");
    assert!(shown.contains("&& use05"), "it says how to open one:\n{shown}");
    let row = shown.lines().find(|l| l.contains(&dir_name(&busy))).unwrap();
    assert!(row.split_whitespace().nth(2) == Some("1"), "one task waits there: {row}");
    assert!(!shown.contains("> "), "no prompt without a terminal");
}

#[test]
fn bare_use05_outside_a_repository_prints_the_same_table_for_a_pipe() {
    let busy = Sandbox::waiting_for_approval();
    let out = bare_elsewhere(busy.home.path());
    assert_eq!(code(&out), 0, "{}", text(&out));
    snapshot("status_repos", &busy, &out);
}

#[test]
fn bare_use05_outside_a_repository_on_a_terminal_opens_the_repository_picked() {
    let busy = Sandbox::waiting_for_approval();
    // Somewhere that is no repository, with the same per-user directory.
    let somewhere = Sandbox { dir: tempfile::tempdir().unwrap(), home: tempfile::tempdir().unwrap() };
    fs::copy(busy.home.path().join("repos.tsv"), somewhere.home.path().join("repos.tsv")).unwrap();
    let (code_, screen) = on_a_terminal(&somewhere, &[], &["1", "q"]);
    assert_eq!(code_, 0, "{screen}");
    let shown = plain(&screen);
    assert!(shown.contains("Last active") && shown.contains("Needs you") && shown.contains("Tighten the policy"), "the first row's page was opened:\n{shown}");
}

#[test]
fn bare_use05_in_a_repository_is_one_page_of_who_needs_you_who_is_working_and_what_landed() {
    let s = Sandbox::waiting_for_approval();
    let holder = tempfile::tempdir().unwrap();
    // An agent working in a worktree of its own.
    let working = agent_worktree(&s, &holder, "claude/retries");
    let working_id = task_in(&s, &working, "Add retries");
    // Another that finished, and whose work is already in main.
    let done = agent_worktree(&s, &holder, "claude/docs");
    let done_id = task_in(&s, &done, "Update the docs");
    fs::write(done.join("docs.md"), "# docs\n").unwrap();
    git_at(&done, &["add", "docs.md"]);
    git_at(&done, &["commit", "-qm", "docs"]);
    assert_eq!(code(&s.run(&["finish", "--task", &done_id, "--repo", done.to_str().unwrap(), "--outcome", "wrote the docs"])), 0);
    s.git(&["merge", "-q", "--ff-only", "claude/docs"]);

    let out = s.run(&[]);
    assert_eq!(code(&out), 0);
    let shown = text(&out);
    let line = |needle: &str| shown.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no line with {needle}:\n{shown}")).to_string();
    let waiting = line("Tighten the policy");
    assert!(waiting.starts_with("Needs you") && waiting.contains("change"), "{waiting}");
    let busy = line("Add retries");
    assert!(busy.starts_with("Working") && busy.contains(&working_id), "{busy}");
    let landed = line("Update the docs");
    assert!(landed.starts_with("Recent") && landed.contains(&done_id) && landed.contains("landed on main"), "{landed}");
    assert!(shown.contains("Next: use05 approve --task"), "{shown}");
    assert!(!shown.contains("Open a task"), "no menu without a terminal:\n{shown}");
    snapshot("status_tasks", &s, &out);

    // At a terminal the one thing to do comes first, and Enter does it (D91); the menu still
    // opens a task, and what can be done with it.
    let (picked, screen) = on_a_terminal(&s, &[], &["2", "q"]);
    assert_eq!(picked, 0, "{screen}");
    let screen = plain(&screen);
    assert!(screen.contains("1  Approve \"") && screen.contains("Enter does 1"), "{screen}");
    assert!(screen.contains("Open a task") && screen.contains("Which task?"), "{screen}");
}

/// A Stop hook that asks the agent for nothing: no answer, or only the line for the person (D91).
fn no_block(out: &std::process::Output) -> bool {
    out.stdout.is_empty() || serde_json::from_slice::<Value>(&out.stdout).is_ok_and(|v| v.get("decision").is_none() && v.get("systemMessage").is_some())
}

// ----------------------------------------------------------------------------- the daily flow (D91)

/// A task on its own agent branch whose committed change needs a person: it edits 05's rules.
fn protected_task(s: &Sandbox, holder: &TempDir, branch: &str) -> (PathBuf, String) {
    let wt = agent_worktree(s, holder, branch);
    let id = task_in(s, &wt, "Tighten the rules");
    let policy = fs::read_to_string(wt.join(".05/policy.toml")).unwrap();
    fs::write(wt.join(".05/policy.toml"), policy + "\n# tightened\n").unwrap();
    git_at(&wt, &["commit", "-qam", "tighten"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    (wt, id)
}

#[test]
fn approving_a_change_lands_it_when_asked_or_when_the_policy_lands_on_its_own() {
    let s = Sandbox::initialised();
    s.approver();
    let holder = tempfile::tempdir().unwrap();

    // Without a terminal and without --land, the approval says how to land it, and lands nothing.
    let (wt, id) = protected_task(&s, &holder, "claude/one");
    let before = s.git(&["rev-parse", "main"]);
    let v = json(&s.run_with_stdin(&["approve", "--task", &id, "--passphrase-stdin", "--json"], "correct horse\n"));
    assert_eq!(v["code"], "APPROVED", "{v}");
    assert!(v["next"].as_str().is_some_and(|n| n.contains(&format!("use05 land --task {id}"))), "{v}");
    assert_eq!(s.git(&["rev-parse", "main"]), before, "nothing landed");
    assert_eq!(code(&s.run(&["land", "--task", &id])), 0, "and it can be landed");
    assert!(!wt.exists());

    // --land lands it in the same step.
    let (_, id) = protected_task(&s, &holder, "claude/two");
    let out = s.run_with_stdin(&["approve", "--task", &id, "--land", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(s.git(&["branch", "--list", "claude/two"]).is_empty(), "the branch was cleaned up");
    let holder_real = fs::canonicalize(holder.path()).unwrap().display().to_string();
    let masked = Output { status: out.status, stdout: String::from_utf8_lossy(&out.stdout).replace(&holder_real, "<WORKTREES>").into_bytes(), stderr: out.stderr.clone() };
    snapshot("approve_land", &s, &masked);

    // With land = "auto" an approval lands it without being asked.
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("land = \"manual\"", "land = \"auto\""));
    s.commit_all("land on its own");
    s.run_with_stdin(&["approve", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    let (wt, id) = protected_task(&s, &holder, "claude/three");
    let head = git_at(&wt, &["rev-parse", "HEAD"]);
    let v = json(&s.run_with_stdin(&["approve", "--task", &id, "--passphrase-stdin", "--json"], "correct horse\n"));
    assert_eq!(v["details"]["landed"], true, "{v}");
    assert_eq!(s.git(&["rev-parse", "main"]), head);
}

#[test]
fn land_push_pushes_the_landing_branch_through_the_pre_push_hook() {
    let s = Sandbox::initialised();
    let remote = tempfile::tempdir().unwrap();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote.path().display().to_string()]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote.path().display().to_string()]);
    s.git(&["push", "-q", "origin", "main"]);
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/push");
    let id = task_in(&s, &wt, "Push it");
    fs::write(wt.join("main.rs"), "fn main() { 12; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "push it"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    let head = git_at(&wt, &["rev-parse", "HEAD"]);

    // Without a terminal or --push, landing leaves the push to the person.
    let out = s.run(&["land", "--task", &id, "--push", "--json"]);
    let v = json(&out);
    assert_eq!((v["code"].as_str(), v["details"]["pushed"].as_bool()), (Some("LANDED"), Some(true)), "{v}");
    assert!(v["next"].is_null(), "nothing is left to do: {v}");
    let remote_main = Command::new("git").arg("-C").arg(remote.path()).args(["rev-parse", "main"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&remote_main.stdout).trim(), head);
}

#[test]
fn when_the_agent_stops_the_person_reads_where_the_work_stands_once() {
    let s = Sandbox::with_agent_hooks();
    assert_eq!(code(&s.run(&["prove", "test"])), 0);
    hook(&s, "s1", "PostToolUse", "Edit", "main.rs");
    s.write("main.rs", "fn main() { 13; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let v = json(&stop(&s, "claude-code", "s1", false));
    let line = v["systemMessage"].as_str().unwrap_or_else(|| panic!("{v}"));
    assert!(v.get("decision").is_none(), "nothing is asked of the agent: {v}");
    assert!(line.starts_with("05: allowed, nothing to read (1 file, checks passed)"), "{line}");
    assert!(stop(&s, "claude-code", "s1", false).stdout.is_empty(), "the same news is not said twice");

    // A change that needs the person says so, and how to approve it.
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# edit\n"));
    s.git(&["add", "-A"]);
    let v = json(&stop(&s, "claude-code", "s1", false));
    let line = v["systemMessage"].as_str().unwrap_or_else(|| panic!("{v}"));
    assert!(line.starts_with("05: needs you") && line.ends_with("Approve: use05 approve"), "{line}");
    // The generic answer carries it as `message`.
    let generic = s.run_with_stdin(&["hook", "generic", "Stop"], &serde_json::json!({ "session_id": "s1", "cwd": s.dir.path(), "hook_event_name": "Stop" }).to_string());
    assert!(generic.stdout.is_empty() || json(&generic)["message"].is_string(), "{}", text(&generic));
}

// ---------------------------------------------------------------- assurance beside the verdict (D101)

impl Sandbox {
    /// Through `init` with no test script to find, so the policy requires no checks.
    fn without_checks(agent_hooks: bool) -> Sandbox {
        let s = Sandbox::new();
        if agent_hooks {
            fs::create_dir_all(s.path(".claude")).unwrap();
        }
        s.commit_all("first");
        let init = s.run(&["init"]);
        assert_eq!(code(&init), 0, "{}", text(&init));
        assert!(!fs::read_to_string(s.path(".05/policy.toml")).unwrap().contains("\n[[check]]"), "no check was detected");
        s.commit_all("add 05");
        s
    }
}

#[test]
fn an_agent_told_05_is_too_old_is_asked_to_stop_not_to_install_it() {
    // Seen with Codex: given an install command, an agent runs it on the person's machine.
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", "[use05]\nmin_version = \"99.0.0\"\n");
    s.commit_all("needs a newer 05");
    let person = json(&s.run(&["policy", "--json"]));
    assert!(person["next"].as_str().unwrap().starts_with("upgrade: npm i -g @use05/cli"), "{person:#}");
    let out = s.command(&["policy", "--json"]).env("CLAUDE_CODE_SESSION_ID", "s1").stdin(Stdio::null()).output().unwrap();
    let agent = json(&out);
    assert_eq!(agent["code"], "POLICY_NEEDS_NEWER", "{agent:#}");
    assert!(agent["next"].as_str().unwrap().starts_with("stop and ask the user to upgrade 05") && !agent["next"].as_str().unwrap().contains("curl"), "{agent:#}");
    // And AGENTS.md says it before anything is tried.
    assert!(fs::read_to_string(s.path("AGENTS.md")).unwrap().contains("If `use05` is missing or says it is too old, stop and ask the user to install or upgrade it. Do not install it yourself."));
}

#[test]
fn doctor_says_when_nothing_is_ever_run_and_how_to_add_a_check_that_works() {
    let s = Sandbox::without_checks(false);
    let out = text(&s.run(&["doctor"]));
    assert!(out.contains("no required checks, so 05 never runs anything here to see whether a change works"), "{out}");
    // Not yet committed, as just after `use05 init`, it is said of the file as written.
    s.git(&["rm", "-q", "--cached", ".05/policy.toml"]);
    s.git(&["commit", "-q", "-m", "not yet"]);
    let out = text(&s.run(&["doctor"]));
    assert!(out.contains("is valid but not committed") && out.contains("no required checks"), "{out}");
    s.git(&["add", ".05/policy.toml"]);
    s.commit_all("add 05 again");
    // A test command it can find is named exactly, and the command it prints works as printed.
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    let out = text(&s.run(&["doctor"]));
    let add = out.split("Add the command that decides it: ").nth(1).map(|t| t.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default();
    let quoted = add.split('\'').nth(1).unwrap_or_default().to_string();
    assert!(add.starts_with("use05 policy add check '{ name = \"test\""), "{out}");
    let added = s.run(&["policy", "add", "check", &quoted]);
    assert_eq!(code(&added), 0, "{}", text(&added));
    assert_eq!(policy_of(&s).check.len(), 1, "the check is in the policy now");
    assert!(!text(&s.run(&["doctor"])).contains("no required checks"), "the file as written has a check");
    // Committed, it is the rules, and the note is still gone.
    s.commit_all("add the test check");
    assert!(!text(&s.run(&["doctor"])).contains("no required checks"));
}

/// The brief's fields as 0.0.13 printed them: every one is still there, with nothing renamed.
const BRIEF_FIELDS_0_0_13: [&str; 25] = [
    "label", "title", "task_id", "author", "request", "agent", "owner", "owner_confirmed", "sandbox", "goal", "card", "risk", "tree", "tree_label",
    "areas", "area_summary", "added", "removed", "outside_scope", "outside_scope_areas", "gate", "unknowns", "undo", "session", "lands_on",
];

#[test]
fn a_change_allowed_with_no_checks_says_so_beside_the_verdict() {
    let s = Sandbox::without_checks(false);
    s.write("main.rs", "fn main() { 1; }\n");
    s.git(&["add", "-A"]);
    let out = s.run(&["brief"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let words = text(&out);
    // D66's label stays; the line under it says what it rests on.
    assert!(words.contains("✓ ALLOW  nothing to read\n  Checks: none required; behaviour not verified\n"), "{words}");
    assert!(!words.contains("Behaviour beyond these checks"), "folded into the checks line when nothing ran: {words}");
    for word in ["verified correct", "proven", "score"] {
        assert!(!words.contains(word), "{word}: {words}");
    }
    snapshot("brief_no_checks", &s, &out);

    // The bare page keeps the label and adds the qualifier.
    let bare = text(&s.run(&[]));
    assert!(bare.contains("✓ ALLOW nothing to read (no checks ran, behaviour not verified)"), "{bare}");
}

#[test]
fn brief_json_keeps_every_existing_field_and_adds_assurance() {
    let s = Sandbox::without_checks(false);
    s.write("main.rs", "fn main() { 2; }\n");
    s.git(&["add", "-A"]);
    let v = json(&s.run(&["brief", "--json"]));
    let top: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(top, ["brief", "command", "decision", "label", "overlap", "v"], "the envelope is unchanged");
    let brief = v["brief"].as_object().unwrap();
    for field in BRIEF_FIELDS_0_0_13 {
        assert!(brief.contains_key(field), "{field} is still printed: {v}");
    }
    let added: Vec<&str> = brief.keys().map(String::as_str).filter(|k| !BRIEF_FIELDS_0_0_13.contains(k)).collect();
    assert_eq!(added, ["assurance", "story"], "two objects are added (D101, D102), nothing else");
    let story: Vec<&str> = v["brief"]["story"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(story, ["agent_says", "asked", "checked", "claim_counts", "claims", "needs_you", "not_known", "observed"], "{v}");
    let a = &v["brief"]["assurance"];
    let keys: Vec<&str> = a.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["behaviour", "checks_required", "enforcement", "evidence", "failed", "limitations", "local_only", "missing", "not_accepted", "not_required", "passed", "stale", "summary", "test_origin", "tests_changed"], "{a}");
    assert_eq!((a["checks_required"].as_u64(), a["evidence"].as_str(), a["behaviour"].as_str(), a["enforcement"].as_str()), (Some(0), Some("none"), Some("not_assessed"), Some("unknown")), "{a}");
    assert_eq!(a["summary"], "none required; behaviour not verified");
    // The unknowns are what they were.
    assert!(v["brief"]["unknowns"].as_array().unwrap().iter().any(|u| u == "policy requires no checks, so nothing was verified by running anything"), "{v}");
}

#[test]
fn the_assurance_changes_no_decision_label_or_exit_code() {
    // Each fixture: what the gate decided before the assurance existed, and what the summary says.
    let none = Sandbox::without_checks(false);
    none.write("main.rs", "fn main() { 3; }\n");
    none.git(&["add", "-A"]);

    let local = Sandbox::initialised();
    local.write("main.rs", "fn main() { 3; }\n");
    local.git(&["add", "-A"]);
    assert_eq!(code(&local.run(&["prove"])), 0);

    let unproved = Sandbox::initialised();
    unproved.write("main.rs", "fn main() { 3; }\n");
    unproved.git(&["add", "-A"]);

    let failing = Sandbox::initialised();
    failing.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"false\"]\n");
    failing.commit_all("failing check");
    failing.write("main.rs", "fn main() { 3; }\n");
    failing.git(&["add", "-A"]);
    failing.run(&["prove"]);

    let protected = Sandbox::initialised();
    protected.write(".05/policy.toml", &(fs::read_to_string(protected.path(".05/policy.toml")).unwrap() + "\n# edited\n"));
    protected.git(&["add", "-A"]);
    assert_eq!(code(&protected.run(&["prove"])), 0);

    let cases: [(&Sandbox, &str, &str, i32, &str); 5] = [
        (&none, "allow", "allow", 0, "none required; behaviour not verified"),
        (&local, "allow", "allow", 0, "1 passed on the machine that ran it (advisory: an agent can run as its user)"),
        (&unproved, "wait", "wait", 5, "1 not run on this tree"),
        (&failing, "deny", "deny", 2, "1 failed"),
        (&protected, "approval_required", "approval_required", 3, "1 passed on the machine that ran it (advisory: an agent can run as its user)"),
    ];
    for (s, decision, label, exit, summary) in cases {
        let out = s.run(&["brief", "--json"]);
        let v = json(&out);
        assert_eq!((v["decision"].as_str(), v["label"].as_str(), code(&out)), (Some(decision), Some(label), exit), "{v}");
        assert_eq!(v["brief"]["gate"]["decision"], decision);
        assert_eq!(v["brief"]["assurance"]["summary"], summary, "{v}");
        // The words and the JSON agree, and the human brief exits the same way.
        let words = s.run(&["brief"]);
        assert_eq!(code(&words), exit);
        assert!(text(&words).contains(&format!("  Checks: {summary}")), "{}", text(&words));
    }
}

#[test]
fn agent_claim_contradicted_by_failing_check_is_shown_as_claim() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"false\"]\n");
    s.commit_all("failing check");
    s.run(&["start", "Anything"]);
    s.write("main.rs", "fn main() { /* x */ }\n");
    s.git(&["add", "-A"]);
    s.run(&["finish", "--outcome", "All tests pass."]);
    s.run(&["prove"]);
    let out = s.run(&["brief"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    let words = text(&out);
    // The agent's words are its claim, shown as one; the checks line counts what the check did.
    assert!(words.contains("Claims     ✗ \"All tests pass\" contradicted: test did not pass"), "{words}");
    assert!(words.contains("did not pass\n\n  Checks: 1 failed\n  Behaviour beyond these checks: not assessed\n"), "apart from the numbered reasons: {words}");
    let v = json(&s.run(&["brief", "--json"]));
    assert_eq!((v["brief"]["assurance"]["passed"].as_u64(), v["brief"]["assurance"]["failed"].as_u64()), (Some(0), Some(1)), "{v}");
}

#[test]
fn the_story_keeps_the_agents_words_apart_from_what_05_saw_and_checked() {
    let s = Sandbox::initialised();
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"false\"]\n");
    s.commit_all("failing check");
    s.run(&["start", "Cap the retries"]);
    s.write("main.rs", "fn main() { /* x */ }\n");
    s.git(&["add", "-A"]);
    s.run(&["finish", "--outcome", "Capped the retries at three. All tests pass."]);
    s.run(&["prove"]);
    let words = text(&s.run(&["brief"]));
    // The agent's words are said to be its own, and its claim is shown against the check that
    // contradicts it; what 05 saw and what the check found are said as 05's.
    assert!(words.contains("Story      asked: not recorded"), "{words}");
    assert!(words.contains("agent says: \"Capped the retries at three. All tests pass.\" (its own words)"), "{words}");
    assert!(words.contains("agent's claims: 1 contradicted by a check"), "{words}");
    assert!(words.contains("05 saw: 1 file changed in the top folder · +1 −1"), "{words}");
    assert!(words.contains("checked: 1 failed"), "{words}");
    assert!(words.contains("needs you:"), "a failed check holds it: {words}");
    let v = json(&s.run(&["brief", "--json"]));
    let st = &v["brief"]["story"];
    assert_eq!(st["claims"][0]["status"], "contradicted", "{st}");
    assert_eq!(st["claim_counts"]["contradicted"], 1);
    // An agent's words are never among what 05 saw or what the checks found.
    for line in st["observed"].as_array().unwrap().iter().chain([&st["checked"]]) {
        assert!(!line.as_str().unwrap().contains("retries"), "{line}");
    }
    // The story decides nothing: the decision is the gate's, as before.
    assert_eq!(v["decision"], "deny");
}

#[test]
fn the_story_says_whether_the_tests_stand_apart_from_the_change() {
    let origin = |s: &Sandbox| {
        let v = json(&s.run(&["brief", "--json"]));
        (v["brief"]["assurance"]["test_origin"].as_str().unwrap_or_default().to_string(), v["brief"]["story"].clone())
    };
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("tests")).unwrap();
    s.write("tests/parser_test.rs", "#[test]\nfn parses() {}\n");
    s.commit_all("tests");
    // Unchanged this time, but no rule keeps a change from rewriting them.
    s.write("main.rs", "fn main() { 8; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let (o, st) = origin(&s);
    assert_eq!(o, "not_protected", "{st}");
    assert!(st["not_known"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("whether the tests stand apart from the change")), "{st}");
    // The policy protects them: a change to one needs a person.
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap().replace("[protect]\n", "[protect]\nappend_only = [\"tests/**\", \"test.sh\"]\n");
    s.write(".05/policy.toml", &policy);
    s.commit_all("protect the tests");
    s.write("main.rs", "fn main() { 9; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let (o, st) = origin(&s);
    assert_eq!(o, "protected", "{st}");
    assert!(st["observed"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("the test files are under the policy's protect rules")), "{st}");
    // The change edits a test itself: it partly grades itself, whatever the rules.
    s.write("tests/new_test.rs", "#[test]\nfn always() {}\n");
    s.git(&["add", "-A"]);
    let (o, _) = origin(&s);
    assert_eq!(o, "edited_by_change");
}

#[test]
fn the_story_of_a_good_change_and_of_one_waiting_for_a_person() {
    // A change in no risk area, its check passed: nothing needs anyone.
    let s = Sandbox::initialised();
    s.write("main.rs", "fn main() { 7; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let st = json(&s.run(&["brief", "--json"]))["brief"]["story"].clone();
    assert_eq!(st["needs_you"].as_array().unwrap().len(), 0, "{st}");
    assert_eq!(st["checked"], "1 passed on the machine that ran it (advisory: an agent can run as its user)");
    assert_eq!(st["not_known"][0], "behaviour beyond these checks");
    // A change to a protected path: what holds it is the first thing a person reads after the facts.
    s.write(".05/policy.toml", &format!("{}\n# tightened\n", fs::read_to_string(s.path(".05/policy.toml")).unwrap()));
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let st = json(&s.run(&["brief", "--json"]))["brief"]["story"].clone();
    assert!(st["needs_you"][0].as_str().unwrap().contains("protected file(s) changed"), "{st}");
}

#[test]
fn the_story_says_a_person_must_try_it_when_the_rules_ask_for_testing_before_a_push() {
    // The brief is not a push, so it allows; but trying it is still a person's to do before one.
    let s = Sandbox::initialised();
    assert_eq!(code(&s.run(&["policy", "set", "testing.local", "required"])), 0);
    s.commit_all("testing before a push");
    s.write("main.rs", "fn main() { 9; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let st = json(&s.run(&["brief", "--json"]))["brief"]["story"].clone();
    assert!(st["needs_you"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("a person must try it in their own environment")), "{st}");
}

#[test]
fn a_change_that_edits_its_own_tests_says_so_under_the_checks_line() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("tests")).unwrap();
    s.write("tests/parser_test.rs", "#[test]\nfn parses() { assert!(true); }\n");
    s.write("main.rs", "fn main() { 4; }\n");
    s.git(&["add", "-A"]);
    assert_eq!(code(&s.run(&["prove"])), 0);
    let words = text(&s.run(&["brief"]));
    assert!(
        words.contains("  Checks: 1 passed on the machine that ran it (advisory: an agent can run as its user)\n  Note: this change also edits 1 test file(s), so it partly grades itself\n  Behaviour beyond these checks: not assessed"),
        "{words}"
    );
    // Narrow, plain and ASCII terminals still hold every line within the width.
    for width in ["40", "60"] {
        let out = s.command(&["brief"]).env("COLUMNS", width).stdin(Stdio::null()).output().unwrap();
        let w: usize = width.parse().unwrap();
        for line in text(&out).lines() {
            assert!(line.chars().count() <= w, "width {w}: {line:?}\n{}", text(&out));
        }
        assert!(text(&out).contains("partly grades itself"), "{}", text(&out));
    }
    let ascii = s.command(&["brief"]).env("LANG", "C").stdin(Stdio::null()).output().unwrap();
    assert!(String::from_utf8_lossy(&ascii.stdout).is_ascii() && text(&ascii).contains("Checks: 1 passed"), "{}", text(&ascii));
}

#[test]
fn when_no_check_ran_the_agent_window_says_so_and_keeps_the_label() {
    let s = Sandbox::without_checks(true);
    hook(&s, "s1", "PostToolUse", "Edit", "main.rs");
    s.write("main.rs", "fn main() { 5; }\n");
    s.git(&["add", "-A"]);
    let v = json(&stop(&s, "claude-code", "s1", false));
    let line = v["systemMessage"].as_str().unwrap_or_else(|| panic!("{v}"));
    assert_eq!(line, "05: allowed, nothing to read (1 file; no checks ran, behaviour not verified). Commit and push when you are ready.");
}

#[test]
fn a_change_landed_with_no_checks_is_not_said_to_have_passed_them() {
    let s = Sandbox::without_checks(true);
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("land = \"manual\"", "land = \"auto\""));
    s.commit_all("land automatically");
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/nochecks");
    let payload = |event: &str| serde_json::json!({ "session_id": "s1", "cwd": wt, "hook_event_name": event, "tool_name": "Edit", "tool_input": { "file_path": wt.join("main.rs") } }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "PostToolUse"], &payload("PostToolUse"));
    fs::write(wt.join("main.rs"), "fn main() { 6; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "no checks"]);
    let out = s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload("Stop"));
    assert_eq!(code(&out), 0, "{}", text(&out));
    let line = json(&out)["systemMessage"].as_str().map(str::to_string).unwrap_or_else(|| panic!("{}", text(&out)));
    assert!(line.contains("landed on main") && line.contains("no checks ran, behaviour not verified") && !line.contains("passed its checks"), "{line}");
}

#[test]
fn a_change_landed_by_a_bypass_over_a_failed_check_is_not_said_to_have_passed_it() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path(".claude")).unwrap();
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"sh\", \"-c\", \"! grep -q broken main.rs\"]\n\n[branches]\nland = \"auto\"\n");
    s.commit_all("a check that fails on broken code, and landing on its own");
    s.approver();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/bypassed");
    let payload = |event: &str| serde_json::json!({ "session_id": "s1", "cwd": wt, "hook_event_name": event, "tool_name": "Edit", "tool_input": { "file_path": wt.join("main.rs") } }).to_string();
    s.run_with_stdin(&["hook", "claude-code", "PostToolUse"], &payload("PostToolUse"));
    fs::write(wt.join("main.rs"), "fn main() { /* broken */ }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "broken"]);
    let head = git_at(&wt, &["rev-parse", "HEAD"]);
    let wt_repo = wt.to_str().unwrap();
    assert_eq!(code(&s.run(&["prove", "--repo", wt_repo])), 2, "the check fails on this tree");
    let bypass = s.run_with_stdin(&["bypass", "--reason", "production is down", "--tree", &head, "--repo", wt_repo, "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&bypass), 0, "{}", text(&bypass));
    let out = s.run_with_stdin(&["hook", "claude-code", "Stop"], &payload("Stop"));
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(s.git(&["rev-parse", "main"]), head, "the bypass let it land: {}", text(&out));
    let line = json(&out)["systemMessage"].as_str().map(str::to_string).unwrap_or_else(|| panic!("{}", text(&out)));
    assert!(line.contains("landed on main (allowed by a bypass)") && !line.contains("passed its checks"), "{line}");
}

#[test]
fn the_ci_gate_says_its_checks_were_signed_by_ci_but_not_that_merging_requires_them() {
    let (s, secret, _remote) = ci_fixture();
    s.write("main.rs", "fn main() { println!(\"ci\"); }\n");
    s.commit_all("improve");
    let out = gate_ci(&s, Some(&secret), &["--json"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let a = &json(&out)["brief"]["assurance"];
    assert_eq!((a["evidence"].as_str(), a["enforcement"].as_str(), a["local_only"].as_u64()), (Some("runner_signed"), Some("ci_gate"), Some(0)), "{a}");
    assert_eq!(a["summary"], "1 passed, signed by CI (merge enforcement not confirmed from here)");
    let words = gate_ci(&s, Some(&secret), &[]);
    assert!(text(&words).contains("  Checks: 1 passed, signed by CI (merge enforcement not confirmed from here)"), "{}", text(&words));
}

#[test]
fn a_push_that_needs_a_person_is_approved_right_there_at_the_terminal() {
    let s = Sandbox::initialised();
    s.approver();
    // A task began earlier, and work since then is already on the remote: the person is shown
    // what this push holds (one file), not everything since the task began.
    s.run(&["start", "Earlier work", "--scope", "**"]);
    s.write("earlier.rs", "fn earlier() {}\n");
    s.commit_all("earlier, already pushed");
    let base = s.git(&["rev-parse", "HEAD"]);
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# tightened\n"));
    s.commit_all("tighten");
    let local = s.git(&["rev-parse", "HEAD"]);
    let refs = format!("refs/heads/main {local} refs/heads/main {base}");
    // Declined: the push stays stopped.
    let (no, screen) = on_a_terminal(&s, &["gate", "--git-hook", "pre-push"], &[&refs, "\x04", "n"]);
    assert_eq!(no, 1, "{screen}");
    assert!(plain(&screen).contains("Approve it now?"), "{}", plain(&screen));
    // Enter, then the passphrase: approved, and the push goes on.
    let (yes, screen) = on_a_terminal(&s, &["gate", "--git-hook", "pre-push"], &[&refs, "\x04", "correct horse"]);
    assert_eq!(yes, 0, "{}", plain(&screen));
    assert!(plain(&screen).contains("05: Approved"), "{}", plain(&screen));
    assert!(plain(&screen).contains("1 file(s) changed"), "{}", plain(&screen));
    assert!(!screen.contains("correct horse"), "the passphrase is never echoed");
}

#[test]
fn the_bare_page_offers_to_land_what_is_allowed_and_enter_does_it() {
    let s = Sandbox::initialised();
    let holder = tempfile::tempdir().unwrap();
    let wt = agent_worktree(&s, &holder, "claude/ready");
    let id = task_in(&s, &wt, "Ready to land");
    fs::write(wt.join("main.rs"), "fn main() { 14; }\n").unwrap();
    git_at(&wt, &["commit", "-qam", "ready"]);
    assert_eq!(code(&s.run(&["prove", "--repo", wt.to_str().unwrap()])), 0);
    s.run(&["finish", "--task", &id, "--repo", wt.to_str().unwrap(), "--outcome", "done"]);
    let shown = text(&s.run(&[]));
    assert!(shown.contains(&format!("Next: use05 land --task {id}")), "{shown}");
    let head = git_at(&wt, &["rev-parse", "HEAD"]);
    let (done, screen) = on_a_terminal(&s, &[], &[""]);
    assert_eq!(done, 0, "{}", plain(&screen));
    assert!(plain(&screen).contains("1  Land \"Ready to land\""), "{}", plain(&screen));
    assert_eq!(s.git(&["rev-parse", "main"]), head, "Enter landed it");
}

// ---------------------------------------------------------------- Git LFS in the exact tree (D96)

const LFS_ATTRIBUTES: &str = "*.bin filter=lfs diff=lfs merge=lfs -text\n";

fn lfs_pointer(oid_byte: &str, size: u64) -> String {
    format!("version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {size}\n", oid_byte.repeat(32))
}

/// A sandbox whose staged tree holds two LFS pointers, with `[evidence] lfs = true` when asked.
fn with_lfs_pointers(lfs: bool) -> Sandbox {
    let s = Sandbox::initialised();
    if lfs {
        let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
        assert!(policy.contains("[evidence]\n"), "{policy}");
        s.write(".05/policy.toml", &policy.replacen("[evidence]\n", "[evidence]\nlfs = true\n", 1));
        s.commit_all("ask for the real LFS files");
    }
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.write("model.bin", &lfs_pointer("11", 10));
    s.write("data.bin", &lfs_pointer("22", 20));
    s.git(&["add", "-A"]);
    s
}

#[test]
fn lfs_pointers_are_listed_under_unknowns_when_lfs_is_off() {
    let s = with_lfs_pointers(false);
    let line = "2 LFS files were checked as pointers (set [evidence] lfs = true to check the real files)";
    // The page wraps the line; its words are the same.
    let page = text(&s.run(&["brief"])).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(page.contains(line), "{page}");
    let unknowns = json(&s.run(&["brief", "--json"]))["brief"]["unknowns"].clone();
    assert!(unknowns.as_array().unwrap().iter().any(|u| u == line), "{unknowns}");

    // One file reads as one file.
    s.git(&["rm", "-q", "--cached", "data.bin"]);
    let one = json(&s.run(&["brief", "--json"]))["brief"]["unknowns"].clone();
    assert!(one.as_array().unwrap().iter().any(|u| u == "1 LFS file was checked as a pointer (set [evidence] lfs = true to check the real file)"), "{one}");

    // Without a .gitattributes that uses LFS, a file that looks like a pointer is just a file.
    s.git(&["rm", "-q", "--cached", ".gitattributes"]);
    let none = json(&s.run(&["brief", "--json"]))["brief"]["unknowns"].clone();
    assert!(!none.to_string().contains("LFS"), "{none}");
}

#[test]
fn lfs_on_leaves_no_pointer_unknown_and_without_git_lfs_fails_loudly() {
    let s = with_lfs_pointers(true);
    let brief = text(&s.run(&["brief"]));
    assert!(!brief.contains("LFS file"), "the checks ask for the real files, so nothing is unknown: {brief}");

    // A PATH with git and sh but no git-lfs.
    let bin = tempfile::tempdir().unwrap();
    for tool in ["git", "sh"] {
        let found = std::env::var("PATH").unwrap().split(':').map(|d| Path::new(d).join(tool)).find(|p| p.exists()).expect("the tool is on PATH");
        std::os::unix::fs::symlink(found, bin.path().join(tool)).unwrap();
    }
    let path = bin.path().to_str().unwrap();
    s.key("me.key");
    let out = s.run_env(&["prove", "--key", "me.key", "--json", "--", "./test.sh"], &[("PATH", path)]);
    assert_eq!(code(&out), 6, "{}", text(&out));
    let report = json(&out);
    assert_eq!(report["code"], "LFS_UNAVAILABLE", "{report}");
    assert!(report["message"].as_str().unwrap().contains("Nothing ran"), "{report}");
    assert!(report["next"].as_str().unwrap().contains("git-lfs.com"), "{report}");
    assert!(s.stored_receipts().is_empty(), "no receipt was made for a check that did not run");
}

#[test]
fn prove_with_lfs_on_checks_the_real_file_and_says_so() {
    if !Command::new("git").args(["lfs", "version"]).stdin(Stdio::null()).output().is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: git-lfs is not installed here");
        return;
    }
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replacen("[evidence]\n", "[evidence]\nlfs = true\n", 1));
    s.commit_all("ask for the real LFS files");
    // The filter only: 05's pre-push hook is already in place, and LFS's own would not replace it.
    s.git(&["lfs", "install", "--local", "--skip-repo"]);
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.write("model.bin", "the real bytes\n");
    s.git(&["add", "-A"]);
    assert!(s.git(&["cat-file", "-p", ":model.bin"]).starts_with("version https://git-lfs.github.com/spec/v1"));

    s.key("me.key");
    let out = s.run(&["prove", "--key", "me.key", "--json", "--", "grep", "-q", "the real bytes", "model.bin"]);
    assert_eq!(code(&out), 0, "the check read the real file, not the pointer: {}", text(&out));
    let lfs = json(&out)["details"]["checks"][0]["lfs"].clone();
    assert_eq!((lfs[0]["path"].as_str(), lfs[0]["size"].as_u64()), (Some("model.bin"), Some(15)), "{lfs}");

    let human = s.run(&["prove", "--key", "me.key", "--", "grep", "-q", "the real bytes", "model.bin"]);
    assert!(text(&human).contains("1 LFS file was fetched, so the check ran on the real file; the receipt lists it."), "{}", text(&human));
}

/// A folder with stand-ins for `git-lfs` and `use05` that record their arguments and standard
/// input, for running the pre-push hook as git would. `lfs_exit` is what the `git-lfs` one returns;
/// `None` leaves git-lfs out altogether.
fn recording_stubs(lfs_exit: Option<i32>, with_use05: bool) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let stub = |name: &str, exit: i32| {
        let path = dir.path().join(name);
        let log = dir.path().join(name);
        let body = format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{0}.args'\ncat >> '{0}.in'\nexit {exit}\n", log.display());
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    };
    if let Some(exit) = lfs_exit {
        stub("git-lfs", exit);
    }
    if with_use05 {
        stub("use05", 0);
    }
    dir
}

/// Run the repository's pre-push hook the way git does: in the work tree, with the refs on stdin.
/// PATH holds the stubs and links to only the programs the hook runs besides its shell builtins,
/// so a real git-lfs on the machine (Linux images ship one in /usr/bin) cannot be found. The
/// hook's temporary file must be gone when it ends, however it ends.
fn run_pre_push(s: &Sandbox, stubs: &TempDir, refs: &str) -> Output {
    use std::io::Write;
    let hook = fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap();
    let tools = tempfile::tempdir().unwrap();
    let search: Vec<String> = std::env::var("PATH").unwrap().split(':').map(str::to_string).chain(["/usr/bin".to_string(), "/bin".to_string()]).collect();
    // Everything the script calls as a program (its builtins are command, trap, export, echo, exit).
    for tool in ["git", "cat", "mktemp", "rm"] {
        assert!(hook.contains(tool), "the hook no longer runs {tool}: update this list");
        let found = search.iter().map(|d| Path::new(d).join(tool)).find(|p| p.exists()).unwrap_or_else(|| panic!("{tool} is not on PATH"));
        std::os::unix::fs::symlink(found, tools.path().join(tool)).unwrap();
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut child = Command::new("/bin/sh")
        .arg(s.path(".git/hooks/pre-push"))
        .args(["origin", "file:///elsewhere"])
        .current_dir(s.dir.path())
        .env_clear()
        .env("PATH", format!("{}:{}", stubs.path().display(), tools.path().display()))
        .env("HOME", s.home.path())
        .env("TMPDIR", tmp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(refs.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let left: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert!(left.is_empty(), "the hook left its temporary file behind: {left:?}");
    out
}

fn recorded(stubs: &TempDir, file: &str) -> String {
    fs::read_to_string(stubs.path().join(file)).unwrap_or_default()
}

#[test]
fn the_pre_push_hook_uploads_lfs_files_first_when_the_repository_uses_lfs() {
    let s = Sandbox::initialised();
    let hook = fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap();
    assert!(hook.contains("git lfs pre-push \"$@\""), "{hook}");
    assert!(hook.contains("use05 gate --git-hook pre-push"), "{hook}");
    let refs = format!("refs/heads/main {} refs/heads/main {}\n", "a".repeat(40), "0".repeat(40));

    // Not an LFS repository: git-lfs is never called, and 05's check gets the refs.
    let plain = recording_stubs(Some(0), true);
    let out = run_pre_push(&s, &plain, &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(recorded(&plain, "git-lfs.args"), "");
    assert_eq!(recorded(&plain, "use05.args"), "gate --git-hook pre-push origin file:///elsewhere\n");
    assert_eq!(recorded(&plain, "use05.in"), refs);

    // An LFS repository: git-lfs gets the same arguments and the same refs, then 05 does too.
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.commit_all("track big files");
    let lfs = recording_stubs(Some(0), true);
    let out = run_pre_push(&s, &lfs, &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(recorded(&lfs, "git-lfs.args"), "pre-push origin file:///elsewhere\n");
    assert_eq!(recorded(&lfs, "git-lfs.in"), refs);
    assert_eq!(recorded(&lfs, "use05.args"), "gate --git-hook pre-push origin file:///elsewhere\n");
    assert_eq!(recorded(&lfs, "use05.in"), refs, "05 reads the refs too, from the same input");

    // The same, found through git's lfs settings alone.
    let by_config = Sandbox::initialised();
    by_config.git(&["config", "lfs.url", "https://lfs.example.invalid/x"]);
    let configured = recording_stubs(Some(0), true);
    run_pre_push(&by_config, &configured, &refs);
    assert_eq!(recorded(&configured, "git-lfs.in"), refs);

    // A failed upload fails the push, and 05's check does not run after it.
    let failing = recording_stubs(Some(1), true);
    let out = run_pre_push(&s, &failing, &refs);
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert_eq!(recorded(&failing, "use05.args"), "", "05 did not run");
}

#[test]
fn the_pre_push_hook_stops_the_push_when_an_lfs_repository_has_no_git_lfs() {
    let s = Sandbox::initialised();
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.commit_all("track big files");
    let refs = format!("refs/heads/main {} refs/heads/main {}\n", "a".repeat(40), "0".repeat(40));

    // As Git LFS's own hook does: say what is missing, and stop (exit 2). 05's check does not run.
    let without = recording_stubs(None, true);
    let out = run_pre_push(&s, &without, &refs);
    assert_eq!(code(&out), 2, "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("uses Git LFS, but git-lfs was not found on PATH, so this push was stopped") && said.contains("git-lfs.com"), "{said}");
    assert_eq!(recorded(&without, "use05.args"), "");

    // A repository that does not use LFS is not held up by it.
    let plain = Sandbox::initialised();
    let out = run_pre_push(&plain, &recording_stubs(None, true), &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));

    // A commented-out filter line is not use, and neither is LFS configured for the whole machine.
    let commented = Sandbox::initialised();
    commented.write(".gitattributes", "# *.bin filter=lfs diff=lfs merge=lfs -text\n   # also off: *.psd filter=lfs\n*.txt text\n");
    commented.commit_all("lfs is off for now");
    fs::write(commented.home.path().join(".gitconfig"), "[lfs]\n\turl = https://lfs.example.invalid/x\n").unwrap();
    let out = run_pre_push(&commented, &recording_stubs(None, true), &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!use05_cli_uses_lfs(&commented), "init and doctor read it the same way");

    // Git LFS writes `lfs.repositoryformatversion` into any repository it runs a command in: that
    // alone is not use, and must not stop a push on a machine without git-lfs.
    let touched = Sandbox::initialised();
    touched.git(&["config", "lfs.repositoryformatversion", "0"]);
    let out = run_pre_push(&touched, &recording_stubs(None, true), &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!use05_cli_uses_lfs(&touched), "init and doctor read it the same way");
}

/// Whether `init` and `doctor` see the repository as using LFS: they warn about its hook only then.
fn use05_cli_uses_lfs(s: &Sandbox) -> bool {
    fs::write(s.path(".git/hooks/pre-push"), "#!/bin/sh\necho theirs\n").unwrap();
    squash_words(&text(&s.run(&["doctor"]))).contains("this repository uses Git LFS")
}

fn squash_words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_pre_push_hook_works_from_a_path_with_a_space_in_it() {
    let s = Sandbox::in_dir(tempfile::Builder::new().prefix("a repo with spaces ").tempdir().unwrap());
    s.write("package.json", "{\"scripts\":{\"test\":\"./test.sh\"}}\n");
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.commit_all("first");
    assert_eq!(code(&s.run(&["init"])), 0);
    let refs = format!("refs/heads/main {} refs/heads/main {}\n", "a".repeat(40), "0".repeat(40));
    let stubs = recording_stubs(Some(0), true);
    let out = run_pre_push(&s, &stubs, &refs);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(recorded(&stubs, "git-lfs.in"), refs);
    assert_eq!(recorded(&stubs, "use05.in"), refs);
}

#[test]
fn init_replaces_git_lfss_own_pre_push_hook_and_leaves_other_hooks_alone() {
    let s = Sandbox::new();
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.commit_all("first");
    fs::create_dir_all(s.path(".git/hooks")).unwrap();
    let standard = "#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found on your path.\\n\"; exit 2; }\ngit lfs pre-push \"$@\"\n";
    s.write(".git/hooks/pre-push", standard);
    let out = s.run(&["init"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let hook = fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap();
    assert!(hook.contains("# 05 pre-push hook") && hook.contains("git lfs pre-push"), "{hook}");
    assert!(text(&out).contains("replaced Git LFS's own pre-push hook"), "{}", text(&out));
    let doctor = text(&s.run(&["doctor"]));
    assert!(!doctor.contains("does not run"), "the hook chains it, so nothing to warn about: {doctor}");

    // Uninstalling takes 05's hook away and says how to get Git LFS's back.
    let gone = s.run(&["uninstall"]);
    assert!(!s.path(".git/hooks/pre-push").exists());
    assert!(text(&gone).contains("git lfs update"), "{}", text(&gone));

    // The hook Git LFS itself writes is recognised too, whatever this version's wording.
    if Command::new("git").args(["lfs", "version"]).stdin(Stdio::null()).output().is_ok_and(|o| o.status.success()) {
        let real = Sandbox::new();
        real.write(".gitattributes", LFS_ATTRIBUTES);
        real.commit_all("first");
        real.git(&["lfs", "install", "--local"]);
        assert!(fs::read_to_string(real.path(".git/hooks/pre-push")).unwrap().contains("git lfs pre-push"));
        let out = real.run(&["init"]);
        assert!(text(&out).contains("replaced Git LFS's own pre-push hook"), "{}", text(&out));
    }
    // Spacing does not matter.
    let spaced = "#!/bin/sh\n\n  command   -v git-lfs >/dev/null 2>&1 ||  { echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found.\\n\"; exit 2; }\n\tgit lfs pre-push   \"$@\"  \n";
    s.write(".git/hooks/pre-push", spaced);
    let out = s.run(&["init"]);
    assert!(text(&out).contains("replaced Git LFS's own pre-push hook"), "{}", text(&out));
    s.run(&["uninstall"]);

    // A hook that does something else as well is another tool's: left alone.
    let theirs = format!("{standard}echo and then our own checks\n");
    s.write(".git/hooks/pre-push", &theirs);
    let out = s.run(&["init"]);
    assert_eq!(fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap(), theirs);
    assert!(text(&out).contains("left alone"), "{}", text(&out));
}

#[test]
fn doctor_warns_when_an_lfs_repository_pushes_through_a_hook_that_skips_lfs() {
    let s = Sandbox::initialised();
    s.write(".gitattributes", LFS_ATTRIBUTES);
    s.commit_all("track big files");
    let fine = text(&s.run(&["doctor"]));
    assert!(!fine.contains("does not run"), "{fine}");

    // Another tool's hook that never calls Git LFS.
    fs::write(s.path(".git/hooks/pre-push"), "#!/bin/sh\necho theirs\n").unwrap();
    // The page wraps its lines; the words are the same.
    let squash = |out: &Output| text(out).split_whitespace().collect::<Vec<_>>().join(" ");
    // A note, not a problem: it may reach Git LFS through a hook manager or a wrapper.
    let foreign_run = s.run(&["doctor"]);
    let foreign = squash(&foreign_run);
    assert!(foreign.contains("this repository uses Git LFS, but the installed hook does not run `git lfs pre-push` itself"), "{foreign}");
    assert!(!foreign.contains("problem to fix") && code(&foreign_run) == 0, "{foreign}");

    // 05's own earlier hook, which did not chain it, is named as such, and init brings it up to date.
    let old = "#!/bin/sh\n# 05 pre-push hook (installed by `use05 init`; remove with `use05 uninstall`)\nexec use05 gate --git-hook pre-push \"$@\"\n";
    fs::write(s.path(".git/hooks/pre-push"), old).unwrap();
    let manifest_path = s.path(".git/05/install.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    for item in manifest["items"].as_array_mut().unwrap() {
        if item["path"].as_str().is_some_and(|p| p.ends_with("hooks/pre-push")) {
            item["sha256"] = Value::String(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(old.as_bytes())));
        }
    }
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let ours_run = s.run(&["doctor"]);
    let ours = squash(&ours_run);
    assert!(ours.contains("the installed hook does not run Git LFS's upload step") && ours.contains("problem to fix"), "05's own hook should have the chain: {ours}");
    assert_eq!(code(&ours_run), 4, "{ours}");
    let init = s.run(&["init"]);
    assert!(text(&init).contains("updated the git pre-push hook"), "{}", text(&init));
    assert!(fs::read_to_string(s.path(".git/hooks/pre-push")).unwrap().contains("git lfs pre-push"));
    assert!(!text(&s.run(&["doctor"])).contains("does not run"));
}

/// The doctor's lines, with each line's wrapping undone.
fn doctor_words(s: &Sandbox) -> String {
    text(&s.run(&["doctor"])).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Nineteen gaps of a minute and then three of 41 minutes in one task (22 gaps, p90 is 41 minutes),
/// then a long silence before another task: that one is no agent going quiet.
fn seed_quiet_gaps(s: &Sandbox) {
    let state = s.path(".git/05");
    let edit = |task: &str, at: u64| use05_core::log::append_at(&state, task, serde_json::json!({ "event": "tool_done", "tool": "Edit", "paths": ["a.rs"] }), at).unwrap();
    let mut at = use05_core::time::now_secs() - 10 * 86_400;
    edit("t1", at);
    for gap in std::iter::repeat_n(60, 19).chain(std::iter::repeat_n(2460, 3)) {
        at += gap;
        edit("t1", at);
    }
    edit("t2", at + 20 * 3600);
}

#[test]
fn doctor_suggests_reservation_idle_from_quiet_gaps() {
    let s = Sandbox::initialised();
    let now = use05_core::time::now_secs();
    let before = json(&s.run(&["doctor", "--json"]));
    seed_quiet_gaps(&s);
    let said = doctor_words(&s);
    assert!(said.contains("Tip: agents here go quiet up to 41 min between edits (p90, 30 days); reservations lapse after 2 h."), "{said}");
    assert!(said.contains("Less strict, so set it at a terminal, not from the console: use05 policy set drift.reservation_idle_hours 1"), "{said}");
    // A tip is not something that is not set up: it has its own level and its own count.
    assert!(said.contains("1 tip shown above"), "{said}");
    let after = json(&s.run(&["doctor", "--json"]));
    let tip = after["details"]["record"].as_array().unwrap().iter().find(|l| l["text"].as_str().unwrap().contains("go quiet")).unwrap();
    assert_eq!(tip["level"], "tip", "{after}");
    let notes = |r: &Value| r["message"].as_str().unwrap().split(", ").nth(1).unwrap().to_string();
    assert_eq!(notes(&before), notes(&after), "the notes are the same with the tip");
    assert!(after["message"].as_str().unwrap().ends_with("1 tip(s)"), "{after}");
    // The command it prints is one `policy set` accepts.
    let set = s.run(&["policy", "set", "drift.reservation_idle_hours", "1"]);
    assert_eq!(code(&set), 0, "{}", text(&set));

    // No policy file, or one not committed yet: `policy set` would have nothing to change, so no tip.
    let none = Sandbox::new();
    none.commit_all("first");
    seed_quiet_gaps(&none);
    assert!(!doctor_words(&none).contains("go quiet"), "{}", doctor_words(&none));
    let draft = Sandbox::new();
    draft.commit_all("first");
    fs::create_dir_all(draft.path(".05")).unwrap();
    draft.write(".05/policy.toml", "[drift]\nscope = \"warn\"\n");
    seed_quiet_gaps(&draft);
    assert!(!doctor_words(&draft).contains("go quiet"), "{}", doctor_words(&draft));
    draft.commit_all("policy");
    assert!(doctor_words(&draft).contains("go quiet"), "{}", doctor_words(&draft));
    // A reservation time of 0 is deliberate.
    draft.write(".05/policy.toml", "[drift]\nreservation_idle_hours = 0\n");
    draft.commit_all("free areas at once");
    assert!(!doctor_words(&draft).contains("go quiet"), "{}", doctor_words(&draft));

    // Too few gaps, or gaps older than thirty days, suggest nothing.
    let t = Sandbox::initialised();
    let old = now - 40 * 86_400;
    for i in 0..30u64 {
        use05_core::log::append_at(&t.path(".git/05"), "old", serde_json::json!({ "event": "tool_done", "tool": "Edit", "paths": ["a.rs"] }), old + i * 2460).unwrap();
    }
    assert!(!doctor_words(&t).contains("go quiet"), "{}", doctor_words(&t));
}

#[test]
fn doctor_suggests_stop_budget() {
    let s = Sandbox::new();
    s.write("slow.sh", "#!/bin/sh\nsleep 2\n");
    fs::set_permissions(s.path("slow.sh"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", "[[check]]\nname = \"slow\"\nrun = [\"./slow.sh\"]\n\n[evidence]\nstop_budget_secs = 1\n");
    s.commit_all("first");
    let quiet = doctor_words(&s);
    assert!(!quiet.contains("Stop hook"), "nothing has run yet, so nothing is known: {quiet}");
    assert!(!quiet.contains("tip shown above"), "{quiet}");
    assert_eq!(code(&s.run(&["prove", "slow"])), 0);
    let said = doctor_words(&s);
    assert!(said.contains("Tip: your checks that have run take 2."), "{said}");
    assert!(said.contains("more than the 1 s the Stop hook may spend") && said.contains("use05 policy set evidence.stop_budget_secs 10"), "{said}");
    let set = s.run(&["policy", "set", "evidence.stop_budget_secs", "10"]);
    assert_eq!(code(&set), 0, "{}", text(&set));
    // Once the rule is committed the checks fit, and the tip goes. A budget turned off on purpose is left alone.
    s.commit_all("allow the checks at stop");
    assert!(!doctor_words(&s).contains("Stop hook may spend"), "{}", doctor_words(&s));
    let off = s.run(&["policy", "set", "evidence.stop_budget_secs", "0"]);
    assert_eq!(code(&off), 0, "{}", text(&off));
    s.commit_all("no proving at stop");
    assert!(!doctor_words(&s).contains("Stop hook may spend"));
}

#[test]
fn the_stop_budget_tip_counts_the_longest_scoped_check_once() {
    let s = Sandbox::new();
    for (name, secs) in [("always", 1), ("web", 2), ("api", 2)] {
        s.write(&format!("{name}.sh"), &format!("#!/bin/sh\nsleep {secs}\n"));
        fs::set_permissions(s.path(&format!("{name}.sh")), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(
        ".05/policy.toml",
        &"[use05]\nmin_version = \"{ver}\"\n\n[[check]]\nname = \"always\"\nrun = [\"./always.sh\"]\n\n[[check]]\nname = \"web\"\nrun = [\"./web.sh\"]\npaths = [\"web/**\"]\n\n[[check]]\nname = \"api\"\nrun = [\"./api.sh\"]\npaths = [\"api/**\"]\n\n[evidence]\nstop_budget_secs = 1\n".replace("{ver}", env!("CARGO_PKG_VERSION")),
    );
    s.commit_all("first");
    let proved = s.run(&["prove", "always", "web", "api"]);
    assert_eq!(code(&proved), 0, "{}", text(&proved));
    // One change rarely calls for both scoped checks to be run at stop; the figure is the checks
    // that always apply (1 s) and the longest scoped one (2 s), not the 5 s of all three.
    let said = doctor_words(&s);
    assert!(said.contains("Tip: your checks that have run take 3."), "{said}");
    assert!(!said.contains("take 5."), "{said}");
}

#[test]
fn a_rule_that_asks_too_often_is_a_tip_not_something_unset() {
    let s = Sandbox::initialised();
    let before = json(&s.run(&["doctor", "--json"]));
    let now = use05_core::time::now_secs();
    let line = format!("{{\"at\":{now},\"approved\":true,\"asked\":[{{\"code\":\"PROTECTED_PATH\",\"area\":\"docs/\"}}]}}\n");
    fs::write(s.path(".git/05/asked.jsonl"), line.repeat(5)).unwrap();
    let after = json(&s.run(&["doctor", "--json"]));
    let rule = after["details"]["record"].as_array().unwrap().iter().find(|l| l["text"].as_str().unwrap().contains("PROTECTED_PATH held 5 changes")).unwrap();
    assert_eq!(rule["level"], "tip", "{after}");
    assert_eq!(before["message"].as_str().unwrap().split(", ").nth(1), after["message"].as_str().unwrap().split(", ").nth(1), "not counted as a note");
    assert!(doctor_words(&s).contains("1 tip shown above"), "{}", doctor_words(&s));
}

#[test]
fn doctor_names_missing_hook_events() {
    let s = Sandbox::with_agent_hooks();
    assert!(!doctor_words(&s).contains("older 05"), "{}", doctor_words(&s));
    for file in [".claude/settings.local.json", ".codex/hooks.json"] {
        let old = fs::read_to_string(s.path(file)).unwrap();
        assert!(old.contains("SubagentStart"), "{file}");
        fs::write(s.path(file), old.replace(" SubagentStart", " Something").replace(" SubagentStop", " SomethingElse")).unwrap();
    }
    let said = doctor_words(&s);
    assert!(said.contains("Agent hooks were installed by an older 05 and lack SubagentStart, SubagentStop."), "{said}");
    assert!(said.contains("`use05 init`"), "{said}");
    let init = s.run(&["init"]);
    assert_eq!(code(&init), 0, "{}", text(&init));
    assert!(!doctor_words(&s).contains("older 05"), "init brings the hooks up to date: {}", doctor_words(&s));
}

#[test]
fn policy_set_replaces_the_commented_example() {
    let s = Sandbox::initialised();
    let before = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(before.contains("# locked = []"), "the template offers it as a comment");
    let out = s.run(&["policy", "set", "protect.locked", "[\"vendor/**\"]"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let after = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(after.contains("locked = [\"vendor/**\"]") && !after.contains("# locked = []"), "the example became the rule:\n{after}");
    assert!(after.contains("never changed; no approval clears it"), "its comment stays:\n{after}");
    assert_eq!(after.matches("locked = ").count(), 1, "{after}");
    assert!(after.contains("# append_only = []"), "the other examples stay");
}

#[test]
fn an_lfs_server_that_never_answers_stops_the_proof_at_the_time_limit() {
    if !Command::new("git").args(["lfs", "version"]).stdin(Stdio::null()).output().is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: git-lfs is not installed here");
        return;
    }
    let real = Command::new("sh").args(["-c", "command -v git-lfs"]).output().unwrap();
    let real = String::from_utf8_lossy(&real.stdout).trim().to_string();
    if real.is_empty() {
        eprintln!("skipped: git-lfs is not on PATH");
        return;
    }
    let s = with_lfs_pointers(true);
    // A server that never answers stalls only the download (smudge); everything git-lfs does on
    // this machine, such as the clean filter `git status` runs, still works. So the stub ahead of
    // the real git-lfs hangs on smudge and hands every other command to the real one.
    let stub = tempfile::tempdir().unwrap();
    let script = stub.path().join("git-lfs");
    fs::write(&script, format!("#!/bin/sh\n[ \"$1\" = smudge ] && sleep 60\nexec '{real}' \"$@\"\n")).unwrap();
    fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", stub.path().display(), std::env::var("PATH").unwrap());
    // As on most machines with Git LFS (and on CI runners): its filter is set up for every repository.
    let system = stub.path().join("gitconfig");
    fs::write(&system, "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n").unwrap();
    s.key("me.key");
    let started = std::time::Instant::now();
    let out = s.run_env(&["prove", "--key", "me.key", "--json", "--", "./test.sh"], &[("PATH", &path), ("USE05_LFS_TIMEOUT_SECS", "1"), ("GIT_CONFIG_SYSTEM", system.to_str().unwrap())]);
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "gave up near the limit, not after the sleep: {:?} {}", started.elapsed(), text(&out));
    assert_eq!(code(&out), 6, "{}", text(&out));
    let report = json(&out);
    assert_eq!(report["code"], "LFS_FAILED", "{report}");
    assert!(report["message"].as_str().unwrap().contains("the LFS server did not answer within 1 seconds"), "{report}");
    assert!(s.stored_receipts().is_empty());
}

// ----------------------------------------------------------------------------- monorepo checks (D97)

/// Initialised, with a second check that is required only when something under `docs/` changes.
fn with_a_docs_check() -> Sandbox {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"docs\"\nrun = [\"./test.sh\"]\npaths = [\"docs/**\"]\n"));
    s.commit_all("a check for the docs");
    s
}

fn check_states(s: &Sandbox) -> std::collections::BTreeMap<String, Value> {
    let out = json(&s.run(&["brief", "--json"]));
    out["brief"]["gate"]["checks"].as_array().unwrap().iter().map(|c| (c["name"].as_str().unwrap().to_string(), c.clone())).collect()
}

#[test]
fn the_brief_says_a_check_was_not_required_and_why_and_a_change_to_its_paths_requires_it() {
    let s = with_a_docs_check();
    s.write("main.rs", "fn main() { 1; }\n");
    let human = text(&s.run(&["brief"]));
    assert!(human.contains("docs") && human.contains("not required: no change in its paths"), "{human}");
    let states = check_states(&s);
    assert_eq!((states["docs"]["state"].as_str(), states["docs"]["reason"].as_str(), states["docs"]["required"].as_bool()), (Some("not_required"), Some("no change in its paths"), Some(false)));
    assert_eq!(states["test"]["state"], "missing", "a check without paths is required for every change");
    let waiting: Vec<String> = json(&s.run(&["brief", "--json"]))["brief"]["gate"]["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "CHECK_MISSING").map(|f| f["message"].to_string()).collect();
    assert_eq!(waiting.len(), 1, "only the check that is required is missing: {waiting:?}");

    // A receipt made for it anyway is shown, labelled; it decides nothing.
    assert_eq!(code(&s.run(&["prove", "docs"])), 0);
    let shown = text(&s.run(&["brief"]));
    assert!(shown.contains("not required") && shown.contains("a receipt says it passed") && shown.contains("not counted"), "{shown}");

    // Touch its paths and it is required, on this tree.
    fs::create_dir_all(s.path("docs")).unwrap();
    s.write("docs/guide.md", "words\n");
    let states = check_states(&s);
    assert_eq!(states["docs"]["state"], "stale", "required again, and its receipt is for the earlier tree: {}", states["docs"]);
    assert_eq!(states["docs"]["required"], true);
}

#[test]
fn use05_prove_with_no_names_still_runs_every_required_check_because_it_does_not_know_the_base() {
    let s = with_a_docs_check();
    s.write("main.rs", "fn main() { 2; }\n");
    let out = json(&s.run(&["prove", "--json"]));
    let names: Vec<&str> = out["details"]["checks"].as_array().unwrap().iter().filter_map(|c| c["check"].as_str()).collect();
    assert!(names.contains(&"test") && names.contains(&"docs"), "{names:?}");
}

#[test]
fn the_pre_push_hook_proves_the_checks_a_change_calls_for_and_not_the_ones_scoped_to_other_paths() {
    let s = with_a_docs_check();
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["branch", "-M", "main"]);
    let push = || {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(s.dir.path()).args(["push", "origin", "main"]);
        cmd.env("PATH", format!("{}:{}", bin_dir(), std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("LANG", "C.UTF-8").env("COLUMNS", "100");
        cmd.output().unwrap()
    };
    assert!(push().status.success());
    s.write("main.rs", "fn main() { 3; }\n");
    s.commit_all("a change that is not about the docs");
    let out = push();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let states = check_states(&s);
    assert_eq!(states["test"]["state"], "passed", "the hook proved what the change calls for");
    assert!(states["docs"]["state"] == "not_required" && states["docs"]["result"].is_null(), "and ran nothing else: {}", states["docs"]);
}

#[test]
fn the_stop_hook_does_not_prove_a_check_scoped_to_other_paths() {
    let s = Sandbox::with_agent_hooks();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"docs\"\nrun = [\"./test.sh\"]\npaths = [\"docs/**\"]\n"));
    s.commit_all("a check for the docs");
    // Both have run before, so both would fit the budget; only the one the change calls for runs.
    assert_eq!(code(&s.run(&["prove", "test", "docs"])), 0);
    hook(&s, "s1", "PostToolUse", "Edit", "main.rs");
    s.write("main.rs", "fn main() { 4; }\n");
    let checks = |s: &Sandbox| s.stored_receipts().into_iter().filter(|(_, p)| p.starts_with("receipts/") && p.split('/').nth(1).is_some_and(|subject| subject.len() == 40)).count();
    let before = checks(&s);
    let out = stop(&s, "claude-code", "s1", false);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(checks(&s), before + 1, "one fresh receipt, for the check the change calls for");
    let log = log_text(&s, "s1");
    assert!(log.contains("proved_at_stop") && log.contains("\"test\"") && !log.contains("\"docs\""), "{log}");
}

#[test]
fn prove_runs_a_check_in_its_dir() {
    let s = Sandbox::initialised();
    fs::create_dir_all(s.path("pkg")).unwrap();
    s.write("pkg/marker.txt", "here\n");
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(
        ".05/policy.toml",
        &format!(
            "{policy}\n[[check]]\nname = \"inside\"\nrun = [\"sh\", \"-c\", \"test -f marker.txt && test ! -f main.rs\"]\ndir = \"pkg\"\n\n[[check]]\nname = \"outside\"\nrun = [\"sh\", \"-c\", \"test -f marker.txt\"]\n"
        ),
    );
    s.commit_all("two checks");
    let inside = json(&s.run(&["prove", "inside", "--json"]));
    assert_eq!(inside["details"]["checks"][0]["status"], "passed", "{inside}");
    let outside = s.run(&["prove", "outside", "--json"]);
    assert_eq!(code(&outside), 2, "the same command at the root does not find the file: {}", text(&outside));
    // The receipt says which folder, and the gate counts it for this check only.
    let states = check_states(&s);
    assert_eq!(states["inside"]["state"], "passed", "{}", states["inside"]);
    assert_eq!(states["inside"]["dir"], "pkg");
    assert_eq!(states["outside"]["state"], "failed");
    assert!(states["outside"]["dir"].is_null());
}

#[test]
fn a_dir_that_leaves_the_tree_is_refused_with_its_code() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"out\"\nrun = [\"true\"]\ndir = \"../elsewhere\"\n"));
    s.commit_all("a check that runs outside");
    let out = s.run(&["prove", "out", "--json"]);
    assert_ne!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("CHECK_DIR_OUTSIDE"), "{}", text(&out));
}

fn a_pnpm_monorepo() -> Sandbox {
    let s = Sandbox::new();
    s.write("package.json", "{\"private\":true,\"scripts\":{\"test\":\"pnpm -r test\"}}\n");
    s.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n");
    s.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    for (dir, test) in [("api", "true"), ("web", "true"), ("docs", "")] {
        fs::create_dir_all(s.path(&format!("packages/{dir}"))).unwrap();
        let scripts = if test.is_empty() { String::new() } else { format!(",\"scripts\":{{\"test\":\"{test}\"}}") };
        s.write(&format!("packages/{dir}/package.json"), &format!("{{\"name\":\"@acme/{dir}\"{scripts}}}\n"));
    }
    s.commit_all("a monorepo");
    s
}

#[test]
fn init_suggests_a_check_per_pnpm_workspace() {
    let s = a_pnpm_monorepo();
    let out = s.run(&["init", "--defaults"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    let checks: Vec<(&str, Vec<String>, Vec<String>, Option<&str>)> = p.check.iter().map(|c| (c.name.as_str(), c.run.clone(), c.paths.clone(), c.dir.as_deref())).collect();
    let to_vec = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        checks,
        [
            ("test-api", to_vec(&["pnpm", "--filter", "./packages/api", "test"]), to_vec(&["packages/api/**", "pnpm-workspace.yaml", "package.json", "pnpm-lock.yaml"]), None),
            ("test-web", to_vec(&["pnpm", "--filter", "./packages/web", "test"]), to_vec(&["packages/web/**", "pnpm-workspace.yaml", "package.json", "pnpm-lock.yaml"]), None),
        ],
        "one per package that has a test script, in place of the single test check"
    );
    assert!(p.use05.min_version.is_some(), "a policy that scopes checks says which version reads it");
    let shown = text(&out);
    assert!(shown.contains("Found 2 packages") && shown.contains("pnpm"), "{shown}");
    assert!(shown.contains("packages/docs has no test script"), "what was left out is said: {shown}");
    assert!(shown.contains("not rerun when only a package it depends on changes") && shown.contains("`paths`"), "{shown}");
    assert!(shown.contains("test-api") && shown.contains("test-web"), "{shown}");
    // The written file reads back with its comments, and changing only the docs asks for neither check.
    let file = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    assert!(file.contains("paths = [\"packages/api/**\", \"pnpm-workspace.yaml\", \"package.json\", \"pnpm-lock.yaml\"]   # required only when a change touches one of these"), "{file}");
}

#[test]
fn init_suggests_a_check_per_cargo_member() {
    let s = Sandbox::new();
    s.write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
    s.write("Cargo.lock", "# lock\n");
    for name in ["alpha", "beta"] {
        fs::create_dir_all(s.path(&format!("crates/{name}/src"))).unwrap();
        s.write(&format!("crates/{name}/Cargo.toml"), &format!("[package]\nname = \"acme-{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"));
        s.write(&format!("crates/{name}/src/lib.rs"), "");
    }
    s.commit_all("a cargo workspace");
    let out = s.run(&["init", "--defaults"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    let names: Vec<&str> = p.check.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["lint", "test-alpha", "test-beta"], "the workspace-wide test is replaced, the lint stays");
    let alpha = p.check.iter().find(|c| c.name == "test-alpha").unwrap();
    assert_eq!(alpha.run, ["cargo", "test", "-p", "acme-alpha"]);
    assert_eq!(alpha.paths, ["crates/alpha/**", "Cargo.toml", "Cargo.lock"]);
    assert_eq!(alpha.env, ["HOME"]);
    assert!(alpha.dir.is_none());
}

#[test]
fn init_suggests_a_go_module_with_its_own_dir() {
    let s = Sandbox::new();
    s.write("go.work", "go 1.22\n\nuse ./svc\n");
    fs::create_dir_all(s.path("svc")).unwrap();
    s.write("svc/go.mod", "module svc\n");
    s.commit_all("a go workspace");
    assert_eq!(code(&s.run(&["init", "--defaults"])), 0);
    let p = policy_of(&s);
    let svc = p.check.iter().find(|c| c.name == "test-svc").expect("a check for svc");
    assert_eq!((svc.run.clone(), svc.dir.as_deref(), svc.paths.clone()), (vec!["go".to_string(), "test".into(), "./...".into()], Some("svc"), vec!["svc/**".to_string(), "go.work".to_string()]));
    assert!(fs::read_to_string(s.path(".05/policy.toml")).unwrap().contains("dir = \"svc\""));
}

#[test]
fn guided_init_shows_the_package_checks_and_asks_once_whether_to_use_them() {
    // The flags answer the team, the landing branch and the environments, so the first thing read
    // from stdin is the question about the package checks (step 4); after it, Enter takes defaults.
    let flags = ["init", "--guided", "--team", "solo", "--target", "main", "--env", "dev=main"];
    let enters = "\n".repeat(40);

    // Enter: the package checks replace the single test check.
    let s = a_pnpm_monorepo();
    let out = s.run_with_stdin(&flags, &enters);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("Found 2 packages") && shown.contains("Use these checks?"), "{shown}");
    assert!(shown.contains("not rerun when only a package it depends on changes"), "{shown}");
    assert_eq!(shown.matches("Keep them?").count(), 0, "asked once, not twice: {shown}");
    let names: Vec<String> = policy_of(&s).check.iter().map(|c| c.name.clone()).collect();
    assert_eq!(names, ["test-api", "test-web"], "{shown}");

    // `n` to that question: the checks found at the top stay, and they are asked about as before.
    let s = a_pnpm_monorepo();
    let out = s.run_with_stdin(&flags, &format!("n\n{enters}"));
    assert_eq!(code(&out), 0, "{}", text(&out));
    let names: Vec<String> = policy_of(&s).check.iter().map(|c| c.name.clone()).collect();
    assert_eq!(names, ["test"], "{}", text(&out));
    assert!(text(&out).contains("Keep them?"), "{}", text(&out));
}

// ----- the fixes of review round 1

#[test]
fn a_top_that_is_a_package_keeps_its_test_check_for_every_change() {
    let s = Sandbox::new();
    s.write("Cargo.toml", "[package]\nname = \"acme-root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\nmembers = [\"crates/alpha\"]\n");
    fs::create_dir_all(s.path("src")).unwrap();
    s.write("src/lib.rs", "");
    fs::create_dir_all(s.path("crates/alpha/src")).unwrap();
    s.write("crates/alpha/Cargo.toml", "[package]\nname = \"acme-alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
    s.write("crates/alpha/src/lib.rs", "");
    s.commit_all("a root crate with a member");
    let out = s.run(&["init", "--defaults"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let p = policy_of(&s);
    let root = p.check.iter().find(|c| c.name == "test").expect("the root keeps its test check");
    assert!(root.paths.is_empty(), "unscoped: required for every change");
    assert!(p.check.iter().any(|c| c.name == "test-alpha"));
    assert!(text(&out).contains("top of the repository is a package too"), "{}", text(&out));
}

#[test]
fn the_brief_names_changed_files_that_no_checks_paths_cover() {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", "[[check]]\nname = \"docs\"\nrun = [\"./test.sh\"]\npaths = [\"docs/**\"]\n");
    s.commit_all("base");
    s.write("main.rs", "fn main() { 1; }\n");
    s.write("tsconfig.base.json", "{}\n");
    s.git(&["add", "-A"]);
    let human = text(&s.run(&["brief"]));
    assert!(human.contains("2 changed files are outside every check's paths") && human.contains("main.rs") && human.contains("tsconfig.base.json"), "{human}");
    // A change that does touch the paths has nothing to report; so does a policy with a check for everything.
    s.git(&["reset", "-q"]);
    s.git(&["checkout", "--", "."]);
    fs::remove_file(s.path("tsconfig.base.json")).unwrap();
    fs::create_dir_all(s.path("docs")).unwrap();
    s.write("docs/a.md", "x\n");
    s.git(&["add", "-A"]);
    assert!(!text(&s.run(&["brief"])).contains("outside every check's paths"));
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"all\"\nrun = [\"./test.sh\"]\n"));
    s.commit_all("a check for everything");
    s.write("main.rs", "fn main() { 2; }\n");
    s.git(&["add", "-A"]);
    assert!(!text(&s.run(&["brief"])).contains("outside every check's paths"), "an unscoped required check covers every file");
}

#[test]
fn a_check_with_a_bare_double_star_is_required_for_every_change() {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", "[[check]]\nname = \"everything\"\nrun = [\"./test.sh\"]\npaths = [\"**\"]\n");
    s.commit_all("base");
    s.write("main.rs", "fn main() { 3; }\n");
    s.git(&["add", "-A"]);
    let states = check_states(&s);
    assert_eq!(states["everything"]["state"], "missing", "{}", states["everything"]);
}

#[test]
fn a_check_whose_folder_was_deleted_fails_alone_and_the_others_still_run() {
    let s = Sandbox::initialised();
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &format!("{policy}\n[[check]]\nname = \"gone\"\nrun = [\"./test.sh\"]\ndir = \"removed-package\"\n"));
    s.commit_all("a check for a package that is not there");
    let out = s.run(&["prove", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    let v = json(&out);
    let by_name = |n: &str| v["details"]["checks"].as_array().unwrap().iter().find(|c| c["check"] == n).cloned().unwrap_or_else(|| panic!("no {n}: {v}"));
    assert_eq!(by_name("test")["status"], "passed", "the other check still ran");
    assert_eq!(by_name("gone")["status"], "failed");
    assert!(by_name("gone")["reason"].as_str().unwrap().contains("removed-package"), "{v}");
    let human = text(&s.run(&["prove", "gone"]));
    assert!(human.contains("removed-package") && human.contains("not run"), "{human}");
    // The gate sees a failed check, not a missing one.
    assert_eq!(check_states(&s)["gone"]["state"], "failed");
}

#[test]
fn the_ci_gate_does_not_run_or_fail_on_a_check_the_change_does_not_call_for() {
    let extra = "\n[[check]]\nname = \"web\"\nrun = [\"no-such-tool-for-the-web\"]\npaths = [\"web/**\"]\n";
    let (s, secret, _remote) = ci_fixture_with(extra);
    s.write("main.rs", "fn main() { println!(\"not the web\"); }\n");
    s.commit_all("a change outside web/");
    let out = gate_ci(&s, Some(&secret), &[]);
    assert_eq!(code(&out), 0, "a toolchain the change does not need cannot stop it: {}", text(&out));
    assert!(text(&out).contains("not required: no change in its paths"), "{}", text(&out));
    // A change to its paths does call for it, and then the missing tool is a real problem.
    fs::create_dir_all(s.path("web")).unwrap();
    s.write("web/app.js", "1\n");
    s.commit_all("a change in web/");
    let out = gate_ci(&s, Some(&secret), &[]);
    assert_ne!(code(&out), 0, "{}", text(&out));
}

// ---------------------------------------------------------------- path owners (D92)

/// A repository on `main`, pushed to a bare `origin`, whose policy makes another key Lee's, and
/// `billing/**` owned by eng-managers (Dana, Lee). Dana's key is this machine's approver key when
/// `mine_is_danas`, else a key from elsewhere. Alex's branch `alex/billing`, changing billing,
/// was pushed from elsewhere and is fetched here only.
fn owned_billing(mine_is_danas: bool) -> (Sandbox, TempDir) {
    let s = Sandbox::new();
    s.approver();
    let dana = if mine_is_danas {
        json(&s.run(&["key", "show", "--json"]))["details"]["approver"].as_str().unwrap().to_string()
    } else {
        s.key("dana.key");
        let public = fs::read_to_string(s.path("dana.key.pub")).unwrap().trim().to_string();
        for f in ["dana.key", "dana.key.pub"] {
            fs::remove_file(s.path(f)).unwrap();
        }
        public
    };
    s.key("lee.key");
    let lee = fs::read_to_string(s.path("lee.key.pub")).unwrap().trim().to_string();
    for f in ["lee.key", "lee.key.pub"] {
        fs::remove_file(s.path(f)).unwrap();
    }
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(
        ".05/policy.toml",
        &format!("[[trust.key]]\nname = \"dana\"\nrole = \"approver\"\npublic = \"{dana}\"\nperson = \"Dana\"\n\n[[trust.key]]\nname = \"lee\"\nrole = \"approver\"\npublic = \"{lee}\"\nperson = \"Lee\"\n\n[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\", \"Lee\"]\n\n[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-managers\"]\n"),
    );
    s.commit_all("base");
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.git(&["push", "-q", "origin", "main"]);
    s.git(&["checkout", "-q", "-b", "alex/billing"]);
    fs::create_dir_all(s.path("billing")).unwrap();
    s.write("billing/pay.rs", "fn pay() {}\n");
    s.commit_all("billing change");
    s.git(&["push", "-q", "origin", "alex/billing"]);
    s.git(&["checkout", "-q", "main"]);
    s.git(&["branch", "-q", "-D", "alex/billing"]);
    s.git(&["fetch", "-q", "origin"]);
    (s, remote)
}

#[test]
fn an_owner_approves_someone_elses_branch_by_its_revision_and_the_brief_names_them() {
    let (s, _remote) = owned_billing(true);
    let rev = "origin/alex/billing";
    let commit = s.git(&["rev-parse", rev]);
    let short = &commit[..12];
    let waiting = s.run(&["brief", "--rev", rev, "--json"]);
    assert_eq!(decision_of(&waiting), "approval_required", "{}", text(&waiting));
    let owner = json(&waiting)["brief"]["gate"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "OWNER_APPROVAL_REQUIRED").cloned().unwrap();
    assert_eq!(owner["message"], "billing/** needs an approval from eng-managers (Dana, Lee): 0 of 1");
    assert_eq!(owner["next"], "ask Dana or Lee to run: use05 approve --outcome --rev <commit>");
    let words = text(&s.run(&["brief", "--rev", rev]));
    assert!(words.contains("billing/** owned by eng-managers (Dana, Lee): 0 of 1, nobody yet"), "{words}");
    assert!(words.contains(&format!("({rev} at commit {short})")), "the brief names the commit to approve: {words}");

    // An agent has no terminal: it cannot approve someone else's work either.
    let refused = s.run(&["approve", "--outcome", "--rev", rev, "--json"]);
    assert_eq!(json(&refused)["code"], "NEEDS_A_PERSON", "{}", text(&refused));
    assert!(s.stored_receipts().is_empty(), "nothing was signed or stored");
    let missing = s.run(&["approve", "--outcome", "--rev", "origin/nobody", "--json"]);
    assert_eq!(json(&missing)["code"], "REV_NOT_FOUND", "{}", text(&missing));

    // By the commit the brief showed: what it binds and which owned files it changes, said first.
    let approved = s.run_with_stdin(&["approve", "--outcome", "--rev", short, "--reason", "billing looks right", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    let said = text(&approved);
    let before = said.find("You are about to approve").expect("the preview");
    assert!(said[before..].contains(&format!("Commit {commit}.")), "{said}");
    assert!(said[before..].contains("Owned by eng-managers (Dana, Lee) (billing/**): billing/pay.rs."), "{said}");
    assert!(said.contains("It counts as an owner's approval for billing/**."), "{said}");
    let brief = s.run(&["brief", "--rev", rev, "--json"]);
    assert_eq!(decision_of(&brief), "allow", "{}", text(&brief));
    assert_eq!(json(&brief)["brief"]["gate"]["owners"][0]["approved_by"], serde_json::json!(["Dana"]));
    // Commit ids change from run to run; the undo line names two.
    let shown = normalise(&s, &text(&s.run(&["brief", "--rev", rev]))).replace(&s.git(&["rev-parse", "--short", "main"]), "<BASE>").replace(&s.git(&["rev-parse", "--short", rev]), "<HEAD>");
    snapshot_text("brief_owners", &shown);

    let again = s.run_with_stdin(&["approve", "--outcome", "--rev", rev, "--passphrase-stdin", "--json"], "correct horse\n");
    assert_eq!(json(&again)["details"]["owner_of"], serde_json::json!(["billing/**"]), "{}", text(&again));
    assert_eq!(json(&again)["details"]["scope"], "outcome");
}

#[test]
fn a_name_in_git_config_never_makes_this_machines_key_an_owners() {
    // An agent can set user.name; only the policy's `person` makes a key someone's.
    let (s, _remote) = owned_billing(false);
    s.git(&["config", "user.name", "Dana"]);
    let rev = "origin/alex/billing";
    let approved = s.run_with_stdin(&["approve", "--outcome", "--rev", rev, "--passphrase-stdin", "--json"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    assert_eq!(json(&approved)["details"]["owner_of"], serde_json::json!([]), "{}", text(&approved));
    let brief = s.run(&["brief", "--rev", rev, "--json"]);
    assert_eq!(decision_of(&brief), "approval_required", "{}", text(&brief));
    assert_eq!(json(&brief)["brief"]["gate"]["owners"][0]["approved_by"], serde_json::json!([]));
}

#[test]
fn an_organisation_floor_naming_a_group_it_does_not_define_is_not_signed() {
    let s = Sandbox::new();
    s.key("org.key");
    s.write("floor.toml", "[[protect_owner]]\npaths = [\"infra/**\"]\nsigners = [\"security\"]\n");
    let out = s.run(&["policy", "--json", "org-sign", "floor.toml", "--org", "Acme", "--key", "org.key", "--out", "org.json"]);
    assert_eq!(json(&out)["code"], "UNKNOWN_SIGNER", "{}", text(&out));
    assert!(json(&out)["message"].as_str().unwrap().contains("\"security\""), "{}", text(&out));
    assert!(!s.path("org.json").exists(), "nothing was signed");
}

#[test]
fn a_policy_naming_an_unknown_signer_is_refused_with_the_name() {
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", "[[protect.owner]]\npaths = [\"billing/**\"]\nsigners = [\"eng-mgrs\"]\n");
    s.commit_all("base");
    let out = s.run(&["brief", "--json"]);
    assert_eq!(json(&out)["code"], "UNKNOWN_SIGNER", "{}", text(&out));
    assert!(json(&out)["message"].as_str().unwrap().contains("\"eng-mgrs\""), "{}", text(&out));
}

// ---------------------------------------------------------------- environments and promotion (D93)

const ENVIRONMENTS: &str = "[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n\n[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"uat\"\nbranch = \"uat\"\n\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n";

/// dev on main, uat and prod, all pushed to a bare origin; then one commit on main that uat has
/// and prod lacks, its checks proved on uat's head. `prod_rules` go under prod's environment.
fn promotion_fixture(prod_rules: &str) -> (Sandbox, TempDir) {
    promotion_fixture_with("", prod_rules)
}

/// Like `promotion_fixture`, with `head` at the top of the policy (trusted keys, evidence).
fn promotion_fixture_with(head: &str, prod_rules: &str) -> (Sandbox, TempDir) {
    promotion_fixture_of(&format!("{head}\n{ENVIRONMENTS}{prod_rules}"))
}

/// Like `promotion_fixture`, with this whole policy on every branch.
fn promotion_fixture_of(policy: &str) -> (Sandbox, TempDir) {
    promotion_fixture_in(Sandbox::new(), policy)
}

/// Like `promotion_fixture`, for the CI gate: the policy trusts this machine's key (so its
/// promotion records count) and a CI runner key, whose secret is returned.
fn ci_promotion_fixture(prod_rules: &str) -> (Sandbox, TempDir, String) {
    let s = Sandbox::new();
    assert_eq!(code(&s.run(&["prove", "--", "./test.sh"])), 0, "creates this machine's key");
    let machine = fs::read_to_string(s.home.path().join("local.pub")).unwrap().trim().to_string();
    s.approver();
    let approver = fs::read_to_string(s.home.path().join("approver.pub")).unwrap().trim().to_string();
    s.key("runner.key");
    let public = fs::read_to_string(s.path("runner.key.pub")).unwrap().trim().to_string();
    let secret = fs::read_to_string(s.path("runner.key")).unwrap().trim().to_string();
    fs::remove_file(s.path("runner.key")).unwrap();
    fs::remove_file(s.path("runner.key.pub")).unwrap();
    let trust = format!(
        "[[trust.key]]\nname = \"ci\"\nrole = \"runner\"\npublic = \"{public}\"\n\n[[trust.key]]\nname = \"dev laptop\"\nrole = \"local\"\npublic = \"{machine}\"\n\n[[trust.key]]\nname = \"alex\"\nrole = \"approver\"\nperson = \"Alex Rivera\"\npublic = \"{approver}\"\n"
    );
    let (s, remote) = promotion_fixture_in(s, &format!("{trust}\n{ENVIRONMENTS}{prod_rules}"));
    (s, remote, secret)
}

/// The CI gate as the 05 gate workflow runs it on a push of `head` to `branch`.
fn gate_ci_push(s: &Sandbox, secret: &str, branch: &str, head: &str) -> Output {
    let event = serde_json::json!({
        "workflow_run": { "event": "push", "head_sha": head, "head_branch": branch, "head_repository": { "full_name": "acme/app" }, "pull_requests": [] },
        "repository": { "full_name": "acme/app", "default_branch": "main" },
    });
    let (api, server) = statuses_api(2);
    let summary = s.home.path().join("summary.md");
    let out = gate_workflow_run_with(s, Some(secret), &event, &api, &summary, &[("USE05_RECORD_TRIES", "1")]);
    let _ = server.join();
    out
}

fn promotion_fixture_in(s: Sandbox, policy: &str) -> (Sandbox, TempDir) {
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", policy);
    s.commit_all("base");
    s.git(&["branch", "uat"]);
    s.git(&["branch", "prod"]);
    let remote = tempfile::tempdir().unwrap();
    let remote_path = remote.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote_path]);
    s.write("feature.rs", "pub fn feature() {}\n");
    s.commit_all("Add the feature");
    s.git(&["branch", "-f", "uat", "main"]);
    s.git(&["push", "-q", "origin", "main", "uat", "prod"]);
    let proved = s.run(&["prove", "--tree", "origin/uat"]);
    assert_eq!(code(&proved), 0, "{}", text(&proved));
    (s, remote)
}

/// Every ref here and on the remote, with what it points at.
fn all_refs(s: &Sandbox, remote: &TempDir) -> (String, String) {
    let here = s.git(&["for-each-ref", "--format=%(refname) %(objectname)"]);
    let out = Command::new("git").arg("-C").arg(remote.path()).args(["for-each-ref", "--format=%(refname) %(objectname)"]).output().unwrap();
    (here, String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn promote_check_lists_every_rule_and_changes_nothing() {
    let (s, remote) = promotion_fixture("");
    let before = (all_refs(&s, &remote), s.git(&["status", "--porcelain"]));
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let j = json(&out);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!((j["command"].as_str(), j["code"].as_str(), j["outcome"].as_str()), (Some("promote"), Some("PROMOTE_CHECKED"), Some("allow")), "{j:#}");
    let d = &j["details"];
    assert_eq!((d["env"].as_str(), d["from"].as_str(), d["decision"].as_str(), d["how"].as_str()), (Some("prod"), Some("uat"), Some("allow"), Some("fast-forward")));
    let rules: Vec<&str> = d["rules"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["source_checks", "source_confirmed", "soak", "migrations", "untasked", "sign_off"]);
    let outcome = |name: &str| d["rules"].as_array().unwrap().iter().find(|r| r["rule"] == name).unwrap()["outcome"].as_str().unwrap().to_string();
    assert_eq!(outcome("source_checks"), "pass", "proved on uat's head: {d:#}");
    assert_eq!((outcome("source_confirmed"), outcome("untasked")), ("fail".to_string(), "fail".to_string()), "no deployment record, and the commit is no task's: {d:#}");
    assert_eq!(d["delta"].as_array().unwrap().len(), 1);
    assert_eq!(d["source_head"], s.git(&["rev-parse", "uat"]));
    assert_eq!(d["rollback_point"], s.git(&["rev-parse", "prod"]));
    assert_eq!(d["rules_from"], "prod's policy (origin/prod)");
    let codes: Vec<&str> = d["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"SOURCE_NOT_CONFIRMED") && codes.contains(&"UNTASKED_COMMITS"), "{codes:?}");
    assert_eq!((all_refs(&s, &remote), s.git(&["status", "--porcelain"])), before, "a check moves no branch, here or on origin, and touches no file");
    snapshot("promote_check", &s, &s.run(&["promote", "prod", "--check"]));
    assert_eq!((all_refs(&s, &remote), s.git(&["status", "--porcelain"])), before);
}

#[test]
fn brief_promote_is_the_one_page_for_a_promotion() {
    let (s, remote) = promotion_fixture("\n[environment.sign_off]\nquestions = [\"What did you check in uat?\"]\n\n[[environment.confirm]]\ntext = \"The release notes are published\"\n");
    let before = all_refs(&s, &remote);
    let out = s.run(&["brief", "--promote", "prod"]);
    assert_eq!(code(&out), 3, "a statement only a person can give needs their sign-off: {}", text(&out));
    snapshot("brief_promote", &s, &out);
    let j = json(&s.run(&["brief", "--promote", "prod", "--json"]));
    assert_eq!((j["command"].as_str(), j["decision"].as_str()), (Some("brief"), Some("approval_required")), "{j:#}");
    assert_eq!(j["promotion"]["rules"].as_array().unwrap().len(), 6);
    assert!(j["promotion"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "SIGNOFF_REQUIRED"), "{j:#}");
    assert_eq!(all_refs(&s, &remote), before);
}

/// Every receipt on this repository's receipts branches: the envelope and its statement. A task's
/// sealed log copy (`logs/<task>.jsonl`) is no receipt.
fn envelopes(s: &Sandbox) -> Vec<(Value, Value)> {
    use base64::Engine;
    s.stored_receipts()
        .iter()
        .filter(|(_, path)| path.ends_with(".json"))
        .map(|(branch, path)| {
            let envelope: Value = serde_json::from_str(&s.git(&["show", &format!("{branch}:{path}")])).unwrap();
            let body = base64::engine::general_purpose::STANDARD.decode(envelope["payload"].as_str().unwrap()).unwrap();
            let statement = serde_json::from_slice(&body).unwrap();
            (envelope, statement)
        })
        .collect()
}

/// The statements of one record type here, by its last word: `promotion`, `signoff`, `bypass`.
fn records(s: &Sandbox, kind: &str) -> Vec<Value> {
    envelopes(s).into_iter().map(|(_, st)| st).filter(|st| st["predicateType"] == format!("https://use05.dev/{kind}/v0")).collect()
}

fn remote_git(remote: &TempDir, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(remote.path()).args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn promote_fast_forwards_pushes_and_files_a_record() {
    let (s, remote) = promotion_fixture("agent = true\n");
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let out = s.run(&["promote", "prod"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    snapshot("promote", &s, &out);
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat, "origin's prod is uat's head");
    assert_eq!(s.git(&["rev-parse", "prod"]), uat, "this machine's prod, checked out nowhere, follows");
    assert_eq!(s.git(&["worktree", "list"]).lines().count(), 1, "no worktree was made or left for a fast-forward");

    let promotions = records(&s, "promotion");
    assert_eq!(promotions.len(), 1, "one record");
    let (st, p) = (&promotions[0], &promotions[0]["predicate"]);
    assert_eq!(st["subject"][0]["digest"]["gitCommit"], uat, "its subject is the source commit");
    assert_eq!((p["env"].as_str(), p["from"].as_str(), p["direction"].as_str(), p["how"].as_str()), (Some("prod"), Some("uat"), Some("up"), Some("fast-forward")));
    assert_eq!((p["source_commit"].as_str(), p["result_commit"].as_str()), (Some(uat.as_str()), Some(uat.as_str())));
    assert_eq!((p["target_before"].as_str(), p["rollback_point"].as_str()), (Some(prod.as_str()), Some(prod.as_str())));
    assert_eq!(p["rules"].as_array().unwrap().len(), 6);
    assert_eq!(p["policy_sha256"], policy_of(&s).digest());
    assert!(all_refs(&s, &remote).1.contains("refs/heads/05-receipts/"), "the record went to origin on the receipts branch");

    // Moved, so there is nothing left to promote; the record counts the commit as moved by 05.
    let again = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&again), json(&again)["code"].as_str()), (0, Some("NOTHING_TO_PROMOTE")), "{}", text(&again));
    assert_eq!(records(&s, "promotion").len(), 1, "nothing moved, so no new record");
}

#[test]
fn ci_holds_a_push_to_prod_without_a_promotion_record() {
    let (s, _remote, secret) = ci_promotion_fixture("agent = true\n");
    let uat = s.git(&["rev-parse", "uat"]);
    // Pushed by hand, past 05: no record says this move was made.
    s.git(&["push", "-q", "origin", "uat:prod"]);
    let out = gate_ci_push(&s, &secret, "prod", &uat);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(finding_codes(&out).contains(&"PROMOTION_RECORD_MISSING".to_string()), "{:?}", finding_codes(&out));
}

#[test]
fn ci_allows_a_push_to_prod_with_a_counted_record() {
    let (s, _remote, secret) = ci_promotion_fixture("agent = true\n");
    let out = s.run(&["promote", "prod", "--no-wait"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let prod = s.git(&["rev-parse", "origin/prod"]);
    let out = gate_ci_push(&s, &secret, "prod", &prod);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let codes = finding_codes(&out);
    assert!(codes.contains(&"PROMOTION_RECORD".to_string()), "{codes:?}");
    assert!(!codes.iter().any(|c| c == "PROMOTE_NOT_EVALUATED_MOVE" || c == "AGENT_MAY_NOT_PROMOTE"), "judged as of before the push: {codes:?}");
    // Judged as of before the push, and put back after: origin's copies are as they were.
    assert_eq!(s.git(&["rev-parse", "origin/prod"]), prod);
}

#[test]
fn ci_holds_a_hand_push_on_top_of_a_promotion() {
    let (s, _remote, secret) = ci_promotion_fixture("agent = true\n");
    assert_eq!(code(&s.run(&["promote", "prod", "--no-wait"])), 0);
    // Someone adds a commit to prod by hand: the record names the commit before it, not this one.
    s.git(&["checkout", "-q", "prod"]);
    s.write("sneaky.rs", "pub fn sneaky() {}\n");
    s.commit_all("Sneak something onto prod");
    s.git(&["push", "-q", "origin", "prod"]);
    let out = gate_ci_push(&s, &secret, "prod", &s.git(&["rev-parse", "prod"]));
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(finding_codes(&out).contains(&"PROMOTION_RECORD_MISSING".to_string()), "{:?}", finding_codes(&out));
}

#[test]
fn ci_allows_a_counted_revert_and_holds_one_without_its_record() {
    let (s, _remote, secret) = ci_promotion_fixture("agent = true\n");
    let before = s.git(&["rev-parse", "prod"]);
    assert_eq!(code(&s.run(&["promote", "prod", "--no-wait"])), 0);
    let out = s.run(&["promote", "prod", "--rollback", "--no-wait"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let reverted = s.git(&["rev-parse", "origin/prod"]);
    assert_eq!(s.git(&["rev-parse", &format!("{reverted}^{{tree}}")]), s.git(&["rev-parse", &format!("{before}^{{tree}}")]), "the revert holds the rollback point's files");
    let out = gate_ci_push(&s, &secret, "prod", &reverted);
    assert_eq!(code(&out), 0, "a counted revert goes through: {}", text(&out));

    // The same kind of commit made by hand, with no record: held.
    s.git(&["checkout", "-q", "prod"]);
    s.git(&["reset", "-q", "--hard", "origin/prod"]);
    s.write("again.rs", "pub fn again() {}\n");
    s.commit_all("Change prod by hand");
    s.git(&["push", "-q", "origin", "prod"]);
    let out = gate_ci_push(&s, &secret, "prod", &s.git(&["rev-parse", "prod"]));
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(finding_codes(&out).contains(&"PROMOTION_RECORD_MISSING".to_string()), "{:?}", finding_codes(&out));
}

#[test]
fn ci_allows_a_hotfix_landing_and_a_merge_back_by_their_records() {
    let (s, remote, secret) = ci_promotion_fixture("");
    let (_task, fix) = hotfix_ready(&s);
    let approved = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    with_pre_push_hook(&s);
    let landed = s.run(&["land", "--push", "--json"]);
    assert_eq!((code(&landed), json(&landed)["code"].as_str()), (0, Some("LANDED")), "{}", text(&landed));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), fix);
    // CI has no task store of this machine's: it rebuilds the hotfix from its record, and its
    // approval, which names the hotfix and is signed by a key the policy lists, counts.
    let out = gate_ci_push(&s, &secret, "prod", &fix);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(finding_codes(&out).contains(&"HOTFIX_LANDING".to_string()), "{:?}", finding_codes(&out));

    // Merged back into uat by 05, with its record: allowed in CI too.
    s.git(&["checkout", "-q", "main"]);
    let back = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!((code(&back), json(&back)["code"].as_str()), (0, Some("MERGED_BACK")), "{}", text(&back));
    let uat = remote_git(&remote, &["rev-parse", "uat"]);
    s.git(&["fetch", "-q", "origin"]);
    let out = gate_ci_push(&s, &secret, "uat", &uat);
    assert_eq!(code(&out), 0, "{}", text(&out));
}

#[test]
fn ci_holds_a_promotion_record_signed_on_a_machine_when_only_ci_counts() {
    // Only CI's evidence counts: a record a developer's machine signs is not enough.
    let (s, _remote, secret) = ci_promotion_fixture("agent = true\n\n[evidence]\naccept = [\"runner\"]\n");
    s.git(&["push", "-q", "origin", "uat:prod"]);
    let out = gate_ci_push(&s, &secret, "prod", &s.git(&["rev-parse", "uat"]));
    assert_eq!(code(&out), 2, "{}", text(&out));
    let j = json(&out);
    let said = j["brief"]["gate"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "PROMOTION_RECORD_MISSING").map(|f| f["message"].as_str().unwrap_or_default().to_string()).unwrap_or_default();
    assert!(said.contains("promote from CI"), "{said}");
}

#[test]
fn promote_merge_makes_a_merge_commit_with_trailers() {
    let (s, remote) = promotion_fixture("how = \"merge\"\nagent = true\n");
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let out = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    let merge = remote_git(&remote, &["rev-parse", "prod"]);
    assert_eq!(json(&out)["details"]["result_commit"], merge);
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &merge]), format!("{merge} {prod} {uat}"), "a merge commit on prod's head, with uat's as its second parent");
    assert_eq!(remote_git(&remote, &["rev-parse", &format!("{merge}^{{tree}}")]), s.git(&["rev-parse", "uat^{tree}"]), "it holds exactly uat's tree");
    let message = remote_git(&remote, &["log", "-1", "--format=%B", &merge]);
    assert!(message.starts_with(&format!("Promote uat into prod ({})", &uat[..12])), "{message}");
    let mut parse = Command::new("git").args(["interpret-trailers", "--parse"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut parse.stdin.take().unwrap(), message.as_bytes()).unwrap();
    let trailers = String::from_utf8(parse.wait_with_output().unwrap().stdout).unwrap();
    let lines: Vec<&str> = trailers.lines().collect();
    assert_eq!(lines[..2], ["05-Promotion: prod from uat".to_string(), format!("05-Source: {uat}")], "git reads them as trailers: {trailers}");
    assert!(lines[2].starts_with("05-Rules: source_checks=pass,source_confirmed=fail,soak=skipped,"), "{trailers}");
    let promotions = records(&s, "promotion");
    assert_eq!((promotions[0]["predicate"]["result_commit"].as_str(), promotions[0]["predicate"]["how"].as_str()), (Some(merge.as_str()), Some("merge")));
    assert_eq!(s.git(&["worktree", "list"]).lines().count(), 1, "the temporary worktree is gone");
    assert_eq!(s.git(&["status", "--porcelain"]), "", "the person's checkout was not touched");
    // A merge that brings nothing of its own does not put prod ahead: nothing is left to promote.
    let again = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&again), json(&again)["code"].as_str()), (0, Some("NOTHING_TO_PROMOTE")), "{}", text(&again));
}

#[test]
fn a_refused_push_leaves_no_record_and_restores_the_branch() {
    for how in ["fast-forward", "merge"] {
        let (s, remote) = promotion_fixture(&format!("how = \"{how}\"\nagent = true\n"));
        let hook = remote.path().join("hooks").join("pre-receive");
        fs::write(&hook, "#!/bin/sh\necho \"prod is frozen today\" >&2\nexit 1\n").unwrap();
        fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let before = all_refs(&s, &remote);
        let out = s.run(&["promote", "prod", "--json"]);
        let j = json(&out);
        assert_eq!((code(&out), j["code"].as_str()), (4, Some("PROMOTE_PUSH_FAILED")), "{how}: {}", text(&out));
        assert!(j["message"].as_str().unwrap().contains("remote: prod is frozen today"), "git's own first line: {j:#}");
        assert!(j["notes"][0].as_str().unwrap().contains("no promotion record was written"), "{j:#}");
        assert_eq!(all_refs(&s, &remote), before, "{how}: no branch moved, here or on origin, and nothing else was pushed");
        assert!(records(&s, "promotion").is_empty(), "{how}: no record");
        assert_eq!(s.git(&["worktree", "list"]).lines().count(), 1, "{how}: no worktree left behind");
        assert_eq!(s.git(&["status", "--porcelain"]), "");
    }
}

#[test]
fn a_promotion_whose_record_did_not_reach_origin_says_so() {
    let (s, remote) = promotion_fixture("agent = true\n");
    // Origin takes prod, and refuses every receipts branch.
    let hook = remote.path().join("hooks").join("pre-receive");
    fs::write(&hook, "#!/bin/sh\nwhile read old new ref; do case \"$ref\" in refs/heads/05-receipts/*) echo \"no receipts here\" >&2; exit 1;; esac; done\nexit 0\n").unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let out = s.run(&["promote", "prod", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["record_on_origin"].as_bool()), (0, Some("PROMOTED_WITHOUT_RECORD"), Some(false)), "{}", text(&out));
    assert!(j["message"].as_str().unwrap().ends_with("but its record is not on origin"), "{j:#}");
    assert!(j["next"].as_str().unwrap().starts_with("git push origin 05-receipts/"), "{j:#}");
    assert!(j["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("CI holds prod's branch")), "{j:#}");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]), "the promotion itself went through");
    assert_eq!(records(&s, "promotion").len(), 1, "the record is stored here");
}

/// Install 05's pre-push hook, as `use05 init` does.
fn with_pre_push_hook(s: &Sandbox) {
    let hook = s.path(".git").join("hooks").join("pre-push");
    fs::write(&hook, "#!/bin/sh\nuse05 gate --git-hook pre-push \"$@\"\n").unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

/// A `git push` by hand, through the hooks, with `use05` on PATH, and with no terminal (as from a
/// script or CI), whatever terminal these tests run in.
fn hand_push(s: &Sandbox, args: &[&str]) -> Output {
    hand_push_as(s, args, &[])
}

/// Like `hand_push`, with these variables set too (an agent's session id, say).
fn hand_push_as(s: &Sandbox, args: &[&str], envs: &[(&str, &str)]) -> Output {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("git");
    // SAFETY: setsid is async-signal-safe; the push runs in a new session with no controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.current_dir(s.dir.path()).arg("push").args(args).env("PATH", format!("{}:{}", bin_dir(), std::env::var("PATH").unwrap())).env("USE05_HOME", s.home.path()).env("HOME", s.home.path()).env("USE05_NO_TOUCH_ID", "1").env("LANG", "C.UTF-8").env("COLUMNS", "100");
    for var in ["CLAUDE_CODE_SESSION_ID", "CODEX_SESSION_ID", "USE05_SESSION_ID"] {
        cmd.env_remove(var);
    }
    cmd.envs(envs.iter().copied());
    cmd.stdin(Stdio::null()).output().unwrap()
}

#[test]
fn the_pre_push_hook_judges_an_environment_push_as_its_promotion() {
    // What moves changes the policy file, which the task gate would hold for a person; the
    // promotion's rules allow it, and the hook judges the push by those.
    let (s, remote) = promotion_fixture("agent = true\n");
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n# a note\n"));
    s.commit_all("Note in the policy");
    s.git(&["branch", "-f", "uat", "main"]);
    s.git(&["push", "-q", "origin", "main", "uat"]);
    assert_eq!(code(&s.run(&["prove", "--tree", "origin/uat"])), 0);
    with_pre_push_hook(&s);
    let out = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));

    // A push by hand that is not the move 05 judged is held, here, by the same rules.
    s.git(&["checkout", "-q", "-b", "other", "prod"]);
    s.write("hotfix.rs", "pub fn fix() {}\n");
    s.commit_all("Fix prod by hand");
    s.git(&["checkout", "-q", "main"]);
    let held = hand_push(&s, &["origin", "other:prod"]);
    assert!(!held.status.success(), "{}", text(&held));
    assert!(text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE") && text(&held).contains("use05 promote prod"), "{}", text(&held));
    assert!(!text(&held).contains("use05 bypass"), "no bypass clears what is built in: {}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]), "origin's prod did not move");
}

#[test]
fn an_environment_push_that_cannot_be_judged_is_held() {
    let (s, remote) = promotion_fixture("agent = true\n");
    // The source is gone everywhere, so the promotion into prod cannot be judged.
    s.git(&["push", "-q", "origin", ":uat"]);
    s.git(&["branch", "-D", "uat"]);
    s.git(&["update-ref", "-d", "refs/remotes/origin/uat"]);
    with_pre_push_hook(&s);
    s.git(&["checkout", "-q", "-b", "fix-a", "prod"]);
    s.write("hotfix.rs", "pub fn fix() {}\n");
    s.commit_all("Fix prod by hand");
    s.git(&["checkout", "-q", "main"]);
    let before = remote_git(&remote, &["rev-parse", "prod"]);
    let held = hand_push(&s, &["origin", "fix-a:prod"]);
    assert!(!held.status.success(), "it must not fail open: {}", text(&held));
    assert!(text(&held).contains("PROMOTE_NOT_JUDGED") && !text(&held).contains("NOT blocked"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), before, "origin's prod did not move");
}

#[test]
fn a_hand_push_where_people_promote_needs_a_person_at_a_terminal() {
    // prod is the last rung: kept for people. A script or CI pushing uat to it is held.
    let (s, remote) = promotion_fixture("");
    with_pre_push_hook(&s);
    let before = remote_git(&remote, &["rev-parse", "prod"]);
    let held = hand_push(&s, &["origin", "uat:prod"]);
    assert!(!held.status.success(), "{}", text(&held));
    assert!(text(&held).contains("AGENT_MAY_NOT_PROMOTE") && text(&held).contains("nothing here shows a person pushing"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), before);
    // A person at a terminal promotes it, through the same hook.
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
}

#[test]
fn deleting_an_environment_branch_is_held_without_a_person() {
    let (s, remote) = promotion_fixture("");
    s.git(&["push", "-q", "origin", "main:agent/old-work"]);
    with_pre_push_hook(&s);
    for branch in ["uat", "prod", "main"] {
        let held = hand_push(&s, &["origin", &format!(":{branch}")]);
        assert!(!held.status.success(), "{branch}: {}", text(&held));
        assert!(text(&held).contains("ENVIRONMENT_DELETE_HELD"), "{branch}: {}", text(&held));
        assert!(remote_git(&remote, &["branch", "--list", branch]).contains(branch), "{branch} is still on origin");
    }
    // An agent's working branch is not kept: deleting it is fine.
    let gone = hand_push(&s, &["origin", "--delete", "agent/old-work"]);
    assert!(gone.status.success(), "{}", text(&gone));
    // The agent hooks refuse it before it runs.
    let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push origin --delete prod" } }).to_string();
    let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{}", text(&out));
}

#[test]
fn deleting_an_environment_branch_is_held_from_a_checkout_whose_policy_names_none() {
    let (s, remote) = promotion_fixture("");
    // This checkout's policy knows no environments: prod is kept by prod's own policy and
    // origin's default branch's, and those decide too.
    s.git(&["checkout", "-q", "-b", "elsewhere"]);
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n");
    s.commit_all("A policy with no environments");
    with_pre_push_hook(&s);
    let held = hand_push(&s, &["origin", ":prod"]);
    assert!(!held.status.success(), "{}", text(&held));
    assert!(text(&held).contains("ENVIRONMENT_DELETE_HELD"), "{}", text(&held));
    assert!(remote_git(&remote, &["branch", "--list", "prod"]).contains("prod"), "prod is still on origin");
    // The agent hooks read the same policies, from git, with no network.
    let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push origin :prod" } }).to_string();
    let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{}", text(&out));
}

#[test]
fn a_hand_push_of_the_source_to_an_environment_is_held_by_its_rules() {
    let (s, remote) = promotion_fixture("agent = true\n\n[environment.rules]\nuntasked = \"deny\"\n");
    with_pre_push_hook(&s);
    let before = remote_git(&remote, &["rev-parse", "prod"]);
    let held = hand_push(&s, &["origin", "uat:prod"]);
    assert!(!held.status.success(), "{}", text(&held));
    assert!(text(&held).contains("UNTASKED_COMMITS") && text(&held).contains("use05 bypass --promote prod --rule"), "a rule a bypass can clear says how: {}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), before);
    // The landing branch keeps the task gate: an ordinary change there still goes through.
    s.write("more.rs", "pub fn more() {}\n");
    s.commit_all("More");
    assert_eq!(code(&s.run(&["prove", "--tree", "HEAD"])), 0);
    let landed = hand_push(&s, &["origin", "main"]);
    assert!(landed.status.success(), "{}", text(&landed));
}

#[test]
fn an_agent_cannot_promote_where_agent_is_false() {
    let (s, remote) = promotion_fixture("");
    let before = all_refs(&s, &remote);
    // Under an agent the rules deny it, whatever else holds.
    let out = s.run_env(&["promote", "prod", "--json"], &[("CLAUDE_CODE_SESSION_ID", "s-1")]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (2, Some("AGENT_MAY_NOT_PROMOTE")), "{}", text(&out));
    assert!(json(&out)["message"].as_str().unwrap().ends_with("nothing moved"), "{}", text(&out));
    // No agent session, and no terminal either (CI, a pipe): nothing proves a person, so it fails closed.
    let out = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (3, Some("NEEDS_A_PERSON")), "{}", text(&out));
    // The agent's hooks hold it before it runs; checking it is anyone's.
    let hook = |command: &str| {
        let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": command } }).to_string();
        let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v["hookSpecificOutput"]["permissionDecision"].as_str().map(str::to_string), text(&out))
    };
    let (held, why) = hook("use05 promote prod");
    assert_eq!(held.as_deref(), Some("deny"), "{why}");
    assert!(why.contains("use05 promote prod --check"), "{why}");
    assert_eq!(hook("use05 promote prod --check").0, None);
    assert_eq!(hook("use05 promote uat").0, None, "below the last rung an agent may");
    assert_eq!(all_refs(&s, &remote), before, "nothing moved, here or on origin");
    assert!(records(&s, "promotion").is_empty());
    let help = s.run(&["promote", "--help"]);
    assert!(text(&help).contains("use05 approve --promote prod"), "{}", text(&help));
}

#[test]
fn a_person_at_a_terminal_promotes_where_agents_may_not_and_signs_the_record() {
    let (s, remote) = promotion_fixture("");
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert!(screen.contains("You are about to promote") && screen.contains("Promoted uat → prod"), "{screen}");
    assert!(!screen.contains("correct horse"), "{screen}");
    let uat = s.git(&["rev-parse", "uat"]);
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat);
    let signed: Vec<(Value, Value)> = envelopes(&s).into_iter().filter(|(_, st)| st["predicateType"] == "https://use05.dev/promotion/v0").collect();
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].0["signatures"].as_array().unwrap().len(), 2, "this machine's signature and the person's: {:#}", signed[0].0);
    assert_eq!(signed[0].1["predicate"]["by"], "approver", "the person, as this machine names them");

    // The person's own key verifies it, and 05 reads the machine as its signer and the person as
    // its co-signer, whichever order the policy lists them in.
    let public = |file: &str| fs::read_to_string(s.home.path().join(file)).unwrap().trim().to_string();
    let (machine, person) = (public("local.pub"), public("approver.pub"));
    let at = envelopes(&s).iter().position(|(_, st)| st["predicateType"] == "https://use05.dev/promotion/v0").unwrap();
    let (branch, path) = s.stored_receipts()[at].clone();
    let bytes = s.git(&["show", &format!("{branch}:{path}")]).into_bytes();
    assert!(use05_receipt::verify_any(&bytes, &use05_receipt::parse_public_key(&person).unwrap()).is_ok(), "the person's signature checks out with their key");
    let laptop = format!("[[trust.key]]\nname = \"laptop\"\nrole = \"local\"\npublic = \"{machine}\"\n\n");
    let me = format!("[[trust.key]]\nname = \"alex\"\nrole = \"approver\"\npublic = \"{person}\"\nperson = \"Alex Rivera\"\n\n");
    for keys in [format!("{laptop}{me}"), format!("{me}{laptop}")] {
        let trust = use05_core::evidence::Trust::new(&use05_core::policy::Policy::parse(&keys).unwrap(), false);
        let found = use05_core::evidence::classify(&trust, &[use05_core::store::Raw { source: branch.clone(), path: path.clone(), bytes: bytes.clone() }]);
        assert_eq!(found.promotions.len(), 1, "{keys}");
        let p = &found.promotions[0];
        assert_eq!((p.signer.name.as_str(), p.cosigners.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()), ("laptop", vec!["alex"]), "{keys}");
        assert_eq!(trust.person_of(&p.cosigners[0].key_id).as_deref(), Some("Alex Rivera"));
    }
}

const SIGN_OFF_RULES: &str = "\n[environment.rules]\nsign_off = \"approval\"\n\n[environment.sign_off]\nmin_length = 20\nquestions = [\"What did you check in uat?\"]\n\n[[environment.confirm]]\ntext = \"The release notes are published\"\n";

#[test]
fn a_signoff_shorter_than_min_length_is_refused() {
    let (s, _remote) = promotion_fixture(SIGN_OFF_RULES);
    s.approver();
    let confirm = "The release notes are published";
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "prod", "--note", "looks fine", "--answer", "checkout", "--confirm", confirm], &[]);
    assert_eq!(exit, 6, "{screen}");
    assert!(screen.contains("your words are 10 characters; prod asks for at least 20"), "{screen}");
    assert!(records(&s, "signoff").is_empty(), "nothing was signed");
    assert_eq!(code(&s.run(&["promote", "prod", "--check"])), 3, "still waiting for a sign-off");

    // At a terminal, what no flag gives is asked: the words, each question, each statement.
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "prod"], &["Tried checkout in uat for an hour", "checkout and refunds", "y", "correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert!(screen.contains("What did you check in uat?") && screen.contains("Confirm: The release notes are published? [y/N]"), "{screen}");
    assert!(screen.contains("Signed off on promoting"), "{screen}");
    let signoffs = records(&s, "signoff");
    assert_eq!(signoffs.len(), 1);
    let p = &signoffs[0]["predicate"];
    assert_eq!((p["text"].as_str(), p["answers"][0].as_str(), p["confirmations"][0].as_str()), (Some("Tried checkout in uat for an hour"), Some("checkout and refunds"), Some(confirm)));
    assert_eq!(signoffs[0]["subject"][0]["digest"]["gitCommit"], s.git(&["rev-parse", "uat"]));
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!((code(&out), rule_outcome(&out, "sign_off")), (0, "pass".to_string()), "{}", text(&out));
}

#[test]
fn a_signoff_for_a_passkey_is_prepared_unsigned_and_filed_signed() {
    let dana = use05_receipt::SigningKey::from_bytes(&[21; 32]);
    let (s, _remote) = promotion_fixture_with(&key_entry("dana", "approver", &dana, Some("Dana")), SIGN_OFF_RULES);
    let confirm = "The release notes are published";
    // Without a terminal nothing can be asked, so every answer comes by flag.
    let out = s.run(&["approve", "--promote", "prod", "--unsigned", "--approver", "Dana", "--note", "Tried checkout in uat for an hour", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("ANSWER_REQUIRED")), "{}", text(&out));
    let out = s.run(&["approve", "--promote", "prod", "--unsigned", "--approver", "Dana", "--note", "Tried checkout in uat for an hour", "--answer", "checkout", "--confirm", confirm, "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["kind"].as_str()), (0, Some("UNSIGNED"), Some("signoff")), "{}", text(&out));
    assert!(j["details"]["challenge"].is_string() && j["details"]["cosignature"].is_object(), "a passkey signs the challenge; this machine co-signs: {j:#}");
    assert!(records(&s, "signoff").is_empty(), "nothing is stored until it is signed");
    // Signed elsewhere with Dana's key, then filed here.
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.decode(j["details"]["payload"].as_str().unwrap()).unwrap();
    let envelope = use05_receipt::seal_bytes(&body, &dana).to_json_bytes();
    fs::write(s.path("signoff.json"), &envelope).unwrap();
    let out = s.run(&["approve", "--signed", "signoff.json", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str(), json(&out)["details"]["counts"].as_bool()), (0, Some("SIGNED_OFF"), Some(true)), "{}", text(&out));
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(rule_outcome(&out, "sign_off"), "pass", "{}", text(&out));
}

#[test]
fn a_signoff_by_a_passkey_pinned_here_counts_where_no_signers_are_named() {
    // As the console files it: the person's passkey, pinned on their machine, which co-signs.
    let (s, _remote) = promotion_fixture(SIGN_OFF_RULES);
    let (sk, key) = test_passkey(37);
    s.pin_passkey(&key, "Laptop");
    let unsigned = json(&s.run(&["approve", "--promote", "prod", "--unsigned", "--note", "Tried checkout in uat for an hour", "--answer", "checkout", "--confirm", "The release notes are published", "--json"]));
    assert_eq!(unsigned["code"], "UNSIGNED", "{unsigned:#}");
    s.write("signed.json", &sign_with_passkey(&unsigned, &sk));
    let out = s.run(&["approve", "--signed", "signed.json", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str(), json(&out)["details"]["counts"].as_bool()), (0, Some("SIGNED_OFF"), Some(true)), "{}", text(&out));
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(rule_outcome(&out, "sign_off"), "pass", "{}", text(&out));
}

#[test]
fn a_signoff_from_outside_the_signers_does_not_count() {
    let (dana, sam) = (use05_receipt::SigningKey::from_bytes(&[21; 32]), use05_receipt::SigningKey::from_bytes(&[22; 32]));
    let keys = format!("{}{}[[signer]]\nname = \"eng-managers\"\npeople = [\"Dana\"]\n\n", key_entry("dana", "approver", &dana, Some("Dana")), key_entry("sam", "approver", &sam, Some("Sam")));
    let (s, _remote) = promotion_fixture_with(&keys, "\n[environment.rules]\nsign_off = \"approval\"\n\n[environment.sign_off]\nsigners = [\"eng-managers\"]\n");
    // At a terminal, a key the policy names for no signer is told so before anything is signed.
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "prod", "--note", "looks right to me"], &[]);
    assert_eq!(exit, 2, "{screen}");
    assert!(screen.contains("would not count") && screen.contains("nothing was signed"), "{screen}");
    assert!(records(&s, "signoff").is_empty());
    // Sam signs one elsewhere: it is on the receipts branch, and it does not count.
    let uat = s.git(&["rev-parse", "uat"]);
    let signoff = |person: &str| use05_receipt::Statement::new(vec![use05_receipt::commit_subject(&uat)], use05_receipt::SignOff {
        env: "prod".into(), from: "uat".into(), source_commit: uat.clone(), decision: use05_receipt::Decision::Approve, signer_person: person.into(), text: "checked it in uat".into(),
        answers: vec![], confirmations: vec![], policy_sha256: policy_of(&s).digest(),
        created: use05_core::time::now_rfc3339(), expires: use05_core::time::rfc3339(use05_core::time::now_secs() + 3600),
    });
    file_record(&s, &signoff("Sam"), &sam, &uat);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    let required = json(&out)["details"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "SIGNOFF_REQUIRED").cloned().unwrap_or_else(|| panic!("{}", text(&out)));
    assert!(required["message"].as_str().unwrap().contains("Sam's does not count: Sam is not among those who may sign (eng-managers (Dana))"), "{required}");
    // Dana is one of them: hers counts.
    file_record(&s, &signoff("Dana"), &dana, &uat);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!((code(&out), rule_outcome(&out, "sign_off")), (0, "pass".to_string()), "{}", text(&out));
}

#[test]
fn bypass_of_a_never_rule_is_refused() {
    let (s, _remote) = promotion_fixture("agent = true\n\n[environment.rules]\nuntasked = \"deny\"\n\n[environment.bypass]\nnever = [\"source_checks\"]\n");
    s.approver();
    let bypass = |rule: &str, reason: &str, lines: &[&str]| on_a_terminal(&s, &["bypass", "--promote", "prod", "--rule", rule, "--reason", reason], lines);
    let why = "a hand-made fix, reviewed by two of us";
    for (rule, exit, said) in [
        ("source_checks", 2, "prod never lets a bypass clear source_checks"),
        ("target_ahead", 2, "built in and never bypassed"),
        ("PROMOTE_NOT_EVALUATED_HEAD", 2, "built in and never bypassed"),
        ("nonsense", 6, "not a promotion rule"),
        ("soak", 6, "holds nothing back"),
    ] {
        let (code, screen) = bypass(rule, why, &[]);
        assert_eq!(code, exit, "{rule}: {screen}");
        assert!(screen.contains(said), "{rule}: {screen}");
    }
    let (code_short, screen) = bypass("untasked", "quick", &[]);
    assert_eq!(code_short, 6, "{screen}");
    assert!(screen.contains("at least 10 characters"), "{screen}");
    assert!(records(&s, "bypass").is_empty(), "nothing was signed");

    // A rule a person may bypass: held before, through after, and carried in the record.
    assert_eq!(code(&s.run(&["promote", "prod", "--check"])), 2);
    let (exit, screen) = bypass("untasked", why, &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert!(screen.contains("Break-glass: untasked bypassed"), "{screen}");
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!((code(&out), rule_outcome(&out, "untasked")), (0, "bypassed".to_string()), "{}", text(&out));
    let out = s.run(&["promote", "prod", "--json"]);
    assert_eq!(json(&out)["code"], "PROMOTED", "{}", text(&out));
    let promotion = &records(&s, "promotion")[0]["predicate"];
    assert_eq!(promotion["bypasses"].as_array().unwrap().len(), 1, "{promotion:#}");
    assert!(promotion["rules"].as_array().unwrap().iter().any(|r| r["rule"] == "untasked" && r["outcome"] == "bypassed"), "{promotion:#}");
    let b = &records(&s, "bypass")[0];
    assert_eq!((b["predicate"]["env"].as_str(), b["predicate"]["rule"].as_str(), b["subject"][0]["digest"]["gitCommit"].as_str()), (Some("prod"), Some("untasked"), Some(s.git(&["rev-parse", "uat"]).as_str())));
    // It verifies like any receipt, and says what it clears.
    let at = envelopes(&s).iter().position(|(_, st)| st["predicateType"] == "https://use05.dev/bypass/v0").unwrap();
    let (branch, path) = &s.stored_receipts()[at];
    let out = s.run(&["verify", &format!("{branch}:{path}")]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("untasked, promoting") && text(&out).contains("from uat into prod"), "{}", text(&out));
}

#[test]
fn under_an_agent_approve_promote_and_bypass_promote_are_refused() {
    let (s, _remote) = promotion_fixture("\n[environment.rules]\nuntasked = \"deny\"\n");
    s.approver();
    let agent = [("CLAUDE_CODE_SESSION_ID", "s-1")];
    let approve = ["approve", "--promote", "prod", "--note", "checked it all in uat today"];
    let bypass = ["bypass", "--promote", "prod", "--rule", "untasked", "--reason", "a hand-made fix, reviewed"];
    for args in [&approve[..], &bypass[..]] {
        // Even at a terminal: the agent's session says it is not a person.
        let (exit, screen) = on_a_terminal_with(&s, args, &[], &agent);
        assert_eq!(exit, 3, "{args:?}: {screen}");
        assert!(screen.contains("runs under an agent"), "{args:?}: {screen}");
        // No terminal (CI, a pipe, --json): nothing proves a person, so it is refused as well.
        let out = s.run(&[args, &["--json"]].concat());
        assert_eq!((code(&out), json(&out)["code"].as_str()), (3, Some("NEEDS_A_PERSON")), "{args:?}: {}", text(&out));
    }
    let out = s.run_with_stdin(&[&approve[..], &["--passphrase-stdin"]].concat(), "correct horse\n");
    assert_eq!(code(&out), 3, "a passphrase on stdin is no terminal: {}", text(&out));
    assert!(records(&s, "signoff").is_empty() && records(&s, "bypass").is_empty(), "nothing was signed");
}

#[test]
fn an_unknown_or_lowest_environment_is_named_with_the_choices() {
    let (s, _remote) = promotion_fixture("");
    let out = s.run(&["promote", "staging", "--check", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("UNKNOWN_ENVIRONMENT")), "{}", text(&out));
    assert!(json(&out)["message"].as_str().unwrap().contains("dev, uat, prod"), "{}", text(&out));
    let out = s.run(&["promote", "dev", "--check", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("NOTHING_PROMOTES_HERE")), "{}", text(&out));
}

#[test]
fn an_agent_may_check_but_not_promote_onto_the_last_rung() {
    let (s, _remote) = promotion_fixture("");
    let agent = [("CLAUDE_CODE_SESSION_ID", "s-1")];
    let out = s.run_env(&["promote", "prod", "--check", "--json"], &agent);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["details"]["findings"][0]["code"], "AGENT_MAY_NOT_PROMOTE", "{}", text(&out));
    let out = s.run_env(&["promote", "uat", "--check", "--json"], &agent);
    assert_eq!(json(&out)["details"]["decision"], "allow", "below the last rung an agent may: {}", text(&out));
    assert_eq!(json(&out)["details"]["findings"][0]["code"], "NOTHING_TO_PROMOTE", "uat already has main's head: {}", text(&out));
}

#[test]
fn a_target_with_commits_the_source_lacks_is_denied() {
    let (s, _remote) = promotion_fixture("");
    s.git(&["checkout", "-q", "prod"]);
    s.write("hotfix.rs", "pub fn fix() {}\n");
    s.commit_all("Fix prod by hand");
    s.git(&["push", "-q", "origin", "prod"]);
    s.git(&["checkout", "-q", "main"]);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["details"]["findings"][0]["code"], "PROMOTE_TARGET_AHEAD", "{}", text(&out));
}

#[test]
fn the_rules_come_from_the_target_branch_and_loosening_them_needs_a_person() {
    // prod's own branch denies untasked commits; main, then uat, loosen that.
    let (s, _remote) = promotion_fixture("\n[environment.rules]\nuntasked = \"deny\"\n");
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    s.write(".05/policy.toml", &policy.replace("untasked = \"deny\"", "untasked = \"allow\""));
    s.commit_all("Loosen prod");
    s.git(&["branch", "-f", "uat", "main"]);
    s.git(&["push", "-q", "origin", "main", "uat"]);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let d = &json(&out)["details"];
    assert_eq!(code(&out), 2, "judged by prod's rules, not the ones coming in: {}", text(&out));
    let codes: Vec<&str> = d["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"UNTASKED_COMMITS") && codes.contains(&"POLICY_LOOSENED"), "{codes:?}");
}

#[test]
fn promoting_into_a_branch_that_does_not_exist_yet_says_it_creates_it() {
    let (s, remote) = promotion_fixture("");
    s.git(&["branch", "-D", "prod"]);
    s.git(&["update-ref", "-d", "refs/remotes/origin/prod"]);
    assert!(Command::new("git").arg("-C").arg(remote.path()).args(["branch", "-D", "prod"]).status().unwrap().success());
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let d = &json(&out)["details"];
    assert!(d["findings"].as_array().unwrap().iter().any(|f| f["code"] == "PROMOTE_CREATES_BRANCH"), "{}", text(&out));
    assert!(d["findings"].as_array().unwrap().iter().any(|f| f["code"] == "RULES_FROM_SOURCE"), "{}", text(&out));
    assert_eq!(d["rollback_point"], Value::Null);
    assert_eq!(d["delta"].as_array().unwrap().len(), 2, "everything on uat moves");
}

const PROMOTION_SETTINGS: &str = "from = \"uat\"\nagent = false\nsoak_minutes = 30\n\n[environment.rules]\nuntasked = \"deny\"\n\n[environment.sign_off]\nmin_length = 20\n\n[[environment.confirm]]\ntext = \"Notes are out\"\n\n[environment.bypass]\nnever = [\"source_checks\"]\n";

#[test]
fn rerunning_setup_keeps_every_promotion_setting() {
    let s = with_environment_branches();
    assert_eq!(code(&s.run(&["init", "--env", "dev=main", "--env", "uat=uat", "--env", "prod=production"])), 0);
    let policy = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
    let prod = "[[environment]]\nname = \"prod\"\nbranch = \"production\"\n";
    assert!(policy.contains(prod), "{policy}");
    s.write(".05/policy.toml", &policy.replacen(prod, &format!("{prod}{PROMOTION_SETTINGS}"), 1));
    let before = policy_of(&s).environment;
    assert_eq!(before[2].rules.untasked, use05_core::policy::Severity::Deny);
    for args in [&["policy", "--edit", "--guided"][..], &["init", "--guided"][..]] {
        let out = s.run_with_stdin(args, &"\n".repeat(60));
        assert_eq!(code(&out), 0, "{args:?}: {}", text(&out));
        let after = fs::read_to_string(s.path(".05/policy.toml")).unwrap();
        assert!(after.contains(&format!("{prod}{PROMOTION_SETTINGS}")), "{args:?} kept prod's table as it was:\n{after}");
        assert_eq!(policy_of(&s).environment, before, "{args:?}");
    }
}

/// Sign a statement with `key` and file it on that key's receipts branch, as 05 files its own.
fn file_record<P: use05_receipt::Predicate>(s: &Sandbox, statement: &use05_receipt::Statement<P>, key: &use05_receipt::SigningKey, subject: &str) {
    let envelope = use05_receipt::seal(statement, key).to_json_bytes();
    use05_core::store::put(s.dir.path(), subject, &envelope, &use05_receipt::key_id(&key.verifying_key())).unwrap();
}

fn key_entry(name: &str, role: &str, key: &use05_receipt::SigningKey, person: Option<&str>) -> String {
    let person = person.map(|p| format!("person = \"{p}\"\n")).unwrap_or_default();
    format!("[[trust.key]]\nname = \"{name}\"\nrole = \"{role}\"\npublic = \"{}\"\n{person}\n", use05_receipt::public_key_text(&key.verifying_key()).trim())
}

fn confirmed_deployment(sha: &str) -> use05_receipt::Statement<use05_receipt::Deployment> {
    deployment_at(sha, use05_core::time::now_secs())
}

/// uat's record that its probe showed `sha`, as made at `at` (seconds).
fn deployment_at(sha: &str, at: u64) -> use05_receipt::Statement<use05_receipt::Deployment> {
    let probe = use05_receipt::ProbeResult { name: "version".into(), matched: true, output_sha256: "00".repeat(32), attempts: 1, seconds: 0 };
    use05_receipt::Statement::new(vec![use05_receipt::commit_subject(sha)], use05_receipt::Deployment {
        env: "uat".into(), commit: sha.into(), probes: vec![probe], smoke: vec![], confirmed: true, created: use05_core::time::rfc3339(at), action: use05_receipt::DeployAction::None,
    })
}

fn rule_outcome(out: &Output, name: &str) -> String {
    let j = json(out);
    j["details"]["rules"].as_array().unwrap_or_else(|| panic!("{j:#}")).iter().find(|r| r["rule"] == name).unwrap()["outcome"].as_str().unwrap().to_string()
}

#[test]
fn a_deployment_record_counts_only_from_a_kind_of_key_the_policy_takes_evidence_from() {
    let machine = use05_receipt::SigningKey::from_bytes(&[11; 32]);
    let runner = use05_receipt::SigningKey::from_bytes(&[12; 32]);
    let keys = format!("{}{}", key_entry("laptop", "local", &machine, None), key_entry("ci", "runner", &runner, None));
    // By default this machine's records count: advisory, and the page says so.
    let (s, _remote) = promotion_fixture_with(&keys, "");
    let uat = s.git(&["rev-parse", "uat"]);
    file_record(&s, &confirmed_deployment(&uat), &machine, &uat);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(rule_outcome(&out, "source_confirmed"), "pass", "{}", text(&out));
    assert!(json(&out)["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("rest on its own word")), "{}", text(&out));
    // Under accept = ["runner"], only CI's record counts.
    let (s, _remote) = promotion_fixture_with(&format!("[evidence]\naccept = [\"runner\"]\n\n{keys}"), "");
    let uat = s.git(&["rev-parse", "uat"]);
    file_record(&s, &confirmed_deployment(&uat), &machine, &uat);
    assert_eq!(rule_outcome(&s.run(&["promote", "prod", "--check", "--json"]), "source_confirmed"), "fail", "this machine's word is not enough");
    file_record(&s, &confirmed_deployment(&uat), &runner, &uat);
    assert_eq!(rule_outcome(&s.run(&["promote", "prod", "--check", "--json"]), "source_confirmed"), "pass", "CI's record counts");
}

#[test]
fn an_unreachable_origin_is_said_and_the_last_fetched_copies_are_judged() {
    let (s, _remote) = promotion_fixture("");
    s.git(&["remote", "set-url", "origin", &s.path("no-such-remote").display().to_string()]);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let notes: Vec<String> = json(&out)["details"]["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect();
    assert!(notes.iter().any(|n| n.starts_with("Could not reach origin") && n.contains("judged on what this machine last fetched")), "{notes:?}");
    assert_eq!(json(&out)["details"]["source_ref"], "origin/uat", "the copy this machine last fetched");
}

#[test]
fn a_receipt_whose_tree_content_does_not_match_denies_whatever_source_checks_says() {
    let (s, _remote) = promotion_fixture("\n[environment.rules]\nsource_checks = \"allow\"\n");
    // This machine's own record of the tree's content now disagrees with the receipt's.
    assert_eq!(code(&s.run(&["promote", "prod", "--check"])), 0);
    let tree = s.git(&["rev-parse", "uat^{tree}"]);
    let cache = s.dir.path().join(".git").join("05").join("digests").join(&tree);
    assert!(cache.exists(), "the digest is kept once it is worked out");
    fs::write(&cache, "ab".repeat(32)).unwrap();
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert_eq!(json(&out)["details"]["findings"][0]["code"], "TREE_DIGEST_MISMATCH", "{}", text(&out));
}

#[test]
fn brief_promote_says_when_the_rules_come_from_the_source() {
    // prod's branch has a policy that knows nothing of environments; uat's names them.
    let s = Sandbox::new();
    fs::create_dir_all(s.path(".05")).unwrap();
    s.write(".05/policy.toml", "[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n");
    s.commit_all("base");
    s.git(&["branch", "uat"]);
    s.git(&["branch", "prod"]);
    s.write(".05/policy.toml", &format!("{ENVIRONMENTS}"));
    s.commit_all("Name the environments");
    s.git(&["branch", "-f", "uat", "main"]);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let from = json(&out)["details"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "RULES_FROM_SOURCE").cloned().unwrap_or_else(|| panic!("{}", text(&out)));
    assert_eq!(from["effect"], "warn", "prod has rules, just none for prod: {from}");
    assert!(from["message"].as_str().unwrap().contains("uat's policy"), "{from}");
    snapshot("brief_promote_rules_from_source", &s, &s.run(&["brief", "--promote", "prod"]));
}

#[test]
fn brief_promote_says_why_a_sign_off_does_not_count() {
    let dana = use05_receipt::SigningKey::from_bytes(&[13; 32]);
    let (s, _remote) = promotion_fixture_with(&key_entry("dana", "approver", &dana, Some("Dana")), "\n[environment.rules]\nsign_off = \"approval\"\n\n[environment.sign_off]\nmin_length = 20\n");
    let uat = s.git(&["rev-parse", "uat"]);
    let signoff = use05_receipt::Statement::new(vec![use05_receipt::commit_subject(&uat)], use05_receipt::SignOff {
        env: "prod".into(), from: "uat".into(), source_commit: uat.clone(), decision: use05_receipt::Decision::Approve, signer_person: "Dana".into(), text: "looks fine".into(),
        answers: vec![], confirmations: vec![], policy_sha256: policy_of(&s).digest(),
        created: use05_core::time::now_rfc3339(), expires: use05_core::time::rfc3339(use05_core::time::now_secs() + 3600),
    });
    file_record(&s, &signoff, &dana, &uat);
    let out = s.run(&["brief", "--promote", "prod"]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    let j = json(&s.run(&["brief", "--promote", "prod", "--json"]));
    assert_eq!(j["promotion"]["signoffs"][0]["void"], "its words are shorter than the 20 characters the policy asks", "{j:#}");
    assert!(j["promotion"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "SIGNOFF_REQUIRED" && f["message"].as_str().unwrap().contains("Dana's does not count")), "{j:#}");
    snapshot("brief_promote_signoff_not_counted", &s, &out);
}

// ---------------------------------------------------------------- deploy confirmation, failure and rollback (D93 4–5)

/// The policy: dev on main, then uat and prod, with `uat` and `prod` under each.
fn ladder(uat: &str, prod: &str) -> String {
    format!("[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n\n[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n[[environment]]\nname = \"uat\"\nbranch = \"uat\"\n{uat}\n[[environment]]\nname = \"prod\"\nbranch = \"prod\"\n{prod}")
}

/// A probe that prints the file `$DEPLOYED` names: what the environment says it runs. One try.
const PROBE: &str = "\n[[environment.probe]]\nname = \"version\"\nrun = ['sh', '-c', 'cat \"$DEPLOYED\"']\nenv = [\"DEPLOYED\"]\nwait_minutes = 0\n";

/// The environment says it runs `what`: the file the probe reads, outside the repository.
fn says_it_runs(s: &Sandbox, what: &str) -> String {
    let file = s.home.path().join("deployed");
    fs::write(&file, format!("running {what}\n")).unwrap();
    file.display().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[test]
fn a_probe_that_shows_the_commit_confirms() {
    let (s, remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{PROBE}")));
    let uat = s.git(&["rev-parse", "uat"]);
    let file = says_it_runs(&s, &uat[..12]);
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file)]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert_eq!((j["details"]["deploy"]["confirmed"].as_bool(), j["details"]["deploy"]["commit"].as_str()), (Some(true), Some(uat.as_str())), "{j:#}");
    let deployments = records(&s, "deployment");
    assert_eq!(deployments.len(), 1);
    let (st, d) = (&deployments[0], &deployments[0]["predicate"]);
    assert_eq!(st["subject"][0]["digest"]["gitCommit"], uat, "its subject is the deployed commit");
    assert_eq!((d["env"].as_str(), d["commit"].as_str(), d["confirmed"].as_bool(), d["action"].as_str()), (Some("prod"), Some(uat.as_str()), Some(true), Some("none")));
    assert_eq!((d["probes"][0]["name"].as_str(), d["probes"][0]["matched"].as_bool(), d["probes"][0]["attempts"].as_u64()), (Some("version"), Some(true), Some(1)));
    assert_eq!(d["probes"][0]["output_sha256"], sha256_hex(format!("running {}\n", &uat[..12]).as_bytes()), "a hash of what it printed, never the text");
    assert!(!serde_json::to_string(d).unwrap().contains("running"), "{d}");
    assert!(remote_git(&remote, &["for-each-ref", "--format=%(refname)"]).contains("refs/heads/05-receipts/"));
    // Confirming again, as CI would, says the same in words.
    let again = s.run_env(&["promote", "prod", "--confirm"], &[("DEPLOYED", &file)]);
    assert_eq!(code(&again), 0, "{}", text(&again));
    snapshot("promote_confirm", &s, &again);
    assert!(records(&s, "deployment").iter().all(|d| d["predicate"]["confirmed"] == true));
}

#[test]
fn a_probe_is_asked_again_until_it_shows_the_commit() {
    // It shows the commit on its third try. The waits between tries are pretend in this test.
    let probe = "\n[[environment.probe]]\nname = \"version\"\nrun = ['sh', '-c', 'n=$(cat \"$DEPLOYED.n\" 2>/dev/null || echo 0); n=$((n+1)); echo $n > \"$DEPLOYED.n\"; [ $n -ge 3 ] && cat \"$DEPLOYED\"']\nenv = [\"DEPLOYED\"]\nwait_minutes = 1\ninterval_secs = 15\n";
    let (s, _remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{probe}")));
    let uat = s.git(&["rev-parse", "uat"]);
    let file = says_it_runs(&s, &uat);
    let started = std::time::Instant::now();
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file), ("USE05_TEST_NO_SLEEP", "1")]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert!(started.elapsed() < std::time::Duration::from_secs(25), "no real waiting");
    let d = &records(&s, "deployment")[0]["predicate"];
    assert_eq!((d["probes"][0]["matched"].as_bool(), d["probes"][0]["attempts"].as_u64()), (Some(true), Some(3)), "{d}");
    assert!((30..32).contains(&d["probes"][0]["seconds"].as_u64().unwrap()), "two waits of 15 seconds: {d}");
}

#[test]
fn a_probe_that_never_shows_it_times_out_and_reports() {
    let (s, remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{PROBE}")));
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let file = says_it_runs(&s, &prod);
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file)]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED")), "{}", text(&out));
    assert_eq!(j["next"], "use05 promote prod --rollback", "{j:#}");
    assert_eq!(j["details"]["deploy"]["action"], "none");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat, "the promotion went through; nothing was rolled back by itself");
    let d = &records(&s, "deployment")[0]["predicate"];
    assert_eq!((d["confirmed"].as_bool(), d["probes"][0]["matched"].as_bool(), d["probes"][0]["attempts"].as_u64(), d["action"].as_str()), (Some(false), Some(false), Some(1), Some("none")), "wait 0 is one try: {d}");
    assert_eq!(records(&s, "promotion").len(), 1, "the promotion's own record is kept");
    let again = s.run_env(&["promote", "prod", "--confirm"], &[("DEPLOYED", &file)]);
    assert_eq!(code(&again), 2, "{}", text(&again));
    snapshot("promote_confirm_not_confirmed", &s, &again);
}

#[test]
fn a_missing_probe_program_fails_that_probe() {
    let probe = "\n[[environment.probe]]\nname = \"version\"\nrun = [\"no-such-probe-05\"]\n";
    let (s, _remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{probe}")));
    let out = s.run(&["promote", "prod", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED")), "not a crash: {}", text(&out));
    assert!(text(&out).contains("could not run no-such-probe-05"), "{}", text(&out));
    let d = &records(&s, "deployment")[0]["predicate"];
    assert_eq!((d["probes"][0]["matched"].as_bool(), d["probes"][0]["attempts"].as_u64(), d["confirmed"].as_bool()), (Some(false), Some(1), Some(false)), "no second try of a program that is not there: {d}");
}

#[test]
fn smoke_failure_means_not_confirmed() {
    let smoke = "\n[[environment.smoke]]\nname = \"health\"\nrun = ['sh', '-c', 'exit 1']\n";
    let (s, _remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{PROBE}{smoke}")));
    let uat = s.git(&["rev-parse", "uat"]);
    let file = says_it_runs(&s, &uat);
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file)]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED")), "{}", text(&out));
    let d = &records(&s, "deployment")[0]["predicate"];
    assert_eq!((d["probes"][0]["matched"].as_bool(), d["smoke"][0]["name"].as_str(), d["smoke"][0]["passed"].as_bool(), d["confirmed"].as_bool()), (Some(true), Some("health"), Some(false), Some(false)), "{d}");
}

#[test]
fn on_failure_revert_pushes_a_revert_commit_not_a_force_push() {
    let (s, remote) = promotion_fixture_of(&ladder("", &format!("agent = true\non_failure = \"revert\"\n{PROBE}")));
    with_pre_push_hook(&s);
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let before: Vec<String> = remote_git(&remote, &["rev-list", "prod"]).lines().map(str::to_string).collect();
    // prod still says it runs the old commit, so neither the promotion nor its revert is confirmed.
    let file = says_it_runs(&s, &prod);
    let out = s.run_env(&["promote", "prod"], &[("DEPLOYED", &file)]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    snapshot("promote_reverted", &s, &out);
    let head = remote_git(&remote, &["rev-parse", "prod"]);
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &head]), format!("{head} {uat}"), "a new commit on what was promoted");
    assert_eq!(remote_git(&remote, &["rev-parse", &format!("{head}^{{tree}}")]), s.git(&["rev-parse", &format!("{prod}^{{tree}}")]), "holding the rollback point's files");
    let after: Vec<String> = remote_git(&remote, &["rev-list", "prod"]).lines().map(str::to_string).collect();
    assert!(before.iter().all(|c| after.contains(c)) && after.contains(&uat), "origin's history only grew: no force-push");
    let message = remote_git(&remote, &["log", "-1", "--format=%B", &head]);
    assert!(message.starts_with(&format!("Revert prod to {} (deploy not confirmed)", &prod[..12])), "{message}");
    assert!(message.contains(&format!("05-Reverts: {uat}")) && message.contains(&format!("05-Rollback-To: {prod}")), "{message}");
    // Confirmed once more, and no further: the revert is not confirmed either, and nothing else moves.
    let deployments = records(&s, "deployment");
    let of = |c: &str| deployments.iter().map(|d| &d["predicate"]).find(|d| d["commit"] == c).cloned().unwrap_or_else(|| panic!("{deployments:#?}"));
    assert_eq!(deployments.len(), 2, "{deployments:#?}");
    assert_eq!((of(&uat)["action"].as_str(), of(&uat)["confirmed"].as_bool()), (Some("reverted"), Some(false)));
    assert_eq!((of(&head)["action"].as_str(), of(&head)["confirmed"].as_bool()), (Some("none"), Some(false)));
    let revert = records(&s, "promotion").into_iter().map(|p| p["predicate"].clone()).find(|p| p["how"] == "revert").unwrap();
    assert_eq!((revert["reverts"].as_str(), revert["result_commit"].as_str(), revert["target_before"].as_str()), (Some(uat.as_str()), Some(head.as_str()), Some(uat.as_str())));
    let words = text(&out).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains(&format!("05 reverted prod to {}", &prod[..12])) && words.contains("prod now has a commit uat lacks (the revert)"), "{words}");
    // prod has the revert, which uat lacks: promoting into prod waits until uat has it.
    let check = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!(json(&check)["details"]["findings"][0]["code"], "PROMOTE_TARGET_AHEAD", "{}", text(&check));
}

#[test]
fn on_failure_command_runs_rollback_with_env() {
    let out_dir = tempfile::tempdir().unwrap();
    let said = out_dir.path().join("rollback.txt");
    // It says which files it runs in: the rollback point's lack the feature that moved.
    let rollback = format!("on_failure = \"command\"\nrollback = ['sh', '-c', 'echo \"$USE05_ENV $USE05_ROLLBACK_TO [$DEPLOYED] [$ROLLBACK_TOKEN] $(test -e feature.rs && echo new || echo old)\" > {}']\nrollback_env = [\"ROLLBACK_TOKEN\"]\nrollback_timeout_secs = 30\n", said.display());
    let (s, remote) = promotion_fixture_of(&ladder("", &format!("agent = true\n{rollback}{PROBE}")));
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let file = says_it_runs(&s, &prod);
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file), ("ROLLBACK_TOKEN", "s3cret")]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["deploy"]["action"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED"), Some("rollback-command")), "{}", text(&out));
    assert_eq!(fs::read_to_string(&said).unwrap(), format!("prod {prod} [] [s3cret] old\n"), "the environment, the rollback point and the variables it names, in the rollback point's files");
    assert_eq!(records(&s, "deployment")[0]["predicate"]["action"], "rollback-command");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat, "the command is the developer's; 05 moved no branch");
}

#[test]
fn soak_counts_from_the_source_deployment() {
    let (s, _remote) = promotion_fixture_of(&ladder(PROBE, "soak_minutes = 60\n\n[environment.rules]\nsoak = \"deny\"\n"));
    let uat = s.git(&["rev-parse", "uat"]);
    let file = says_it_runs(&s, &uat);
    let confirmed = s.run_env(&["promote", "uat", "--confirm", "--json"], &[("DEPLOYED", &file)]);
    assert_eq!((code(&confirmed), json(&confirmed)["code"].as_str()), (0, Some("DEPLOY_CONFIRMED")), "{}", text(&confirmed));
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    assert_eq!((rule_outcome(&out, "source_confirmed"), rule_outcome(&out, "soak")), ("pass".to_string(), "fail".to_string()), "{}", text(&out));
    assert!(json(&out)["details"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "SOAK_NOT_DONE" && f["message"].as_str().unwrap().contains("for 0 minutes")), "{}", text(&out));
    // uat was confirmed two hours ago too, and has been since: the soak counts from then.
    let key = use05_core::keys::read_secret_file(&s.home.path().join("local.key")).unwrap();
    file_record(&s, &deployment_at(&uat, use05_core::time::now_secs() - 7200), &key, &uat);
    assert_eq!(rule_outcome(&s.run(&["promote", "prod", "--check", "--json"]), "soak"), "pass");
}

#[test]
fn no_probes_never_claims_confirmed() {
    let (s, _remote) = promotion_fixture("agent = true\n");
    // uat has no probe: its confirmation says so, and so does a promotion from it.
    let uat = s.run(&["promote", "uat", "--confirm", "--json"]);
    assert_eq!((code(&uat), json(&uat)["code"].as_str()), (5, Some("NO_PROBES")), "{}", text(&uat));
    assert!(json(&uat)["message"].as_str().unwrap().contains("no probes: 05 cannot tell what uat runs"), "{}", text(&uat));
    let check = s.run(&["promote", "prod", "--check", "--json"]);
    let finding = json(&check)["details"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "SOURCE_NOT_CONFIRMED").cloned().unwrap();
    assert!(finding["message"].as_str().unwrap().contains("no probes: 05 cannot tell what uat runs"), "{finding}");
    let out = s.run(&["promote", "prod", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert_eq!((j["details"]["deploy"]["confirmed"].as_bool(), j["details"]["deploy"]["summary"].as_str()), (Some(false), Some("no probes: 05 cannot tell what prod runs")), "{j:#}");
    let prod = records(&s, "deployment").into_iter().map(|d| d["predicate"].clone()).find(|d| d["env"] == "prod").unwrap();
    assert_eq!((prod["probes"].as_array().map(Vec::len), prod["confirmed"].as_bool(), prod["action"].as_str()), (Some(0), Some(false), Some("none")), "{prod}");
}

#[test]
fn no_wait_leaves_confirmation_to_confirm_and_rollback_reverts_with_a_new_commit() {
    let (s, remote) = promotion_fixture("agent = true\n");
    with_pre_push_hook(&s);
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let out = s.run(&["promote", "prod", "--no-wait", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert!(records(&s, "deployment").is_empty() && j["details"]["deploy"].is_null(), "nothing was confirmed: {j:#}");
    assert!(j["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("use05 promote prod --confirm")), "{j:#}");
    // A push that only looks like a revert, onto the right commit but with other files, is held.
    s.git(&["checkout", "-q", "-b", "not-a-revert", &uat]);
    s.write("other.rs", "pub fn other() {}\n");
    s.commit_all("Looks like a revert");
    s.git(&["checkout", "-q", "main"]);
    let held = hand_push(&s, &["origin", "not-a-revert:prod"]);
    assert!(!held.status.success() && text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE"), "{}", text(&held));
    // The rollback: a new commit with the rollback point's files, through the same hook.
    let out = s.run(&["promote", "prod", "--rollback", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("ROLLED_BACK")), "{}", text(&out));
    let head = remote_git(&remote, &["rev-parse", "prod"]);
    assert_eq!((j["details"]["rollback_to"].as_str(), j["details"]["reverts"].as_str(), j["details"]["result_commit"].as_str()), (Some(prod.as_str()), Some(uat.as_str()), Some(head.as_str())), "{j:#}");
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &head]), format!("{head} {uat}"));
    assert_eq!(remote_git(&remote, &["rev-parse", &format!("{head}^{{tree}}")]), s.git(&["rev-parse", &format!("{prod}^{{tree}}")]));
    assert!(remote_git(&remote, &["log", "-1", "--format=%s", &head]).starts_with(&format!("Revert prod to {} (rolled back by", &prod[..12])));
    assert_eq!(records(&s, "promotion").iter().filter(|p| p["predicate"]["how"] == "revert").count(), 1);
    // prod now holds the rollback point's files: there is nothing more to roll back.
    let again = s.run(&["promote", "prod", "--rollback", "--json"]);
    assert_eq!((code(&again), json(&again)["code"].as_str()), (0, Some("NOTHING_TO_ROLL_BACK")), "{}", text(&again));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), head);
}

#[test]
fn a_merge_back_that_brings_a_rollback_down_is_held_for_a_person() {
    let (s, _remote) = promotion_fixture("agent = true\n");
    with_pre_push_hook(&s);
    assert_eq!(code(&s.run(&["promote", "prod", "--no-wait"])), 0);
    let rolled = json(&s.run(&["promote", "prod", "--rollback", "--json"]));
    assert_eq!(rolled["code"], "ROLLED_BACK", "{rolled:#}");
    let (undone, revert) = (rolled["details"]["reverts"].as_str().unwrap().to_string(), rolled["details"]["result_commit"].as_str().unwrap().to_string());
    // Merged down, prod's rollback would undo on uat the work it undid on prod.
    let out = s.run(&["promote", "uat", "--back", "--check", "--json"]);
    let j = json(&out);
    let f = j["details"]["findings"].as_array().unwrap().iter().find(|f| f["code"] == "BACK_MERGE_CARRIES_ROLLBACK").cloned().unwrap_or_else(|| panic!("{j:#}"));
    assert_eq!(code(&out), 3, "held for a person, not refused: {j:#}");
    let message = f["message"].as_str().unwrap();
    assert!(message.contains(&format!("the rollback of prod ({})", &revert[..12])) && message.contains(&undone[..12]), "{f:#}");
    assert!(f["next"].as_str().unwrap().contains("use05 approve --promote uat --back"), "{f:#}");
    // A person's sign-off on that merge back says uat should lose that work too.
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "uat", "--back", "--note", "uat goes back with prod"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let out = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("MERGED_BACK")), "{}", text(&out));
}

#[test]
fn rollback_is_for_a_person_where_agents_may_not_promote() {
    let (s, remote) = promotion_fixture("");
    with_pre_push_hook(&s);
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod", "--no-wait"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let uat = s.git(&["rev-parse", "uat"]);
    // Under an agent, or with no terminal, it is refused, and nothing moves.
    let out = s.run_env(&["promote", "prod", "--rollback", "--json"], &[("CLAUDE_CODE_SESSION_ID", "s-1")]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (3, Some("NEEDS_A_PERSON")), "{}", text(&out));
    let out = s.run(&["promote", "prod", "--rollback", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (3, Some("NEEDS_A_PERSON")), "{}", text(&out));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat);
    // The agent's hooks hold it before it runs; confirming is anyone's.
    let hook = |command: &str| {
        let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": command } }).to_string();
        let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v["hookSpecificOutput"]["permissionDecision"].as_str().map(str::to_string), text(&out))
    };
    let (held, why) = hook("use05 promote prod --rollback");
    assert_eq!(held.as_deref(), Some("deny"), "{why}");
    assert!(why.contains("rolling back prod is for a person"), "{why}");
    assert_eq!(hook("use05 promote prod --confirm").0, None);
    // A person at a terminal rolls it back, and signs the record beside the machine.
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod", "--rollback"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert!(screen.contains("You are about to roll prod back") && screen.contains("Rolled prod back"), "{screen}");
    let head = remote_git(&remote, &["rev-parse", "prod"]);
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &head]), format!("{head} {uat}"));
    let signed: Vec<(Value, Value)> = envelopes(&s).into_iter().filter(|(_, st)| st["predicate"]["how"] == "revert").collect();
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].0["signatures"].as_array().unwrap().len(), 2, "this machine's signature and the person's");
}

#[test]
fn rollback_says_what_it_did() {
    let (s, _remote) = promotion_fixture("agent = true\n");
    assert_eq!(code(&s.run(&["promote", "prod", "--no-wait"])), 0);
    let out = s.run(&["promote", "prod", "--rollback"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    snapshot("promote_rollback", &s, &out);
}

#[test]
fn confirm_with_no_probes_says_so() {
    let (s, _remote) = promotion_fixture("");
    let out = s.run(&["promote", "uat", "--confirm"]);
    assert_eq!(code(&out), 5, "{}", text(&out));
    snapshot("promote_confirm_no_probes", &s, &out);
}

#[test]
fn a_forged_rollback_point_off_the_branch_history_is_held() {
    let (s, remote) = promotion_fixture("agent = true\n");
    with_pre_push_hook(&s);
    assert_eq!(code(&s.run(&["promote", "prod", "--no-wait"])), 0);
    let uat = s.git(&["rev-parse", "uat"]);
    // Any files at all, on a commit prod never had.
    s.git(&["checkout", "-q", "--orphan", "anything"]);
    s.write("payload.rs", "pub fn payload() {}\n");
    s.commit_all("Anything");
    let off = s.git(&["rev-parse", "HEAD"]);
    s.git(&["checkout", "-q", "-f", "main"]);
    // This machine's key says prod was at that commit before the promotion.
    let forged = use05_receipt::Statement::new(vec![use05_receipt::commit_subject(&uat)], use05_receipt::Promotion {
        env: "prod".into(), from: "uat".into(), direction: use05_receipt::Direction::Up, source_commit: uat.clone(), target_before: Some(off.clone()), result_commit: uat.clone(), how: "fast-forward".into(),
        rollback_point: Some(off.clone()), rules: vec![], bypasses: vec![], signoffs: vec![], policy_sha256: policy_of(&s).digest(), created: use05_core::time::rfc3339(use05_core::time::now_secs() + 60), by: "this machine".into(), reverts: None, task: None,
    });
    let key = use05_core::keys::read_secret_file(&s.home.path().join("local.key")).unwrap();
    file_record(&s, &forged, &key, &uat);
    // A "revert" to it, on prod's head, is no revert 05 knows: held.
    let fake = s.git(&["commit-tree", &format!("{off}^{{tree}}"), "-p", &uat, "-m", "Revert prod"]);
    let held = hand_push(&s, &["origin", &format!("{fake}:refs/heads/prod")]);
    assert!(!held.status.success() && text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat);
    let out = s.run(&["promote", "prod", "--rollback", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("NO_ROLLBACK_POINT")), "{}", text(&out));
}

#[test]
fn the_hook_holds_an_agents_revert_where_people_promote() {
    let (s, remote) = promotion_fixture("");
    with_pre_push_hook(&s);
    s.approver();
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod", "--no-wait"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    // Exactly the revert 05 would make, pushed by an agent, or by a script with no terminal.
    let revert = s.git(&["commit-tree", &format!("{prod}^{{tree}}"), "-p", &uat, "-m", "Revert prod"]);
    let held = hand_push_as(&s, &["origin", &format!("{revert}:refs/heads/prod")], &[("CLAUDE_CODE_SESSION_ID", "s-1")]);
    assert!(!held.status.success() && text(&held).contains("AGENT_MAY_NOT_PROMOTE") && text(&held).split_whitespace().collect::<Vec<_>>().join(" ").contains("may not roll back prod"), "{}", text(&held));
    let held = hand_push(&s, &["origin", &format!("{revert}:refs/heads/prod")]);
    assert!(!held.status.success() && text(&held).split_whitespace().collect::<Vec<_>>().join(" ").contains("there is no terminal"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat);
}

#[test]
fn where_people_promote_a_failed_deploy_is_reported_not_reverted_by_itself() {
    let (s, remote) = promotion_fixture_of(&ladder("", &format!("on_failure = \"revert\"\n{PROBE}")));
    s.approver();
    let (prod, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let (exit, screen) = on_a_terminal(&s, &["promote", "prod", "--no-wait"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let file = says_it_runs(&s, &prod);
    // CI, or anyone with no terminal: reported, nothing moves.
    let out = s.run_env(&["promote", "prod", "--confirm", "--json"], &[("DEPLOYED", &file)]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["action"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED"), Some("none")), "{}", text(&out));
    assert_eq!(j["next"], "use05 promote prod --rollback");
    assert!(j["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("05 did not revert prod")), "{j:#}");
    // A person at the terminal: no key is asked for after the wait; they roll back themselves.
    let (exit, screen) = on_a_terminal_with(&s, &["promote", "prod", "--confirm"], &[], &[("DEPLOYED", &file)]);
    assert_eq!(exit, 2, "{screen}");
    let words = screen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("05 did not revert prod by itself") && !words.contains("passphrase"), "{words}");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat, "nothing was reverted");
    assert!(records(&s, "promotion").iter().all(|p| p["predicate"]["how"] != "revert"));
}

#[test]
fn under_runner_only_evidence_this_machine_does_not_revert_on_its_own_word() {
    let prod = format!("agent = true\non_failure = \"revert\"\n{PROBE}\n[environment.rules]\nsource_checks = \"allow\"\n");
    let (s, remote) = promotion_fixture_of(&format!("[evidence]\naccept = [\"runner\"]\n\n{}", ladder("", &prod)));
    let (before, uat) = (s.git(&["rev-parse", "prod"]), s.git(&["rev-parse", "uat"]));
    let file = says_it_runs(&s, &before);
    let out = s.run_env(&["promote", "prod", "--json"], &[("DEPLOYED", &file)]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["deploy"]["action"].as_str()), (2, Some("DEPLOY_NOT_CONFIRMED"), Some("none")), "{}", text(&out));
    assert!(j["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("05 did not revert prod: no promotion record into prod that counts here")), "{j:#}");
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), uat);
}

// ---------------------------------------------------------------- hotfix and back-merge (D93 6)

/// Start a hotfix for prod, commit a fix on it, prove and finish it: the task's id and the fix.
fn hotfix_ready(s: &Sandbox) -> (String, String) {
    hotfix_ready_with(s, |s| s.write("fix.rs", "pub fn fix() {}\n"))
}

/// Like `hotfix_ready`, with the fix that `edit` makes.
fn hotfix_ready_with(s: &Sandbox, edit: impl Fn(&Sandbox)) -> (String, String) {
    let started = s.run(&["start", "--hotfix", "prod", "Fix the checkout total", "--json"]);
    assert_eq!(code(&started), 0, "{}", text(&started));
    let task = json(&started)["details"]["task"].as_str().unwrap().to_string();
    edit(s);
    s.commit_all("Fix the checkout total");
    assert_eq!(code(&s.run(&["prove", "--tree", "HEAD"])), 0);
    assert_eq!(code(&s.run(&["finish", "--outcome", "Fixed the checkout total"])), 0);
    (task, s.git(&["rev-parse", "HEAD"]))
}

/// A hotfix for prod, approved by a person and landed and pushed through the pre-push hook.
fn hotfix_landed(s: &Sandbox) -> (String, String) {
    hotfix_landed_with(s, hotfix_ready(s))
}

/// Approve, land and push the hotfix `ready` made.
fn hotfix_landed_with(s: &Sandbox, ready: (String, String)) -> (String, String) {
    let (task, fix) = ready;
    s.approver();
    let approved = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    with_pre_push_hook(s);
    let landed = s.run(&["land", "--push", "--json"]);
    assert_eq!((code(&landed), json(&landed)["code"].as_str(), json(&landed)["details"]["pushed"].as_bool()), (0, Some("LANDED"), Some(true)), "{}", text(&landed));
    (task, fix)
}

#[test]
fn a_hotfix_task_starts_from_the_environment_branch() {
    let (s, _remote) = promotion_fixture("");
    let prod = s.git(&["rev-parse", "origin/prod"]);
    assert_ne!(prod, s.git(&["rev-parse", "main"]), "main has moved on from prod");
    let out = s.run(&["start", "--hotfix", "prod", "Fix the checkout total", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("TASK_STARTED")), "{}", text(&out));
    let d = &j["details"];
    assert_eq!((d["hotfix"].as_str(), d["target"].as_str(), d["base_commit"].as_str()), (Some("prod"), Some("prod"), Some(prod.as_str())), "{j:#}");
    let branch = s.git(&["branch", "--show-current"]);
    assert!(branch.starts_with("05/hotfix-prod-"), "{branch}");
    assert_eq!(s.git(&["rev-parse", "HEAD"]), prod, "the work starts from origin's prod");
    assert_eq!(s.git(&["rev-parse", "--abbrev-ref", "@{upstream}"]), "origin/prod", "and is judged by prod's rules");
    let shown = s.run(&["start", "--hotfix", "prod", "Fix it again"]);
    assert_eq!(code(&shown), 0, "{}", text(&shown));
    snapshot_text("start_hotfix", &normalise(&s, &text(&shown)).replace(&prod[..10], "<PROD10>"));
    // Not where work lands, and not with uncommitted work in the way.
    let lowest = s.run(&["start", "--hotfix", "dev", "Fix dev", "--json"]);
    assert_eq!((code(&lowest), json(&lowest)["code"].as_str()), (6, Some("HOTFIX_ON_LANDING_BRANCH")), "{}", text(&lowest));
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "# a change not committed\n"));
    let dirty = s.run(&["start", "--hotfix", "prod", "Fix it", "--json"]);
    assert_eq!((code(&dirty), json(&dirty)["code"].as_str()), (6, Some("UNCOMMITTED")), "{}", text(&dirty));
}

#[test]
fn a_hotfix_needs_an_approval_even_when_nothing_else_does() {
    let (s, remote) = promotion_fixture("");
    let before = s.git(&["rev-parse", "origin/prod"]);
    let (task, fix) = hotfix_ready(&s);
    let brief = json(&s.run(&["brief", "--json"]));
    let holding: Vec<&str> = brief["brief"]["gate"]["findings"].as_array().unwrap().iter().filter(|f| f["effect"] == "approval" || f["effect"] == "deny" || f["effect"] == "wait").map(|f| f["code"].as_str().unwrap()).collect();
    assert_eq!(holding, ["HOTFIX_NEEDS_APPROVAL"], "nothing else holds it: {brief:#}");
    let held = s.run(&["land", "--json"]);
    assert_eq!((code(&held), json(&held)["code"].as_str()), (3, Some("NOT_ALLOWED")), "{}", text(&held));
    assert!(json(&held)["message"].as_str().unwrap().contains("a hotfix lands straight on prod"), "{}", text(&held));
    assert_eq!(json(&held)["next"], "ask a person to approve it: use05 approve --outcome");
    // A push of it by hand is held by the pre-push hook for the same reason.
    with_pre_push_hook(&s);
    let pushed = hand_push(&s, &["origin", "HEAD:prod"]);
    assert!(!pushed.status.success() && text(&pushed).contains("HOTFIX_NEEDS_APPROVAL"), "{}", text(&pushed));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), before);
    // Approved, it lands on prod and goes out through the same hook, with a hotfix record.
    s.approver();
    let approved = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    let landed = s.run(&["land", "--push", "--json"]);
    let j = json(&landed);
    assert_eq!((code(&landed), j["code"].as_str(), j["details"]["target"].as_str(), j["details"]["pushed"].as_bool()), (0, Some("LANDED"), Some("prod"), Some(true)), "{}", text(&landed));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), fix, "origin's prod is the fix");
    let hotfixes: Vec<Value> = records(&s, "promotion").into_iter().filter(|p| p["predicate"]["direction"] == "hotfix").collect();
    assert_eq!(hotfixes.len(), 1, "{hotfixes:#?}");
    let p = &hotfixes[0]["predicate"];
    assert_eq!((p["env"].as_str(), p["from"].as_str(), p["task"].as_str(), p["how"].as_str()), (Some("prod"), Some("prod"), Some(task.as_str()), Some("fast-forward")));
    assert_eq!((p["source_commit"].as_str(), p["result_commit"].as_str(), p["target_before"].as_str()), (Some(fix.as_str()), Some(fix.as_str()), Some(before.as_str())));
}

#[test]
fn promotion_into_prod_after_a_hotfix_is_refused_until_back_merged() {
    let (s, _remote) = promotion_fixture("");
    let (task, _fix) = hotfix_landed(&s);
    s.git(&["checkout", "-q", "main"]);
    let out = s.run(&["promote", "prod", "--check", "--json"]);
    let j = json(&out);
    let f = &j["details"]["findings"][0];
    assert_eq!((code(&out), f["code"].as_str()), (2, Some("PROMOTE_TARGET_AHEAD")), "{}", text(&out));
    assert!(f["message"].as_str().unwrap().contains(&format!("they come from the hotfix task {task}")), "{f:#}");
    assert_eq!(f["next"], "merge it down into uat first: use05 promote uat --back");
    let back = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!((code(&back), json(&back)["code"].as_str()), (0, Some("MERGED_BACK")), "{}", text(&back));
    let out = json(&s.run(&["promote", "prod", "--check", "--json"]));
    let codes: Vec<&str> = out["details"]["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap()).collect();
    assert!(!codes.contains(&"PROMOTE_TARGET_AHEAD"), "uat has the fix now: {codes:?}");
    // uat is now ahead of dev by the same hotfix: the next rung down says so.
    let uat = json(&s.run(&["promote", "uat", "--check", "--json"]));
    let f = &uat["details"]["findings"][0];
    assert_eq!(f["code"], "PROMOTE_TARGET_AHEAD", "{uat:#}");
    assert!(f["message"].as_str().unwrap().contains(&format!("they come from the hotfix task {task}")), "{f:#}");
    assert_eq!(f["next"], "merge it down into dev first: use05 promote dev --back");
}

#[test]
fn back_merge_merges_down_one_rung_with_a_record() {
    let (s, remote) = promotion_fixture("");
    let (_task, fix) = hotfix_landed(&s);
    s.git(&["checkout", "-q", "main"]);
    let (uat, main) = (remote_git(&remote, &["rev-parse", "uat"]), remote_git(&remote, &["rev-parse", "main"]));
    let checked = s.run(&["promote", "uat", "--back", "--check", "--json"]);
    assert_eq!((code(&checked), json(&checked)["code"].as_str(), json(&checked)["details"]["direction"].as_str()), (0, Some("PROMOTE_CHECKED"), Some("back")), "{}", text(&checked));
    // A sign-off on it is bound to uat, as it comes from prod.
    let signoff = json(&s.run(&["approve", "--promote", "uat", "--back", "--unsigned", "--note", "checked the fix in uat", "--json"]));
    assert_eq!((signoff["details"]["env"].as_str(), signoff["details"]["from"].as_str(), signoff["details"]["source_commit"].as_str()), (Some("uat"), Some("prod"), Some(fix.as_str())), "{signoff:#}");
    assert_eq!(remote_git(&remote, &["rev-parse", "uat"]), uat, "a check moves nothing");
    let out = s.run(&["promote", "uat", "--back"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    snapshot("promote_back", &s, &out);
    let merge = remote_git(&remote, &["rev-parse", "uat"]);
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &merge]), format!("{merge} {uat} {fix}"), "a merge commit on uat's head, with prod's as its second parent");
    assert!(remote_git(&remote, &["log", "-1", "--format=%B", &merge]).starts_with(&format!("Merge prod back into uat ({})", &fix[..12])));
    let backs: Vec<Value> = records(&s, "promotion").into_iter().filter(|p| p["predicate"]["direction"] == "back").collect();
    assert_eq!(backs.len(), 1);
    let p = &backs[0]["predicate"];
    assert_eq!((p["env"].as_str(), p["from"].as_str(), p["how"].as_str()), (Some("uat"), Some("prod"), Some("merge")));
    assert_eq!((p["source_commit"].as_str(), p["target_before"].as_str(), p["result_commit"].as_str(), p["rollback_point"].as_str()), (Some(fix.as_str()), Some(uat.as_str()), Some(merge.as_str()), Some(uat.as_str())));
    // One rung at a time: next into dev, which is where work lands and keeps the task gate.
    let j = json(&s.run(&["promote", "dev", "--back", "--json"]));
    assert_eq!(j["code"], "MERGED_BACK", "{j:#}");
    let into_main = remote_git(&remote, &["rev-parse", "main"]);
    assert_eq!(remote_git(&remote, &["rev-list", "--parents", "-n", "1", &into_main]), format!("{into_main} {main} {merge}"));
    assert_eq!(records(&s, "promotion").iter().filter(|p| p["predicate"]["direction"] == "back" && p["predicate"]["env"] == "dev").count(), 1);
    let again = s.run(&["promote", "dev", "--back", "--json"]);
    assert_eq!(json(&again)["code"], "NOTHING_TO_MERGE_BACK", "{}", text(&again));
}

#[test]
fn back_merge_conflict_leaves_nothing_behind() {
    let (s, remote) = promotion_fixture("");
    for (branch, content) in [("prod", "prod's fix\n"), ("uat", "uat's change\n")] {
        s.git(&["checkout", "-q", branch]);
        s.write("feature.rs", content);
        s.commit_all(&format!("Change the feature on {branch}"));
        s.git(&["push", "-q", "origin", branch]);
    }
    s.git(&["checkout", "-q", "main"]);
    // What git itself records when it fetches origin's default branch (origin/HEAD) is not a move.
    let state = || {
        let (here, there) = all_refs(&s, &remote);
        (here.lines().filter(|l| !l.starts_with("refs/remotes/origin/HEAD ")).collect::<Vec<_>>().join("\n"), there, s.git(&["status", "--porcelain"]), s.git(&["worktree", "list"]))
    };
    let before = state();
    let out = s.run(&["promote", "uat", "--back", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (2, Some("BACK_MERGE_CONFLICT")), "{}", text(&out));
    assert!(j["message"].as_str().unwrap().contains("feature.rs"), "{j:#}");
    assert!(j["next"].as_str().unwrap().contains("by hand"), "{j:#}");
    assert_eq!(state(), before, "no branch, file or worktree changed, here or on origin");
    assert!(records(&s, "promotion").is_empty());
}

#[test]
fn a_back_merge_onto_the_landing_branch_is_judged_as_one_before_the_task_gate() {
    // The hotfix touches 05's own policy file, which the task gate holds for a person; merged
    // back down, the landing branch judges it by its rules but those about the source.
    let (s, remote) = promotion_fixture("");
    let note = |s: &Sandbox| s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "# hotfix note\n"));
    let (_task, _fix) = hotfix_landed_with(&s, hotfix_ready_with(&s, note));
    s.git(&["checkout", "-q", "main"]);
    let back = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!(json(&back)["code"], "MERGED_BACK", "{}", text(&back));
    let main = remote_git(&remote, &["rev-parse", "main"]);
    // A merge of the same two heads made by hand, with something else in it, is the task gate's.
    s.git(&["checkout", "-q", "-b", "by-hand", "origin/main"]);
    s.git(&["merge", "-q", "--no-ff", "-m", "Merge uat by hand", "origin/uat"]);
    s.write("extra.rs", "pub fn extra() {}\n");
    s.git(&["add", "-A"]);
    s.git(&["commit", "-q", "--amend", "--no-edit"]);
    let held = hand_push(&s, &["origin", "by-hand:main"]);
    assert!(!held.status.success() && text(&held).contains("PROTECTED_PATH"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "main"]), main);
    s.git(&["checkout", "-q", "main"]);
    let into_dev = s.run(&["promote", "dev", "--back", "--json"]);
    assert_eq!((code(&into_dev), json(&into_dev)["code"].as_str()), (0, Some("MERGED_BACK")), "{}", text(&into_dev));
    assert_ne!(remote_git(&remote, &["rev-parse", "main"]), main, "the hook let the back-merge onto main");
}

#[test]
fn an_agent_may_start_a_hotfix_and_its_hook_seals_it_from_the_environments_branch() {
    let s = Sandbox::with_agent_hooks();
    let ladder = ENVIRONMENTS.split_once("[[environment]]").map(|(_, rest)| format!("[[environment]]{rest}")).unwrap();
    s.write(".05/policy.toml", &(fs::read_to_string(s.path(".05/policy.toml")).unwrap() + "\n" + &ladder));
    s.commit_all("Environments");
    s.git(&["branch", "uat"]);
    s.git(&["branch", "prod"]);
    let remote = tempfile::tempdir().unwrap();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &remote.path().display().to_string()]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &remote.path().display().to_string()]);
    s.write("feature.rs", "pub fn feature() {}\n");
    s.commit_all("Add the feature");
    s.git(&["push", "-q", "origin", "main", "uat", "prod"]);
    let prod = s.git(&["rev-parse", "prod"]);
    let out = s.run_env(&["start", "--hotfix", "prod", "Fix the checkout total", "--scope", "src/**"], &[("CODEX_SESSION_ID", "s1")]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("Declared: Fix the checkout total") && text(&out).contains("lands on prod"), "{}", text(&out));
    assert_eq!(s.git(&["rev-parse", "HEAD"]), prod, "the agent works from prod");
    codex_hook(&s, "s1", "PreToolUse", "src/a.rs");
    let task = task_json(&s, "s1");
    assert_eq!((task["hotfix"].as_str(), task["base_commit"].as_str()), (Some("prod"), Some(prod.as_str())), "{task}");
    assert!(task["branch"].as_str().unwrap().starts_with("05/hotfix-prod-"), "{task}");
}

// ---------------------------------------------------------------- hotfix and back-merge, fix round 1

/// Approve the current tree as a person, with these words.
fn approve_outcome(s: &Sandbox, args: &[&str]) -> Output {
    let mut all = vec!["approve", "--outcome", "--passphrase-stdin"];
    all.extend_from_slice(args);
    s.run_with_stdin(&all, "correct horse\n")
}

#[test]
fn an_approval_given_for_something_else_does_not_land_a_hotfix() {
    let (s, _remote) = promotion_fixture("");
    hotfix_ready(&s);
    s.approver();
    // An approval of the same tree, given as someone else's work and not as this hotfix.
    let other = approve_outcome(&s, &["--rev", "HEAD", "--reason", "looked at the commit"]);
    assert_eq!(code(&other), 0, "{}", text(&other));
    let held = s.run(&["land", "--json"]);
    assert_eq!((code(&held), json(&held)["code"].as_str()), (3, Some("NOT_ALLOWED")), "{}", text(&held));
    assert!(json(&held)["message"].as_str().unwrap().contains("an approval of this tree given for something else does not count for it"), "{}", text(&held));
    // Given for this hotfix, it counts.
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD"])), 0);
    let records = records(&s, "approval");
    assert!(records.iter().any(|a| a["predicate"]["hotfix"] == "prod"), "{records:#?}");
    let landed = s.run(&["land", "--json"]);
    assert_eq!((code(&landed), json(&landed)["code"].as_str()), (0, Some("LANDED")), "{}", text(&landed));
}

#[test]
fn a_hotfix_that_carries_other_work_onto_prod_is_refused() {
    let (s, remote) = promotion_fixture("");
    s.approver();
    let feature = s.git(&["rev-parse", "main"]);
    // A person approved main's head, for main.
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD"])), 0);
    // A hotfix that is main's work, not its own: approved for the hotfix too, it is still refused.
    assert_eq!(code(&s.run(&["start", "--hotfix", "prod", "Bring the feature"])), 0);
    s.git(&["merge", "-q", "--ff-only", "origin/main"]);
    assert_eq!(code(&s.run(&["finish", "--outcome", "Fixed"])), 0);
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD"])), 0);
    let held = s.run(&["land", "--json"]);
    let j = json(&held);
    assert_eq!((code(&held), j["code"].as_str()), (2, Some("NOT_ALLOWED")), "{}", text(&held));
    assert!(j["message"].as_str().unwrap().contains(&format!("{} is already on main", &feature[..12])), "{j:#}");
    with_pre_push_hook(&s);
    let before = remote_git(&remote, &["rev-parse", "prod"]);
    let pushed = hand_push(&s, &["origin", "HEAD:prod"]);
    assert!(!pushed.status.success() && text(&pushed).contains("HOTFIX_NOT_ITS_WORK"), "{}", text(&pushed));
    assert_eq!(remote_git(&remote, &["rev-parse", "prod"]), before);
    // A merge commit in the range is no hotfix's own work either.
    s.git(&["checkout", "-q", "-b", "side", "origin/prod"]);
    s.write("side.rs", "pub fn side() {}\n");
    s.commit_all("Side work");
    assert_eq!(code(&s.run(&["start", "--hotfix", "prod", "Merge side work"])), 0);
    s.git(&["merge", "-q", "--no-ff", "-m", "Merge side", "side"]);
    let held = s.run(&["land", "--json"]);
    assert!(json(&held)["message"].as_str().unwrap().contains("is a merge commit"), "{}", text(&held));
}

#[test]
fn a_hotfix_is_held_to_prods_signers_words_and_statements() {
    let dana = use05_receipt::SigningKey::from_bytes(&[13; 32]);
    let (s, _remote) = promotion_fixture_with(&key_entry("dana", "approver", &dana, Some("Dana")), "\n[environment.sign_off]\nsigners = [\"Dana\"]\n");
    hotfix_ready(&s);
    s.approver();
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD", "--reason", "fixed and checked"])), 0);
    let held = s.run(&["land", "--json"]);
    assert_eq!(code(&held), 3, "{}", text(&held));
    assert!(json(&held)["message"].as_str().unwrap().contains("'s approval does not count for it: its key names no person in the policy"), "only Dana may sign, and the policy knows this key for nobody: {}", text(&held));

    let (s, _remote) = promotion_fixture("\n[environment.sign_off]\nmin_length = 20\n\n[[environment.confirm]]\ntext = \"The release notes are published\"\n");
    hotfix_ready(&s);
    s.approver();
    // Words too short for prod's sign-off are refused before anything is signed, not held later.
    let short = approve_outcome(&s, &["--tree", "HEAD", "--reason", "ok", "--json"]);
    assert_eq!((code(&short), json(&short)["code"].as_str()), (6, Some("HOTFIX_WORDS_TOO_SHORT")), "{}", text(&short));
    assert!(json(&short)["message"].as_str().unwrap().contains("at least 20 characters") && records(&s, "approval").is_empty(), "{}", text(&short));
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD", "--reason", "fixed the total, tried it"])), 0);
    // A statement only a person can give needs a sign-off that gives it.
    let held = s.run(&["land", "--json"]);
    assert_eq!(code(&held), 3, "{}", text(&held));
    assert_eq!(json(&held)["next"], "use05 approve --promote prod --hotfix --note \"<what you checked>\"", "{}", text(&held));
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "prod", "--hotfix", "--note", "tried the fixed total by hand", "--confirm", "The release notes are published"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let signoff = &records(&s, "signoff")[0]["predicate"];
    assert_eq!((signoff["env"].as_str(), signoff["from"].as_str(), signoff["source_commit"].as_str()), (Some("prod"), Some("prod"), Some(s.git(&["rev-parse", "HEAD"]).as_str())));
    let landed = s.run(&["land", "--json"]);
    assert_eq!((code(&landed), json(&landed)["code"].as_str()), (0, Some("LANDED")), "{}", text(&landed));
}

#[test]
fn a_hotfix_record_is_filed_only_once_its_push_went_through() {
    let (s, remote) = promotion_fixture("");
    hotfix_ready(&s);
    s.approver();
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD"])), 0);
    with_pre_push_hook(&s);
    let hook = remote.path().join("hooks").join("pre-receive");
    fs::write(&hook, "#!/bin/sh\nwhile read old new ref; do [ \"$ref\" = refs/heads/prod ] && { echo \"prod is frozen\" >&2; exit 1; }; done\nexit 0\n").unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let refused = s.run(&["land", "--push", "--json"]);
    let j = json(&refused);
    assert_eq!((j["code"].as_str(), j["details"]["pushed"].as_bool()), (Some("LANDED"), Some(false)), "{j:#}");
    assert!(j["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("no hotfix record exists yet")), "{j:#}");
    assert!(records(&s, "promotion").is_empty(), "no record, here or on origin");
    // Once the push goes through, the record is filed.
    fs::remove_file(&hook).unwrap();
    let pushed = s.run(&["land", "--push", "--json"]);
    assert_eq!((json(&pushed)["code"].as_str(), json(&pushed)["details"]["pushed"].as_bool()), (Some("LANDED"), Some(true)), "{}", text(&pushed));
    assert_eq!(records(&s, "promotion").iter().filter(|p| p["predicate"]["direction"] == "hotfix").count(), 1);
    assert!(remote_git(&remote, &["for-each-ref", "refs/heads/05-receipts/"]).contains("05-receipts/"), "the record is on origin");
}

#[test]
fn a_hotfix_whose_environment_moved_on_is_refused() {
    let (s, _remote) = promotion_fixture("");
    hotfix_ready(&s);
    s.approver();
    assert_eq!(code(&approve_outcome(&s, &["--tree", "HEAD"])), 0);
    let here = s.git(&["branch", "--show-current"]);
    s.git(&["checkout", "-q", "prod"]);
    s.write("other.rs", "pub fn other() {}\n");
    s.commit_all("Something else on prod");
    s.git(&["push", "-q", "origin", "prod"]);
    s.git(&["checkout", "-q", &here]);
    let held = s.run(&["land", "--json"]);
    assert_eq!(code(&held), 2, "{}", text(&held));
    assert!(json(&held)["message"].as_str().unwrap().contains("prod moved on since it started"), "{}", text(&held));
}

#[test]
fn a_refused_hotfix_start_leaves_the_checkout_as_it_was() {
    let (s, _remote) = promotion_fixture_with("[drift]\noverlap = \"deny\"\n", "");
    assert_eq!(code(&s.run(&["start", "Cap retries", "--scope", "src/**"])), 0);
    let before = (s.git(&["branch", "--show-current"]), s.git(&["rev-parse", "HEAD"]), s.git(&["branch", "--list"]));
    let out = s.run(&["start", "--hotfix", "prod", "Fix retries", "--scope", "src/**", "--json"]);
    assert_eq!(json(&out)["code"], "OVERLAP", "{}", text(&out));
    assert_eq!((s.git(&["branch", "--show-current"]), s.git(&["rev-parse", "HEAD"]), s.git(&["branch", "--list"])), before, "no branch made, nothing checked out");
}

/// prod and uat each change feature.rs their own way, pushed: they conflict.
fn conflicting_rungs() -> (Sandbox, TempDir) {
    let (s, remote) = promotion_fixture("");
    for (branch, content) in [("prod", "prod's fix\n"), ("uat", "uat's change\n")] {
        s.git(&["checkout", "-q", branch]);
        s.write("feature.rs", content);
        s.commit_all(&format!("Change the feature on {branch}"));
        s.git(&["push", "-q", "origin", branch]);
    }
    s.git(&["checkout", "-q", "main"]);
    (s, remote)
}

/// Merge origin/prod into a copy of origin/uat by hand, resolving feature.rs: the merge commit.
fn resolve_by_hand(s: &Sandbox, branch: &str, extra: Option<&str>) -> String {
    s.git(&["checkout", "-q", "-b", branch, "origin/uat"]);
    let _ = Command::new("git").current_dir(s.dir.path()).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "merge", "-q", "origin/prod"]).output().unwrap();
    s.write("feature.rs", "both changes\n");
    if let Some(path) = extra {
        s.write(path, "more\n");
    }
    s.git(&["add", "-A"]);
    s.git(&["commit", "-q", "--no-edit"]);
    s.git(&["checkout", "-q", "main"]);
    s.git(&["rev-parse", branch])
}

#[test]
fn a_back_merge_resolved_by_hand_passes_with_a_persons_sign_off_on_it() {
    let (s, remote) = conflicting_rungs();
    let refused = json(&s.run(&["promote", "uat", "--back", "--json"]));
    assert_eq!(refused["code"], "BACK_MERGE_CONFLICT");
    let next = refused["next"].as_str().unwrap();
    assert!(next.contains("git merge origin/prod") && next.contains("use05 approve --promote uat --back --rev <merge commit>"), "{next}");
    with_pre_push_hook(&s);
    let merge = resolve_by_hand(&s, "resolved", None);
    let held = hand_push(&s, &["origin", "resolved:uat"]);
    assert!(!held.status.success() && text(&held).contains("BACK_MERGE_RESOLVED"), "{}", text(&held));
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "uat", "--back", "--rev", &merge, "--note", "kept both changes to feature.rs"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let pushed = hand_push(&s, &["origin", "resolved:uat"]);
    assert!(pushed.status.success(), "{}", text(&pushed));
    assert_eq!(remote_git(&remote, &["rev-parse", "uat"]), merge);
    // A merge that changes anything beyond the conflicted files is no back-merge.
    let (s, remote) = conflicting_rungs();
    with_pre_push_hook(&s);
    let before = remote_git(&remote, &["rev-parse", "uat"]);
    resolve_by_hand(&s, "more", Some("extra.rs"));
    let held = hand_push(&s, &["origin", "more:uat"]);
    assert!(!held.status.success() && text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "uat"]), before);
}

#[test]
fn a_forged_back_merge_into_uat_is_held() {
    let (s, remote) = promotion_fixture("");
    hotfix_landed(&s);
    s.git(&["checkout", "-q", "main"]);
    let before = remote_git(&remote, &["rev-parse", "uat"]);
    // Its second parent is not prod's head.
    let tree = s.git(&["rev-parse", "origin/main^{tree}"]);
    let wrong = s.git(&["commit-tree", &tree, "-p", "origin/uat", "-p", "origin/main", "-m", "Merge prod back into uat"]);
    let held = hand_push(&s, &["origin", &format!("{wrong}:refs/heads/uat")]);
    assert!(!held.status.success() && text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE"), "{}", text(&held));
    // The right parents, with something added to the clean merge.
    s.git(&["checkout", "-q", "-b", "forged", "origin/uat"]);
    s.git(&["merge", "-q", "--no-ff", "-m", "Merge prod back into uat", "origin/prod"]);
    s.write("extra.rs", "pub fn extra() {}\n");
    s.git(&["add", "-A"]);
    s.git(&["commit", "-q", "--amend", "--no-edit"]);
    let held = hand_push(&s, &["origin", "forged:uat"]);
    assert!(!held.status.success() && text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE"), "{}", text(&held));
    assert_eq!(remote_git(&remote, &["rev-parse", "uat"]), before);
}

#[test]
fn a_back_merges_rule_can_be_bypassed_by_a_person_for_that_merge() {
    let uat = "\n[environment.rules]\nuntasked = \"deny\"\n";
    let (s, remote) = promotion_fixture_of(&ladder(uat, ""));
    // A commit made on prod by hand, which belongs to no task.
    s.git(&["checkout", "-q", "prod"]);
    s.write("hand.rs", "pub fn hand() {}\n");
    s.commit_all("Fix prod by hand");
    s.git(&["push", "-q", "origin", "prod"]);
    s.git(&["checkout", "-q", "main"]);
    let held = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!((code(&held), json(&held)["code"].as_str()), (2, Some("UNTASKED_COMMITS")), "{}", text(&held));
    // The pre-push hook says how to break glass for it.
    with_pre_push_hook(&s);
    s.git(&["checkout", "-q", "-b", "by-hand", "origin/uat"]);
    s.git(&["merge", "-q", "--no-ff", "-m", "Merge prod back into uat", "origin/prod"]);
    s.git(&["checkout", "-q", "main"]);
    let pushed = hand_push(&s, &["origin", "by-hand:uat"]);
    assert!(!pushed.status.success() && text(&pushed).contains("use05 bypass --promote uat --back --rule <rule>"), "{}", text(&pushed));
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["bypass", "--promote", "uat", "--back", "--rule", "untasked", "--reason", "fixed by hand during the outage"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let bypass = &records(&s, "bypass")[0];
    assert_eq!((bypass["predicate"]["env"].as_str(), bypass["predicate"]["from"].as_str(), bypass["subject"][0]["digest"]["gitCommit"].as_str()), (Some("uat"), Some("prod"), Some(s.git(&["rev-parse", "origin/prod"]).as_str())));
    let out = s.run(&["promote", "uat", "--back", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("MERGED_BACK")), "{}", text(&out));
    assert_eq!(remote_git(&remote, &["rev-parse", "uat"]), json(&out)["details"]["result_commit"].as_str().unwrap());
}

// ---------------------------------------------------------------- destinations and agent remotes (D93 7)

/// A repository whose landing branch `main` holds `product/` and is on a bare origin, its checks
/// proved there, and a second, empty bare repository: the destination. `dest` goes into the
/// policy, with `{REMOTE}` standing for the destination's path.
fn destination_fixture(dest: &str) -> (Sandbox, TempDir, TempDir) {
    let s = Sandbox::new();
    let public = tempfile::tempdir().unwrap();
    let public_path = public.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &public_path]).status().unwrap().success());
    fs::create_dir_all(s.path(".05")).unwrap();
    fs::create_dir_all(s.path("product/src")).unwrap();
    s.write(".05/policy.toml", &format!("[[check]]\nname = \"test\"\nrun = [\"./test.sh\"]\n\n{}", dest.replace("{REMOTE}", &public_path)));
    s.write("product/README.md", "# The product\n");
    s.write("product/src/lib.rs", "pub fn product() {}\n");
    s.commit_all("base");
    s.write("notes.md", "internal notes\n");
    s.commit_all("Internal notes");
    let origin = tempfile::tempdir().unwrap();
    let origin_path = origin.path().display().to_string();
    assert!(Command::new("git").args(["init", "-q", "--bare", "-b", "main", &origin_path]).status().unwrap().success());
    s.git(&["remote", "add", "origin", &origin_path]);
    s.git(&["push", "-q", "origin", "main"]);
    let proved = s.run(&["prove", "--tree", "origin/main"]);
    assert_eq!(code(&proved), 0, "{}", text(&proved));
    (s, origin, public)
}

const EXPORT: &str = "[[destination]]\nname = \"public\"\nhow = \"export\"\nfrom = \"product/\"\nremote = \"{REMOTE}\"\nbranch = \"main\"\nagent = true\n";
const MIRROR: &str = "[[destination]]\nname = \"mirror\"\nhow = \"push\"\nremote = \"{REMOTE}\"\nbranch = \"main\"\nagent = true\n";

#[test]
fn export_destination_copies_the_folder_as_one_commit() {
    let (s, _origin, public) = destination_fixture(EXPORT);
    let head = s.git(&["rev-parse", "origin/main"]);
    // Not committed, so never exported.
    s.write("product/scratch.txt", "work in progress\n");
    let checked = s.run(&["promote", "public", "--check", "--json"]);
    let j = json(&checked);
    assert_eq!((code(&checked), j["code"].as_str(), j["details"]["how"].as_str(), j["details"]["from"].as_str()), (0, Some("PROMOTE_CHECKED"), Some("export"), Some("main")), "{}", text(&checked));
    assert_eq!(j["details"]["rules"].as_array().unwrap().len(), 6, "{j:#}");
    assert_eq!(j["details"]["rules_from"], "main's policy (origin/main)", "{j:#}");
    assert!(remote_git(&public, &["for-each-ref"]).is_empty(), "a check pushes nothing");
    let brief = s.run(&["brief", "--promote", "public"]);
    assert_eq!(code(&brief), 0, "{}", text(&brief));
    assert!(text(&brief).contains("main → public"), "{}", text(&brief));

    let out = s.run(&["promote", "public", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    let sync = remote_git(&public, &["rev-parse", "main"]);
    assert_eq!(j["details"]["result_commit"], sync);
    assert_eq!(remote_git(&public, &["rev-parse", "main^{tree}"]), s.git(&["rev-parse", &format!("{head}:product")]), "its whole tree is the folder's exact committed content");
    assert_eq!(remote_git(&public, &["ls-tree", "-r", "--name-only", "main"]), "README.md\nsrc/lib.rs", "the folder's files, and nothing from outside it or uncommitted");
    assert_eq!(remote_git(&public, &["rev-list", "--count", "main"]), "1", "one commit");
    let message = remote_git(&public, &["log", "-1", "--format=%B", "main"]);
    assert!(message.starts_with(&format!("Sync from {}", &head[..12])), "{message}");
    assert!(message.contains("05-Promotion: public from main") && message.contains(&format!("05-Source: {head}")), "{message}");
    let promotions = records(&s, "promotion");
    assert_eq!(promotions.len(), 1);
    let p = &promotions[0]["predicate"];
    assert_eq!((p["env"].as_str(), p["from"].as_str(), p["direction"].as_str(), p["how"].as_str()), (Some("public"), Some("main"), Some("up"), Some("export")));
    assert_eq!((p["source_commit"].as_str(), p["result_commit"].as_str(), p["target_before"].as_str()), (Some(head.as_str()), Some(sync.as_str()), None));

    // Nothing changed in the folder: nothing to sync, even though main moved.
    fs::remove_file(s.path("product/scratch.txt")).unwrap();
    s.write("notes.md", "more internal notes\n");
    s.commit_all("More notes");
    s.git(&["push", "-q", "origin", "main"]);
    let again = s.run(&["promote", "public", "--json"]);
    assert_eq!((code(&again), json(&again)["code"].as_str()), (0, Some("NOTHING_TO_PROMOTE")), "{}", text(&again));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), sync);
    assert_eq!(records(&s, "promotion").len(), 1, "nothing moved, so no new record");

    // A change in it: one more commit on top, never forced.
    s.write("product/src/more.rs", "pub fn more() {}\n");
    s.commit_all("More product");
    s.git(&["push", "-q", "origin", "main"]);
    assert_eq!(code(&s.run(&["prove", "--tree", "origin/main"])), 0);
    let next = s.run(&["promote", "public", "--json"]);
    assert_eq!((code(&next), json(&next)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&next));
    let second = remote_git(&public, &["rev-parse", "main"]);
    assert_eq!(remote_git(&public, &["rev-parse", "main^"]), sync, "on top of the last sync");
    assert_eq!(remote_git(&public, &["rev-parse", "main^{tree}"]), s.git(&["rev-parse", "origin/main:product"]));
    assert_eq!(records(&s, "promotion").iter().filter(|r| r["predicate"]["target_before"] == sync.as_str()).count(), 1);
    assert_ne!(second, sync);
}

#[test]
fn a_destination_check_is_the_promotion_page() {
    // Named by a remote here, so the page reads the same on every machine.
    let (s, _origin, public) = destination_fixture(&EXPORT.replace("{REMOTE}", "public"));
    s.git(&["remote", "add", "public", &public.path().display().to_string()]);
    let out = s.run(&["promote", "public", "--check"]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    snapshot("promote_destination_check", &s, &out);
}

#[test]
fn an_export_is_held_by_its_rules_and_refused_cleanly() {
    let (s, _origin, public) = destination_fixture(&format!("{EXPORT}\n[destination.rules]\nuntasked = \"deny\"\n"));
    let held = s.run(&["promote", "public", "--json"]);
    assert_eq!((code(&held), json(&held)["code"].as_str()), (2, Some("UNTASKED_COMMITS")), "{}", text(&held));
    assert!(remote_git(&public, &["for-each-ref"]).is_empty(), "held: nothing pushed");
    // A refused push leaves no record.
    let (s, _origin, public) = destination_fixture(EXPORT);
    let hook = public.path().join("hooks").join("pre-receive");
    fs::write(&hook, "#!/bin/sh\necho \"public is frozen\" >&2\nexit 1\n").unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let out = s.run(&["promote", "public", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str()), (4, Some("PROMOTE_PUSH_FAILED")), "{}", text(&out));
    assert!(j["message"].as_str().unwrap().contains("public is frozen"), "{j:#}");
    assert!(records(&s, "promotion").is_empty(), "no record");
    assert!(remote_git(&public, &["for-each-ref"]).is_empty());
    // Under an agent, where agent is not set, it is for a person.
    let (s, _origin, _public) = destination_fixture(&EXPORT.replace("agent = true\n", ""));
    let out = s.run_env(&["promote", "public", "--json"], &[("CLAUDE_CODE_SESSION_ID", "s-1")]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (2, Some("AGENT_MAY_NOT_PROMOTE")), "{}", text(&out));
    for flag in ["--back", "--confirm", "--rollback"] {
        let out = s.run(&["promote", "public", flag, "--json"]);
        assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("NOT_FOR_A_DESTINATION")), "{flag}: {}", text(&out));
    }
}

#[test]
fn push_destination_fast_forwards_only() {
    let (s, _origin, public) = destination_fixture(MIRROR);
    let head = s.git(&["rev-parse", "origin/main"]);
    let out = s.run(&["promote", "mirror", "--json"]);
    let j = json(&out);
    assert_eq!((code(&out), j["code"].as_str(), j["details"]["how"].as_str()), (0, Some("PROMOTED"), Some("push")), "{}", text(&out));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), head, "the landing branch's head, as it is");
    let p = &records(&s, "promotion")[0]["predicate"];
    assert_eq!((p["env"].as_str(), p["from"].as_str(), p["how"].as_str(), p["result_commit"].as_str()), (Some("mirror"), Some("main"), Some("push"), Some(head.as_str())));
    let again = s.run(&["promote", "mirror", "--json"]);
    assert_eq!((code(&again), json(&again)["code"].as_str()), (0, Some("NOTHING_TO_PROMOTE")), "{}", text(&again));

    // The destination gains a commit of its own: promoting would leave it behind, so it is refused.
    let other = tempfile::tempdir().unwrap();
    let other_path = other.path().display().to_string();
    assert!(Command::new("git").args(["clone", "-q", &public.path().display().to_string(), &other_path]).status().unwrap().success());
    fs::write(other.path().join("theirs.md"), "theirs\n").unwrap();
    for args in [vec!["add", "-A"], vec!["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "Theirs"], vec!["push", "-q", "origin", "main"]] {
        assert!(Command::new("git").arg("-C").arg(other.path()).args(&args).status().unwrap().success(), "{args:?}");
    }
    let theirs = remote_git(&public, &["rev-parse", "main"]);
    s.write("product/src/more.rs", "pub fn more() {}\n");
    s.commit_all("More product");
    s.git(&["push", "-q", "origin", "main"]);
    assert_eq!(code(&s.run(&["prove", "--tree", "origin/main"])), 0);
    let held = s.run(&["promote", "mirror", "--json"]);
    assert_eq!((code(&held), json(&held)["code"].as_str()), (2, Some("PROMOTE_TARGET_AHEAD")), "{}", text(&held));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), theirs, "never forced");
    assert_eq!(records(&s, "promotion").len(), 1);
}

#[test]
fn an_agent_push_to_another_remote_is_held() {
    let (s, origin, public) = destination_fixture("[push]\nagent = [\"origin\"]\n");
    let public_path = public.path().display().to_string();
    s.git(&["remote", "add", "public", &public_path]);
    with_pre_push_hook(&s);
    let agent = [("CLAUDE_CODE_SESSION_ID", "s-1")];
    for remote in ["public", public_path.as_str()] {
        let held = hand_push_as(&s, &[remote, "main"], &agent);
        assert!(!held.status.success(), "{remote}: {}", text(&held));
        let said = text(&held).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(said.contains("PUSH_REMOTE_NOT_ALLOWED") && said.contains("ask the person to push it, or add the remote to [push] agent"), "{remote}: {said}");
        assert!(remote_git(&public, &["for-each-ref"]).is_empty(), "{remote}: nothing reached it");
    }
    // Origin is listed, by name or by its URL.
    s.git(&["branch", "agent/work", "main"]);
    let pushed = hand_push_as(&s, &["origin", "agent/work"], &agent);
    assert!(pushed.status.success(), "{}", text(&pushed));
    let pushed = hand_push_as(&s, &[&origin.path().display().to_string(), "agent/work:agent/other"], &agent);
    assert!(pushed.status.success(), "{}", text(&pushed));
    // A person's push, with no agent session, is not held by it.
    let pushed = hand_push(&s, &["public", "main"]);
    assert!(pushed.status.success(), "{}", text(&pushed));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), s.git(&["rev-parse", "main"]));
}

#[test]
fn agent_hook_holds_git_push_to_unlisted_remote() {
    let (s, origin, public) = destination_fixture(&format!("[push]\nagent = [\"origin\"]\n\n{}", EXPORT.replace("agent = true\n", "")));
    s.git(&["remote", "add", "public", &public.path().display().to_string()]);
    let hook = |command: &str| {
        let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": command } }).to_string();
        let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v["hookSpecificOutput"]["permissionDecision"].as_str().map(str::to_string), v["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap_or_default().to_string())
    };
    let public_url = public.path().display().to_string();
    for held in ["git push public main".to_string(), format!("git push {public_url} main"), "git -C . push public".to_string(), "sh -c 'git push public HEAD:main'".to_string(), "git push -u public main".to_string(), "cd app && git push public".to_string()] {
        let (decision, why) = hook(&held);
        assert_eq!(decision.as_deref(), Some("deny"), "should be held: {held}");
        assert!(why.contains("PUSH_REMOTE_NOT_ALLOWED") && why.contains("ask the person to push it, or add the remote to [push] agent"), "{held}: {why}");
    }
    for ok in ["git push origin main".to_string(), "git push".to_string(), format!("git push {} main", origin.path().display()), "git status".to_string(), "echo git push public".to_string()] {
        assert_eq!(hook(&ok).0, None, "should be allowed: {ok}");
    }
    // A destination kept for people: the agent hooks hold its promotion, and checking it is anyone's.
    let (decision, why) = hook("use05 promote public");
    assert_eq!(decision.as_deref(), Some("deny"), "{why}");
    assert!(why.contains("use05 promote public --check"), "{why}");
    assert_eq!(hook("use05 promote public --check").0, None);
    // With no [push] agent, any remote.
    let (s, _origin, public) = destination_fixture("");
    s.git(&["remote", "add", "public", &public.path().display().to_string()]);
    let payload = serde_json::json!({ "session_id": "sess-1234abcd", "cwd": s.dir.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push public main" } }).to_string();
    let out = s.run_with_stdin(&["hook", "claude-code", "PreToolUse"], &payload);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], Value::Null, "{}", text(&out));
}

#[test]
fn a_destination_is_signed_off_on_and_bypassed_as_an_environment_is() {
    let (s, _origin, public) = destination_fixture(&format!("{EXPORT}\n[destination.rules]\nsign_off = \"approval\"\nuntasked = \"deny\"\n\n[[destination.confirm]]\ntext = \"The licence is in the folder\"\n"));
    let held = s.run(&["promote", "public", "--check", "--json"]);
    let codes: Vec<String> = json(&held)["details"]["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect();
    assert_eq!(code(&held), 2, "{}", text(&held));
    assert!(codes.contains(&"SIGNOFF_REQUIRED".to_string()) && codes.contains(&"UNTASKED_COMMITS".to_string()), "{codes:?}");
    let page = text(&s.run(&["brief", "--promote", "public"]));
    assert!(page.contains("confirms: The licence is in the folder") && page.contains("05 never rolls public back"), "{page}");
    s.approver();
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "public", "--note", "Read every file in the folder", "--confirm", "The licence is in the folder"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    assert!(screen.contains("Signed off on promoting"), "{screen}");
    let signoff = &records(&s, "signoff")[0]["predicate"];
    assert_eq!((signoff["env"].as_str(), signoff["from"].as_str()), (Some("public"), Some("main")));
    let (exit, screen) = on_a_terminal(&s, &["bypass", "--promote", "public", "--rule", "untasked", "--reason", "the folder was written by hand before 05"], &["correct horse"]);
    assert_eq!(exit, 0, "{screen}");
    let out = s.run(&["promote", "public", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    let message = remote_git(&public, &["log", "-1", "--format=%B", "main"]);
    assert!(message.contains("signed off: Read every file in the folder") && message.contains("05-Bypass: untasked"), "{message}");
    let p = &records(&s, "promotion")[0]["predicate"];
    assert_eq!((p["signoffs"].as_array().unwrap().len(), p["bypasses"].as_array().unwrap().len()), (1, 1), "{p:#}");
    // A destination has no back-merge, hotfix or merge resolved by hand to sign off on.
    let (exit, screen) = on_a_terminal(&s, &["approve", "--promote", "public", "--back"], &[]);
    assert_eq!(exit, 6, "{screen}");
    assert!(screen.contains("public is a destination"), "{screen}");
}

#[test]
fn a_push_destination_goes_out_through_the_pre_push_hook_and_a_hand_push_is_held() {
    let (s, _origin, public) = destination_fixture(&format!("[push]\nagent = [\"origin\"]\n\n{MIRROR}"));
    let public_path = public.path().display().to_string();
    s.git(&["remote", "add", "public", &public_path]);
    with_pre_push_hook(&s);
    // An agent the destination lets in promotes to it through the hook, though [push] agent leaves it out.
    let out = s.run_env(&["promote", "mirror", "--json"], &[("CLAUDE_CODE_SESSION_ID", "s-1")]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (0, Some("PROMOTED")), "{}", text(&out));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), s.git(&["rev-parse", "origin/main"]));
    // By hand, only the head 05 judged goes there.
    s.git(&["checkout", "-q", "-b", "other"]);
    s.write("product/src/hand.rs", "pub fn hand() {}\n");
    s.commit_all("By hand");
    s.git(&["checkout", "-q", "main"]);
    let held = hand_push(&s, &["public", "other:main"]);
    assert!(!held.status.success(), "{}", text(&held));
    assert!(text(&held).contains("PROMOTE_NOT_EVALUATED_MOVE") && text(&held).contains("use05 promote mirror"), "{}", text(&held));
    assert_eq!(remote_git(&public, &["rev-parse", "main"]), s.git(&["rev-parse", "origin/main"]), "it did not move");
}

#[test]
fn a_destination_named_like_an_environment_is_refused() {
    let (s, _origin, public) = destination_fixture("");
    let twice = format!("[[environment]]\nname = \"dev\"\nbranch = \"main\"\n\n{}", EXPORT.replace("\"public\"", "\"dev\"").replace("{REMOTE}", &public.path().display().to_string()));
    s.write(".05/policy.toml", &twice);
    s.commit_all("Two targets named dev");
    s.git(&["push", "-q", "origin", "main"]);
    let out = s.run(&["promote", "dev", "--check", "--json"]);
    assert_eq!((code(&out), json(&out)["code"].as_str()), (6, Some("DUPLICATE_TARGET")), "{}", text(&out));
}

#[test]
fn approving_a_hotfix_says_it_lands_straight_on_its_environment() {
    let (s, _remote) = promotion_fixture("");
    hotfix_ready(&s);
    s.approver();
    let approved = s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin"], "correct horse\n");
    assert_eq!(code(&approved), 0, "{}", text(&approved));
    let said = text(&approved).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(said.contains("This approval lands the hotfix straight on prod"), "the prompt says it: {said}");
    let j = json(&s.run_with_stdin(&["approve", "--outcome", "--tree", "HEAD", "--passphrase-stdin", "--json"], "correct horse\n"));
    assert!(j["message"].as_str().unwrap().contains("a hotfix this approval lands straight on prod"), "the headline says it: {j:#}");
}

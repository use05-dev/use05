//! Integration tests against real, throwaway git repositories.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use use05_receipt::Status;
use use05_runner::{ProveOptions, identify, prove};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn repo() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["config", "core.autocrlf", "false"]);
    dir
}

fn write(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn options(dir: &Path, tree: &str, argv: &[&str], secs: u64) -> ProveOptions {
    ProveOptions {
        repo: dir.to_path_buf(),
        tree: tree.to_string(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        timeout: Duration::from_secs(secs),
        pass_env: Vec::new(),
        check: None,
    }
}

fn sh(dir: &Path, tree: &str, script: &str) -> use05_receipt::Outcome {
    prove(&options(dir, tree, &["sh", "-c", script], 30)).expect("proves").predicate.result
}

#[test]
fn the_tree_identity_is_deterministic_and_sensitive_to_content_and_mode() {
    let r = repo();
    write(r.path(), "a.txt", "one\n");
    write(r.path(), "run.sh", "#!/bin/sh\n");
    git(r.path(), &["add", "-A"]);

    let first = identify(r.path(), "index").unwrap();
    assert_eq!(first, identify(r.path(), "index").unwrap());
    assert_eq!(first.sha256.len(), 64);

    git(r.path(), &["commit", "-q", "-m", "one"]);
    assert_eq!(first, identify(r.path(), "HEAD").unwrap(), "HEAD and the index name the same tree");

    write(r.path(), "a.txt", "two\n");
    git(r.path(), &["add", "-A"]);
    let changed = identify(r.path(), "index").unwrap();
    assert_ne!(first.oid, changed.oid);
    assert_ne!(first.sha256, changed.sha256);

    fs::set_permissions(r.path().join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    git(r.path(), &["add", "-A"]);
    let moded = identify(r.path(), "index").unwrap();
    assert_ne!(changed.sha256, moded.sha256, "the executable bit is part of the tree");
}

#[test]
fn the_command_sees_the_staged_tree_not_the_working_directory() {
    let r = repo();
    write(r.path(), "a.txt", "staged\n");
    git(r.path(), &["add", "-A"]);
    write(r.path(), "a.txt", "edited but not staged\n");
    write(r.path(), "untracked.txt", "x");

    let statement = prove(&options(r.path(), "index", &["cat", "a.txt"], 30)).unwrap();
    assert_eq!(statement.predicate.result.stdout.sha256, sha(b"staged\n"));

    let result = sh(r.path(), "index", "test ! -e untracked.txt");
    assert_eq!(result.status, Status::Passed, "untracked files are not in the proven tree");
}

#[test]
fn modes_symlinks_and_submodule_entries_survive_export() {
    let r = repo();
    write(r.path(), "a.txt", "x\n");
    write(r.path(), "bin/run.sh", "#!/bin/sh\n");
    fs::set_permissions(r.path().join("bin/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("a.txt", r.path().join("link")).unwrap();
    git(r.path(), &["add", "-A"]);
    git(r.path(), &["commit", "-q", "-m", "base"]);
    let head = git(r.path(), &["rev-parse", "HEAD"]);
    git(r.path(), &["update-index", "--add", "--cacheinfo", &format!("160000,{head},sub")]);

    let script = r#"
        test -x bin/run.sh && test ! -x a.txt &&
        test -L link && test "$(readlink link)" = a.txt &&
        test -d sub && test -z "$(ls -A sub)"
    "#;
    assert_eq!(sh(r.path(), "index", script).status, Status::Passed);
}

#[test]
fn a_failing_command_is_a_result_not_an_error() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let result = sh(r.path(), "index", "echo oops >&2; exit 3");
    assert_eq!(result.status, Status::Failed);
    assert_eq!(result.exit_code, Some(3));
    assert_eq!(result.stderr.sha256, sha(b"oops\n"));
    assert_eq!(result.stdout.total_bytes, 0);
}

#[test]
fn output_beyond_the_bound_is_counted_but_not_kept() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let result = sh(r.path(), "index", "head -c 3145728 /dev/zero");
    assert_eq!(result.status, Status::Passed, "a chatty command must not block or fail");
    assert_eq!(result.stdout.total_bytes, 3_145_728);
    assert_eq!(result.stdout.retained_bytes, 1_048_576);
    assert!(result.stdout.truncated);
    assert_eq!(result.stdout.sha256, sha(&vec![0u8; 1_048_576]));
}

#[test]
fn non_utf8_output_is_digested_as_bytes() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let result = sh(r.path(), "index", r"printf '\377\376'");
    assert_eq!(result.stdout.total_bytes, 2);
    assert_eq!(result.stdout.sha256, sha(&[0xff, 0xfe]));
}

#[test]
fn a_command_that_runs_too_long_is_killed_and_recorded() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let started = Instant::now();
    let statement = prove(&options(r.path(), "index", &["sleep", "30"], 1)).unwrap();
    assert_eq!(statement.predicate.result.status, Status::TimedOut);
    assert_eq!(statement.predicate.result.exit_code, None);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_timeout_also_stops_the_commands_children() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let started = Instant::now();
    let statement = prove(&options(r.path(), "index", &["sh", "-c", "sleep 30 & sleep 30"], 1)).unwrap();
    assert_eq!(statement.predicate.result.status, Status::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10), "children holding the pipes must not hang the proof");
}

#[test]
fn processes_left_running_after_a_clean_exit_do_not_hang_the_proof() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let started = Instant::now();
    let result = sh(r.path(), "index", "sleep 30 & exit 0");
    assert_eq!(result.status, Status::Passed);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_environment_is_scrubbed() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);

    assert!(std::env::var("CARGO_MANIFEST_DIR").is_ok(), "the test process has a variable to leak");
    assert_eq!(sh(r.path(), "index", "printenv CARGO_MANIFEST_DIR").status, Status::Failed);
    assert_eq!(sh(r.path(), "index", r#"test -n "$PATH" && test -d "$HOME" && test -d "$TMPDIR""#).status, Status::Passed);

    let statement = prove(&options(r.path(), "index", &["true"], 30)).unwrap();
    assert_eq!(statement.predicate.environment.names, ["HOME", "LANG", "PATH", "TMPDIR"]);
    let again = prove(&options(r.path(), "index", &["true"], 30)).unwrap();
    assert_eq!(
        statement.predicate.environment.fingerprint, again.predicate.environment.fingerprint,
        "per-run scratch paths must not change the fingerprint"
    );
}

#[test]
fn the_command_cannot_change_the_repository_it_was_proven_from() {
    let r = repo();
    write(r.path(), "a.txt", "x\n");
    git(r.path(), &["add", "-A"]);
    let before = identify(r.path(), "index").unwrap();
    let status_before = git(r.path(), &["status", "--porcelain"]);

    let result = sh(r.path(), "index", "echo built > generated.txt && rm a.txt");
    assert_eq!(result.status, Status::Passed);

    assert_eq!(before, identify(r.path(), "index").unwrap());
    assert_eq!(status_before, git(r.path(), &["status", "--porcelain"]));
    assert!(r.path().join("a.txt").exists());
    assert!(!r.path().join("generated.txt").exists());
}

#[test]
fn the_statement_records_the_command_and_runner() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let statement = prove(&options(r.path(), "index", &["true"], 30)).unwrap();
    let evidence = &statement.predicate;
    assert_eq!(evidence.command.argv, ["true"]);
    assert_eq!(evidence.command.cwd, ".");
    assert_eq!(evidence.runner.name, "use05");
    assert!(evidence.runner.platform.contains('-'));
    assert_eq!(evidence.created.len(), 20);
    assert!(evidence.created.ends_with('Z'));
    let (oid, digest) = statement.tree_subject().unwrap();
    let id = identify(r.path(), "index").unwrap();
    assert_eq!((oid, digest), (id.oid.as_str(), id.sha256.as_str()));
}

#[test]
fn errors_have_stable_codes() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);

    let code = |o: ProveOptions| prove(&o).unwrap_err().code();
    assert_eq!(code(options(r.path(), "index", &["definitely-not-a-command-05"], 5)), "COMMAND_NOT_STARTED");
    assert_eq!(code(options(r.path(), "index", &[], 5)), "NO_COMMAND");
    assert_eq!(code(options(r.path(), "no-such-rev", &["true"], 5)), "TREE_NOT_FOUND");
    assert_eq!(code(options(r.path(), "--help", &["true"], 5)), "TREE_NOT_FOUND", "a revision cannot look like an option");

    let elsewhere = tempfile::tempdir().unwrap();
    assert_eq!(code(options(elsewhere.path(), "index", &["true"], 5)), "NOT_A_REPO");
}

fn mktree(dir: &Path, line: &str) -> Option<String> {
    use std::io::Write;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("{line}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn trees_with_paths_that_could_escape_or_touch_git_are_refused() {
    let r = repo();
    let blob = git(r.path(), &["hash-object", "-w", "--stdin"]);
    let blob = if blob.is_empty() {
        // `hash-object --stdin` reads nothing from our null stdin: an empty blob, which is fine.
        git(r.path(), &["hash-object", "-w", "/dev/null"])
    } else {
        blob
    };
    let mut tried = 0;
    for name in [".git", ".GIT", ".."] {
        let Some(inner) = mktree(r.path(), &format!("100644 blob {blob}\tx")) else { continue };
        let Some(outer) = mktree(r.path(), &format!("040000 tree {inner}\t{name}")) else {
            eprintln!("git refused to build a tree named {name:?}; nothing to test for it");
            continue;
        };
        tried += 1;
        let err = identify(r.path(), &outer).unwrap_err();
        assert_eq!(err.code(), "UNSAFE_PATH", "name {name:?}");
        let err = prove(&options(r.path(), &outer, &["true"], 5)).unwrap_err();
        assert_eq!(err.code(), "UNSAFE_PATH", "name {name:?}");
    }
    assert!(tried > 0, "git accepted none of the hostile names, so this test proved nothing");
}

#[test]
fn a_large_tree_is_identified_consistently() {
    let r = repo();
    for i in 0..1500 {
        write(r.path(), &format!("dir{}/file{i}.txt", i % 30), &format!("content {i}\n"));
    }
    git(r.path(), &["add", "-A"]);
    let started = Instant::now();
    let first = identify(r.path(), "index").unwrap();
    let elapsed = started.elapsed();
    assert_eq!(first, identify(r.path(), "index").unwrap());
    eprintln!("identified 1500 files in {elapsed:?}");
    assert!(elapsed < Duration::from_secs(30));
}

#[test]
fn an_empty_tree_can_be_proven() {
    let r = repo();
    git(r.path(), &["commit", "-q", "--allow-empty", "-m", "empty"]);
    let statement = prove(&options(r.path(), "HEAD", &["true"], 5)).unwrap();
    assert_eq!(statement.predicate.result.status, Status::Passed);
    assert_eq!(statement.tree_subject().unwrap().0, "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
}

fn with_env(dir: &Path, argv: &[&str], pass: &[(&str, &str)]) -> ProveOptions {
    let mut o = options(dir, "index", argv, 30);
    o.pass_env = pass.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    o
}

#[test]
fn passed_through_variables_reach_the_command_and_are_recorded_by_name_only() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);

    let seen = prove(&with_env(r.path(), &["sh", "-c", r#"test "$MY_FLAG" = on"#], &[("MY_FLAG", "on")])).unwrap();
    assert_eq!(seen.predicate.result.status, Status::Passed);
    assert_eq!(seen.predicate.environment.names, ["HOME", "LANG", "MY_FLAG", "PATH", "TMPDIR"]);
    let receipt = serde_json::to_string(&seen).unwrap();
    assert!(!receipt.contains("\"on\""), "the value must not be in the receipt");

    let without = prove(&with_env(r.path(), &["sh", "-c", r#"test "$MY_FLAG" = on"#], &[])).unwrap();
    assert_eq!(without.predicate.result.status, Status::Failed, "unlisted variables stay hidden");

    let other_value = prove(&with_env(r.path(), &["true"], &[("MY_FLAG", "off")])).unwrap();
    let same_value = prove(&with_env(r.path(), &["true"], &[("MY_FLAG", "on")])).unwrap();
    let again = prove(&with_env(r.path(), &["true"], &[("MY_FLAG", "on")])).unwrap();
    assert_eq!(same_value.predicate.environment.fingerprint, again.predicate.environment.fingerprint);
    assert_ne!(
        same_value.predicate.environment.fingerprint, other_value.predicate.environment.fingerprint,
        "a different value must change the fingerprint even though the value is not stored"
    );
}

#[test]
fn a_passed_home_replaces_the_scratch_home() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let result = prove(&with_env(r.path(), &["sh", "-c", r#"test "$HOME" = /somewhere/else"#], &[("HOME", "/somewhere/else")])).unwrap();
    assert_eq!(result.predicate.result.status, Status::Passed);
}

#[test]
fn unusable_variable_names_are_refused() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    for bad in ["", "1ABC", "A=B", "A B", "A-B", "É"] {
        let err = prove(&with_env(r.path(), &["true"], &[(bad, "v")])).unwrap_err();
        assert_eq!(err.code(), "BAD_ENV", "name {bad:?}");
    }
}

#[test]
fn the_end_of_the_output_is_available_for_display_but_not_in_the_statement() {
    use use05_runner::prove_with_output;
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let proof = prove_with_output(&options(r.path(), "index", &["sh", "-c", "seq 1 100000 >&2; exit 1"], 30)).unwrap();
    let tail = String::from_utf8(proof.stderr_tail.clone()).unwrap();
    assert!(tail.trim_end().ends_with("100000"), "the tail is the end of the stream");
    assert!(proof.stderr_tail.len() <= 4096);
    let receipt = serde_json::to_string(&proof.statement).unwrap();
    assert!(!receipt.contains("99999"), "output never enters the statement");
}

#[test]
fn the_remembered_blob_digests_never_change_the_answer_and_a_damaged_cache_is_ignored() {
    let dir = repo();
    write(dir.path(), "a.txt", "alpha\n");
    write(dir.path(), "src/b.txt", "beta\n");
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-q", "-m", "one"]);

    // The digest an export computes (no cache involved) is the reference.
    let reference = prove(&options(dir.path(), "HEAD", &["true"], 20)).unwrap();
    let (_, exported) = reference.tree_subject().expect("tree subject");
    let exported = exported.to_string();

    // identify() fills the cache, and gives the same answer cold and warm.
    let cold = identify(dir.path(), "HEAD").unwrap();
    let cache = dir.path().join(".git/05/blob-digests");
    assert!(cache.exists(), "the digests are remembered");
    let warm = identify(dir.path(), "HEAD").unwrap();
    assert_eq!((cold.sha256.as_str(), warm.sha256.as_str()), (exported.as_str(), exported.as_str()));

    // Damaged, truncated and foreign lines are ignored; the answer is still right.
    let mut text = fs::read_to_string(&cache).unwrap();
    text.push_str("not a line\nzz zz\n0000 1111\n");
    text.insert_str(0, "deadbeef not-hex\n");
    fs::write(&cache, text).unwrap();
    assert_eq!(identify(dir.path(), "HEAD").unwrap().sha256, exported);
    fs::write(&cache, "").unwrap();
    assert_eq!(identify(dir.path(), "HEAD").unwrap().sha256, exported, "an empty cache just means recomputing");

    // Changing one file changes the digest; the other file's remembered digest is reused.
    write(dir.path(), "a.txt", "alpha, edited\n");
    git(dir.path(), &["commit", "-q", "-am", "two"]);
    let after = identify(dir.path(), "HEAD").unwrap().sha256;
    assert_ne!(after, exported);
    let reference = prove(&options(dir.path(), "HEAD", &["true"], 20)).unwrap();
    assert_eq!(reference.tree_subject().unwrap().1, after);
}

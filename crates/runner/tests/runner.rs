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
        check_user: None,
        dir: None,
        lfs: false,
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

fn whoami() -> String {
    String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim().to_string()
}

#[test]
fn check_user_missing_is_an_error_not_a_fallback() {
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let marker = tempfile::tempdir().unwrap();
    let ran = marker.path().join("ran");
    let mut o = options(r.path(), "index", &["sh", "-c", &format!("touch '{}'", ran.display())], 5);

    // An ordinary run records no check user at all.
    let plain = prove(&o).unwrap();
    assert_eq!(plain.predicate.runner.check_user, None);
    assert!(!serde_json::to_string(&plain).unwrap().contains("check_user"), "the field is left out, so older receipts read the same");
    fs::remove_file(&ran).unwrap();

    // A user that does not exist, root, the user 05 runs as, and a name that is not one: none
    // keeps the key out of reach, and the command never runs as the key holder instead.
    for user in ["use05-no-such-user", "root", &whoami(), "-u"] {
        o.check_user = Some(user.to_string());
        let err = prove(&o).expect_err(user);
        assert_eq!(err.code(), "CHECK_USER_UNAVAILABLE", "{user}: {err}");
        assert!(err.to_string().contains(user), "it names the user: {err}");
        assert!(!ran.exists(), "{user}: the command ran anyway");
    }
}

const LFS_ATTRIBUTES: &str = "*.bin filter=lfs diff=lfs merge=lfs -text\n";

fn lfs_pointer_text(content: &str) -> String {
    format!("version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n", sha(content.as_bytes()), content.len())
}

/// Whether `git lfs` is installed here. The tests that need it say so and pass when it is not.
fn git_lfs_here() -> bool {
    let ok = Command::new("git").args(["lfs", "version"]).stdin(Stdio::null()).output().is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipped: git-lfs is not installed here");
    }
    ok
}

/// A repository whose `big.bin` is committed as an LFS pointer, written by hand so that no
/// git-lfs is needed to make it. The object it names is nowhere.
fn repo_with_a_pointer(content: &str) -> TempDir {
    let r = repo();
    write(r.path(), ".gitattributes", LFS_ATTRIBUTES);
    write(r.path(), "big.bin", &lfs_pointer_text(content));
    write(r.path(), "plain.txt", "not lfs\n");
    git(r.path(), &["add", "-A"]);
    git(r.path(), &["commit", "-q", "-m", "pointer"]);
    r
}

#[test]
fn lfs_pointers_are_checked_as_committed_unless_asked_and_the_tree_digest_never_moves() {
    let r = repo_with_a_pointer("the real bytes\n");
    let pointer = lfs_pointer_text("the real bytes\n");

    let off = prove(&options(r.path(), "HEAD", &["sh", "-c", &format!("test \"$(cat big.bin)\" = '{}'", pointer.trim_end())], 30)).unwrap();
    assert_eq!(off.predicate.result.status, Status::Passed, "with lfs off the check sees the pointer exactly as committed");
    assert!(off.predicate.lfs.is_empty());
    assert!(!serde_json::to_string(&off).unwrap().contains("\"lfs\""), "the field is left out when there is nothing to list");
    assert_eq!(off.tree_subject().unwrap().1, identify(r.path(), "HEAD").unwrap().sha256);

    // A tree with no pointers needs no git-lfs even when it is asked for.
    let plain = repo();
    write(plain.path(), "a.txt", "x\n");
    git(plain.path(), &["add", "-A"]);
    let mut o = options(plain.path(), "index", &["true"], 5);
    o.lfs = true;
    assert!(prove(&o).unwrap().predicate.lfs.is_empty());
    // Pointer-looking files that no .gitattributes sends through LFS stay as they are.
    let stray = repo();
    write(stray.path(), "big.bin", &pointer);
    git(stray.path(), &["add", "-A"]);
    let mut o = options(stray.path(), "index", &["true"], 5);
    o.lfs = true;
    assert!(prove(&o).unwrap().predicate.lfs.is_empty(), "no .gitattributes uses LFS, so nothing is fetched");
}

#[test]
fn lfs_on_resolves_pointers_and_lists_them() {
    if !git_lfs_here() {
        return;
    }
    let r = repo();
    git(r.path(), &["lfs", "install", "--local"]);
    write(r.path(), ".gitattributes", LFS_ATTRIBUTES);
    write(r.path(), "assets/big.bin", "the real bytes\n");
    write(r.path(), "plain.txt", "not lfs\n");
    git(r.path(), &["add", "-A"]);
    git(r.path(), &["commit", "-q", "-m", "lfs"]);
    let committed = git(r.path(), &["cat-file", "-p", "HEAD:assets/big.bin"]);
    assert!(committed.starts_with("version https://git-lfs.github.com/spec/v1"), "committed as a pointer: {committed}");

    let script = r#"test "$(cat assets/big.bin)" = "the real bytes" && test "$(cat plain.txt)" = "not lfs""#;
    let mut o = options(r.path(), "HEAD", &["sh", "-c", script], 30);
    o.lfs = true;
    let on = prove(&o).unwrap();
    assert_eq!(on.predicate.result.status, Status::Passed, "the check saw the real file");
    let files = &on.predicate.lfs;
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!((files[0].path.as_str(), files[0].oid.as_str(), files[0].size), ("assets/big.bin", sha(b"the real bytes\n").as_str(), 15));
    let json = serde_json::to_value(&on).unwrap();
    assert_eq!(json["predicate"]["lfs"][0]["path"], "assets/big.bin");

    // The tree is the committed one: the same identity, with or without the real files.
    o.lfs = false;
    o.argv = vec!["sh".into(), "-c".into(), "head -1 assets/big.bin | grep -q git-lfs".into()];
    let off = prove(&o).unwrap();
    assert_eq!(off.predicate.result.status, Status::Passed, "with lfs off it is the pointer");
    assert_eq!(on.tree_subject(), off.tree_subject());
    assert_eq!(on.tree_subject().unwrap().1, identify(r.path(), "HEAD").unwrap().sha256);
}

#[test]
fn an_lfs_file_that_cannot_be_fetched_stops_the_proof() {
    if !git_lfs_here() {
        return;
    }
    // The pointer names an object that is nowhere: not here, and there is no server to ask.
    let r = repo_with_a_pointer("bytes nobody has\n");
    git(r.path(), &["lfs", "install", "--local"]);
    let marker = tempfile::tempdir().unwrap();
    let ran = marker.path().join("ran");
    let mut o = options(r.path(), "HEAD", &["sh", "-c", &format!("touch '{}'", ran.display())], 30);
    o.lfs = true;
    let err = prove(&o).unwrap_err();
    assert_eq!(err.code(), "LFS_FAILED", "{err}");
    assert!(err.to_string().contains("big.bin"), "it names the file: {err}");
    assert!(!ran.exists(), "the check never ran on a pointer it was told would be the real file");
}

/// Needs Linux, passwordless sudo and the check user (`sudo useradd --create-home use05-check`),
/// as on a GitHub runner; run with USE05_TEST_SUDO=1.
#[cfg(target_os = "linux")]
#[test]
fn checks_run_as_the_check_user_and_cannot_read_the_key() {
    if std::env::var("USE05_TEST_SUDO").as_deref() != Ok("1") {
        eprintln!("skipped: set USE05_TEST_SUDO=1 where sudo needs no password and the user use05-check exists");
        return;
    }
    let user = std::env::var("USE05_TEST_CHECK_USER").unwrap_or_else(|_| "use05-check".into());
    let r = repo();
    write(r.path(), "a", "x");
    git(r.path(), &["add", "-A"]);
    let secret = tempfile::tempdir().unwrap();
    let key = secret.path().join("runner.key");
    fs::write(&key, "use05-ed25519-secret:s3cret").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    // It reports who it is, tries the key holder's environment and key file, writes where a check
    // writes, and leaves something running.
    let script = "id -un; cat /proc/$HOLDER/environ >/dev/null 2>&1 && echo ENV_READ; cat \"$KEY\" 2>/dev/null; touch here \"$HOME/home\" \"$TMPDIR/tmp\" && echo WROTE; sleep 30 & true";
    let mut o = options(r.path(), "index", &["sh", "-c", script], 20);
    o.pass_env = vec![("HOLDER".into(), std::process::id().to_string()), ("KEY".into(), key.display().to_string())];
    o.check_user = Some(user.clone());
    let started = Instant::now();
    let proof = use05_runner::prove_with_output(&o).unwrap();
    let out = String::from_utf8_lossy(&proof.stdout_tail).to_string();
    assert_eq!(out.lines().next(), Some(user.as_str()), "{out}");
    assert!(!out.contains("ENV_READ") && !out.contains("s3cret"), "the check read the key holder's secrets:\n{out}");
    assert!(out.contains("WROTE"), "the check can write its tree, home and temp:\n{out}");
    assert_eq!(proof.statement.predicate.result.status, Status::Passed);
    assert_eq!(proof.statement.predicate.runner.check_user.as_deref(), Some(user.as_str()));
    assert!(started.elapsed() < Duration::from_secs(15), "what the check left running was stopped");

    // A command the check user cannot reach (in the key holder's own folder) or cannot find is
    // not started, as without a check user, rather than a signed failure.
    let private = tempfile::tempdir().unwrap();
    let tool = private.path().join("tool");
    fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    // Closed to others, as a runner's home is.
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for program in [tool.to_str().unwrap(), "use05-no-such-tool"] {
        let mut o = options(r.path(), "index", &[program], 20);
        o.check_user = Some(user.clone());
        let err = prove(&o).expect_err(program);
        assert_eq!(err.code(), "COMMAND_NOT_STARTED", "{program}: {err}");
        assert!(err.to_string().contains(&user), "it names the check user: {err}");
    }
}

// ---------------------------------------------------------------- the folder a check runs in (D97)

fn in_dir(dir: &Path, folder: &str, script: &str) -> Result<use05_receipt::Statement<use05_receipt::Evidence>, use05_runner::RunnerError> {
    let mut o = options(dir, "index", &["sh", "-c", script], 30);
    o.dir = Some(folder.to_string());
    prove(&o)
}

#[test]
fn a_check_runs_in_its_folder_of_the_exact_tree_and_the_receipt_says_which() {
    let r = repo();
    write(r.path(), "root.txt", "at the root\n");
    write(r.path(), "pkg/sub/here.txt", "in the folder\n");
    git(r.path(), &["add", "-A"]);
    let proved = in_dir(r.path(), "pkg/sub", "test -f here.txt && test ! -f root.txt").expect("proves");
    assert_eq!(proved.predicate.result.status, Status::Passed, "the command ran in pkg/sub");
    assert_eq!(proved.predicate.command.dir.as_deref(), Some("pkg/sub"));
    assert_eq!(proved.predicate.command.cwd, ".");
    // At the root it sees the other file, and records no folder.
    let at_root = prove(&options(r.path(), "index", &["sh", "-c", "test -f root.txt && test ! -f here.txt"], 30)).unwrap();
    assert_eq!((at_root.predicate.result.status, at_root.predicate.command.dir.clone()), (Status::Passed, None));
    let json = serde_json::to_string(&at_root.predicate.command).unwrap();
    assert!(!json.contains("dir"), "a command run at the root is written as it always was: {json}");
}

#[test]
fn a_folder_outside_the_tree_or_not_in_it_fails_the_check_and_runs_nothing() {
    let r = repo();
    write(r.path(), "pkg/a.txt", "a\n");
    write(r.path(), "file.txt", "not a folder\n");
    symlink("../..", r.path().join("pkg/up")).unwrap(); // leads out of the tree
    symlink("..", r.path().join("pkg/back")).unwrap(); // leads to the tree's own root: not out
    git(r.path(), &["add", "-A"]);
    assert!(in_dir(r.path(), "pkg/back", "test -f file.txt").is_ok_and(|s| s.predicate.result.status == Status::Passed), "a link that stays inside the tree is fine");
    // The command is not run, and the check fails by itself with the reason; nothing aborts.
    for (folder, reason) in [("..", "not inside the tree"), ("pkg/../..", "not inside the tree"), ("/tmp", "not inside the tree"), ("", "not inside the tree"), ("pkg/up", "not inside the tree"), ("nope", "not in this tree"), ("file.txt", "not in this tree")] {
        let proof = use05_runner::prove_with_output(&{
            let mut o = options(r.path(), "index", &["sh", "-c", "touch ran"], 30);
            o.dir = Some(folder.to_string());
            o
        })
        .unwrap_or_else(|e| panic!("{folder:?}: {e}"));
        assert_eq!(proof.statement.predicate.result.status, Status::Failed, "{folder:?}");
        assert_eq!((proof.statement.predicate.result.exit_code, proof.statement.predicate.command.dir.as_deref()), (None, Some(folder)));
        let said = proof.not_run.unwrap_or_default();
        assert!(said.contains(reason) && said.contains("not run"), "{folder:?}: {said}");
        assert!(String::from_utf8_lossy(&proof.stderr_tail).contains(reason));
    }
}

#[test]
fn an_export_runs_commands_again_and_again_in_the_exact_tree() {
    use use05_runner::Export;
    let r = repo();
    write(r.path(), "VERSION", "c0ffee1\n");
    write(r.path(), "ops/where.sh", "#!/bin/sh\npwd\n");
    git(r.path(), &["add", "-A"]);
    git(r.path(), &["commit", "-q", "-m", "one"]);
    write(r.path(), "VERSION", "changed in the working tree\n");
    let export = Export::new(r.path(), "HEAD", false).expect("exports");
    let argv = |s: &str| vec!["sh".to_string(), "-c".to_string(), s.to_string()];
    let secs = Duration::from_secs(10);
    for _ in 0..2 {
        let ran = export.run(&argv("cat VERSION; echo \"[$SECRET][$PASSED]\""), None, secs, &[("PASSED".into(), "yes".into())], None).expect("runs");
        assert_eq!(ran.status, Status::Passed);
        assert_eq!(String::from_utf8_lossy(&ran.stdout_tail), "c0ffee1\n[][yes]\n", "the committed file, and only the named variables");
        assert_eq!(ran.stdout_sha256, sha(b"c0ffee1\n[][yes]\n"));
    }
    assert_eq!(export.run(&argv("exit 3"), None, secs, &[], None).expect("a failure is a result").status, Status::Failed);
    assert_eq!(export.run(&argv("sleep 5"), None, Duration::from_millis(200), &[], None).expect("a timeout is a result").status, Status::TimedOut);
    let inside = export.run(&argv("pwd"), Some("ops"), secs, &[], None).expect("runs in the folder");
    assert!(String::from_utf8_lossy(&inside.stdout_tail).trim_end().ends_with("/ops"));
    assert_eq!(export.run(&["no-such-program-05".to_string()], None, secs, &[], None).unwrap_err().code(), "COMMAND_NOT_STARTED");
    assert_eq!(export.run(&argv("true"), Some("../up"), secs, &[], None).unwrap_err().code(), "CHECK_DIR_OUTSIDE");
    assert_eq!(export.run(&argv("true"), Some("gone"), secs, &[], None).unwrap_err().code(), "CHECK_DIR_MISSING");
    assert_eq!(export.run(&argv("true"), None, secs, &[("1BAD".into(), "x".into())], None).unwrap_err().code(), "BAD_ENV");
}

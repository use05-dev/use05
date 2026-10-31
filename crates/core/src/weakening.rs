//! Weakened tests: a change that makes its own checks easier to pass. Carried over from 05's
//! predecessor project (its test-weakening analysis and file classes). Line-based and deterministic: it reads the
//! change's diff, never runs or judges anything, and says plainly what it saw.

use std::path::Path;

use crate::error::Result;
use crate::git::{self, Change};
use crate::glob;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Tests,
    Verification,
    Configuration,
    Other,
}

const TESTS: &[&str] = &[
    "**/*.test.*", "**/*.spec.*", "**/__tests__/**", "**/__snapshots__/**", "*.snap", "test/**", "tests/**", "**/test/**", "**/tests/**", "**/*_test.go",
    "**/test_*.py", "**/*_test.py", "**/*Test.java", "**/*Tests.cs",
];
const VERIFICATION: &[&str] = &[".05/**", ".github/workflows/**", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/**"];
const CONFIGURATION: &[&str] = &["*.json", "*.yml", "*.yaml", "*.toml", "*.ini", "*.cfg", "*.conf", "*.env", "*.properties", "*.xml", "*.lock", ".*rc"];
const SNAPSHOTS: &[&str] = &["**/__snapshots__/**", "*.snap"];

pub fn classify(path: &str) -> Class {
    let any = |patterns: &[&str]| patterns.iter().any(|p| glob::matches(p, path));
    if any(VERIFICATION) {
        Class::Verification
    } else if any(TESTS) {
        Class::Tests
    } else if any(CONFIGURATION) {
        Class::Configuration
    } else {
        Class::Other
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weakening {
    pub kind: &'static str,
    pub path: String,
    pub message: String,
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `needle` occurs in `line` with no word character just before it (and, if `end`, just after).
fn occurs(line: &str, needle: &str, end: bool) -> bool {
    line.match_indices(needle).any(|(i, _)| {
        let before = line[..i].chars().next_back().is_none_or(|c| !is_word(c));
        let after = line[i + needle.len()..].chars().next().is_none_or(|c| !is_word(c));
        before && (!end || after)
    })
}

/// An assertion, as the predecessor's assertion pattern recognises one.
pub fn has_assertion(line: &str) -> bool {
    let words = line.split(|c: char| !is_word(c)).filter(|w| !w.is_empty());
    let prefixed = ["assert", "toBe", "toMatch", "toThrow", "toHaveBeenCalled", "XCTAssert"];
    let exact = ["should", "toEqual", "toContain", "toStrictEqual"];
    for w in words {
        if prefixed.iter().any(|p| w.starts_with(p)) || exact.contains(&w) {
            return true;
        }
    }
    if ["require.", "t.Error", "t.Fatal", "t.Equal", "self.assert"].iter().any(|n| occurs(line, n, false)) {
        return true;
    }
    line.match_indices("expect").any(|(i, _)| {
        let before = line[..i].chars().next_back().is_none_or(|c| !is_word(c));
        before && line[i + "expect".len()..].trim_start().starts_with('(')
    })
}

/// A test newly skipped or disabled, as the predecessor's skip pattern recognises one.
pub fn has_skip(line: &str) -> bool {
    if line.match_indices(".skip").any(|(i, _)| line[i + ".skip".len()..].chars().next().is_none_or(|c| !is_word(c))) {
        return true;
    }
    let calls = ["xit", "xdescribe", "xtest", "pending"];
    if calls.iter().any(|c| line.match_indices(c).any(|(i, _)| line[..i].chars().next_back().is_none_or(|p| !is_word(p)) && line[i + c.len()..].trim_start().starts_with('('))) {
        return true;
    }
    ["it.todo", "test.todo", "describe.todo", "@Ignore"].iter().any(|n| occurs(line, n, true))
        || ["@pytest.mark.skip", "@unittest.skip", "t.Skip", "#[ignore]", "@Disabled"].iter().any(|n| line.contains(n))
}

const THRESHOLD_WORDS: &[&str] = &["threshold", "fail_under", "fail-under", "min_coverage", "minimum_coverage", "min-coverage", "minimum-coverage", "coverage"];

/// The threshold word that occurs first in the line, lower-cased.
fn threshold_key(line: &str) -> Option<&'static str> {
    let lower = line.to_lowercase();
    THRESHOLD_WORDS.iter().filter_map(|w| lower.find(w).map(|i| (i, *w))).min_by_key(|(i, w)| (*i, std::cmp::Reverse(w.len()))).map(|(_, w)| w)
}

/// The first plain number on the line. A version (`1.2.0`, `^1.2`, `~3`) is not a threshold, so a
/// line whose first number is one has none.
fn first_number(line: &str) -> Option<f64> {
    let mut rest = line;
    let mut offset = 0;
    while let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
        let digits: String = rest[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        let before = line[..offset + start].chars().next_back();
        let version = digits.matches('.').count() >= 2 || matches!(before, Some('^' | '~' | 'v' | '@'));
        if !version {
            if let Ok(n) = digits.trim_end_matches('.').parse() {
                return Some(n);
            }
        }
        offset += start + digits.len().max(1);
        rest = &line[offset..];
    }
    None
}

/// The line where a test module starts: a `#[cfg(test)]` (or `cfg(all(test, ..))`, `cfg(any(test, ..))`)
/// attribute on a `mod`. A test-only `use` or function does not make what follows a test.
fn rust_test_start(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        let is_test_cfg = t.starts_with("#[cfg(") && (t.contains("(test") || t.contains(" test,") || t.contains(" test)"));
        if !is_test_cfg {
            continue;
        }
        let next = lines[i + 1..].iter().map(|n| n.trim_start()).find(|n| !n.is_empty() && !n.starts_with("#["));
        if next.is_some_and(|n| (n.starts_with("mod ") || n.starts_with("pub mod ")) && n.trim_end().ends_with('{')) {
            return Some(i + 1);
        }
    }
    None
}

fn disables_a_check(line: &str) -> bool {
    let squeezed: String = line.split_whitespace().collect::<Vec<_>>().join(" ");
    let compact = squeezed.replace(": ", ":");
    compact.contains("continue-on-error:true") || compact.contains("allow_failure:true") || compact.contains("if:false") || squeezed.contains("|| true") && occurs(&squeezed, "true", true)
}

/// Everything the change does to weaken its own checks.
pub fn analyse(top: &Path, base: Option<&str>, target: &str, changes: &[Change]) -> Result<Vec<Weakening>> {
    let mut out = Vec::new();
    // Assertions removed and added across the whole change: tests moved between files (say from
    // a source file's test module into tests/) are not weaker.
    let mut tally = (0usize, 0usize);
    // A test file moved elsewhere was not deleted.
    let moved = if changes.iter().any(|c| c.status == 'D') { git::renamed_from(top, base, target) } else { Vec::new() };
    // Git is asked once for every Rust file's contents and once for the whole diff, never per
    // file: a change of thousands of files stays fast.
    let rust: Vec<&Change> = changes.iter().filter(|c| classify(&c.path) == Class::Other && c.path.ends_with(".rs") && c.status != 'D').collect();
    let mut specs = Vec::new();
    for c in &rust {
        specs.push(format!("{target}:{}", c.path));
        if let (Some(b), false) = (base, c.status == 'A') {
            specs.push(format!("{b}:{}", c.path));
        }
    }
    // Only where each file's test module starts is kept, not the file.
    let starts: std::collections::HashMap<String, usize> = specs
        .iter()
        .cloned()
        .zip(git::blobs_with(top, &specs, |b| rust_test_start(&String::from_utf8_lossy(b)))?)
        .filter_map(|(k, v)| v.flatten().map(|v| (k, v)))
        .collect();
    let test_start_at = |rev: Option<&str>, path: &str| rev.and_then(|r| starts.get(&format!("{r}:{path}")).copied());
    let mut wanted: std::collections::HashSet<String> = changes
        .iter()
        .filter(|c| c.status != 'D' && matches!(classify(&c.path), Class::Tests | Class::Configuration | Class::Verification))
        .map(|c| c.path.clone())
        .collect();
    wanted.extend(rust.iter().filter(|c| test_start_at(base, &c.path).is_some() || test_start_at(Some(target), &c.path).is_some()).map(|c| c.path.clone()));
    let all = if wanted.is_empty() { std::collections::HashMap::new() } else { git::hunks_by_path(top, base, target, &wanted)? };
    let hunks = |path: &str| -> Result<git::Hunks> {
        match all.get(path) {
            Some(h) => Ok(h.clone()),
            None => git::diff_hunks(top, base, target, path),
        }
    };
    let lines = |path: &str| -> Result<(Vec<String>, Vec<String>)> {
        let (r, a) = hunks(path)?;
        Ok((r.into_iter().map(|(_, l)| l).collect(), a.into_iter().map(|(_, l)| l).collect()))
    };
    for change in changes {
        let path = change.path.as_str();
        let class = classify(path);
        let w = |kind: &'static str, message: String| Weakening { kind, path: path.to_string(), message };
        if class == Class::Tests {
            if change.status == 'D' && !moved.contains(&change.path) {
                out.push(w("test_deleted", format!("test file {path} was deleted")));
            }
            if SNAPSHOTS.iter().any(|p| glob::matches(p, path)) {
                out.push(w("snapshot_changed", format!("snapshot {path} was {}; expected output was rewritten", if change.status == 'D' { "deleted" } else { "changed" })));
            }
            if change.status != 'D' {
                let (removed, added) = lines(path)?;
                let (r, a) = (removed.iter().filter(|l| has_assertion(l)).count(), added.iter().filter(|l| has_assertion(l)).count());
                tally = (tally.0 + r, tally.1 + a);
                if r > a {
                    out.push(w("test_assertions_removed", format!("{r} assertion(s) removed and {a} added in {path}; the checks became weaker unless replaced")));
                }
                let skips = added.iter().filter(|l| has_skip(l)).count();
                if skips > 0 {
                    out.push(w("test_skip_added", format!("{skips} test(s) newly skipped or disabled in {path}")));
                }
            }
        }
        // Rust keeps unit tests in the source file, in a `#[cfg(test)]` module: judge only the lines
        // from that point down, on each side of the change.
        if class == Class::Other && path.ends_with(".rs") && change.status != 'D' {
            let (from, to) = (if change.status == 'A' { None } else { test_start_at(base, path) }, test_start_at(Some(target), path));
            if from.is_some() || to.is_some() {
                let (removed, added) = hunks(path)?;
                let in_tests = |line: usize, start: Option<usize>| start.is_some_and(|s| line >= s);
                let r = removed.iter().filter(|(n, l)| in_tests(*n, from) && has_assertion(l)).count();
                let a = added.iter().filter(|(n, l)| in_tests(*n, to) && has_assertion(l)).count();
                tally = (tally.0 + r, tally.1 + a);
                if r > a {
                    out.push(w("test_assertions_removed", format!("{r} assertion(s) removed and {a} added in the tests of {path}; the checks became weaker unless replaced")));
                }
                let skips = added.iter().filter(|(n, l)| in_tests(*n, to) && has_skip(l)).count();
                if skips > 0 {
                    out.push(w("test_skip_added", format!("{skips} test(s) newly skipped or disabled in {path}")));
                }
            }
        }
        if matches!(class, Class::Configuration | Class::Verification) && change.status != 'D' {
            let (removed, added) = lines(path)?;
            let lowered = removed.iter().any(|r| {
                let (Some(key), Some(from)) = (threshold_key(r), first_number(r)) else { return false };
                match added.iter().find(|a| threshold_key(a) == Some(key)).and_then(|a| first_number(a)) {
                    Some(to) => to < from,
                    None => true,
                }
            });
            if lowered {
                out.push(w("coverage_threshold_lowered", format!("a coverage threshold in {path} was lowered or removed")));
            }
            let disabled = added.iter().filter(|l| disables_a_check(l)).count();
            if disabled > 0 {
                out.push(w("check_disabled", format!("{disabled} line(s) in {path} let a failing check pass")));
            }
        }
    }
    if tally.1 >= tally.0 {
        out.retain(|w| w.kind != "test_assertions_removed");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct Repo(tempfile::TempDir);

    impl Repo {
        fn new() -> Repo {
            let r = Repo(tempfile::tempdir().unwrap());
            r.git(&["init", "-q"]);
            r
        }
        fn git(&self, args: &[&str]) -> String {
            let out = Command::new("git").arg("-C").arg(self.0.path()).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        fn write(&self, name: &str, body: &str) {
            let p = self.0.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        fn commit(&self) -> String {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", "c"]);
            self.git(&["rev-parse", "HEAD^{tree}"])
        }
        fn kinds(&self, base: &str, target: &str) -> Vec<(&'static str, String)> {
            let changes = git::changed(self.0.path(), Some(base), target).unwrap();
            analyse(self.0.path(), Some(base), target, &changes).unwrap().into_iter().map(|w| (w.kind, w.path)).collect()
        }
    }

    const TEST_V1: &str = "import { test } from 'node:test';\ntest('a', () => {\n  assert.equal(add(1, 1), 2);\n  assert.equal(add(0, 0), 0);\n});\n";

    #[test]
    fn removed_assertions_are_found_and_one_for_one_replacement_is_not() {
        let r = Repo::new();
        r.write("src/add.test.ts", TEST_V1);
        let base = r.commit();
        r.write("src/add.test.ts", "import { test } from 'node:test';\ntest('a', () => {\n  assert.equal(add(1, 1), 2);\n});\n");
        let weaker = r.commit();
        assert_eq!(r.kinds(&base, &weaker), [("test_assertions_removed", "src/add.test.ts".to_string())]);
        r.write("src/add.test.ts", "import { test } from 'node:test';\ntest('a', () => {\n  assert.equal(add(1, 1), 2);\n  expect(add(0, 0)).toBe(0);\n});\n");
        let replaced = r.commit();
        assert!(r.kinds(&weaker, &replaced).is_empty());
    }

    #[test]
    fn new_skips_deleted_test_files_and_changed_snapshots_are_found() {
        let r = Repo::new();
        r.write("src/a.test.ts", TEST_V1);
        r.write("tests/old_test.py", "def test_x():\n    assert 1 == 1\n");
        r.write("src/__snapshots__/a.snap", "exports[`a`] = `1`;\n");
        let base = r.commit();
        r.write("src/a.test.ts", &TEST_V1.replace("test('a'", "test.skip('a'"));
        std::fs::remove_file(r.0.path().join("tests/old_test.py")).unwrap();
        r.write("src/__snapshots__/a.snap", "exports[`a`] = `2`;\n");
        let target = r.commit();
        let mut found = r.kinds(&base, &target);
        found.sort();
        assert_eq!(
            found,
            [
                ("snapshot_changed", "src/__snapshots__/a.snap".to_string()),
                ("test_deleted", "tests/old_test.py".to_string()),
                ("test_skip_added", "src/a.test.ts".to_string()),
            ]
        );
    }

    #[test]
    fn lowering_or_removing_a_coverage_threshold_is_found_and_raising_it_is_not() {
        let r = Repo::new();
        r.write("jest.config.json", "{\n  \"coverageThreshold\": 80\n}\n");
        let base = r.commit();
        r.write("jest.config.json", "{\n  \"coverageThreshold\": 60\n}\n");
        let lowered = r.commit();
        assert_eq!(r.kinds(&base, &lowered), [("coverage_threshold_lowered", "jest.config.json".to_string())]);
        r.write("jest.config.json", "{\n  \"coverageThreshold\": 90\n}\n");
        let raised = r.commit();
        assert!(r.kinds(&lowered, &raised).is_empty());
        r.write("jest.config.json", "{\n}\n");
        let removed = r.commit();
        assert_eq!(r.kinds(&raised, &removed), [("coverage_threshold_lowered", "jest.config.json".to_string())]);
    }

    #[test]
    fn removing_a_dependency_whose_name_mentions_coverage_is_not_a_lowered_threshold() {
        let r = Repo::new();
        r.write("package.json", "{\n  \"devDependencies\": {\n    \"jest-coverage-reporter\": \"^1.2\",\n    \"@vitest/coverage-v8\": \"~2\"\n  }\n}\n");
        let base = r.commit();
        r.write("package.json", "{\n  \"devDependencies\": {\n  }\n}\n");
        let target = r.commit();
        assert!(r.kinds(&base, &target).is_empty(), "{:?}", r.kinds(&base, &target));
    }

    #[test]
    fn disabling_a_check_in_ci_configuration_is_found() {
        let r = Repo::new();
        r.write(".github/workflows/ci.yml", "jobs:\n  test:\n    steps:\n      - run: npm test\n");
        let base = r.commit();
        r.write(".github/workflows/ci.yml", "jobs:\n  test:\n    steps:\n      - run: npm test || true\n        continue-on-error: true\n");
        let target = r.commit();
        assert_eq!(r.kinds(&base, &target), [("check_disabled", ".github/workflows/ci.yml".to_string())]);
    }

    #[test]
    fn moving_a_test_file_is_not_deleting_it() {
        let r = Repo::new();
        r.write("tests/old_test.py", "def test_x():\n    assert 1 == 1\n");
        let base = r.commit();
        std::fs::create_dir_all(r.0.path().join("tests/unit")).unwrap();
        r.git(&["mv", "tests/old_test.py", "tests/unit/old_test.py"]);
        let target = r.commit();
        assert!(r.kinds(&base, &target).is_empty(), "{:?}", r.kinds(&base, &target));
    }

    const RUST_V1: &str = "pub fn f() -> u8 {\n    assert!(true);\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn a() {\n        assert_eq!(super::f(), 1);\n        assert_eq!(1 + 1, 2);\n    }\n}\n";

    #[test]
    fn weakening_tests_inside_a_rust_source_file_is_found_and_production_asserts_are_not_tests() {
        let r = Repo::new();
        r.write("src/lib.rs", RUST_V1);
        let base = r.commit();
        r.write("src/lib.rs", &RUST_V1.replace("        assert_eq!(1 + 1, 2);\n", "").replace("    #[test]\n", "    #[test]\n    #[ignore]\n"));
        let weaker = r.commit();
        let mut found = r.kinds(&base, &weaker);
        found.sort();
        assert_eq!(found, [("test_assertions_removed", "src/lib.rs".to_string()), ("test_skip_added", "src/lib.rs".to_string())]);
        r.write("src/lib.rs", RUST_V1);
        let restored = r.commit();
        r.write("src/lib.rs", &RUST_V1.replace("    assert!(true);\n", ""));
        let prod_only = r.commit();
        assert!(r.kinds(&restored, &prod_only).is_empty(), "an assert in production code is not a test: {:?}", r.kinds(&restored, &prod_only));
    }

    #[test]
    fn only_a_cfg_test_module_starts_the_tests_and_its_variants_count() {
        let r = Repo::new();
        let src = "#[cfg(test)]\nuse std::fmt;\n\npub fn f(x: u8) -> u8 {\n    assert!(x > 0);\n    x\n}\n";
        r.write("src/lib.rs", src);
        let base = r.commit();
        r.write("src/lib.rs", &src.replace("    assert!(x > 0);\n", ""));
        let target = r.commit();
        assert!(r.kinds(&base, &target).is_empty(), "a test-only import does not make production code a test: {:?}", r.kinds(&base, &target));
        let feat = RUST_V1.replace("#[cfg(test)]", "#[cfg(all(test, feature = \"x\"))]");
        r.write("src/lib.rs", &feat);
        let base = r.commit();
        r.write("src/lib.rs", &feat.replace("        assert_eq!(1 + 1, 2);\n", ""));
        let target = r.commit();
        assert_eq!(r.kinds(&base, &target), [("test_assertions_removed", "src/lib.rs".to_string())]);
    }

    #[test]
    fn moving_rust_unit_tests_into_tests_is_not_weakening() {
        let r = Repo::new();
        r.write("src/lib.rs", RUST_V1);
        let base = r.commit();
        r.write("src/lib.rs", &RUST_V1.replace("        assert_eq!(1 + 1, 2);\n", ""));
        r.write("tests/moved.rs", "#[test]\nfn b() {\n    assert_eq!(1 + 1, 2);\n}\n");
        let target = r.commit();
        assert!(r.kinds(&base, &target).is_empty(), "{:?}", r.kinds(&base, &target));
    }

    #[test]
    fn a_threshold_after_a_version_on_the_same_line_is_still_found() {
        let r = Repo::new();
        r.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npx vitest@v1 run --coverage.thresholds.lines=80\n");
        let base = r.commit();
        r.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npx vitest@v1 run\n");
        let target = r.commit();
        assert_eq!(r.kinds(&base, &target), [("coverage_threshold_lowered", ".github/workflows/ci.yml".to_string())]);
    }

    #[test]
    fn content_lines_that_start_with_dashes_keep_their_numbers() {
        let r = Repo::new();
        r.write("q.sql", "a\n-- note\nb\nc\n");
        let base = r.commit();
        r.write("q.sql", "a\nb\n");
        let target = r.commit();
        let (removed, _) = git::diff_hunks(r.0.path(), Some(&base), &target, "q.sql").unwrap();
        assert_eq!(removed, [(2, "-- note".to_string()), (4, "c".to_string())]);
    }

    #[test]
    fn adding_a_new_test_file_is_not_weakening() {
        let r = Repo::new();
        r.write("src/lib.rs", "pub fn f() {}\n");
        let base = r.commit();
        r.write("tests/new.rs", "#[test]\nfn t() { assert_eq!(1, 1); }\n");
        let target = r.commit();
        assert!(r.kinds(&base, &target).is_empty());
    }

    #[test]
    fn assertion_and_skip_tokens_are_matched_as_words() {
        for yes in ["assert x", "  assertEquals(a, b)", "assert_eq!(a, b);", "expect (x).toBe(1)", "self.assertTrue(x)", "XCTAssertEqual(a, b)", "t.Errorf(\"x\")", "require.NoError(t, err)"] {
            assert!(has_assertion(yes), "{yes}");
        }
        for no in ["reassert", "let expected = 1;", "// nothing here"] {
            assert!(!has_assertion(no), "{no}");
        }
        for yes in ["it.skip('x')", "xit('x', () => {})", "@pytest.mark.skip", "#[ignore]", "t.Skip(\"later\")", "@Disabled"] {
            assert!(has_skip(yes), "{yes}");
        }
        for no in ["skipper()", "let skipped = 0;", "unpending(x)"] {
            assert!(!has_skip(no), "{no}");
        }
        assert_eq!(classify("src/a.test.ts"), Class::Tests);
        assert_eq!(classify(".github/workflows/ci.yml"), Class::Verification);
        assert_eq!(classify("jest.config.json"), Class::Configuration);
        assert_eq!(classify("src/lib.rs"), Class::Other);
    }
}

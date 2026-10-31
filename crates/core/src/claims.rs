//! Claims: what the author said they did. An assertion until evidence supports it.
//!
//! Extraction is plain keyword matching on purpose: a deterministic rule can be read, tested and
//! argued with; a model's judgement cannot.

use serde::Serialize;
use use05_receipt::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Tests,
    Lint,
    Types,
    Build,
}

impl Category {
    pub fn word(self) -> &'static str {
        match self {
            Category::Tests => "tests",
            Category::Lint => "lint",
            Category::Types => "type check",
            Category::Build => "build",
        }
    }

    /// Words that, in a check's name or command, mean it covers this category.
    fn check_words(self) -> &'static [&'static str] {
        match self {
            Category::Tests => &["test", "pytest", "jest", "spec", "unit"],
            Category::Lint => &["lint", "clippy", "eslint", "ruff", "flake8"],
            Category::Types => &["typecheck", "type-check", "tsc", "mypy", "pyright", "types"],
            Category::Build => &["build", "compile"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    pub text: String,
    pub category: Category,
}

const NEGATIONS: &[&str] = &[" not ", "n't", "fail", "broken", "skip", "todo", "unable", "without running", "didn't", "never"];
const GOOD: &[&str] = &["pass", "green", "succe", "ok", "clean", "works", "compiles", "no error", "no warning", "all good"];

pub fn extract(outcome: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    for sentence in outcome.split(['.', ';', '\n', '!', '?']) {
        let text = sentence.trim();
        if text.is_empty() {
            continue;
        }
        let lower = format!(" {} ", text.to_lowercase());
        if NEGATIONS.iter().any(|n| lower.contains(n)) || !GOOD.iter().any(|g| lower.contains(g)) {
            continue;
        }
        let mut add = |category: Category, words: &[&str]| {
            if words.iter().any(|w| lower.contains(w)) {
                claims.push(Claim { text: text.to_string(), category });
            }
        };
        add(Category::Tests, &["test", "spec"]);
        add(Category::Lint, &["lint", "clippy", "eslint"]);
        add(Category::Types, &["type check", "typecheck", "type-check", "tsc", "mypy", "types"]);
        add(Category::Build, &["build", "compile"]);
    }
    claims
}

/// What the evidence on this exact tree says about one claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Judged {
    /// A passing check of this kind ran on this tree.
    Supported { by: String },
    /// No check of this kind ran on this tree.
    Unsupported,
    /// A check of this kind ran on this tree and did not pass.
    Contradicted { by: String },
}

pub struct Observed<'a> {
    pub name: &'a str,
    pub argv: &'a [String],
    pub status: Status,
}

pub fn judge(claim: &Claim, observed: &[Observed<'_>]) -> Judged {
    let covers = |o: &Observed<'_>| {
        let haystack = format!("{} {}", o.name, o.argv.join(" ")).to_lowercase();
        claim.category.check_words().iter().any(|w| haystack.contains(w))
    };
    let relevant: Vec<&Observed<'_>> = observed.iter().filter(|o| covers(o)).collect();
    if let Some(bad) = relevant.iter().find(|o| o.status != Status::Passed) {
        return Judged::Contradicted { by: bad.name.to_string() };
    }
    match relevant.first() {
        Some(good) => Judged::Supported { by: good.name.to_string() },
        None => Judged::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(c: &[Claim]) -> Vec<(&str, Category)> {
        c.iter().map(|c| (c.text.as_str(), c.category)).collect()
    }

    #[test]
    fn claims_are_found_by_rule() {
        let claims = extract("Capped retries at three. All tests pass and lint is clean; the build succeeds.");
        assert_eq!(
            texts(&claims),
            [
                ("All tests pass and lint is clean", Category::Tests),
                ("All tests pass and lint is clean", Category::Lint),
                ("the build succeeds", Category::Build),
            ]
        );
    }

    #[test]
    fn negations_and_non_claims_are_ignored() {
        assert!(extract("I did not run the tests. The tests are failing. Skipped lint.").is_empty());
        assert!(extract("Refactored the payment module").is_empty());
        assert!(extract("").is_empty());
    }

    #[test]
    fn a_claim_needs_matching_evidence_on_the_tree() {
        let claim = Claim { text: "tests pass".into(), category: Category::Tests };
        let argv = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let (cargo, lint) = (argv(&["cargo", "test"]), argv(&["cargo", "clippy"]));
        assert_eq!(judge(&claim, &[]), Judged::Unsupported);
        assert_eq!(judge(&claim, &[Observed { name: "lint", argv: &lint, status: Status::Passed }]), Judged::Unsupported, "lint is not tests");
        assert_eq!(judge(&claim, &[Observed { name: "test", argv: &cargo, status: Status::Passed }]), Judged::Supported { by: "test".into() });
        assert_eq!(judge(&claim, &[Observed { name: "test", argv: &cargo, status: Status::Failed }]), Judged::Contradicted { by: "test".into() });
        assert_eq!(judge(&claim, &[Observed { name: "test", argv: &cargo, status: Status::TimedOut }]), Judged::Contradicted { by: "test".into() });
    }
}

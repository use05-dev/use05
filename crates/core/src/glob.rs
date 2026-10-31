//! Path patterns: `*` matches within one segment, `**` matches any number of segments,
//! `?` matches one character. Patterns and paths use `/`. A pattern with no `/` matches
//! a file name at any depth, like `.gitignore`.

pub fn matches(pattern: &str, path: &str) -> bool {
    let path = path.trim_start_matches("./");
    let pattern = pattern.trim_start_matches("./");
    if !pattern.contains('/') {
        return path.split('/').any(|segment| segment_matches(pattern, segment))
            && (pattern != "**");
    }
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let parts: Vec<&str> = path.split('/').collect();
    // A pattern naming a directory covers everything under it.
    let dir_pattern = pattern.ends_with('/');
    walk(&pat, &parts, dir_pattern)
}

fn walk(pat: &[&str], parts: &[&str], dir_pattern: bool) -> bool {
    match (pat.first(), parts.first()) {
        (None, None) => true,
        (None, Some(_)) => dir_pattern,
        (Some(&"**"), _) => {
            // `**` may swallow zero or more segments.
            (0..=parts.len()).any(|skip| walk(&pat[1..], &parts[skip..], dir_pattern))
        }
        (Some(_), None) => false,
        (Some(p), Some(s)) => segment_matches(p, s) && walk(&pat[1..], &parts[1..], dir_pattern),
    }
}

fn segment_matches(pattern: &str, segment: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pattern.chars().collect(), segment.chars().collect());
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => (0..=s.len()).any(|i| go(&p[1..], &s[i..])),
            Some('?') => !s.is_empty() && go(&p[1..], &s[1..]),
            Some(c) => s.first() == Some(c) && go(&p[1..], &s[1..]),
        }
    }
    go(&p, &s)
}

/// The literal directory prefix before the first wildcard, for overlap tests.
fn literal_prefix(pattern: &str) -> &str {
    let cut = pattern.find(['*', '?']).unwrap_or(pattern.len());
    &pattern[..cut]
}

/// Could a declared scope reach something the other pattern names? Deliberately quiet: a bare
/// file name (like `Cargo.lock`) only overlaps a pattern whose final segment can match it, so a
/// directory wildcard such as `src/**` does not count as touching every manifest name.
pub fn overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim_start_matches("./"), b.trim_start_matches("./"));
    let final_segment = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    match (a.contains('/'), b.contains('/')) {
        (false, false) => segment_matches(a, b) || segment_matches(b, a),
        (true, true) => {
            let (pa, pb) = (literal_prefix(a), literal_prefix(b));
            pa.starts_with(pb) || pb.starts_with(pa)
        }
        (a_has_slash, _) => {
            let (bare, path) = if a_has_slash { (b, a) } else { (a, b) };
            let tail = final_segment(path);
            tail != "**" && (segment_matches(bare, &tail) || segment_matches(&tail, bare))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        assert!(matches("src/**", "src/a/b.rs"));
        assert!(matches("src/**", "src/a.rs"));
        assert!(!matches("src/**", "other/src/a.rs"));
        assert!(matches("src/*.rs", "src/a.rs"));
        assert!(!matches("src/*.rs", "src/a/b.rs"));
        assert!(matches("**/*.lock", "a/b/Cargo.lock"));
        assert!(matches("**/*.lock", "Cargo.lock"));
        assert!(matches("Cargo.lock", "Cargo.lock"));
        assert!(matches("Cargo.lock", "crates/x/Cargo.lock"), "bare names match at any depth");
        assert!(matches(".05/**", ".05/policy.toml"));
        assert!(matches("migrations/", "migrations/001.sql"), "a trailing slash covers the directory");
        assert!(matches("a?c.txt", "abc.txt"));
        assert!(!matches("a?c.txt", "ac.txt"));
        assert!(matches("./src/**", "src/x"));
    }

    #[test]
    fn overlap() {
        assert!(overlaps("src/payments/**", "src/**"));
        assert!(overlaps("src/**", "src/payments/ledger/**"));
        assert!(!overlaps("src/payments/**", "docs/**"));
        assert!(overlaps("migrations/**", "migrations/2026/**"));
        assert!(overlaps("Cargo.lock", "crates/x/Cargo.lock"));
        assert!(!overlaps("Cargo.lock", "src/**"));
    }
}

//! Who may set up a fresh console. Until it has a passkey, whoever signs up first becomes its
//! admin, and a new public address is found within minutes. So the first sign-up must show a
//! claim code: one the console makes for itself and writes to its log (which only whoever runs
//! it can read), or the SETUP_SECRET setting when one is set. `use05 cloud login` takes the code
//! at a terminal and gets back a one-time link to sign up with, so nobody types it in a browser.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::{hash, same_secret, token};

/// How long a claim link stays good.
const LINK_LIFE: Duration = Duration::from_secs(15 * 60);

pub struct Claims {
    code: String,
    /// Made by the console (written to its log) rather than set by whoever runs it.
    pub made_here: bool,
    links: Mutex<Vec<(String, Instant)>>,
}

impl Claims {
    /// The SETUP_SECRET setting, or a code made now.
    pub fn new(setting: Option<String>) -> Claims {
        match setting {
            Some(code) => Claims { code, made_here: false, links: Mutex::default() },
            None => Claims { code: new_code(), made_here: true, links: Mutex::default() },
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    /// The code, as typed at a terminal: a one-time link token for the browser to sign up with.
    pub fn claim(&self, typed: &str) -> Option<String> {
        if !same_secret(&normal(&self.code), &normal(typed)) {
            return None;
        }
        let link = token();
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links.retain(|(_, at)| at.elapsed() < LINK_LIFE);
        links.push((hash(&link), Instant::now()));
        Some(link)
    }

    /// What a first sign-up showed: the code itself, or a claim link that has not run out.
    pub fn accepts(&self, given: &str) -> bool {
        let given = given.trim();
        if given.is_empty() {
            return false;
        }
        if same_secret(&normal(&self.code), &normal(given)) {
            return true;
        }
        let h = hash(given);
        self.links.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|(l, at)| at.elapsed() < LINK_LIFE && same_secret(l, &h))
    }
}

/// Ten letters and digits (50 bits), in two groups, without ones easily misread.
fn new_code() -> String {
    const LETTERS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let pick: Vec<char> = (0..10).map(|_| LETTERS[rand::random::<usize>() % LETTERS.len()] as char).collect();
    format!("{}-{}", pick[..5].iter().collect::<String>(), pick[5..].iter().collect::<String>())
}

/// Typed loosely: case, spaces and dashes do not matter.
fn normal(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_made_here_claims_once_typed_and_gives_a_link_that_signs_up() {
        let c = Claims::new(None);
        assert!(c.made_here);
        assert!(regex_like(c.code()), "{}", c.code());
        assert!(c.claim("WRONG-CODES").is_none());
        let link = c.claim(&c.code().to_lowercase().replace('-', " ")).expect("typed loosely");
        assert!(c.accepts(&link), "the link signs up");
        assert!(c.accepts(c.code()), "so does the code itself, typed in the browser");
        assert!(!c.accepts("") && !c.accepts("someone-elses-link"));
        assert_ne!(Claims::new(None).code(), c.code());
    }

    #[test]
    fn the_setting_is_the_code_when_set() {
        let c = Claims::new(Some("correct horse".into()));
        assert!(!c.made_here);
        assert!(c.accepts("correct horse") && c.claim("correct horse").is_some());
    }

    fn regex_like(code: &str) -> bool {
        code.len() == 11 && code.as_bytes()[5] == b'-' && code.chars().filter(|c| *c != '-').all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }
}

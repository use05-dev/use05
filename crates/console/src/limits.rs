//! How often one address may try to sign in or pair, and one poll per machine at a time. Kept in
//! memory: one console, one process.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use uuid::Uuid;

use crate::util::Fail;

#[derive(Default)]
pub struct Limiter {
    windows: Mutex<HashMap<(String, &'static str), (u64, u32)>>,
    polls: Arc<Mutex<HashSet<Uuid>>>,
}

/// The address a request came from, as the proxy in front of the console saw it. A client can
/// put anything in `x-forwarded-for`, but the proxy appends the real address last.
pub fn client(headers: &HeaderMap) -> String {
    headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.rsplit(',').next()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| "direct".into())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// An open poll; dropping it lets the machine poll again.
pub struct Polling {
    id: Uuid,
    polls: Arc<Mutex<HashSet<Uuid>>>,
}

impl Drop for Polling {
    fn drop(&mut self) {
        self.polls.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.id);
    }
}

impl Limiter {
    pub fn allow_at(&self, who: &str, what: &'static str, max: u32, window_secs: u64, now: u64) -> bool {
        let mut w = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        if w.len() > 10_000 {
            w.retain(|_, (start, _)| now < *start + 3600);
        }
        let entry = w.entry((who.to_string(), what)).or_insert((now, 0));
        if now >= entry.0 + window_secs {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }

    /// Refuse when this address has tried `what` more than `max` times in `window_secs`.
    pub fn check(&self, headers: &HeaderMap, what: &'static str, max: u32, window_secs: u64) -> Result<(), Fail> {
        if self.allow_at(&client(headers), what, max, window_secs, now()) {
            Ok(())
        } else {
            Err(crate::util::too_many("too many attempts from here; wait a few minutes"))
        }
    }

    pub fn polling(&self, id: Uuid) -> Option<Polling> {
        let mut p = self.polls.lock().unwrap_or_else(|p| p.into_inner());
        p.insert(id).then(|| Polling { id, polls: self.polls.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn a_window_allows_so_many_then_refuses_until_it_passes() {
        let l = Limiter::default();
        for _ in 0..3 {
            assert!(l.allow_at("1.2.3.4", "auth", 3, 60, 1000));
        }
        assert!(!l.allow_at("1.2.3.4", "auth", 3, 60, 1001));
        assert!(l.allow_at("5.6.7.8", "auth", 3, 60, 1001), "another address has its own count");
        assert!(l.allow_at("1.2.3.4", "pair", 3, 60, 1001), "another purpose has its own count");
        assert!(l.allow_at("1.2.3.4", "auth", 3, 60, 1061), "a new window");
    }

    #[test]
    fn the_address_is_the_one_the_proxy_saw() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 10.0.0.1, 203.0.113.9".parse().unwrap());
        assert_eq!(client(&h), "203.0.113.9", "the last hop is added by the proxy; earlier ones can be made up");
        assert_eq!(client(&HeaderMap::new()), "direct");
    }

    #[test]
    fn one_poll_per_machine() {
        let l = Limiter::default();
        let id = uuid::Uuid::new_v4();
        let first = l.polling(id).expect("first poll");
        assert!(l.polling(id).is_none(), "a second poll while the first is open");
        drop(first);
        assert!(l.polling(id).is_some(), "after the first one ends");
    }
}

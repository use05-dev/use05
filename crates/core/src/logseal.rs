//! How strongly an agent's action log can be trusted (D70): is it anchored by seals, sealed by
//! CI, and does every sealed line still match? Read from this machine's copy and from the copy
//! that travels on the receipts branch.

use std::path::Path;

use serde::Serialize;

use crate::evidence::Found;
use crate::log::{self, Chain};
use crate::policy::Role;
use crate::store;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LogIntegrity {
    /// Lines in the log as it stands.
    pub lines: u64,
    /// Seals by this machine or a person, made while the work happened.
    pub hook_seals: usize,
    pub last_hook_seal: Option<u64>,
    /// The line up to which the CI runner sealed it.
    pub ci_sealed_at: Option<u64>,
    /// The first sealed line that no longer matches its chain or a seal.
    pub altered_at: Option<u64>,
    /// Where the chain breaks after the last seal: not proof of tampering, but not provable either.
    pub tail_broken_at: Option<u64>,
    /// A copy is on the receipts branch, so it can be checked without this machine.
    pub travels: bool,
}

/// The log of `task` as this machine has it, else as a trusted signer's receipts branch has it.
pub fn copy(top: &Path, state_dir: Option<&Path>, found: &Found, task: &str) -> Option<String> {
    let local = state_dir.and_then(|d| std::fs::read_to_string(log::path_for(d, task)).ok()).filter(|t| !t.is_empty());
    local.or_else(|| branch_copy(top, found, task))
}

/// The copy on the branch of a key whose seal on this log verified; never an unsigned branch.
fn branch_copy(top: &Path, found: &Found, task: &str) -> Option<String> {
    let signers: Vec<String> = found.log_seals.iter().filter(|s| s.statement.predicate.task == task && s.signer.role != Role::Runner).map(|s| s.signer.key_id.clone()).collect();
    if signers.is_empty() {
        return None;
    }
    store::read_file_from(top, &format!("logs/{task}.jsonl"), Some(&signers)).filter(|t| !t.is_empty())
}

/// The last line, within `lines`, sealed by a trusted signer where the work happened: CI never
/// countersigns past it.
pub fn last_trusted_seal(found: &Found, task: &str, lines: u64) -> Option<u64> {
    found.log_seals.iter().filter(|s| s.statement.predicate.task == task && s.signer.role != Role::Runner).map(|s| s.statement.predicate.seq).filter(|&s| s <= lines).max()
}

pub fn check(top: &Path, state_dir: Option<&Path>, found: &Found, task: &str) -> Option<LogIntegrity> {
    let text = copy(top, state_dir, found, task)?;
    let branch = branch_copy(top, found, task);
    let seals: Vec<_> = found.log_seals.iter().filter(|s| s.statement.predicate.task == task).collect();
    // A break in the chain is tampering only where a seal covers it; past the last seal it is an
    // unsealed tail (for example two hooks that wrote at once), reported as such.
    let sealed_to = seals.iter().map(|s| s.statement.predicate.seq).max().unwrap_or(0);
    let mut tail_broken_at = None;
    let mut altered: Option<u64> = match log::verify_text(&text) {
        Chain::Broken(line) if (line as u64) <= sealed_to => Some(line as u64),
        Chain::Broken(line) => {
            tail_broken_at = Some(line as u64);
            None
        }
        Chain::Intact(_) => None,
    };
    let first = |line: u64, altered: &mut Option<u64>| *altered = Some(altered.map_or(line, |a| a.min(line)));
    for seal in &seals {
        let p = &seal.statement.predicate;
        // The copy as it stands must still carry every sealed line, unchanged.
        if log::hash_at(&text, p.seq).as_deref() != Some(p.head.as_str()) {
            first(p.seq, &mut altered);
        }
        // The copy on the branch, if it reaches that far, must agree too.
        if let Some(b) = &branch {
            if let Some(h) = log::hash_at(b, p.seq) {
                if h != p.head {
                    first(p.seq, &mut altered);
                }
            }
        }
    }
    let by_hooks: Vec<u64> = seals.iter().filter(|s| s.signer.role != Role::Runner).map(|s| s.statement.predicate.seq).collect();
    Some(LogIntegrity {
        lines: text.lines().count() as u64,
        hook_seals: by_hooks.len(),
        last_hook_seal: by_hooks.iter().max().copied(),
        ci_sealed_at: seals.iter().filter(|s| s.signer.role == Role::Runner).map(|s| s.statement.predicate.seq).max(),
        altered_at: altered,
        tail_broken_at,
        travels: branch.is_some(),
    })
}

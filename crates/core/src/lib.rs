//! 05's engine. It decides things; the CLI renders them.
//!
//! Nothing here prints. Every failure is an [`Error`] with a stable code.
#![deny(unsafe_code)]

pub mod asked;
pub mod branches;
pub mod brief;
pub mod claims;
pub mod discard;
pub mod error;
pub mod evidence;
pub mod fresh;
pub mod gate;
pub mod git;
pub mod glob;
pub mod inbox;
pub mod intent;
pub mod keys;
pub mod log;
pub mod logseal;
pub mod org;
pub mod overlap;
pub mod policy;
pub mod repos;
pub mod risk;
pub mod session;
pub mod setup;
pub mod store;
pub mod task;
pub mod time;
pub mod tty;
pub mod weakening;

pub use error::{Error, Result};

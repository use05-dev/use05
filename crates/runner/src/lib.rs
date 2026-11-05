//! Runs a check on an exact git tree and builds the evidence statement.
//!
//! The tree is read straight from git objects (no checkout filters, no `.gitattributes`
//! conversions), written to a scratch directory, and the command runs there with a scrubbed
//! environment. The statement records what happened; signing is done by `use05-receipt`.
#![deny(unsafe_code)]

mod error;
mod exec;
mod git;
mod prove;
mod time;
mod tree;

pub use error::RunnerError;
pub use prove::{Export, Proof, ProveOptions, Ran, TreeIdentity, identify, prove, prove_with_output};

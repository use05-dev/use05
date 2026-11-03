//! Policy edits from a browser (D86): what may change (`guard`) and how a change is applied while
//! keeping the file's comments (`edit`). The same code runs in the web app as WebAssembly, in the
//! helper that prepares the commit, and nowhere it could be skipped.
pub mod edit;
pub mod guard;

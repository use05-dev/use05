pub mod approve;
pub mod brief;
pub mod ci_env;
pub mod deploy;
pub mod destination;
pub mod discard;
pub mod doctor;
pub mod gate;
pub mod hook;
pub mod hotfix;
pub mod init;
pub mod land;
pub mod policy;
pub mod promote;
pub mod prove;
pub mod setup;
pub mod signoff;
pub mod start;
pub mod status;
pub mod verify;

/// After a receipt is stored: push its branch if the person asked, and say what happened. A failed
/// push never fails the command: the receipt is stored either way.
pub fn push_note(top: &std::path::Path, branch: &str, push: bool) -> Option<String> {
    if !push {
        return None;
    }
    Some(match use05_core::store::push(top, branch) {
        Ok(remote) => format!("Pushed {branch} to {remote}, so others (and CI) can see it."),
        Err(e) => format!("{} The receipt is stored here; push it yourself: git push origin {branch}", e.message),
    })
}

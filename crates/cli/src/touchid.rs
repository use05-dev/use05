//! The Touch ID approver key (D91): a P-256 key made inside the Mac's Secure Enclave. Signing
//! with it needs the person: Touch ID, an Apple Watch, or the Mac's login password in the
//! system's own dialog, enforced by the Secure Enclave rather than by 05. Its signatures are
//! passkey signatures, so the gate, CI and `use05 verify` check them as they check a phone's.
//!
//! Only macOS builds made with a Swift compiler have it (see build.rs); everywhere else
//! [`supported`] is false and the passphrase key is used.

/// Why the Secure Enclave did not sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// No Secure Enclave, or this build of 05 has no Touch ID.
    Unavailable,
    /// The person said no.
    Cancelled,
    /// The key does not open on this Mac (it was made on another one, or reset).
    NotThisMac,
    /// No login session to show the dialog in (over SSH, say).
    NoSession,
    Failed(String),
}

impl Failure {
    pub fn message(&self) -> String {
        match self {
            Failure::Unavailable => "Touch ID is not available here".into(),
            Failure::Cancelled => "cancelled; nothing was signed".into(),
            Failure::NotThisMac => "the Touch ID key does not open on this Mac".into(),
            Failure::NoSession => "there is no login session to ask you in (over SSH, say)".into(),
            Failure::Failed(m) => format!("Touch ID failed: {m}"),
        }
    }
}

#[cfg(use05_touch_id)]
#[allow(unsafe_code)]
mod se {
    use std::ffi::CString;

    unsafe extern "C" {
        fn use05_se_available() -> i32;
        fn use05_se_biometry() -> i32;
        fn use05_se_create(blob: *mut u8, blob_cap: usize, blob_len: *mut usize, public: *mut u8, err: *mut u8, err_cap: usize) -> i32;
        fn use05_se_sign(blob: *const u8, blob_len: usize, msg: *const u8, msg_len: usize, reason: *const std::ffi::c_char, sig: *mut u8, sig_cap: usize, sig_len: *mut usize, err: *mut u8, err_cap: usize) -> i32;
    }

    fn failure(code: i32, err: &[u8]) -> super::Failure {
        let text = String::from_utf8_lossy(err.split(|b| *b == 0).next().unwrap_or_default()).to_string();
        match code {
            1 => super::Failure::Unavailable,
            2 => super::Failure::Cancelled,
            5 => super::Failure::NotThisMac,
            6 => super::Failure::NoSession,
            4 => super::Failure::Failed("a buffer was too small".into()),
            _ => super::Failure::Failed(if text.is_empty() { format!("error {code}") } else { text }),
        }
    }

    pub fn available() -> bool {
        // SAFETY: no arguments; the Swift side only reads system state.
        unsafe { use05_se_available() == 1 }
    }

    pub fn biometry() -> bool {
        // SAFETY: as above.
        unsafe { use05_se_biometry() == 1 }
    }

    pub fn create() -> Result<(Vec<u8>, [u8; 65]), super::Failure> {
        let mut blob = vec![0u8; 4096];
        let mut len = 0usize;
        let mut public = [0u8; 65];
        let mut err = [0u8; 512];
        // SAFETY: every pointer is to a live buffer of the length passed with it; the Swift side
        // writes at most that many bytes and sets `len` to what it wrote.
        let code = unsafe { use05_se_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr(), err.as_mut_ptr(), err.len()) };
        if code != 0 {
            return Err(failure(code, &err));
        }
        blob.truncate(len.min(blob.len()));
        Ok((blob, public))
    }

    pub fn sign(blob: &[u8], message: &[u8], reason: &str) -> Result<Vec<u8>, super::Failure> {
        let reason = CString::new(reason.replace('\0', " ")).expect("no NUL left");
        let mut sig = vec![0u8; 128];
        let mut len = 0usize;
        let mut err = [0u8; 512];
        // SAFETY: as in `create`; `blob`, `message` and `reason` are only read.
        let code = unsafe { use05_se_sign(blob.as_ptr(), blob.len(), message.as_ptr(), message.len(), reason.as_ptr(), sig.as_mut_ptr(), sig.len(), &mut len, err.as_mut_ptr(), err.len()) };
        if code != 0 {
            return Err(failure(code, &err));
        }
        sig.truncate(len.min(sig.len()));
        Ok(sig)
    }
}

#[cfg(not(use05_touch_id))]
mod se {
    pub fn available() -> bool {
        false
    }
    pub fn biometry() -> bool {
        false
    }
    pub fn create() -> Result<(Vec<u8>, [u8; 65]), super::Failure> {
        Err(super::Failure::Unavailable)
    }
    pub fn sign(_: &[u8], _: &[u8], _: &str) -> Result<Vec<u8>, super::Failure> {
        Err(super::Failure::Unavailable)
    }
}

/// Can this machine make and use a Touch ID approver key? `USE05_NO_TOUCH_ID` says no, for tests
/// and for people who prefer the passphrase.
pub fn supported() -> bool {
    std::env::var_os("USE05_NO_TOUCH_ID").is_none() && se::available()
}

/// What the person will be asked for: "Touch ID", or the Mac's password where there is no sensor.
pub fn method() -> &'static str {
    if se::biometry() { "Touch ID" } else { "your Mac's password (no Touch ID here)" }
}

/// Make the key and keep it: the blob in `approver-touchid.key`, the public key beside it.
pub fn create() -> Result<use05_receipt::PasskeyKey, String> {
    let (blob, public) = se::create().map_err(|f| f.message())?;
    let key = use05_receipt::PasskeyKey::from_sec1(use05_receipt::TOUCH_ID_SITE, &public).map_err(|e| e.to_string())?;
    use05_core::keys::save_touch_id(&blob, &key).map_err(|e| e.message)?;
    Ok(key)
}

/// Sign a person's statement with the Touch ID key, co-signed by this machine's key, as an
/// envelope the gate counts as a passkey approval. `reason` is shown in the system's dialog.
pub fn seal(body: &[u8], reason: &str) -> Result<use05_receipt::Envelope, Failure> {
    use base64::Engine;
    use use05_receipt::{Envelope, PAYLOAD_TYPE, TOUCH_ID_SITE, cosignature, local_assertion, passkey_entry};
    let key = use05_core::keys::touch_id_public().ok_or(Failure::Unavailable)?;
    let blob = use05_core::keys::touch_id_blob().ok_or(Failure::NotThisMac)?;
    let (machine, _) = use05_core::keys::ensure_local().map_err(|e| Failure::Failed(e.message))?;
    let assertion = local_assertion(TOUCH_ID_SITE, PAYLOAD_TYPE, body);
    let der = se::sign(&blob, &assertion.message, reason)?;
    Ok(Envelope {
        payload: base64::engine::general_purpose::STANDARD.encode(body),
        payload_type: PAYLOAD_TYPE.to_string(),
        signatures: vec![passkey_entry(&key, &assertion, &der), cosignature(PAYLOAD_TYPE, body, &machine)],
    })
}

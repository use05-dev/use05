//! Keys and who holds them.
//!
//! * `local`: a plain key file in the user's config directory. Any process running as the user
//!   can use it, so what it signs is advisory.
//! * `approver`: a person's key, encrypted with a passphrase (scrypt + XChaCha20-Poly1305).
//!   Signing an approval or a bypass needs that passphrase, which an agent does not have.
//! * `runner`: a key given to CI through a secret. It is never written here.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use use05_receipt::{SigningKey, VerifyingKey, parse_public_key, parse_secret_key, public_key_text, secret_key_text};

use crate::error::{Error, Result};

const ENC_PREFIX: &str = "use05-ed25519-secret-enc:v1:";
const SALT: usize = 16;
const NONCE: usize = 24;

/// Where 05 keeps per-user state: `$USE05_HOME`, else `$XDG_CONFIG_HOME/05`, else `~/.config/05`.
pub fn user_dir() -> Result<PathBuf> {
    let dir = if let Some(home) = std::env::var_os("USE05_HOME") {
        PathBuf::from(home)
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("05")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("05")
    } else {
        return Err(Error::new("NO_USER_DIR", "cannot find a place for 05's keys: HOME is not set"));
    };
    Ok(dir)
}

fn random(buf: &mut [u8]) -> Result<()> {
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).map_err(|e| Error::io("reading system randomness", e))
}

fn write_private(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::io("creating the key directory", e))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| Error::io(&format!("writing {}", path.display()), e))
}

fn new_key() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    random(&mut seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

// ----------------------------------------------------------------------------- encryption

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(15, 8, 1, 32).expect("valid scrypt parameters");
    let mut out = [0u8; 32];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut out).map_err(|_| Error::new("KEY_DERIVE_FAILED", "could not derive a key from the passphrase"))?;
    Ok(out)
}

pub fn encrypt_secret(key: &SigningKey, passphrase: &str) -> Result<String> {
    let (mut salt, mut nonce) = ([0u8; SALT], [0u8; NONCE]);
    random(&mut salt)?;
    random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(&derive(passphrase, &salt)?.into());
    let sealed = cipher.encrypt(&nonce.into(), key.to_bytes().as_slice()).map_err(|_| Error::new("KEY_ENCRYPT_FAILED", "could not encrypt the key"))?;
    let mut blob = [salt.as_slice(), nonce.as_slice(), sealed.as_slice()].concat();
    let text = format!("{ENC_PREFIX}{}\n", STANDARD.encode(&blob));
    blob.fill(0);
    Ok(text)
}

/// Decrypt a protected key file's text. A wrong passphrase and a damaged file are told apart
/// only as far as is safe: both say the key could not be opened.
pub fn decrypt_secret(text: &str, passphrase: &str) -> Result<SigningKey> {
    let body = text.trim().strip_prefix(ENC_PREFIX).ok_or_else(|| Error::new("KEY_UNUSABLE", "this is not a protected key file"))?;
    let blob = STANDARD.decode(body.trim()).map_err(|_| Error::new("KEY_UNUSABLE", "the key file is damaged"))?;
    if blob.len() < SALT + NONCE + 16 {
        return Err(Error::new("KEY_UNUSABLE", "the key file is damaged"));
    }
    let (salt, rest) = blob.split_at(SALT);
    let (nonce, sealed) = rest.split_at(NONCE);
    let cipher = XChaCha20Poly1305::new(&derive(passphrase, salt)?.into());
    let plain = cipher
        .decrypt(nonce.into(), sealed)
        .map_err(|_| Error::new("KEY_PASSPHRASE_WRONG", "that passphrase does not open the approver key"))?;
    let seed: [u8; 32] = plain.try_into().map_err(|_| Error::new("KEY_UNUSABLE", "the key file is damaged"))?;
    Ok(SigningKey::from_bytes(&seed))
}

// ----------------------------------------------------------------------------- key files

/// Read a secret key from a file the person named. A key other users can read is refused: it is
/// not a secret any more.
pub fn read_secret_file(path: &std::path::Path) -> Result<SigningKey> {
    let meta = fs::metadata(path).map_err(|e| Error::new("KEY_UNUSABLE", format!("cannot read {}: {e}", path.display())))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::new("KEY_TOO_OPEN", format!("the secret key {} can be read by other users", path.display())).with_next(format!("chmod 600 {}", path.display())));
    }
    let text = fs::read_to_string(path).map_err(|e| Error::new("KEY_UNUSABLE", format!("cannot read {}: {e}", path.display())))?;
    parse_secret_key(&text).map_err(|e| Error::new("KEY_UNUSABLE", format!("{}: {e}", path.display())))
}

// ----------------------------------------------------------------------------- local key

pub fn local_paths() -> Result<(PathBuf, PathBuf)> {
    let dir = user_dir()?;
    Ok((dir.join("local.key"), dir.join("local.pub")))
}

/// The machine's advisory key, created on first use.
pub fn ensure_local() -> Result<(SigningKey, bool)> {
    let (secret, public) = local_paths()?;
    if let Ok(text) = fs::read_to_string(&secret) {
        return Ok((parse_secret_key(&text).map_err(|e| Error::new("KEY_UNUSABLE", format!("{}: {e}", secret.display())))?, false));
    }
    let key = new_key()?;
    write_private(&secret, &secret_key_text(&key))?;
    let _ = fs::remove_file(&public);
    fs::write(&public, public_key_text(&key.verifying_key())).map_err(|e| Error::io("writing the public key", e))?;
    Ok((key, true))
}

pub fn local_public() -> Option<VerifyingKey> {
    let (_, public) = local_paths().ok()?;
    parse_public_key(&fs::read_to_string(public).ok()?).ok()
}

// ----------------------------------------------------------------------------- approver key

pub fn approver_paths() -> Result<(PathBuf, PathBuf)> {
    let dir = user_dir()?;
    Ok((dir.join("approver.key"), dir.join("approver.pub")))
}

pub fn approver_exists() -> bool {
    approver_paths().is_ok_and(|(secret, _)| secret.exists())
}

/// Is the approver key protected by a passphrase?
pub fn approver_protected() -> bool {
    approver_paths().ok().and_then(|(s, _)| fs::read_to_string(s).ok()).is_some_and(|t| t.starts_with(ENC_PREFIX))
}

/// Create the approver key. An empty passphrase stores it unencrypted, which the caller must
/// tell the person: anyone who can read the file can then approve.
pub fn create_approver(passphrase: &str) -> Result<VerifyingKey> {
    let (secret, public) = approver_paths()?;
    if secret.exists() {
        return Err(Error::new("KEY_EXISTS", format!("{} already exists; refusing to overwrite it", secret.display())));
    }
    let key = new_key()?;
    let text = if passphrase.is_empty() { secret_key_text(&key) } else { encrypt_secret(&key, passphrase)? };
    write_private(&secret, &text)?;
    fs::write(&public, public_key_text(&key.verifying_key())).map_err(|e| Error::io("writing the public key", e))?;
    Ok(key.verifying_key())
}

pub fn load_approver(passphrase: &str) -> Result<SigningKey> {
    let (secret, _) = approver_paths()?;
    let text = fs::read_to_string(&secret).map_err(|_| {
        Error::new("NO_APPROVER_KEY", "there is no approver key on this machine").with_next("create one: use05 key new --approver")
    })?;
    if text.starts_with(ENC_PREFIX) {
        decrypt_secret(&text, passphrase)
    } else {
        parse_secret_key(&text).map_err(|e| Error::new("KEY_UNUSABLE", e.to_string()))
    }
}

pub fn approver_public() -> Option<VerifyingKey> {
    let (_, public) = approver_paths().ok()?;
    parse_public_key(&fs::read_to_string(public).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protected_key_opens_only_with_its_passphrase() {
        let key = new_key().unwrap();
        let text = encrypt_secret(&key, "correct horse").unwrap();
        assert!(text.starts_with(ENC_PREFIX));
        assert!(!text.contains(&secret_key_text(&key)[22..40]), "the seed must not appear in the file");
        assert_eq!(decrypt_secret(&text, "correct horse").unwrap().to_bytes(), key.to_bytes());
        assert_eq!(decrypt_secret(&text, "wrong").unwrap_err().code, "KEY_PASSPHRASE_WRONG");
        assert_eq!(decrypt_secret(&text, "").unwrap_err().code, "KEY_PASSPHRASE_WRONG");
        // Each encryption is different (fresh salt and nonce) but both open.
        let other = encrypt_secret(&key, "correct horse").unwrap();
        assert_ne!(text, other);
    }

    #[test]
    fn damaged_files_are_refused_not_panicked_on() {
        let key = new_key().unwrap();
        let text = encrypt_secret(&key, "pw").unwrap();
        let cut = &text[..text.len() / 2];
        assert!(decrypt_secret(cut, "pw").is_err());
        assert!(decrypt_secret("use05-ed25519-secret-enc:v1:!!!", "pw").is_err());
        assert!(decrypt_secret("hello", "pw").is_err());
        let mut tampered = text.trim().as_bytes().to_vec();
        let last = tampered.len() - 4;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_secret(&String::from_utf8(tampered).unwrap(), "pw").is_err(), "a flipped byte must fail authentication");
    }
}

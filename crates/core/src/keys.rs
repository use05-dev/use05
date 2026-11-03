//! Keys and who holds them.
//!
//! * `local`: a plain key file in the user's config directory. Any process running as the user
//!   can use it, so what it signs is advisory.
//! * `approver`: a person's key, encrypted with a passphrase (scrypt + XChaCha20-Poly1305).
//!   Signing an approval or a bypass needs that passphrase, which an agent does not have.
//! * `runner`: a key given to CI through a secret. It is never written here.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use use05_receipt::{PasskeyKey, PublicKey, SigningKey, VerifyingKey, parse_any_public_key, parse_public_key, parse_secret_key, public_key_text, secret_key_text};

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
        #[cfg(unix)]
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
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
    #[cfg(not(unix))]
    let _ = &meta;
    #[cfg(unix)]
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

/// Does this person have an approver key here: the passphrase one, or the Touch ID one?
pub fn approver_exists() -> bool {
    passphrase_approver_exists() || touch_id_public().is_some()
}

/// The passphrase-protected (or unprotected) Ed25519 approver key file.
pub fn passphrase_approver_exists() -> bool {
    approver_paths().is_ok_and(|(secret, _)| secret.exists())
}

// ----------------------------------------------------------------------------- Touch ID key

const SE_PREFIX: &str = "use05-secure-enclave-p256:v1:";

/// The Touch ID approver key (D91): `approver-touchid.key` holds an opaque blob that only this
/// Mac's Secure Enclave can use, `approver-touchid.pub` its public key, in passkey form.
pub fn touch_id_paths() -> Result<(PathBuf, PathBuf)> {
    let dir = user_dir()?;
    Ok((dir.join("approver-touchid.key"), dir.join("approver-touchid.pub")))
}

pub fn touch_id_public() -> Option<PasskeyKey> {
    let (secret, public) = touch_id_paths().ok()?;
    if !secret.exists() {
        return None;
    }
    match parse_any_public_key(fs::read_to_string(public).ok()?.trim()) {
        Ok(PublicKey::Passkey(p)) => Some(p),
        _ => None,
    }
}

/// The Secure Enclave's blob for the Touch ID key. It is not a secret anywhere but on this Mac.
pub fn touch_id_blob() -> Option<Vec<u8>> {
    let (secret, _) = touch_id_paths().ok()?;
    let text = fs::read_to_string(secret).ok()?;
    STANDARD.decode(text.trim().strip_prefix(SE_PREFIX)?).ok()
}

pub fn save_touch_id(blob: &[u8], public: &PasskeyKey) -> Result<()> {
    let (secret, public_path) = touch_id_paths()?;
    if secret.exists() {
        return Err(Error::new("KEY_EXISTS", format!("{} already exists; refusing to overwrite it", secret.display())));
    }
    write_private(&secret, &format!("{SE_PREFIX}{}\n", STANDARD.encode(blob)))?;
    fs::write(&public_path, use05_receipt::passkey_public_text(public)).map_err(|e| Error::io("writing the public key", e))
}

/// Every approver key this person has here, as the ids the gate compares owners with.
pub fn approver_ids() -> Vec<String> {
    let mut ids: Vec<String> = touch_id_public().map(|p| PublicKey::Passkey(p).id()).into_iter().collect();
    ids.extend(approver_public().map(|k| use05_receipt::key_id(&k)));
    ids
}

/// The key that names this person as the owner of work started here: Touch ID if they have it.
pub fn owner_key_id() -> Option<String> {
    approver_ids().into_iter().next()
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

// ----------------------------------------------------------------------------- passkeys

/// Passkeys this person pinned on this machine as approvers, one per line:
/// `<public key text> <name>`. They count for this machine's gate like `approver.pub` does.
pub fn passkeys_path() -> Result<PathBuf> {
    Ok(user_dir()?.join("passkeys.pub"))
}

/// Every readable passkey line, with its name. Comments, blank lines and anything unreadable
/// are skipped: a damaged line must never stop a hook or the gate.
pub fn parse_pinned_passkeys(text: &str) -> Vec<(String, PasskeyKey)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let (key, name) = line.split_once(char::is_whitespace).map_or((line, ""), |(k, n)| (k, n.trim()));
            match parse_any_public_key(key) {
                Ok(PublicKey::Passkey(p)) => Some((if name.is_empty() { "passkey".to_string() } else { name.to_string() }, p)),
                _ => None,
            }
        })
        .collect()
}

/// The passkeys pinned here, and how many lines were not a passkey (so doctor can say so).
#[derive(Debug, Default)]
pub struct Pinned {
    pub keys: Vec<(String, PasskeyKey)>,
    pub skipped: usize,
}

/// Read a passkeys file, whatever bytes it holds: a line that is not text is one bad line, not a
/// reason to drop the good ones.
pub fn read_pinned_passkeys(bytes: &[u8]) -> Pinned {
    let text = String::from_utf8_lossy(bytes);
    let keys = parse_pinned_passkeys(&text);
    let lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).count();
    Pinned { skipped: lines - keys.len(), keys }
}

pub fn pinned_passkeys_file() -> Pinned {
    passkeys_path().ok().and_then(|p| fs::read(p).ok()).map(|b| read_pinned_passkeys(&b)).unwrap_or_default()
}

pub fn pinned_passkeys() -> Vec<(String, PasskeyKey)> {
    pinned_passkeys_file().keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_passkeys_skip_comments_blank_and_bad_lines() {
        let a = use05_receipt::PasskeyKey::from_sec1("localhost", &p256_point(1)).unwrap();
        let b = use05_receipt::PasskeyKey::from_sec1("console.example", &p256_point(2)).unwrap();
        let text = format!(
            "# my passkeys\n\n{} iPhone 15\nnot a key at all\n{} YubiKey\n",
            use05_receipt::passkey_public_text(&a).trim(),
            use05_receipt::passkey_public_text(&b).trim()
        );
        let got = parse_pinned_passkeys(&text);
        assert_eq!(got, vec![("iPhone 15".to_string(), a), ("YubiKey".to_string(), b)]);
    }

    #[test]
    fn a_damaged_passkeys_file_keeps_its_good_lines_and_counts_the_rest() {
        let a = use05_receipt::PasskeyKey::from_sec1("localhost", &p256_point(1)).unwrap();
        let mut bytes = format!("{} iPhone\n", use05_receipt::passkey_public_text(&a).trim()).into_bytes();
        bytes.extend_from_slice(b"\xff\xfe not text\nnot a key either\n# a comment\n");
        let pinned = read_pinned_passkeys(&bytes);
        assert_eq!(pinned.keys, vec![("iPhone".to_string(), a)]);
        assert_eq!(pinned.skipped, 2);
    }

    fn p256_point(seed: u8) -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

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

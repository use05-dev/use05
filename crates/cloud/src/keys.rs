//! This machine's own keys for the console (D86): X25519 to open what the team sends it, Ed25519
//! to sign what it reports. Made at pairing, kept in 05's per-user folder, readable by you only.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use use05_receipt::SigningKey;

pub struct MachineKeys {
    pub x_secret: [u8; 32],
    pub x_public: [u8; 32],
    pub ed: SigningKey,
}

fn path(name: &str) -> Result<PathBuf> {
    Ok(crate::home()?.join(name))
}

fn read_or_make(name: &str) -> Result<[u8; 32]> {
    let p = path(name)?;
    if let Ok(text) = fs::read_to_string(&p) {
        let bytes = hex::decode(text.trim()).context("a damaged key file")?;
        return bytes.try_into().map_err(|_| anyhow!("{} is not a 32-byte key", p.display()));
    }
    let secret: [u8; 32] = rand::random();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    fs::create_dir_all(p.parent().expect("a folder"))?;
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
    f.write_all(hex::encode(secret).as_bytes())?;
    Ok(secret)
}

pub fn load() -> Result<MachineKeys> {
    let x_secret = read_or_make("cloud-x25519.key")?;
    let ed = SigningKey::from_bytes(&read_or_make("cloud-ed25519.key")?);
    Ok(MachineKeys { x_public: cloud::seal::public_of(&x_secret), x_secret, ed })
}

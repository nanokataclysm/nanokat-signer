//! Ed25519 provenance signing compatible with `nkscripts/signer.py` and
//! `nkscripts/ingestor.py` in the NANOKAT monorepo.
//!
//! Contract (do not change without updating the ingestor):
//! - keys: raw 32-byte files `artisan.priv` / `artisan.pub` in the key dir
//! - payload: `"{asset_name}|{sha256_hex}|{signed_at}"`
//! - sidecar `<file>.nanokat`: JSON with asset_name, merkle_root (the sha256),
//!   signature (hex), public_key (hex), signed_at, version.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SIDECAR_SUFFIX: &str = ".nanokat";
pub const VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sidecar {
    pub asset_name: String,
    /// Named for the ingestor's schema; this is the plain SHA-256 of the file.
    pub merkle_root: String,
    pub signature: String,
    pub public_key: String,
    pub signed_at: String,
    pub version: String,
}

impl Sidecar {
    pub fn payload(&self) -> Vec<u8> {
        payload(&self.asset_name, &self.merkle_root, &self.signed_at)
    }

    /// Verify the signature over the recorded fields. Does not touch the asset file.
    pub fn verify_signature(&self) -> Result<()> {
        let pk_bytes: [u8; 32] = hex::decode(&self.public_key)
            .context("public_key is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public_key is not 32 bytes"))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .context("signature is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
        let key = VerifyingKey::from_bytes(&pk_bytes).context("invalid public key")?;
        key.verify(&self.payload(), &Signature::from_bytes(&sig_bytes))
            .context("signature does not match payload")
    }
}

pub fn payload(asset_name: &str, file_hash: &str, signed_at: &str) -> Vec<u8> {
    format!("{asset_name}|{file_hash}|{signed_at}").into_bytes()
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Matches Python's `datetime.utcnow().isoformat() + "Z"` (microsecond precision).
pub fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

pub fn default_key_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("NANOKAT_KEY_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".nanokat").join("keys"))
}

pub struct KeyPair {
    pub signing: SigningKey,
    pub public_hex: String,
}

/// Load the artisan keypair, generating one if absent (same behaviour as signer.py).
pub fn load_or_create_keys(key_dir: &Path) -> Result<KeyPair> {
    let priv_path = key_dir.join("artisan.priv");
    let pub_path = key_dir.join("artisan.pub");

    if !priv_path.exists() {
        ensure_private_dir(key_dir)?;
        eprintln!("[PROVENANCE] Generating new Ed25519 artisan keypair...");
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        write_private(&priv_path, signing.as_bytes())?;
        fs::write(&pub_path, signing.verifying_key().as_bytes())
            .with_context(|| format!("write {}", pub_path.display()))?;
        eprintln!("[PROVENANCE] Keys generated at {}", key_dir.display());
    }

    let priv_bytes =
        fs::read(&priv_path).with_context(|| format!("read {}", priv_path.display()))?;
    let seed: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not a raw 32-byte Ed25519 key", priv_path.display()))?;
    let signing = SigningKey::from_bytes(&seed);

    // signer.py reads the stored .pub verbatim; check it agrees with the private key.
    let derived = signing.verifying_key();
    let public_hex = match fs::read(&pub_path) {
        Ok(stored) if stored.as_slice() == derived.as_bytes() => hex::encode(stored),
        Ok(_) => bail!(
            "{} does not match {}",
            pub_path.display(),
            priv_path.display()
        ),
        Err(_) => {
            fs::write(&pub_path, derived.as_bytes())?;
            hex::encode(derived.as_bytes())
        }
    };
    Ok(KeyPair {
        signing,
        public_hex,
    })
}

pub fn sign_asset(file: &Path, keys: &KeyPair, signed_at: Option<String>) -> Result<Sidecar> {
    let asset_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .context("asset path has no valid file name")?
        .to_string();
    let merkle_root = hash_file(file)?;
    let signed_at = signed_at.unwrap_or_else(now_iso);
    let signature = keys
        .signing
        .sign(&payload(&asset_name, &merkle_root, &signed_at));
    Ok(Sidecar {
        asset_name,
        merkle_root,
        signature: hex::encode(signature.to_bytes()),
        public_key: keys.public_hex.clone(),
        signed_at,
        version: VERSION.to_string(),
    })
}

pub fn sidecar_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(SIDECAR_SUFFIX);
    PathBuf::from(s)
}

pub fn write_sidecar(file: &Path, sidecar: &Sidecar) -> Result<PathBuf> {
    let path = sidecar_path(file);
    let json = serde_json::to_string_pretty(sidecar)?;
    fs::write(&path, format!("{json}\n")).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn read_sidecar(path: &Path) -> Result<Sidecar> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// Full verification: signature over the recorded fields, plus the asset's
/// current hash and name match the sidecar when the asset is present.
pub fn verify_asset(sidecar: &Sidecar, asset: Option<&Path>) -> Result<()> {
    sidecar.verify_signature()?;
    if let Some(asset) = asset {
        let hash = hash_file(asset)?;
        if hash != sidecar.merkle_root {
            bail!(
                "asset hash {hash} does not match sidecar merkle_root {}",
                sidecar.merkle_root
            );
        }
        let name = asset.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name != sidecar.asset_name {
            bail!(
                "asset name {name:?} does not match sidecar asset_name {:?}",
                sidecar.asset_name
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keys() -> (tempfile::TempDir, KeyPair) {
        let dir = tempfile::tempdir().unwrap();
        let keys = load_or_create_keys(dir.path()).unwrap();
        (dir, keys)
    }

    #[test]
    fn payload_matches_python_format() {
        assert_eq!(
            payload("a.html", "abc", "2026-01-01T00:00:00.000000Z"),
            b"a.html|abc|2026-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn hash_file_is_sha256_hex() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.txt");
        fs::write(&f, b"hello").unwrap();
        assert_eq!(
            hash_file(&f).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn keys_are_raw_32_bytes_and_reloadable() {
        let (dir, keys) = temp_keys();
        let priv_bytes = fs::read(dir.path().join("artisan.priv")).unwrap();
        let pub_bytes = fs::read(dir.path().join("artisan.pub")).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
        assert_eq!(hex::encode(&pub_bytes), keys.public_hex);
        let again = load_or_create_keys(dir.path()).unwrap();
        assert_eq!(again.public_hex, keys.public_hex);
        assert_eq!(again.signing.to_bytes(), keys.signing.to_bytes());
    }

    #[test]
    fn sign_is_deterministic_with_fixed_timestamp_and_verifies() {
        let (_kd, keys) = temp_keys();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("asset.bin");
        fs::write(&f, b"payload").unwrap();
        let ts = Some("2026-09-18T00:00:00.000000Z".to_string());
        let a = sign_asset(&f, &keys, ts.clone()).unwrap();
        let b = sign_asset(&f, &keys, ts).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.version, "1.0");
        verify_asset(&a, Some(&f)).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_fields_and_files() {
        let (_kd, keys) = temp_keys();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("asset.bin");
        fs::write(&f, b"payload").unwrap();
        let sc = sign_asset(&f, &keys, None).unwrap();

        let mut bad = sc.clone();
        bad.signed_at = "2000-01-01T00:00:00Z".into();
        assert!(bad.verify_signature().is_err());

        fs::write(&f, b"changed").unwrap();
        assert!(sc.verify_signature().is_ok());
        assert!(verify_asset(&sc, Some(&f)).is_err());
    }

    #[test]
    fn sidecar_roundtrip_and_path() {
        let (_kd, keys) = temp_keys();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("index.html");
        fs::write(&f, b"<html>").unwrap();
        let sc = sign_asset(&f, &keys, None).unwrap();
        let p = write_sidecar(&f, &sc).unwrap();
        assert_eq!(p, dir.path().join("index.html.nanokat"));
        assert_eq!(read_sidecar(&p).unwrap(), sc);
    }
}

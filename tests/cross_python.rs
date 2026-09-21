//! Cross-implementation tests against the Python signer / ingestor contract.
//! Skipped (pass with a note) when python3+cryptography or signer.py is absent.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nanokat-signer"))
}

fn python_signer() -> Option<PathBuf> {
    let p = std::env::var_os("NANOKAT_PY_SIGNER")?;
    let path = PathBuf::from(p);
    path.is_file().then_some(path)
}

fn python_has_cryptography() -> bool {
    Command::new("python3")
        .args(["-c", "import cryptography"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Exactly the ingestor's validate_signature (nkscripts/ingestor.py:14-22).
const INGESTOR_VERIFY: &str = r#"
import json, sys
from cryptography.hazmat.primitives.asymmetric import ed25519
metadata = json.load(open(sys.argv[1]))
pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(metadata['public_key']))
payload = f"{metadata['asset_name']}|{metadata['merkle_root']}|{metadata['signed_at']}".encode()
pub.verify(bytes.fromhex(metadata['signature']), payload)
print("ingestor-ok")
"#;

#[test]
fn rust_sidecar_verifies_with_ingestor_logic() {
    if !python_has_cryptography() {
        eprintln!("skip: python3 cryptography not available");
        return;
    }
    let keys = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let asset = dir.path().join("index.html");
    fs::write(&asset, b"<html>portfolio</html>").unwrap();

    let out = bin()
        .args(["sign"])
        .arg(&asset)
        .env("NANOKAT_KEY_DIR", keys.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sidecar = dir.path().join("index.html.nanokat");
    let py = Command::new("python3")
        .args(["-c", INGESTOR_VERIFY])
        .arg(&sidecar)
        .output()
        .unwrap();
    assert!(
        py.status.success(),
        "{}",
        String::from_utf8_lossy(&py.stderr)
    );
    assert!(String::from_utf8_lossy(&py.stdout).contains("ingestor-ok"));
}

#[test]
fn python_sidecar_verifies_with_rust_and_keys_are_shared() {
    let Some(signer) = python_signer() else {
        eprintln!("skip: signer.py not found (set NANOKAT_PY_SIGNER)");
        return;
    };
    if !python_has_cryptography() {
        eprintln!("skip: python3 cryptography not available");
        return;
    }
    // signer.py keys off $HOME/.nanokat/keys; point HOME at a temp dir.
    let home = tempfile::tempdir().unwrap();
    let key_dir = home.path().join(".nanokat/keys");
    let dir = tempfile::tempdir().unwrap();
    let asset = dir.path().join("asset.txt");
    fs::write(&asset, b"python signed this").unwrap();

    let py = Command::new("python3")
        .arg(&signer)
        .arg(&asset)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(
        py.status.success(),
        "{}",
        String::from_utf8_lossy(&py.stderr)
    );
    let sidecar = dir.path().join("asset.txt.nanokat");
    assert!(sidecar.is_file());

    // 1. Rust verifies the Python-produced sidecar, including re-hashing the asset.
    let v = bin().args(["verify"]).arg(&sidecar).output().unwrap();
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stderr));

    // 2. Rust loads the Python-generated raw key files and reports the same public key.
    let pk = bin()
        .args(["pubkey"])
        .env("NANOKAT_KEY_DIR", &key_dir)
        .output()
        .unwrap();
    assert!(
        pk.status.success(),
        "{}",
        String::from_utf8_lossy(&pk.stderr)
    );
    let sc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&sidecar).unwrap()).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&pk.stdout).trim(),
        sc["public_key"].as_str().unwrap()
    );

    // 3. Same key, same file, same timestamp => byte-identical signature to Python's.
    let ts = sc["signed_at"].as_str().unwrap();
    let r = bin()
        .args(["sign", "--json", "--signed-at", ts])
        .arg(&asset)
        .env("NANOKAT_KEY_DIR", &key_dir)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    let rs: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
    assert_eq!(rs["signature"], sc["signature"]);
    assert_eq!(rs["merkle_root"], sc["merkle_root"]);
    assert_eq!(rs["asset_name"], sc["asset_name"]);
    assert_eq!(rs["version"], sc["version"]);

    // 4. Tampered asset fails full verify but passes --signature-only.
    fs::write(&asset, b"tampered").unwrap();
    assert!(!bin()
        .args(["verify"])
        .arg(&sidecar)
        .status()
        .unwrap()
        .success());
    assert!(bin()
        .args(["verify", "--signature-only"])
        .arg(&sidecar)
        .status()
        .unwrap()
        .success());
}

#[test]
fn cli_reports_missing_file_and_bad_sidecar() {
    let keys = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["sign", "/nonexistent/file"])
        .env("NANOKAT_KEY_DIR", keys.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));

    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("x.nanokat");
    fs::write(&bad, "{}").unwrap();
    assert!(!bin().args(["verify"]).arg(&bad).status().unwrap().success());
}

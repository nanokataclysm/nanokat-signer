# nanokat-signer

Rust port of `nkscripts/signer.py` from the NANOKAT monorepo: Ed25519 provenance
signatures for creative assets, written as `<file>.nanokat` JSON sidecars that
`nkscripts/ingestor.py` verifies and imports.

## Compatibility contract

- Keys: raw 32-byte `artisan.priv` / `artisan.pub` in `~/.nanokat/keys`
  (override with `NANOKAT_KEY_DIR` or `--key-dir`). Existing Python-generated
  keys load unchanged. Missing keys are generated automatically; on Unix, a
  new private key uses mode 0600 and a newly created key directory uses 0700.
- Payload: `"{asset_name}|{sha256_hex}|{signed_at}"`.
- Sidecar fields: `asset_name`, `merkle_root` (the SHA-256, name kept for the
  ingestor schema), `signature`, `public_key`, `signed_at`, `version`.
- Given the same key, file and `--signed-at`, the signature is byte-identical to
  the Python signer's. `tests/cross_python.rs` proves both directions.

## Usage

```sh
nanokat-signer sign path/to/index.html            # writes index.html.nanokat
nanokat-signer sign --signed-at 2026-01-01T00:00:00.000000Z --json file
nanokat-signer verify path/to/index.html          # re-hashes the asset
nanokat-signer verify index.html.nanokat --signature-only
nanokat-signer pubkey
```

`sign` writes the sidecar beside the asset, including when `--json` also prints
it to stdout. Both `sign` and `pubkey` create a keypair if none exists.

Pass the asset path to `verify` when you require its current contents and name
to match the signed record. Passing a `.nanokat` path checks the neighboring
asset if present; if that asset is absent, only the recorded signature is
checked. `--signature-only` explicitly skips the asset check.

Verification uses the public key embedded in the sidecar. Establish the expected
signer's public key independently before treating a valid signature as proof of
that person's identity. Keep private keys outside the repository.

## Build, test, install

Use Rust **1.98.1 or newer**; 1.98.1 is the validated stable toolchain. The
checked-in `Cargo.lock` records the resolved dependency versions. Ed25519 Dalek
3 and SHA-2 0.11 preserve the existing raw key, signature, and sidecar formats.
New keys use fallible operating-system entropy through `getrandom`; the temporary
key-generation seed buffer is cleared on drop with `zeroize`.

```sh
cargo test --locked             # cross tests skip if python3+cryptography or NANOKAT_PY_SIGNER absent
cargo install --locked --path . # -> ~/.cargo/bin/nanokat-signer
```

Cross-implementation tests can optionally verify against a companion Python signer:
set `NANOKAT_PY_SIGNER=/path/to/signer.py` to enable them. Use `cargo test --locked -- --nocapture`
to see skip messages when a dependency is unavailable. With dependencies already cached,
`cargo test --locked --offline` runs without accessing the package registry.
`cargo audit` is an optional separate dependency-audit tool.

Downstream build scripts and portfolio generators prefer `nanokat-signer` (or
`$NANOKAT_SIGNER` on `PATH`) for fast native signing.

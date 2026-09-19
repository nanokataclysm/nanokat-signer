use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nanokat_signer::{
    default_key_dir, load_or_create_keys, read_sidecar, sidecar_path, sign_asset, verify_asset,
    write_sidecar, SIDECAR_SUFFIX,
};

/// NANOKAT Creative Provenance Signer
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Key directory (default: $NANOKAT_KEY_DIR or ~/.nanokat/keys)
    #[arg(long, global = true)]
    key_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign a file and write a <file>.nanokat sidecar
    Sign {
        file: PathBuf,
        /// Override the signed_at timestamp (for reproducible tests)
        #[arg(long)]
        signed_at: Option<String>,
        /// Print the sidecar JSON to stdout instead of the status lines
        #[arg(long)]
        json: bool,
    },
    /// Verify a sidecar (pass either the asset or its .nanokat file)
    Verify {
        path: PathBuf,
        /// Only check the signature; skip re-hashing the asset
        #[arg(long)]
        signature_only: bool,
    },
    /// Print the artisan public key as hex
    Pubkey,
}

fn key_dir(cli: &Cli) -> Result<PathBuf> {
    match &cli.key_dir {
        Some(d) => Ok(d.clone()),
        None => default_key_dir(),
    }
}

fn run(cli: Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Sign {
            file,
            signed_at,
            json,
        } => {
            if !file.is_file() {
                anyhow::bail!("File {} not found.", file.display());
            }
            let keys = load_or_create_keys(&key_dir(&cli)?)?;
            let sidecar = sign_asset(file, &keys, signed_at.clone())?;
            let path = write_sidecar(file, &sidecar)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&sidecar)?);
            } else {
                println!("[PROVENANCE] Asset signed: {}", sidecar.asset_name);
                println!("[PROVENANCE] Sidecar created: {}", path.display());
            }
        }
        Cmd::Verify {
            path,
            signature_only,
        } => {
            let (sidecar_file, asset): (PathBuf, Option<PathBuf>) =
                if path.to_string_lossy().ends_with(SIDECAR_SUFFIX) {
                    let s = path.to_string_lossy();
                    let asset = PathBuf::from(&s[..s.len() - SIDECAR_SUFFIX.len()]);
                    (path.clone(), asset.is_file().then_some(asset))
                } else {
                    (sidecar_path(path), Some(path.clone()))
                };
            let sidecar = read_sidecar(&sidecar_file)?;
            let asset: Option<&Path> = if *signature_only {
                None
            } else {
                asset.as_deref()
            };
            verify_asset(&sidecar, asset)
                .with_context(|| format!("verification failed for {}", sidecar_file.display()))?;
            println!(
                "[PROVENANCE] OK: {} signed {} by {}",
                sidecar.asset_name, sidecar.signed_at, sidecar.public_key
            );
        }
        Cmd::Pubkey => {
            let keys = load_or_create_keys(&key_dir(&cli)?)?;
            println!("{}", keys.public_hex);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

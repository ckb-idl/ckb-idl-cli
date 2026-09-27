use std::{fs, path::PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::{
    binding::{bind_bundle, verify_binding},
    error::CliError,
    hash::{ckb_data_hash, hex_prefixed},
    idl::ValidatedIdl,
    trailer::{TRAILER_PAYLOAD_LEN, parse_bound_code},
};

/// Package and verify exact-byte IDL bindings for CKB executables.
#[derive(Debug, Parser)]
#[command(name = "ckb-idl", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate an exact RFC 8785 canonical IDL artifact.
    Validate(ValidateArgs),
    /// Bind a clean executable to an authoritative canonical IDL artifact.
    Bind(BindArgs),
    /// Verify a bound executable against frozen IDL and an optional manifest.
    Verify(VerifyArgs),
    /// Display Binding Trailer 1 metadata from a bound executable.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Canonical IDL 0.1.0 JSON artifact.
    #[arg(long)]
    idl: PathBuf,
}

#[derive(Debug, Args)]
pub struct BindArgs {
    /// Clean executable with no Binding Trailer 1.
    #[arg(long)]
    executable: PathBuf,
    /// Canonical IDL 0.1.0 JSON artifact.
    #[arg(long)]
    idl: PathBuf,
    /// New destination directory for the completed bundle.
    #[arg(long)]
    out_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Bound executable containing Binding Trailer 1.
    #[arg(long)]
    executable: PathBuf,
    /// Frozen canonical IDL 0.1.0 JSON artifact.
    #[arg(long)]
    idl: PathBuf,
    /// Optional binding manifest to validate against the supplied artifacts.
    #[arg(long)]
    manifest: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Bound executable containing Binding Trailer 1.
    #[arg(long)]
    executable: PathBuf,
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Validate(args) => {
            let idl = ValidatedIdl::from_path(args.idl)?;
            println!(
                "status=valid idl_sha256={} bytes={}",
                hex_prefixed(idl.sha256()),
                idl.bytes().len()
            );
            Ok(())
        }
        Command::Bind(args) => {
            let report = bind_bundle(args.executable, args.idl, args.out_dir)?;
            println!(
                "status=bound executable_file={} idl_file={} manifest_file={} idl_sha256={} bound_code_data_ckb_hash={}",
                report
                    .bundle
                    .executable
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("bundle executable name is UTF-8"),
                report
                    .bundle
                    .idl
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("bundle IDL name is UTF-8"),
                report
                    .bundle
                    .manifest
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("bundle manifest name is UTF-8"),
                hex_prefixed(report.idl_sha256),
                hex_prefixed(report.bound_code_data_ckb_hash),
            );
            Ok(())
        }
        Command::Verify(args) => {
            let report = verify_binding(args.executable, args.idl, args.manifest.as_deref())?;
            println!(
                "status=verified idl_sha256={} clean_executable_bytes={} bound_code_data_bytes={} bound_code_data_ckb_hash={}",
                hex_prefixed(report.idl_sha256),
                report.clean_executable_bytes,
                report.bound_code_data_bytes,
                hex_prefixed(report.bound_code_data_ckb_hash),
            );
            Ok(())
        }
        Command::Inspect(args) => {
            let bound_code_data = fs::read(&args.executable)
                .map_err(|error| CliError::io(&args.executable, error))?;
            let parsed =
                parse_bound_code(&bound_code_data).map_err(|error| CliError::InvalidTrailer {
                    message: error.to_string(),
                })?;
            println!(
                "trailer_version={} flags={} payload_length={} idl_sha256={} clean_executable_bytes={} bound_code_data_ckb_hash={}",
                parsed.trailer.version,
                parsed.trailer.flags,
                TRAILER_PAYLOAD_LEN,
                hex_prefixed(parsed.trailer.idl_sha256),
                parsed.clean_executable.len(),
                hex_prefixed(ckb_data_hash(&bound_code_data)),
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn parses_each_initial_command() {
        for arguments in [
            ["ckb-idl", "validate", "--idl", "artifact.json"].as_slice(),
            [
                "ckb-idl",
                "bind",
                "--executable",
                "clean",
                "--idl",
                "artifact.json",
                "--out-dir",
                "dist",
            ]
            .as_slice(),
            [
                "ckb-idl",
                "verify",
                "--executable",
                "bound",
                "--idl",
                "artifact.json",
                "--manifest",
                "binding.json",
            ]
            .as_slice(),
            ["ckb-idl", "inspect", "--executable", "bound"].as_slice(),
        ] {
            Cli::try_parse_from(arguments).expect("initial command must parse");
        }
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(Cli::try_parse_from(["ckb-idl", "package"]).is_err());
    }
}

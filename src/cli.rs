use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::error::CliError;

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
    let command = match cli.command {
        Command::Validate(_) => "validate",
        Command::Bind(_) => "bind",
        Command::Verify(_) => "verify",
        Command::Inspect(_) => "inspect",
    };

    Err(CliError::NotImplemented { command })
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

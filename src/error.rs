use std::{io, path::PathBuf};

use thiserror::Error;

/// Stable process outcomes for non-parser failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    InvalidDocument = 3,
    InvalidTrailer = 4,
    CommitmentMismatch = 5,
    ManifestMismatch = 6,
    IoOrFilesystemSafety = 7,
}

/// Errors returned by command implementations.
///
/// Parser errors are emitted by clap with its conventional exit code. Every
/// error in this type renders as one machine-readable, line-oriented record.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("category=invalid_document path={path:?} message={message:?}")]
    InvalidDocument { path: String, message: String },

    #[error("category=invalid_trailer path= message={message}")]
    InvalidTrailer { message: String },

    #[error("category=commitment_mismatch path= message={message}")]
    CommitmentMismatch { message: String },

    #[error("category=manifest_mismatch path={path} message={message}")]
    ManifestMismatch { path: String, message: String },

    #[error("category=io_error path={path} message={message}")]
    Io { path: PathBuf, message: String },

    #[error("category=filesystem_safety path={path} message={message}")]
    FilesystemSafety { path: PathBuf, message: String },

    #[error("category=not_implemented path= message=command `{command}` is not implemented yet")]
    NotImplemented { command: &'static str },
}

impl CliError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidDocument { .. } => "invalid_document",
            Self::InvalidTrailer { .. } => "invalid_trailer",
            Self::CommitmentMismatch { .. } => "commitment_mismatch",
            Self::ManifestMismatch { .. } => "manifest_mismatch",
            Self::Io { .. } => "io_error",
            Self::FilesystemSafety { .. } => "filesystem_safety",
            Self::NotImplemented { .. } => "not_implemented",
        }
    }

    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidDocument { .. } => ExitCode::InvalidDocument as i32,
            Self::InvalidTrailer { .. } => ExitCode::InvalidTrailer as i32,
            Self::CommitmentMismatch { .. } => ExitCode::CommitmentMismatch as i32,
            Self::ManifestMismatch { .. } => ExitCode::ManifestMismatch as i32,
            Self::Io { .. } | Self::FilesystemSafety { .. } | Self::NotImplemented { .. } => {
                ExitCode::IoOrFilesystemSafety as i32
            }
        }
    }

    pub fn io(path: impl Into<PathBuf>, error: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, path::PathBuf};

    use super::{CliError, ExitCode};

    #[test]
    fn protocol_errors_have_stable_categories_and_exit_codes() {
        let cases = [
            (
                CliError::InvalidDocument {
                    path: "/interfaces/0".into(),
                    message: "invalid document".into(),
                },
                "invalid_document",
                ExitCode::InvalidDocument,
            ),
            (
                CliError::InvalidTrailer {
                    message: "bad magic".into(),
                },
                "invalid_trailer",
                ExitCode::InvalidTrailer,
            ),
            (
                CliError::CommitmentMismatch {
                    message: "digest differs".into(),
                },
                "commitment_mismatch",
                ExitCode::CommitmentMismatch,
            ),
            (
                CliError::ManifestMismatch {
                    path: "/idl_sha256".into(),
                    message: "digest differs".into(),
                },
                "manifest_mismatch",
                ExitCode::ManifestMismatch,
            ),
            (
                CliError::io("bundle", io::Error::other("write failed")),
                "io_error",
                ExitCode::IoOrFilesystemSafety,
            ),
            (
                CliError::FilesystemSafety {
                    path: PathBuf::from("dist"),
                    message: "destination exists".into(),
                },
                "filesystem_safety",
                ExitCode::IoOrFilesystemSafety,
            ),
        ];

        for (error, category, exit_code) in cases {
            assert_eq!(error.category(), category);
            assert_eq!(error.exit_code(), exit_code as i32);
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("category={category}"))
            );
        }
    }

    #[test]
    fn invalid_document_escapes_newlines_in_its_record() {
        let error = CliError::InvalidDocument {
            path: "/interfaces\n/0".into(),
            message: "first line\nsecond line".into(),
        };

        let record = error.to_string();
        assert!(!record.contains('\n'));
        assert!(record.contains("path=\"/interfaces\\n/0\""));
        assert!(record.contains("message=\"first line\\nsecond line\""));
    }
}

//! Creation and verification of complete Binding Trailer 1 bundles.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    bundle::{BundleContents, BundleSources, PublishedBundle, publish_bundle},
    error::CliError,
    hash::{ckb_data_hash, hex_prefixed},
    idl::ValidatedIdl,
    manifest::{BindingManifest, ENCODING, IDL_VERSION, MANIFEST_FORMAT, TrailerManifest},
    trailer::{
        BindingTrailer, ExecutableSuffix, TRAILER_FLAGS, TRAILER_MAGIC, TRAILER_PAYLOAD_LEN,
        TRAILER_VERSION, classify_executable_suffix, parse_bound_code,
    },
};

/// Successful local binding output.
#[derive(Debug, Clone)]
pub struct BindingReport {
    pub bundle: PublishedBundle,
    pub idl_sha256: [u8; 32],
    pub bound_code_data_ckb_hash: [u8; 32],
}

/// Successful binding verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationReport {
    pub idl_sha256: [u8; 32],
    pub clean_executable_bytes: usize,
    pub bound_code_data_bytes: usize,
    pub bound_code_data_ckb_hash: [u8; 32],
}

/// Produces and semantically verifies an atomically published binding bundle.
pub fn bind_bundle(
    executable_path: impl AsRef<Path>,
    idl_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
) -> Result<BindingReport, CliError> {
    let executable_path = executable_path.as_ref();
    let idl_path = idl_path.as_ref();
    let idl = ValidatedIdl::from_path(idl_path)?;
    let clean_executable =
        fs::read(executable_path).map_err(|error| CliError::io(executable_path, error))?;
    reject_non_clean_executable(executable_path, &clean_executable)?;

    let executable_file = utf8_file_name(executable_path)?;
    let idl_file = format!("{executable_file}.idl.json");
    let manifest_file = format!("{executable_file}.binding.json");
    let mut bound_code_data = clean_executable.clone();
    bound_code_data.extend_from_slice(&BindingTrailer::new(idl.sha256()).encode());

    let manifest = BindingManifest {
        format: MANIFEST_FORMAT.into(),
        idl_version: IDL_VERSION.into(),
        encoding: ENCODING.into(),
        executable_file: executable_file.to_owned(),
        idl_file: idl_file.clone(),
        idl_sha256: hex_prefixed(idl.sha256()),
        clean_executable_ckb_hash: hex_prefixed(ckb_data_hash(&clean_executable)),
        bound_code_data_ckb_hash: hex_prefixed(ckb_data_hash(&bound_code_data)),
        clean_executable_bytes: bytes_as_u64(clean_executable.len())?,
        bound_code_data_bytes: bytes_as_u64(bound_code_data.len())?,
        trailer: TrailerManifest {
            version: TRAILER_VERSION,
            flags: TRAILER_FLAGS,
            payload_length: TRAILER_PAYLOAD_LEN,
            magic_hex: hex_prefixed(TRAILER_MAGIC),
        },
    };
    let manifest_bytes = manifest.to_canonical_bytes()?;
    let contents = BundleContents {
        executable_file,
        executable_bytes: &bound_code_data,
        idl_file: &idl_file,
        idl_bytes: idl.bytes(),
        manifest_file: &manifest_file,
        manifest_bytes: &manifest_bytes,
    };
    let bundle = publish_bundle(
        out_dir,
        BundleSources {
            executable: executable_path,
            idl: idl_path,
        },
        contents,
        |staged| {
            verify_binding(&staged.executable, &staged.idl, Some(&staged.manifest)).map(|_| ())
        },
    )?;

    Ok(BindingReport {
        bundle,
        idl_sha256: idl.sha256(),
        bound_code_data_ckb_hash: ckb_data_hash(&bound_code_data),
    })
}

/// Verifies a bound executable against frozen canonical IDL and optional manifest.
pub fn verify_binding(
    executable_path: impl AsRef<Path>,
    idl_path: impl AsRef<Path>,
    manifest_path: Option<&Path>,
) -> Result<VerificationReport, CliError> {
    let executable_path = executable_path.as_ref();
    let idl_path = idl_path.as_ref();
    let bound_code_data =
        fs::read(executable_path).map_err(|error| CliError::io(executable_path, error))?;
    let parsed = parse_bound_code(&bound_code_data).map_err(invalid_trailer)?;
    let idl = ValidatedIdl::from_path(idl_path)?;
    if parsed.trailer.idl_sha256 != idl.sha256() {
        return Err(CliError::CommitmentMismatch {
            message: "Binding Trailer 1 IDL digest does not match frozen IDL".into(),
        });
    }

    if let Some(manifest_path) = manifest_path {
        let manifest_bytes =
            fs::read(manifest_path).map_err(|error| CliError::io(manifest_path, error))?;
        let manifest = BindingManifest::from_canonical_bytes(&manifest_bytes)?;
        manifest.verify_artifacts(
            utf8_file_name(executable_path)?,
            utf8_file_name(idl_path)?,
            idl.sha256(),
            parsed.clean_executable,
            &bound_code_data,
        )?;
    }

    Ok(VerificationReport {
        idl_sha256: idl.sha256(),
        clean_executable_bytes: parsed.clean_executable.len(),
        bound_code_data_bytes: bound_code_data.len(),
        bound_code_data_ckb_hash: ckb_data_hash(&bound_code_data),
    })
}

fn reject_non_clean_executable(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    match classify_executable_suffix(bytes) {
        ExecutableSuffix::Clean => Ok(()),
        ExecutableSuffix::ValidTrailer(_) => Err(filesystem_safety(
            path,
            "executable already ends in a valid Binding Trailer 1",
        )),
        ExecutableSuffix::MalformedTrailerLike(_) => Err(filesystem_safety(
            path,
            "executable ends in a malformed Binding Trailer 1-like suffix",
        )),
    }
}

fn invalid_trailer(error: impl ToString) -> CliError {
    CliError::InvalidTrailer {
        message: error.to_string(),
    }
}

fn utf8_file_name(path: &Path) -> Result<&str, CliError> {
    path.file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| filesystem_safety(path, "path must have a UTF-8 file name"))
}

fn bytes_as_u64(value: usize) -> Result<u64, CliError> {
    u64::try_from(value).map_err(|_| filesystem_safety("", "byte count does not fit in u64"))
}

fn filesystem_safety(path: impl Into<PathBuf>, message: impl Into<String>) -> CliError {
    CliError::FilesystemSafety {
        path: path.into(),
        message: message.into(),
    }
}

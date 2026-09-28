//! Deterministic binding-manifest serialization and validation.

use serde::{Deserialize, Serialize};

use crate::{
    error::CliError,
    hash::{ckb_data_hash, hex_prefixed},
    trailer::{TRAILER_FLAGS, TRAILER_MAGIC, TRAILER_PAYLOAD_LEN, TRAILER_VERSION},
};

/// Binding manifest format identifier.
pub const MANIFEST_FORMAT: &str = "ckb-idl-binding-manifest-0.1";
/// IDL version bound by this release.
pub const IDL_VERSION: &str = "0.1.0";
/// IDL wire encoding bound by this release.
pub const ENCODING: &str = "ckb-idl-linear-0.1.0";

/// Deterministic metadata for one bound code-data bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingManifest {
    pub format: String,
    pub idl_version: String,
    pub encoding: String,
    pub executable_file: String,
    pub idl_file: String,
    pub idl_sha256: String,
    pub clean_executable_ckb_hash: String,
    pub bound_code_data_ckb_hash: String,
    pub clean_executable_bytes: u64,
    pub bound_code_data_bytes: u64,
    pub trailer: TrailerManifest,
}

/// The fixed Trailer 1 constants recorded in a binding manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrailerManifest {
    pub version: u8,
    pub flags: u8,
    pub payload_length: u32,
    pub magic_hex: String,
}

impl BindingManifest {
    /// Serializes a valid manifest as deterministic RFC 8785 JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CliError> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(manifest_error)
    }

    /// Parses, verifies canonical form, and validates manifest values.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CliError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let manifest = Self::deserialize(&mut deserializer).map_err(manifest_error)?;
        deserializer.end().map_err(manifest_error)?;

        let canonical = serde_json_canonicalizer::to_vec(&manifest).map_err(manifest_error)?;
        if canonical != bytes {
            return Err(mismatch("", "manifest bytes are not RFC 8785 canonical"));
        }
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates the fixed format and syntactic integrity of a manifest.
    pub fn validate(&self) -> Result<(), CliError> {
        expect("/format", &self.format, MANIFEST_FORMAT)?;
        expect("/idl_version", &self.idl_version, IDL_VERSION)?;
        expect("/encoding", &self.encoding, ENCODING)?;
        validate_file_name("/executable_file", &self.executable_file)?;
        validate_file_name("/idl_file", &self.idl_file)?;
        validate_hash("/idl_sha256", &self.idl_sha256)?;
        validate_hash(
            "/clean_executable_ckb_hash",
            &self.clean_executable_ckb_hash,
        )?;
        validate_hash("/bound_code_data_ckb_hash", &self.bound_code_data_ckb_hash)?;

        if self.trailer.version != TRAILER_VERSION {
            return Err(mismatch(
                "/trailer/version",
                "manifest trailer version does not match Binding Trailer 1",
            ));
        }
        if self.trailer.flags != TRAILER_FLAGS {
            return Err(mismatch(
                "/trailer/flags",
                "manifest trailer flags do not match Binding Trailer 1",
            ));
        }
        if self.trailer.payload_length != TRAILER_PAYLOAD_LEN {
            return Err(mismatch(
                "/trailer/payload_length",
                "manifest trailer payload length does not match Binding Trailer 1",
            ));
        }
        let expected_magic = crate::hash::hex_prefixed(TRAILER_MAGIC);
        if self.trailer.magic_hex != expected_magic {
            return Err(mismatch(
                "/trailer/magic_hex",
                "manifest trailer magic does not match Binding Trailer 1",
            ));
        }
        Ok(())
    }

    /// Verifies every manifest value against already-validated bundle artifacts.
    pub fn verify_artifacts(
        &self,
        executable_file: &str,
        idl_file: &str,
        idl_sha256: [u8; 32],
        clean_executable: &[u8],
        bound_code_data: &[u8],
    ) -> Result<(), CliError> {
        self.validate()?;
        expect("/executable_file", &self.executable_file, executable_file)?;
        expect("/idl_file", &self.idl_file, idl_file)?;
        expect("/idl_sha256", &self.idl_sha256, &hex_prefixed(idl_sha256))?;
        expect(
            "/clean_executable_ckb_hash",
            &self.clean_executable_ckb_hash,
            &hex_prefixed(ckb_data_hash(clean_executable)),
        )?;
        expect(
            "/bound_code_data_ckb_hash",
            &self.bound_code_data_ckb_hash,
            &hex_prefixed(ckb_data_hash(bound_code_data)),
        )?;
        expect_u64(
            "/clean_executable_bytes",
            self.clean_executable_bytes,
            bytes_as_u64(clean_executable.len())?,
        )?;
        expect_u64(
            "/bound_code_data_bytes",
            self.bound_code_data_bytes,
            bytes_as_u64(bound_code_data.len())?,
        )
    }
}

fn expect(path: &str, actual: &str, expected: &str) -> Result<(), CliError> {
    if actual == expected {
        Ok(())
    } else {
        Err(mismatch(path, format!("expected `{expected}`")))
    }
}

fn expect_u64(path: &str, actual: u64, expected: u64) -> Result<(), CliError> {
    if actual == expected {
        Ok(())
    } else {
        Err(mismatch(path, format!("expected {expected}")))
    }
}

fn bytes_as_u64(value: usize) -> Result<u64, CliError> {
    u64::try_from(value).map_err(|_| mismatch("", "byte count does not fit in u64"))
}

fn validate_file_name(path: &str, name: &str) -> Result<(), CliError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(mismatch(path, "manifest file name must be a basename"));
    }
    Ok(())
}

fn validate_hash(path: &str, hash: &str) -> Result<(), CliError> {
    let Some(hex) = hash.strip_prefix("0x") else {
        return Err(mismatch(path, "hash must start with lowercase `0x`"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(mismatch(
            path,
            "hash must contain 32 lowercase hexadecimal bytes",
        ));
    }
    Ok(())
}

fn mismatch(path: impl Into<String>, message: impl Into<String>) -> CliError {
    CliError::ManifestMismatch {
        path: path.into(),
        message: message.into(),
    }
}

fn manifest_error(error: impl ToString) -> CliError {
    mismatch("", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{BindingManifest, ENCODING, IDL_VERSION, MANIFEST_FORMAT, TrailerManifest};
    use crate::{error::CliError, hash::hex_prefixed, trailer::TRAILER_MAGIC};

    fn manifest() -> BindingManifest {
        BindingManifest {
            format: MANIFEST_FORMAT.into(),
            idl_version: IDL_VERSION.into(),
            encoding: ENCODING.into(),
            executable_file: "authorization-choice-lock".into(),
            idl_file: "authorization-choice-lock.idl.json".into(),
            idl_sha256: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            clean_executable_ckb_hash:
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            bound_code_data_ckb_hash:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            clean_executable_bytes: 123_456,
            bound_code_data_bytes: 123_502,
            trailer: TrailerManifest {
                version: 1,
                flags: 0,
                payload_length: 34,
                magic_hex: hex_prefixed(TRAILER_MAGIC),
            },
        }
    }

    #[test]
    fn manifest_serialization_is_canonical_and_deterministic() {
        let manifest = manifest();
        let first = manifest.to_canonical_bytes().expect("valid manifest");
        let second = manifest.to_canonical_bytes().expect("valid manifest");

        assert_eq!(first, second);
        assert_eq!(
            BindingManifest::from_canonical_bytes(&first).expect("canonical manifest parses"),
            manifest
        );
    }

    #[test]
    fn rejects_noncanonical_and_trailing_manifest_bytes() {
        let canonical = manifest().to_canonical_bytes().expect("valid manifest");
        let pretty = serde_json::to_vec_pretty(&manifest()).expect("manifest JSON");

        for bytes in [pretty, [canonical.clone(), b"\n".to_vec()].concat()] {
            assert!(matches!(
                BindingManifest::from_canonical_bytes(&bytes),
                Err(CliError::ManifestMismatch { path, .. }) if path.is_empty()
            ));
        }
    }

    #[test]
    fn validates_fixed_fields_and_file_hash_syntax() {
        let mut cases = Vec::new();

        let mut invalid = manifest();
        invalid.format = "wrong".into();
        cases.push((invalid, "/format"));
        let mut invalid = manifest();
        invalid.idl_version = "0.2.0".into();
        cases.push((invalid, "/idl_version"));
        let mut invalid = manifest();
        invalid.encoding = "wrong".into();
        cases.push((invalid, "/encoding"));
        let mut invalid = manifest();
        invalid.executable_file = "nested/file".into();
        cases.push((invalid, "/executable_file"));
        let mut invalid = manifest();
        invalid.idl_file = "nested\\file".into();
        cases.push((invalid, "/idl_file"));
        let mut invalid = manifest();
        invalid.idl_sha256 = "0xABC".into();
        cases.push((invalid, "/idl_sha256"));
        let mut invalid = manifest();
        invalid.clean_executable_ckb_hash = "not-a-hash".into();
        cases.push((invalid, "/clean_executable_ckb_hash"));
        let mut invalid = manifest();
        invalid.bound_code_data_ckb_hash = "0xDD".into();
        cases.push((invalid, "/bound_code_data_ckb_hash"));
        let mut invalid = manifest();
        invalid.trailer.version = 2;
        cases.push((invalid, "/trailer/version"));
        let mut invalid = manifest();
        invalid.trailer.flags = 1;
        cases.push((invalid, "/trailer/flags"));
        let mut invalid = manifest();
        invalid.trailer.payload_length = 0;
        cases.push((invalid, "/trailer/payload_length"));
        let mut invalid = manifest();
        invalid.trailer.magic_hex = "0x00".into();
        cases.push((invalid, "/trailer/magic_hex"));

        for (manifest, path) in cases {
            assert!(matches!(
                manifest.validate(),
                Err(CliError::ManifestMismatch { path: actual, .. }) if actual == path
            ));
        }
    }
}

//! Exact-byte validation for IDL 0.1.0 commitment artifacts.

use std::{fs, path::Path};

use ckb_idl_client::{IdlClient, IdlDocument, IdlError};
use serde::Deserialize;

use crate::{error::CliError, hash::sha256};

/// A validated, unchanged canonical IDL artifact and its raw SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdl {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl ValidatedIdl {
    /// Reads and validates an IDL without modifying its source file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CliError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|error| CliError::io(path, error))?;
        Self::from_bytes(bytes)
    }

    /// Validates owned IDL bytes without canonicalizing or rewriting them.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CliError> {
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(non_canonical("UTF-8 BOM is not permitted"));
        }

        let value = parse_one_json_value(&bytes)?;
        let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|error| {
            CliError::InvalidDocument {
                path: String::new(),
                message: error.to_string(),
            }
        })?;
        if canonical != bytes {
            return Err(non_canonical("IDL bytes are not RFC 8785 canonical"));
        }

        let document = IdlClient::parse_document(&bytes).map_err(client_error)?;
        document.validate().map_err(client_error)?;
        enforce_provisional_limits(&document)?;

        Ok(Self {
            sha256: sha256(&bytes),
            bytes,
        })
    }

    /// Returns the original validated IDL bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns raw SHA-256 of the original validated IDL bytes.
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

fn parse_one_json_value(bytes: &[u8]) -> Result<serde_json::Value, CliError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_json::Value::deserialize(&mut deserializer).map_err(|error| {
        CliError::InvalidDocument {
            path: String::new(),
            message: error.to_string(),
        }
    })?;
    deserializer
        .end()
        .map_err(|error| CliError::InvalidDocument {
            path: String::new(),
            message: error.to_string(),
        })?;
    Ok(value)
}

fn client_error(error: IdlError) -> CliError {
    CliError::IdlValidation {
        category: error.category(),
        path: error.path().to_owned(),
        message: error.to_string(),
    }
}

fn non_canonical(message: impl Into<String>) -> CliError {
    CliError::IdlValidation {
        category: "non_canonical_document",
        path: String::new(),
        message: message.into(),
    }
}

/// Placeholder for the provisional IDL 0.1.0 limit policy.
///
/// Limits are intentionally not enforced until registry, browser/WASM, and
/// mobile validation finalizes their normative values.
fn enforce_provisional_limits(_document: &IdlDocument) -> Result<(), CliError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::ValidatedIdl;
    use crate::{error::CliError, hash::hex_prefixed};

    const CANONICAL_FIXTURES: [(&[u8], &str); 4] = [
        (
            include_bytes!(
                "../tests/examples/flat-witness.json"
            ),
            "0xaab089aa382452a21c4850db078af67f3d3294844f87c36735c3684d27c6920d",
        ),
        (
            include_bytes!(
                "../tests/examples/nested-witness.json"
            ),
            "0x055af6c7264b6cca58d61ef7185f2f28369af44937edbabe818445e8b5c55fc0",
        ),
        (
            include_bytes!(
                "../tests/examples/typed-vector.json"
            ),
            "0x33ad2b8b18a6b1a2cf4de18cc0c5282d494ae61dfc903a17bc6fc41a59cd45d4",
        ),
        (
            include_bytes!(
                "../tests/examples/union-witness.json"
            ),
            "0xe027eb19bf5478aced236b537cf6a823156443991ed12c102b1281376eb71ad2",
        ),
    ];

    #[test]
    fn accepts_canonical_fixtures_and_preserves_their_hashes() {
        for (bytes, expected_hash) in CANONICAL_FIXTURES {
            let validated = ValidatedIdl::from_bytes(bytes.to_vec())
                .expect("canonical client fixture must validate");
            assert_eq!(validated.bytes(), bytes);
            assert_eq!(hex_prefixed(validated.sha256()), expected_hash);
        }
    }

    #[test]
    fn source_file_is_unchanged_after_validation() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("artifact.idl.json");
        let original = CANONICAL_FIXTURES[0].0;
        fs::write(&path, original).expect("fixture write");

        let validated = ValidatedIdl::from_path(&path).expect("fixture validates");

        assert_eq!(validated.bytes(), original);
        assert_eq!(fs::read(path).expect("fixture reread"), original);
    }

    #[test]
    fn rejects_bom_pretty_key_order_and_trailing_idl_bytes() {
        let cases = [
            b"\xEF\xBB\xBF{}".as_slice(),
            b"{\n  \"idl_version\": \"0.1.0\"\n}".as_slice(),
            b"{\"z\":0,\"a\":0}".as_slice(),
            b"{\"idl_version\":\"0.1.0\"}\n".as_slice(),
        ];

        for bytes in cases {
            assert!(matches!(
                ValidatedIdl::from_bytes(bytes.to_vec()),
                Err(CliError::IdlValidation {
                    category: "non_canonical_document",
                    path,
                    ..
                }) if path.is_empty()
            ));
        }
    }

    #[test]
    fn rejects_malformed_or_non_json_trailing_input() {
        for bytes in [b"{".as_slice(), b"{} trailing".as_slice()] {
            assert!(matches!(
                ValidatedIdl::from_bytes(bytes.to_vec()),
                Err(CliError::InvalidDocument { path, .. }) if path.is_empty()
            ));
        }
    }
}

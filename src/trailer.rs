//! Binding Trailer 1 encoding, end-relative parsing, and suffix classification.

use thiserror::Error;

/// Binding Trailer 1 format version.
pub const TRAILER_VERSION: u8 = 1;
/// Binding Trailer 1 has no enabled flags.
pub const TRAILER_FLAGS: u8 = 0;
/// Number of bytes in the version, flags, and IDL digest payload.
pub const TRAILER_PAYLOAD_LEN: u32 = 34;
/// Binding Trailer 1 magic bytes: `CKBIDL` followed by two zero bytes.
pub const TRAILER_MAGIC: [u8; 8] = *b"CKBIDL\0\0";
/// Complete Binding Trailer 1 byte length.
pub const TRAILER_LEN: usize = TRAILER_PAYLOAD_LEN as usize + 4 + TRAILER_MAGIC.len();

/// The parsed fixed payload of Binding Trailer 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingTrailer {
    pub version: u8,
    pub flags: u8,
    pub idl_sha256: [u8; 32],
}

impl BindingTrailer {
    /// Creates the only Trailer 1 shape this release can write.
    pub const fn new(idl_sha256: [u8; 32]) -> Self {
        Self {
            version: TRAILER_VERSION,
            flags: TRAILER_FLAGS,
            idl_sha256,
        }
    }

    /// Encodes the full 46-byte suffix.
    pub fn encode(self) -> [u8; TRAILER_LEN] {
        let mut encoded = [0_u8; TRAILER_LEN];
        encoded[0] = self.version;
        encoded[1] = self.flags;
        encoded[2..34].copy_from_slice(&self.idl_sha256);
        encoded[34..38].copy_from_slice(&TRAILER_PAYLOAD_LEN.to_le_bytes());
        encoded[38..].copy_from_slice(&TRAILER_MAGIC);
        encoded
    }
}

/// Borrowed views of a bound executable and its parsed trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedBoundCode<'a> {
    pub clean_executable: &'a [u8],
    pub trailer: BindingTrailer,
}

/// A malformed or unsupported Binding Trailer 1 suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrailerError {
    #[error("bound executable has {actual} bytes; Binding Trailer 1 needs at least {TRAILER_LEN}")]
    TooShort { actual: usize },

    #[error("magic bytes do not match Binding Trailer 1")]
    InvalidMagic,

    #[error("payload length must be {TRAILER_PAYLOAD_LEN} bytes, got {actual}")]
    InvalidPayloadLength { actual: u32 },

    #[error("unsupported trailer version {actual}")]
    UnsupportedVersion { actual: u8 },

    #[error("unknown trailer flags {actual}")]
    UnsupportedFlags { actual: u8 },
}

/// Parses Binding Trailer 1 from the end of `bound_code_data`.
pub fn parse_bound_code(bound_code_data: &[u8]) -> Result<ParsedBoundCode<'_>, TrailerError> {
    if bound_code_data.len() < TRAILER_LEN {
        return Err(TrailerError::TooShort {
            actual: bound_code_data.len(),
        });
    }

    let total_len = bound_code_data.len();
    let magic_offset = total_len - TRAILER_MAGIC.len();
    if bound_code_data[magic_offset..] != TRAILER_MAGIC {
        return Err(TrailerError::InvalidMagic);
    }

    let length_offset = magic_offset - 4;
    let payload_len = u32::from_le_bytes(
        bound_code_data[length_offset..magic_offset]
            .try_into()
            .expect("trailer payload length has exactly four bytes"),
    );
    if payload_len != TRAILER_PAYLOAD_LEN {
        return Err(TrailerError::InvalidPayloadLength {
            actual: payload_len,
        });
    }

    let payload_offset = length_offset - TRAILER_PAYLOAD_LEN as usize;
    let payload = &bound_code_data[payload_offset..length_offset];
    if payload[0] != TRAILER_VERSION {
        return Err(TrailerError::UnsupportedVersion { actual: payload[0] });
    }
    if payload[1] != TRAILER_FLAGS {
        return Err(TrailerError::UnsupportedFlags { actual: payload[1] });
    }

    let mut idl_sha256 = [0_u8; 32];
    idl_sha256.copy_from_slice(&payload[2..]);
    Ok(ParsedBoundCode {
        clean_executable: &bound_code_data[..payload_offset],
        trailer: BindingTrailer {
            version: payload[0],
            flags: payload[1],
            idl_sha256,
        },
    })
}

/// Classifies whether an executable can safely be treated as clean input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableSuffix {
    Clean,
    ValidTrailer(BindingTrailer),
    MalformedTrailerLike(TrailerError),
}

/// Detects valid and suspicious Trailer 1-like suffixes without modifying bytes.
///
/// A suffix is suspicious when it has the trailer magic or when its fixed
/// version, flags, and payload-length framing all match Trailer 1. `bind` must
/// accept only [`ExecutableSuffix::Clean`].
pub fn classify_executable_suffix(executable: &[u8]) -> ExecutableSuffix {
    match parse_bound_code(executable) {
        Ok(parsed) => return ExecutableSuffix::ValidTrailer(parsed.trailer),
        Err(error) if executable.ends_with(&TRAILER_MAGIC) => {
            return ExecutableSuffix::MalformedTrailerLike(error);
        }
        Err(_) => {}
    }

    let has_trailer_framing = executable.len() >= TRAILER_LEN
        && executable[executable.len() - TRAILER_LEN] == TRAILER_VERSION
        && executable[executable.len() - TRAILER_LEN + 1] == TRAILER_FLAGS
        && executable[executable.len() - 12..executable.len() - 8]
            == TRAILER_PAYLOAD_LEN.to_le_bytes();

    if has_trailer_framing {
        return ExecutableSuffix::MalformedTrailerLike(TrailerError::InvalidMagic);
    }

    ExecutableSuffix::Clean
}

#[cfg(test)]
mod tests {
    use ckb_idl_client::IdlClient;

    use super::{
        BindingTrailer, ExecutableSuffix, TRAILER_FLAGS, TRAILER_LEN, TRAILER_MAGIC,
        TRAILER_PAYLOAD_LEN, TRAILER_VERSION, TrailerError, classify_executable_suffix,
        parse_bound_code,
    };
    use crate::hash::sha256;

    fn bound_code() -> Vec<u8> {
        let mut bound = b"clean executable".to_vec();
        bound.extend_from_slice(&BindingTrailer::new([0xA5; 32]).encode());
        bound
    }

    #[test]
    fn encodes_the_exact_trailer_one_layout() {
        let encoded = BindingTrailer::new([0xA5; 32]).encode();

        assert_eq!(encoded.len(), TRAILER_LEN);
        assert_eq!(encoded[0], TRAILER_VERSION);
        assert_eq!(encoded[1], TRAILER_FLAGS);
        assert_eq!(&encoded[2..34], &[0xA5; 32]);
        assert_eq!(&encoded[34..38], &TRAILER_PAYLOAD_LEN.to_le_bytes());
        assert_eq!(&encoded[38..], &TRAILER_MAGIC);
    }

    #[test]
    fn parses_trailer_from_the_end() {
        let bound = bound_code();
        let parsed = parse_bound_code(&bound).expect("valid trailer must parse");

        assert_eq!(parsed.clean_executable, b"clean executable");
        assert_eq!(parsed.trailer, BindingTrailer::new([0xA5; 32]));
    }

    #[test]
    fn rejects_each_invalid_fixed_trailer_field() {
        let cases = [
            (Vec::new(), TrailerError::TooShort { actual: 0 }),
            (
                {
                    let mut bytes = bound_code();
                    *bytes.last_mut().expect("nonempty") ^= 1;
                    bytes
                },
                TrailerError::InvalidMagic,
            ),
            (
                {
                    let mut bytes = bound_code();
                    let offset = bytes.len() - 12;
                    bytes[offset..offset + 4].copy_from_slice(&0_u32.to_le_bytes());
                    bytes
                },
                TrailerError::InvalidPayloadLength { actual: 0 },
            ),
            (
                {
                    let mut bytes = bound_code();
                    let offset = bytes.len() - TRAILER_LEN;
                    bytes[offset] = TRAILER_VERSION + 1;
                    bytes
                },
                TrailerError::UnsupportedVersion {
                    actual: TRAILER_VERSION + 1,
                },
            ),
            (
                {
                    let mut bytes = bound_code();
                    let offset = bytes.len() - TRAILER_LEN;
                    bytes[offset + 1] = TRAILER_FLAGS + 1;
                    bytes
                },
                TrailerError::UnsupportedFlags {
                    actual: TRAILER_FLAGS + 1,
                },
            ),
        ];

        for (bytes, expected) in cases {
            assert_eq!(parse_bound_code(&bytes), Err(expected));
        }
    }

    #[test]
    fn classifies_clean_valid_and_malformed_like_suffixes() {
        assert_eq!(
            classify_executable_suffix(b"ordinary executable"),
            ExecutableSuffix::Clean
        );
        assert_eq!(
            classify_executable_suffix(&bound_code()),
            ExecutableSuffix::ValidTrailer(BindingTrailer::new([0xA5; 32]))
        );
        assert!(matches!(
            classify_executable_suffix(&TRAILER_MAGIC),
            ExecutableSuffix::MalformedTrailerLike(TrailerError::TooShort { .. })
        ));

        let mut weak_framing = vec![0_u8; TRAILER_LEN];
        weak_framing[0] = TRAILER_VERSION;
        weak_framing[1] = TRAILER_FLAGS;
        assert_eq!(
            classify_executable_suffix(&weak_framing),
            ExecutableSuffix::Clean
        );

        let mut framing_only = vec![0_u8; TRAILER_LEN];
        framing_only[0] = TRAILER_VERSION;
        framing_only[1] = TRAILER_FLAGS;
        framing_only[TRAILER_LEN - 12..TRAILER_LEN - 8]
            .copy_from_slice(&TRAILER_PAYLOAD_LEN.to_le_bytes());
        assert!(matches!(
            classify_executable_suffix(&framing_only),
            ExecutableSuffix::MalformedTrailerLike(TrailerError::InvalidMagic)
        ));
    }

    #[test]
    fn client_accepts_the_encoded_trailer() {
        let idl = br#"{"idl_version":"0.1.0"}"#;
        let mut bound = b"clean executable".to_vec();
        bound.extend_from_slice(&BindingTrailer::new(sha256(idl)).encode());

        IdlClient::verify_commitment(idl, &bound)
            .expect("client must accept bytes emitted by the trailer encoder");
    }
}

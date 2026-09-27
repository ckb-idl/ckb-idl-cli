//! Hash helpers for exact-byte IDL commitments and CKB code data.

use std::fmt::Write;

use sha2::{Digest, Sha256};

/// Computes the raw SHA-256 digest of the supplied bytes.
pub fn sha256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes.as_ref()).into()
}

/// Computes CKB's personalized Blake2b-256 hash of the supplied code-data.
pub fn ckb_data_hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    ckb_hash::blake2b_256(bytes)
}

/// Encodes bytes as lowercase hexadecimal with the required `0x` prefix.
pub fn hex_prefixed(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use blake2b_simd::Params;

    use super::{ckb_data_hash, hex_prefixed, sha256};

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex_prefixed(sha256(b"")),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_prefixed(sha256(b"abc")),
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_prefixed_is_lowercase() {
        assert_eq!(hex_prefixed([0x00, 0xAB, 0xFF]), "0x00abff");
    }

    #[test]
    fn ckb_data_hash_uses_ckb_personalization() {
        let ckb_hash = ckb_data_hash(b"");
        let plain_hash = Params::new().hash(b"");

        assert_eq!(
            hex_prefixed(ckb_hash),
            "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e"
        );
        assert_ne!(ckb_hash.as_slice(), plain_hash.as_bytes());
    }
}

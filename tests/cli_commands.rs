use std::{fs, process::Command};

use ckb_idl_cli::{
    hash::{ckb_data_hash, hex_prefixed, sha256},
    trailer::BindingTrailer,
};
use tempfile::tempdir;

const FLAT_IDL: &[u8] =
    include_bytes!("./examples/flat-witness.json");

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ckb-idl"))
}

#[test]
fn validate_reports_the_exact_idl_digest() {
    let directory = tempdir().expect("temporary directory");
    let idl_path = directory.path().join("artifact.idl.json");
    fs::write(&idl_path, FLAT_IDL).expect("IDL write");

    let output = command()
        .args(["validate", "--idl"])
        .arg(&idl_path)
        .output()
        .expect("validate command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "status=valid idl_sha256=0xaab089aa382452a21c4850db078af67f3d3294844f87c36735c3684d27c6920d bytes=190\n"
    );
}

#[test]
fn validate_reports_noncanonical_idl_with_a_stable_error() {
    let directory = tempdir().expect("temporary directory");
    let idl_path = directory.path().join("artifact.idl.json");
    fs::write(&idl_path, b"{\n  \"idl_version\": \"0.1.0\"\n}").expect("IDL write");

    let output = command()
        .args(["validate", "--idl"])
        .arg(&idl_path)
        .output()
        .expect("validate command runs");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with("category=non_canonical_document path=\"\" message=")
    );
}

#[test]
fn inspect_reports_trailer_and_bound_code_hash() {
    let directory = tempdir().expect("temporary directory");
    let executable_path = directory.path().join("bound");
    let mut bound_code = b"clean".to_vec();
    bound_code.extend_from_slice(&BindingTrailer::new(sha256(FLAT_IDL)).encode());
    fs::write(&executable_path, &bound_code).expect("bound executable write");

    let output = command()
        .args(["inspect", "--executable"])
        .arg(&executable_path)
        .output()
        .expect("inspect command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "trailer_version=1 flags=0 payload_length=34 idl_sha256={} clean_executable_bytes=5 bound_code_data_ckb_hash={}\n",
            hex_prefixed(sha256(FLAT_IDL)),
            hex_prefixed(ckb_data_hash(&bound_code)),
        )
    );
}

#[test]
fn inspect_reports_invalid_trailers_with_a_stable_error() {
    let directory = tempdir().expect("temporary directory");
    let executable_path = directory.path().join("not-bound");
    fs::write(&executable_path, b"not bound").expect("executable write");

    let output = command()
        .args(["inspect", "--executable"])
        .arg(&executable_path)
        .output()
        .expect("inspect command runs");

    assert_eq!(output.status.code(), Some(4));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("category=invalid_trailer"));
}

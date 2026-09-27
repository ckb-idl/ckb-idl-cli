use std::{fs, path::Path, process::Command};

use ckb_idl_cli::{
    manifest::BindingManifest,
    trailer::{BindingTrailer, parse_bound_code},
};
use tempfile::tempdir;

const FLAT_IDL: &[u8] =
    include_bytes!("../../ckb-idl-client/tests/fixtures/idl-0.1.0/examples/flat-witness.json");
const NESTED_IDL: &[u8] =
    include_bytes!("../../ckb-idl-client/tests/fixtures/idl-0.1.0/examples/nested-witness.json");

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ckb-idl"))
}

fn bind(executable: &Path, idl: &Path, out_dir: &Path) -> std::process::Output {
    command()
        .args(["bind", "--executable"])
        .arg(executable)
        .args(["--idl"])
        .arg(idl)
        .args(["--out-dir"])
        .arg(out_dir)
        .output()
        .expect("bind command runs")
}

fn verify(executable: &Path, idl: &Path, manifest: Option<&Path>) -> std::process::Output {
    let mut command = command();
    command.args(["verify", "--executable"]);
    command.arg(executable);
    command.args(["--idl"]);
    command.arg(idl);
    if let Some(manifest) = manifest {
        command.args(["--manifest"]);
        command.arg(manifest);
    }
    command.output().expect("verify command runs")
}

fn source_artifacts(directory: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let executable = directory.join("authorization-choice-lock");
    let idl = directory.join("source.idl.json");
    fs::write(&executable, b"clean executable bytes").expect("clean executable write");
    fs::write(&idl, FLAT_IDL).expect("IDL write");
    (executable, idl)
}

#[test]
fn bind_creates_a_deterministic_verified_bundle_without_changing_sources() {
    let directory = tempdir().expect("temporary directory");
    let (executable, idl) = source_artifacts(directory.path());
    let original_executable = fs::read(&executable).expect("source executable");
    let original_idl = fs::read(&idl).expect("source IDL");
    let first_dir = directory.path().join("first");

    let output = bind(&executable, &idl, &first_dir);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("status=bound "));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let bound = first_dir.join("authorization-choice-lock");
    let frozen_idl = first_dir.join("authorization-choice-lock.idl.json");
    let manifest = first_dir.join("authorization-choice-lock.binding.json");
    assert_eq!(fs::read(&frozen_idl).expect("frozen IDL"), FLAT_IDL);
    assert_eq!(
        fs::read(&executable).expect("source executable"),
        original_executable
    );
    assert_eq!(fs::read(&idl).expect("source IDL"), original_idl);
    let bound_bytes = fs::read(&bound).expect("bound executable");
    let parsed = parse_bound_code(&bound_bytes).expect("bound executable trailer");
    assert_eq!(parsed.clean_executable, original_executable);
    BindingManifest::from_canonical_bytes(&fs::read(&manifest).expect("manifest"))
        .expect("canonical manifest");

    let verified = verify(&bound, &frozen_idl, Some(&manifest));
    assert!(verified.status.success(), "{verified:?}");
    assert!(String::from_utf8_lossy(&verified.stdout).starts_with("status=verified "));

    let second_dir = directory.path().join("second");
    let second = bind(&executable, &idl, &second_dir);
    assert!(second.status.success(), "{second:?}");
    for file in [
        "authorization-choice-lock",
        "authorization-choice-lock.idl.json",
        "authorization-choice-lock.binding.json",
    ] {
        assert_eq!(
            fs::read(first_dir.join(file)).expect("first bundle member"),
            fs::read(second_dir.join(file)).expect("second bundle member")
        );
    }
}

#[test]
fn bind_rejects_already_bound_and_malformed_trailer_like_inputs() {
    let directory = tempdir().expect("temporary directory");
    let (executable, idl) = source_artifacts(directory.path());
    let original = fs::read(&executable).expect("source executable");

    let mut already_bound = original.clone();
    already_bound.extend_from_slice(&BindingTrailer::new([0xA5; 32]).encode());
    fs::write(&executable, already_bound).expect("already-bound executable");
    let output = bind(
        &executable,
        &idl,
        &directory.path().join("already-bound-output"),
    );
    assert_eq!(output.status.code(), Some(7));
    assert!(!directory.path().join("already-bound-output").exists());

    fs::write(&executable, b"clean executableCKBIDL\0\0").expect("malformed executable");
    let output = bind(
        &executable,
        &idl,
        &directory.path().join("malformed-output"),
    );
    assert_eq!(output.status.code(), Some(7));
    assert!(!directory.path().join("malformed-output").exists());
}

#[test]
fn verify_detects_idl_trailer_executable_and_manifest_tampering() {
    let directory = tempdir().expect("temporary directory");
    let (executable, idl) = source_artifacts(directory.path());
    let bundle = directory.path().join("bundle");
    assert!(bind(&executable, &idl, &bundle).status.success());
    let bound = bundle.join("authorization-choice-lock");
    let frozen_idl = bundle.join("authorization-choice-lock.idl.json");
    let manifest = bundle.join("authorization-choice-lock.binding.json");

    fs::write(&frozen_idl, NESTED_IDL).expect("IDL tamper");
    assert_eq!(verify(&bound, &frozen_idl, None).status.code(), Some(5));
    fs::write(&frozen_idl, FLAT_IDL).expect("IDL restore");

    let original_bound = fs::read(&bound).expect("bound executable");
    let mut modified_bound = original_bound.clone();
    modified_bound[0] ^= 1;
    fs::write(&bound, &modified_bound).expect("executable tamper");
    assert_eq!(
        verify(&bound, &frozen_idl, Some(&manifest)).status.code(),
        Some(6)
    );
    fs::write(&bound, &original_bound).expect("bound executable restore");

    let mut manifest_value =
        BindingManifest::from_canonical_bytes(&fs::read(&manifest).expect("manifest"))
            .expect("manifest parses");
    manifest_value.idl_sha256 =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    fs::write(
        &manifest,
        manifest_value
            .to_canonical_bytes()
            .expect("canonical manifest tamper"),
    )
    .expect("manifest tamper");
    assert_eq!(
        verify(&bound, &frozen_idl, Some(&manifest)).status.code(),
        Some(6)
    );

    let mut bad_magic = original_bound;
    *bad_magic.last_mut().expect("nonempty") ^= 1;
    fs::write(&bound, bad_magic).expect("trailer tamper");
    assert_eq!(verify(&bound, &frozen_idl, None).status.code(), Some(4));
}

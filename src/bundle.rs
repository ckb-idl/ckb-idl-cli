//! Transactional publication of completed CKB IDL bundles.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use tempfile::{Builder, TempDir};

use crate::error::CliError;

/// Existing source files whose modes and alias safety are preserved by publication.
#[derive(Debug, Clone, Copy)]
pub struct BundleSources<'a> {
    pub executable: &'a Path,
    pub idl: &'a Path,
}

/// The three finished bundle members to stage and publish.
#[derive(Debug, Clone, Copy)]
pub struct BundleContents<'a> {
    pub executable_file: &'a str,
    pub executable_bytes: &'a [u8],
    pub idl_file: &'a str,
    pub idl_bytes: &'a [u8],
    pub manifest_file: &'a str,
    pub manifest_bytes: &'a [u8],
}

/// Paths of staged bundle members available to the caller's semantic verifier.
#[derive(Debug, Clone)]
pub struct StagedBundle {
    pub directory: PathBuf,
    pub executable: PathBuf,
    pub idl: PathBuf,
    pub manifest: PathBuf,
}

/// Paths of an atomically published bundle.
#[derive(Debug, Clone)]
pub struct PublishedBundle {
    pub directory: PathBuf,
    pub executable: PathBuf,
    pub idl: PathBuf,
    pub manifest: PathBuf,
}

/// Stages and atomically publishes a complete bundle in a previously absent directory.
///
/// The verifier runs after byte-for-byte staging checks and before directory rename.
/// Returning an error leaves no output directory and lets the temporary-directory
/// guard remove only the staging directory it created.
pub fn publish_bundle(
    out_dir: impl AsRef<Path>,
    sources: BundleSources<'_>,
    contents: BundleContents<'_>,
    verify: impl FnOnce(&StagedBundle) -> Result<(), CliError>,
) -> Result<PublishedBundle, CliError> {
    let out_dir = out_dir.as_ref();
    preflight(out_dir, sources, contents)?;

    let parent = output_parent(out_dir)?;
    let staging = Builder::new()
        .prefix(".ckb-idl-staging-")
        .tempdir_in(&parent)
        .map_err(|error| CliError::io(&parent, error))?;
    let staged = stage_bundle(&staging, sources, contents)?;
    verify_staged_bytes(&staged, contents)?;
    verify(&staged)?;

    fs::rename(staging.path(), out_dir).map_err(|error| CliError::io(out_dir, error))?;
    Ok(PublishedBundle {
        directory: out_dir.to_path_buf(),
        executable: out_dir.join(contents.executable_file),
        idl: out_dir.join(contents.idl_file),
        manifest: out_dir.join(contents.manifest_file),
    })
}

fn preflight(
    out_dir: &Path,
    sources: BundleSources<'_>,
    contents: BundleContents<'_>,
) -> Result<(), CliError> {
    if out_dir.exists() {
        return Err(filesystem_safety(
            out_dir,
            "output directory already exists; refusing to overwrite it",
        ));
    }
    let _ = fs::metadata(sources.executable)
        .map_err(|error| CliError::io(sources.executable, error))?;
    let _ = fs::metadata(sources.idl).map_err(|error| CliError::io(sources.idl, error))?;
    validate_member_names(contents)?;
    ensure_sources_do_not_alias_destinations(out_dir, sources, contents)
}

fn output_parent(out_dir: &Path) -> Result<PathBuf, CliError> {
    let parent = out_dir.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| CliError::io(parent, error))?;
    Ok(parent.to_path_buf())
}

fn validate_member_names(contents: BundleContents<'_>) -> Result<(), CliError> {
    let names = [
        contents.executable_file,
        contents.idl_file,
        contents.manifest_file,
    ];
    if names.iter().any(|name| !is_basename(name)) {
        return Err(filesystem_safety(
            "",
            "bundle member names must be non-empty basenames",
        ));
    }
    if names[0] == names[1] || names[0] == names[2] || names[1] == names[2] {
        return Err(filesystem_safety(
            "",
            "bundle member names must be distinct",
        ));
    }
    Ok(())
}

fn is_basename(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\'])
}

fn ensure_sources_do_not_alias_destinations(
    out_dir: &Path,
    sources: BundleSources<'_>,
    contents: BundleContents<'_>,
) -> Result<(), CliError> {
    let destinations = [
        out_dir.join(contents.executable_file),
        out_dir.join(contents.idl_file),
        out_dir.join(contents.manifest_file),
    ];
    for source in [sources.executable, sources.idl] {
        let source = absolute_path(source)?;
        if destinations
            .iter()
            .map(|destination| absolute_path(destination))
            .collect::<Result<Vec<_>, _>>()?
            .contains(&source)
        {
            return Err(filesystem_safety(
                source,
                "source file aliases a bundle destination",
            ));
        }
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| CliError::io(path, error))
    }
}

fn stage_bundle(
    staging: &TempDir,
    sources: BundleSources<'_>,
    contents: BundleContents<'_>,
) -> Result<StagedBundle, CliError> {
    let directory = staging.path().to_path_buf();
    let executable = directory.join(contents.executable_file);
    let idl = directory.join(contents.idl_file);
    let manifest = directory.join(contents.manifest_file);

    write_new(&executable, contents.executable_bytes)?;
    let permissions = fs::metadata(sources.executable)
        .map_err(|error| CliError::io(sources.executable, error))?
        .permissions();
    fs::set_permissions(&executable, permissions)
        .map_err(|error| CliError::io(&executable, error))?;
    write_new(&idl, contents.idl_bytes)?;
    write_new(&manifest, contents.manifest_bytes)?;

    Ok(StagedBundle {
        directory,
        executable,
        idl,
        manifest,
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CliError::io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| CliError::io(path, error))?;
    file.sync_all().map_err(|error| CliError::io(path, error))?;
    Ok(())
}

fn verify_staged_bytes(
    staged: &StagedBundle,
    contents: BundleContents<'_>,
) -> Result<(), CliError> {
    verify_file_bytes(&staged.executable, contents.executable_bytes)?;
    verify_file_bytes(&staged.idl, contents.idl_bytes)?;
    verify_file_bytes(&staged.manifest, contents.manifest_bytes)
}

fn verify_file_bytes(path: &Path, expected: &[u8]) -> Result<(), CliError> {
    let actual = fs::read(path).map_err(|error| CliError::io(path, error))?;
    if actual == expected {
        Ok(())
    } else {
        Err(filesystem_safety(
            path,
            "staged file bytes differ from requested bytes",
        ))
    }
}

fn filesystem_safety(path: impl Into<PathBuf>, message: impl Into<String>) -> CliError {
    CliError::FilesystemSafety {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{
        BundleContents, BundleSources, ensure_sources_do_not_alias_destinations, publish_bundle,
    };
    use crate::error::CliError;

    fn contents<'a>() -> BundleContents<'a> {
        BundleContents {
            executable_file: "contract",
            executable_bytes: b"bound executable",
            idl_file: "contract.idl.json",
            idl_bytes: b"exact idl",
            manifest_file: "contract.binding.json",
            manifest_bytes: b"canonical manifest",
        }
    }

    #[test]
    fn publishes_a_complete_bundle_without_changing_sources() {
        let directory = tempdir().expect("temporary directory");
        let executable_source = directory.path().join("clean");
        let idl_source = directory.path().join("source.idl.json");
        fs::write(&executable_source, b"clean executable").expect("executable source");
        fs::write(&idl_source, b"source idl").expect("IDL source");
        let output = directory.path().join("dist");
        let source = BundleSources {
            executable: &executable_source,
            idl: &idl_source,
        };

        let published = publish_bundle(&output, source, contents(), |_| Ok(())).expect("publish");

        assert_eq!(
            fs::read(&published.executable).expect("executable output"),
            b"bound executable"
        );
        assert_eq!(fs::read(&published.idl).expect("IDL output"), b"exact idl");
        assert_eq!(
            fs::read(&published.manifest).expect("manifest output"),
            b"canonical manifest"
        );
        assert_eq!(
            fs::read(&executable_source).expect("executable source"),
            b"clean executable"
        );
        assert_eq!(fs::read(&idl_source).expect("IDL source"), b"source idl");
        assert_eq!(published.directory, output);
    }

    #[test]
    fn refuses_existing_output_directory() {
        let directory = tempdir().expect("temporary directory");
        let executable_source = directory.path().join("clean");
        let idl_source = directory.path().join("source.idl.json");
        fs::write(&executable_source, b"clean executable").expect("executable source");
        fs::write(&idl_source, b"source idl").expect("IDL source");
        let output = directory.path().join("dist");
        fs::create_dir(&output).expect("existing output directory");
        let source = BundleSources {
            executable: &executable_source,
            idl: &idl_source,
        };

        assert!(matches!(
            publish_bundle(&output, source, contents(), |_| Ok(())),
            Err(CliError::FilesystemSafety { .. })
        ));
        assert_eq!(
            fs::read(executable_source).expect("executable source"),
            b"clean executable"
        );
        assert_eq!(fs::read(idl_source).expect("IDL source"), b"source idl");
    }

    #[test]
    fn rejects_source_destination_aliases_before_writing() {
        let directory = tempdir().expect("temporary directory");
        let output = directory.path().join("dist");
        let executable_source = output.join("contract");
        let idl_source = directory.path().join("source.idl.json");
        let source = BundleSources {
            executable: &executable_source,
            idl: &idl_source,
        };

        assert!(matches!(
            ensure_sources_do_not_alias_destinations(&output, source, contents()),
            Err(CliError::FilesystemSafety { .. })
        ));
    }

    #[test]
    fn verifier_failure_cleans_the_staging_directory() {
        let directory = tempdir().expect("temporary directory");
        let executable_source = directory.path().join("clean");
        let idl_source = directory.path().join("source.idl.json");
        fs::write(&executable_source, b"clean executable").expect("executable source");
        fs::write(&idl_source, b"source idl").expect("IDL source");
        let output = directory.path().join("dist");
        let source = BundleSources {
            executable: &executable_source,
            idl: &idl_source,
        };

        let result = publish_bundle(&output, source, contents(), |_| {
            Err(CliError::FilesystemSafety {
                path: Path::new("staging").into(),
                message: "semantic verification failed".into(),
            })
        });

        assert!(result.is_err());
        assert!(!output.exists());
        assert!(
            fs::read_dir(directory.path())
                .expect("temporary directory entries")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ckb-idl-staging-"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_executable_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().expect("temporary directory");
        let executable_source = directory.path().join("clean");
        let idl_source = directory.path().join("source.idl.json");
        fs::write(&executable_source, b"clean executable").expect("executable source");
        fs::set_permissions(&executable_source, fs::Permissions::from_mode(0o751))
            .expect("source permissions");
        fs::write(&idl_source, b"source idl").expect("IDL source");
        let source = BundleSources {
            executable: &executable_source,
            idl: &idl_source,
        };

        let published =
            publish_bundle(
                directory.path().join("dist"),
                source,
                contents(),
                |_| Ok(()),
            )
            .expect("publish");

        assert_eq!(
            fs::metadata(published.executable)
                .expect("published executable metadata")
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
    }
}

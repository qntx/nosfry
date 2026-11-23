//! The identity-key directory rule shared by the embedded
//! transports (`onion:`, `iroh:` listeners): the state dir must be a
//! directory with no group/other permission bits. A missing
//! directory is created with mode 0700; an existing one that is too
//! open is an error naming the fix, never silently tightened.
//!
//! Errors are plain strings: each caller maps them to its own
//! [`crate::ServerError`] variant, and `what` names the transport in
//! the message (`"onion"`, `"iroh"`).

use std::path::Path;

/// `path` must be a directory with no group/other permission bits —
/// it holds the transport's identity key. A missing directory is
/// created with mode 0700; an existing one that is too open is an
/// error naming the fix, never silently tightened.
#[cfg(unix)]
pub(crate) fn prepare(path: &Path, what: &str) -> Result<(), String> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    match std::fs::metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(path)
                .map_err(|e| format!("cannot create {what} state dir {}: {e}", path.display()))?;
            Ok(())
        }
        Err(err) => Err(format!(
            "cannot stat {what} state dir {}: {err}",
            path.display()
        )),
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if !meta.is_dir() || mode & 0o077 != 0 {
                return Err(format!(
                    "{what} state dir {} is unsafe (mode {mode:03o}): \
                     it must be a directory with mode 0700; run `chmod 700 {}`",
                    path.display(),
                    path.display()
                ));
            }
            Ok(())
        }
    }
}

/// Non-unix builds have no mode bits to enforce; `path` only has to
/// be a directory.
#[cfg(not(unix))]
pub(crate) fn prepare(path: &Path, what: &str) -> Result<(), String> {
    match std::fs::metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(path)
            .map_err(|err| format!("cannot create {what} state dir {}: {err}", path.display())),
        Err(err) => Err(format!(
            "cannot stat {what} state dir {}: {err}",
            path.display()
        )),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "{what} state dir {} is not a directory",
            path.display()
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    /// The shared rule: a missing dir is created 0700, an open one
    /// refused with the chmod hint, a non-directory refused.
    #[cfg(unix)]
    #[test]
    fn prepare_rules() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        // Missing → created with mode 0700.
        let missing = root.path().join("new");
        prepare(&missing, "onion").unwrap();
        assert_eq!(missing.metadata().unwrap().mode() & 0o777, 0o700);
        // Mode 0700 accepted.
        prepare(&missing, "onion").unwrap();
        // Too open → refused with the chmod hint.
        let open = root.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare(&open, "onion").unwrap_err();
        assert!(err.contains("mode 755"), "{err}");
        assert!(err.contains("chmod 700"), "{err}");
        // Not a directory → refused.
        let file = root.path().join("file");
        std::fs::File::create(&file).unwrap();
        assert!(prepare(&file, "iroh").is_err());
    }
}

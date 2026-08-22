use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::error::Result;
#[cfg(any(windows, not(any(unix, windows))))]
use crate::error::{ErrorCategory, ReltioError};

const MAX_LOCAL_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct PrivateExecutableGuard {
    #[cfg(unix)]
    _inner: File,
    #[cfg(windows)]
    _inner: reltio_windows_security::PrivateExecutableGuard,
}

#[cfg(unix)]
#[path = "unix_fs.rs"]
mod unix;

#[cfg(windows)]
pub(crate) fn normalize_storage_path(path: &Path) -> Result<PathBuf> {
    reltio_windows_security::normalize_local_path(path).map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub(crate) fn normalize_storage_path(path: &Path) -> Result<PathBuf> {
    unix::normalize_storage_path(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn normalize_storage_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| ReltioError::io("failed to resolve a local storage path", &error))
    }
}

#[cfg(windows)]
pub(crate) fn storage_path_is_same_or_descendant(path: &Path, ancestor: &Path) -> Result<bool> {
    reltio_windows_security::local_path_is_same_or_descendant(path, ancestor)
        .map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub(crate) fn storage_path_is_same_or_descendant(path: &Path, ancestor: &Path) -> Result<bool> {
    unix::storage_path_is_same_or_descendant(path, ancestor)
}

#[cfg(windows)]
pub fn ensure_private_parent(path: &Path) -> Result<()> {
    reltio_windows_security::ensure_private_parent(path).map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub fn ensure_private_parent(path: &Path) -> Result<()> {
    unix::ensure_private_parent(path)
}

#[cfg(not(any(unix, windows)))]
pub fn ensure_private_parent(_path: &Path) -> Result<()> {
    Err(private_files_unsupported())
}

#[cfg(windows)]
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    reltio_windows_security::atomic_write_private(path, bytes)
        .map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    unix::atomic_write_private(path, bytes)
}

#[cfg(not(any(unix, windows)))]
pub fn atomic_write_private(_path: &Path, _bytes: &[u8]) -> Result<()> {
    Err(private_files_unsupported())
}

#[cfg(windows)]
pub fn read_bounded(path: &Path, require_private: bool) -> Result<Vec<u8>> {
    read_bounded_with_limit(path, require_private, MAX_LOCAL_FILE_BYTES)
}

#[cfg(windows)]
pub fn read_bounded_with_limit(
    path: &Path,
    require_private: bool,
    maximum_bytes: u64,
) -> Result<Vec<u8>> {
    reltio_windows_security::open_bounded_file(path, maximum_bytes, require_private)
        .and_then(reltio_windows_security::BoundedFile::read_all)
        .map_err(|error| map_windows_bounded_read_error(&error, maximum_bytes))
}

#[cfg(windows)]
pub fn read_bounded_optional(path: &Path, require_private: bool) -> Result<Option<Vec<u8>>> {
    read_bounded_optional_with_limit(path, require_private, MAX_LOCAL_FILE_BYTES)
}

#[cfg(windows)]
pub fn read_bounded_optional_with_limit(
    path: &Path,
    require_private: bool,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    reltio_windows_security::open_optional_bounded_file(path, maximum_bytes, require_private)
        .and_then(|file| {
            file.map(reltio_windows_security::BoundedFile::read_all)
                .transpose()
        })
        .map_err(|error| map_windows_bounded_read_error(&error, maximum_bytes))
}

#[cfg(unix)]
pub fn read_bounded_optional(path: &Path, require_private: bool) -> Result<Option<Vec<u8>>> {
    read_bounded_optional_with_limit(path, require_private, MAX_LOCAL_FILE_BYTES)
}

#[cfg(unix)]
pub fn read_bounded_optional_with_limit(
    path: &Path,
    require_private: bool,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    unix::read_bounded_optional(path, require_private, maximum_bytes)
}

#[cfg(not(any(unix, windows)))]
pub fn read_bounded_optional(_path: &Path, _require_private: bool) -> Result<Option<Vec<u8>>> {
    Err(private_files_unsupported())
}

#[cfg(not(any(unix, windows)))]
pub fn read_bounded_optional_with_limit(
    _path: &Path,
    _require_private: bool,
    _maximum_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    Err(private_files_unsupported())
}

#[cfg(unix)]
pub fn read_bounded(path: &Path, require_private: bool) -> Result<Vec<u8>> {
    read_bounded_with_limit(path, require_private, MAX_LOCAL_FILE_BYTES)
}

#[cfg(unix)]
pub fn read_bounded_with_limit(
    path: &Path,
    require_private: bool,
    maximum_bytes: u64,
) -> Result<Vec<u8>> {
    unix::read_bounded(path, require_private, maximum_bytes)
}

#[cfg(not(any(unix, windows)))]
pub fn read_bounded(_path: &Path, _require_private: bool) -> Result<Vec<u8>> {
    Err(private_files_unsupported())
}

#[cfg(not(any(unix, windows)))]
pub fn read_bounded_with_limit(
    _path: &Path,
    _require_private: bool,
    _maximum_bytes: u64,
) -> Result<Vec<u8>> {
    Err(private_files_unsupported())
}

#[cfg(windows)]
pub fn open_private_lock(path: &Path) -> Result<File> {
    reltio_windows_security::open_private_lock(path).map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub fn open_private_lock(path: &Path) -> Result<File> {
    unix::open_private_lock(path)
}

/// Returns whether a non-blocking `fs2` lock attempt failed because the lock is held.
pub fn is_lock_contended(error: &std::io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|actual| fs2::lock_contended_error().raw_os_error() == Some(actual))
}

#[cfg(not(any(unix, windows)))]
pub fn open_private_lock(_path: &Path) -> Result<File> {
    Err(private_files_unsupported())
}

pub fn path_permissions_are_private(path: &Path, metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        unix::path_permissions_are_private(path, metadata)
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        reltio_windows_security::open_bounded_file(path, u64::MAX, true).is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, metadata);
        false
    }
}

#[cfg(windows)]
pub fn private_file_status(path: &Path) -> Result<Option<bool>> {
    reltio_windows_security::private_file_status(path).map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub fn private_file_status(path: &Path) -> Result<Option<bool>> {
    unix::private_file_status(path)
}

#[cfg(not(any(unix, windows)))]
pub fn private_file_status(_path: &Path) -> Result<Option<bool>> {
    Err(private_files_unsupported())
}

#[cfg(windows)]
pub(crate) fn validate_private_executable(path: &Path) -> Result<PrivateExecutableGuard> {
    reltio_windows_security::inspect_private_executable(path)
        .map(|guard| PrivateExecutableGuard { _inner: guard })
        .map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub(crate) fn validate_private_executable(path: &Path) -> Result<PrivateExecutableGuard> {
    unix::validate_private_executable(path).map(|file| PrivateExecutableGuard { _inner: file })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn validate_private_executable(_path: &Path) -> Result<PrivateExecutableGuard> {
    Err(private_files_unsupported())
}

#[cfg(windows)]
pub fn remove_private_file(path: &Path) -> Result<bool> {
    reltio_windows_security::remove_private_file(path).map_err(|error| map_windows_error(&error))
}

#[cfg(unix)]
pub fn remove_private_file(path: &Path) -> Result<bool> {
    unix::remove_private_file(path)
}

#[cfg(not(any(unix, windows)))]
pub fn remove_private_file(_path: &Path) -> Result<bool> {
    Err(private_files_unsupported())
}

#[cfg(not(any(unix, windows)))]
fn private_files_unsupported() -> ReltioError {
    ReltioError::new(
        "private_file_permissions_unsupported",
        ErrorCategory::Safety,
        "owner-only private files are unsupported on this platform",
    )
}

#[cfg(windows)]
fn map_windows_error(error: &reltio_windows_security::Error) -> ReltioError {
    use reltio_windows_security::ErrorKind;

    match error.kind() {
        ErrorKind::InvalidPath => ReltioError::usage(
            "local_path_unsupported",
            "the local path uses a refused Windows namespace or ambiguous name",
        ),
        ErrorKind::ReparsePoint => ReltioError::new(
            "symlink_refused",
            ErrorCategory::Safety,
            "refusing to follow a Windows reparse point",
        ),
        ErrorKind::NotRegularFile | ErrorKind::NotDirectory => ReltioError::usage(
            "local_file_not_regular",
            "the local path is not the required regular file or directory",
        ),
        ErrorKind::TooLarge => ReltioError::usage(
            "local_file_too_large",
            "the local file exceeds the 64 MB local input limit",
        ),
        ErrorKind::InsecurePolicy | ErrorKind::UnsafeAncestor | ErrorKind::ProcessContainment => ReltioError::new(
            "insecure_file_permissions",
            ErrorCategory::Safety,
            "the Windows path does not satisfy the private filesystem policy",
        )
        .with_hint(
            "Use a local, current-user-controlled path with protected non-inherited permissions.",
        ),
        ErrorKind::MultipleLinks => ReltioError::new(
            "hard_link_refused",
            ErrorCategory::Safety,
            "refusing a multiply linked private Windows file",
        ),
        ErrorKind::AlreadyExists
        | ErrorKind::Canceled
        | ErrorKind::TimedOut
        | ErrorKind::InvalidUnicode
        | ErrorKind::ConsoleUnavailable
        | ErrorKind::InputCleanup
        | ErrorKind::Io => {
            let fallback;
            let source = if let Some(source) = error.io_error() {
                source
            } else {
                fallback = std::io::Error::other(error.to_string());
                &fallback
            };
            ReltioError::io("the Windows filesystem operation failed", source)
        }
    }
}

#[cfg(windows)]
fn map_windows_bounded_read_error(
    error: &reltio_windows_security::Error,
    maximum_bytes: u64,
) -> ReltioError {
    if error.kind() == reltio_windows_security::ErrorKind::TooLarge {
        ReltioError::usage(
            "local_file_too_large",
            format!("the local file exceeds the {maximum_bytes}-byte local input limit"),
        )
    } else {
        map_windows_error(error)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::is_lock_contended;
    #[cfg(target_os = "macos")]
    use super::storage_path_is_same_or_descendant;

    #[test]
    fn fs2_contention_sentinel_is_recognized() {
        assert!(is_lock_contended(&fs2::lock_contended_error()));
    }

    #[test]
    fn unrelated_would_block_error_is_not_lock_contention() {
        let error = io::Error::new(io::ErrorKind::WouldBlock, "unrelated operation");

        assert!(!is_lock_contended(&error));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_storage_comparison_is_conservatively_case_insensitive() {
        assert!(
            storage_path_is_same_or_descendant(
                std::path::Path::new("/private/Cache/tokens"),
                std::path::Path::new("/PRIVATE/cache"),
            )
            .expect("ASCII case comparison")
        );
        assert!(
            !storage_path_is_same_or_descendant(
                std::path::Path::new("/private/CacheOther/tokens"),
                std::path::Path::new("/private/cache"),
            )
            .expect("component comparison does not use string prefixes")
        );
        let composed = std::path::PathBuf::from("/private/cach\u{e9}/tokens");
        let decomposed = std::path::PathBuf::from(format!("/private/cache{}", '\u{301}'));
        assert_eq!(
            storage_path_is_same_or_descendant(&composed, &decomposed)
                .expect_err("distinct Unicode spellings fail closed")
                .code,
            "storage_path_comparison_ambiguous"
        );
    }
}

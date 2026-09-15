use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use exacl::{AclEntryKind, Perm};
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::error::{ErrorCategory, ReltioError, Result};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const COMPARISON_FLAGS: OFlags = READ_FLAGS;
const WRITE_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

#[derive(Debug)]
struct DirectoryGuard {
    file: File,
    path: PathBuf,
}

impl DirectoryGuard {
    fn verify(&self) -> Result<()> {
        verify_ancestor(&self.path, &self.file)
    }
}

#[derive(Debug)]
struct GuardedParent {
    directories: Vec<DirectoryGuard>,
    leaf: OsString,
}

impl GuardedParent {
    fn open(path: &Path, create_missing: bool) -> Result<Self> {
        Self::open_internal(path, create_missing, false)?
            .ok_or_else(|| rustix_error("failed to open a local path ancestor", Errno::NOENT))
    }

    fn open_optional(path: &Path) -> Result<Option<Self>> {
        Self::open_internal(path, false, true)
    }

    fn open_internal(
        path: &Path,
        create_missing: bool,
        allow_missing: bool,
    ) -> Result<Option<Self>> {
        let resolved = resolve_trusted_path(path)?;
        let leaf = resolved.file_name().ok_or_else(|| {
            ReltioError::usage(
                "local_path_unsupported",
                "the local path must identify a file rather than a directory root",
            )
        })?;
        let parent = resolved.parent().ok_or_else(|| {
            ReltioError::usage("local_path_unsupported", "the local path has no parent")
        })?;
        let root = File::from(
            rfs::open("/", DIRECTORY_FLAGS, Mode::empty())
                .map_err(|error| rustix_error("failed to open the filesystem root", error))?,
        );
        let mut directories = vec![DirectoryGuard {
            file: root,
            path: PathBuf::from("/"),
        }];
        directories[0].verify()?;

        let mut current_path = PathBuf::from("/");
        for component in parent.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let current = directories
                .last()
                .unwrap_or_else(|| unreachable!("the root guard is always present"));
            let opened = match rfs::openat(&current.file, name, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(file) => File::from(file),
                Err(Errno::NOENT) if create_missing => {
                    match rfs::mkdirat(&current.file, name, Mode::RWXU) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(error) => {
                            return Err(rustix_error(
                                "failed to create a private directory",
                                error,
                            ));
                        }
                    }
                    let file = File::from(
                        rfs::openat(&current.file, name, DIRECTORY_FLAGS, Mode::empty()).map_err(
                            |error| map_component_open_error(&current_path.join(name), error),
                        )?,
                    );
                    let created_path = current_path.join(name);
                    secure_private_directory(&created_path, &file)?;
                    rfs::fsync(&current.file).map_err(|error| {
                        rustix_error("failed to sync a private directory parent", error)
                    })?;
                    file
                }
                Err(Errno::NOENT) if allow_missing => return Ok(None),
                Err(error) => {
                    return Err(map_component_open_error(&current_path.join(name), error));
                }
            };
            current_path.push(name);
            let guard = DirectoryGuard {
                file: opened,
                path: current_path.clone(),
            };
            guard.verify()?;
            directories.push(guard);
        }

        let guarded = Self {
            directories,
            leaf: leaf.to_os_string(),
        };
        guarded.revalidate()?;
        Ok(Some(guarded))
    }

    fn parent(&self) -> &File {
        &self
            .directories
            .last()
            .unwrap_or_else(|| unreachable!("the root guard is always present"))
            .file
    }

    fn path(&self) -> PathBuf {
        self.directories
            .last()
            .unwrap_or_else(|| unreachable!("the root guard is always present"))
            .path
            .join(&self.leaf)
    }

    fn revalidate(&self) -> Result<()> {
        for directory in &self.directories {
            directory.verify()?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PendingTemporaryFile {
    file: File,
    parent: File,
    name: OsString,
    identity: (u128, u128),
    armed: bool,
}

impl PendingTemporaryFile {
    fn new(file: File, parent: File, name: OsString) -> Result<Self> {
        let stat = rfs::fstat(&file)
            .map_err(|error| rustix_error("failed to inspect a private temporary file", error))?;
        Ok(Self {
            file,
            parent,
            name,
            identity: stat_identity(&stat),
            armed: true,
        })
    }

    fn verify_name(&self) -> Result<()> {
        let named = rfs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| rustix_error("failed to verify a private temporary file", error))?;
        let opened = rfs::fstat(&self.file)
            .map_err(|error| rustix_error("failed to inspect a private temporary file", error))?;
        if stat_identity(&named) != self.identity
            || stat_identity(&opened) != self.identity
            || opened.st_nlink != 1
            || !FileType::from_raw_mode(opened.st_mode).is_file()
        {
            return Err(ReltioError::new(
                "private_file_identity_changed",
                ErrorCategory::Safety,
                "the private temporary file changed identity before commit",
            ));
        }
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingTemporaryFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if rfs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| stat_identity(&stat) == self.identity)
        {
            let _ = rfs::unlinkat(&self.parent, &self.name, AtFlags::empty());
        }
    }
}

pub(super) fn ensure_private_parent(path: &Path) -> Result<()> {
    GuardedParent::open(path, true)?.revalidate()
}

pub(super) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let guarded = GuardedParent::open(path, true)?;
    validate_existing_destination(&guarded)?;

    let mut temporary = loop {
        let name = OsString::from(format!(".reltio-{:032x}.tmp", rand::random::<u128>()));
        match rfs::openat(
            guarded.parent(),
            &name,
            WRITE_FLAGS,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => {
                let file = File::from(file);
                break PendingTemporaryFile::new(
                    file,
                    guarded.parent().try_clone().map_err(|error| {
                        ReltioError::io("failed to retain the private directory", &error)
                    })?,
                    name,
                )?;
            }
            Err(Errno::EXIST) => {}
            Err(error) => {
                return Err(rustix_error(
                    "failed to create a private temporary file",
                    error,
                ));
            }
        }
    };
    let temporary_path = guarded
        .directories
        .last()
        .unwrap_or_else(|| unreachable!("the root guard is always present"))
        .path
        .join(&temporary.name);
    secure_private_file(&temporary_path, &temporary.file)?;
    temporary
        .file
        .write_all(bytes)
        .and_then(|()| temporary.file.sync_all())
        .map_err(|error| ReltioError::io("failed to write the private file", &error))?;
    verify_private_file(&temporary_path, &temporary.file)?;
    temporary.verify_name()?;
    guarded.revalidate()?;
    validate_existing_destination(&guarded)?;

    rfs::renameat(
        &temporary.parent,
        &temporary.name,
        guarded.parent(),
        &guarded.leaf,
    )
    .map_err(|error| rustix_error("failed to atomically install the private file", error))?;
    temporary.disarm();
    if let Err(error) = rfs::fsync(guarded.parent()) {
        return Err(
            rustix_error("failed to sync the committed private directory", error)
                .with_details(serde_json::json!({ "committed": true, "durability": "uncertain" })),
        );
    }
    Ok(())
}

pub(super) fn read_bounded(path: &Path, require_private: bool, limit: u64) -> Result<Vec<u8>> {
    read_bounded_optional(path, require_private, limit)?
        .ok_or_else(|| rustix_error("failed to open the local file", Errno::NOENT))
}

pub(super) fn read_bounded_optional(
    path: &Path,
    require_private: bool,
    limit: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(guarded) = GuardedParent::open_optional(path)? else {
        return Ok(None);
    };
    let file = match rfs::openat(guarded.parent(), &guarded.leaf, READ_FLAGS, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_leaf_open_error(&guarded.path(), error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect the local file", &error))?;
    if !metadata.is_file() {
        return Err(ReltioError::usage(
            "local_file_not_regular",
            format!("{} is not a regular file", guarded.path().display()),
        ));
    }
    if metadata.len() > limit {
        return Err(file_too_large(&guarded.path(), limit));
    }
    if require_private {
        verify_private_file(&guarded.path(), &file)?;
    } else {
        verify_named_identity(&guarded.path(), &file)?;
    }
    guarded.revalidate()?;

    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReltioError::io("failed to read the local file", &error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(file_too_large(&guarded.path(), limit));
    }
    guarded.revalidate()?;
    Ok(Some(bytes))
}

pub(super) fn open_private_lock(path: &Path) -> Result<File> {
    let guarded = GuardedParent::open(path, true)?;
    let (file, created) = match rfs::openat(
        guarded.parent(),
        &guarded.leaf,
        WRITE_FLAGS,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => (File::from(file), true),
        Err(Errno::EXIST) => (
            File::from(
                rfs::openat(
                    guarded.parent(),
                    &guarded.leaf,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| map_leaf_open_error(&guarded.path(), error))?,
            ),
            false,
        ),
        Err(error) => return Err(map_leaf_open_error(&guarded.path(), error)),
    };
    if created {
        secure_private_file(&guarded.path(), &file)?;
    }
    verify_private_file(&guarded.path(), &file)?;
    guarded.revalidate()?;
    Ok(file)
}

pub(super) fn path_permissions_are_private(path: &Path, metadata: &fs::Metadata) -> bool {
    #[allow(clippy::verbose_bit_mask)] // Octal permission masks communicate the policy directly.
    let mode_is_private = metadata.permissions().mode() & 0o077 == 0;
    mode_is_private
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && unix_acl_is_private(path)
}

pub(super) fn private_file_status(path: &Path) -> Result<Option<bool>> {
    let Some(guarded) = GuardedParent::open_optional(path)? else {
        return Ok(None);
    };
    let file = match rfs::openat(guarded.parent(), &guarded.leaf, READ_FLAGS, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_leaf_open_error(&guarded.path(), error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect the local file", &error))?;
    let private = metadata.is_file()
        && metadata.nlink() == 1
        && path_permissions_are_private(&guarded.path(), &metadata);
    verify_named_identity(&guarded.path(), &file)?;
    guarded.revalidate()?;
    Ok(Some(private))
}

pub(super) fn validate_private_executable(path: &Path) -> Result<File> {
    let guarded = GuardedParent::open(path, false)?;
    let file = File::from(
        rfs::openat(guarded.parent(), &guarded.leaf, READ_FLAGS, Mode::empty())
            .map_err(|error| map_leaf_open_error(&guarded.path(), error))?,
    );
    verify_private_file(&guarded.path(), &file)?;
    let mode = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect the credential process", &error))?
        .permissions()
        .mode();
    if mode & 0o100 == 0 {
        return Err(ReltioError::new(
            "credential_process_insecure",
            ErrorCategory::Safety,
            "the credential-process file is not executable by its owner",
        ));
    }
    let mut prefix = Vec::with_capacity(2);
    (&file)
        .take(2)
        .read_to_end(&mut prefix)
        .map_err(|error| ReltioError::io("failed to inspect the credential process", &error))?;
    if prefix == b"#!" {
        return Err(ReltioError::new(
            "credential_process_script_refused",
            ErrorCategory::Safety,
            "credential-process scripts are refused; configure a private native executable",
        ));
    }
    verify_private_file(&guarded.path(), &file)?;
    guarded.revalidate()?;
    Ok(file)
}

pub(super) fn remove_private_file(path: &Path) -> Result<bool> {
    let Some(guarded) = GuardedParent::open_optional(path)? else {
        return Ok(false);
    };
    let file = match rfs::openat(guarded.parent(), &guarded.leaf, READ_FLAGS, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(Errno::NOENT) => return Ok(false),
        Err(error) => return Err(map_leaf_open_error(&guarded.path(), error)),
    };
    verify_private_file(&guarded.path(), &file)?;
    guarded.revalidate()?;
    rfs::unlinkat(guarded.parent(), &guarded.leaf, AtFlags::empty())
        .map_err(|error| rustix_error("failed to remove a private file", error))?;
    rfs::fsync(guarded.parent()).map_err(|error| {
        rustix_error("failed to sync the committed private directory", error).with_details(
            serde_json::json!({ "committed": true, "removed": true, "durability": "uncertain" }),
        )
    })?;
    Ok(true)
}

fn resolve_trusted_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(ReltioError::usage(
            "local_path_unsupported",
            "empty local paths are not supported",
        ));
    }
    let input = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ReltioError::io("failed to resolve the current directory", &error))?
            .join(path)
    };
    let mut absolute = PathBuf::from("/");
    for component in input.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => absolute.push(name),
            Component::ParentDir => {
                return Err(ReltioError::usage(
                    "local_path_unsupported",
                    "parent-directory components are refused in security-sensitive local paths",
                ));
            }
            Component::Prefix(_) => {
                return Err(ReltioError::usage(
                    "local_path_unsupported",
                    "the local path uses an unsupported prefix",
                ));
            }
        }
    }

    resolve_trusted_root_alias(absolute)
}

pub(super) fn normalize_storage_path(path: &Path) -> Result<PathBuf> {
    resolve_trusted_path(path)
}

#[derive(Debug)]
struct StoragePathComponent {
    name: OsString,
    // Missing components remain lexical because there is no inode to compare.
    identity: Option<(u128, u128)>,
}

#[derive(Debug)]
struct StoragePathKey {
    components: Vec<StoragePathComponent>,
}

pub(super) fn storage_path_is_same_or_descendant(path: &Path, ancestor: &Path) -> Result<bool> {
    let path = storage_path_key(path)?;
    let ancestor = storage_path_key(ancestor)?;
    storage_keys_are_same_or_descendant(&path, &ancestor)
}

fn storage_path_key(path: &Path) -> Result<StoragePathKey> {
    let resolved = resolve_trusted_path(path)?;
    let names = resolved
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let root = File::from(
        rfs::open("/", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|error| rustix_error("failed to open the filesystem root", error))?,
    );
    let root_stat = rfs::fstat(&root)
        .map_err(|error| rustix_error("failed to inspect the filesystem root", error))?;
    let mut components = Vec::with_capacity(names.len().saturating_add(1));
    components.push(StoragePathComponent {
        name: OsString::new(),
        identity: Some(stat_identity(&root_stat)),
    });

    let mut parent = root;
    let mut current_path = PathBuf::from("/");
    let mut missing = false;
    for (index, name) in names.iter().enumerate() {
        if missing {
            components.push(StoragePathComponent {
                name: name.clone(),
                identity: None,
            });
            continue;
        }
        let child = match rfs::openat(&parent, name, COMPARISON_FLAGS, Mode::empty()) {
            Ok(child) => File::from(child),
            Err(Errno::NOENT) => {
                missing = true;
                components.push(StoragePathComponent {
                    name: name.clone(),
                    identity: None,
                });
                continue;
            }
            Err(error) => {
                return Err(map_storage_comparison_open_error(
                    &parent,
                    &current_path.join(name),
                    name,
                    error,
                ));
            }
        };
        let stat = rfs::fstat(&child)
            .map_err(|error| rustix_error("failed to inspect a storage path component", error))?;
        if index + 1 < names.len() && !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(ReltioError::usage(
                "local_file_not_regular",
                "a storage path ancestor is not a directory",
            ));
        }
        current_path.push(name);
        components.push(StoragePathComponent {
            name: name.clone(),
            identity: Some(stat_identity(&stat)),
        });
        parent = child;
    }
    Ok(StoragePathKey { components })
}

fn map_storage_comparison_open_error(
    parent: &File,
    path: &Path,
    name: &std::ffi::OsStr,
    error: Errno,
) -> ReltioError {
    if matches!(error, Errno::LOOP | Errno::NOTDIR)
        && rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode).is_symlink())
    {
        symlink_error(path)
    } else if error == Errno::NOTDIR {
        ReltioError::usage(
            "local_file_not_regular",
            "a storage path ancestor is not a directory",
        )
    } else {
        rustix_error("failed to inspect a storage path component", error)
    }
}

fn storage_keys_are_same_or_descendant(
    path: &StoragePathKey,
    ancestor: &StoragePathKey,
) -> Result<bool> {
    // Firmlinks and bind mounts can reach one inode through different-length
    // lexical chains, so align every shared physical ancestor before matching.
    for (ancestor_index, ancestor_component) in ancestor.components.iter().enumerate().rev() {
        let Some(ancestor_identity) = ancestor_component.identity else {
            continue;
        };
        for (path_index, path_component) in path.components.iter().enumerate().rev() {
            if path_component.identity != Some(ancestor_identity) {
                continue;
            }
            let path_tail = &path.components[path_index + 1..];
            let ancestor_tail = &ancestor.components[ancestor_index + 1..];
            if ancestor_tail.len() > path_tail.len() {
                continue;
            }
            let mut matches = true;
            for (path_component, ancestor_component) in path_tail.iter().zip(ancestor_tail.iter()) {
                if !storage_components_match(path_component, ancestor_component)? {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn storage_components_match(
    path: &StoragePathComponent,
    ancestor: &StoragePathComponent,
) -> Result<bool> {
    match (path.identity, ancestor.identity) {
        (Some(path), Some(ancestor)) => Ok(path == ancestor),
        _ => storage_component_names_equal(&path.name, &ancestor.name),
    }
}

fn storage_component_names_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;

    if left == right {
        return Ok(true);
    }
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.is_ascii() && right.is_ascii() {
        return Ok(left.eq_ignore_ascii_case(right));
    }
    Err(ReltioError::new(
        "storage_path_comparison_ambiguous",
        ErrorCategory::Safety,
        "Unix storage paths with distinct non-ASCII missing component spellings cannot be proven isolated",
    )
    .with_hint(
        "Use identical parent spelling and distinct ASCII names for config, cache, and state storage.",
    ))
}

fn resolve_trusted_root_alias(path: PathBuf) -> Result<PathBuf> {
    let mut names = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(first) = names.first() else {
        return Ok(path);
    };
    if !matches!(first.to_str(), Some("etc" | "home" | "tmp" | "var")) {
        return Ok(path);
    }
    let alias = Path::new("/").join(first);
    let metadata = match fs::symlink_metadata(&alias) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(path),
        Err(error) => {
            return Err(ReltioError::io(
                "failed to inspect a root filesystem alias",
                &error,
            ));
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(path);
    }
    if metadata.uid() != 0 {
        return Err(symlink_error(&alias));
    }
    let target = fs::read_link(&alias)
        .map_err(|error| ReltioError::io("failed to read a root filesystem alias", &error))?;
    let mut resolved = PathBuf::from("/");
    for component in target.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ReltioError::new(
                    "symlink_refused",
                    ErrorCategory::Safety,
                    "a root filesystem alias has an unsupported target",
                ));
            }
        }
    }
    for name in names.drain(1..) {
        resolved.push(name);
    }
    Ok(resolved)
}

fn verify_ancestor(path: &Path, file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect a local path ancestor", &error))?;
    if !metadata.is_dir() {
        return Err(ReltioError::usage(
            "local_file_not_regular",
            "a local path ancestor is not a directory",
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    let root_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
    if metadata.uid() != 0 && metadata.uid() != euid
        || mode & 0o022 != 0 && !root_sticky
        || !ancestor_acl_is_safe(path, root_sticky)
    {
        return Err(unsafe_ancestor_error(path));
    }
    verify_named_identity(path, file)
}

fn verify_named_identity(path: &Path, file: &File) -> Result<()> {
    let named = fs::symlink_metadata(path)
        .map_err(|error| ReltioError::io("failed to revalidate the local path", &error))?;
    if named.file_type().is_symlink() {
        return Err(symlink_error(path));
    }
    let opened = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect the opened local file", &error))?;
    if named.dev() != opened.dev() || named.ino() != opened.ino() {
        return Err(ReltioError::new(
            "local_path_identity_changed",
            ErrorCategory::Safety,
            format!("{} changed identity during validation", path.display()),
        ));
    }
    Ok(())
}

fn validate_existing_destination(guarded: &GuardedParent) -> Result<()> {
    match rfs::statat(guarded.parent(), &guarded.leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(rustix_error(
            "failed to inspect the private-file destination",
            error,
        )),
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode).is_symlink() {
                return Err(symlink_error(&guarded.path()));
            }
            if !FileType::from_raw_mode(stat.st_mode).is_file() {
                return Err(ReltioError::usage(
                    "local_file_not_regular",
                    format!("{} is not a regular file", guarded.path().display()),
                ));
            }
            let metadata = fs::symlink_metadata(guarded.path()).map_err(|error| {
                ReltioError::io("failed to inspect the private-file destination", &error)
            })?;
            if stat.st_nlink != 1 || !path_permissions_are_private(&guarded.path(), &metadata) {
                return Err(private_permissions_error(&guarded.path()));
            }
            Ok(())
        }
    }
}

fn secure_private_file(path: &Path, file: &File) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| clear_extended_acl(path, 0o600))
        .map_err(|error| ReltioError::io("failed to secure a private file", &error))?;
    verify_private_file(path, file)
}

fn verify_private_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect a private file", &error))?;
    if !metadata.is_file() {
        return Err(ReltioError::usage(
            "local_file_not_regular",
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.nlink() != 1 {
        return Err(ReltioError::new(
            "hard_link_refused",
            ErrorCategory::Safety,
            format!("refusing multiply linked private file {}", path.display()),
        ));
    }
    if !path_permissions_are_private(path, &metadata) {
        return Err(private_permissions_error(path));
    }
    verify_named_identity(path, file)
}

fn secure_private_directory(path: &Path, file: &File) -> Result<()> {
    rfs::fchmod(file, Mode::RWXU)
        .map_err(|error| rustix_error("failed to secure a private directory", error))?;
    clear_extended_acl(path, 0o700)
        .map_err(|error| ReltioError::io("failed to clear a private directory ACL", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| ReltioError::io("failed to inspect a private directory", &error))?;
    if !path_permissions_are_private(path, &metadata) {
        return Err(private_permissions_error(path));
    }
    verify_named_identity(path, file)
}

fn ancestor_acl_is_safe(path: &Path, root_sticky: bool) -> bool {
    let Ok(entries) = exacl::getfacl(path, None) else {
        return false;
    };
    entries.iter().all(|entry| {
        if entry.kind == AclEntryKind::Unknown {
            return false;
        }
        if !entry.allow || !acl_grants_mutation(entry.perms) {
            return true;
        }
        if entry.kind == AclEntryKind::User && entry.name.is_empty() {
            return true;
        }
        root_sticky && entry.name.is_empty()
    })
}

fn acl_grants_mutation(perms: Perm) -> bool {
    if perms.contains(Perm::WRITE) {
        return true;
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        if perms.intersects(
            Perm::DELETE
                | Perm::APPEND
                | Perm::DELETE_CHILD
                | Perm::WRITEATTR
                | Perm::WRITEEXTATTR
                | Perm::WRITESECURITY
                | Perm::CHOWN,
        ) {
            return true;
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        if perms.contains(Perm::WRITE_DATA) {
            return true;
        }
    }
    false
}

fn unix_acl_is_private(path: &Path) -> bool {
    let Ok(entries) = exacl::getfacl(path, None) else {
        return false;
    };
    entries.iter().all(|entry| {
        if entry.kind == AclEntryKind::Unknown {
            return false;
        }
        if !entry.allow || entry.perms.is_empty() {
            return true;
        }
        entry.kind == AclEntryKind::User && entry.name.is_empty()
    })
}

#[cfg(target_os = "macos")]
fn clear_extended_acl(path: &Path, _mode: u32) -> std::io::Result<()> {
    exacl::setfacl(&[path], &[], None)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn clear_extended_acl(path: &Path, mode: u32) -> std::io::Result<()> {
    let entries = exacl::from_mode(mode);
    exacl::setfacl(&[path], &entries, None)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn clear_extended_acl(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "extended ACL verification is unsupported on this Unix platform",
    ))
}

fn map_component_open_error(path: &Path, error: Errno) -> ReltioError {
    if matches!(error, Errno::LOOP | Errno::NOTDIR)
        && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        symlink_error(path)
    } else {
        rustix_error("failed to open a local path ancestor", error)
    }
}

fn map_leaf_open_error(path: &Path, error: Errno) -> ReltioError {
    if error == Errno::LOOP
        || fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        symlink_error(path)
    } else {
        rustix_error("failed to open the local file", error)
    }
}

fn rustix_error(operation: &str, error: Errno) -> ReltioError {
    ReltioError::io(operation, &std::io::Error::from(error))
}

fn symlink_error(path: &Path) -> ReltioError {
    ReltioError::new(
        "symlink_refused",
        ErrorCategory::Safety,
        format!("refusing non-privileged symbolic link {}", path.display()),
    )
}

fn unsafe_ancestor_error(path: &Path) -> ReltioError {
    ReltioError::new(
        "insecure_file_permissions",
        ErrorCategory::Safety,
        format!(
            "local path ancestor {} can be mutated by an untrusted user",
            path.display()
        ),
    )
    .with_hint("Use a current-user or root-owned path without group/other mutation rights.")
}

fn private_permissions_error(path: &Path) -> ReltioError {
    ReltioError::new(
        "insecure_file_permissions",
        ErrorCategory::Safety,
        format!(
            "{} is not owned and accessible only by the current user",
            path.display()
        ),
    )
    .with_hint(
        "Restrict the file to the current user and remove inherited or extended access entries.",
    )
}

fn file_too_large(path: &Path, limit: u64) -> ReltioError {
    ReltioError::usage(
        "local_file_too_large",
        format!(
            "{} exceeds the {}-byte local input limit",
            path.display(),
            limit
        ),
    )
}

fn stat_identity(stat: &Stat) -> (u128, u128) {
    #[cfg(target_os = "macos")]
    let device = u128::try_from(stat.st_dev).unwrap_or(u128::MAX);
    #[cfg(not(target_os = "macos"))]
    let device = u128::from(stat.st_dev);
    (device, u128::from(stat.st_ino))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing_component(name: &str, inode: u128) -> StoragePathComponent {
        StoragePathComponent {
            name: OsString::from(name),
            identity: Some((1, inode)),
        }
    }

    fn missing_component(name: &str) -> StoragePathComponent {
        StoragePathComponent {
            name: OsString::from(name),
            identity: None,
        }
    }

    #[test]
    fn bare_file_resolves_under_the_current_directory() {
        let expected = std::env::current_dir()
            .expect("current directory")
            .join("resume.json");
        assert_eq!(
            resolve_trusted_path(Path::new("resume.json")).expect("resolved path"),
            expected
        );
    }

    #[test]
    fn lexical_resolution_never_follows_non_root_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target directory");
        let link = directory.path().join("link");
        symlink(&target, &link).expect("directory symlink");
        let input = link.join("secret");

        let resolved = resolve_trusted_path(&input).expect("lexical path");
        assert_eq!(
            resolved.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("link"))
        );
        assert_eq!(
            read_bounded(&input, false, 64)
                .expect_err("descriptor traversal must refuse the link")
                .code,
            "symlink_refused"
        );
        assert_eq!(
            storage_path_is_same_or_descendant(&input, &target)
                .expect_err("storage comparison must not follow the link")
                .code,
            "symlink_refused"
        );
    }

    #[test]
    fn storage_comparison_aligns_physical_alias_ancestors() {
        let path = StoragePathKey {
            components: vec![
                existing_component("", 1),
                existing_component("mount", 2),
                existing_component("alias", 40),
                missing_component("cache"),
                missing_component("tokens"),
            ],
        };
        let ancestor = StoragePathKey {
            components: vec![
                existing_component("", 1),
                existing_component("real", 40),
                missing_component("cache"),
            ],
        };

        assert!(
            storage_keys_are_same_or_descendant(&path, &ancestor)
                .expect("synthetic mount identity comparison")
        );
    }

    #[test]
    fn storage_comparison_treats_missing_ascii_case_aliases_conservatively() {
        let path = StoragePathKey {
            components: vec![
                existing_component("", 1),
                existing_component("secure", 2),
                missing_component("cache"),
                missing_component("tokens"),
            ],
        };
        let ancestor = StoragePathKey {
            components: vec![
                existing_component("", 1),
                existing_component("secure", 2),
                missing_component("Cache"),
            ],
        };

        assert!(
            storage_keys_are_same_or_descendant(&path, &ancestor)
                .expect("missing case aliases compare conservatively")
        );
    }

    #[test]
    fn storage_comparison_recognizes_hard_linked_existing_paths() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let original = directory.path().join("original");
        let alias = directory.path().join("alias");
        fs::write(&original, b"storage identity").expect("write original");
        fs::hard_link(&original, &alias).expect("create hard link");

        assert!(
            storage_path_is_same_or_descendant(&alias, &original)
                .expect("hard-link identity comparison")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn storage_comparison_detects_users_firmlink_when_available() {
        let users = Path::new("/Users");
        let data_users = Path::new("/System/Volumes/Data/Users");
        let (Ok(users_metadata), Ok(data_metadata)) =
            (fs::metadata(users), fs::metadata(data_users))
        else {
            return;
        };
        if users_metadata.dev() != data_metadata.dev()
            || users_metadata.ino() != data_metadata.ino()
        {
            return;
        }
        let missing = "__reltio_storage_path_identity_test_missing__";
        if users.join(missing).exists() || data_users.join(missing).exists() {
            return;
        }

        assert!(
            storage_path_is_same_or_descendant(
                &users.join(missing).join("cache/tokens"),
                &data_users.join(missing).join("cache"),
            )
            .expect("APFS firmlink identity comparison")
        );
    }

    #[test]
    fn writing_private_file_preserves_existing_parent_mode() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1755))
            .expect("set parent permissions");
        let path = directory.path().join("resume.json");

        atomic_write_private(&path, b"{}").expect("private write");

        let directory_mode = fs::metadata(directory.path())
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o7777;
        let file_mode = fs::metadata(path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o1755);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn newly_created_parent_is_private() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("new").join("nested");
        atomic_write_private(&parent.join("state.json"), b"{}").expect("private write");
        let mode = fs::metadata(parent)
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn private_operations_refuse_final_and_intermediate_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real = directory.path().join("real");
        fs::create_dir(&real).expect("real directory");
        let target = real.join("target");
        fs::write(&target, b"secret").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("secure target");
        let file_link = directory.path().join("file-link");
        symlink(&target, &file_link).expect("file symlink");
        let directory_link = directory.path().join("directory-link");
        symlink(&real, &directory_link).expect("directory symlink");

        for result in [
            read_bounded(&file_link, true, 64).map(|_| ()),
            read_bounded(&directory_link.join("target"), true, 64).map(|_| ()),
            atomic_write_private(&directory_link.join("new"), b"secret"),
            open_private_lock(&directory_link.join("state.lock")).map(|_| ()),
        ] {
            assert_eq!(
                result.expect_err("symlink must fail").code,
                "symlink_refused"
            );
        }
        assert_eq!(fs::read(target).expect("target remains"), b"secret");
    }

    #[test]
    fn private_read_rejects_wrong_mode_and_hard_links() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config.toml");
        fs::write(&path, b"version = 1").expect("write config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("set broad mode");
        assert_eq!(
            read_bounded(&path, true, 64)
                .expect_err("broad permissions must fail")
                .code,
            "insecure_file_permissions"
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure mode");
        fs::hard_link(&path, directory.path().join("alias")).expect("hard link");
        assert_eq!(
            read_bounded(&path, true, 64)
                .expect_err("hard-linked private file must fail")
                .code,
            "hard_link_refused"
        );
    }

    #[test]
    fn unsafe_writable_ancestor_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("unsafe");
        fs::create_dir(&parent).expect("create parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).expect("broad parent");
        let path = parent.join("config");
        fs::write(&path, b"secret").expect("write file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure file");

        assert_eq!(
            read_bounded(&path, true, 64)
                .expect_err("writable ancestor must fail")
                .code,
            "insecure_file_permissions"
        );
    }

    #[test]
    fn pinned_parent_detects_textual_replacement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("parent");
        fs::create_dir(&parent).expect("create parent");
        let path = parent.join("state");
        let guarded = GuardedParent::open(&path, false).expect("guard parent");
        let moved = directory.path().join("moved");
        fs::rename(&parent, &moved).expect("rename parent");
        fs::create_dir(&parent).expect("replacement parent");

        assert_eq!(
            guarded
                .revalidate()
                .expect_err("replacement must be detected")
                .code,
            "local_path_identity_changed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_read_rejects_extended_allow_acl() {
        use exacl::AclEntry;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("secret");
        fs::write(&path, b"secret").expect("write secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode");
        exacl::setfacl(
            &[path.as_path()],
            &[AclEntry::allow_group("everyone", Perm::READ, None)],
            None,
        )
        .expect("set extended ACL");

        assert_eq!(
            read_bounded(&path, true, 64)
                .expect_err("extended allow ACL must fail")
                .code,
            "insecure_file_permissions"
        );
    }
}

#![cfg(windows)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::error::Error as StdError;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

#[allow(unsafe_code)]
mod ffi;

/// Stable classifications consumed by `reltio-client` without exposing paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidPath,
    ReparsePoint,
    NotRegularFile,
    NotDirectory,
    TooLarge,
    InsecurePolicy,
    UnsafeAncestor,
    MultipleLinks,
    AlreadyExists,
    ProcessContainment,
    Canceled,
    TimedOut,
    InvalidUnicode,
    ConsoleUnavailable,
    InputCleanup,
    Io,
}

/// A path-redacted Windows filesystem error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    operation: &'static str,
    source: Option<std::io::Error>,
}

impl Error {
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn io_error(&self) -> Option<&std::io::Error> {
        self.source.as_ref()
    }

    const fn policy(kind: ErrorKind, operation: &'static str) -> Self {
        Self {
            kind,
            operation,
            source: None,
        }
    }

    fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            operation,
            source: Some(source),
        }
    }

    fn from_win32(operation: &'static str, code: u32) -> Self {
        Self::io(
            operation,
            std::io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        )
    }

    fn is_not_found(&self) -> bool {
        matches!(
            self.source.as_ref().and_then(std::io::Error::raw_os_error),
            Some(2 | 3)
        )
    }

    fn is_already_exists(&self) -> bool {
        self.kind == ErrorKind::AlreadyExists
            || matches!(
                self.source.as_ref().and_then(std::io::Error::raw_os_error),
                Some(80 | 183)
            )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            write!(formatter, "{}: {source}", self.operation)
        } else {
            formatter.write_str(self.operation)
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

const WINDOWS_INPUT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const VK_BACK: u16 = 0x08;
const VK_RETURN: u16 = 0x0D;
const VK_MENU: u16 = 0x12;
const VK_C: u16 = 0x43;
const LEFT_CTRL_PRESSED: u32 = 0x0008;
const RIGHT_CTRL_PRESSED: u32 = 0x0004;

#[derive(Debug, Default)]
struct HiddenInputState {
    value: Zeroizing<String>,
    pending_high_surrogate: Option<(u16, u16)>,
}

impl HiddenInputState {
    fn apply(&mut self, event: ffi::ConsoleInputEvent, maximum_bytes: u64) -> Result<bool> {
        let ffi::ConsoleInputEvent::Key {
            key_down,
            repeat_count,
            virtual_key_code,
            unicode_char,
            control_key_state,
        } = event
        else {
            return Ok(false);
        };
        let alt_numpad_character = !key_down && virtual_key_code == VK_MENU && unicode_char != 0;
        if !key_down && !alt_numpad_character {
            return Ok(false);
        }
        if virtual_key_code == VK_RETURN {
            if self.pending_high_surrogate.is_some() {
                return Err(Error::policy(
                    ErrorKind::InvalidUnicode,
                    "hidden Windows credential input ended inside a UTF-16 surrogate pair",
                ));
            }
            return Ok(true);
        }
        if virtual_key_code == VK_BACK {
            for _ in 0..repeat_count.max(1) {
                if self.pending_high_surrogate.take().is_none() {
                    self.value.pop();
                }
            }
            return Ok(false);
        }
        if unicode_char == 0 {
            return Ok(false);
        }
        let control_pressed = control_key_state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0;
        if unicode_char == 3 || control_pressed && virtual_key_code == VK_C {
            return Err(Error::policy(
                ErrorKind::Canceled,
                "hidden Windows credential input was canceled",
            ));
        }
        if control_pressed && unicode_char == 21 {
            self.value.clear();
            self.pending_high_surrogate = None;
            return Ok(false);
        }
        if control_pressed && unicode_char == 23 {
            for _ in 0..repeat_count.max(1) {
                while self
                    .value
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace)
                {
                    self.value.pop();
                }
                while self
                    .value
                    .chars()
                    .next_back()
                    .is_some_and(|character| !character.is_whitespace())
                {
                    self.value.pop();
                }
            }
            return Ok(false);
        }
        self.push_utf16(unicode_char, repeat_count.max(1), maximum_bytes)?;
        Ok(false)
    }

    fn push_utf16(&mut self, unit: u16, repeat_count: u16, maximum_bytes: u64) -> Result<()> {
        let character = if (0xD800..=0xDBFF).contains(&unit) {
            if self.pending_high_surrogate.is_some() {
                return Err(Error::policy(
                    ErrorKind::InvalidUnicode,
                    "hidden Windows credential input contains consecutive high surrogates",
                ));
            }
            self.pending_high_surrogate = Some((unit, repeat_count));
            return Ok(());
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            let (high, high_repeat_count) =
                self.pending_high_surrogate.take().ok_or_else(|| {
                    Error::policy(
                        ErrorKind::InvalidUnicode,
                        "hidden Windows credential input contains an unmatched low surrogate",
                    )
                })?;
            if repeat_count != high_repeat_count {
                return Err(Error::policy(
                    ErrorKind::InvalidUnicode,
                    "hidden Windows credential input has mismatched surrogate repeat counts",
                ));
            }
            char::decode_utf16([high, unit])
                .next()
                .and_then(std::result::Result::ok)
                .ok_or_else(|| {
                    Error::policy(
                        ErrorKind::InvalidUnicode,
                        "hidden Windows credential input contains invalid UTF-16",
                    )
                })?
        } else {
            if self.pending_high_surrogate.take().is_some() {
                return Err(Error::policy(
                    ErrorKind::InvalidUnicode,
                    "hidden Windows credential input contains an unmatched high surrogate",
                ));
            }
            char::from_u32(u32::from(unit)).ok_or_else(|| {
                Error::policy(
                    ErrorKind::InvalidUnicode,
                    "hidden Windows credential input contains invalid UTF-16",
                )
            })?
        };
        let repeated_bytes = character
            .len_utf8()
            .saturating_mul(usize::from(repeat_count));
        let next_length = self.value.len().saturating_add(repeated_bytes);
        if u64::try_from(next_length).unwrap_or(u64::MAX) > maximum_bytes {
            return Err(Error::policy(
                ErrorKind::TooLarge,
                "hidden Windows credential input exceeds its byte limit",
            ));
        }
        for _ in 0..repeat_count {
            self.value.push(character);
        }
        Ok(())
    }

    fn finish(mut self) -> String {
        std::mem::take(&mut *self.value)
    }
}

/// Reads one non-echoing line from the native Windows console without changing
/// shared console modes or leaving a blocking read behind.
///
/// # Errors
///
/// Returns a typed, path-free error when no native console is available, the
/// deadline or cancellation callback fires, input is invalid or oversized, or
/// abandoned console input cannot be cleared safely.
pub fn read_hidden_console_line_until(
    deadline: Instant,
    maximum_bytes: u64,
    is_cancelled: impl Fn() -> bool,
) -> Result<String> {
    let input = ffi::open_console_input()?;
    let mut state = HiddenInputState::default();
    loop {
        let control_error = if is_cancelled() {
            Some(Error::policy(
                ErrorKind::Canceled,
                "hidden Windows credential input was canceled",
            ))
        } else if Instant::now() >= deadline {
            Some(Error::policy(
                ErrorKind::TimedOut,
                "hidden Windows credential input exceeded its deadline",
            ))
        } else {
            None
        };
        if let Some(error) = control_error {
            return match input.flush() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = WINDOWS_INPUT_POLL_INTERVAL.min(remaining);
        let wait_millis = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
        if wait_millis == 0 {
            std::thread::yield_now();
            continue;
        }
        let available = match input.wait(wait_millis) {
            Ok(available) => available,
            Err(error) => {
                return match input.flush() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                };
            }
        };
        if !available {
            continue;
        }
        if is_cancelled() {
            return match input.flush() {
                Ok(()) => Err(Error::policy(
                    ErrorKind::Canceled,
                    "hidden Windows credential input was canceled",
                )),
                Err(cleanup) => Err(cleanup),
            };
        }
        let event = match input.read_event_nowait() {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(error) => {
                return match input.flush() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                };
            }
        };
        match state.apply(event, maximum_bytes) {
            Ok(true) => return Ok(state.finish()),
            Ok(false) => {}
            Err(error) => {
                return match input.flush() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                };
            }
        }
    }
}

/// A regular-file reader that cannot return more than its configured bound.
#[derive(Debug)]
pub struct BoundedFile {
    file: File,
    maximum_bytes: u64,
    initial_length: u64,
}

/// Retains the validated executable and ancestor handles while a process starts.
#[derive(Debug)]
pub struct PrivateExecutableGuard {
    _file: File,
    _directories: DirectoryGuards,
}

/// Owns a kill-on-close Job Object for one suspended credential process tree.
#[derive(Debug)]
pub struct CredentialProcessJob {
    inner: ffi::CredentialProcessJob,
}

impl CredentialProcessJob {
    /// Configures a command to start suspended and prepares its containment Job.
    ///
    /// # Errors
    ///
    /// Returns a process-containment error if the Job cannot be created or
    /// configured before process creation.
    pub fn prepare(command: &mut tokio::process::Command) -> Result<Self> {
        let inner = ffi::create_credential_process_job()?;
        command.creation_flags(ffi::credential_process_creation_flags());
        command.kill_on_drop(true);
        Ok(Self { inner })
    }

    /// Assigns the suspended child to this Job and resumes its sole primary thread.
    ///
    /// # Errors
    ///
    /// Returns a containment error if assignment, thread identity validation,
    /// or the single resume transition cannot be proven. Windows reports the
    /// prior suspend count only after attempting the resume, so an unexpected
    /// count leaves the contained child's execution state uncertain.
    pub fn assign_and_resume(&self, child: &tokio::process::Child) -> Result<()> {
        ffi::assign_credential_process_and_resume(&self.inner, child)
    }

    /// Terminates every process currently associated with this Job.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if Windows refuses Job termination.
    pub fn terminate(&self) -> Result<()> {
        ffi::terminate_credential_process_job(&self.inner)
    }
}

impl BoundedFile {
    /// Reads through the held handle while enforcing the configured maximum.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::TooLarge`] if the file grew after open, or
    /// [`ErrorKind::Io`] if the handle cannot be read.
    pub fn read_all(self) -> Result<Vec<u8>> {
        let capacity =
            usize::try_from(self.initial_length.min(self.maximum_bytes)).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(capacity);
        let read_limit = self.maximum_bytes.saturating_add(1);
        self.file
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::io("failed to read the local file", error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.maximum_bytes {
            return Err(Error::policy(
                ErrorKind::TooLarge,
                "the local file grew beyond its configured limit",
            ));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
struct DirectoryGuards {
    handles: Vec<File>,
}

impl DirectoryGuards {
    fn revalidate(&self, context: &ffi::SecurityContext) -> Result<()> {
        for handle in &self.handles {
            validate_directory_handle(handle)?;
            ffi::inspect_ancestor_policy(handle, context)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PendingTemporaryFile {
    file: File,
    path: PathBuf,
    armed: bool,
}

impl PendingTemporaryFile {
    fn new(file: File, path: PathBuf) -> Self {
        Self {
            file,
            path,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingTemporaryFile {
    fn drop(&mut self) {
        if self.armed && ffi::delete_on_close(&self.file).is_err() {
            // A private empty orphan is safer than leaving secret bytes if a
            // filesystem refuses handle-based delete disposition.
            let _ = self.file.set_len(0);
            let _ = self.file.sync_all();
        }
    }
}

/// Ensures every missing directory above `path` is private at creation.
///
/// # Errors
///
/// Returns a typed policy or I/O error if the path or any ancestor cannot be
/// validated, or if a missing directory cannot be created privately.
pub fn ensure_private_parent(path: &Path) -> Result<()> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = ensure_directory_tree(parent, &context)?;
    guards.revalidate(&context)
}

/// Writes a user-only file through a flushed same-directory atomic rename.
///
/// # Errors
///
/// Returns a typed policy or I/O error if path validation, private creation,
/// flushing, pre-commit verification, or replacement fails.
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = ensure_directory_tree(parent, &context)?;
    guards.revalidate(&context)?;

    if let Some(existing) = open_existing_for_inspection(&path)? {
        validate_private_file_handle(&existing, &context)?;
    }

    let mut temporary = loop {
        let name = format!(".reltio-{:032x}.tmp", rand::random::<u128>());
        let temporary_path = parent.join(name);
        match ffi::create_private_temporary(&temporary_path, &context) {
            Ok(file) => break PendingTemporaryFile::new(file, temporary_path),
            Err(error) if error.is_already_exists() => continue,
            Err(error) => return Err(error),
        }
    };

    validate_private_file_handle(&temporary.file, &context)?;
    temporary
        .file
        .write_all(bytes)
        .and_then(|()| temporary.file.sync_all())
        .map_err(|error| Error::io("failed to flush the private temporary file", error))?;
    validate_private_file_handle(&temporary.file, &context)?;
    guards.revalidate(&context)?;

    if let Some(existing) = open_existing_for_inspection(&path)? {
        validate_private_file_handle(&existing, &context)?;
    }

    ffi::move_replace(&temporary.file, &temporary.path, &path)?;
    // A successful rename is the commit point. Cleanup must never delete the
    // installed destination if any later diagnostic were to fail.
    temporary.disarm();
    Ok(())
}

/// Opens one regular file through a no-follow, same-handle, bounded read path.
///
/// # Errors
///
/// Returns a typed policy, size, or I/O error if the path, ancestors, handle,
/// object type, or requested private policy cannot be validated.
pub fn open_bounded_file(
    path: &Path,
    maximum_bytes: u64,
    require_private: bool,
) -> Result<BoundedFile> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = validate_directory_tree(parent, &context)?;
    let file = ffi::open_file_for_read(&path)?;
    let information = validate_regular_handle(&file)?;
    if require_private {
        ffi::inspect_private_policy(&file, &context, ffi::ObjectKind::File)?;
        require_single_link(information.number_of_links)?;
    }
    if information.length > maximum_bytes {
        return Err(Error::policy(
            ErrorKind::TooLarge,
            "the local file exceeds its configured limit",
        ));
    }
    guards.revalidate(&context)?;
    Ok(BoundedFile {
        file,
        maximum_bytes,
        initial_length: information.length,
    })
}

/// Securely opens an optional bounded file without a path-based existence probe.
///
/// # Errors
///
/// Returns a typed policy or I/O error for any condition other than a missing
/// ancestor or final file.
pub fn open_optional_bounded_file(
    path: &Path,
    maximum_bytes: u64,
    require_private: bool,
) -> Result<Option<BoundedFile>> {
    match open_bounded_file(path, maximum_bytes, require_private) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}

/// Validates and retains the private policy required for an executable.
///
/// Windows executable identity is determined by its absolute file name; the
/// caller separately requires an explicit `.exe` extension. The returned guard
/// excludes writes, deletion, and ancestor replacement and must remain live
/// until process creation has returned.
///
/// # Errors
///
/// Returns a typed policy or I/O error if the file is absent or not private.
pub fn inspect_private_executable(path: &Path) -> Result<PrivateExecutableGuard> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the executable path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let directories = validate_directory_tree(parent, &context)?;
    let file = ffi::open_file_for_inspection(&path)?;
    validate_private_file_handle(&file, &context)?;
    directories.revalidate(&context)?;
    let executable_directory = directories.handles.last().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the executable path has no guarded parent directory",
        )
    })?;
    ffi::inspect_executable_directory_policy(executable_directory, &context)?;
    require_dedicated_executable_directory(parent)?;
    ffi::reset_process_dll_directory()?;
    Ok(PrivateExecutableGuard {
        _file: file,
        _directories: directories,
    })
}

fn require_dedicated_executable_directory(directory: &Path) -> Result<()> {
    let mut entries = fs::read_dir(directory).map_err(|error| {
        Error::io(
            "failed to enumerate the Windows executable directory",
            error,
        )
    })?;
    let first = entries
        .next()
        .transpose()
        .map_err(|error| Error::io("failed to inspect the Windows executable directory", error))?;
    let second = entries
        .next()
        .transpose()
        .map_err(|error| Error::io("failed to inspect the Windows executable directory", error))?;
    if first.is_none() || second.is_some() {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows credential-process directory must contain only its executable",
        ));
    }
    Ok(())
}

/// Removes one verified private file through the same handle used for policy inspection.
///
/// # Errors
///
/// Returns a typed policy or I/O error if path validation, inspection, or the
/// handle-based delete disposition fails.
pub fn remove_private_file(path: &Path) -> Result<bool> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = match validate_directory_tree(parent, &context) {
        Ok(guards) => guards,
        Err(error) if error.is_not_found() => return Ok(false),
        Err(error) => return Err(error),
    };
    let file = match ffi::open_private_file_for_delete(&path) {
        Ok(file) => file,
        Err(error) if error.is_not_found() => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_private_file_handle(&file, &context)?;
    guards.revalidate(&context)?;
    ffi::delete_on_close(&file)?;
    drop(file);
    Ok(true)
}

/// Reports whether an optional file satisfies the private-file policy.
///
/// # Errors
///
/// Returns a typed path or I/O error when the path cannot be inspected safely.
pub fn private_file_status(path: &Path) -> Result<Option<bool>> {
    match open_optional_bounded_file(path, u64::MAX, true) {
        Ok(Some(file)) => {
            drop(file);
            Ok(Some(true))
        }
        Ok(None) => Ok(None),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::InsecurePolicy | ErrorKind::MultipleLinks
            ) =>
        {
            Ok(Some(false))
        }
        Err(error) => Err(error),
    }
}

/// Creates a private lock or opens an existing lock without changing its ACL.
///
/// # Errors
///
/// Returns a typed policy or I/O error if the path is unsafe, private creation
/// fails, or an existing lock is not a private single-link regular file.
pub fn open_private_lock(path: &Path) -> Result<File> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = ensure_directory_tree(parent, &context)?;
    guards.revalidate(&context)?;

    let file = match ffi::create_private_lock(&path, &context) {
        Ok(file) => file,
        Err(error) if error.is_already_exists() => ffi::open_existing_lock(&path)?,
        Err(error) => return Err(error),
    };
    validate_private_file_handle(&file, &context)?;
    guards.revalidate(&context)?;
    Ok(file)
}

/// Applies the complete private-file policy to one already-open handle.
///
/// # Errors
///
/// Returns a typed policy or I/O error if the handle is not a private,
/// user-owned, single-link regular disk file.
pub fn inspect_private_file_handle(file: &File) -> Result<()> {
    let context = ffi::SecurityContext::new()?;
    validate_private_file_handle(file, &context)
}

/// Opens and checks a directory through the same handle used for ACL inspection.
///
/// # Errors
///
/// Returns a typed policy or I/O error if the path, ancestors, directory type,
/// reparse state, owner, or DACL cannot be validated.
pub fn inspect_private_directory(path: &Path) -> Result<()> {
    let path = normalize_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the local path has no parent directory",
        )
    })?;
    let context = ffi::SecurityContext::new()?;
    let guards = validate_directory_tree(parent, &context)?;
    let directory = ffi::open_directory(&path)?;
    validate_private_directory_handle(&directory, &context)?;
    guards.revalidate(&context)
}

fn open_existing_for_inspection(path: &Path) -> Result<Option<File>> {
    match ffi::open_file_for_inspection(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}

fn ensure_directory_tree(
    directory: &Path,
    context: &ffi::SecurityContext,
) -> Result<DirectoryGuards> {
    let components = directory_chain(directory)?;
    let mut handles = Vec::with_capacity(components.len());

    for (index, component) in components.iter().enumerate() {
        match ffi::open_directory(component) {
            Ok(handle) => {
                validate_directory_handle(&handle)?;
                ffi::inspect_ancestor_policy(&handle, context)?;
                handles.push(handle);
            }
            Err(error) if error.is_not_found() && index > 0 => {
                match ffi::create_private_directory(component, context) {
                    Ok(()) => {}
                    Err(error) if error.is_already_exists() => {}
                    Err(error) => return Err(error),
                }
                let handle = ffi::open_directory(component)?;
                validate_private_directory_handle(&handle, context)?;
                handles.push(handle);
            }
            Err(error) => return Err(error),
        }
    }

    Ok(DirectoryGuards { handles })
}

fn validate_directory_tree(
    directory: &Path,
    context: &ffi::SecurityContext,
) -> Result<DirectoryGuards> {
    let mut handles = Vec::new();
    for component in directory_chain(directory)? {
        let handle = ffi::open_directory(&component)?;
        validate_directory_handle(&handle)?;
        ffi::inspect_ancestor_policy(&handle, context)?;
        handles.push(handle);
    }
    Ok(DirectoryGuards { handles })
}

fn validate_private_file_handle(file: &File, context: &ffi::SecurityContext) -> Result<()> {
    let information = validate_regular_handle(file)?;
    ffi::inspect_private_policy(file, context, ffi::ObjectKind::File)?;
    require_single_link(information.number_of_links)
}

fn validate_private_directory_handle(file: &File, context: &ffi::SecurityContext) -> Result<()> {
    validate_directory_handle(file)?;
    ffi::inspect_private_policy(file, context, ffi::ObjectKind::Directory)
}

fn validate_regular_handle(file: &File) -> Result<ffi::HandleInformation> {
    let information = ffi::handle_information(file)?;
    if information.reparse_point {
        return Err(Error::policy(
            ErrorKind::ReparsePoint,
            "reparse points are refused for local files",
        ));
    }
    if information.directory {
        return Err(Error::policy(
            ErrorKind::NotRegularFile,
            "the local path is not a regular file",
        ));
    }
    Ok(information)
}

fn validate_directory_handle(file: &File) -> Result<ffi::HandleInformation> {
    let information = ffi::handle_information(file)?;
    if information.reparse_point {
        return Err(Error::policy(
            ErrorKind::ReparsePoint,
            "reparse points are refused in local paths",
        ));
    }
    if !information.directory {
        return Err(Error::policy(
            ErrorKind::NotDirectory,
            "a local path component is not a directory",
        ));
    }
    Ok(information)
}

fn require_single_link(number_of_links: u32) -> Result<()> {
    if number_of_links == 1 {
        Ok(())
    } else {
        Err(Error::policy(
            ErrorKind::MultipleLinks,
            "multiply linked private files are refused",
        ))
    }
}

/// Resolves a local path lexically without following reparse points or
/// converting it to a verbatim namespace.
///
/// # Errors
///
/// Returns a policy or I/O error when the path is ambiguous, remote, or does
/// not reside on a fixed local drive.
pub fn normalize_local_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "empty local paths are refused",
        ));
    }
    if path.has_root() && !path.is_absolute() {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "rooted paths without a drive are refused",
        ));
    }
    if matches!(path.components().next(), Some(Component::Prefix(_))) && !path.is_absolute() {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "drive-relative paths are refused",
        ));
    }
    validate_terminal_component(path)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| Error::io("failed to resolve the current directory", error))?
            .join(path)
    };

    let mut components = candidate.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            Prefix::Verbatim(_)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::VerbatimDisk(_)
            | Prefix::DeviceNS(_)
            | Prefix::UNC(_, _) => {
                return Err(Error::policy(
                    ErrorKind::InvalidPath,
                    "UNC, device, and verbatim paths are refused",
                ));
            }
        },
        _ => {
            return Err(Error::policy(
                ErrorKind::InvalidPath,
                "drive-relative and rooted-without-drive paths are refused",
            ));
        }
    };
    ffi::require_fixed_local_drive(drive)?;
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "drive-relative paths are refused",
        ));
    }

    let mut names = Vec::<OsString>::new();
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if names.pop().is_none() {
                    return Err(Error::policy(
                        ErrorKind::InvalidPath,
                        "local paths may not traverse above their drive root",
                    ));
                }
            }
            Component::Normal(name) => {
                validate_component(name)?;
                names.push(name.to_os_string());
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(Error::policy(
                    ErrorKind::InvalidPath,
                    "unexpected Windows path prefix",
                ));
            }
        }
    }

    let mut normalized = PathBuf::from(format!("{}:\\", char::from(drive)));
    for name in names {
        normalized.push(name);
    }
    Ok(normalized)
}

/// Returns whether `path` is the same as or beneath `ancestor` using Windows'
/// ordinal case-insensitive component comparison.
///
/// # Errors
///
/// Returns a policy or I/O error if either path is not an ordinary fixed-drive
/// local path or Windows cannot compare a component.
pub fn local_path_is_same_or_descendant(path: &Path, ancestor: &Path) -> Result<bool> {
    let path = local_path_comparison_key(path)?;
    let ancestor = local_path_comparison_key(ancestor)?;
    let mut path_components = path.components();
    for ancestor_component in ancestor.components() {
        let Some(path_component) = path_components.next() else {
            return Ok(false);
        };
        if !ffi::os_str_eq_ordinal_ignore_case(
            path_component.as_os_str(),
            ancestor_component.as_os_str(),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn local_path_comparison_key(path: &Path) -> Result<PathBuf> {
    let normalized = normalize_local_path(path)?;
    validate_storage_comparison_path(&normalized)?;
    let chain = directory_chain(&normalized)?;
    let mut deepest = None;
    for (index, component_path) in chain.iter().enumerate() {
        let handle = match ffi::open_path_for_comparison(component_path) {
            Ok(handle) => handle,
            Err(error) if error.is_not_found() => break,
            Err(error) => return Err(error),
        };
        let information = ffi::handle_information(&handle)?;
        if information.reparse_point {
            return Err(Error::policy(
                ErrorKind::ReparsePoint,
                "reparse points are refused in local path comparisons",
            ));
        }
        if index + 1 < chain.len() && !information.directory {
            return Err(Error::policy(
                ErrorKind::NotDirectory,
                "a local path comparison component is not a directory",
            ));
        }
        deepest = Some((
            index,
            PathBuf::from(ffi::final_normalized_nt_path(&handle)?),
        ));
    }
    let (index, mut key) = deepest.ok_or_else(|| {
        Error::policy(
            ErrorKind::InvalidPath,
            "the fixed-drive root could not be resolved for path comparison",
        )
    })?;
    for component_path in &chain[index + 1..] {
        let name = component_path.file_name().ok_or_else(|| {
            Error::policy(
                ErrorKind::InvalidPath,
                "a local path comparison suffix was ambiguous",
            )
        })?;
        key.push(name);
    }
    Ok(key)
}

fn validate_storage_comparison_path(path: &Path) -> Result<()> {
    if path.components().any(|component| {
        matches!(component, Component::Normal(name) if name.encode_wide().any(|unit| unit == u16::from(b'~')))
    }) {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "tilde components are refused in storage paths because 8.3 aliases cannot be resolved safely",
        ));
    }
    Ok(())
}

fn validate_terminal_component(path: &Path) -> Result<()> {
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let terminal = wide
        .rsplit(|character| matches!(*character, 47 | 92))
        .next()
        .unwrap_or_default();
    let drive_root = path.is_absolute() && path.components().count() == 2;
    if (!drive_root && terminal.is_empty())
        || terminal == [u16::from(b'.')]
        || terminal == [u16::from(b'.'), u16::from(b'.')]
    {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "ambiguous terminal path components are refused",
        ));
    }
    Ok(())
}

fn validate_component(component: &OsStr) -> Result<()> {
    let wide = component.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide.iter().any(|character| {
            *character <= 31
                || matches!(
                    char::from_u32(u32::from(*character)),
                    Some('"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|')
                )
        })
        || matches!(wide.last(), Some(character) if *character == u16::from(b'.') || *character == u16::from(b' '))
    {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "alternate data streams and ambiguous Windows names are refused",
        ));
    }
    let text = String::from_utf16(&wide).map_err(|_| {
        Error::policy(
            ErrorKind::InvalidPath,
            "ill-formed Unicode is refused in security-sensitive Windows paths",
        )
    })?;
    let stem = text
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        || matches!(
            stem.as_str(),
            "COM\u{b9}" | "COM\u{b2}" | "COM\u{b3}" | "LPT\u{b9}" | "LPT\u{b2}" | "LPT\u{b3}"
        );
    if reserved {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "Windows device names are refused",
        ));
    }
    Ok(())
}

fn directory_chain(directory: &Path) -> Result<Vec<PathBuf>> {
    let normalized = normalize_local_path(directory)?;
    let mut components = normalized.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            _ => {
                return Err(Error::policy(
                    ErrorKind::InvalidPath,
                    "non-disk paths are refused",
                ));
            }
        },
        _ => {
            return Err(Error::policy(
                ErrorKind::InvalidPath,
                "an absolute disk path is required",
            ));
        }
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "an absolute disk path is required",
        ));
    }

    let mut current = PathBuf::from(format!("{}:\\", char::from(drive)));
    let mut chain = vec![current.clone()];
    for component in components {
        if let Component::Normal(name) = component {
            current.push(name);
            chain.push(current.clone());
        } else {
            return Err(Error::policy(
                ErrorKind::InvalidPath,
                "the normalized path contained an unexpected component",
            ));
        }
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::windows::fs::{OpenOptionsExt, symlink_dir, symlink_file};
    use std::process::Command;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_WRITE_DATA,
    };

    const JOB_TEST_ROLE: &str = "RELTIO_WINDOWS_JOB_TEST_ROLE";
    const JOB_TEST_DIRECTORY: &str = "RELTIO_WINDOWS_JOB_TEST_DIRECTORY";

    fn key_event(
        key_down: bool,
        repeat_count: u16,
        virtual_key_code: u16,
        unicode_char: u16,
    ) -> ffi::ConsoleInputEvent {
        ffi::ConsoleInputEvent::Key {
            key_down,
            repeat_count,
            virtual_key_code,
            unicode_char,
            control_key_state: 0,
        }
    }

    #[test]
    fn hidden_input_parser_preserves_unicode_editing_and_utf8_limit() {
        let mut state = HiddenInputState::default();
        state
            .apply(key_event(true, 2, 0, u16::from(b'a')), 10)
            .expect("repeated ASCII input");
        state
            .apply(key_event(true, 2, 0, 0xD83D), 10)
            .expect("repeated high surrogate");
        state
            .apply(key_event(true, 2, 0, 0xDE00), 10)
            .expect("matching repeated low surrogate");
        assert_eq!(&*state.value, "aa😀😀");
        state
            .apply(key_event(true, 2, VK_BACK, 0), 6)
            .expect("repeated backspace");
        assert_eq!(&*state.value, "aa");
        assert!(
            state.apply(key_event(true, 1, 0, 0x20AC), 3).is_err(),
            "a multibyte character crossing the byte limit must fail"
        );

        let mut words = HiddenInputState::default();
        words.value.push_str("one two three");
        words
            .apply(
                ffi::ConsoleInputEvent::Key {
                    key_down: true,
                    repeat_count: 2,
                    virtual_key_code: 0,
                    unicode_char: 23,
                    control_key_state: LEFT_CTRL_PRESSED,
                },
                64,
            )
            .expect("repeated word deletion");
        assert_eq!(&*words.value, "one ");
    }

    #[test]
    fn hidden_input_parser_rejects_malformed_surrogates_and_completes_on_enter() {
        let mut malformed = HiddenInputState::default();
        assert_eq!(
            malformed
                .apply(key_event(true, 1, 0, 0xDC00), 64)
                .expect_err("unmatched low surrogate")
                .kind(),
            ErrorKind::InvalidUnicode
        );

        let mut complete = HiddenInputState::default();
        complete
            .apply(key_event(true, 1, 0, u16::from(b'x')), 64)
            .expect("ordinary input");
        assert!(
            complete
                .apply(key_event(true, 1, VK_RETURN, u16::from(b'\r')), 64)
                .expect("enter completes")
        );
        assert_eq!(complete.finish(), "x");

        let mut mismatched_repeats = HiddenInputState::default();
        mismatched_repeats
            .apply(key_event(true, 2, 0, 0xD83D), 64)
            .expect("repeated high surrogate");
        assert_eq!(
            mismatched_repeats
                .apply(key_event(true, 1, 0, 0xDE00), 64)
                .expect_err("surrogate repeat counts must match")
                .kind(),
            ErrorKind::InvalidUnicode
        );
    }

    #[test]
    fn local_path_normalization_rejects_remote_namespaces_and_compares_case_aliases() {
        for path in [r"\\server\share\config.toml", r"\\?\C:\config.toml"] {
            assert_eq!(
                normalize_local_path(Path::new(path))
                    .expect_err("remote and verbatim paths fail before filesystem access")
                    .kind(),
                ErrorKind::InvalidPath
            );
        }

        let temporary = tempfile::tempdir().expect("temporary directory");
        let ancestor = temporary.path().join("Cache");
        let descendant = temporary.path().join("cache").join("tokens");
        assert!(
            local_path_is_same_or_descendant(&descendant, &ancestor)
                .expect("ordinal path comparison")
        );
        let normalized = normalize_local_path(&ancestor).expect("ordinary drive path");
        assert!(!normalized.to_string_lossy().starts_with(r"\\?\"));

        let existing_tilde = temporary.path().join("existing~1");
        fs::create_dir(&existing_tilde).expect("existing tilde directory");
        for path in [existing_tilde, temporary.path().join("future~1")] {
            assert_eq!(
                local_path_is_same_or_descendant(&path, temporary.path())
                    .expect_err("tilde storage components must fail closed")
                    .kind(),
                ErrorKind::InvalidPath
            );
        }
    }

    #[test]
    fn creation_uses_private_file_and_directory_acls() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = temporary.path().join("private").join("nested");
        let path = parent.join("secret");

        atomic_write_private(&path, b"secret").expect("private write");
        atomic_write_private(&path, b"replacement").expect("private replacement");

        inspect_private_directory(&parent).expect("private directory policy");
        let reader = open_bounded_file(&path, 64, true).expect("private file policy");
        assert_eq!(reader.read_all().expect("bounded read"), b"replacement");
    }

    #[test]
    fn broad_null_and_unprotected_dacls_are_rejected() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        for policy in [
            ffi::TestPolicy::Broad,
            ffi::TestPolicy::NullDacl,
            ffi::TestPolicy::Unprotected,
        ] {
            let path = temporary.path().join(format!("policy-{policy:?}"));
            atomic_write_private(&path, b"secret").expect("private write");
            let context = ffi::SecurityContext::new().expect("security context");
            let editor = ffi::open_for_policy_test(&path).expect("ACL editor");
            ffi::apply_test_policy(&editor, &context, policy).expect("replace ACL policy");
            drop(editor);

            let error =
                open_bounded_file(&path, 64, true).expect_err("insecure DACL must be rejected");
            assert_eq!(error.kind(), ErrorKind::InsecurePolicy);
        }
    }

    #[test]
    fn final_and_ancestor_reparse_points_are_refused() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("target");
        atomic_write_private(&target, b"secret").expect("private target");
        let file_link = temporary.path().join("file-link");
        symlink_file(&target, &file_link)
            .expect("the Windows security test runner must support file symlinks");
        assert_eq!(
            open_bounded_file(&file_link, 64, false)
                .expect_err("file reparse point must fail")
                .kind(),
            ErrorKind::ReparsePoint
        );

        let real_directory = temporary.path().join("real-directory");
        std::fs::create_dir(&real_directory).expect("real directory");
        let directory_link = temporary.path().join("directory-link");
        symlink_dir(&real_directory, &directory_link)
            .expect("the Windows security test runner must support directory symlinks");
        assert_eq!(
            open_bounded_file(&directory_link.join("missing"), 64, false)
                .expect_err("ancestor reparse point must fail")
                .kind(),
            ErrorKind::ReparsePoint
        );
    }

    #[test]
    fn hard_linked_lock_is_refused() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let lock_path = temporary.path().join("state.lock");
        drop(open_private_lock(&lock_path).expect("create lock"));
        let alias = temporary.path().join("state-alias.lock");
        std::fs::hard_link(&lock_path, &alias).expect("create hard link");

        let error = open_private_lock(&lock_path).expect_err("hard-linked lock must fail");
        assert_eq!(error.kind(), ErrorKind::MultipleLinks);
    }

    #[test]
    fn bounded_reader_is_a_snapshot_and_allows_atomic_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("snapshot");
        atomic_write_private(&path, b"before").expect("private write");
        let reader = open_bounded_file(&path, 64, true).expect("bounded open");

        atomic_write_private(&path, b"after").expect("atomic replacement while reading");

        assert_eq!(reader.read_all().expect("old snapshot"), b"before");
        assert_eq!(
            open_bounded_file(&path, 64, true)
                .expect("new bounded open")
                .read_all()
                .expect("new snapshot"),
            b"after"
        );
    }

    #[test]
    fn bounded_reader_denies_concurrent_writes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("immutable-snapshot");
        atomic_write_private(&path, b"before").expect("private write");
        let reader = open_bounded_file(&path, 64, true).expect("bounded open");

        let error = OpenOptions::new()
            .access_mode(FILE_WRITE_DATA)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect_err("the reader must deny data-write access");
        assert_eq!(
            error.raw_os_error(),
            Some(i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(i32::MAX))
        );
        assert_eq!(reader.read_all().expect("snapshot read"), b"before");

        OpenOptions::new()
            .access_mode(FILE_WRITE_DATA)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect("write access succeeds after the reader closes");
    }

    #[test]
    fn bounded_reader_defense_rejects_growth_beyond_limit() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("growth");
        std::fs::write(&path, b"before").expect("write fixture");
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect("write-shared test reader");
        let reader = BoundedFile {
            file,
            maximum_bytes: 6,
            initial_length: 6,
        };
        OpenOptions::new()
            .append(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect("concurrent test writer")
            .write_all(b"-after")
            .expect("grow fixture");

        assert_eq!(
            reader
                .read_all()
                .expect_err("growth must exceed the bound")
                .kind(),
            ErrorKind::TooLarge
        );
    }

    #[test]
    fn ancestor_guards_block_delete_and_preexisting_append_handles_block_scan() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = temporary.path().join("guarded");
        let path = parent.join("secret");
        atomic_write_private(&path, b"secret").expect("private write");
        let context = ffi::SecurityContext::new().expect("security context");
        let guards = validate_directory_tree(&parent, &context).expect("directory guards");

        let error = OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&parent)
            .expect_err("held ancestor guard must deny delete access");
        assert_eq!(
            error.raw_os_error(),
            Some(i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(i32::MAX))
        );
        drop(guards);

        let append = OpenOptions::new()
            .access_mode(FILE_APPEND_DATA)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&parent)
            .expect("append-capable ancestor handle");
        let error = open_bounded_file(&path, 64, true)
            .expect_err("preexisting append access must block ancestor traversal");
        assert_eq!(
            error.io_error().and_then(std::io::Error::raw_os_error),
            Some(i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(i32::MAX))
        );
        drop(append);
        open_bounded_file(&path, 64, true).expect("traversal succeeds after append handle closes");
    }

    #[test]
    fn add_only_ancestor_ace_does_not_imply_replacement_authority() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = temporary.path().join("append-policy");
        let path = parent.join("secret");
        atomic_write_private(&path, b"secret").expect("private write");
        let context = ffi::SecurityContext::new().expect("security context");
        let editor = ffi::open_for_policy_test(&parent).expect("directory ACL editor");
        ffi::apply_test_policy(
            &editor,
            &context,
            ffi::TestPolicy::AncestorWorldAddDirectory,
        )
        .expect("append policy");
        drop(editor);

        open_bounded_file(&path, 64, true)
            .expect("add-child rights alone cannot replace a validated existing child");
    }

    #[test]
    fn lock_handle_excludes_delete_sharing() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("state.lock");
        let lock = open_private_lock(&path).expect("private lock");
        let error = OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect_err("delete access must conflict with the lock");
        assert_eq!(
            error.raw_os_error(),
            Some(i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(i32::MAX))
        );
        drop(lock);
    }

    #[test]
    fn private_executable_guard_excludes_replacement_until_process_creation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary
            .path()
            .join("private")
            .join("credential-provider.exe");
        atomic_write_private(&path, b"executable fixture").expect("private executable");
        let guard = inspect_private_executable(&path).expect("private executable guard");

        let error = OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect_err("delete access must conflict with the executable guard");
        assert_eq!(
            error.raw_os_error(),
            Some(i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(i32::MAX))
        );

        drop(guard);
        OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect("delete access succeeds after process creation completes");
    }

    #[test]
    fn private_executable_rejects_dependency_planting_rights() {
        for policy in [
            ffi::TestPolicy::AncestorWorldAddFile,
            ffi::TestPolicy::AncestorWorldAddDirectory,
        ] {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let parent = temporary.path().join(format!("broker-{policy:?}"));
            let path = parent.join("credential-provider.exe");
            atomic_write_private(&path, b"executable fixture").expect("private executable");
            let context = ffi::SecurityContext::new().expect("security context");
            let editor = ffi::open_for_policy_test(&parent).expect("directory ACL editor");
            ffi::apply_test_policy(&editor, &context, policy).expect("dependency-planting policy");
            drop(editor);

            assert_eq!(
                inspect_private_executable(&path)
                    .expect_err("dependency-plantable directory must fail")
                    .kind(),
                ErrorKind::UnsafeAncestor
            );
        }
    }

    #[test]
    fn private_executable_rejects_preexisting_app_local_dependencies() {
        for child in ["dependency.dll", "credential-provider.exe.local"] {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let parent = temporary.path().join("private");
            let path = parent.join("credential-provider.exe");
            atomic_write_private(&path, b"executable fixture").expect("private executable");
            let child = parent.join(child);
            if child
                .extension()
                .is_some_and(|extension| extension == "local")
            {
                fs::create_dir(&child).expect("local dependency directory");
            } else {
                fs::write(&child, b"dependency fixture").expect("app-local dependency");
            }

            assert_eq!(
                inspect_private_executable(&path)
                    .expect_err("app-local dependencies must fail")
                    .kind(),
                ErrorKind::InsecurePolicy
            );
        }
    }

    #[test]
    fn private_executable_guard_allows_validated_pe_process_creation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary
            .path()
            .join("private")
            .join("credential-provider.exe");
        let current = std::env::current_exe().expect("current test executable");
        let bytes = std::fs::read(current).expect("read current test executable");
        atomic_write_private(&path, &bytes).expect("private PE fixture");

        let guard = inspect_private_executable(&path).expect("private executable guard");
        let output = Command::new(&path)
            .arg("--list")
            .output()
            .expect("guarded PE process creation");
        drop(guard);
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
    }

    #[tokio::test]
    async fn credential_process_job_starts_suspended_and_terminates_descendants() {
        if let Ok(role) = std::env::var(JOB_TEST_ROLE) {
            let directory = PathBuf::from(
                std::env::var_os(JOB_TEST_DIRECTORY).expect("job test directory environment"),
            );
            if role == "grandchild" {
                fs::write(directory.join("grandchild-ready"), b"ready")
                    .expect("write grandchild readiness");
                std::thread::sleep(std::time::Duration::from_secs(1));
                fs::write(directory.join("descendant-survived"), b"survived")
                    .expect("write survivor marker");
                return;
            }
            let executable = std::env::current_exe().expect("current test executable");
            let mut grandchild = Command::new(executable)
                .args([
                    "--exact",
                    "tests::credential_process_job_starts_suspended_and_terminates_descendants",
                ])
                .env(JOB_TEST_ROLE, "grandchild")
                .env(JOB_TEST_DIRECTORY, &directory)
                .spawn()
                .expect("spawn job-test grandchild");
            fs::write(directory.join("parent-ready"), b"ready").expect("write parent readiness");
            let _ = grandchild.wait();
            return;
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = std::env::current_exe().expect("current test executable");
        let mut command = tokio::process::Command::new(executable);
        command
            .args([
                "--exact",
                "tests::credential_process_job_starts_suspended_and_terminates_descendants",
            ])
            .env(JOB_TEST_ROLE, "parent")
            .env(JOB_TEST_DIRECTORY, directory.path())
            .kill_on_drop(true);
        let job = CredentialProcessJob::prepare(&mut command).expect("prepare Job containment");
        let mut child = command.spawn().expect("spawn suspended job-test parent");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !directory.path().join("parent-ready").exists(),
            "the child executed before Job assignment and resume"
        );
        job.assign_and_resume(&child)
            .expect("assign and resume contained child");
        for _ in 0..200 {
            if directory.path().join("parent-ready").exists()
                && directory.path().join("grandchild-ready").exists()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(directory.path().join("parent-ready").exists());
        assert!(directory.path().join("grandchild-ready").exists());

        drop(job);
        tokio::time::timeout(std::time::Duration::from_secs(2), child.wait())
            .await
            .expect("contained child exits promptly when the Job closes")
            .expect("wait for contained child");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(
            !directory.path().join("descendant-survived").exists(),
            "a descendant survived Job close"
        );
    }

    #[test]
    fn inherited_dll_directory_is_reset_before_process_creation() {
        const CHILD: &str = "RELTIO_DLL_DIRECTORY_RESET_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let attacker = temporary.path().join("attacker-dll-directory");
            fs::create_dir(&attacker).expect("attacker directory fixture");
            let broker = temporary
                .path()
                .join("private")
                .join("credential-provider.exe");
            atomic_write_private(&broker, b"executable fixture").expect("private executable");
            ffi::set_process_dll_directory_for_test(&attacker).expect("set DLL directory");
            assert!(!ffi::process_dll_directory_is_default_for_test());

            let _guard = inspect_private_executable(&broker).expect("private executable guard");
            assert!(ffi::process_dll_directory_is_default_for_test());
            return;
        }

        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "tests::inherited_dll_directory_is_reset_before_process_creation",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated DLL-directory test process");
        assert!(
            output.status.success(),
            "child stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn directories_are_rejected_from_the_opened_handle() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("directory");
        std::fs::create_dir(&path).expect("create directory");

        let error = open_bounded_file(&path, 64, false).expect_err("directory must fail");
        assert_eq!(error.kind(), ErrorKind::NotRegularFile);
    }

    #[test]
    fn unsafe_windows_namespaces_and_ads_are_refused() {
        for path in [
            Path::new(r"\\server\share\secret"),
            Path::new(r"\\.\C:\secret"),
            Path::new(r"\\?\C:\secret"),
            Path::new(r"C:\secret:stream"),
            Path::new(r"C:drive-relative"),
            Path::new(r"\rooted-without-drive"),
            Path::new(r"C:\NUL.txt"),
            Path::new(r"C:\CON .txt"),
            Path::new("C:\\COM\u{b9}.txt"),
            Path::new(r"C:\trailing."),
            Path::new(r"C:\trailing "),
            Path::new("C:\\trailing\\"),
            Path::new("C:\\name\\."),
            Path::new(r"C:\wild*card"),
            Path::new("C:\\control\u{1}character"),
            Path::new(r"C:\..\above-root"),
        ] {
            assert_eq!(
                open_bounded_file(path, 64, false)
                    .expect_err("unsafe namespace must fail")
                    .kind(),
                ErrorKind::InvalidPath
            );
        }
    }
}

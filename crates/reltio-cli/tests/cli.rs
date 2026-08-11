use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use base64::Engine as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_bytes, body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    directory: TempDir,
}

impl Harness {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().expect("temporary directory"),
        }
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.directory.path().join("config.toml")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("reltio"));
        command
            .env("RELTIO_CONFIG", self.config_path())
            .env("RELTIO_CACHE_DIR", self.directory.path().join("cache"))
            .env("RELTIO_STATE_DIR", self.directory.path().join("state"));
        for key in [
            "RELTIO_PROFILE",
            "RELTIO_ENVIRONMENT",
            "RELTIO_BASE_URL",
            "RELTIO_TENANT",
            "RELTIO_AUTH_URL",
            "RELTIO_ACCESS_TOKEN",
            "RELTIO_CLIENT_ID",
            "RELTIO_CLIENT_SECRET",
            "RELTIO_OUTPUT",
            "RELTIO_TIMEOUT",
            "RELTIO_CONFIRM_TENANT",
        ] {
            command.env_remove(key);
        }
        command
    }

    fn add_profile(&self, base_url: Option<&str>) {
        let mut command = self.command();
        command.args([
            "profile",
            "add",
            "test",
            "--environment",
            "test",
            "--tenant",
            "TestTenant",
        ]);
        if let Some(base_url) = base_url {
            command.args(["--base-url", base_url]);
        }
        let output = command.output().expect("profile command executes");
        assert_success(&output);
    }

    fn set_service_url(&self, profile: &str, service: &str, url: &str) {
        let assignment = format!("{service}={url}");
        let output = self
            .command()
            .args(["profile", "update", profile, "--service-url", &assignment])
            .output()
            .expect("profile service update executes");
        assert_success(&output);
    }
}

#[test]
fn profile_lifecycle_and_private_permissions() {
    let harness = Harness::new();
    harness.add_profile(None);
    let mut show = harness.command();
    let output = show
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["tenant"], "TestTenant");
    assert_eq!(envelope["data"]["current"], true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(harness.config_path())
            .expect("config metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "config must be owner-only");
    }
}

#[test]
fn duplicate_service_aliases_are_rejected_without_mutating_config() {
    let harness = Harness::new();
    let before = fs::read(harness.config_path()).ok();
    let output = harness
        .command()
        .args([
            "profile",
            "add",
            "duplicate",
            "--environment",
            "test",
            "--tenant",
            "Tenant",
            "--service-url",
            "physical-config=https://one.example",
            "--service-url",
            "physical_config=https://two.example",
        ])
        .output()
        .expect("duplicate profile add executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("duplicate error")["error"]["code"],
        "duplicate_service_override"
    );
    assert_eq!(fs::read(harness.config_path()).ok(), before);

    harness.add_profile(None);
    let before = fs::read(harness.config_path()).expect("config preimage");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--service-url",
            "physical-config=https://one.example",
            "--service-url",
            "physical_config=https://two.example",
        ])
        .output()
        .expect("duplicate profile update executes");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("duplicate error")["error"]["code"],
        "duplicate_service_override"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("unchanged config"),
        before
    );
}

#[test]
fn profile_update_clear_auth_conflicts_with_every_auth_setter_before_mutation() {
    let harness = Harness::new();
    harness.add_profile(None);
    let secret_file = harness.directory.path().join("replacement-secret");
    let setters = [
        vec!["--auth-method", "bearer"],
        vec!["--client-id", "replacement-client"],
        vec!["--secret-file", secret_file.to_str().expect("UTF-8 path")],
    ];
    for setter in setters {
        let before = fs::read(harness.config_path()).expect("config preimage");
        let output = harness
            .command()
            .args(["profile", "update", "test", "--clear-auth"])
            .args(setter)
            .output()
            .expect("conflicting update executes");

        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).expect("clap error")["error"]["code"],
            "invalid_cli_usage"
        );
        assert_eq!(
            fs::read(harness.config_path()).expect("unchanged config"),
            before
        );
    }
}

#[test]
fn profile_update_explicit_clear_and_service_removal_controls_return_committed_snapshot() {
    let harness = Harness::new();
    let secret_file = harness.directory.path().join("profile-secret");
    let output = harness
        .command()
        .args([
            "profile",
            "add",
            "managed",
            "--environment",
            "test",
            "--base-url",
            "https://base.example",
            "--tenant",
            "Tenant",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "profile-client",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
            "--service-url",
            "data=https://data.example/reltio/api/{tenant}",
            "--service-url",
            "physical-config=https://physical.example",
            "--service-url",
            "auth=https://login.example",
        ])
        .output()
        .expect("profile add executes");
    assert_success(&output);

    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "managed",
            "--clear-environment",
            "--clear-base-url",
            "--clear-tenant",
            "--clear-client-id",
            "--clear-secret-file",
            "--remove-service-url",
            "physical_config",
        ])
        .output()
        .expect("profile clear update executes");
    assert_success(&output);
    let profile = stdout_json(&output)["data"].clone();
    assert!(profile["environment"].is_null());
    assert!(profile["base_url"].is_null());
    assert!(profile["tenant"].is_null());
    assert_eq!(profile["auth"]["method"], "client_credentials");
    assert!(profile["auth"]["client_id"].is_null());
    assert!(profile["auth"]["secret_file"].is_null());
    assert!(profile["services"].get("physical-config").is_none());
    assert!(profile["services"].get("data").is_some());
    assert!(profile["services"].get("auth").is_some());

    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "managed",
            "--clear-auth",
            "--clear-service-urls",
        ])
        .output()
        .expect("profile clear-all update executes");
    assert_success(&output);
    let profile = stdout_json(&output)["data"].clone();
    assert_eq!(profile["services"], json!({}));
    assert!(profile["auth"]["method"].is_null());
    assert!(profile["auth"]["client_id"].is_null());
    assert!(profile["auth"]["secret_file"].is_null());

    let shown = harness
        .command()
        .args(["profile", "show", "managed"])
        .output()
        .expect("profile show executes");
    assert_success(&shown);
    assert_eq!(stdout_json(&shown)["data"], profile);
}

#[test]
fn profile_service_set_remove_conflict_and_output_guard_refusal_preserve_exact_config() {
    let harness = Harness::new();
    harness.add_profile(None);
    let before = fs::read(harness.config_path()).expect("config preimage");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--service-url",
            "physical-config=https://physical.example",
            "--remove-service-url",
            "physical_config",
        ])
        .output()
        .expect("conflicting service update executes");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("conflict error")["error"]["code"],
        "profile_update_argument_conflict"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("unchanged config"),
        before
    );

    login_bearer(&harness, "test", "profile.update");
    let before = fs::read(harness.config_path()).expect("guarded config preimage");
    let output = harness
        .command()
        .args(["profile", "update", "test", "--tenant", "NewTenant"])
        .output()
        .expect("guarded profile update executes");
    assert_eq!(output.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&output.stderr).expect("guarded error");
    assert_eq!(error["error"]["code"], "credential_output_refused");
    assert_eq!(error["error"]["details"]["local_state_committed"], false);
    assert_eq!(error["error"]["details"]["safe_to_replay"], true);
    assert_eq!(
        fs::read(harness.config_path()).expect("guard-refused config"),
        before
    );
}

#[cfg(unix)]
#[test]
fn profile_update_stdout_failure_reports_committed_non_replayable_state() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let harness = Harness::new();
    harness.add_profile(None);
    let (reader, writer) = UnixStream::pair().expect("Unix socket pair");
    drop(reader);
    let output = harness
        .command()
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .args(["profile", "update", "test", "--tenant", "CommittedTenant"])
        .output()
        .expect("profile update executes");

    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).expect("output failure");
    assert_eq!(error["error"]["code"], "output_write_failed");
    assert_eq!(error["error"]["details"]["local_state_committed"], true);
    assert_eq!(error["error"]["details"]["safe_to_replay"], false);
    let shown = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&shown);
    assert_eq!(stdout_json(&shown)["data"]["tenant"], "CommittedTenant");
}

#[test]
fn dry_run_is_rejected_instead_of_mutating_local_profile_state() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .args(["--dry-run", "profile", "remove", "test"])
        .output()
        .expect("profile dry run executes");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("structured error")["error"]["code"],
        "dry_run_unsupported"
    );

    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile remains readable");
    assert_success(&output);
}

#[test]
fn raw_output_is_rejected_for_commands_without_documented_raw_material() {
    let harness = Harness::new();
    for arguments in [
        vec!["--output", "raw", "profile", "list"],
        vec!["--output", "raw", "api", "practices", "list"],
    ] {
        let output = harness
            .command()
            .args(arguments)
            .output()
            .expect("unsupported raw command executes");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).expect("structured error")["error"]["code"],
            "raw_output_unsupported"
        );
    }
}

#[cfg(unix)]
#[test]
fn typed_raw_output_is_refused_on_pseudoterminal_stdout() {
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Stdio;

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("pseudoterminal master");
    grantpt(&master).expect("grant pseudoterminal");
    unlockpt(&master).expect("unlock pseudoterminal");
    let slave_name = ptsname(&master, Vec::new()).expect("pseudoterminal slave name");
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .open(OsStr::from_bytes(slave_name.as_bytes()))
        .expect("pseudoterminal slave");
    let harness = Harness::new();
    let output = harness
        .command()
        .args(["--output", "raw", "entity", "get", "entities/example"])
        .stdout(Stdio::from(slave))
        .output()
        .expect("typed raw command executes");

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("structured safety error")["error"]
            ["code"],
        "raw_output_tty_refused"
    );
}

#[test]
fn bearer_login_and_profile_edits_preserve_unrelated_profile_tokens() {
    let harness = Harness::new();
    for name in ["first", "second"] {
        let output = harness
            .command()
            .args([
                "profile",
                "add",
                name,
                "--environment",
                "test",
                "--tenant",
                "TestTenant",
            ])
            .output()
            .expect("profile add executes");
        assert_success(&output);
        login_bearer(&harness, name, &format!("{name}-token"));
    }

    for mutation in [
        vec!["profile", "update", "second", "--client-id", "changed"],
        vec!["profile", "remove", "second"],
    ] {
        let output = harness
            .command()
            .args(mutation)
            .output()
            .expect("profile mutation executes");
        assert_success(&output);
        let output = harness
            .command()
            .args([
                "--profile",
                "first",
                "--output",
                "raw",
                "auth",
                "token",
                "--show",
            ])
            .output()
            .expect("token read executes");
        assert_success(&output);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "first-token"
        );
    }
    assert_eq!(
        cached_token_files(&harness.directory.path().join("cache")).len(),
        1,
        "removing one profile must remove only its imported bearer"
    );
}

#[cfg(unix)]
#[test]
fn profile_remove_cache_failure_preserves_profile_and_bearer() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }

    let harness = Harness::new();
    harness.add_profile(None);
    login_bearer(&harness, "test", "preserved-cache-token");
    let token_directory = harness.directory.path().join("cache").join("tokens");
    fs::set_permissions(&token_directory, fs::Permissions::from_mode(0o500))
        .expect("make token directory read-only");

    let output = harness
        .command()
        .args(["profile", "remove", "test"])
        .output()
        .expect("profile remove executes");
    fs::set_permissions(&token_directory, fs::Permissions::from_mode(0o700))
        .expect("restore token directory permissions");

    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "profile_remove_cache_failed");
    assert_eq!(error["error"]["details"]["local_profile_committed"], false);
    assert_eq!(error["error"]["details"]["local_cache_committed"], false);
    assert_eq!(error["error"]["details"]["local_state_committed"], false);
    assert_eq!(error["error"]["details"]["safe_to_replay"], true);
    assert_profile_and_token(&harness, "test", "preserved-cache-token");
}

#[cfg(unix)]
#[test]
fn profile_remove_config_failure_restores_exact_bearer_preimage() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }

    let harness = Harness::new();
    harness.add_profile(None);
    login_bearer(&harness, "test", "restored-config-token");
    let cache_before = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .map(|path| fs::read(path).expect("cache preimage"))
        .collect::<Vec<_>>();
    fs::set_permissions(harness.directory.path(), fs::Permissions::from_mode(0o500))
        .expect("make config parent read-only");

    let output = harness
        .command()
        .args(["profile", "remove", "test"])
        .output()
        .expect("profile remove executes");
    fs::set_permissions(harness.directory.path(), fs::Permissions::from_mode(0o700))
        .expect("restore temporary directory permissions");

    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "profile_remove_config_failed");
    assert_eq!(error["error"]["details"]["local_profile_committed"], false);
    assert_eq!(error["error"]["details"]["local_cache_committed"], false);
    assert_eq!(error["error"]["details"]["local_state_committed"], false);
    assert_eq!(error["error"]["details"]["safe_to_replay"], true);
    let cache_after = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .map(|path| fs::read(path).expect("restored cache"))
        .collect::<Vec<_>>();
    assert_eq!(cache_after, cache_before);
    assert_profile_and_token(&harness, "test", "restored-config-token");
}

#[test]
fn profile_remove_output_preflight_changes_no_local_state() {
    let harness = Harness::new();
    harness.add_profile(None);
    login_bearer(&harness, "test", "profile.remove");

    let output = harness
        .command()
        .args(["profile", "remove", "test"])
        .output()
        .expect("profile remove executes");

    assert_eq!(output.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "credential_output_refused");
    assert_eq!(error["error"]["details"]["local_profile_committed"], false);
    assert_eq!(error["error"]["details"]["local_cache_committed"], false);
    assert_eq!(error["error"]["details"]["local_state_committed"], false);
    assert_eq!(error["error"]["details"]["safe_to_replay"], true);
    assert_profile_and_token(&harness, "test", "profile.remove");
}

#[cfg(unix)]
#[test]
fn profile_remove_and_auth_logout_honor_the_global_cache_timeout() {
    use std::time::{Duration, Instant};

    use fs2::FileExt;

    let harness = Harness::new();
    harness.add_profile(None);
    login_bearer(&harness, "test", "timeout-preserved-token");
    let config_before = fs::read(harness.config_path()).expect("config preimage");
    let cache_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .next()
        .expect("bearer cache");
    let cache_before = fs::read(&cache_path).expect("cache preimage");
    let maintenance = reltio_client::fs::open_private_lock(
        &harness
            .directory
            .path()
            .join("cache/tokens/cache-maintenance.lock"),
    )
    .expect("maintenance lock");
    FileExt::try_lock_exclusive(&maintenance).expect("hold maintenance lock");

    let started = Instant::now();
    let output = harness
        .command()
        .args(["--timeout", "50ms", "profile", "remove", "test"])
        .output()
        .expect("timed profile remove executes");
    assert_eq!(output.status.code(), Some(7));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        fs::read(harness.config_path()).expect("unchanged config"),
        config_before
    );
    assert_eq!(
        fs::read(&cache_path).expect("unchanged cache"),
        cache_before
    );

    FileExt::unlock(&maintenance).expect("release maintenance lock");
    FileExt::try_lock_exclusive(&maintenance).expect("reacquire maintenance lock");
    let started = Instant::now();
    let output = harness
        .command()
        .args(["--timeout", "50ms", "auth", "logout"])
        .output()
        .expect("timed logout executes");
    assert_eq!(output.status.code(), Some(7));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        fs::read(&cache_path).expect("unchanged cache"),
        cache_before
    );
    FileExt::unlock(&maintenance).expect("release maintenance lock");
}

#[test]
fn raw_auth_token_retains_shadow_environment_guard() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "prefix-shadow-secret-suffix")
        .env("RELTIO_CLIENT_SECRET", "shadow-secret")
        .args(["--output", "raw", "auth", "token", "--show"])
        .output()
        .expect("raw token disclosure executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("shadow-secret"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("guarded error")["error"]["code"],
        "credential_output_refused"
    );
}

#[test]
fn cached_tokens_guard_local_command_metadata() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "profile.show")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);

    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("profile.show"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("guarded error")["error"]["code"],
        "credential_output_refused"
    );
}

#[test]
fn help_output_is_guarded_against_cached_credentials() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "Usage:")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);

    let output = harness
        .command()
        .arg("--help")
        .output()
        .expect("help command executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn maximum_accepted_bearer_cache_remains_readable_and_removable() {
    use std::io::Write as _;
    use std::process::Stdio;

    let harness = Harness::new();
    harness.add_profile(None);
    let token = vec![b'x'; 1024 * 1024];
    let mut command = harness.command();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--token-stdin",
            "--expires-in",
            "1h",
        ]);
    let mut child = command.spawn().expect("bearer login starts");
    child
        .stdin
        .take()
        .expect("token stdin")
        .write_all(&token)
        .expect("write maximum token");
    let output = child.wait_with_output().expect("bearer login completes");
    assert_success(&output);

    let cache_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .next()
        .expect("maximum bearer cache path");
    assert!(
        fs::metadata(&cache_path).expect("cache metadata").len() > 1024 * 1024,
        "the regression requires JSON metadata to push the cache beyond 1 MiB"
    );

    let help = harness
        .command()
        .arg("--help")
        .output()
        .expect("help executes with maximum cache");
    assert_success(&help);

    let status = harness
        .command()
        .args(["auth", "status"])
        .output()
        .expect("status executes with maximum cache");
    assert_success(&status);
    assert_eq!(stdout_json(&status)["data"]["cache_state"], "valid");

    let logout = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes with maximum cache");
    assert_success(&logout);
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[test]
fn duplicate_cache_values_guard_local_command_metadata() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "initial-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);
    let cache_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .next()
        .expect("bearer cache path");
    let expires_at = (chrono::Utc::now() + chrono::TimeDelta::hours(1)).to_rfc3339();
    let obtained_at = chrono::Utc::now().to_rfc3339();
    let malformed = format!(
        r#"{{"version":1,"provider":"bearer","access_token":"profile.show","access_token":"safe-token","expires_at":"{expires_at}","obtained_at":"{obtained_at}"}}"#
    );
    reltio_client::fs::atomic_write_private(&cache_path, malformed.as_bytes())
        .expect("install duplicate cache fixture");

    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("profile.show"));
}

#[test]
fn malformed_cache_generation_does_not_hide_later_help_guard() {
    let harness = Harness::new();
    let token_dir = harness.directory.path().join("cache").join("tokens");
    let expires_at = (chrono::Utc::now() + chrono::TimeDelta::hours(1)).to_rfc3339();
    let obtained_at = chrono::Utc::now().to_rfc3339();
    let malformed = json!({
        "version": 1,
        "provider": "bearer",
        "access_token": "malformed-generation-secret",
        "expires_at": expires_at.clone(),
        "obtained_at": obtained_at.clone(),
        "future_secret": "malformed-extension-secret"
    });
    reltio_client::fs::atomic_write_private(
        &token_dir.join(format!("{}.json", "0".repeat(64))),
        &serde_json::to_vec(&malformed).expect("encode malformed cache"),
    )
    .expect("malformed cache fixture");
    let valid = json!({
        "version": 1,
        "provider": "bearer",
        "access_token": "Usage:",
        "expires_at": expires_at,
        "obtained_at": obtained_at,
        "reissued_after_rejection": false
    });
    reltio_client::fs::atomic_write_private(
        &token_dir.join(format!("{}.json", "f".repeat(64))),
        &serde_json::to_vec(&valid).expect("encode valid cache"),
    )
    .expect("valid cache fixture");

    let output = harness
        .command()
        .arg("--help")
        .output()
        .expect("help command executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn raw_auth_token_retains_prior_cache_generation_guard() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "old-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "prefix-old-token-suffix")
        .args(["--output", "raw", "auth", "token", "--show"])
        .output()
        .expect("raw token disclosure executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("old-token"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("guarded error")["error"]["code"],
        "credential_output_refused"
    );
}

#[test]
fn unusable_bearer_candidate_preserves_valid_cache_preimage() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "old-valid-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("initial bearer login executes");
    assert_success(&output);
    let config_before = fs::read(harness.config_path()).expect("snapshot config");
    let cache_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .next()
        .expect("bearer cache path");
    let cache_before = fs::read(&cache_path).expect("snapshot bearer cache");

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "new-unusable-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1s",
        ])
        .output()
        .expect("short bearer login executes");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("new-unusable-token"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("expiry error")["error"]["code"],
        "auth_token_expiry_too_soon"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("read config"),
        config_before
    );
    assert_eq!(fs::read(&cache_path).expect("read cache"), cache_before);

    let output = harness
        .command()
        .args(["--output", "raw", "auth", "token", "--show"])
        .output()
        .expect("prior token read executes");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "old-valid-token"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_auth_token_broken_pipe_is_reported() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let harness = Harness::new();
    harness.add_profile(None);
    let (reader, writer) = UnixStream::pair().expect("Unix socket pair");
    drop(reader);
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "deliberately-disclosed-token")
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .args(["--output", "raw", "auth", "token", "--show"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("output error")["error"]["code"],
        "output_write_failed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_auth_token_retains_transient_refresh_guard() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "prefix-refresh-only-suffix",
            "refresh_token": "refresh-only",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("raw-token-client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);
    let mut command = harness.command();
    command
        .env("RELTIO_AUTH_URL", auth.uri())
        .args(["--output", "raw", "auth", "token", "--show"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("refresh-only"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("guarded error")["error"]["code"],
        "credential_output_refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_auth_token_rejects_refresh_token_that_spans_its_appended_newline() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "raw-visible",
            "refresh_token": "raw-visible\n",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("raw-newline-client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);
    let mut command = harness.command();
    command
        .env("RELTIO_AUTH_URL", auth.uri())
        .args(["--output", "raw", "auth", "token", "--show"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("raw-visible"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_auth_token_write_failure_keeps_transient_refresh_guard() {
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "deliberately-disclosed-token",
            "refresh_token": "output_write_failed",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("write-failure-client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);

    let (_reader, mut writer) = UnixStream::pair().expect("Unix socket pair");
    writer
        .set_nonblocking(true)
        .expect("nonblocking output socket");
    let fill = [0_u8; 8192];
    loop {
        match writer.write(&fill) {
            Ok(0) => panic!("output socket accepted an empty write"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("failed to fill output socket: {error}"),
        }
    }
    let mut command = harness.command();
    command
        .env("RELTIO_AUTH_URL", auth.uri())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .args(["--output", "raw", "auth", "token", "--show"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("output_write_failed"));
    let fields: Value = serde_json::from_slice(&output.stderr).expect("guarded error");
    assert_eq!(fields.as_array().unwrap().len(), 12);
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert!(fields[1].is_null());
    assert_eq!(fields[11], -1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_cli_processes_singleflight_client_credentials() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "shared-process-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    let auth_service = format!("auth={}", auth.uri());
    let output = harness
        .command()
        .args([
            "profile",
            "add",
            "workers",
            "--environment",
            "test",
            "--tenant",
            "TestTenant",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "worker-client",
            "--service-url",
            &auth_service,
        ])
        .output()
        .expect("profile add executes");
    assert_success(&output);

    let mut processes = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let mut command = harness.command();
        command.env("RELTIO_CLIENT_SECRET", "worker-secret").args([
            "--profile",
            "workers",
            "--output",
            "raw",
            "auth",
            "token",
            "--show",
        ]);
        processes.spawn(run_process(command));
    }
    while let Some(output) = processes.join_next().await {
        let output = output.expect("process task completes");
        assert_success(&output);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "shared-process-token"
        );
    }
}

#[cfg(unix)]
#[test]
fn insecure_configuration_is_rejected_instead_of_only_warned() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::new();
    harness.add_profile(None);
    fs::set_permissions(harness.config_path(), fs::Permissions::from_mode(0o666))
        .expect("make config insecure");

    let output = harness
        .command()
        .args(["profile", "list"])
        .output()
        .expect("profile list executes");

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "insecure_file_permissions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misspelled_production_field_fails_before_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    fs::write(
        harness.config_path(),
        format!(
            r#"version = 1
current_profile = "prod"

[profiles.prod]
environment = "test"
base_url = "{}"
tenant = "ProdTenant"
productionn = true
"#,
            server.uri()
        ),
    )
    .expect("write misspelled config");

    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["entity", "get", "1"]);
    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "config_parse_failed"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn structured_error_and_search_boundary_exit_contract() {
    let harness = Harness::new();
    harness.add_profile(None);
    let mut command = harness.command();
    let output = command
        .env("RELTIO_ACCESS_TOKEN", "token")
        .args(["entity", "search", "--offset", "9999", "--max-items", "2"])
        .output()
        .expect("search executes");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured stderr");
    assert_eq!(error["error"]["code"], "entity_search_boundary_exceeded");
    assert_eq!(error["error"]["category"], "usage");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_not_found_uses_stable_exit_four() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["entity", "get", "missing"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resource_not_found"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_timeout_uses_stable_exit_seven() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(2))
                .set_body_json(json!({"cursor": {"value": "cursor-1"}, "objects": []})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--timeout",
        "500ms",
        "entity",
        "scan",
        "--filter",
        "equals(type,'configuration/entityTypes/Organization')",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "request_timeout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_get_contract_and_consistency_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .and(header("authorization", "Bearer opaque-token"))
        .and(query_param("select", "uri,label"))
        .and(query_param("time", "1720000000000"))
        .and(query_param("options", "ovOnly"))
        .and(query_param("mergeDuplicateCrosswalks", "true"))
        .and(query_param("defaultMaxValues", "10"))
        .and(query_param(
            "explicitSurvivorshipGroup",
            "configuration/entityTypes/Individual/survivorshipGroups/Default",
        ))
        .and(query_param("reverseTranscodeLookups", "Salesforce"))
        .and(query_param("sendMasked", "true"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-request-id", "request-1")
                .set_body_json(json!({
                    "uri": "entities/1",
                    "futureField": {"preserved": true},
                    "password": "ordinary-upstream-value",
                    "message": "password=ordinary-upstream-value"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--fields",
        "uri,label",
        "entity",
        "get",
        "1",
        "--time",
        "1720000000000",
        "--option",
        "ovOnly",
        "--merge-duplicate-crosswalks",
        "--default-max-values",
        "10",
        "--explicit-survivorship-group",
        "configuration/entityTypes/Individual/survivorshipGroups/Default",
        "--reverse-transcode-lookups",
        "Salesforce",
        "--send-masked",
    ]);
    let output = run_process(command).await;
    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["futureField"]["preserved"], true);
    assert_eq!(envelope["data"]["password"], "ordinary-upstream-value");
    assert_eq!(
        envelope["data"]["message"],
        "password=ordinary-upstream-value"
    );
    assert_eq!(envelope["meta"]["consistency"], "consistent");
    assert_eq!(envelope["meta"]["request_id"], "request-1");
    assert_eq!(envelope["meta"]["practice_coverage"], "reviewed");
    assert!(
        envelope["meta"]["practice_ids"]
            .as_array()
            .unwrap()
            .contains(&Value::String("ENTITY-GET-PARAMETERS-001".to_owned()))
    );
    assert!(
        envelope["meta"]["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Preview")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_by_crosswalk_preserves_wrapper_and_consistency_contract() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/reltio/api/TestTenant/entities/_byCrosswalk/customer-123",
        ))
        .and(header("authorization", "Bearer opaque-token"))
        .and(query_param("type", "configuration/sources/CRM"))
        .and(query_param("sourceTable", "contacts"))
        .and(query_param("options", "sendHidden,ovOnly"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "index": 0,
                "object": {
                    "uri": "entities/1",
                    "crosswalks": [{
                        "type": "configuration/sources/CRM",
                        "value": "customer-123",
                        "sourceTable": "contacts"
                    }],
                    "futureField": {"preserved": true}
                },
                "successful": true,
                "futureWrapperField": "preserved"
            }
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let output = run_process({
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "entity",
            "by-crosswalk",
            "--value",
            "customer-123",
            "--type",
            "configuration/sources/CRM",
            "--source-table",
            "contacts",
            "--option",
            "sendHidden",
            "--option",
            "ovOnly",
        ]);
        command
    })
    .await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(
        envelope["data"][0]["object"]["futureField"]["preserved"],
        true
    );
    assert_eq!(envelope["data"][0]["futureWrapperField"], "preserved");
    assert_eq!(envelope["meta"]["consistency"], "consistent");
    assert_eq!(envelope["meta"]["practice_coverage"], "reviewed");
    assert!(envelope["meta"]["warnings"].as_array().unwrap().is_empty());
    assert!(
        envelope["meta"]["practice_ids"]
            .as_array()
            .expect("practice IDs")
            .contains(&Value::String("ENTITY-CROSSWALK-CONTRACT-001".to_owned()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_by_crosswalk_warns_when_documented_id_fallback_is_detected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/reltio/api/TestTenant/entities/_byCrosswalk/customer-123",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "index": 0,
            "object": {"uri": "entities/customer-123", "crosswalks": []},
            "successful": true
        }])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "by-crosswalk",
        "--value",
        "customer-123",
        "--type",
        "configuration/sources/CRM",
    ]);

    let output = run_process(command).await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert!(
        envelope["meta"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("ID-fallback")))
    );
}

#[test]
fn raw_entity_crosswalk_enforces_the_narrowed_contract() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/_byCrosswalk/customer-123",
            "--service",
            "data",
            "--query",
            "type=CRM",
            "--query",
            "options=ovOnly",
        ])
        .output()
        .expect("reviewed crosswalk dry run executes");
    assert_success(&output);
    assert_eq!(
        stdout_json(&output)["data"]["practice_coverage"],
        "reviewed"
    );

    for query in ["options=ovOnly,nonOvOnly", "options=explainOv"] {
        let output = harness
            .command()
            .env("RELTIO_ACCESS_TOKEN", "opaque-token")
            .args([
                "--dry-run",
                "api",
                "request",
                "GET",
                "/entities/_byCrosswalk/customer-123",
                "--service",
                "data",
                "--query",
                "type=CRM",
                "--query",
                query,
            ])
            .output()
            .expect("invalid crosswalk dry run executes");
        assert_eq!(output.status.code(), Some(2), "query {query}");
        assert!(output.stdout.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_history_preserves_changes_and_explicit_order() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1/_changes"))
        .and(header("authorization", "Bearer opaque-token"))
        .and(query_param("max", "2"))
        .and(query_param("offset", "998"))
        .and(query_param("order", "desc"))
        .and(query_param("showAll", "true"))
        .and(query_param("showMajorEventsOnly", "false"))
        .and(query_param("options", "skipReferenceAttributesProcessing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"timestamp": 2, "type": "ENTITY_CHANGED", "future": {"preserved": true}},
            {"timestamp": 1, "type": "ENTITY_CREATED", "timestampSuffix": "0001"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "history",
        "1",
        "--max-items",
        "2",
        "--offset",
        "998",
        "--show-all",
        "--show-major-events-only",
        "false",
        "--skip-reference-attributes-processing",
    ]);
    let output = run_process(command).await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"][0]["future"]["preserved"], true);
    assert_eq!(envelope["data"][1]["timestampSuffix"], "0001");
    assert_eq!(envelope["meta"]["consistency"], "unknown");
    assert_eq!(envelope["meta"]["pagination"]["boundary_reached"], true);
    let warnings = envelope["meta"]["warnings"].as_array().expect("warnings");
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|warning| warning.contains("1,000-event"))
    }));
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|warning| warning.contains("canonical values"))
    }));
}

#[test]
fn raw_entity_history_enforces_conflicts_and_boundary() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    for query in [
        vec!["max=1", "offset=1000", "order=desc"],
        vec![
            "max=50",
            "offset=0",
            "order=desc",
            "showAll=true",
            "filter=equals(type,'ENTITY_CHANGED')",
        ],
    ] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_changes",
            "--service",
            "data",
        ]);
        for value in query {
            command.args(["--query", value]);
        }
        let output = command.output().expect("history dry run executes");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }

    for (query, expected_coverage) in [(None, "partial"), (Some("order=desc"), "reviewed")] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_changes",
            "--service",
            "data",
        ]);
        if let Some(query) = query {
            command.args(["--query", query]);
        }
        let output = command.output().expect("history coverage dry run executes");
        assert_success(&output);
        assert_eq!(
            stdout_json(&output)["data"]["practice_coverage"],
            expected_coverage
        );
        if query.is_some() {
            let envelope = stdout_json(&output);
            let warnings = envelope["meta"]["warnings"].as_array().expect("warnings");
            assert!(warnings.iter().any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|warning| warning.contains("canonical values"))
            }));
            assert!(warnings.iter().any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|warning| warning.contains("showAll=true"))
            }));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_matches_preserves_stored_direct_results_and_warns_about_freshness() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1/_matches"))
        .and(header("authorization", "Bearer opaque-token"))
        .and(query_param("transitive", "false"))
        .and(query_param("forceMatch", "false"))
        .and(query_param("deep", "1"))
        .and(query_param("max", "2"))
        .and(query_param("offset", "0"))
        .and(query_param("type", "suspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "configuration/entityTypes/Individual/matchGroups/Suspect": [
                {"object": {"uri": "entities/2", "futureEntityField": 1}, "futureResult": true},
                {"object": {"uri": "entities/3"}, "relevance": 0.9}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "matches",
        "1",
        "--max-items",
        "2",
        "--match-type",
        "suspect",
    ]);
    let output = run_process(command).await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    let group = &envelope["data"]["configuration/entityTypes/Individual/matchGroups/Suspect"];
    assert_eq!(group[0]["futureResult"], true);
    assert_eq!(group[0]["object"]["futureEntityField"], 1);
    assert_eq!(envelope["meta"]["consistency"], "unknown");
    assert!(envelope["meta"]["pagination"]["returned"].is_null());
    assert!(envelope["meta"]["pagination"]["next_offset"].is_null());
    assert_eq!(envelope["meta"]["pagination"]["continuation_known"], false);
    assert!(
        envelope["meta"]["warnings"][0]
            .as_str()
            .is_some_and(|warning| warning.contains("out of date"))
    );
}

#[test]
fn raw_entity_matches_refuses_force_match_and_reviews_only_stored_direct_reads() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_matches",
            "--service",
            "data",
            "--query",
            "forceMatch=true",
            "--query",
            "max=50",
        ])
        .output()
        .expect("force-match dry run executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("force-match refusal")["error"]["code"],
        "raw_force_match_refused"
    );

    let missing_direct_depth = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_matches",
            "--service",
            "data",
            "--query",
            "forceMatch=false",
            "--query",
            "max=50",
        ])
        .output()
        .expect("match request without direct depth executes");
    assert_success(&missing_direct_depth);
    assert_eq!(
        stdout_json(&missing_direct_depth)["data"]["practice_coverage"],
        "partial"
    );

    let custom_action = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_matches",
            "--service",
            "data",
            "--query",
            "deep=1",
            "--query",
            "type=tenant_custom_action",
        ])
        .output()
        .expect("custom match action dry run executes");
    assert_success(&custom_action);
    assert_eq!(
        stdout_json(&custom_action)["data"]["practice_coverage"],
        "partial"
    );

    let reviewed = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1/_matches",
            "--service",
            "data",
            "--query",
            "forceMatch=false",
            "--query",
            "transitive=false",
            "--query",
            "deep=1",
            "--query",
            "max=50",
            "--query",
            "offset=0",
        ])
        .output()
        .expect("stored direct dry run executes");
    assert_success(&reviewed);
    assert_eq!(
        stdout_json(&reviewed)["data"]["practice_coverage"],
        "reviewed"
    );
    assert!(
        stdout_json(&reviewed)["meta"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("out of date")))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_entity_raw_output_preserves_upstream_bytes() {
    let server = MockServer::start().await;
    let get_body = b"{ \"z\":1, \"a\":2 }";
    let crosswalk_body = b"[ { \"index\":0, \"object\":{\"z\":1,\"a\":2} } ]";
    let search_body = b"[\n  { \"z\":1, \"a\":2 }\n]";
    let history_body = b"[ { \"timestamp\":2, \"future\":true } ]";
    let matches_body = b"{ \"configuration/matchGroups/One\":[ { \"future\":true } ] }";
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .and(header("authorization", "Bearer opaque-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(get_body.as_slice(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/reltio/api/TestTenant/entities/_byCrosswalk/customer-123",
        ))
        .and(query_param("type", "CRM"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(crosswalk_body.as_slice(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer opaque-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(search_body.as_slice(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1/_changes"))
        .and(query_param("max", "50"))
        .and(query_param("offset", "0"))
        .and(query_param("order", "desc"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(history_body.as_slice(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1/_matches"))
        .and(query_param("transitive", "false"))
        .and(query_param("forceMatch", "false"))
        .and(query_param("deep", "1"))
        .and(query_param("max", "50"))
        .and(query_param("offset", "0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(matches_body.as_slice(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["--output", "raw", "entity", "get", "1"]);
    let output = run_process(command).await;
    assert_success(&output);
    assert_eq!(output.stdout, get_body);

    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--output",
        "raw",
        "entity",
        "by-crosswalk",
        "--type",
        "CRM",
        "--value",
        "customer-123",
    ]);
    let output = run_process(command).await;
    assert_success(&output);
    assert_eq!(output.stdout, crosswalk_body);

    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["--output", "raw", "entity", "search"]);
    let output = run_process(command).await;
    assert_success(&output);
    assert_eq!(output.stdout, search_body);

    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["--output", "raw", "entity", "history", "1"]);
    let output = run_process(command).await;
    assert_success(&output);
    assert_eq!(output.stdout, history_body);

    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["--output", "raw", "entity", "matches", "1"]);
    let output = run_process(command).await;
    assert_success(&output);
    assert_eq!(output.stdout, matches_body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_get_preview_warning_reaches_raw_and_table_outputs() {
    let server = MockServer::start().await;
    let body = br#"{"uri":"entities/1","label":"Example"}"#;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .and(query_param("reverseTranscodeLookups", "Salesforce"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body.as_slice(), "application/json"))
        .expect(2)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for format in ["raw", "table"] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "--output",
            format,
            "entity",
            "get",
            "1",
            "--reverse-transcode-lookups",
            "Salesforce",
        ]);
        let output = run_process(command).await;

        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("Preview"));
        if format == "raw" {
            assert_eq!(output.stdout, body);
        } else {
            assert!(String::from_utf8_lossy(&output.stdout).contains("entities/1"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_search_uses_post_body_and_eventual_metadata() {
    let server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer opaque-token"))
        .and(body_json(json!({
            "filter": filter,
            "select": "uri,type",
            "max": 2,
            "offset": 0,
            "sort": "uri",
            "order": "asc",
            "options": "ovOnly",
            "defaultMaxValues": 10,
            "activeness": "active",
            "scoreEnabled": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uri": "entities/1"},
            {"uri": "entities/2"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--fields",
        "uri,type",
        "entity",
        "search",
        "--filter",
        filter,
        "--max-items",
        "2",
        "--sort",
        "uri",
        "--order",
        "asc",
        "--option",
        "ovOnly",
        "--default-max-values",
        "10",
        "--activeness",
        "active",
        "--score-enabled",
    ]);
    let output = run_process(command).await;
    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"].as_array().map(Vec::len), Some(2));
    assert_eq!(envelope["meta"]["consistency"], "eventual");
    assert_eq!(envelope["meta"]["pagination"]["next_offset"], 2);
    let continuation = &envelope["meta"]["pagination"]["continuation"]["arguments"];
    assert_eq!(continuation["filter"], filter);
    assert_eq!(continuation["fields"], "uri,type");
    assert_eq!(continuation["sort"], "uri");
    assert_eq!(continuation["order"], "asc");
    assert_eq!(continuation["options"], json!(["ovOnly"]));
    assert_eq!(continuation["default_max_values"], 10);
    assert_eq!(continuation["activeness"], "active");
    assert_eq!(continuation["score_enabled"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_search_filter_guard_precedes_typed_and_raw_post_network_io() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let filter = "x".repeat(reltio_client::entities::QUERY_FILTER_CHARACTER_LIMIT + 1);

    let mut typed = harness.command();
    typed
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["entity", "search", "--filter", &filter]);
    let output = run_process(typed).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("typed error JSON")["error"]["code"],
        "query_filter_too_long"
    );

    let body = json!({ "filter": filter, "max": 1, "offset": 0 }).to_string();
    let mut raw = harness.command();
    raw.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "POST",
        "/entities/_search",
        "--service",
        "data",
        "--data",
        &body,
    ]);
    let output = run_process(raw).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("raw error JSON")["error"]["code"],
        "query_filter_too_long"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_search_boundary_warning_reaches_structured_raw_and_table_outputs() {
    let server = MockServer::start().await;
    let boundary_body = br#"[{"uri":"entities/10000"}]"#;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(body_json(json!({ "max": 1, "offset": 9999 })))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(boundary_body.as_slice(), "application/json"),
        )
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(body_json(json!({ "max": 2, "offset": 9998 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uri": "entities/9999"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for format in ["json", "raw", "table"] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "--output",
            format,
            "entity",
            "search",
            "--offset",
            "9999",
            "--max-items",
            "1",
        ]);
        let output = run_process(command).await;
        assert_success(&output);

        if format == "json" {
            let envelope = stdout_json(&output);
            assert_eq!(envelope["meta"]["pagination"]["boundary_reached"], true);
            assert!(
                envelope["meta"]["warnings"][0]
                    .as_str()
                    .is_some_and(|warning| warning.contains("10,000-result"))
            );
            assert!(output.stderr.is_empty());
        } else {
            assert!(String::from_utf8_lossy(&output.stderr).contains("10,000-result"));
            if format == "raw" {
                assert_eq!(output.stdout, boundary_body);
            } else {
                assert!(String::from_utf8_lossy(&output.stdout).contains("entities/10000"));
            }
        }
    }

    let mut short_page = harness.command();
    short_page.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--output",
        "table",
        "entity",
        "search",
        "--offset",
        "9998",
        "--max-items",
        "2",
    ]);
    let output = run_process(short_page).await;
    assert_success(&output);
    assert!(output.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_entity_search_boundary_warning_reaches_reviewed_api_outputs() {
    let server = MockServer::start().await;
    let boundary_body = br#"[{"uri":"entities/10000"}]"#;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(body_json(json!({ "max": 1, "offset": 9999 })))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(boundary_body.as_slice(), "application/json"),
        )
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(body_json(json!({ "max": 2, "offset": 9998 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uri": "entities/9999"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities"))
        .and(query_param("offset", "9999"))
        .and(query_param("max", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uri": "entities/10000"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for format in ["json", "raw", "table"] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
            "--output",
            format,
            "api",
            "request",
            "POST",
            "/entities/_search",
            "--service",
            "data",
            "--data",
            r#"{"max":1,"offset":9999}"#,
        ]);
        let output = run_process(command).await;
        assert_success(&output);

        if format == "json" {
            let envelope = stdout_json(&output);
            assert_eq!(envelope["meta"]["practice_coverage"], "reviewed");
            assert!(
                envelope["meta"]["warnings"][0]
                    .as_str()
                    .is_some_and(|warning| warning.contains("10,000-result"))
            );
            assert!(output.stderr.is_empty());
        } else {
            assert!(String::from_utf8_lossy(&output.stderr).contains("10,000-result"));
            if format == "raw" {
                assert_eq!(output.stdout, boundary_body);
            } else {
                assert!(String::from_utf8_lossy(&output.stdout).contains("entities/10000"));
            }
        }
    }

    let mut get_search = harness.command();
    get_search.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "GET",
        "/entities",
        "--service",
        "data",
        "--query",
        "offset=9999",
        "--query",
        "max=1",
    ]);
    let output = run_process(get_search).await;
    assert_success(&output);
    assert!(
        stdout_json(&output)["meta"]["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("10,000-result"))))
    );

    let mut short_page = harness.command();
    short_page.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--output",
        "table",
        "api",
        "request",
        "POST",
        "/entities/_search",
        "--service",
        "data",
        "--data",
        r#"{"max":2,"offset":9998}"#,
    ]);
    let output = run_process(short_page).await;
    assert_success(&output);
    assert!(output.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_online_uses_the_registered_search_contract() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer opaque-token"))
        .and(body_json(json!({
            "select": "URI",
            "max": 1,
            "offset": 0
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-request-id", "doctor-request-1")
                .set_body_json(json!([])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["doctor", "--online"]);

    let output = run_process(command).await;
    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["healthy"], true);
    assert_eq!(envelope["meta"]["practice_coverage"], "reviewed");
    assert_eq!(envelope["meta"]["consistency"], "eventual");
    assert_eq!(envelope["meta"]["request_id"], "doctor-request-1");
    assert!(
        envelope["meta"]["practice_ids"]
            .as_array()
            .expect("practice IDs")
            .contains(&Value::String("ENTITY-SEARCH-POST-001".to_owned()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_unhealthy_online_check_is_a_structured_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer opaque-token"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("x-request-id", "doctor-failure-1")
                .set_body_json(json!({"message": "temporary failure"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["doctor", "--online"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured doctor error");
    assert_eq!(error["error"]["code"], "doctor_unhealthy");
    assert_eq!(error["error"]["category"], "api");
    assert_eq!(error["error"]["http_status"], 500);
    assert_eq!(error["error"]["request_id"], "doctor-failure-1");
    assert_eq!(error["error"]["details"]["healthy"], false);
    assert_eq!(error["error"]["details"]["online"], true);
    assert!(
        error["error"]["details"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "tenant.read" && check["status"] == "fail")
    );
}

#[test]
fn doctor_reports_config_parse_failures_in_its_diagnostic_contract() {
    let harness = Harness::new();
    reltio_client::fs::atomic_write_private(&harness.config_path(), b"not valid [ TOML\n")
        .expect("invalid private config");

    let output = harness
        .command()
        .arg("doctor")
        .output()
        .expect("doctor executes");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured doctor error");
    assert_eq!(error["error"]["code"], "doctor_unhealthy");
    assert_eq!(error["error"]["details"]["target"], Value::Null);
    assert!(
        error["error"]["details"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "config.parse" && check["status"] == "fail")
    );
}

#[test]
fn doctor_reports_target_resolution_failures_in_its_diagnostic_contract() {
    let harness = Harness::new();

    let output = harness
        .command()
        .arg("doctor")
        .output()
        .expect("doctor executes");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured doctor error");
    assert_eq!(error["error"]["code"], "doctor_unhealthy");
    assert_eq!(error["error"]["details"]["target"], Value::Null);
    assert!(
        error["error"]["details"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "target.resolve" && check["status"] == "fail")
    );
}

#[cfg(unix)]
#[test]
fn doctor_reports_insecure_config_permissions_in_its_diagnostic_contract() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::new();
    harness.add_profile(None);
    fs::set_permissions(harness.config_path(), fs::Permissions::from_mode(0o644))
        .expect("make config insecure");

    let output = harness
        .command()
        .arg("doctor")
        .output()
        .expect("doctor executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured doctor error");
    assert_eq!(error["error"]["code"], "doctor_unhealthy");
    assert!(
        error["error"]["details"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "config.permissions" && check["status"] == "fail")
    );
}

#[test]
fn doctor_warning_requires_attention_and_a_nonzero_exit() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);
    let cache_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .next()
        .expect("bearer cache path");
    let mut cache: Value =
        serde_json::from_slice(&fs::read(&cache_path).expect("read cache")).expect("cache JSON");
    cache["expires_at"] =
        Value::String((chrono::Utc::now() - chrono::TimeDelta::minutes(1)).to_rfc3339());
    reltio_client::fs::atomic_write_private(
        &cache_path,
        &serde_json::to_vec(&cache).expect("encode expired cache"),
    )
    .expect("expire cache");

    let output = harness
        .command()
        .arg("doctor")
        .output()
        .expect("doctor executes");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured doctor error");
    assert_eq!(error["error"]["code"], "doctor_unhealthy");
    let checks = error["error"]["details"]["checks"]
        .as_array()
        .expect("doctor checks");
    assert!(checks.iter().all(|check| check["status"] != "fail"));
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "auth.offline" && check["status"] == "warn")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_guards_credentials_carried_by_caught_online_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer api_internal_error"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "api_internal_error")
        .args(["doctor", "--online"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("api_internal_error"));
    let fields = serde_json::from_slice::<Value>(&output.stderr).expect("guarded doctor error");
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert_eq!(fields[1], "doctor_unhealthy");
    assert_eq!(fields[2], "api");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_streams_pages_and_writes_resume_checkpoint() {
    let server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .and(query_param("filter", filter))
        .and(query_param("max", "1"))
        .and(body_bytes(Vec::<u8>::new()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .and(query_param("max", "1"))
        .and(body_json(json!({"cursor": {"value": "cursor-1"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-2"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let resume = harness.directory.path().join("scan.resume.json");
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--page-size",
        "1",
        "--resume-file",
        resume.to_str().expect("UTF-8 path"),
    ]);
    let output = run_process(command).await;
    assert_success(&output);
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .expect("UTF-8 JSONL")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid event"))
        .collect();
    assert_eq!(
        events.first().and_then(|event| event["type"].as_str()),
        Some("item")
    );
    assert_eq!(
        events.last().and_then(|event| event["type"].as_str()),
        Some("summary")
    );
    assert_eq!(events.last().unwrap()["meta"]["exhausted"], true);
    assert_eq!(events.first().unwrap()["meta"]["consistency"], "eventual");
    assert_eq!(events.last().unwrap()["meta"]["consistency"], "eventual");
    let checkpoint: Value = serde_json::from_slice(&fs::read(&resume).expect("resume file"))
        .expect("valid resume JSON");
    assert_eq!(checkpoint["cursor"], "cursor-2");
    assert_eq!(checkpoint["exhausted"], true);
    assert_eq!(checkpoint["cli_version"], env!("CARGO_PKG_VERSION"));

    let mut resumed = harness.command();
    resumed.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--page-size",
        "1",
        "--resume-file",
        resume.to_str().expect("UTF-8 path"),
    ]);
    let output = run_process(resumed).await;
    assert_success(&output);
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .expect("UTF-8 JSONL")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid event"))
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "summary");
    assert_eq!(events[0]["meta"]["returned_this_run"], 0);
    assert_eq!(events[0]["meta"]["exhausted"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_custom_errors_keep_the_cumulative_output_guard() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .and(header("authorization", "Bearer unsafe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}, {"uri": "entities/2"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "unsafe").args([
        "entity",
        "scan",
        "--filter",
        "equals(type,'configuration/entityTypes/Organization')",
        "--page-size",
        "1",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("unsafe"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_scan_shape_does_not_echo_protected_cursor_values() {
    let server = MockServer::start().await;
    let cursor = "protected-cursor-value";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": {"secret": cursor}},
            "objects": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        "equals(type,'configuration/entityTypes/Organization')",
        "--max-pages",
        "1",
    ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(!stderr.contains(cursor));
    assert_eq!(
        serde_json::from_str::<Value>(&stderr).expect("structured error")["error"]["code"],
        "api_response_invalid_json"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_refuses_invalid_or_mismatched_resume_context() {
    let server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}]
        })))
        .expect(2)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let resume = harness.directory.path().join("scan.resume.json");
    let resume_text = resume.to_str().expect("UTF-8 path");
    let mut first = harness.command();
    first.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--page-size",
        "1",
        "--max-pages",
        "1",
        "--resume-file",
        resume_text,
    ]);
    assert_success(&run_process(first).await);

    let mut second = harness.command();
    second.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--page-size",
        "2",
        "--resume-file",
        resume_text,
    ]);
    let output = run_process(second).await;
    assert_eq!(output.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "resume_context_mismatch");

    let mut changed_query = harness.command();
    changed_query
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "entity",
            "scan",
            "--filter",
            filter,
            "--page-size",
            "1",
            "--option",
            "ovOnly",
            "--resume-file",
            resume_text,
        ]);
    let output = run_process(changed_query).await;
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resume_context_mismatch"
    );

    let mut state: Value =
        serde_json::from_slice(&fs::read(&resume).expect("resume file")).expect("resume JSON");
    state["cursor"] = Value::Null;
    reltio_client::fs::atomic_write_private(
        &resume,
        &serde_json::to_vec(&state).expect("encode resume"),
    )
    .expect("replace resume");
    let mut missing_cursor = harness.command();
    missing_cursor
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "entity",
            "scan",
            "--filter",
            filter,
            "--page-size",
            "1",
            "--resume-file",
            resume_text,
        ]);
    let output = run_process(missing_cursor).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resume_file_invalid"
    );

    state["cursor"] = Value::String("cursor-1".to_owned());
    state["sequence"] = Value::from(u64::MAX);
    reltio_client::fs::atomic_write_private(
        &resume,
        &serde_json::to_vec(&state).expect("encode resume"),
    )
    .expect("replace resume");
    let mut maximum_sequence = harness.command();
    maximum_sequence
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "entity",
            "scan",
            "--filter",
            filter,
            "--page-size",
            "1",
            "--resume-file",
            resume_text,
        ]);
    let output = run_process(maximum_sequence).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resume_file_invalid"
    );

    state["sequence"] = Value::from(u64::MAX - 1);
    reltio_client::fs::atomic_write_private(
        &resume,
        &serde_json::to_vec(&state).expect("encode resume"),
    )
    .expect("replace resume");
    let mut exhausted_sequence = harness.command();
    exhausted_sequence
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "entity",
            "scan",
            "--filter",
            filter,
            "--page-size",
            "1",
            "--max-pages",
            "1",
            "--resume-file",
            resume_text,
        ]);
    let output = run_process(exhausted_sequence).await;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "resume_file_invalid");
    assert_eq!(error["error"]["details"]["reason"], "sequence_out_of_range");
    let unchanged: Value =
        serde_json::from_slice(&fs::read(&resume).expect("resume file")).expect("resume JSON");
    assert_eq!(unchanged["sequence"], Value::from(u64::MAX - 1));
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_resume_is_bound_to_cli_version() {
    let server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let resume = harness.directory.path().join("version.resume.json");
    let resume_text = resume.to_str().expect("UTF-8 path");
    let mut first = harness.command();
    first.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--max-pages",
        "1",
        "--resume-file",
        resume_text,
    ]);
    assert_success(&run_process(first).await);
    let mut state: Value =
        serde_json::from_slice(&fs::read(&resume).expect("resume file")).expect("resume JSON");
    state["cli_version"] = Value::String("0.0.0-different".to_owned());
    reltio_client::fs::atomic_write_private(
        &resume,
        &serde_json::to_vec(&state).expect("encode resume"),
    )
    .expect("replace resume");

    let mut resumed = harness.command();
    resumed.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--resume-file",
        resume_text,
    ]);
    let output = run_process(resumed).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resume_context_mismatch"
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_refuses_an_expired_resume_cursor() {
    let server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let resume = harness.directory.path().join("expired.resume.json");
    let resume_text = resume.to_str().expect("UTF-8 path");
    let mut first = harness.command();
    first.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--max-pages",
        "1",
        "--resume-file",
        resume_text,
    ]);
    assert_success(&run_process(first).await);
    let mut state: Value =
        serde_json::from_slice(&fs::read(&resume).expect("resume file")).expect("resume JSON");
    state["acquired_at"] =
        Value::String((chrono::Utc::now() - chrono::TimeDelta::hours(3)).to_rfc3339());
    state["last_read_at"] =
        Value::String((chrono::Utc::now() - chrono::TimeDelta::hours(2)).to_rfc3339());
    state["expires_at"] =
        Value::String((chrono::Utc::now() + chrono::TimeDelta::hours(24)).to_rfc3339());
    reltio_client::fs::atomic_write_private(
        &resume,
        &serde_json::to_vec(&state).expect("encode resume"),
    )
    .expect("replace resume");

    let mut resumed = harness.command();
    resumed.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--resume-file",
        resume_text,
    ]);
    let output = run_process(resumed).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "resume_cursor_expired"
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_rejects_non_utf8_resume_path_before_network() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let resume = harness
        .directory
        .path()
        .join(OsString::from_vec(b"resume-\xff.json".to_vec()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "entity",
            "scan",
            "--filter",
            "equals(type,'configuration/entityTypes/Organization')",
            "--resume-file",
        ])
        .arg(&resume);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("error JSON")["error"]["code"],
        "invalid_resume_file_path"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entity_scan_resume_is_bound_to_original_service_route() {
    let first_server = MockServer::start().await;
    let filter = "equals(type,'configuration/entityTypes/Organization')";
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cursor": {"value": "cursor-1"},
            "objects": [{"uri": "entities/1"}]
        })))
        .expect(1)
        .mount(&first_server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&first_server.uri()));
    let resume = harness.directory.path().join("route.resume.json");
    let resume_text = resume.to_str().expect("UTF-8 path");
    let mut first = harness.command();
    first.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--max-pages",
        "1",
        "--resume-file",
        resume_text,
    ]);
    assert_success(&run_process(first).await);

    let second_server = MockServer::start().await;
    let mut update = harness.command();
    let output = update
        .args([
            "profile",
            "update",
            "test",
            "--base-url",
            &second_server.uri(),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);

    let mut resumed = harness.command();
    resumed.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "entity",
        "scan",
        "--filter",
        filter,
        "--resume-file",
        resume_text,
    ]);
    let output = run_process(resumed).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "resume_context_mismatch"
    );
    assert!(second_server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_500_is_not_retried_and_echoed_token_is_redacted() {
    let server = MockServer::start().await;
    let token = format!("s.{}", "x".repeat(4096));
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "message": format!("server echoed {token}")
        })))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", &token)
        .args(["entity", "get", "1"]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(!stderr.contains(&token));
    let error: Value = serde_json::from_str(&stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "api_internal_error");
    assert_eq!(error["error"]["details"]["attempts"], 1);
}

#[test]
fn raw_mutation_and_protected_header_are_refused_before_network_io() {
    let harness = Harness::new();
    harness.add_profile(None);
    let mut mutation = harness.command();
    let output = mutation
        .args([
            "api",
            "request",
            "DELETE",
            "/entities/1",
            "--service",
            "data",
        ])
        .output()
        .expect("raw request executes");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "unreviewed_mutation_refused"
    );

    let mut protected = harness.command();
    let output = protected
        .args([
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
            "--header",
            "Authorization: Bearer bad",
        ])
        .output()
        .expect("raw request executes");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "protected_header_refused"
    );

    let output = harness
        .command()
        .args([
            "--yes",
            "api",
            "request",
            "POST",
            "/",
            "--service",
            "mcp",
            "--data",
            r#"{"method":"admin/deleteTenant","params":{"arguments":{"tenant_id":"TestTenant"}}}"#,
            "--allow-unreviewed-endpoint",
        ])
        .output()
        .expect("raw MCP request executes");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "raw_mcp_mutation_refused"
    );
}

#[test]
fn release_gate_reports_prd_blockers_and_refuses_stable_readiness() {
    let harness = Harness::new();
    let report = harness
        .command()
        .args(["--compact", "api", "practices", "check", "--strict"])
        .output()
        .expect("practice report executes");
    assert_success(&report);
    let readiness = &stdout_json(&report)["data"]["release_requirements"];
    assert_eq!(readiness["required_operation_count"], 50);
    assert_eq!(readiness["command_present_count"], 28);
    assert_eq!(readiness["missing_command_count"], 22);
    assert_eq!(
        readiness["acceptance_scenarios"].as_array().map(Vec::len),
        Some(19)
    );
    assert_eq!(readiness["release_ready"], false);

    let refused = harness
        .command()
        .args(["api", "practices", "check", "--release-ready"])
        .output()
        .expect("release gate executes");
    assert_eq!(refused.status.code(), Some(5));
    assert!(refused.stdout.is_empty());
    let error: Value = serde_json::from_slice(&refused.stderr).expect("release gate error");
    assert_eq!(error["error"]["code"], "release_operations_incomplete");
    assert_eq!(error["error"]["details"]["required_operation_count"], 50);
    assert_eq!(error["error"]["details"]["release_ready"], false);

    let version_mismatch = harness
        .command()
        .args([
            "api",
            "practices",
            "check",
            "--release-ready",
            "--expected-release",
            "v9.9.9",
        ])
        .output()
        .expect("version-bound release gate executes");
    assert_eq!(version_mismatch.status.code(), Some(5));
    let error: Value =
        serde_json::from_slice(&version_mismatch.stderr).expect("version mismatch error");
    assert_eq!(error["error"]["code"], "release_version_mismatch");
    assert_eq!(error["error"]["details"]["expected_release"], "9.9.9");
    assert_eq!(error["error"]["details"]["manifest_release"], "0.1.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_audit_absence_fails_closed_before_network_io() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/mutate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--yes",
        "api",
        "request",
        "POST",
        "/mutate",
        "--service",
        "data",
        "--data",
        r#"{"mutation":"applied"}"#,
        "--allow-unreviewed-endpoint",
    ]);
    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("structured refusal");
    assert_eq!(error["error"]["code"], "mutation_audit_unavailable");
    assert_eq!(error["error"]["category"], "safety");
    assert_eq!(error["error"]["retryable"], false);
    let details = &error["error"]["details"];
    assert_eq!(details["required_contract"], "mutation_audit_v1");
    assert_eq!(details["body_sha256"].as_str().map(str::len), Some(64));
    assert_eq!(details["remote_response_received"], false);
    assert_eq!(details["remote_request_completed"], false);
    assert_eq!(details["remote_operation_completed"], false);
    assert_eq!(details["remote_operation_state"], "request_not_sent");
    assert_eq!(details["safe_to_replay"], true);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_during_login_exits_130_without_committing_or_disclosing_provider_output() {
    use std::process::Stdio;

    use rustix::process::{Pid, Signal, kill_process};

    let auth = MockServer::start().await;
    let issued_token = "sigint-newly-issued-token";
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(2))
                .set_body_json(json!({
                    "access_token": issued_token,
                    "token_type": "bearer",
                    "expires_in": 3600
                })),
        )
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let config_before = fs::read(harness.config_path()).expect("read profile preimage");
    let client_secret = "sigint-client-secret";
    let mut command = harness.command();
    command
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", client_secret)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);
    let mut child = command.spawn().expect("CLI process starts");
    let pid = Pid::from_child(&child);

    let mut observed = false;
    for _ in 0..500 {
        if auth
            .received_requests()
            .await
            .expect("received token requests")
            .len()
            == 1
        {
            observed = true;
            break;
        }
        assert!(
            child.try_wait().expect("inspect CLI process").is_none(),
            "CLI exited before token acquisition reached the server"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(observed, "the token request did not reach the server");

    kill_process(pid, Signal::INT).expect("send SIGINT");
    let output = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .expect("wait task completes")
        .expect("CLI process completes");

    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(issued_token));
    assert!(!stderr.contains(client_secret));
    assert_eq!(
        fs::read(harness.config_path()).expect("read profile after SIGINT"),
        config_before
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_output_conflict_is_rejected_before_mutation() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--output",
        "raw",
        "--yes",
        "api",
        "request",
        "DELETE",
        "/entities/1",
        "--service",
        "data",
        "--include-headers",
        "--allow-unreviewed-endpoint",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "raw_headers_ambiguous"
    );

    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "--output",
        "raw",
        "--dry-run",
        "api",
        "request",
        "DELETE",
        "/entities/1",
        "--service",
        "data",
    ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "dry_run_raw_output_unsupported"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_success_redacts_credentials_without_corrupting_ordinary_data() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "opaque-token": "credential-key",
            "refresh_token": "upstream-refresh-secret",
            "password": "ordinary-upstream-value",
            "message": "password=ordinary-upstream-value"
        })))
        .expect(2)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "opaque-token");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args(["api", "request", "GET", "/entities/1", "--service", "data"]);
        let output = run_process(command).await;
        assert_success(&output);
        let value: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
        let data = if raw { &value } else { &value["data"] };
        let rendered = data.to_string();
        assert!(!rendered.contains("opaque-token"));
        assert!(!rendered.contains("upstream-refresh-secret"));
        assert_eq!(data["refresh_token"], "[REDACTED]");
        assert_eq!(data["password"], "ordinary-upstream-value");
        assert_eq!(data["message"], "password=ordinary-upstream-value");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_api_warnings_are_preflighted_against_the_local_guard() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/custom"))
        .and(header("authorization", "Bearer unknown"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"safe": "visible"})))
        .expect(0)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "unknown").args([
        "--output",
        "raw",
        "api",
        "request",
        "GET",
        "/custom",
        "--service",
        "data",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("unknown"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_renderer_refuses_credentials_synthesized_by_the_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/guard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"safe": "visible"})))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "data").args([
        "--compact",
        "api",
        "request",
        "GET",
        "/entities/guard",
        "--service",
        "data",
    ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("data"));
    let error: Value = serde_json::from_slice(&output.stderr).expect("guarded error JSON");
    assert_eq!(error["error"]["code"], "credential_output_refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_tokens_and_private_content_type_classification_are_redacted_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/encoded"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(b"secret%2Dtoken".as_slice(), "text/plain"),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/content-type"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"refresh_token":"upstream-refresh-secret"}"#.as_slice(),
            "application/json",
        ))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/binary"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            [b"\xff".as_slice(), b"secret%2Dtoken"].concat(),
            "application/octet-stream",
        ))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/token-syntax"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": "secret%252Dtoken"
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/overencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": "secret%25252Dtoken"
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/lexical"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(br#"{"value":1E-00}"#.as_slice(), "application/json"),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/serialized-token"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"value":"longprefix\"longsuffix"}"#.as_slice(),
            "application/json",
        ))
        .expect(2)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "secret-token");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args([
            "api",
            "request",
            "GET",
            "/entities/encoded",
            "--service",
            "data",
        ]);
        let output = run_process(command).await;
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret%2Dtoken"));
    }

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "json");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args([
            "api",
            "request",
            "GET",
            "/entities/content-type",
            "--service",
            "data",
        ]);
        let output = run_process(command).await;
        assert_success(&output);
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(!rendered.contains("upstream-refresh-secret"));
        let value: Value = serde_json::from_slice(&output.stdout).expect("sanitized JSON output");
        let data = if raw { &value } else { &value["data"] };
        assert_eq!(data["refresh_token"], "");
    }

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "secret-token");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args([
            "api",
            "request",
            "GET",
            "/entities/binary",
            "--service",
            "data",
        ]);
        let output = run_process(command).await;
        assert_success(&output);
        if raw {
            assert_eq!(output.stdout, b"[REDACTED]");
        } else {
            let encoded = stdout_json(&output)["data"]["data"]
                .as_str()
                .expect("base64 response data")
                .to_owned();
            assert_eq!(
                encoded,
                base64::engine::general_purpose::STANDARD.encode("[REDACTED]")
            );
        }
    }

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "secret%2Dtoken");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args(["entity", "get", "token-syntax"]);
        let output = run_process(command).await;
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret%252Dtoken"));
        assert!(String::from_utf8_lossy(&output.stdout).contains("[REDACTED]"));
    }

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "secret-token");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args(["entity", "get", "overencoded"]);
        let output = run_process(command).await;
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
    }

    for raw in [false, true] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "1E-00");
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args(["entity", "get", "lexical"]);
        let output = run_process(command).await;
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("1E-00"));
        serde_json::from_slice::<Value>(&output.stdout).expect("sanitized JSON output");
    }

    for raw in [false, true] {
        let token = r#"longprefix\"longsuffix"#;
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", token);
        if raw {
            command.args(["--output", "raw"]);
        }
        command.args(["entity", "get", "serialized-token"]);
        let output = run_process(command).await;
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
        serde_json::from_slice::<Value>(&output.stdout).expect("sanitized JSON output");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_credential_assignments_are_redacted_from_api_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "refresh%5Ftoken=upstream-refresh-secret"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/serialized-token"))
        .respond_with(ResponseTemplate::new(400).set_body_raw(
            br#"{"value":"longprefix\"longsuffix"}"#.as_slice(),
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "GET",
        "/entities/1",
        "--service",
        "data",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("upstream-refresh-secret"));

    let token = r#"longprefix\"longsuffix"#;
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", token).args([
        "api",
        "request",
        "GET",
        "/entities/serialized-token",
        "--service",
        "data",
    ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
    serde_json::from_slice::<Value>(&output.stderr).expect("sanitized error JSON");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_header_is_rejected_before_stdin_or_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "POST",
        "/entities/1",
        "--service",
        "data",
        "--data",
        "-",
        "--header",
        "Authorization: secret",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "protected_header_refused"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn underscore_header_is_rejected_before_stdin_or_network() {
    use std::io::Seek as _;
    use std::process::Stdio;

    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let input_path = harness.directory.path().join("unread-underscore-body");
    fs::write(&input_path, br#"{"must":"remain unread"}"#).expect("stdin fixture");
    let mut input = fs::File::open(&input_path).expect("open stdin fixture");
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .stdin(Stdio::from(
            input.try_clone().expect("duplicate stdin fixture"),
        ))
        .args([
            "api",
            "request",
            "POST",
            "/entities/1",
            "--service",
            "data",
            "--data",
            "-",
            "--header",
            "X_Workflow_ID: benign-looking",
        ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("structured header error")["error"]
            ["code"],
        "ambiguous_header_name_refused"
    );
    assert_eq!(input.stream_position().expect("stdin position"), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_scan_preflight_rejects_duplicate_filter_without_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "POST",
        "/entities/_scan",
        "--service",
        "data",
        "--query",
        "filter=short",
        "--query",
        &format!("filter={}", "x".repeat(300)),
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "duplicate_query_parameter"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_scan_preflight_rejects_invalid_cursor_without_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "POST",
        "/entities/_scan",
        "--service",
        "data",
        "--query",
        "max=100",
        "--data",
        r#"{"cursor":{"value":""}}"#,
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "scan_cursor_empty"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn raw_search_preflight_accepts_the_official_body_schema() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "--no-retry",
            "api",
            "request",
            "POST",
            "/entities/_search",
            "--service",
            "data",
            "--data",
            r#"{"options":"sortByOV,ovOnly","defaultMaxValues":10,"max":1,"offset":0}"#,
        ])
        .output()
        .expect("raw search preflight executes");

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["practice_coverage"], "reviewed");
    assert_eq!(envelope["data"]["endpoint_id"], "entity.search");
    assert_eq!(envelope["data"]["retry_policy"]["classification"], "safe");
    assert_eq!(
        envelope["data"]["retry_policy"]["automatic_retries_enabled"],
        false
    );
    assert_eq!(envelope["data"]["retry_policy"]["no_retry"], true);
}

#[test]
fn deterministic_entity_validation_precedes_profile_resolution() {
    let harness = Harness::new();
    let search = harness
        .command()
        .args(["entity", "search", "--offset", "9999", "--max-items", "2"])
        .output()
        .expect("search executes");
    assert_eq!(search.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&search.stderr).unwrap()["error"]["code"],
        "entity_search_boundary_exceeded"
    );

    let get = harness
        .command()
        .args(["entity", "get", "entities/a/b"])
        .output()
        .expect("get executes");
    assert_eq!(get.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&get.stderr).unwrap()["error"]["code"],
        "invalid_entity_uri"
    );

    for entity in [
        "entities/1?select=uri",
        "entities/1#fragment",
        "entities/1 ",
    ] {
        let output = harness
            .command()
            .args(["entity", "get", entity])
            .output()
            .expect("get executes");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
            "invalid_entity_uri"
        );
    }

    for arguments in [
        vec!["--fields", "URI", "entity", "get", "entities/1"],
        vec!["entity", "get", "entities/1", "--option", "sortByOV"],
    ] {
        let output = harness
            .command()
            .args(arguments)
            .output()
            .expect("invalid Get Entity contract executes");
        assert_eq!(output.status.code(), Some(2));
        assert!(matches!(
            serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"].as_str(),
            Some("invalid_query_value" | "invalid_entity_option")
        ));
    }
}

#[test]
fn missing_raw_input_file_is_a_usage_error_before_profile_resolution() {
    let harness = Harness::new();
    let missing = harness.directory.path().join("missing.json");
    let output = harness
        .command()
        .args([
            "api",
            "request",
            "POST",
            "/entities/_search",
            "--service",
            "data",
            "--data",
            &format!("@{}", missing.display()),
        ])
        .output()
        .expect("raw request executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "local_input_unreadable"
    );
}

#[test]
fn enormous_timeout_is_a_usage_error_instead_of_a_panic() {
    let harness = Harness::new();
    let output = harness
        .command()
        .args(["--timeout", "18446744073709551615s", "entity", "get", "1"])
        .output()
        .expect("command executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "invalid_cli_usage"
    );
}

#[test]
fn output_environment_is_validated_and_formats_parse_errors() {
    let harness = Harness::new();
    let invalid = harness
        .command()
        .env("RELTIO_OUTPUT", "bogus")
        .args(["profile", "list"])
        .output()
        .expect("invalid output command executes");
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&invalid.stderr).unwrap()["error"]["code"],
        "invalid_output_format"
    );

    let mut environment_table = harness.command();
    environment_table
        .env("RELTIO_OUTPUT", "table")
        .arg("--definitely-invalid");
    let mut equals_table = harness.command();
    equals_table.args(["--output=table", "--definitely-invalid"]);
    for mut command in [environment_table, equals_table] {
        let output = command.output().expect("table parse error executes");
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).starts_with("error[invalid_cli_usage]:"));
    }

    let explicit = harness
        .command()
        .env("RELTIO_OUTPUT", "bogus")
        .args(["--output", "json", "profile", "list"])
        .output()
        .expect("explicit output command executes");
    assert_success(&explicit);
}

#[test]
fn guarded_usage_errors_never_mutate_documented_object_fields() {
    let harness = Harness::new();
    for token in ["false", "error"] {
        let output = harness
            .command()
            .env("RELTIO_ACCESS_TOKEN", token)
            .arg("--definitely-invalid")
            .output()
            .expect("invalid command executes");

        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
        let fields: Value = serde_json::from_slice(&output.stderr).expect("guarded error JSON");
        assert_eq!(fields.as_array().unwrap().len(), 12);
        assert_eq!(fields[0], "reltio_guarded_failure");
        assert_eq!(fields[1], "invalid_cli_usage");
        assert_eq!(fields[2], "usage");
        assert_eq!(fields[3], 0);
        assert_eq!(fields[6], -1);
        assert_eq!(fields[7], -1);
        assert_eq!(fields[11], -1);
    }
}

#[test]
fn environment_tenant_confirmation_is_honored_for_dry_run() {
    let harness = Harness::new();
    harness.add_profile(None);
    let mut command = harness.command();
    let output = command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .env("RELTIO_CONFIRM_TENANT", "TestTenant")
        .args([
            "--tenant",
            "TestTenant",
            "--yes",
            "--dry-run",
            "api",
            "request",
            "DELETE",
            "/entities/1",
            "--service",
            "data",
            "--allow-unreviewed-endpoint",
        ])
        .output()
        .expect("dry run executes");

    assert_success(&output);
    assert_eq!(stdout_json(&output)["data"]["network_request_sent"], false);
}

#[test]
fn dry_run_redacts_configured_opaque_credentials_from_the_plan() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-access-secret")
        .env("RELTIO_CLIENT_SECRET", "opaque-client-secret")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
            "--query",
            "futureOne=opaque-access-secret",
            "--query",
            "futureTwo=opaque-client-secret",
        ])
        .output()
        .expect("credential-bearing preflight executes");

    assert_success(&output);
    let rendered = String::from_utf8(output.stdout).expect("UTF-8 dry-run output");
    assert!(!rendered.contains("opaque-access-secret"));
    assert!(!rendered.contains("opaque-client-secret"));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn changed_namespace_cannot_displace_profile_routing_even_with_confirmations() {
    let harness = Harness::new();
    harness.add_profile(Some("https://profile.example.com"));
    let mut command = harness.command();
    let output = command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--environment",
            "override",
            "--tenant",
            "TestTenant",
            "--yes",
            "--confirm-tenant",
            "TestTenant",
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
        ])
        .output()
        .expect("dry run executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("routing error")["error"]["code"],
        "unsafe_profile_routing_override"
    );
}

#[test]
fn same_environment_flag_and_environment_variable_preserve_private_data_route() {
    let harness = Harness::new();
    harness.add_profile(Some("https://fallback.example"));
    harness.set_service_url(
        "test",
        "data",
        "https://private.example/private/reltio/{tenant}",
    );
    for source in ["flag", "environment"] {
        let mut command = harness.command();
        command.env("RELTIO_ACCESS_TOKEN", "invocation-token");
        if source == "flag" {
            command.args(["--environment", "test"]);
        } else {
            command.env("RELTIO_ENVIRONMENT", "test");
        }
        let output = command
            .args([
                "--dry-run",
                "api",
                "request",
                "GET",
                "/entities/1",
                "--service",
                "data",
            ])
            .output()
            .expect("same-environment dry run executes");

        assert_success(&output);
        assert_eq!(
            stdout_json(&output)["data"]["url"],
            "https://private.example/private/reltio/TestTenant/entities/1",
            "{source} source"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_profile_route_with_profile_credentials_sends_no_auth_or_data_request() {
    let profile_data = MockServer::start().await;
    let destination_data = MockServer::start().await;
    let auth = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url(
        "test",
        "data",
        &format!("{}/reltio/api/{{tenant}}", profile_data.uri()),
    );
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("profile-route-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"profile-secret")
        .expect("private profile secret");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "profile-client",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile auth update executes");
    assert_success(&output);

    let mut command = harness.command();
    command.args([
        "--environment",
        &destination_data.uri(),
        "--tenant",
        "NewTenant",
        "--yes",
        "--confirm-tenant",
        "NewTenant",
        "entity",
        "get",
        "entities/1",
    ]);
    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("routing error")["error"]["code"],
        "unsafe_profile_routing_override"
    );
    assert!(
        auth.received_requests()
            .await
            .expect("Auth requests")
            .is_empty()
    );
    assert!(
        profile_data
            .received_requests()
            .await
            .expect("profile Data requests")
            .is_empty()
    );
    assert!(
        destination_data
            .received_requests()
            .await
            .expect("destination Data requests")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_changed_route_and_tenant_send_only_environment_bearer() {
    let profile_data = MockServer::start().await;
    let destination_data = MockServer::start().await;
    let auth = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/NewTenant/entities/1"))
        .and(header("authorization", "Bearer invocation-route-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "entities/1"
        })))
        .expect(1)
        .mount(&destination_data)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url(
        "test",
        "data",
        &format!("{}/reltio/api/{{tenant}}", profile_data.uri()),
    );
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("displaced-profile-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"profile-secret")
        .expect("private profile secret");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "profile-client",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile auth update executes");
    assert_success(&output);

    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "invocation-route-token")
        .args([
            "--environment",
            &destination_data.uri(),
            "--tenant",
            "NewTenant",
            "entity",
            "get",
            "entities/1",
        ]);
    let output = run_process(command).await;

    assert_success(&output);
    assert!(
        auth.received_requests()
            .await
            .expect("Auth requests")
            .is_empty()
    );
    assert!(
        profile_data
            .received_requests()
            .await
            .expect("profile Data requests")
            .is_empty()
    );
    assert_eq!(
        destination_data
            .received_requests()
            .await
            .expect("destination Data requests")
            .len(),
        1
    );
}

#[test]
fn profile_rejects_static_data_tenant_route_and_dot_tenant() {
    let harness = Harness::new();
    let output = harness
        .command()
        .args([
            "profile",
            "add",
            "bad-route",
            "--environment",
            "test",
            "--tenant",
            "Tenant",
            "--service-url",
            "data=https://example.com/reltio/api/OtherTenant",
        ])
        .output()
        .expect("profile command executes");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "tenant_placeholder_required"
    );

    let output = harness
        .command()
        .args([
            "profile",
            "add",
            "bad-tenant",
            "--environment",
            "test",
            "--tenant",
            "..",
        ])
        .output()
        .expect("profile command executes");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "invalid_tenant"
    );
}

#[test]
fn bare_relative_config_path_is_supported() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("reltio"));
    let output = command
        .current_dir(directory.path())
        .env("RELTIO_CONFIG", "config.toml")
        .env("RELTIO_CACHE_DIR", "cache")
        .env("RELTIO_STATE_DIR", "state")
        .args([
            "profile",
            "add",
            "test",
            "--environment",
            "test",
            "--tenant",
            "TestTenant",
        ])
        .output()
        .expect("profile command executes");

    assert_success(&output);
    assert!(directory.path().join("config.toml").is_file());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_auth_login_preserves_previous_provider() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "invalid"})))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let output = harness
        .command()
        .args(["profile", "update", "test", "--auth-method", "bearer"])
        .output()
        .expect("profile update executes");
    assert_success(&output);

    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "secret")
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "new-client",
        ]);
    let output = run_process(login).await;
    assert_eq!(output.status.code(), Some(3));

    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&output);
    assert_eq!(stdout_json(&output)["data"]["auth"]["method"], "bearer");
}

#[test]
fn login_resolves_the_selected_profile_before_reading_secret_stdin() {
    use std::io::Seek as _;
    use std::process::Stdio;

    let harness = Harness::new();
    let input_path = harness.directory.path().join("candidate-secret");
    fs::write(&input_path, b"profile_not_found").expect("secret input fixture");
    let mut input = fs::File::open(&input_path).expect("open secret input");
    let mut command = harness.command();
    let output = command
        .stdin(Stdio::from(
            input.try_clone().expect("duplicate secret input handle"),
        ))
        .args([
            "--profile",
            "missing",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-stdin",
        ])
        .output()
        .expect("login process completes");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert_eq!(input.stream_position().expect("secret input position"), 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "profile_not_found"
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_rejects_changed_route_or_tenant_before_secret_stdin_or_network() {
    use std::io::Seek as _;
    use std::process::Stdio;

    let auth = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(None);
    let input_path = harness.directory.path().join("unread-login-secret");
    fs::write(&input_path, b"stdin-secret-must-remain-unread").expect("secret input fixture");
    let mut input = fs::File::open(&input_path).expect("open secret input");
    let mut command = harness.command();
    command
        .stdin(Stdio::from(
            input.try_clone().expect("duplicate secret input handle"),
        ))
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_ID", "environment-client")
        .env("RELTIO_CLIENT_SECRET", "environment-secret")
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--secret-stdin",
        ]);
    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("login routing error");
    assert_eq!(error["error"]["code"], "auth_login_target_override");
    assert_eq!(error["error"]["details"]["secret_input_consumed"], false);
    assert_eq!(error["error"]["details"]["network_request_sent"], false);
    assert_eq!(input.stream_position().expect("secret input position"), 0);
    assert!(
        auth.received_requests()
            .await
            .expect("Auth requests")
            .is_empty()
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());

    let tenant_input_path = harness.directory.path().join("unread-tenant-secret");
    fs::write(&tenant_input_path, b"tenant-secret-must-remain-unread")
        .expect("tenant secret input fixture");
    let mut tenant_input = fs::File::open(&tenant_input_path).expect("open tenant secret input");
    let mut command = harness.command();
    command
        .stdin(Stdio::from(
            tenant_input
                .try_clone()
                .expect("duplicate tenant secret input handle"),
        ))
        .args([
            "--tenant",
            "DifferentTenant",
            "--timeout",
            "1s",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "login-client",
            "--secret-stdin",
        ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&output.stderr).expect("login tenant error");
    assert_eq!(error["error"]["code"], "auth_login_target_override");
    assert_eq!(error["error"]["details"]["routing_overridden"], false);
    assert_eq!(error["error"]["details"]["tenant_overridden"], true);
    assert_eq!(
        tenant_input
            .stream_position()
            .expect("tenant secret input position"),
        0
    );
    assert!(
        auth.received_requests()
            .await
            .expect("Auth requests")
            .is_empty()
    );
}

#[test]
fn login_guards_displaced_secret_file_and_basic_credentials() {
    for (environment, client_id, secret, protected) in [
        ("test", "old-client", "auth.login", "auth.login"),
        ("enhxOnZ3", "zxq", "vw", "enhxOnZ3"),
    ] {
        let harness = Harness::new();
        let output = harness
            .command()
            .args([
                "profile",
                "add",
                "test",
                "--environment",
                environment,
                "--tenant",
                "TestTenant",
            ])
            .output()
            .expect("profile add executes");
        assert_success(&output);
        let secret_file = harness.directory.path().join("previous-secret");
        reltio_client::fs::atomic_write_private(&secret_file, secret.as_bytes())
            .expect("private prior secret file");
        let output = harness
            .command()
            .args([
                "profile",
                "update",
                "test",
                "--auth-method",
                "client-credentials",
                "--client-id",
                client_id,
                "--secret-file",
                secret_file.to_str().expect("UTF-8 path"),
            ])
            .output()
            .expect("profile update executes");
        assert_success(&output);
        let config_before = fs::read(harness.config_path()).expect("snapshot profile");

        let output = harness
            .command()
            .env("RELTIO_ACCESS_TOKEN", "candidate-bearer-token")
            .args([
                "--quiet",
                "auth",
                "login",
                "--method",
                "bearer",
                "--expires-in",
                "1h",
            ])
            .output()
            .expect("bearer login executes");

        assert_eq!(output.status.code(), Some(5));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(protected));
        assert_eq!(
            fs::read(harness.config_path()).expect("read unchanged profile"),
            config_before
        );
        assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newly_issued_token_guards_post_parse_authentication_errors() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "bearer",
            "token_type": "MAC",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "fixture-client-credential-9f4c2a7b")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("bearer"));
    let fields: Value = serde_json::from_slice(&output.stderr).expect("guarded error JSON");
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert_eq!(fields[1], "auth_token_type_unsupported");
    assert_eq!(fields[2], "authentication");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_token_guard_survives_successful_login_rendering() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-access-token",
            "refresh_token": "auth.login",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let config_before = fs::read(harness.config_path()).expect("read initial config");
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "fixture-client-credential-9f4c2a7b")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("auth.login"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "credential_output_refused"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("read config after refusal"),
        config_before
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn warning_guard_refusal_does_not_commit_login_state() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-access-token",
            "refresh_token": "access tokens are cached",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let config_before = fs::read(harness.config_path()).expect("read initial config");
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "client-secret")
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("access tokens are cached"));
    assert_eq!(
        fs::read(harness.config_path()).expect("read config after refusal"),
        config_before
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_commit_conflict_guards_the_winning_profile_and_rolls_back_cache() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use wiremock::{Request, Respond};

    struct DelayedTokenResponse {
        observed: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl Respond for DelayedTokenResponse {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            self.observed.store(true, Ordering::Release);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !self.release.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "candidate-managed-token",
                "token_type": "bearer",
                "expires_in": 3600
            }))
        }
    }

    let auth = MockServer::start().await;
    let request_observed = Arc::new(AtomicBool::new(false));
    let release_response = Arc::new(AtomicBool::new(false));
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(DelayedTokenResponse {
            observed: request_observed.clone(),
            release: release_response.clone(),
        })
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let candidate_secret = harness.directory.path().join("candidate-secret");
    reltio_client::fs::atomic_write_private(&candidate_secret, b"candidate-secret")
        .expect("candidate secret file");
    let winner_secret = harness.directory.path().join("winner-secret");
    reltio_client::fs::atomic_write_private(&winner_secret, b"auth_login_commit_conflict")
        .expect("winner secret file");
    let mut login = harness.command();
    login.env("RELTIO_AUTH_URL", auth.uri()).args([
        "--quiet",
        "auth",
        "login",
        "--method",
        "client-credentials",
        "--client-id",
        "candidate-client",
        "--secret-file",
        candidate_secret.to_str().expect("UTF-8 path"),
    ]);
    login
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = login.spawn().expect("login process starts");
    let pending_login = tokio::task::spawn_blocking(move || child.wait_with_output());
    for _ in 0..6_000 {
        if request_observed.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        request_observed.load(Ordering::Acquire),
        "login must load the old profile before the concurrent update"
    );
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "winner-client",
            "--secret-file",
            winner_secret.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("winning profile update executes");
    assert_success(&output);
    release_response.store(true, Ordering::Release);

    let output = pending_login
        .await
        .expect("login task completes")
        .expect("login process completes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("auth_login_commit_conflict"));
    let fields: Value = serde_json::from_slice(&output.stderr).expect("guarded conflict error");
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert!(fields[1].is_null());
    assert_eq!(fields[7], 0);
    assert_eq!(fields[11], 0);
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
    let profile = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&profile);
    assert_eq!(
        stdout_json(&profile)["data"]["auth"]["client_id"],
        "winner-client"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn line_broken_refresh_token_is_rejected_without_output_or_local_commit() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-access-token",
            "refresh_token": "\n",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let config_before = fs::read(harness.config_path()).expect("snapshot config");
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "client-secret")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read(harness.config_path()).expect("read unchanged config"),
        config_before
    );
    assert!(cached_token_files(&harness.directory.path().join("cache")).is_empty());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_output_failure_reports_that_local_state_was_committed() {
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "local_state_committed",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let config_before = fs::read(harness.config_path()).expect("read initial config");
    let secret_file = harness.directory.path().join("committed-login-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");

    let (_reader, mut writer) = UnixStream::pair().expect("Unix socket pair");
    writer
        .set_nonblocking(true)
        .expect("nonblocking output socket");
    let fill = [0_u8; 8192];
    loop {
        match writer.write(&fill) {
            Ok(0) => panic!("output socket accepted an empty write"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("failed to fill output socket: {error}"),
        }
    }
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).expect("output error");
    let fields = error.as_array().expect("guarded positional output error");
    assert_eq!(fields.len(), 12);
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert_eq!(fields[1], "output_write_failed");
    assert_eq!(fields[7], 0);
    assert_eq!(fields[11], 1);
    assert_ne!(
        fs::read(harness.config_path()).expect("read committed config"),
        config_before
    );
    let output = harness
        .command()
        .env("RELTIO_AUTH_URL", auth.uri())
        .args(["auth", "status"])
        .output()
        .expect("auth status executes");
    assert_success(&output);
    let status = stdout_json(&output);
    assert_eq!(status["data"]["provider"], "client_credentials");
    assert_eq!(status["data"]["cache_state"], "valid");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_broken_pipe_is_reported_after_local_commit() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "broken-pipe-login-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("broken-pipe-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");
    let (reader, writer) = UnixStream::pair().expect("Unix socket pair");
    drop(reader);
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).expect("output error");
    assert_eq!(error["error"]["code"], "output_write_failed");
    assert_eq!(error["error"]["details"]["local_state_committed"], true);
    let status = harness
        .command()
        .env("RELTIO_AUTH_URL", auth.uri())
        .args(["auth", "status"])
        .output()
        .expect("auth status executes");
    assert_success(&status);
    assert_eq!(stdout_json(&status)["data"]["cache_state"], "valid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_token_guard_reaches_successful_entity_responses() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-access-token",
            "refresh_token": "echoed-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let data = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .and(header("authorization", "Bearer opaque-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "entities/1",
            "label": "echoed-refresh-token"
        })))
        .expect(1)
        .mount(&data)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&data.uri()));
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"fixture-client-credential-9f4c2a7b")
        .expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);
    let mut get = harness.command();
    get.env("RELTIO_AUTH_URL", auth.uri())
        .args(["entity", "get", "1"]);

    let output = run_process(get).await;

    assert_success(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("echoed-refresh-token"));
    assert_eq!(stdout_json(&output)["data"]["label"], "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_auth_url_reports_partial_practice_coverage() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "fixture-client-credential-9f4c2a7b")
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["meta"]["practice_coverage"], "partial");
    assert!(
        !envelope["meta"]["practice_ids"]
            .as_array()
            .unwrap()
            .contains(&Value::String("AUTH-CENTRALIZED-001".to_owned()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_login_credentials_override_environment_credentials() {
    let auth = MockServer::start().await;
    let expected =
        base64::engine::general_purpose::STANDARD.encode("explicit-client:explicit-secret");
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header("authorization", format!("Basic {expected}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque-access-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("explicit-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"explicit-secret")
        .expect("private secret file");
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_ID", "environment-client")
        .env("RELTIO_CLIENT_SECRET", "environment-secret")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "explicit-client",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ]);

    let output = run_process(login).await;

    assert_success(&output);
    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&output);
    let profile = stdout_json(&output);
    assert_eq!(profile["data"]["auth"]["client_id"], "explicit-client");
    assert_eq!(
        profile["data"]["auth"]["secret_file"],
        secret_file.to_string_lossy().as_ref()
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_config_commit_does_not_persist_a_new_provider_token() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }

    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "transaction-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let output = harness
        .command()
        .args(["profile", "update", "test", "--auth-method", "bearer"])
        .output()
        .expect("profile update executes");
    assert_success(&output);
    let secret_file = harness.directory.path().join("transaction-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"explicit-secret")
        .expect("private secret file");
    let token_directory = harness.directory.path().join("cache").join("tokens");
    fs::create_dir_all(&token_directory).expect("token directory");
    fs::set_permissions(&token_directory, fs::Permissions::from_mode(0o700))
        .expect("private token directory");
    fs::set_permissions(harness.directory.path(), fs::Permissions::from_mode(0o500))
        .expect("make config parent read-only");
    let mut login = harness.command();
    login.env("RELTIO_AUTH_URL", auth.uri()).args([
        "--quiet",
        "auth",
        "login",
        "--method",
        "client-credentials",
        "--client-id",
        "explicit-client",
        "--secret-file",
        secret_file.to_str().expect("UTF-8 path"),
    ]);

    let output = run_process(login).await;
    fs::set_permissions(harness.directory.path(), fs::Permissions::from_mode(0o700))
        .expect("restore temporary directory permissions");

    assert!(!output.status.success());
    let cached_tokens = fs::read_dir(&token_directory)
        .expect("token directory remains readable")
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            let path = entry.path();
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("rate-"))
        })
        .count();
    assert_eq!(cached_tokens, 0);
    let output = harness
        .command()
        .args(["profile", "show", "test"])
        .output()
        .expect("profile show executes");
    assert_success(&output);
    assert_eq!(stdout_json(&output)["data"]["auth"]["method"], "bearer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_displaced_bearer_fails_closed_without_touching_managed_cache() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "previous-managed-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let secret_file = harness.directory.path().join("transaction-client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"client-secret")
        .expect("private secret file");

    let mut first_login = harness.command();
    first_login.env("RELTIO_AUTH_URL", auth.uri()).args([
        "--quiet",
        "auth",
        "login",
        "--method",
        "client-credentials",
        "--client-id",
        "client-id",
        "--secret-file",
        secret_file.to_str().expect("UTF-8 path"),
    ]);
    let output = run_process(first_login).await;
    assert_success(&output);
    let managed_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .find(|path| {
            fs::read(path)
                .expect("read managed cache")
                .windows("previous-managed-token".len())
                .any(|window| window == b"previous-managed-token")
        })
        .expect("managed cache path");
    let managed_before = fs::read(&managed_path).expect("snapshot managed cache");

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "previous-bearer-token")
        .args([
            "--quiet",
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);
    let bearer_path = cached_token_files(&harness.directory.path().join("cache"))
        .into_iter()
        .find(|path| {
            fs::read(path)
                .expect("read bearer cache")
                .windows("previous-bearer-token".len())
                .any(|window| window == b"previous-bearer-token")
        })
        .expect("bearer cache path");
    fs::remove_file(&bearer_path).expect("remove bearer cache fixture");
    fs::create_dir(&bearer_path).expect("replace bearer cache with a directory");
    let config_before = fs::read(harness.config_path()).expect("snapshot bearer profile");

    auth.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-candidate-token",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(0)
        .mount(&auth)
        .await;
    let mut failed_login = harness.command();
    failed_login.env("RELTIO_AUTH_URL", auth.uri()).args([
        "--quiet",
        "auth",
        "login",
        "--method",
        "client-credentials",
        "--client-id",
        "client-id",
        "--secret-file",
        secret_file.to_str().expect("UTF-8 path"),
    ]);

    let output = run_process(failed_login).await;

    assert!(!output.status.success());
    assert!(
        output.stderr.is_empty(),
        "an unreadable recognized cache generation must fail closed"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("read profile after failed cleanup"),
        config_before
    );
    assert_eq!(
        fs::read(&managed_path).expect("read managed cache after failed cleanup"),
        managed_before
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("new-candidate-token"));
}

#[test]
fn auth_status_guards_configured_secret_file_material() {
    let harness = Harness::new();
    harness.add_profile(None);
    let secret_file = harness.directory.path().join("client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, b"data").expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);

    let output = harness
        .command()
        .args(["auth", "status"])
        .output()
        .expect("auth status executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("data"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "credential_output_refused"
    );
}

#[test]
fn oversized_client_secret_file_is_refused_before_guard_construction() {
    let harness = Harness::new();
    harness.add_profile(None);
    let secret_file = harness.directory.path().join("oversized-client-secret");
    reltio_client::fs::atomic_write_private(&secret_file, &vec![b'x'; 1024 * 1024 + 1])
        .expect("private secret file");
    let output = harness
        .command()
        .args([
            "profile",
            "update",
            "test",
            "--auth-method",
            "client-credentials",
            "--client-id",
            "client-id",
            "--secret-file",
            secret_file.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("profile update executes");
    assert_success(&output);

    let output = harness
        .command()
        .args(["auth", "status"])
        .output()
        .expect("auth status executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "local_file_too_large"
    );
}

#[test]
fn provider_inapplicable_login_options_are_rejected() {
    let harness = Harness::new();
    for arguments in [
        vec![
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
            "--credential-process-arg",
            "ignored",
        ],
        vec![
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--credential-process-arg",
            "ignored",
        ],
        vec![
            "auth",
            "login",
            "--method",
            "credential-process",
            "--credential-process",
            "/private/broker",
            "--expires-in",
            "1h",
        ],
    ] {
        let output = harness
            .command()
            .args(arguments)
            .output()
            .expect("auth login executes");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
            "auth_login_argument_conflict"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_credentials_rejects_conflicting_direct_secret_sources_before_io() {
    let auth = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(None);
    let config_before = fs::read(harness.config_path()).expect("read initial config");
    let missing = harness.directory.path().join("missing-client-secret");
    let mut command = harness.command();
    command.env("RELTIO_AUTH_URL", auth.uri()).args([
        "auth",
        "login",
        "--method",
        "client-credentials",
        "--client-id",
        "client-id",
        "--secret-stdin",
        "--secret-file",
        missing.to_str().expect("UTF-8 path"),
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("usage error")["error"]["code"],
        "auth_login_argument_conflict"
    );
    assert_eq!(
        fs::read(harness.config_path()).expect("read config after conflict"),
        config_before
    );
    assert!(auth.received_requests().await.unwrap().is_empty());
}

#[test]
fn successful_output_guards_shadowed_environment_client_secret() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-access-token")
        .env("RELTIO_CLIENT_SECRET", "data")
        .args(["auth", "status"])
        .output()
        .expect("auth status executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("data"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "credential_output_refused"
    );
}

#[test]
fn help_output_is_guarded_against_environment_credentials() {
    let harness = Harness::new();
    let output = harness
        .command()
        .env("RELTIO_CLIENT_SECRET", "Manage named routing")
        .arg("--help")
        .output()
        .expect("help executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Manage named routing"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_check_reports_reviewed_search_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer opaque-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-request-id", "auth-check-1")
                .set_body_json(json!([])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["auth", "check"]);

    let output = run_process(command).await;

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["meta"]["practice_coverage"], "reviewed");
    assert_eq!(envelope["meta"]["consistency"], "eventual");
    assert_eq!(envelope["meta"]["request_id"], "auth-check-1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_check_uses_the_response_output_guard() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reltio/api/TestTenant/entities/_search"))
        .and(header("authorization", "Bearer valid"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "valid")
        .args(["auth", "check"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("valid"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "credential_output_refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_retry_disables_token_endpoint_rate_limit_replay() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .expect(1)
        .mount(&auth)
        .await;
    let harness = Harness::new();
    harness.add_profile(None);
    harness.set_service_url("test", "auth", &auth.uri());
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", auth.uri())
        .env("RELTIO_CLIENT_SECRET", "secret")
        .args([
            "--no-retry",
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "auth_rate_limited");
    assert_eq!(error["error"]["details"]["attempts"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_auth_path_is_refused_before_network() {
    let auth = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(None);
    let retired_auth_url = format!("{}/services", auth.uri());
    harness.set_service_url("test", "auth", &retired_auth_url);
    let mut login = harness.command();
    login
        .env("RELTIO_AUTH_URL", retired_auth_url)
        .env("RELTIO_CLIENT_SECRET", "secret")
        .args([
            "auth",
            "login",
            "--method",
            "client-credentials",
            "--client-id",
            "client-id",
        ]);

    let output = run_process(login).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "deprecated_auth_endpoint_refused"
    );
    assert!(auth.received_requests().await.unwrap().is_empty());
}

#[test]
fn logout_with_only_environment_token_is_a_successful_noop() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_success(&output);
    assert_eq!(stdout_json(&output)["data"]["local_cache_cleared"], false);
}

#[test]
fn logout_clears_stale_profile_tokens_even_when_auth_is_unconfigured() {
    let harness = Harness::new();
    harness.add_profile(None);
    let cache_dir = harness.directory.path().join("cache");
    reltio_client::auth::TokenManager::import_bearer(
        &cache_dir,
        "test",
        SecretString::from("stale-token".to_owned()),
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    )
    .expect("import stale token");

    let output = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_success(&output);
    assert_eq!(stdout_json(&output)["data"]["local_cache_cleared"], true);
    let token_files = fs::read_dir(cache_dir.join("tokens"))
        .expect("token directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    assert_eq!(token_files, 0);
}

#[test]
fn logout_guards_tokens_collected_before_cache_deletion() {
    let harness = Harness::new();
    harness.add_profile(None);
    let cache_dir = harness.directory.path().join("cache");
    reltio_client::auth::TokenManager::import_bearer(
        &cache_dir,
        "test",
        SecretString::from("data".to_owned()),
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    )
    .expect("import token");

    let output = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("data"));
    let error: Value = serde_json::from_slice(&output.stderr).expect("guarded error JSON");
    assert_eq!(error["error"]["code"], "credential_output_refused");
    assert_eq!(error["error"]["details"]["local_cache_cleared"], true);
    let token_files = fs::read_dir(cache_dir.join("tokens"))
        .expect("token directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    assert_eq!(token_files, 0);
}

#[test]
fn logout_emergency_error_reports_committed_cache_clear() {
    let harness = Harness::new();
    harness.add_profile(None);
    let cache_dir = harness.directory.path().join("cache");
    reltio_client::auth::TokenManager::import_bearer(
        &cache_dir,
        "test",
        SecretString::from("false".to_owned()),
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    )
    .expect("import token");

    let output = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("false"));
    let fields: Value = serde_json::from_slice(&output.stderr).expect("emergency error JSON");
    assert_eq!(fields[0], "reltio_guarded_failure");
    assert_eq!(fields[1], "credential_output_refused");
    assert_eq!(fields[2], "safety");
    assert_eq!(fields[11], 1);
    assert!(cached_token_files(&cache_dir).is_empty());
}

#[test]
fn logout_irreducible_short_token_uses_a_safe_scalar_after_commit() {
    let harness = Harness::new();
    harness.add_profile(None);
    let cache_dir = harness.directory.path().join("cache");
    reltio_client::auth::TokenManager::import_bearer(
        &cache_dir,
        "test",
        SecretString::from("1".to_owned()),
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    )
    .expect("import token");

    let output = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains('1'));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("safe scalar error"),
        json!(0)
    );
    assert!(cached_token_files(&cache_dir).is_empty());
}

#[test]
fn logout_clears_cache_even_when_configuration_is_invalid() {
    let harness = Harness::new();
    harness.add_profile(None);
    let cache_dir = harness.directory.path().join("cache");
    reltio_client::auth::TokenManager::import_bearer(
        &cache_dir,
        "test",
        SecretString::from("stale-token".to_owned()),
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    )
    .expect("import stale token");
    fs::write(harness.config_path(), "not valid [ TOML\n").expect("break config");

    let output = harness
        .command()
        .args(["auth", "logout"])
        .output()
        .expect("logout executes");

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["local_cache_cleared"], true);
    assert!(!envelope["meta"]["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn persisted_bearer_login_requires_an_expiry() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args(["auth", "login", "--method", "bearer"])
        .output()
        .expect("login executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "bearer_expiry_required"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_is_not_followed_with_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            "/callback?code=auth-code-secret&state_token=state-secret&otp=123456",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "GET",
        "/entities/1",
        "--service",
        "data",
    ]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&output.stderr).expect("error JSON");
    assert_eq!(error["error"]["code"], "redirect_refused");
    assert_eq!(error["error"]["details"]["remote_response_received"], true);
    assert_eq!(error["error"]["details"]["remote_request_completed"], true);
    assert!(error["error"]["details"]["remote_operation_completed"].is_null());
    assert_eq!(error["error"]["details"]["safe_to_replay"], true);
    assert_eq!(
        error["error"]["details"]["remote_operation_state"],
        "redirect_response_received_completion_unknown"
    );
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(!stderr.contains("auth-code-secret"));
    assert!(!stderr.contains("state-secret"));
    assert!(!stderr.contains("123456"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_success_body_cannot_echo_access_token() {
    let server = MockServer::start().await;
    let token = format!("s.{}", "z".repeat(4096));
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(format!("not-json {token}")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", &token)
        .args(["entity", "get", "1"]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(!stderr.contains(&token));
    assert_eq!(
        serde_json::from_str::<Value>(&stderr).unwrap()["error"]["code"],
        "api_response_invalid_json"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_error_json_cannot_echo_unicode_escaped_access_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reltio/api/TestTenant/entities/1"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_raw(
                    br#"{"message":"secret\u002dtoken""#.as_slice(),
                    "application/json",
                ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let mut command = harness.command();
    command
        .env("RELTIO_ACCESS_TOKEN", "secret-token")
        .args(["entity", "get", "1"]);
    let output = run_process(command).await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(!stderr.contains("secret-token"));
    assert!(!stderr.contains(r"secret\u002dtoken"));
    let error: Value = serde_json::from_str(&stderr).expect("structured error");
    assert_eq!(error["error"]["details"]["response"]["body_omitted"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_case_absolute_url_userinfo_is_refused_before_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));
    let absolute = format!(
        "hTtP://user:password@{}/reltio/api/TestTenant/entities/1",
        server
            .uri()
            .strip_prefix("http://")
            .expect("wiremock uses HTTP")
    );
    let mut command = harness.command();
    command.env("RELTIO_ACCESS_TOKEN", "opaque-token").args([
        "api",
        "request",
        "GET",
        &absolute,
        "--service",
        "data",
    ]);

    let output = run_process(command).await;

    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "url_credentials_refused"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_route_and_method_override_are_refused_before_network() {
    let server = MockServer::start().await;
    let harness = Harness::new();
    harness.add_profile(Some(&server.uri()));

    for extra in [
        vec!["/entities/%5Fsearch", "--service", "data"],
        vec![
            "/entities/1",
            "--service",
            "data",
            "--header",
            "X-HTTP-Method-Override: DELETE",
        ],
    ] {
        let mut command = harness.command();
        command
            .env("RELTIO_ACCESS_TOKEN", "opaque-token")
            .args(["api", "request", "GET"])
            .args(extra);
        let output = run_process(command).await;
        assert_eq!(output.status.code(), Some(5));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn tenant_binding_uses_service_specific_positions() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/OtherTenant/tasks/TestTenant",
            "--service",
            "jobs",
        ])
        .output()
        .expect("jobs dry run executes");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "request_tenant_unbound"
    );

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "--yes",
            "api",
            "request",
            "POST",
            "/",
            "--service",
            "mcp",
            "--allow-unreviewed-endpoint",
            "--data",
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"tenant_id":"TestTenant"}}}"#,
        ])
        .output()
        .expect("MCP dry run executes");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "raw_mcp_mutation_refused"
    );
}

#[test]
fn explicit_environment_url_precedes_environment_base_url() {
    let harness = Harness::new();
    harness.add_profile(None);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .env("RELTIO_BASE_URL", "https://environment.example")
        .args([
            "--environment",
            "https://flag.example",
            "--tenant",
            "TestTenant",
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
        ])
        .output()
        .expect("dry run executes");

    assert_success(&output);
    assert_eq!(
        stdout_json(&output)["data"]["url"],
        "https://flag.example/reltio/api/TestTenant/entities/1"
    );
}

#[test]
fn partially_reviewed_raw_filter_guard_runs_before_network() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    let filter = "x".repeat(reltio_client::entities::QUERY_FILTER_CHARACTER_LIMIT + 1);
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities",
            "--service",
            "data",
            "--query",
            &format!("filter={filter}"),
        ])
        .output()
        .expect("raw dry run executes");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
        "query_filter_too_long"
    );
}

#[test]
fn raw_get_search_enforces_boundary_and_reports_recommendation() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    for endpoint in ["/entities", "/entities/_search"] {
        let output = harness
            .command()
            .env("RELTIO_ACCESS_TOKEN", "opaque-token")
            .args([
                "--dry-run",
                "api",
                "request",
                "GET",
                endpoint,
                "--service",
                "data",
                "--query",
                "offset=9999",
                "--query",
                "max=2",
            ])
            .output()
            .expect("raw GET search executes");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"],
            "entity_search_boundary_exceeded"
        );
    }

    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities",
            "--service",
            "data",
            "--query",
            "max=1",
        ])
        .output()
        .expect("valid raw GET search executes");
    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["practice_coverage"], "reviewed");
    assert_eq!(envelope["data"]["safe_to_replay"], true);
    assert_eq!(envelope["meta"]["consistency"], "eventual");
    assert!(
        envelope["meta"]["warnings"][0]
            .as_str()
            .unwrap()
            .contains("recommends POST")
    );
}

#[test]
fn partial_raw_match_is_non_replayable_and_warns_during_dry_run() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
            "--query",
            "futureOption=a,b",
        ])
        .output()
        .expect("partial raw dry run executes");

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["practice_coverage"], "partial");
    assert_eq!(envelope["data"]["safe_to_replay"], false);
    assert_eq!(envelope["data"]["query"][0]["name"], "futureOption");
    assert_eq!(envelope["data"]["query"][0]["value"], "a,b");
    assert!(
        envelope["data"]["url"]
            .as_str()
            .is_some_and(|url| url.ends_with("?futureOption=a%2Cb"))
    );
    assert_eq!(envelope["meta"]["consistency"], "consistent");
    assert!(!envelope["meta"]["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn raw_entity_get_recognizes_every_reviewed_query_parameter() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", "opaque-token")
        .args([
            "--dry-run",
            "api",
            "request",
            "GET",
            "/entities/1",
            "--service",
            "data",
            "--query",
            "select=uri,label",
            "--query",
            "time=1720000000000",
            "--query",
            "options=ovOnly",
            "--query",
            "mergeDuplicateCrosswalks=true",
            "--query",
            "defaultMaxValues=10",
            "--query",
            "explicitSurvivorshipGroup=configuration/entityTypes/Individual/survivorshipGroups/Default",
            "--query",
            "reverseTranscodeLookups=Salesforce",
            "--query",
            "sendMasked=true",
        ])
        .output()
        .expect("raw entity get preflight executes");

    assert_success(&output);
    let envelope = stdout_json(&output);
    assert_eq!(envelope["data"]["practice_coverage"], "reviewed");
    assert_eq!(envelope["data"]["safe_to_replay"], true);
    assert!(
        envelope["meta"]["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Preview")
    );
}

#[test]
fn raw_entity_get_rejects_malformed_reviewed_query_parameters() {
    let harness = Harness::new();
    harness.add_profile(Some("https://routing.example"));
    for query in [
        "select=",
        "select=URI",
        "select=unknown",
        "select=attributes.",
        "time=not-a-timestamp",
        "mergeDuplicateCrosswalks=yes",
        "defaultMaxValues=-1",
        "explicitSurvivorshipGroup=",
        "reverseTranscodeLookups=",
        "sendMasked=1",
        "options=ovOnly,,sendHidden",
        "options=sortByOV",
    ] {
        let output = harness
            .command()
            .env("RELTIO_ACCESS_TOKEN", "opaque-token")
            .args([
                "--dry-run",
                "api",
                "request",
                "GET",
                "/entities/1",
                "--service",
                "data",
                "--query",
                query,
            ])
            .output()
            .expect("raw entity get validation executes");

        assert_eq!(output.status.code(), Some(2), "query {query}");
        assert!(output.stdout.is_empty(), "query {query}");
    }
}

#[test]
fn command_schema_and_embedded_guide_are_available() {
    let harness = Harness::new();
    let output = harness
        .command()
        .args(["command", "schema", "entity.get"])
        .output()
        .expect("schema command executes");
    assert_success(&output);
    let schema = stdout_json(&output);
    assert_eq!(schema["data"]["name"], "entity.get");
    assert_eq!(
        schema["data"]["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|argument| argument["name"] == "time")
            .expect("time argument")["value_type"],
        "unsigned_integer"
    );
    let options = schema["data"]["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .find(|argument| argument["name"] == "options")
        .expect("Get Entity options");
    assert_eq!(options["possible_values"].as_array().unwrap().len(), 8);
    assert!(
        options["possible_values"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "explainOv")
    );

    let guide = harness
        .command()
        .args(["agent", "guide"])
        .output()
        .expect("guide command executes");
    assert_success(&guide);
    assert!(String::from_utf8_lossy(&guide.stdout).contains("Reltio CLI Agent Guide"));
}

#[test]
fn shipped_local_markdown_links_resolve() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut documents = vec![root.join("README.md")];
    for directory in [root.join("docs"), root.join("skills")] {
        for entry in fs::read_dir(&directory).expect("documentation directory") {
            let path = entry.expect("documentation entry").path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("md") {
                documents.push(path);
            }
        }
    }

    for document in documents {
        let source = fs::read_to_string(&document).expect("Markdown document");
        let mut remaining = source.as_str();
        while let Some(start) = remaining.find("](") {
            remaining = &remaining[start + 2..];
            let Some(end) = remaining.find(')') else {
                break;
            };
            let destination = remaining[..end].trim().trim_matches(['<', '>']);
            remaining = &remaining[end + 1..];
            if destination.is_empty()
                || destination.starts_with('#')
                || destination.starts_with("http://")
                || destination.starts_with("https://")
                || destination.starts_with("mailto:")
            {
                continue;
            }
            let local = destination.split('#').next().unwrap_or_default();
            assert!(
                document
                    .parent()
                    .expect("document parent")
                    .join(local)
                    .exists(),
                "{} links to missing {destination}",
                document.display()
            );
        }
    }
}

async fn run_process(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output().expect("CLI process executes"))
        .await
        .expect("process task completes")
}

fn login_bearer(harness: &Harness, profile: &str, token: &str) {
    let output = harness
        .command()
        .env("RELTIO_ACCESS_TOKEN", token)
        .args([
            "--profile",
            profile,
            "auth",
            "login",
            "--method",
            "bearer",
            "--expires-in",
            "1h",
        ])
        .output()
        .expect("bearer login executes");
    assert_success(&output);
}

fn assert_profile_and_token(harness: &Harness, profile: &str, expected_token: &str) {
    let output = harness
        .command()
        .args(["profile", "show", profile])
        .output()
        .expect("profile show executes");
    assert_success(&output);

    let output = harness
        .command()
        .args([
            "--profile",
            profile,
            "--output",
            "raw",
            "auth",
            "token",
            "--show",
        ])
        .output()
        .expect("token read executes");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_token
    );
}

fn cached_token_files(cache_dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(cache_dir.join("tokens")) else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| {
                    stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

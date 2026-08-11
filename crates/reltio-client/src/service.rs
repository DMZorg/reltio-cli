use std::fmt;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::ResolvedTarget;
use crate::error::{ErrorCategory, ReltioError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Service {
    Data,
    Tasks,
    PhysicalConfig,
    Jobs,
    Workflow,
    Rdm,
    Dtss,
    Mcp,
    Auth,
}

impl Service {
    pub const ALL: [Self; 9] = [
        Self::Data,
        Self::Tasks,
        Self::PhysicalConfig,
        Self::Jobs,
        Self::Workflow,
        Self::Rdm,
        Self::Dtss,
        Self::Mcp,
        Self::Auth,
    ];
}

impl fmt::Display for Service {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Data => "data",
            Self::Tasks => "tasks",
            Self::PhysicalConfig => "physical-config",
            Self::Jobs => "jobs",
            Self::Workflow => "workflow",
            Self::Rdm => "rdm",
            Self::Dtss => "dtss",
            Self::Mcp => "mcp",
            Self::Auth => "auth",
        })
    }
}

impl std::str::FromStr for Service {
    type Err = ReltioError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "data" => Ok(Self::Data),
            "tasks" => Ok(Self::Tasks),
            "physical-config" | "physical_config" => Ok(Self::PhysicalConfig),
            "jobs" => Ok(Self::Jobs),
            "workflow" => Ok(Self::Workflow),
            "rdm" => Ok(Self::Rdm),
            "dtss" => Ok(Self::Dtss),
            "mcp" => Ok(Self::Mcp),
            "auth" => Ok(Self::Auth),
            _ => Err(ReltioError::usage(
                "invalid_service",
                format!("unknown Reltio service {value:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceResolver {
    target: ResolvedTarget,
}

impl ServiceResolver {
    pub fn new(target: ResolvedTarget) -> Self {
        Self { target }
    }

    pub fn target(&self) -> &ResolvedTarget {
        &self.target
    }

    pub fn base_url(&self, service: Service) -> Result<Url> {
        if let Some(configured) = self.target.service_urls.get(&service) {
            let expanded = configured
                .replace("{tenant}", &self.target.tenant)
                .replace("{environment}", &self.target.environment);
            let url = trailing_slash(validate_service_url(&expanded)?);
            if matches!(service, Service::Data | Service::Tasks)
                && !path_ends_with_segment(&url, &self.target.tenant)
            {
                return Err(ReltioError::new(
                    "service_tenant_mismatch",
                    ErrorCategory::Safety,
                    format!(
                        "configured {service} URL does not end with the selected tenant path segment"
                    ),
                ));
            }
            return Ok(url);
        }

        if service == Service::Auth {
            return Ok(trailing_slash(validate_service_url(
                "https://auth.reltio.com",
            )?));
        }
        if service == Service::Rdm {
            return Ok(trailing_slash(validate_service_url(
                "https://rdm.reltio.com",
            )?));
        }

        let origin = self.environment_origin()?;
        match service {
            Service::Data | Service::Tasks => {
                append_path(&origin, &["reltio", "api", &self.target.tenant])
            }
            Service::PhysicalConfig => {
                append_path(&origin, &["reltio", "tenants", &self.target.tenant])
            }
            Service::Jobs => append_path(&origin, &["jobs"]),
            Service::Dtss => append_path(&origin, &["dtss"]),
            Service::Mcp => append_path(&origin, &["ai", "tools", "mcp"]),
            Service::Workflow => {
                if self.target.environment.starts_with("http://")
                    || self.target.environment.starts_with("https://")
                {
                    return Err(ReltioError::profile(
                        "workflow_url_unresolved",
                        "a custom environment URL requires an explicit workflow service URL",
                    ));
                }
                let workflow = format!(
                    "https://{}-workflow.reltio.com/workflow-adapter/workflow/",
                    self.target.environment
                );
                validate_service_url(&workflow)
            }
            Service::Rdm | Service::Auth => unreachable!("handled above"),
        }
    }

    pub fn request_url(&self, service: Service, path: &str) -> Result<Url> {
        let base = self.base_url(service)?;
        if path.trim() != path {
            return Err(ReltioError::usage(
                "invalid_request_path",
                "request URLs and paths cannot contain leading or trailing whitespace",
            ));
        }

        let (url, absolute) = match Url::parse(path) {
            Ok(url) => {
                validate_absolute_input_path(path)?;
                (validate_service_url(url.as_str())?, true)
            }
            Err(url::ParseError::RelativeUrlWithoutBase) => {
                validate_relative_path(path)?;
                let relative = path.trim_start_matches('/');
                let joined = base.join(relative).map_err(|error| {
                    ReltioError::usage(
                        "invalid_request_path",
                        format!("invalid request path: {error}"),
                    )
                })?;
                (joined, false)
            }
            Err(error) => {
                return Err(ReltioError::usage(
                    "invalid_request_path",
                    format!("invalid request URL or path: {error}"),
                ));
            }
        };

        // Validate the parsed result as a second line of defense. URL joining can
        // recognize absolute references that simplistic string checks miss.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ReltioError::new(
                "url_credentials_refused",
                ErrorCategory::Safety,
                "embedded URL credentials are not allowed",
            ));
        }
        canonical_url_path(&url)?;
        if !same_origin(&base, &url) || !path_is_within_base(&base, &url)? {
            return Err(ReltioError::new(
                if absolute {
                    "absolute_url_outside_service"
                } else {
                    "request_path_escape"
                },
                ErrorCategory::Safety,
                "request URL is outside the selected service and tenant base",
            ));
        }
        Ok(url)
    }

    /// Whether a raw request URL is provably scoped to the selected tenant.
    pub fn request_is_tenant_bound(
        &self,
        service: Service,
        url: &Url,
        body: Option<&[u8]>,
    ) -> Result<bool> {
        let base = self.base_url(service)?;
        let configured_template_is_tenant_scoped = self
            .target
            .service_urls
            .get(&service)
            .is_some_and(|value| service_template_ends_with_tenant(value));

        match service {
            Service::Data | Service::Tasks | Service::PhysicalConfig => {
                Ok(path_ends_with_segment(&base, &self.target.tenant))
            }
            Service::Jobs => {
                if configured_template_is_tenant_scoped {
                    return Ok(path_ends_with_segment(&base, &self.target.tenant));
                }
                Ok(relative_segments(&base, url)?
                    .first()
                    .is_some_and(|segment| *segment == self.target.tenant))
            }
            Service::Mcp => self.mcp_body_is_tenant_bound(&base, url, body),
            Service::Workflow | Service::Rdm | Service::Dtss => {
                Ok(configured_template_is_tenant_scoped
                    && path_ends_with_segment(&base, &self.target.tenant))
            }
            Service::Auth => Ok(false),
        }
    }

    fn mcp_body_is_tenant_bound(&self, base: &Url, url: &Url, body: Option<&[u8]>) -> Result<bool> {
        if !relative_segments(base, url)?.is_empty() {
            return Ok(false);
        }
        let Some(body) = body else {
            return Ok(false);
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Ok(false);
        };
        Ok(value
            .pointer("/params/arguments/tenant_id")
            .and_then(serde_json::Value::as_str)
            == Some(self.target.tenant.as_str()))
    }

    fn environment_origin(&self) -> Result<Url> {
        if let Some(base_url) = &self.target.base_url {
            return Ok(origin_only(base_url.clone()));
        }
        if self.target.environment.starts_with("http://")
            || self.target.environment.starts_with("https://")
        {
            return Ok(origin_only(validate_service_url(&self.target.environment)?));
        }
        validate_service_url(&format!("https://{}.reltio.com/", self.target.environment))
    }
}

pub fn validate_service_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|error| {
        ReltioError::usage(
            "invalid_service_url",
            format!("invalid service URL: {error}"),
        )
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ReltioError::new(
            "url_credentials_refused",
            ErrorCategory::Safety,
            "embedded URL credentials are not allowed",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ReltioError::usage(
            "invalid_service_url",
            "service URLs cannot contain a query or fragment",
        ));
    }
    let secure = url.scheme() == "https";
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if !(secure || url.scheme() == "http" && loopback) {
        return Err(ReltioError::new(
            "insecure_service_url",
            ErrorCategory::Safety,
            "Reltio service URLs must use HTTPS (HTTP is allowed only for loopback tests)",
        ));
    }
    Ok(url)
}

pub fn normalize_entity_uri(value: &str) -> Result<String> {
    let trimmed = value.trim_matches('/');
    let id = trimmed.strip_prefix("entities/").unwrap_or(trimmed);
    if value.trim() != value
        || id.is_empty()
        || id.contains('/')
        || id.contains(['?', '#'])
        || id == "."
        || id == ".."
        || id.starts_with('_')
        || id
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
    {
        return Err(ReltioError::usage(
            "invalid_entity_uri",
            "entity must be an ID or canonical entities/<id> URI",
        ));
    }
    Ok(format!("entities/{id}"))
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() || path.contains('?') || path.contains('#') || path.contains('\\') {
        return Err(ReltioError::usage(
            "invalid_request_path",
            "request path must be non-empty and must not contain a query, fragment, or backslash",
        ));
    }
    if path.starts_with("//") {
        return Err(ReltioError::new(
            "network_path_refused",
            ErrorCategory::Safety,
            "network-path references are not allowed",
        ));
    }
    canonical_path(path)?;
    Ok(())
}

/// Return one unambiguous, decoded path for endpoint matching.
pub fn canonical_url_path(url: &Url) -> Result<String> {
    canonical_path(url.path())
}

pub fn validate_auth_token_url(url: &Url) -> Result<()> {
    let path = canonical_url_path(url)?;
    if path
        .trim_end_matches('/')
        .to_ascii_lowercase()
        .ends_with("/services/oauth/token")
    {
        return Err(ReltioError::new(
            "deprecated_auth_endpoint_refused",
            ErrorCategory::Safety,
            "the retired /services/oauth/token authentication endpoint is not allowed",
        )
        .with_hint("Use https://auth.reltio.com/oauth/token or an explicit supported identity-provider endpoint."));
    }
    Ok(())
}

fn canonical_path(path: &str) -> Result<String> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') {
        return Err(ReltioError::usage(
            "invalid_request_path",
            "request path must be non-empty and cannot contain a backslash or NUL",
        ));
    }
    if path.trim_start_matches('/').contains("//") {
        return Err(ReltioError::new(
            "request_path_ambiguous",
            ErrorCategory::Safety,
            "request path contains an empty path segment",
        ));
    }

    let leading_slash = path.starts_with('/');
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    let mut decoded_segments = Vec::new();
    for segment in path.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        validate_percent_encoding(segment)?;
        let decoded = percent_decode_str(segment).decode_utf8().map_err(|_| {
            ReltioError::new(
                "request_path_invalid_utf8",
                ErrorCategory::Safety,
                "request path contains percent-encoded bytes that are not valid UTF-8",
            )
        })?;
        if decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.chars().any(char::is_control)
        {
            return Err(ReltioError::new(
                "request_path_traversal",
                ErrorCategory::Safety,
                "request path contains traversal, a control character, or an encoded separator",
            ));
        }
        if percent_encodes_unreserved(segment) {
            return Err(ReltioError::new(
                "request_path_ambiguous_encoding",
                ErrorCategory::Safety,
                "request path percent-encodes an unreserved routing character",
            ));
        }
        if contains_percent_escape(&decoded) {
            return Err(ReltioError::new(
                "request_path_ambiguous_encoding",
                ErrorCategory::Safety,
                "request path contains ambiguous double percent encoding",
            ));
        }
        decoded_segments.push(decoded.into_owned());
    }

    let mut canonical = decoded_segments.join("/");
    if leading_slash {
        canonical.insert(0, '/');
    }
    if trailing_slash && !canonical.ends_with('/') {
        canonical.push('/');
    }
    if canonical.is_empty() {
        canonical.push('/');
    }
    Ok(canonical)
}

fn validate_percent_encoding(segment: &str) -> Result<()> {
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(_) = bytes
            .get(index + 1..index + 3)
            .filter(|pair| pair.len() == 2 && pair.iter().all(u8::is_ascii_hexdigit))
        else {
            return Err(ReltioError::new(
                "request_path_invalid_encoding",
                ErrorCategory::Safety,
                "request path contains an invalid percent escape",
            ));
        };
        index += 3;
    }
    Ok(())
}

fn percent_encodes_unreserved(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%' {
            let decoded = (hex_value(bytes[index + 1]) << 4) | hex_value(bytes[index + 2]);
            if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated hexadecimal byte"),
    }
}

fn contains_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

fn validate_absolute_input_path(value: &str) -> Result<()> {
    let scheme = value.find(':').ok_or_else(|| {
        ReltioError::usage("invalid_request_path", "absolute request URL has no scheme")
    })?;
    let remainder = &value[scheme + 1..];
    let raw_path = if let Some(authority) = remainder.strip_prefix("//") {
        authority
            .find('/')
            .map_or("/", |position| &authority[position..])
    } else {
        remainder
    };
    let raw_path = raw_path
        .split_once(['?', '#'])
        .map_or(raw_path, |(path, _)| path);
    validate_relative_path(raw_path)
}

fn append_path(origin: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = origin_only(origin.clone());
    {
        let mut path = url.path_segments_mut().map_err(|()| {
            ReltioError::internal("service URL cannot be used as a hierarchical base")
        })?;
        path.clear();
        for segment in segments {
            path.push(segment);
        }
        path.push("");
    }
    Ok(url)
}

fn origin_only(mut url: Url) -> Url {
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    trailing_slash(url)
}

fn trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn path_ends_with_segment(url: &Url, expected: &str) -> bool {
    url.path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        == Some(expected)
}

fn path_is_within_base(base: &Url, request: &Url) -> Result<bool> {
    let base = canonical_url_path(base)?;
    let request = canonical_url_path(request)?;
    Ok(request == base.trim_end_matches('/') || request.starts_with(&base))
}

fn relative_segments<'a>(base: &Url, request: &'a Url) -> Result<Vec<&'a str>> {
    let relative = request.path().strip_prefix(base.path()).ok_or_else(|| {
        ReltioError::new(
            "request_path_escape",
            ErrorCategory::Safety,
            "request URL is outside the selected service base",
        )
    })?;
    Ok(relative
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect())
}

fn service_template_ends_with_tenant(value: &str) -> bool {
    value
        .split(['?', '#'])
        .next()
        .is_some_and(|path| path.trim_end_matches('/').ends_with("/{tenant}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::{AuthProfile, ResolvedTarget};

    use super::*;

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            profile: Some("dev".to_owned()),
            environment: "dev".to_owned(),
            tenant: "ExampleTenant".to_owned(),
            production: false,
            target_overridden: false,
            routing_overridden: false,
            tenant_overridden: false,
            base_url: None,
            service_urls: BTreeMap::new(),
            auth: AuthProfile::default(),
            sources: BTreeMap::new(),
        }
    }

    #[test]
    fn constructs_canonical_data_url() {
        let resolver = ServiceResolver::new(target());
        assert_eq!(
            resolver.base_url(Service::Data).expect("data URL").as_str(),
            "https://dev.reltio.com/reltio/api/ExampleTenant/"
        );
    }

    #[test]
    fn physical_configuration_base_is_tenant_scoped() {
        let resolver = ServiceResolver::new(target());
        assert_eq!(
            resolver
                .base_url(Service::PhysicalConfig)
                .expect("physical configuration URL")
                .as_str(),
            "https://dev.reltio.com/reltio/tenants/ExampleTenant/"
        );
    }

    #[test]
    fn configured_data_url_must_match_target_tenant() {
        let mut configured = target();
        configured.service_urls.insert(
            Service::Data,
            "https://example.com/reltio/api/OtherTenant".to_owned(),
        );
        let error = ServiceResolver::new(configured)
            .base_url(Service::Data)
            .expect_err("wrong-tenant URL must fail");
        assert_eq!(error.code, "service_tenant_mismatch");
    }

    #[test]
    fn jobs_tenant_must_be_the_first_relative_segment() {
        let resolver = ServiceResolver::new(target());
        let unbound = resolver
            .request_url(Service::Jobs, "exports")
            .expect("jobs URL");
        assert!(
            !resolver
                .request_is_tenant_bound(Service::Jobs, &unbound, None)
                .expect("binding check")
        );

        let bound = resolver
            .request_url(Service::Jobs, "ExampleTenant/exports")
            .expect("tenant jobs URL");
        assert!(
            resolver
                .request_is_tenant_bound(Service::Jobs, &bound, None)
                .expect("binding check")
        );

        let decoy = resolver
            .request_url(Service::Jobs, "OtherTenant/tasks/ExampleTenant")
            .expect("decoy jobs URL");
        assert!(
            !resolver
                .request_is_tenant_bound(Service::Jobs, &decoy, None)
                .expect("binding check")
        );
    }

    #[test]
    fn mixed_case_absolute_url_credentials_are_refused() {
        let mut configured = target();
        configured.base_url = Some(Url::parse("http://127.0.0.1:39000").unwrap());
        let error = ServiceResolver::new(configured)
            .request_url(
                Service::Data,
                "hTtP://user:password@127.0.0.1:39000/reltio/api/ExampleTenant/entities/1",
            )
            .expect_err("userinfo must fail regardless of scheme casing");
        assert_eq!(error.code, "url_credentials_refused");
    }

    #[test]
    fn endpoint_paths_reject_ambiguous_percent_encoding() {
        let resolver = ServiceResolver::new(target());
        for path in [
            "/entities/%5Fsearch",
            "/entities/%2fsearch",
            "/entities/%255Fsearch",
        ] {
            assert!(resolver.request_url(Service::Data, path).is_err(), "{path}");
        }
    }

    #[test]
    fn mcp_binding_uses_the_tool_argument_position() {
        let resolver = ServiceResolver::new(target());
        let url = resolver.request_url(Service::Mcp, "/").expect("MCP URL");
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"tenant_id":"ExampleTenant"}}}"#;
        assert!(
            resolver
                .request_is_tenant_bound(Service::Mcp, &url, Some(body))
                .expect("binding check")
        );
        let decoy =
            br#"{"tenant_id":"ExampleTenant","params":{"arguments":{"tenant_id":"OtherTenant"}}}"#;
        assert!(
            !resolver
                .request_is_tenant_bound(Service::Mcp, &url, Some(decoy))
                .expect("binding check")
        );
    }

    #[test]
    fn auth_url_is_centralized_and_deprecated_path_is_absent() {
        let resolver = ServiceResolver::new(target());
        let auth = resolver.base_url(Service::Auth).expect("auth URL");
        assert_eq!(auth.as_str(), "https://auth.reltio.com/");
        assert!(!auth.as_str().contains("/services/oauth/token"));
    }

    #[test]
    fn deprecated_auth_token_path_is_refused() {
        let retired = Url::parse("https://example.test/services/oauth/token").unwrap();
        let error = validate_auth_token_url(&retired).expect_err("retired endpoint must fail");
        assert_eq!(error.code, "deprecated_auth_endpoint_refused");

        let custom = Url::parse("https://idp.example.test/oauth/token").unwrap();
        validate_auth_token_url(&custom).expect("explicit non-retired endpoint remains supported");
    }

    #[test]
    fn refuses_path_traversal() {
        let resolver = ServiceResolver::new(target());
        let error = resolver
            .request_url(Service::Data, "/entities/%2e%2e/configuration")
            .expect_err("traversal is refused");
        assert_eq!(error.code, "request_path_traversal");
    }

    #[test]
    fn normalizes_entity_ids() {
        assert_eq!(
            normalize_entity_uri("entities/00009qz").unwrap(),
            "entities/00009qz"
        );
        assert_eq!(normalize_entity_uri("00009qz").unwrap(), "entities/00009qz");
        for invalid in [
            "entities/a/b",
            "entities/1?select=uri",
            "entities/1#fragment",
            "entities/1 ",
            "entities/a b",
        ] {
            assert!(normalize_entity_uri(invalid).is_err(), "{invalid}");
        }
    }
}

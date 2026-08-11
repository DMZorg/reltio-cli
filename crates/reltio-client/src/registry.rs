use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ReltioError, Result};
use crate::service::Service;

const ENDPOINTS_YAML: &str = include_str!("../../../docs/endpoints.yaml");
const PRACTICES_YAML: &str = include_str!("../../../docs/reltio-api-practices.yaml");
const UPSTREAM_LOCK_YAML: &str = include_str!("../../../docs/upstream.lock.yaml");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EndpointDocument {
    pub schema_version: u32,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Endpoint {
    pub id: String,
    pub service: Service,
    pub method: String,
    pub path_pattern: String,
    pub safety: Safety,
    pub consistency: Consistency,
    pub replay: ReplayPolicy,
    pub pagination: Pagination,
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
    #[serde(default)]
    pub result_boundary: Option<u64>,
    #[serde(default)]
    pub cursor_ttl_seconds: Option<u64>,
    pub commands: Vec<String>,
    pub practice_ids: Vec<String>,
    pub test_ids: Vec<String>,
    pub verified_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Safety {
    Read,
    Authentication,
    Write,
    HighImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    Consistent,
    Eventual,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayPolicy {
    Safe,
    SafeWithLimit,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pagination {
    None,
    Offset,
    Cursor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PracticeDocument {
    pub schema_version: u32,
    pub catalog: CatalogMetadata,
    pub practices: Vec<Practice>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogMetadata {
    pub corpus_commit: String,
    pub reviewed_at: String,
    pub release_notes_through: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Practice {
    pub id: String,
    pub title: String,
    pub classification: String,
    pub enforcement: String,
    pub api_family: String,
    pub service: String,
    pub methods: Vec<String>,
    pub path_patterns: Vec<String>,
    #[serde(default)]
    pub operations: Vec<PracticeOperation>,
    pub summary: String,
    pub source: PracticeSource,
    pub reviewed_at: String,
    pub commands: Vec<String>,
    pub implementation: String,
    pub test_ids: Vec<String>,
    #[serde(default)]
    pub limits: BTreeMap<String, Value>,
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PracticeOperation {
    pub method: String,
    pub path_pattern: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PracticeSource {
    pub url: String,
    pub section: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
struct UpstreamLock {
    schema_version: u32,
    corpus: UpstreamCorpus,
    deprecations: UpstreamDeprecations,
    review: UpstreamReview,
}

#[derive(Debug, Clone, Deserialize)]
struct UpstreamCorpus {
    commit: String,
}

#[derive(Debug, Clone, Deserialize)]
struct UpstreamDeprecations {
    index_url: String,
    sitemap_url: String,
    notice_count: usize,
    notice_url_set_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct UpstreamReview {
    reviewed_at: String,
    release_notes_through: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PracticeCoverage {
    Reviewed,
    Partial,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Registry {
    endpoints: EndpointDocument,
    practices: PracticeDocument,
}

impl Registry {
    pub fn embedded() -> Result<&'static Self> {
        static REGISTRY: OnceLock<std::result::Result<Registry, String>> = OnceLock::new();
        match REGISTRY.get_or_init(|| Self::parse().map_err(|error| error.to_string())) {
            Ok(registry) => Ok(registry),
            Err(message) => Err(ReltioError::internal(format!(
                "embedded API registry is invalid: {message}"
            ))),
        }
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints.endpoints
    }

    pub fn practices(&self) -> &[Practice] {
        &self.practices.practices
    }

    pub fn metadata(&self) -> &CatalogMetadata {
        &self.practices.catalog
    }

    pub fn practice(&self, id: &str) -> Option<&Practice> {
        self.practices
            .practices
            .iter()
            .find(|practice| practice.id == id)
    }

    pub fn endpoint(&self, id: &str) -> Option<&Endpoint> {
        self.endpoints
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == id)
    }

    pub fn match_endpoint(&self, service: Service, method: &str, path: &str) -> Option<&Endpoint> {
        self.endpoints.endpoints.iter().find(|endpoint| {
            endpoint.service == service
                && endpoint.method.eq_ignore_ascii_case(method)
                && path_matches(&endpoint.path_pattern, path)
        })
    }

    pub fn match_practices(&self, service: Service, method: &str, path: &str) -> Vec<&Practice> {
        let service = service.to_string();
        self.practices
            .practices
            .iter()
            .filter(|practice| {
                (practice.service == "any" || practice.service == service)
                    && practice_matches_request(practice, method, path)
            })
            .collect()
    }

    pub fn request_coverage(
        &self,
        endpoint: Option<&Endpoint>,
        matched_practices: &[&Practice],
    ) -> PracticeCoverage {
        if endpoint.is_some() {
            return self.coverage(endpoint);
        }
        if matched_practices.iter().any(|practice| {
            practice.service != "any" || practice.path_patterns.iter().any(|pattern| pattern != "*")
        }) {
            PracticeCoverage::Partial
        } else {
            PracticeCoverage::Unknown
        }
    }

    pub fn coverage(&self, endpoint: Option<&Endpoint>) -> PracticeCoverage {
        let Some(endpoint) = endpoint else {
            return PracticeCoverage::Unknown;
        };
        let known: BTreeSet<&str> = self
            .practices
            .practices
            .iter()
            .map(|practice| practice.id.as_str())
            .collect();
        if endpoint
            .practice_ids
            .iter()
            .all(|id| known.contains(id.as_str()))
        {
            PracticeCoverage::Reviewed
        } else {
            PracticeCoverage::Partial
        }
    }

    pub fn review_age_days(&self) -> Result<i64> {
        let reviewed = validated_date(
            "catalog review",
            &self.practices.catalog.reviewed_at,
            Utc::now().date_naive(),
        )?;
        Ok((Utc::now().date_naive() - reviewed).num_days())
    }

    fn parse() -> Result<Self> {
        let endpoints: EndpointDocument =
            serde_yaml::from_str(ENDPOINTS_YAML).map_err(|error| {
                ReltioError::internal(format!("failed to parse endpoint registry: {error}"))
            })?;
        let practices: PracticeDocument =
            serde_yaml::from_str(PRACTICES_YAML).map_err(|error| {
                ReltioError::internal(format!("failed to parse practice registry: {error}"))
            })?;
        let upstream: UpstreamLock = serde_yaml::from_str(UPSTREAM_LOCK_YAML).map_err(|error| {
            ReltioError::internal(format!("failed to parse upstream lock: {error}"))
        })?;
        if endpoints.schema_version != 1
            || practices.schema_version != 1
            || upstream.schema_version != 1
        {
            return Err(ReltioError::internal(
                "unsupported embedded registry schema",
            ));
        }
        if practices.catalog.corpus_commit != upstream.corpus.commit
            || practices.catalog.reviewed_at != upstream.review.reviewed_at
            || practices.catalog.release_notes_through != upstream.review.release_notes_through
        {
            return Err(ReltioError::internal(
                "API-practice catalog does not match the embedded upstream review lock",
            ));
        }
        if !upstream.deprecations.index_url.starts_with("https://")
            || !upstream.deprecations.sitemap_url.starts_with("https://")
            || upstream.deprecations.notice_count == 0
            || upstream.deprecations.notice_url_set_sha256.len() != 64
            || !upstream
                .deprecations
                .notice_url_set_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReltioError::internal(
                "upstream lock has an invalid deprecation-index fingerprint",
            ));
        }
        let today = Utc::now().date_naive();
        validated_date(
            "practice catalog review",
            &practices.catalog.reviewed_at,
            today,
        )?;
        let mut practice_ids = BTreeSet::new();
        for practice in &practices.practices {
            if !practice_ids.insert(practice.id.as_str()) {
                return Err(ReltioError::internal(format!(
                    "duplicate API-practice ID {}",
                    practice.id
                )));
            }
            validated_date(
                &format!("practice {} review", practice.id),
                &practice.reviewed_at,
                today,
            )?;
            validated_date(
                &format!("practice {} source update", practice.id),
                &practice.source.updated_at,
                today,
            )?;
            if practice.methods.is_empty()
                || practice.path_patterns.is_empty()
                || practice.commands.is_empty()
                || practice.implementation.trim().is_empty()
                || practice.test_ids.is_empty() && practice.rationale.is_none()
                || !practice.source.url.starts_with("https://")
            {
                return Err(ReltioError::internal(format!(
                    "API practice {} has an incomplete disposition",
                    practice.id
                )));
            }
            if practice.operations.iter().any(|operation| {
                operation.method.trim().is_empty()
                    || !operation.path_pattern.starts_with('/') && operation.path_pattern != "*"
            }) {
                return Err(ReltioError::internal(format!(
                    "API practice {} has an invalid method/path operation",
                    practice.id
                )));
            }
        }
        let mut endpoint_ids = BTreeSet::new();
        for endpoint in &endpoints.endpoints {
            if !endpoint_ids.insert(endpoint.id.as_str()) {
                return Err(ReltioError::internal(format!(
                    "duplicate endpoint ID {}",
                    endpoint.id
                )));
            }
            if endpoint.commands.is_empty()
                || endpoint.practice_ids.is_empty()
                || endpoint.test_ids.is_empty()
                || endpoint
                    .practice_ids
                    .iter()
                    .any(|id| !practice_ids.contains(id.as_str()))
            {
                return Err(ReltioError::internal(format!(
                    "endpoint {} has incomplete API-practice coverage",
                    endpoint.id
                )));
            }
            validated_date(
                &format!("endpoint {} verification", endpoint.id),
                &endpoint.verified_at,
                today,
            )?;
            for practice_id in &endpoint.practice_ids {
                let practice = practices
                    .practices
                    .iter()
                    .find(|practice| practice.id == *practice_id)
                    .unwrap_or_else(|| unreachable!("practice IDs were validated above"));
                let same_service = practice.service == endpoint.service.to_string();
                if (practice.service == "any" || same_service)
                    && !practice_matches_request(practice, &endpoint.method, &endpoint.path_pattern)
                {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} links inapplicable practice {}",
                        endpoint.id, practice.id
                    )));
                }
                for command in &endpoint.commands {
                    if !practice.commands.contains(command) {
                        return Err(ReltioError::internal(format!(
                            "practice {} omits endpoint command {} for {}",
                            practice.id, command, endpoint.id
                        )));
                    }
                }
            }
        }
        Ok(Self {
            endpoints,
            practices,
        })
    }
}

fn practice_matches_request(practice: &Practice, method: &str, path: &str) -> bool {
    if !practice.operations.is_empty() {
        return practice.operations.iter().any(|operation| {
            (operation.method == "*" || operation.method.eq_ignore_ascii_case(method))
                && path_matches(&operation.path_pattern, path)
        });
    }
    practice
        .methods
        .iter()
        .any(|candidate| candidate == "*" || candidate.eq_ignore_ascii_case(method))
        && practice
            .path_patterns
            .iter()
            .any(|pattern| path_matches(pattern, path))
}

fn validated_date(label: &str, value: &str, today: NaiveDate) -> Result<NaiveDate> {
    let parsed = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|error| ReltioError::internal(format!("invalid {label} date: {error}")))?;
    if parsed > today {
        return Err(ReltioError::internal(format!(
            "{label} date {value} is in the future"
        )));
    }
    Ok(parsed)
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern_segments: Vec<_> = pattern.trim_matches('/').split('/').collect();
    let path_segments: Vec<_> = path.trim_matches('/').split('/').collect();
    pattern_segments.len() == path_segments.len()
        && pattern_segments
            .iter()
            .zip(path_segments)
            .all(|(expected, actual)| {
                if expected.starts_with('{') && expected.ends_with('}') {
                    !actual.is_empty() && !actual.starts_with('_')
                } else {
                    *expected == actual
                }
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_endpoint_has_complete_practice_coverage() {
        let registry = Registry::embedded().expect("registry parses");
        for endpoint in registry.endpoints() {
            assert_eq!(
                registry.coverage(Some(endpoint)),
                PracticeCoverage::Reviewed,
                "{} is not fully reviewed",
                endpoint.id
            );
        }
    }

    #[test]
    fn raw_matcher_does_not_treat_search_as_entity_id() {
        let registry = Registry::embedded().expect("registry parses");
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/_search")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.search.get_alias")
        );
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/00009qz")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.get")
        );
    }

    #[test]
    fn catalog_and_endpoint_match_reviewed_get_search_paths() {
        let registry = Registry::embedded().expect("registry parses");
        let practices = registry.match_practices(Service::Data, "GET", "/entities");
        assert!(
            practices
                .iter()
                .any(|practice| practice.id == "ENTITY-FILTER-QUERY-001")
        );
        assert_eq!(
            registry.request_coverage(
                registry.match_endpoint(Service::Data, "GET", "/entities"),
                &practices
            ),
            PracticeCoverage::Reviewed
        );
    }

    #[test]
    fn future_review_dates_are_rejected() {
        let today = Utc::now().date_naive();
        let future = today
            .succ_opt()
            .expect("the current date has a successor")
            .format("%Y-%m-%d")
            .to_string();
        assert!(validated_date("test", &future, today).is_err());
    }
}

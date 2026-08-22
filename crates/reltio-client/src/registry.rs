use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{ReltioError, Result};
use crate::service::Service;

const ENDPOINTS_YAML: &str = include_str!("../../../docs/endpoints.yaml");
const PRACTICES_YAML: &str = include_str!("../../../docs/reltio-api-practices.yaml");
const RELEASE_REQUIREMENTS_YAML: &str = include_str!("../../../docs/release-requirements.yaml");
const UPSTREAM_LOCK_YAML: &str = include_str!("../../../docs/upstream.lock.yaml");
const PRODUCT_CONTRACT: &[u8] = include_bytes!("../../../docs/PRD.md");

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDocument {
    pub schema_version: u32,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    pub page_size_max: Option<u32>,
    #[serde(default)]
    pub cursor_ttl_seconds: Option<u64>,
    pub command_links: Vec<EndpointCommandLink>,
    pub practice_ids: Vec<String>,
    pub test_ids: Vec<String>,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCommandLink {
    pub command: String,
    pub role: EndpointCommandRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCommandRole {
    TypedPrimary,
    WorkflowComponent,
    AuthDependency,
    HealthcheckDependency,
    RawAdapter,
}

impl EndpointCommandRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedPrimary => "typed_primary",
            Self::WorkflowComponent => "workflow_component",
            Self::AuthDependency => "auth_dependency",
            Self::HealthcheckDependency => "healthcheck_dependency",
            Self::RawAdapter => "raw_adapter",
        }
    }
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
    Conditional,
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
    #[serde(default)]
    pub excluded_services: Vec<String>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequirementDocument {
    pub schema_version: u32,
    pub target_release: String,
    pub product_contract: ProductContract,
    pub inventory_test_ids: Vec<String>,
    pub operations: Vec<ReleaseOperation>,
    pub capabilities: Vec<ReleaseCapability>,
    pub acceptance_scenarios: Vec<AcceptanceScenario>,
    pub contracts: Vec<ReleaseContract>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductContract {
    pub path: String,
    pub sha256: String,
    pub sections: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseOperation {
    pub id: String,
    pub command: String,
    pub kind: String,
    pub safety: String,
    pub source_section: String,
    #[serde(default)]
    pub required_endpoint_role: Option<EndpointCommandRole>,
    #[serde(default)]
    pub required_endpoint_ids: Vec<String>,
    #[serde(default)]
    pub contract_ids: Vec<String>,
    #[serde(default)]
    pub implementation_test_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCapability {
    pub id: String,
    pub command: String,
    pub argument: String,
    pub required_value: String,
    pub source_section: String,
    pub implementation_test_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScenario {
    pub id: String,
    pub summary: String,
    pub source_section: String,
    pub implementation_test_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseContract {
    pub id: String,
    pub source_section: String,
    pub required_result_fields: Vec<String>,
    pub allowed_results: Vec<String>,
    pub guard_test_ids: Vec<String>,
    pub field_test_ids: BTreeMap<String, Vec<String>>,
    pub result_test_ids: BTreeMap<String, Vec<String>>,
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
    requirements: ReleaseRequirementDocument,
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

    pub fn requirements(&self) -> &ReleaseRequirementDocument {
        &self.requirements
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
                    && !practice.excluded_services.contains(&service)
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
        let requirements: ReleaseRequirementDocument =
            serde_yaml::from_str(RELEASE_REQUIREMENTS_YAML).map_err(|error| {
                ReltioError::internal(format!("failed to parse release requirements: {error}"))
            })?;
        let upstream: UpstreamLock = serde_yaml::from_str(UPSTREAM_LOCK_YAML).map_err(|error| {
            ReltioError::internal(format!("failed to parse upstream lock: {error}"))
        })?;
        if endpoints.schema_version != 2
            || practices.schema_version != 1
            || upstream.schema_version != 1
            || requirements.schema_version != 1
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
        validate_release_requirements(&requirements)?;
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
            if endpoint.command_links.is_empty()
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
            let mut command_links = BTreeSet::new();
            for link in &endpoint.command_links {
                if !command_links.insert((link.command.as_str(), link.role)) {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} has duplicate command link {} ({:?})",
                        endpoint.id, link.command, link.role
                    )));
                }
                let operation = requirements
                    .operations
                    .iter()
                    .find(|operation| operation.command == link.command)
                    .ok_or_else(|| {
                        ReltioError::internal(format!(
                            "endpoint {} links command {} outside the release contract",
                            endpoint.id, link.command
                        ))
                    })?;
                if link.role == EndpointCommandRole::TypedPrimary
                    && operation.required_endpoint_role != Some(EndpointCommandRole::TypedPrimary)
                {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} assigns typed-primary ownership to incompatible requirement {}",
                        endpoint.id, operation.id
                    )));
                }
                if operation.required_endpoint_role == Some(link.role)
                    && !operation
                        .required_endpoint_ids
                        .iter()
                        .any(|id| id == &endpoint.id)
                {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} is not an approved binding for requirement {} ({:?})",
                        endpoint.id, operation.id, link.role
                    )));
                }
                if operation.required_endpoint_role == Some(link.role)
                    && link.role != EndpointCommandRole::AuthDependency
                {
                    let expected_safety = match operation.safety.as_str() {
                        "read" => Some(Safety::Read),
                        "authentication" => Some(Safety::Authentication),
                        "remote_write" => Some(Safety::Write),
                        "remote_high_impact" => Some(Safety::HighImpact),
                        _ => None,
                    };
                    if expected_safety.is_some_and(|safety| safety != endpoint.safety) {
                        return Err(ReltioError::internal(format!(
                            "endpoint {} safety does not match requirement {}",
                            endpoint.id, operation.id
                        )));
                    }
                }
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
                if practice
                    .excluded_services
                    .contains(&endpoint.service.to_string())
                {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} links practice {} despite its service exclusion",
                        endpoint.id, practice.id
                    )));
                }
                let same_service = practice.service == endpoint.service.to_string();
                if (practice.service == "any" || same_service)
                    && !practice
                        .excluded_services
                        .contains(&endpoint.service.to_string())
                    && !practice_matches_request(practice, &endpoint.method, &endpoint.path_pattern)
                {
                    return Err(ReltioError::internal(format!(
                        "endpoint {} links inapplicable practice {}",
                        endpoint.id, practice.id
                    )));
                }
                for command in endpoint.commands() {
                    if !practice
                        .commands
                        .iter()
                        .any(|candidate| candidate == command)
                    {
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
            requirements,
        })
    }
}

impl Endpoint {
    pub fn commands(&self) -> impl Iterator<Item = &str> {
        self.command_links.iter().map(|link| link.command.as_str())
    }

    pub fn has_command_role(&self, command: &str, role: EndpointCommandRole) -> bool {
        self.command_links
            .iter()
            .any(|link| link.command == command && link.role == role)
    }
}

fn validate_release_requirements(requirements: &ReleaseRequirementDocument) -> Result<()> {
    if requirements.target_release != "0.1.0"
        || requirements.product_contract.path != "docs/PRD.md"
        || requirements.product_contract.sections.is_empty()
        || requirements.inventory_test_ids.is_empty()
        || !evidence_matches(
            &requirements.inventory_test_ids,
            &crate::release_contract::V0_1_INVENTORY_TEST_IDS,
        )
        || requirements.operations.len() != crate::release_contract::V0_1_REQUIRED_OPERATIONS.len()
        || requirements.capabilities.len()
            != crate::release_contract::V0_1_REQUIRED_CAPABILITIES.len()
        || requirements.acceptance_scenarios.len()
            != crate::release_contract::MVP_ACCEPTANCE_SCENARIOS.len()
        || requirements.contracts.is_empty()
    {
        return Err(ReltioError::internal(
            "the v0.1.0 release-requirement inventory is incomplete",
        ));
    }
    let product_contract_sha256 = format!("{:x}", Sha256::digest(PRODUCT_CONTRACT));
    if requirements.product_contract.sha256 != product_contract_sha256 {
        return Err(ReltioError::internal(
            "the release-requirement inventory does not match docs/PRD.md",
        ));
    }

    let mut contract_ids = BTreeSet::new();
    for contract in &requirements.contracts {
        let required_fields = contract
            .required_result_fields
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let field_evidence = contract
            .field_test_ids
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_fields = crate::release_contract::MUTATION_AUDIT_FIELDS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let allowed_results = contract
            .allowed_results
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let result_evidence = contract
            .result_test_ids
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_results = crate::release_contract::MUTATION_AUDIT_RESULTS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let guard_tests = contract
            .guard_test_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let implementation_tests = contract
            .field_test_ids
            .values()
            .chain(contract.result_test_ids.values())
            .flatten()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !contract_ids.insert(contract.id.as_str())
            || contract.source_section.trim().is_empty()
            || required_fields != expected_fields
            || required_fields.len() != contract.required_result_fields.len()
            || field_evidence != expected_fields
            || allowed_results != expected_results
            || allowed_results.len() != contract.allowed_results.len()
            || result_evidence != expected_results
            || contract.guard_test_ids.is_empty()
            || !evidence_matches(
                &contract.guard_test_ids,
                &crate::release_contract::MUTATION_AUDIT_GUARD_EVIDENCE,
            )
            || !contract.field_test_ids.iter().all(|(field, evidence)| {
                crate::release_contract::MUTATION_AUDIT_FIELD_EVIDENCE
                    .iter()
                    .find_map(|(expected_field, expected)| {
                        (*expected_field == field).then_some(*expected)
                    })
                    .is_some_and(|expected| evidence_matches(evidence, expected))
            })
            || !contract.result_test_ids.iter().all(|(result, evidence)| {
                crate::release_contract::MUTATION_AUDIT_RESULT_EVIDENCE
                    .iter()
                    .find_map(|(expected_result, expected)| {
                        (*expected_result == result).then_some(*expected)
                    })
                    .is_some_and(|expected| evidence_matches(evidence, expected))
            })
            || !guard_tests.is_disjoint(&implementation_tests)
        {
            return Err(ReltioError::internal(format!(
                "release contract {} has an incomplete acceptance definition",
                contract.id
            )));
        }
    }
    if !contract_ids.contains("mutation_audit_v1") {
        return Err(ReltioError::internal(
            "the release requirements omit mutation_audit_v1",
        ));
    }

    let mut operation_ids = BTreeSet::new();
    let mut commands = BTreeSet::new();
    let mut write_operations = BTreeSet::new();
    let mut high_impact_operations = BTreeSet::new();
    let valid_kinds = ["local", "typed_api", "workflow", "raw_adapter", "discovery"];
    let valid_safety = [
        "read",
        "local_write",
        "authentication",
        "secret_disclosure",
        "remote_write",
        "remote_high_impact",
        "dynamic",
    ];
    for operation in &requirements.operations {
        let endpoint_ids = operation
            .required_endpoint_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if operation.id != operation.command
            || !operation_ids.insert(operation.id.as_str())
            || !commands.insert(operation.command.as_str())
            || !valid_kinds.contains(&operation.kind.as_str())
            || !valid_safety.contains(&operation.safety.as_str())
            || operation.source_section.trim().is_empty()
            || endpoint_ids.len() != operation.required_endpoint_ids.len()
            || operation.required_endpoint_role.is_none()
                && !operation.required_endpoint_ids.is_empty()
            || operation
                .contract_ids
                .iter()
                .any(|id| !contract_ids.contains(id.as_str()))
        {
            return Err(ReltioError::internal(format!(
                "release operation {} has an invalid acceptance definition",
                operation.id
            )));
        }
        let expected_safety = crate::release_contract::V0_1_OPERATION_SAFETY
            .iter()
            .find_map(|(command, safety)| (*command == operation.id).then_some(*safety))
            .ok_or_else(|| {
                ReltioError::internal(format!(
                    "independent safety inventory omits release operation {}",
                    operation.id
                ))
            })?;
        if operation.safety != expected_safety {
            return Err(ReltioError::internal(format!(
                "release operation {} has the wrong safety tier",
                operation.id
            )));
        }
        let expected_role = crate::release_contract::V0_1_ENDPOINT_REQUIREMENTS
            .iter()
            .find_map(|(command, role)| (*command == operation.id).then_some(*role));
        if operation
            .required_endpoint_role
            .map(EndpointCommandRole::as_str)
            != expected_role
        {
            return Err(ReltioError::internal(format!(
                "release operation {} has the wrong endpoint-role obligation",
                operation.id
            )));
        }
        let expected_endpoint_ids = crate::release_contract::REVIEWED_ENDPOINT_BINDINGS
            .iter()
            .filter_map(|(command, endpoint_id)| (*command == operation.id).then_some(*endpoint_id))
            .collect::<BTreeSet<_>>();
        if endpoint_ids != expected_endpoint_ids {
            return Err(ReltioError::internal(format!(
                "release operation {} has an unapproved endpoint binding",
                operation.id
            )));
        }
        let expected_implementation_evidence = crate::release_contract::V0_1_OPERATION_EVIDENCE
            .iter()
            .find_map(|(command, evidence)| (*command == operation.id).then_some(*evidence))
            .unwrap_or(&[]);
        if !evidence_matches(
            &operation.implementation_test_ids,
            expected_implementation_evidence,
        ) {
            return Err(ReltioError::internal(format!(
                "release operation {} has unapproved implementation evidence",
                operation.id
            )));
        }
        if operation.safety == "remote_write" {
            write_operations.insert(operation.id.as_str());
        }
        if operation.safety == "remote_high_impact" {
            high_impact_operations.insert(operation.id.as_str());
        }
        if matches!(
            operation.safety.as_str(),
            "remote_write" | "remote_high_impact"
        ) && !operation
            .contract_ids
            .iter()
            .any(|id| id == "mutation_audit_v1")
        {
            return Err(ReltioError::internal(format!(
                "remote mutation {} omits mutation_audit_v1",
                operation.id
            )));
        }
    }
    let expected_operations = crate::release_contract::V0_1_REQUIRED_OPERATIONS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if operation_ids != expected_operations {
        return Err(ReltioError::internal(
            "the release inventory does not match the independent v0.1.0 operation set",
        ));
    }
    if write_operations
        != crate::release_contract::V0_1_WRITE_OPERATIONS
            .into_iter()
            .collect::<BTreeSet<_>>()
        || high_impact_operations
            != crate::release_contract::V0_1_HIGH_IMPACT_OPERATIONS
                .into_iter()
                .collect::<BTreeSet<_>>()
    {
        return Err(ReltioError::internal(
            "the release inventory does not match the independent mutation safety sets",
        ));
    }
    for operation_id in crate::release_contract::V0_1_DYNAMIC_MUTATION_ADAPTERS {
        if !requirements
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .is_some_and(|operation| {
                operation.safety == "dynamic"
                    && operation
                        .contract_ids
                        .iter()
                        .any(|id| id == "mutation_audit_v1")
            })
        {
            return Err(ReltioError::internal(format!(
                "dynamic mutation adapter {operation_id} omits mutation_audit_v1"
            )));
        }
    }

    let mut capability_ids = BTreeSet::new();
    for capability in &requirements.capabilities {
        if !capability_ids.insert(capability.id.as_str())
            || !commands.contains(capability.command.as_str())
            || capability.argument.trim().is_empty()
            || capability.required_value.trim().is_empty()
            || capability.source_section.trim().is_empty()
            || !crate::release_contract::V0_1_CAPABILITY_EVIDENCE
                .iter()
                .find_map(|(id, expected)| (*id == capability.id).then_some(*expected))
                .is_some_and(|expected| {
                    evidence_matches(&capability.implementation_test_ids, expected)
                })
        {
            return Err(ReltioError::internal(format!(
                "release capability {} has an invalid acceptance definition",
                capability.id
            )));
        }
    }
    let expected_capabilities = crate::release_contract::V0_1_REQUIRED_CAPABILITIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    if capability_ids != expected_capabilities {
        return Err(ReltioError::internal(
            "the release inventory does not match the independent v0.1.0 capability set",
        ));
    }

    let mut acceptance_ids = BTreeSet::new();
    for scenario in &requirements.acceptance_scenarios {
        if !acceptance_ids.insert(scenario.id.as_str())
            || scenario.summary.trim().is_empty()
            || scenario.source_section.trim().is_empty()
            || !crate::release_contract::MVP_ACCEPTANCE_EVIDENCE
                .iter()
                .find_map(|(id, expected)| (*id == scenario.id).then_some(*expected))
                .is_some_and(|expected| {
                    evidence_matches(&scenario.implementation_test_ids, expected)
                })
        {
            return Err(ReltioError::internal(format!(
                "acceptance scenario {} has an invalid definition",
                scenario.id
            )));
        }
    }
    let expected_acceptance = crate::release_contract::MVP_ACCEPTANCE_SCENARIOS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if acceptance_ids != expected_acceptance {
        return Err(ReltioError::internal(
            "the release inventory does not match the independent MVP acceptance set",
        ));
    }
    let guard_evidence_ids = requirements
        .contracts
        .iter()
        .flat_map(|contract| contract.guard_test_ids.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let mut implementation_evidence_ids = requirements
        .operations
        .iter()
        .flat_map(|operation| operation.implementation_test_ids.iter().map(String::as_str))
        .collect::<Vec<_>>();
    for contract in &requirements.contracts {
        implementation_evidence_ids.extend(
            contract
                .field_test_ids
                .values()
                .chain(contract.result_test_ids.values())
                .flatten()
                .map(String::as_str),
        );
    }
    for capability in &requirements.capabilities {
        implementation_evidence_ids.extend(
            capability
                .implementation_test_ids
                .iter()
                .map(String::as_str),
        );
    }
    for scenario in &requirements.acceptance_scenarios {
        implementation_evidence_ids
            .extend(scenario.implementation_test_ids.iter().map(String::as_str));
    }
    if !crate::release_contract::evidence_claim_bindings_are_disjoint(
        &requirements
            .inventory_test_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &guard_evidence_ids,
        &implementation_evidence_ids,
        &crate::release_contract::V0_1_RELEASE_EVIDENCE_BINDINGS,
    ) {
        return Err(ReltioError::internal(
            "inventory, guard, and implementation evidence claims overlap",
        ));
    }
    Ok(())
}

fn evidence_matches(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual.iter().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
}

impl ReleaseContract {
    pub fn implementation_evidence_complete(&self) -> bool {
        self.field_test_ids.values().all(|tests| !tests.is_empty())
            && self.result_test_ids.values().all(|tests| !tests.is_empty())
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
    if pattern != "/" && pattern.ends_with('/') != path.ends_with('/') {
        return false;
    }
    let pattern_segments: Vec<_> = pattern.trim_matches('/').split('/').collect();
    let path_segments: Vec<_> = path.trim_matches('/').split('/').collect();
    pattern_segments.len() == path_segments.len()
        && pattern_segments
            .iter()
            .zip(path_segments)
            .all(|(expected, actual)| {
                if expected.starts_with('{') && expected.ends_with('}') {
                    !actual.is_empty()
                        && (*expected == "{crosswalkValue}" || !actual.starts_with('_'))
                } else {
                    *expected == actual
                }
            })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    #[::std::prelude::v1::test]
    fn release_evidence_functions_are_discoverable_in_client_unit_harness() {
        let executable = std::env::current_exe().expect("current test executable");
        let output = Command::new(&executable)
            .args(["--list", "--format", "terse"])
            .output()
            .expect("list client unit tests");
        assert!(output.status.success(), "test listing failed: {output:?}");
        let listed = String::from_utf8(output.stdout).expect("UTF-8 test listing");
        let dep_info = fs::read_to_string(executable.with_extension("d"))
            .expect("client test dep-info is readable")
            .replace('\\', "/");
        for (_, path, _, expected) in crate::release_evidence_bindings_for_validation()
            .iter()
            .filter(|(_, path, _, _)| path.starts_with("crates/reltio-client/src/"))
        {
            assert!(
                listed
                    .lines()
                    .any(|line| line == format!("{expected}: test")),
                "release evidence test {expected} is absent from the client unit harness"
            );
            assert!(
                dep_info
                    .split_ascii_whitespace()
                    .map(|entry| entry.trim_end_matches(':'))
                    .any(|entry| entry == *path),
                "release evidence source {path} is absent from client test dep-info"
            );
        }
    }

    #[::std::prelude::v1::test]
    fn release_inventory_rejects_substituted_required_operation() {
        let mut requirements = Registry::embedded()
            .expect("registry parses")
            .requirements()
            .clone();
        let operation = requirements
            .operations
            .iter_mut()
            .find(|operation| operation.id == "entity.get-many")
            .expect("required operation");
        operation.id = "entity.guessed-replacement".to_owned();
        operation.command.clone_from(&operation.id);

        let _ = validate_release_requirements(&requirements)
            .expect_err("substituting a required operation must fail");
    }

    #[::std::prelude::v1::test]
    fn release_inventory_rejects_safety_and_endpoint_downgrades() {
        let baseline = Registry::embedded()
            .expect("registry parses")
            .requirements()
            .clone();
        let mut safety = baseline.clone();
        safety
            .operations
            .iter_mut()
            .find(|operation| operation.id == "entity.delete")
            .expect("delete requirement")
            .safety = "read".to_owned();
        let _ = validate_release_requirements(&safety)
            .expect_err("a high-impact operation cannot be downgraded to read");

        let mut disclosure = baseline.clone();
        disclosure
            .operations
            .iter_mut()
            .find(|operation| operation.id == "auth.token")
            .expect("token disclosure requirement")
            .safety = "read".to_owned();
        let _ = validate_release_requirements(&disclosure)
            .expect_err("secret disclosure cannot be downgraded to read");

        let mut endpoint = baseline;
        endpoint
            .operations
            .iter_mut()
            .find(|operation| operation.id == "entity.get")
            .expect("get requirement")
            .required_endpoint_ids = vec!["auth.client_credentials".to_owned()];
        let _ = validate_release_requirements(&endpoint)
            .expect_err("an unrelated dependency endpoint cannot satisfy typed ownership");
    }

    #[::std::prelude::v1::test]
    fn mutation_audit_guard_evidence_cannot_claim_implementation() {
        let mut requirements = Registry::embedded()
            .expect("registry parses")
            .requirements()
            .clone();
        let contract = requirements
            .contracts
            .iter_mut()
            .find(|contract| contract.id == "mutation_audit_v1")
            .expect("audit contract");
        contract
            .field_test_ids
            .get_mut("operation_id")
            .expect("operation ID evidence")
            .push("mutation_audit_absence_fails_closed".to_owned());

        let _ = validate_release_requirements(&requirements)
            .expect_err("a refusal guard cannot double as implementation evidence");
    }

    #[test]
    fn aliased_evidence_ids_cannot_bridge_guard_and_implementation_claims() {
        let bindings = [
            ("guard-id", "tests/release.rs", "same_test", "guard_test"),
            (
                "implementation-id",
                "tests/release.rs",
                "same_test",
                "implementation_test",
            ),
        ];

        assert!(
            !crate::release_contract::evidence_claim_bindings_are_disjoint(
                &[],
                &["guard-id"],
                &["implementation-id"],
                &bindings,
            )
        );

        let harness_alias = [
            ("guard-id", "tests/guard.rs", "guard_test", "same_test"),
            (
                "implementation-id",
                "tests/implementation.rs",
                "implementation_test",
                "same_test",
            ),
        ];
        assert!(
            !crate::release_contract::evidence_claim_bindings_are_disjoint(
                &[],
                &["guard-id"],
                &["implementation-id"],
                &harness_alias,
            )
        );
    }

    #[::std::prelude::v1::test]
    fn release_requirements_reject_unapproved_evidence_substitution() {
        let baseline = Registry::embedded()
            .expect("registry parses")
            .requirements()
            .clone();

        let mut capability = baseline.clone();
        capability.capabilities[0]
            .implementation_test_ids
            .push("release_prd_inventory".to_owned());
        let _ = validate_release_requirements(&capability)
            .expect_err("inventory evidence cannot prove an implementation capability");

        let mut scenario = baseline.clone();
        scenario.acceptance_scenarios[0]
            .implementation_test_ids
            .push("entity_matches_contract".to_owned());
        let _ = validate_release_requirements(&scenario)
            .expect_err("an unrelated endpoint test cannot prove an acceptance scenario");

        let mut contract = baseline;
        contract.contracts[0]
            .result_test_ids
            .get_mut("succeeded")
            .expect("success-result evidence")
            .push("mutation_audit_absence_fails_closed".to_owned());
        let _ = validate_release_requirements(&contract)
            .expect_err("a refusal test cannot prove an audit result implementation");
    }

    #[::std::prelude::v1::test]
    fn release_requirement_yaml_rejects_unknown_fields() {
        let source = format!("{RELEASE_REQUIREMENTS_YAML}\nunexpected_release_claim: true\n");
        serde_yaml::from_str::<ReleaseRequirementDocument>(&source)
            .expect_err("unknown release fields must fail closed");
    }

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
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/_byCrosswalk/customer-123")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.by-crosswalk")
        );
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/_byCrosswalk/_source-id")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.by-crosswalk")
        );
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/00009qz/_changes")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.history")
        );
        assert_eq!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/00009qz/_matches")
                .map(|endpoint| endpoint.id.as_str()),
            Some("entity.matches")
        );
    }

    #[test]
    fn raw_matcher_does_not_alias_trailing_slashes_to_reviewed_endpoints() {
        let registry = Registry::embedded().expect("registry");
        assert!(
            registry
                .match_endpoint(Service::Data, "GET", "/entities/1/_matches/")
                .is_none()
        );
        assert!(
            registry
                .match_practices(Service::Data, "GET", "/entities/1/_matches/")
                .iter()
                .all(|practice| practice.service == "any")
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

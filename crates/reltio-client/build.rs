use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use chrono::{NaiveDate, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[path = "src/release_contract.rs"]
mod release_contract;

#[derive(Deserialize)]
struct PracticeDocument {
    schema_version: u32,
    catalog: Catalog,
    practices: Vec<Practice>,
}

#[derive(Deserialize)]
struct Catalog {
    corpus_commit: String,
    reviewed_at: String,
    release_notes_through: String,
}

#[derive(Deserialize)]
struct Practice {
    id: String,
    service: String,
    #[serde(default)]
    excluded_services: Vec<String>,
    enforcement: String,
    reviewed_at: String,
    implementation: String,
    commands: Vec<String>,
    methods: Vec<String>,
    path_patterns: Vec<String>,
    #[serde(default)]
    operations: Vec<PracticeOperation>,
    #[serde(default)]
    test_ids: Vec<String>,
    #[serde(default)]
    rationale: Option<String>,
    source: Source,
}

#[derive(Deserialize)]
struct PracticeOperation {
    method: String,
    path_pattern: String,
}

#[derive(Deserialize)]
struct Source {
    url: String,
    section: String,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointDocument {
    schema_version: u32,
    endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    id: String,
    service: String,
    method: String,
    path_pattern: String,
    safety: String,
    consistency: String,
    replay: String,
    pagination: String,
    #[serde(default)]
    max_body_bytes: Option<usize>,
    #[serde(default)]
    result_boundary: Option<u64>,
    #[serde(default)]
    cursor_ttl_seconds: Option<u64>,
    command_links: Vec<EndpointCommandLink>,
    practice_ids: Vec<String>,
    test_ids: Vec<String>,
    verified_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointCommandLink {
    command: String,
    role: String,
}

#[derive(Deserialize)]
struct EvidenceDocument {
    schema_version: u32,
    tests: Vec<TestEvidence>,
}

#[derive(Deserialize)]
struct TestEvidence {
    id: String,
    path: String,
    function: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequirementDocument {
    schema_version: u32,
    target_release: String,
    product_contract: ProductContract,
    inventory_test_ids: Vec<String>,
    operations: Vec<ReleaseOperation>,
    capabilities: Vec<ReleaseCapability>,
    acceptance_scenarios: Vec<AcceptanceScenario>,
    contracts: Vec<ReleaseContract>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductContract {
    path: String,
    sha256: String,
    sections: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseOperation {
    id: String,
    command: String,
    kind: String,
    safety: String,
    source_section: String,
    #[serde(default)]
    required_endpoint_role: Option<String>,
    #[serde(default)]
    required_endpoint_ids: Vec<String>,
    #[serde(default)]
    contract_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseCapability {
    id: String,
    command: String,
    argument: String,
    required_value: String,
    source_section: String,
    implementation_test_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceScenario {
    id: String,
    summary: String,
    source_section: String,
    implementation_test_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseContract {
    id: String,
    source_section: String,
    required_result_fields: Vec<String>,
    allowed_results: Vec<String>,
    guard_test_ids: Vec<String>,
    field_test_ids: BTreeMap<String, Vec<String>>,
    result_test_ids: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct UpstreamLock {
    schema_version: u32,
    corpus: UpstreamCorpus,
    deprecations: UpstreamDeprecations,
    release_notes: UpstreamReleaseNotes,
    openapi: Vec<UpstreamOpenApi>,
    review: UpstreamReview,
}

#[derive(Deserialize)]
struct UpstreamCorpus {
    commit: String,
}

#[derive(Deserialize)]
struct UpstreamDeprecations {
    index_url: String,
    sitemap_url: String,
    notice_count: usize,
    notice_url_set_sha256: String,
    notice_state_sha256: String,
}

#[derive(Deserialize)]
struct UpstreamReleaseNotes {
    sitemap_url: String,
    family: String,
    page_count: usize,
    page_url_set_sha256: String,
    page_state_sha256: String,
}

#[derive(Deserialize)]
struct UpstreamReview {
    reviewed_at: String,
    release_notes_through: String,
}

#[derive(Deserialize)]
struct UpstreamOpenApi {
    name: String,
    url: String,
    retrieved_at: String,
    last_modified: String,
    etag: String,
    content_type: String,
    sha256: String,
    info_version: String,
    operation_ids: Vec<String>,
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let practices_path = manifest.join("../../docs/reltio-api-practices.yaml");
    let endpoints_path = manifest.join("../../docs/endpoints.yaml");
    let evidence_path = manifest.join("../../docs/test-evidence.yaml");
    let requirements_path = manifest.join("../../docs/release-requirements.yaml");
    let upstream_path = manifest.join("../../docs/upstream.lock.yaml");
    let product_contract_path = manifest.join("../../docs/PRD.md");
    let repository_root = manifest.join("../..");

    println!("cargo:rerun-if-changed={}", practices_path.display());
    println!("cargo:rerun-if-changed={}", endpoints_path.display());
    println!("cargo:rerun-if-changed={}", evidence_path.display());
    println!("cargo:rerun-if-changed={}", requirements_path.display());
    println!("cargo:rerun-if-changed={}", upstream_path.display());
    println!("cargo:rerun-if-changed={}", product_contract_path.display());

    let practices: PracticeDocument = parse_yaml(&practices_path);
    let endpoints: EndpointDocument = parse_yaml(&endpoints_path);
    let evidence: EvidenceDocument = parse_yaml(&evidence_path);
    let requirements: ReleaseRequirementDocument = parse_yaml(&requirements_path);
    let upstream: UpstreamLock = parse_yaml(&upstream_path);
    assert_eq!(practices.schema_version, 1, "unsupported practice schema");
    assert_eq!(endpoints.schema_version, 2, "unsupported endpoint schema");
    assert_eq!(
        evidence.schema_version, 1,
        "unsupported test-evidence schema"
    );
    assert_eq!(
        upstream.schema_version, 1,
        "unsupported upstream-lock schema"
    );
    assert_eq!(
        requirements.schema_version, 1,
        "unsupported release-requirement schema"
    );
    assert_eq!(
        practices.catalog.corpus_commit, upstream.corpus.commit,
        "practice catalog and upstream lock use different corpus commits"
    );
    assert_eq!(
        practices.catalog.reviewed_at, upstream.review.reviewed_at,
        "practice catalog and upstream lock use different review dates"
    );
    assert_eq!(
        practices.catalog.release_notes_through, upstream.review.release_notes_through,
        "practice catalog and upstream lock use different release-note positions"
    );
    assert!(
        upstream.deprecations.index_url.starts_with("https://")
            && upstream.deprecations.sitemap_url.starts_with("https://")
            && upstream.deprecations.notice_count > 0
            && upstream.deprecations.notice_url_set_sha256.len() == 64
            && upstream
                .deprecations
                .notice_url_set_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && valid_sha256(&upstream.deprecations.notice_state_sha256),
        "upstream lock has an invalid deprecation-index fingerprint"
    );
    assert!(
        upstream.release_notes.sitemap_url.starts_with("https://")
            && !upstream.release_notes.family.trim().is_empty()
            && upstream.release_notes.page_count > 0
            && valid_sha256(&upstream.release_notes.page_url_set_sha256)
            && valid_sha256(&upstream.release_notes.page_state_sha256),
        "upstream lock has an invalid release-note fingerprint"
    );
    let mut openapi_names = BTreeSet::new();
    assert!(
        !upstream.openapi.is_empty(),
        "upstream lock has no OpenAPI source"
    );
    for source in &upstream.openapi {
        assert!(
            openapi_names.insert(source.name.as_str()),
            "upstream lock has a duplicate OpenAPI source {}",
            source.name
        );
        assert!(
            source.url.starts_with("https://")
                && chrono::DateTime::parse_from_rfc3339(&source.retrieved_at).is_ok()
                && !source.last_modified.trim().is_empty()
                && !source.etag.trim().is_empty()
                && !source.content_type.trim().is_empty()
                && valid_sha256(&source.sha256)
                && !source.info_version.trim().is_empty()
                && !source.operation_ids.is_empty()
                && source
                    .operation_ids
                    .iter()
                    .all(|operation| !operation.trim().is_empty()),
            "upstream lock has invalid OpenAPI provenance for {}",
            source.name
        );
    }
    assert!(
        valid_date(&practices.catalog.reviewed_at),
        "practice catalog has an invalid review date"
    );

    let mut evidence_ids = BTreeSet::new();
    for test in &evidence.tests {
        assert!(
            evidence_ids.insert(test.id.as_str()),
            "duplicate test-evidence ID: {}",
            test.id
        );
        let source_path = repository_root.join(&test.path);
        println!("cargo:rerun-if-changed={}", source_path.display());
        let source = fs::read_to_string(&source_path).unwrap_or_else(|error| {
            panic!(
                "test evidence {} references unreadable {}: {error}",
                test.id,
                source_path.display()
            )
        });
        assert!(
            source.contains(&format!("fn {}", test.function)),
            "test evidence {} references missing function {} in {}",
            test.id,
            test.function,
            test.path
        );
        let function_offset = source
            .find(&format!("fn {}", test.function))
            .expect("function presence checked above");
        let attribute_window = &source[function_offset.saturating_sub(512)..function_offset];
        assert!(
            attribute_window.contains("#[test]") || attribute_window.contains("#[tokio::test"),
            "test evidence {} references {} without a test attribute",
            test.id,
            test.function
        );
    }

    assert_eq!(
        requirements.target_release, "0.1.0",
        "release requirements target the wrong release"
    );
    assert_eq!(
        requirements.product_contract.path, "docs/PRD.md",
        "release requirements reference the wrong product contract"
    );
    assert!(
        !requirements.product_contract.sections.is_empty(),
        "release requirements have no product-contract sections"
    );
    assert!(
        !requirements.inventory_test_ids.is_empty(),
        "release requirements have no inventory tests"
    );
    for test_id in &requirements.inventory_test_ids {
        assert!(
            evidence_ids.contains(test_id.as_str()),
            "release inventory references test ID {test_id} without evidence"
        );
    }
    let product_contract = fs::read(&product_contract_path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}",
            product_contract_path.display()
        )
    });
    assert_eq!(
        requirements.product_contract.sha256,
        format!("{:x}", Sha256::digest(&product_contract)),
        "release requirements do not match docs/PRD.md"
    );
    assert_eq!(
        requirements.operations.len(),
        release_contract::V0_1_REQUIRED_OPERATIONS.len(),
        "the v0.1.0 release inventory must contain all 50 required command leaves"
    );
    assert_eq!(
        requirements.capabilities.len(),
        release_contract::V0_1_REQUIRED_CAPABILITIES.len(),
        "release requirements have an incorrect capability inventory"
    );
    assert_eq!(
        requirements.acceptance_scenarios.len(),
        release_contract::MVP_ACCEPTANCE_SCENARIOS.len(),
        "release requirements have an incorrect MVP acceptance inventory"
    );
    assert!(
        !requirements.contracts.is_empty(),
        "release requirements have no acceptance contracts"
    );

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
        let expected_fields = release_contract::MUTATION_AUDIT_FIELDS
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
        let expected_results = release_contract::MUTATION_AUDIT_RESULTS
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
        assert!(
            contract_ids.insert(contract.id.as_str()),
            "duplicate release contract ID: {}",
            contract.id
        );
        assert!(
            !contract.source_section.trim().is_empty()
                && required_fields == expected_fields
                && required_fields.len() == contract.required_result_fields.len()
                && field_evidence == expected_fields
                && allowed_results == expected_results
                && allowed_results.len() == contract.allowed_results.len()
                && result_evidence == expected_results
                && !contract.guard_test_ids.is_empty()
                && guard_tests.is_disjoint(&implementation_tests),
            "release contract {} has an incomplete acceptance definition",
            contract.id
        );
        for test_id in contract.guard_test_ids.iter().chain(
            contract
                .field_test_ids
                .values()
                .chain(contract.result_test_ids.values())
                .flatten(),
        ) {
            assert!(
                evidence_ids.contains(test_id.as_str()),
                "release contract {} references test ID {} without evidence",
                contract.id,
                test_id
            );
        }
    }
    assert!(
        contract_ids.contains("mutation_audit_v1"),
        "release requirements omit mutation_audit_v1"
    );

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
    let valid_roles = [
        "typed_primary",
        "workflow_component",
        "auth_dependency",
        "healthcheck_dependency",
        "raw_adapter",
    ];
    let mut operation_ids = BTreeSet::new();
    let mut release_commands = BTreeSet::new();
    let mut write_operations = BTreeSet::new();
    let mut high_impact_operations = BTreeSet::new();
    for operation in &requirements.operations {
        let endpoint_ids = operation
            .required_endpoint_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            operation.id, operation.command,
            "release requirement IDs must equal command leaves"
        );
        assert!(
            operation_ids.insert(operation.id.as_str()),
            "duplicate release operation ID: {}",
            operation.id
        );
        let expected_safety = release_contract::V0_1_OPERATION_SAFETY
            .iter()
            .find_map(|(command, safety)| (*command == operation.id).then_some(*safety))
            .unwrap_or_else(|| {
                panic!(
                    "independent safety inventory omits release operation {}",
                    operation.id
                )
            });
        assert_eq!(
            operation.safety, expected_safety,
            "release operation {} has the wrong safety tier",
            operation.id
        );
        let expected_role = release_contract::V0_1_ENDPOINT_REQUIREMENTS
            .iter()
            .find_map(|(command, role)| (*command == operation.id).then_some(*role));
        assert_eq!(
            operation.required_endpoint_role.as_deref(),
            expected_role,
            "release operation {} has the wrong endpoint-role obligation",
            operation.id
        );
        let expected_endpoint_ids = release_contract::REVIEWED_ENDPOINT_BINDINGS
            .iter()
            .filter_map(|(command, endpoint_id)| (*command == operation.id).then_some(*endpoint_id))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            endpoint_ids, expected_endpoint_ids,
            "release operation {} has an unapproved endpoint binding",
            operation.id
        );
        if operation.safety == "remote_write" {
            write_operations.insert(operation.id.as_str());
        }
        if operation.safety == "remote_high_impact" {
            high_impact_operations.insert(operation.id.as_str());
        }
        assert!(
            release_commands.insert(operation.command.as_str()),
            "duplicate release command: {}",
            operation.command
        );
        assert!(
            valid_kinds.contains(&operation.kind.as_str())
                && valid_safety.contains(&operation.safety.as_str())
                && !operation.source_section.trim().is_empty()
                && operation
                    .required_endpoint_role
                    .as_deref()
                    .is_none_or(|role| valid_roles.contains(&role))
                && endpoint_ids.len() == operation.required_endpoint_ids.len()
                && (operation.required_endpoint_role.is_some()
                    || operation.required_endpoint_ids.is_empty()),
            "release operation {} has an invalid kind, safety, source, or endpoint role",
            operation.id
        );
        assert!(
            operation
                .contract_ids
                .iter()
                .all(|id| contract_ids.contains(id.as_str())),
            "release operation {} references an unknown acceptance contract",
            operation.id
        );
        if matches!(
            operation.safety.as_str(),
            "remote_write" | "remote_high_impact"
        ) {
            assert!(
                operation
                    .contract_ids
                    .iter()
                    .any(|id| id == "mutation_audit_v1"),
                "remote mutation {} omits mutation_audit_v1",
                operation.id
            );
        }
    }
    let expected_operations = release_contract::V0_1_REQUIRED_OPERATIONS
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        operation_ids, expected_operations,
        "release inventory does not match the independent v0.1.0 operation set"
    );
    assert_eq!(
        write_operations,
        release_contract::V0_1_WRITE_OPERATIONS
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "release inventory does not match the independent write-operation set"
    );
    assert_eq!(
        high_impact_operations,
        release_contract::V0_1_HIGH_IMPACT_OPERATIONS
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "release inventory does not match the independent high-impact-operation set"
    );
    for operation_id in release_contract::V0_1_DYNAMIC_MUTATION_ADAPTERS {
        assert!(
            requirements
                .operations
                .iter()
                .find(|operation| operation.id == operation_id)
                .is_some_and(|operation| operation.safety == "dynamic"
                    && operation
                        .contract_ids
                        .iter()
                        .any(|id| id == "mutation_audit_v1")),
            "dynamic mutation adapter {operation_id} omits mutation_audit_v1"
        );
    }

    let mut capability_ids = BTreeSet::new();
    for capability in &requirements.capabilities {
        assert!(
            capability_ids.insert(capability.id.as_str()),
            "duplicate release capability ID: {}",
            capability.id
        );
        assert!(
            release_commands.contains(capability.command.as_str())
                && !capability.argument.trim().is_empty()
                && !capability.required_value.trim().is_empty()
                && !capability.source_section.trim().is_empty(),
            "release capability {} has an invalid acceptance definition",
            capability.id
        );
        for test_id in &capability.implementation_test_ids {
            assert!(
                evidence_ids.contains(test_id.as_str()),
                "release capability {} references test ID {} without evidence",
                capability.id,
                test_id
            );
        }
    }
    let expected_capabilities = release_contract::V0_1_REQUIRED_CAPABILITIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        capability_ids, expected_capabilities,
        "release inventory does not match the independent v0.1.0 capability set"
    );

    let mut acceptance_ids = BTreeSet::new();
    for scenario in &requirements.acceptance_scenarios {
        assert!(
            acceptance_ids.insert(scenario.id.as_str())
                && !scenario.summary.trim().is_empty()
                && !scenario.source_section.trim().is_empty(),
            "acceptance scenario {} has an invalid definition",
            scenario.id
        );
        for test_id in &scenario.implementation_test_ids {
            assert!(
                evidence_ids.contains(test_id.as_str()),
                "acceptance scenario {} references test ID {} without evidence",
                scenario.id,
                test_id
            );
        }
    }
    let expected_acceptance = release_contract::MVP_ACCEPTANCE_SCENARIOS
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        acceptance_ids, expected_acceptance,
        "release inventory does not match the independent MVP acceptance set"
    );

    let mut practice_ids = BTreeSet::new();
    for practice in &practices.practices {
        assert!(
            practice_ids.insert(practice.id.as_str()),
            "duplicate practice ID: {}",
            practice.id
        );
        assert!(
            practice.source.url.starts_with("https://"),
            "practice {} must use an HTTPS source",
            practice.id
        );
        assert!(
            !practice.source.section.trim().is_empty(),
            "practice {} has no source section",
            practice.id
        );
        assert!(
            valid_date(&practice.reviewed_at),
            "practice {} has an invalid review date",
            practice.id
        );
        assert!(
            valid_date(&practice.source.updated_at),
            "practice {} has an invalid source update date",
            practice.id
        );
        assert!(
            !practice.methods.is_empty() && !practice.path_patterns.is_empty(),
            "practice {} has no method/path scope",
            practice.id
        );
        assert!(
            if practice.service == "any" {
                practice
                    .excluded_services
                    .iter()
                    .all(|service| !service.trim().is_empty() && service != "any")
            } else {
                practice.excluded_services.is_empty()
            },
            "practice {} has invalid service exclusions",
            practice.id
        );
        assert!(
            practice.operations.iter().all(|operation| {
                !operation.method.trim().is_empty()
                    && (operation.path_pattern == "*" || operation.path_pattern.starts_with('/'))
            }),
            "practice {} has an invalid operation scope",
            practice.id
        );
        assert!(
            !practice.implementation.trim().is_empty(),
            "practice {} has no implementation disposition",
            practice.id
        );
        let implementation_path = repository_root.join(&practice.implementation);
        assert!(
            implementation_path.is_file(),
            "practice {} references missing implementation {}",
            practice.id,
            practice.implementation
        );
        println!("cargo:rerun-if-changed={}", implementation_path.display());
        assert!(
            !practice.enforcement.trim().is_empty(),
            "practice {} has no enforcement mode",
            practice.id
        );
        assert!(
            !practice.commands.is_empty(),
            "practice {} has no affected commands",
            practice.id
        );
        assert!(
            !practice.test_ids.is_empty()
                || practice.rationale.as_deref().is_some_and(|v| !v.is_empty()),
            "practice {} needs tests or an approved rationale",
            practice.id
        );
        for test_id in &practice.test_ids {
            assert!(
                evidence_ids.contains(test_id.as_str()),
                "practice {} references test ID {} without evidence",
                practice.id,
                test_id
            );
        }
    }

    let mut endpoint_ids = BTreeSet::new();
    for endpoint in &endpoints.endpoints {
        assert!(
            endpoint_ids.insert(endpoint.id.as_str()),
            "duplicate endpoint ID: {}",
            endpoint.id
        );
        assert!(
            !endpoint.service.is_empty(),
            "endpoint {} has no service",
            endpoint.id
        );
        assert!(
            !endpoint.method.is_empty(),
            "endpoint {} has no method",
            endpoint.id
        );
        assert!(
            ["read", "authentication", "write", "high_impact"].contains(&endpoint.safety.as_str())
                && ["consistent", "eventual", "unknown", "not_applicable"]
                    .contains(&endpoint.consistency.as_str())
                && ["safe", "safe_with_limit", "unsafe"].contains(&endpoint.replay.as_str())
                && ["none", "offset", "cursor"].contains(&endpoint.pagination.as_str())
                && endpoint.max_body_bytes.is_none_or(|limit| limit > 0)
                && endpoint.result_boundary.is_none_or(|limit| limit > 0)
                && endpoint.cursor_ttl_seconds.is_none_or(|limit| limit > 0),
            "endpoint {} has invalid protocol or safety metadata",
            endpoint.id
        );
        assert!(
            endpoint.path_pattern.starts_with('/'),
            "endpoint {} path must be absolute within its service",
            endpoint.id
        );
        assert!(
            !endpoint.command_links.is_empty(),
            "endpoint {} has no commands",
            endpoint.id
        );
        let mut endpoint_links = BTreeSet::new();
        for link in &endpoint.command_links {
            assert!(
                endpoint_links.insert((link.command.as_str(), link.role.as_str())),
                "endpoint {} has a duplicate command link {} ({})",
                endpoint.id,
                link.command,
                link.role
            );
            assert!(
                valid_roles.contains(&link.role.as_str()),
                "endpoint {} has invalid command-link role {}",
                endpoint.id,
                link.role
            );
            let operation = requirements
                .operations
                .iter()
                .find(|operation| operation.command == link.command)
                .unwrap_or_else(|| {
                    panic!(
                        "endpoint {} links command {} outside the release contract",
                        endpoint.id, link.command
                    )
                });
            if link.role == "typed_primary" {
                assert_eq!(
                    operation.required_endpoint_role.as_deref(),
                    Some("typed_primary"),
                    "endpoint {} assigns typed-primary ownership to incompatible requirement {}",
                    endpoint.id,
                    operation.id
                );
            }
            if operation.required_endpoint_role.as_deref() == Some(link.role.as_str()) {
                assert!(
                    operation
                        .required_endpoint_ids
                        .iter()
                        .any(|id| id == &endpoint.id),
                    "endpoint {} is not an approved binding for requirement {} ({})",
                    endpoint.id,
                    operation.id,
                    link.role
                );
                if link.role != "auth_dependency" {
                    let expected_safety = match operation.safety.as_str() {
                        "read" => Some("read"),
                        "authentication" => Some("authentication"),
                        "remote_write" => Some("write"),
                        "remote_high_impact" => Some("high_impact"),
                        _ => None,
                    };
                    if let Some(expected_safety) = expected_safety {
                        assert_eq!(
                            endpoint.safety, expected_safety,
                            "endpoint {} safety does not match requirement {}",
                            endpoint.id, operation.id
                        );
                    }
                }
            }
        }
        assert!(
            !endpoint.test_ids.is_empty(),
            "endpoint {} has no tests",
            endpoint.id
        );
        assert!(
            valid_date(&endpoint.verified_at),
            "endpoint {} has an invalid verification date",
            endpoint.id
        );
        assert!(
            !endpoint.practice_ids.is_empty(),
            "endpoint {} has no practice coverage",
            endpoint.id
        );
        for practice_id in &endpoint.practice_ids {
            assert!(
                practice_ids.contains(practice_id.as_str()),
                "endpoint {} references unknown practice {}",
                endpoint.id,
                practice_id
            );
            let practice = practices
                .practices
                .iter()
                .find(|practice| practice.id == *practice_id)
                .expect("practice presence checked above");
            assert!(
                !practice.excluded_services.contains(&endpoint.service),
                "endpoint {} links practice {} despite its service exclusion",
                endpoint.id,
                practice.id
            );
            if (practice.service == "any" || practice.service == endpoint.service)
                && !practice.excluded_services.contains(&endpoint.service)
            {
                assert!(
                    practice.matches(&endpoint.method, &endpoint.path_pattern),
                    "endpoint {} links inapplicable practice {}",
                    endpoint.id,
                    practice.id
                );
            }
            for command in endpoint.command_links.iter().map(|link| &link.command) {
                assert!(
                    practice.commands.contains(command),
                    "practice {} omits endpoint command {} for {}",
                    practice.id,
                    command,
                    endpoint.id
                );
            }
        }
        for practice in practices.practices.iter().filter(|practice| {
            (practice.service == "any" || practice.service == endpoint.service)
                && !practice.excluded_services.contains(&endpoint.service)
                && practice.matches(&endpoint.method, &endpoint.path_pattern)
        }) {
            assert!(
                endpoint.practice_ids.contains(&practice.id),
                "endpoint {} omits applicable practice {}",
                endpoint.id,
                practice.id
            );
            for command in endpoint.command_links.iter().map(|link| &link.command) {
                assert!(
                    practice.commands.contains(command),
                    "applicable practice {} omits endpoint command {} for {}",
                    practice.id,
                    command,
                    endpoint.id
                );
            }
        }
        for test_id in &endpoint.test_ids {
            assert!(
                evidence_ids.contains(test_id.as_str()),
                "endpoint {} references test ID {} without evidence",
                endpoint.id,
                test_id
            );
        }
    }
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> T {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_yaml::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn valid_date(value: &str) -> bool {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok_and(|date| date <= Utc::now().date_naive())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Practice {
    fn matches(&self, method: &str, path: &str) -> bool {
        if !self.operations.is_empty() {
            return self.operations.iter().any(|operation| {
                (operation.method == "*" || operation.method.eq_ignore_ascii_case(method))
                    && path_matches(&operation.path_pattern, path)
            });
        }
        self.methods
            .iter()
            .any(|candidate| candidate == "*" || candidate.eq_ignore_ascii_case(method))
            && self
                .path_patterns
                .iter()
                .any(|pattern| path_matches(pattern, path))
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern != "/" && pattern.ends_with('/') != path.ends_with('/') {
        return false;
    }
    let pattern_segments = pattern.trim_matches('/').split('/').collect::<Vec<_>>();
    let path_segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    pattern_segments.len() == path_segments.len()
        && pattern_segments
            .iter()
            .zip(path_segments)
            .all(|(expected, actual)| {
                (expected.starts_with('{')
                    && expected.ends_with('}')
                    && !actual.is_empty()
                    && (*expected == "{crosswalkValue}" || !actual.starts_with('_')))
                    || *expected == actual
            })
}

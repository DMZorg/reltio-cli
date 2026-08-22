use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use chrono::{NaiveDate, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use syn::ext::IdentExt;

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
    page_size_max: Option<u32>,
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
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    schema_version: u32,
    tests: Vec<TestEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestEvidence {
    id: String,
    path: String,
    function: String,
}

#[derive(Deserialize)]
struct CargoManifest {
    package: CargoPackage,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    lib: Option<CargoTarget>,
    #[serde(default, rename = "bin")]
    bins: Vec<CargoTarget>,
    #[serde(default, rename = "test")]
    tests: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    #[serde(default)]
    build: Option<String>,
    #[serde(default)]
    autolib: Option<bool>,
    #[serde(default)]
    autotests: Option<bool>,
}

#[derive(Deserialize)]
struct CargoTarget {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    test: Option<bool>,
    #[serde(default)]
    harness: Option<bool>,
    #[serde(default, rename = "required-features")]
    required_features: Vec<String>,
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
    #[serde(default)]
    implementation_test_ids: Vec<String>,
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
#[serde(deny_unknown_fields)]
struct UpstreamLock {
    schema_version: u32,
    content_fingerprint_version: u32,
    corpus: UpstreamCorpus,
    deprecations: UpstreamDeprecations,
    release_notes: UpstreamReleaseNotes,
    openapi: Vec<UpstreamOpenApi>,
    review: UpstreamReview,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamCorpus {
    repository: String,
    commit: String,
    generated_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamDeprecations {
    index_url: String,
    index_content_sha256: String,
    index_link_count: usize,
    index_link_url_set_sha256: String,
    index_links: Vec<String>,
    sitemap_url: String,
    notice_count: usize,
    notice_url_set_sha256: String,
    notice_state_sha256: String,
    notice_content_sha256: String,
    notice_content_sources: Vec<UpstreamContentSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamReleaseNotes {
    sitemap_url: String,
    family: String,
    page_count: usize,
    page_url_set_sha256: String,
    page_state_sha256: String,
    page_content_sha256: String,
    page_content_sources: Vec<UpstreamContentSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamReview {
    reviewed_at: String,
    language: String,
    release_notes_through: String,
    practice_source_count: usize,
    practice_source_url_set_sha256: String,
    practice_source_content_sha256: String,
    practice_content_sources: Vec<UpstreamContentSource>,
    notes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamContentSource {
    url: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamOpenApi {
    name: String,
    url: String,
    retrieved_at: String,
    sha256: String,
    info_version: String,
    operations: Vec<UpstreamOpenApiOperation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamOpenApiOperation {
    endpoint_id: String,
    method: String,
    path: String,
    operation_id: String,
}

const REVIEWED_OPENAPI_OPERATIONS: [(&str, &str, &str, &str); 4] = [
    (
        "entity.by-crosswalk",
        "GET",
        "/services/reltio/api/{tenantId}/entities/_byCrosswalk/{crosswalkValue}",
        "getEntityByCrosswalk",
    ),
    (
        "entity.history",
        "GET",
        "/services/reltio/api/{tenantId}/entities/{id}/_changes",
        "getChangesByTenant",
    ),
    (
        "entity.matches",
        "GET",
        "/services/reltio/api/{tenantId}/entities/{id}/_matches",
        "getPotentialMatchesByTenantPerEntity",
    ),
    (
        "entity.scan",
        "POST",
        "/services/reltio/api/{tenantId}/entities/v2/_scan",
        "getEntitiesByScanSearch",
    ),
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let practices_path = manifest.join("../../docs/reltio-api-practices.yaml");
    let endpoints_path = manifest.join("../../docs/endpoints.yaml");
    let evidence_path = manifest.join("../../docs/test-evidence.yaml");
    let requirements_path = manifest.join("../../docs/release-requirements.yaml");
    let upstream_path = manifest.join("../../docs/upstream.lock.yaml");
    let product_contract_path = manifest.join("../../docs/PRD.md");
    let repository_root = manifest.join("../..");

    validate_repository_cargo_manifests(&repository_root);

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
        upstream.content_fingerprint_version, 2,
        "unsupported upstream content-fingerprint version"
    );
    assert!(
        upstream.corpus.repository == "https://github.com/reltio-ai/reltio-ai-ready-docs"
            && upstream
                .corpus
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && upstream.corpus.commit.len() == 40
            && chrono::DateTime::parse_from_rfc3339(&upstream.corpus.generated_at)
                .is_ok_and(|generated| generated <= Utc::now()),
        "upstream lock has invalid corpus provenance"
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
        upstream.deprecations.index_url
            == "https://docs.reltio.com/en/reltio/whats-new-and-notable/whats-new-at-a-glance/deprecation-notices-at-a-glance"
            && valid_sha256(&upstream.deprecations.index_content_sha256)
            && upstream.deprecations.index_link_count > 0
            && valid_sha256(&upstream.deprecations.index_link_url_set_sha256)
            && upstream.deprecations.sitemap_url == "https://docs.reltio.com/en/reltio/sitemap.xml"
            && upstream.deprecations.notice_count > 0
            && upstream.deprecations.notice_url_set_sha256.len() == 64
            && upstream
                .deprecations
                .notice_url_set_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && valid_sha256(&upstream.deprecations.notice_state_sha256)
            && valid_sha256(&upstream.deprecations.notice_content_sha256),
        "upstream lock has an invalid deprecation-index fingerprint"
    );
    validate_url_set(
        "deprecation index links",
        &upstream.deprecations.index_links,
        upstream.deprecations.index_link_count,
        &upstream.deprecations.index_link_url_set_sha256,
    );
    assert!(
        upstream.release_notes.sitemap_url == upstream.deprecations.sitemap_url
            && !upstream.release_notes.family.trim().is_empty()
            && upstream.release_notes.page_count > 0
            && valid_sha256(&upstream.release_notes.page_url_set_sha256)
            && valid_sha256(&upstream.release_notes.page_state_sha256)
            && valid_sha256(&upstream.release_notes.page_content_sha256),
        "upstream lock has an invalid release-note fingerprint"
    );
    assert!(
        upstream.review.language == "en"
            && !upstream.review.notes.trim().is_empty()
            && upstream.review.practice_source_count > 0
            && valid_sha256(&upstream.review.practice_source_url_set_sha256)
            && valid_sha256(&upstream.review.practice_source_content_sha256),
        "upstream lock has an invalid practice-source fingerprint"
    );
    let deprecation_content_urls = validate_content_sources(
        "deprecation notices",
        &upstream.deprecations.notice_content_sources,
        upstream.deprecations.notice_count,
        &upstream.deprecations.notice_url_set_sha256,
        &upstream.deprecations.notice_content_sha256,
    );
    let release_content_urls = validate_content_sources(
        "release notes",
        &upstream.release_notes.page_content_sources,
        upstream.release_notes.page_count,
        &upstream.release_notes.page_url_set_sha256,
        &upstream.release_notes.page_content_sha256,
    );
    let practice_content_urls = validate_content_sources(
        "practice sources",
        &upstream.review.practice_content_sources,
        upstream.review.practice_source_count,
        &upstream.review.practice_source_url_set_sha256,
        &upstream.review.practice_source_content_sha256,
    );
    let catalog_practice_urls = practices
        .practices
        .iter()
        .map(|practice| practice.source.url.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        practice_content_urls, catalog_practice_urls,
        "locked practice-source fingerprints do not match the catalog source URLs"
    );
    assert!(
        !deprecation_content_urls.is_empty() && !release_content_urls.is_empty(),
        "locked documentation content-source sets must not be empty"
    );
    let mut openapi_names = BTreeSet::new();
    assert!(
        !upstream.openapi.is_empty(),
        "upstream lock has no OpenAPI source"
    );
    assert_eq!(
        upstream.openapi.len(),
        1,
        "the drift workflow must be extended before adding another OpenAPI source"
    );
    for source in &upstream.openapi {
        assert!(
            openapi_names.insert(source.name.as_str()),
            "upstream lock has a duplicate OpenAPI source {}",
            source.name
        );
        assert!(
            source.name == "data-operation"
                && source.url == "https://developer.reltio.com/swagger/Data%20Operation"
                && chrono::DateTime::parse_from_rfc3339(&source.retrieved_at)
                    .is_ok_and(|retrieved| retrieved <= Utc::now())
                && valid_sha256(&source.sha256)
                && source.info_version == "2020.2"
                && !source.operations.is_empty()
                && source.operations.iter().all(|operation| {
                    !operation.endpoint_id.is_empty()
                        && !operation.method.is_empty()
                        && operation.path.starts_with('/')
                        && !operation.operation_id.is_empty()
                        && operation
                            .operation_id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                }),
            "upstream lock has invalid OpenAPI provenance for {}",
            source.name
        );
        let operations = source
            .operations
            .iter()
            .map(|operation| {
                (
                    operation.endpoint_id.as_str(),
                    operation.method.as_str(),
                    operation.path.as_str(),
                    operation.operation_id.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            operations.len(),
            source.operations.len(),
            "OpenAPI operation bindings contain duplicates"
        );
        assert_eq!(
            operations,
            REVIEWED_OPENAPI_OPERATIONS.into_iter().collect(),
            "OpenAPI operation bindings differ from the reviewed endpoint ownership"
        );
        let endpoint_ids = endpoints
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            operations
                .iter()
                .all(|(endpoint_id, _, _, _)| endpoint_ids.contains(endpoint_id)),
            "OpenAPI operation bindings reference unknown endpoint IDs"
        );
    }
    assert!(
        valid_date(&practices.catalog.reviewed_at),
        "practice catalog has an invalid review date"
    );

    let mut evidence_ids = BTreeSet::new();
    let mut evidence_attributions = BTreeMap::new();
    let mut evidence_sources = BTreeMap::new();
    let mut package_features = BTreeMap::new();
    let canonical_repository_root = repository_root
        .canonicalize()
        .expect("repository root must be canonicalizable");
    validate_release_cargo_targets(&canonical_repository_root);
    for test in &evidence.tests {
        assert!(
            !test.id.trim().is_empty()
                && !test.path.trim().is_empty()
                && !test.function.trim().is_empty(),
            "test-evidence entries require nonempty IDs, paths, and functions"
        );
        assert!(
            evidence_ids.insert(test.id.as_str()),
            "duplicate test-evidence ID: {}",
            test.id
        );
        evidence_attributions.insert(
            test.id.as_str(),
            (test.path.as_str(), test.function.as_str()),
        );
        let relative_path = Path::new(&test.path);
        assert!(
            !relative_path.is_absolute()
                && relative_path
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "test evidence {} must use a repository-relative path without traversal",
            test.id
        );
        let source_path = repository_root.join(relative_path);
        let canonical_source_path = source_path.canonicalize().unwrap_or_else(|error| {
            panic!(
                "test evidence {} references a source that cannot be canonicalized ({}): {error}",
                test.id, test.path
            )
        });
        assert_eq!(
            canonical_source_path,
            canonical_repository_root.join(relative_path),
            "test evidence {} uses a symlink, case alias, or noncanonical source path",
            test.id
        );
        if !evidence_sources.contains_key(&test.path) {
            println!("cargo:rerun-if-changed={}", source_path.display());
            let source = fs::read_to_string(&source_path).unwrap_or_else(|error| {
                panic!(
                    "test evidence {} references unreadable {}: {error}",
                    test.id,
                    source_path.display()
                )
            });
            let syntax = syn::parse_file(&source).unwrap_or_else(|error| {
                panic!(
                    "test evidence {} references Rust source that cannot be parsed ({}): {error}",
                    test.id, test.path
                )
            });
            evidence_sources.insert(test.path.clone(), syntax);
        }
        let declared_features =
            evidence_package_features(&repository_root, &test.path, &mut package_features);
        validate_test_evidence(
            evidence_sources
                .get(&test.path)
                .expect("evidence source was inserted above"),
            test,
            declared_features,
        );
    }

    let mut release_evidence_ids = BTreeSet::new();
    release_evidence_ids.extend(requirements.inventory_test_ids.iter().map(String::as_str));
    for operation in &requirements.operations {
        release_evidence_ids.extend(operation.implementation_test_ids.iter().map(String::as_str));
    }
    for contract in &requirements.contracts {
        release_evidence_ids.extend(contract.guard_test_ids.iter().map(String::as_str));
        release_evidence_ids.extend(
            contract
                .field_test_ids
                .values()
                .chain(contract.result_test_ids.values())
                .flatten()
                .map(String::as_str),
        );
    }
    for capability in &requirements.capabilities {
        release_evidence_ids.extend(
            capability
                .implementation_test_ids
                .iter()
                .map(String::as_str),
        );
    }
    for scenario in &requirements.acceptance_scenarios {
        release_evidence_ids.extend(scenario.implementation_test_ids.iter().map(String::as_str));
    }
    let approved_release_evidence = release_contract::V0_1_RELEASE_EVIDENCE_BINDINGS
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        release_evidence_ids, approved_release_evidence,
        "release-critical evidence IDs do not match the independently compiled bindings"
    );
    for (id, expected_path, expected_function, harness_name) in
        release_contract::V0_1_RELEASE_EVIDENCE_BINDINGS
    {
        let actual = evidence_attributions
            .get(id)
            .unwrap_or_else(|| panic!("release evidence {id} has no test attribution"));
        assert_eq!(
            *actual,
            (expected_path, expected_function),
            "release evidence {id} was redirected to an unapproved source or function"
        );
        assert!(
            !harness_name.trim().is_empty(),
            "release evidence {id} has no Cargo harness name"
        );
        let expected_harness_name = cargo_harness_name(
            expected_path,
            expected_function,
            evidence_sources
                .get(expected_path)
                .unwrap_or_else(|| panic!("release evidence {id} has no parsed source")),
        );
        assert_eq!(
            harness_name, expected_harness_name,
            "release evidence {id} has a Cargo harness name unrelated to its source function"
        );
        validate_release_test_function(
            evidence_sources
                .get(expected_path)
                .expect("release evidence has parsed source"),
            id,
            expected_function,
        );
        let package = Path::new(expected_path)
            .components()
            .nth(1)
            .and_then(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                _ => None,
            })
            .expect("release evidence package component");
        validate_release_source_module(
            &canonical_repository_root,
            expected_path,
            package_features
                .get(&package)
                .unwrap_or_else(|| panic!("release evidence package {package} has no features")),
        );
        assert!(
            expected_path.starts_with("crates/reltio-client/src/")
                || expected_path.starts_with("crates/reltio-cli/src/")
                || expected_path == "crates/reltio-cli/tests/cli.rs",
            "release evidence {id} uses a target without a Cargo-list verifier"
        );
    }

    let guard_evidence_ids = requirements
        .contracts
        .iter()
        .flat_map(|contract| contract.guard_test_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let mut implementation_evidence_ids = requirements
        .operations
        .iter()
        .flat_map(|operation| operation.implementation_test_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
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
    let guard_evidence_bindings = guard_evidence_ids
        .iter()
        .map(|id| {
            *evidence_attributions
                .get(id)
                .unwrap_or_else(|| panic!("guard evidence {id} has no attribution"))
        })
        .collect::<BTreeSet<_>>();
    let implementation_evidence_bindings = implementation_evidence_ids
        .iter()
        .map(|id| {
            *evidence_attributions
                .get(id)
                .unwrap_or_else(|| panic!("implementation evidence {id} has no attribution"))
        })
        .collect::<BTreeSet<_>>();
    assert!(
        guard_evidence_bindings.is_disjoint(&implementation_evidence_bindings),
        "guard and implementation claims must not resolve to the same test function"
    );
    assert!(
        release_contract::evidence_claim_bindings_are_disjoint(
            &requirements
                .inventory_test_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &guard_evidence_ids.iter().copied().collect::<Vec<_>>(),
            &implementation_evidence_ids
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            &release_contract::V0_1_RELEASE_EVIDENCE_BINDINGS,
        ),
        "independently compiled inventory, guard, and implementation bindings overlap"
    );

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
    assert!(
        evidence_matches(
            &requirements.inventory_test_ids,
            &release_contract::V0_1_INVENTORY_TEST_IDS,
        ),
        "release inventory evidence does not match the independent approved set"
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
                && evidence_matches(
                    &contract.guard_test_ids,
                    &release_contract::MUTATION_AUDIT_GUARD_EVIDENCE,
                )
                && contract.field_test_ids.iter().all(|(field, evidence)| {
                    release_contract::MUTATION_AUDIT_FIELD_EVIDENCE
                        .iter()
                        .find_map(|(expected_field, expected)| {
                            (*expected_field == field).then_some(*expected)
                        })
                        .is_some_and(|expected| evidence_matches(evidence, expected))
                })
                && contract.result_test_ids.iter().all(|(result, evidence)| {
                    release_contract::MUTATION_AUDIT_RESULT_EVIDENCE
                        .iter()
                        .find_map(|(expected_result, expected)| {
                            (*expected_result == result).then_some(*expected)
                        })
                        .is_some_and(|expected| evidence_matches(evidence, expected))
                })
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
        let expected_implementation_evidence = release_contract::V0_1_OPERATION_EVIDENCE
            .iter()
            .find_map(|(command, evidence)| (*command == operation.id).then_some(*evidence))
            .unwrap_or(&[]);
        assert!(
            evidence_matches(
                &operation.implementation_test_ids,
                expected_implementation_evidence,
            ),
            "release operation {} has unapproved implementation evidence",
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
                && !capability.source_section.trim().is_empty()
                && release_contract::V0_1_CAPABILITY_EVIDENCE
                    .iter()
                    .find_map(|(id, expected)| { (*id == capability.id).then_some(*expected) })
                    .is_some_and(|expected| {
                        evidence_matches(&capability.implementation_test_ids, expected)
                    }),
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
                && !scenario.source_section.trim().is_empty()
                && release_contract::MVP_ACCEPTANCE_EVIDENCE
                    .iter()
                    .find_map(|(id, expected)| (*id == scenario.id).then_some(*expected))
                    .is_some_and(|expected| {
                        evidence_matches(&scenario.implementation_test_ids, expected)
                    }),
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
                && ["safe", "safe_with_limit", "conditional", "unsafe"]
                    .contains(&endpoint.replay.as_str())
                && ["none", "offset", "cursor"].contains(&endpoint.pagination.as_str())
                && endpoint.max_body_bytes.is_none_or(|limit| limit > 0)
                && endpoint.result_boundary.is_none_or(|limit| limit > 0)
                && endpoint.page_size_max.is_none_or(|limit| limit > 0)
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

    let mut referenced_evidence_ids = BTreeSet::new();
    referenced_evidence_ids.extend(requirements.inventory_test_ids.iter().map(String::as_str));
    for operation in &requirements.operations {
        referenced_evidence_ids
            .extend(operation.implementation_test_ids.iter().map(String::as_str));
    }
    for contract in &requirements.contracts {
        referenced_evidence_ids.extend(contract.guard_test_ids.iter().map(String::as_str));
        referenced_evidence_ids.extend(
            contract
                .field_test_ids
                .values()
                .chain(contract.result_test_ids.values())
                .flatten()
                .map(String::as_str),
        );
    }
    for capability in &requirements.capabilities {
        referenced_evidence_ids.extend(
            capability
                .implementation_test_ids
                .iter()
                .map(String::as_str),
        );
    }
    for scenario in &requirements.acceptance_scenarios {
        referenced_evidence_ids.extend(scenario.implementation_test_ids.iter().map(String::as_str));
    }
    for practice in &practices.practices {
        referenced_evidence_ids.extend(practice.test_ids.iter().map(String::as_str));
    }
    for endpoint in &endpoints.endpoints {
        referenced_evidence_ids.extend(endpoint.test_ids.iter().map(String::as_str));
    }
    let unreferenced = evidence_ids
        .difference(&referenced_evidence_ids)
        .copied()
        .collect::<Vec<_>>();
    let undeclared = referenced_evidence_ids
        .difference(&evidence_ids)
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unreferenced.is_empty() && undeclared.is_empty(),
        "test-evidence attribution must be exact; unreferenced: {unreferenced:?}; undeclared: {undeclared:?}"
    );
}

fn evidence_package_features<'a>(
    repository_root: &Path,
    evidence_path: &str,
    cache: &'a mut BTreeMap<String, BTreeSet<String>>,
) -> &'a BTreeSet<String> {
    let components = Path::new(evidence_path).components().collect::<Vec<_>>();
    assert!(
        components.len() >= 3
            && components[0].as_os_str() == "crates"
            && matches!(components[1], Component::Normal(_)),
        "test evidence path {evidence_path} is not owned by a workspace crate"
    );
    let package = components[1].as_os_str().to_string_lossy().into_owned();
    if !cache.contains_key(&package) {
        let manifest_path = repository_root
            .join("crates")
            .join(&package)
            .join("Cargo.toml");
        println!("cargo:rerun-if-changed={}", manifest_path.display());
        let manifest = fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
            panic!(
                "test evidence package {package} has no readable Cargo manifest at {}: {error}",
                manifest_path.display()
            )
        });
        let manifest: CargoManifest = toml::from_str(&manifest).unwrap_or_else(|error| {
            panic!(
                "test evidence package {package} has an invalid Cargo manifest at {}: {error}",
                manifest_path.display()
            )
        });
        cache.insert(package.clone(), default_feature_set(&manifest.features));
    }
    cache
        .get(&package)
        .expect("evidence package features were inserted above")
}

fn default_feature_set(features: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut enabled = BTreeSet::new();
    let mut pending = Vec::new();
    if features.contains_key("default") {
        enabled.insert("default".to_owned());
        pending.push("default".to_owned());
    }
    while let Some(feature) = pending.pop() {
        let Some(members) = features.get(&feature) else {
            continue;
        };
        for member in members {
            if member.starts_with("dep:") || member.contains('/') || !features.contains_key(member)
            {
                continue;
            }
            if enabled.insert(member.clone()) {
                pending.push(member.clone());
            }
        }
    }
    enabled
}

fn validate_test_evidence(
    syntax: &syn::File,
    test: &TestEvidence,
    declared_features: &BTreeSet<String>,
) {
    let mut matches = Vec::new();
    let mut inherited_attributes = syntax.attrs.iter().collect::<Vec<_>>();
    collect_test_functions(
        &syntax.items,
        &test.function,
        &mut inherited_attributes,
        &mut matches,
        declared_features,
    );
    assert_eq!(
        matches.len(),
        1,
        "test evidence {} must reference exactly one function named {} in {}",
        test.id,
        test.function,
        test.path
    );
    let (is_test, ignored, matrix_enabled, attributes_supported) = matches[0];
    assert!(
        is_test && !ignored && matrix_enabled && attributes_supported,
        "test evidence {} references {} without an executable test on the release matrix",
        test.id,
        test.function
    );
}

fn collect_test_functions<'a>(
    items: &'a [syn::Item],
    function: &str,
    inherited_attributes: &mut Vec<&'a syn::Attribute>,
    matches: &mut Vec<(bool, bool, bool, bool)>,
    declared_features: &BTreeSet<String>,
) {
    for item in items {
        match item {
            syn::Item::Fn(item) if item.sig.ident == function => {
                let is_test = item.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("test")
                        || path_is(attribute.path(), &["tokio", "test"])
                        || builtin_test_attribute(attribute)
                });
                let ignored = item.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("ignore") || attribute.path().is_ident("cfg_attr")
                });
                let attributes_supported = inherited_attributes
                    .iter()
                    .all(|attribute| passive_evidence_attribute(attribute))
                    && item.attrs.iter().all(|attribute| {
                        passive_evidence_attribute(attribute)
                            || attribute.path().is_ident("test")
                            || path_is(attribute.path(), &["tokio", "test"])
                            || builtin_test_attribute(attribute)
                    });
                let matrix_enabled = EVIDENCE_TARGETS.iter().any(|target| {
                    inherited_attributes
                        .iter()
                        .copied()
                        .chain(item.attrs.iter())
                        .all(|attribute| {
                            !attribute.path().is_ident("cfg_attr")
                                && cfg_attribute_allows(attribute, *target, declared_features)
                        })
                });
                matches.push((is_test, ignored, matrix_enabled, attributes_supported));
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    let inherited_len = inherited_attributes.len();
                    inherited_attributes.extend(item.attrs.iter());
                    collect_test_functions(
                        items,
                        function,
                        inherited_attributes,
                        matches,
                        declared_features,
                    );
                    inherited_attributes.truncate(inherited_len);
                }
            }
            _ => {}
        }
    }
}

fn validate_release_test_function(syntax: &syn::File, id: &str, function: &str) {
    let mut matches = Vec::new();
    collect_release_test_functions(&syntax.items, function, &mut matches);
    assert_eq!(
        matches,
        [true],
        "release evidence {id} must use exactly one synchronous #[::std::prelude::v1::test] function"
    );
}

fn collect_release_test_functions(items: &[syn::Item], function: &str, matches: &mut Vec<bool>) {
    for item in items {
        match item {
            syn::Item::Fn(item) if item.sig.ident == function => {
                matches.push(
                    item.sig.asyncness.is_none()
                        && item.attrs.iter().any(builtin_test_attribute)
                        && item.attrs.iter().all(|attribute| {
                            passive_evidence_attribute(attribute)
                                || builtin_test_attribute(attribute)
                        }),
                );
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    collect_release_test_functions(items, function, matches);
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy)]
struct EvidenceTarget {
    os: &'static str,
    family: &'static str,
    arch: &'static str,
    environment: &'static str,
    vendor: &'static str,
}

const EVIDENCE_TARGETS: [EvidenceTarget; 5] = [
    EvidenceTarget {
        os: "linux",
        family: "unix",
        arch: "x86_64",
        environment: "gnu",
        vendor: "unknown",
    },
    EvidenceTarget {
        os: "linux",
        family: "unix",
        arch: "aarch64",
        environment: "gnu",
        vendor: "unknown",
    },
    EvidenceTarget {
        os: "macos",
        family: "unix",
        arch: "x86_64",
        environment: "",
        vendor: "apple",
    },
    EvidenceTarget {
        os: "macos",
        family: "unix",
        arch: "aarch64",
        environment: "",
        vendor: "apple",
    },
    EvidenceTarget {
        os: "windows",
        family: "windows",
        arch: "x86_64",
        environment: "msvc",
        vendor: "pc",
    },
];

fn cfg_attribute_allows(
    attribute: &syn::Attribute,
    target: EvidenceTarget,
    declared_features: &BTreeSet<String>,
) -> bool {
    if !attribute.path().is_ident("cfg") {
        return true;
    }
    attribute
        .parse_args::<syn::Meta>()
        .ok()
        .and_then(|predicate| cfg_predicate_matches(&predicate, target, declared_features))
        .unwrap_or(false)
}

fn cfg_predicate_matches(
    predicate: &syn::Meta,
    target: EvidenceTarget,
    declared_features: &BTreeSet<String>,
) -> Option<bool> {
    match predicate {
        syn::Meta::Path(path) if path.is_ident("test") => Some(true),
        syn::Meta::Path(path) if path.is_ident("debug_assertions") => Some(false),
        syn::Meta::Path(path) if path.is_ident("unix") || path.is_ident("windows") => {
            Some(path.is_ident(target.family))
        }
        syn::Meta::Path(_) => None,
        syn::Meta::NameValue(value) => {
            let name = value.path.get_ident().map(ToString::to_string)?;
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(expected),
                ..
            }) = &value.value
            else {
                return None;
            };
            Some(match name.as_str() {
                "feature" => declared_features.contains(&expected.value()),
                "target_os" => expected.value() == target.os,
                "target_family" => expected.value() == target.family,
                "target_arch" => expected.value() == target.arch,
                "target_env" => expected.value() == target.environment,
                "target_vendor" => expected.value() == target.vendor,
                "target_pointer_width" => expected.value() == "64",
                "target_endian" => expected.value() == "little",
                "target_has_atomic" => {
                    matches!(expected.value().as_str(), "8" | "16" | "32" | "64" | "ptr")
                }
                _ => return None,
            })
        }
        syn::Meta::List(list) => {
            let predicates = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .ok();
            let predicates = predicates?;
            if list.path.is_ident("all") {
                combine_cfg_all(&predicates, target, declared_features)
            } else if list.path.is_ident("any") {
                combine_cfg_any(&predicates, target, declared_features)
            } else if list.path.is_ident("not") && predicates.len() == 1 {
                cfg_predicate_matches(&predicates[0], target, declared_features).map(|value| !value)
            } else {
                None
            }
        }
    }
}

fn combine_cfg_all(
    predicates: &syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>,
    target: EvidenceTarget,
    declared_features: &BTreeSet<String>,
) -> Option<bool> {
    let mut unknown = false;
    for predicate in predicates {
        match cfg_predicate_matches(predicate, target, declared_features) {
            Some(false) => return Some(false),
            Some(true) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(true)
}

fn combine_cfg_any(
    predicates: &syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>,
    target: EvidenceTarget,
    declared_features: &BTreeSet<String>,
) -> Option<bool> {
    let mut unknown = false;
    for predicate in predicates {
        match cfg_predicate_matches(predicate, target, declared_features) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(false)
}

fn path_is(path: &syn::Path, segments: &[&str]) -> bool {
    path.segments.len() == segments.len()
        && path
            .segments
            .iter()
            .zip(segments)
            .all(|(actual, expected)| actual.ident == *expected)
}

fn passive_evidence_attribute(attribute: &syn::Attribute) -> bool {
    ["cfg", "allow", "warn", "deny", "forbid", "doc"]
        .iter()
        .any(|name| attribute.path().is_ident(name))
}

fn builtin_test_attribute(attribute: &syn::Attribute) -> bool {
    attribute.path().leading_colon.is_some()
        && path_is(attribute.path(), &["std", "prelude", "v1", "test"])
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

fn validate_content_sources(
    label: &str,
    sources: &[UpstreamContentSource],
    expected_count: usize,
    expected_url_set_sha256: &str,
    expected_content_sha256: &str,
) -> BTreeSet<String> {
    assert_eq!(
        sources.len(),
        expected_count,
        "locked {label} content-source count does not match its aggregate count"
    );
    let urls = sources
        .iter()
        .map(|source| {
            assert!(
                source.url.starts_with("https://") && valid_sha256(&source.sha256),
                "locked {label} source has invalid provenance: {}",
                source.url
            );
            source.url.clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        urls.len(),
        sources.len(),
        "locked {label} content sources contain duplicate URLs"
    );
    let url_manifest = urls.iter().cloned().collect::<Vec<_>>().join("\n");
    assert_eq!(
        format!("{:x}", Sha256::digest(url_manifest.as_bytes())),
        expected_url_set_sha256,
        "locked {label} URL-set hash does not match its per-URL entries"
    );
    let by_url = sources
        .iter()
        .map(|source| (source.url.as_str(), source.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut content_manifest = String::new();
    for (url, sha256) in by_url {
        content_manifest.push_str(url);
        content_manifest.push('\t');
        content_manifest.push_str(sha256);
        content_manifest.push('\n');
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(content_manifest.as_bytes())),
        expected_content_sha256,
        "locked {label} aggregate content hash does not match its per-URL entries"
    );
    urls
}

fn validate_url_set(label: &str, urls: &[String], expected_count: usize, expected_sha256: &str) {
    let unique = urls.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        urls.len(),
        expected_count,
        "locked {label} count does not match its aggregate count"
    );
    assert_eq!(
        unique.len(),
        urls.len(),
        "locked {label} contains duplicate URLs"
    );
    assert!(
        unique.iter().all(|url| url == "https://docs.reltio.com/en"
            || url.starts_with("https://docs.reltio.com/en/")),
        "locked {label} contains a noncanonical documentation URL"
    );
    let manifest = unique.into_iter().collect::<Vec<_>>().join("\n");
    assert_eq!(
        format!("{:x}", Sha256::digest(manifest.as_bytes())),
        expected_sha256,
        "locked {label} hash does not match its per-URL entries"
    );
}

fn validate_release_cargo_targets(repository_root: &Path) {
    let client_manifest_path = repository_root.join("crates/reltio-client/Cargo.toml");
    let client_manifest =
        fs::read_to_string(&client_manifest_path).expect("read reltio-client manifest");
    validate_standard_library_dependencies(&client_manifest, &client_manifest_path);
    let client: CargoManifest =
        toml::from_str(&client_manifest).expect("parse reltio-client manifest");
    assert_eq!(client.package.name, "reltio-client");
    assert_eq!(
        client.package.build.as_deref(),
        Some("build.rs"),
        "reltio-client must execute the reviewed release validator"
    );
    let client_features = default_feature_set(&client.features);
    if let Some(target) = &client.lib {
        assert_eq!(target.path.as_deref().unwrap_or("src/lib.rs"), "src/lib.rs");
        assert!(target.test.unwrap_or(true));
        assert!(target.harness.unwrap_or(true));
        assert!(
            target
                .required_features
                .iter()
                .all(|feature| client_features.contains(feature))
        );
    } else {
        assert!(client.package.autolib.unwrap_or(true));
        assert!(
            repository_root
                .join("crates/reltio-client/src/lib.rs")
                .is_file()
        );
    }

    let cli_manifest_path = repository_root.join("crates/reltio-cli/Cargo.toml");
    let cli_manifest = fs::read_to_string(&cli_manifest_path).expect("read reltio-cli manifest");
    validate_standard_library_dependencies(&cli_manifest, &cli_manifest_path);
    let cli: CargoManifest = toml::from_str(&cli_manifest).expect("parse reltio-cli manifest");
    assert_eq!(cli.package.name, "reltio-cli");
    let cli_features = default_feature_set(&cli.features);
    let release_bins = cli
        .bins
        .iter()
        .filter(|target| target.name.as_deref() == Some("reltio"))
        .collect::<Vec<_>>();
    assert_eq!(release_bins.len(), 1, "release CLI target must be unique");
    let release_bin = release_bins[0];
    assert_eq!(
        release_bin.path.as_deref().unwrap_or("src/main.rs"),
        "src/main.rs"
    );
    assert!(release_bin.test.unwrap_or(true));
    assert!(release_bin.harness.unwrap_or(true));
    assert!(
        release_bin
            .required_features
            .iter()
            .all(|feature| cli_features.contains(feature))
    );
    let integration_targets = cli
        .tests
        .iter()
        .filter(|target| target.name.as_deref() == Some("cli"))
        .collect::<Vec<_>>();
    if integration_targets.is_empty() {
        assert!(cli.package.autotests.unwrap_or(true));
        assert!(
            repository_root
                .join("crates/reltio-cli/tests/cli.rs")
                .is_file()
        );
    } else {
        assert_eq!(
            integration_targets.len(),
            1,
            "release integration target must be unique"
        );
        let target = integration_targets[0];
        assert_eq!(
            target.path.as_deref().unwrap_or("tests/cli.rs"),
            "tests/cli.rs"
        );
        assert!(target.test.unwrap_or(true));
        assert!(target.harness.unwrap_or(true));
        assert!(
            target
                .required_features
                .iter()
                .all(|feature| cli_features.contains(feature))
        );
    }
}

fn validate_standard_library_dependencies(source: &str, manifest_path: &Path) {
    let manifest: toml::Value = toml::from_str(source).expect("parse release Cargo manifest");
    validate_standard_library_target_name(&manifest, manifest_path);
    validate_standard_library_dependency_table(&manifest, manifest_path);
}

fn validate_repository_cargo_manifests(repository_root: &Path) {
    let mut directories = vec![
        repository_root
            .canonicalize()
            .expect("repository root must be canonicalizable"),
    ];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).expect("repository directory must be readable") {
            let entry = entry.expect("repository entry must be readable");
            let file_type = entry.file_type().expect("repository entry type");
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                let name = entry.file_name();
                if name != ".git" && name != "target" {
                    directories.push(path);
                }
            } else if file_type.is_file() && entry.file_name() == "Cargo.toml" {
                println!("cargo:rerun-if-changed={}", path.display());
                let source = fs::read_to_string(&path).expect("repository Cargo manifest");
                validate_standard_library_dependencies(&source, &path);
            }
        }
    }
}

fn validate_standard_library_target_name(manifest: &toml::Value, manifest_path: &Path) {
    let package_name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(|name| name.replace('-', "_"));
    let library_name = manifest
        .get("lib")
        .and_then(|target| target.get("name"))
        .and_then(toml::Value::as_str);
    assert!(
        !package_name
            .as_deref()
            .is_some_and(|name| name == "core" || name == "std")
            && !library_name.is_some_and(|name| name == "core" || name == "std"),
        "{} defines a standard-library crate name",
        manifest_path.display()
    );
}

fn validate_standard_library_dependency_table(value: &toml::Value, manifest_path: &Path) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (name, child) in table {
        if ["dependencies", "dev-dependencies", "build-dependencies"].contains(&name.as_str()) {
            if let Some(dependencies) = child.as_table() {
                assert!(
                    !dependencies.contains_key("core") && !dependencies.contains_key("std"),
                    "{} aliases a standard-library crate through {name}",
                    manifest_path.display()
                );
            }
        }
        validate_standard_library_dependency_table(child, manifest_path);
    }
}

fn validate_release_source_module(
    repository_root: &Path,
    evidence_path: &str,
    enabled_features: &BTreeSet<String>,
) {
    let module_path = source_module_prefix(evidence_path);
    let target_root = if evidence_path.starts_with("crates/reltio-client/src/") {
        repository_root.join("crates/reltio-client/src/lib.rs")
    } else if evidence_path.starts_with("crates/reltio-cli/src/") {
        repository_root.join("crates/reltio-cli/src/main.rs")
    } else if evidence_path == "crates/reltio-cli/tests/cli.rs" {
        repository_root.join(evidence_path)
    } else {
        panic!("release evidence path {evidence_path} has no validated Cargo target");
    };
    let expected_source = repository_root.join(evidence_path);
    let canonical_target = target_root
        .canonicalize()
        .unwrap_or_else(|error| panic!("release target root is unreadable: {error}"));
    assert_eq!(
        canonical_target, target_root,
        "release target root uses a symlink or noncanonical path"
    );
    println!("cargo:rerun-if-changed={}", target_root.display());
    let syntax = syn::parse_file(
        &fs::read_to_string(&target_root).expect("release target root must be readable"),
    )
    .expect("release target root must parse");
    let resolved = resolve_module_source(
        &target_root,
        &syntax.items,
        target_root.parent().expect("release target parent"),
        &module_path,
        &EVIDENCE_TARGETS,
        enabled_features,
    );
    assert_eq!(
        resolved, expected_source,
        "release evidence {evidence_path} is not loaded at its claimed Cargo module path"
    );
}

fn resolve_module_source(
    current_source: &Path,
    items: &[syn::Item],
    module_directory: &Path,
    remaining_modules: &[String],
    active_targets: &[EvidenceTarget],
    enabled_features: &BTreeSet<String>,
) -> PathBuf {
    validate_standard_library_source_aliases(items, current_source);
    let Some((module, remaining_modules)) = remaining_modules.split_first() else {
        return current_source.to_path_buf();
    };
    let declarations = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(item) if item.ident == module => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        declarations.len(),
        1,
        "release module path {} has no unique declaration in {}",
        module,
        current_source.display()
    );
    let declaration = declarations[0];
    assert!(
        declaration.attrs.iter().all(passive_evidence_attribute),
        "release module {module} uses an expansion-capable attribute"
    );
    let enabled_targets = active_targets
        .iter()
        .copied()
        .filter(|target| {
            declaration
                .attrs
                .iter()
                .all(|attribute| cfg_attribute_allows(attribute, *target, enabled_features))
        })
        .collect::<Vec<_>>();
    assert!(
        !enabled_targets.is_empty(),
        "release module {module} is disabled on the shipped release matrix"
    );
    let next_module_directory = module_directory.join(module);
    if let Some((_, inline_items)) = &declaration.content {
        return resolve_module_source(
            current_source,
            inline_items,
            &next_module_directory,
            remaining_modules,
            &enabled_targets,
            enabled_features,
        );
    }

    let flat_source = module_directory.join(format!("{module}.rs"));
    let directory_source = next_module_directory.join("mod.rs");
    let candidates = [flat_source, directory_source]
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    assert_eq!(
        candidates.len(),
        1,
        "release module {module} has no unique conventional source"
    );
    let next_source = candidates[0].clone();
    assert_eq!(
        next_source
            .canonicalize()
            .expect("release module source must be canonicalizable"),
        next_source,
        "release module {module} uses a symlink or noncanonical source"
    );
    println!("cargo:rerun-if-changed={}", next_source.display());
    let syntax = syn::parse_file(
        &fs::read_to_string(&next_source).expect("release module source must be readable"),
    )
    .expect("release module source must parse");
    resolve_module_source(
        &next_source,
        &syntax.items,
        &next_module_directory,
        remaining_modules,
        &enabled_targets,
        enabled_features,
    )
}

fn validate_standard_library_source_aliases(items: &[syn::Item], source: &Path) {
    for item in items {
        match item {
            syn::Item::ExternCrate(item) => {
                let bound_name = item
                    .rename
                    .as_ref()
                    .map_or(&item.ident, |(_, rename)| rename)
                    .unraw();
                assert!(
                    bound_name != "core" && bound_name != "std",
                    "release source {} aliases a standard-library crate",
                    source.display()
                );
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    validate_standard_library_source_aliases(items, source);
                }
            }
            _ => {}
        }
    }
}

fn source_module_prefix(path: &str) -> Vec<String> {
    let components = Path::new(path)
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_string_lossy().into_owned(),
            _ => panic!("release evidence path {path} has unsupported components"),
        })
        .collect::<Vec<_>>();
    assert!(
        components.len() >= 4 && components[0] == "crates",
        "release evidence path {path} is not a Cargo source target"
    );
    match components[2].as_str() {
        "src" => {
            let mut prefix = components[3..components.len() - 1].to_vec();
            let stem = Path::new(components.last().expect("source filename"))
                .file_stem()
                .expect("source file stem")
                .to_string_lossy();
            if stem != "lib" && stem != "main" && stem != "mod" {
                prefix.push(stem.into_owned());
            }
            prefix
        }
        "tests" => {
            assert_eq!(
                components.len(),
                4,
                "release integration evidence path {path} requires an explicit verifier"
            );
            Vec::new()
        }
        _ => panic!("release evidence path {path} is not in a verified Cargo target"),
    }
}

fn cargo_harness_name(path: &str, function: &str, syntax: &syn::File) -> String {
    let mut prefix = source_module_prefix(path);

    let mut matches = Vec::new();
    collect_inline_function_paths(&syntax.items, function, &mut Vec::new(), &mut matches);
    assert_eq!(
        matches.len(),
        1,
        "release evidence function {function} in {path} has no unique module path"
    );
    prefix.extend(matches.pop().expect("one function path"));
    prefix.push(function.to_owned());
    prefix.join("::")
}

fn collect_inline_function_paths(
    items: &[syn::Item],
    function: &str,
    modules: &mut Vec<String>,
    matches: &mut Vec<Vec<String>>,
) {
    for item in items {
        match item {
            syn::Item::Fn(item) if item.sig.ident == function => matches.push(modules.clone()),
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    modules.push(item.ident.to_string());
                    collect_inline_function_paths(items, function, modules, matches);
                    modules.pop();
                }
            }
            _ => {}
        }
    }
}

fn evidence_matches(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual.iter().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
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

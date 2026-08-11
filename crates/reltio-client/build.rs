use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use chrono::{NaiveDate, Utc};
use serde::Deserialize;

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
struct EndpointDocument {
    schema_version: u32,
    endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
struct Endpoint {
    id: String,
    service: String,
    method: String,
    path_pattern: String,
    commands: Vec<String>,
    practice_ids: Vec<String>,
    test_ids: Vec<String>,
    verified_at: String,
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
struct UpstreamLock {
    schema_version: u32,
    corpus: UpstreamCorpus,
    deprecations: UpstreamDeprecations,
    release_notes: UpstreamReleaseNotes,
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

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let practices_path = manifest.join("../../docs/reltio-api-practices.yaml");
    let endpoints_path = manifest.join("../../docs/endpoints.yaml");
    let evidence_path = manifest.join("../../docs/test-evidence.yaml");
    let upstream_path = manifest.join("../../docs/upstream.lock.yaml");
    let repository_root = manifest.join("../..");

    println!("cargo:rerun-if-changed={}", practices_path.display());
    println!("cargo:rerun-if-changed={}", endpoints_path.display());
    println!("cargo:rerun-if-changed={}", evidence_path.display());
    println!("cargo:rerun-if-changed={}", upstream_path.display());

    let practices: PracticeDocument = parse_yaml(&practices_path);
    let endpoints: EndpointDocument = parse_yaml(&endpoints_path);
    let evidence: EvidenceDocument = parse_yaml(&evidence_path);
    let upstream: UpstreamLock = parse_yaml(&upstream_path);
    assert_eq!(practices.schema_version, 1, "unsupported practice schema");
    assert_eq!(endpoints.schema_version, 1, "unsupported endpoint schema");
    assert_eq!(
        evidence.schema_version, 1,
        "unsupported test-evidence schema"
    );
    assert_eq!(
        upstream.schema_version, 1,
        "unsupported upstream-lock schema"
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
            endpoint.path_pattern.starts_with('/'),
            "endpoint {} path must be absolute within its service",
            endpoint.id
        );
        assert!(
            !endpoint.commands.is_empty(),
            "endpoint {} has no commands",
            endpoint.id
        );
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
            if practice.service == "any" || practice.service == endpoint.service {
                assert!(
                    practice.matches(&endpoint.method, &endpoint.path_pattern),
                    "endpoint {} links inapplicable practice {}",
                    endpoint.id,
                    practice.id
                );
            }
            for command in &endpoint.commands {
                assert!(
                    practice.commands.contains(command),
                    "practice {} omits endpoint command {} for {}",
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
                    && !actual.starts_with('_'))
                    || *expected == actual
            })
}

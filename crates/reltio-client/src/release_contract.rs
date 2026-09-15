pub const V0_1_REQUIRED_OPERATIONS: [&str; 50] = [
    "profile.list",
    "profile.show",
    "profile.add",
    "profile.update",
    "profile.use",
    "profile.remove",
    "auth.login",
    "auth.status",
    "auth.check",
    "auth.token",
    "auth.logout",
    "entity.get",
    "entity.get-many",
    "entity.by-crosswalk",
    "entity.search",
    "entity.scan",
    "entity.create",
    "entity.upsert",
    "entity.update",
    "entity.delete",
    "entity.history",
    "entity.matches",
    "relation.get",
    "relation.search",
    "relation.scan",
    "relation.create",
    "relation.update",
    "relation.delete",
    "config.get",
    "config.pull",
    "config.validate",
    "config.diff",
    "config.apply",
    "config.backup",
    "task.get",
    "task.list",
    "task.wait",
    "task.cancel",
    "api.request",
    "api.practices.list",
    "api.practices.show",
    "api.practices.check",
    "skills.list",
    "skills.get",
    "skills.path",
    "agent.guide",
    "command.schema",
    "completion.generate",
    "completion.install",
    "doctor",
];

pub const V0_1_REQUIRED_CAPABILITIES: [&str; 1] = ["auth.provider.authorization-code"];

// Operations remain incomplete until exact implementation evidence is approved here.
pub const V0_1_OPERATION_EVIDENCE: [(&str, &[&str]); 0] = [];

pub const V0_1_INVENTORY_TEST_IDS: [&str; 12] = [
    "release_prd_inventory",
    "release_endpoint_role_ownership",
    "release_inventory_substitution_guard",
    "release_safety_binding_downgrade_guard",
    "release_unknown_field_guard",
    "release_audit_evidence_separation",
    "release_evidence_substitution_guard",
    "release_version_binding",
    "release_cli_gate",
    "release_client_harness_discovery",
    "release_cli_unit_harness_discovery",
    "release_cli_integration_harness_discovery",
];

// Consumed by build.rs through its independent inclusion of this module.
#[allow(dead_code)]
pub const V0_1_RELEASE_EVIDENCE_BINDINGS: [(&str, &str, &str, &str); 14] = [
    (
        "mutation_audit_absence_fails_closed",
        "crates/reltio-cli/tests/cli.rs",
        "mutation_audit_absence_fails_closed_before_network_io",
        "mutation_audit_absence_fails_closed_before_network_io",
    ),
    (
        "mutation_method_safety_fail_closed",
        "crates/reltio-cli/src/commands/api.rs",
        "registered_safety_overrides_http_method_defaults_fail_closed",
        "commands::api::tests::registered_safety_overrides_http_method_defaults_fail_closed",
    ),
    (
        "release_prd_inventory",
        "crates/reltio-cli/src/release.rs",
        "release_readiness_reports_the_independent_prd_inventory",
        "release::tests::release_readiness_reports_the_independent_prd_inventory",
    ),
    (
        "release_endpoint_role_ownership",
        "crates/reltio-cli/src/release.rs",
        "endpoint_roles_do_not_count_dependencies_as_typed_ownership",
        "release::tests::endpoint_roles_do_not_count_dependencies_as_typed_ownership",
    ),
    (
        "release_inventory_substitution_guard",
        "crates/reltio-client/src/registry.rs",
        "release_inventory_rejects_substituted_required_operation",
        "registry::tests::release_inventory_rejects_substituted_required_operation",
    ),
    (
        "release_safety_binding_downgrade_guard",
        "crates/reltio-client/src/registry.rs",
        "release_inventory_rejects_safety_and_endpoint_downgrades",
        "registry::tests::release_inventory_rejects_safety_and_endpoint_downgrades",
    ),
    (
        "release_unknown_field_guard",
        "crates/reltio-client/src/registry.rs",
        "release_requirement_yaml_rejects_unknown_fields",
        "registry::tests::release_requirement_yaml_rejects_unknown_fields",
    ),
    (
        "release_audit_evidence_separation",
        "crates/reltio-client/src/registry.rs",
        "mutation_audit_guard_evidence_cannot_claim_implementation",
        "registry::tests::mutation_audit_guard_evidence_cannot_claim_implementation",
    ),
    (
        "release_evidence_substitution_guard",
        "crates/reltio-client/src/registry.rs",
        "release_requirements_reject_unapproved_evidence_substitution",
        "registry::tests::release_requirements_reject_unapproved_evidence_substitution",
    ),
    (
        "release_version_binding",
        "crates/reltio-cli/src/commands/api.rs",
        "release_version_binding_requires_one_stable_exact_version",
        "commands::api::tests::release_version_binding_requires_one_stable_exact_version",
    ),
    (
        "release_cli_gate",
        "crates/reltio-cli/tests/cli.rs",
        "release_gate_reports_prd_blockers_and_refuses_stable_readiness",
        "release_gate_reports_prd_blockers_and_refuses_stable_readiness",
    ),
    (
        "release_client_harness_discovery",
        "crates/reltio-client/src/registry.rs",
        "release_evidence_functions_are_discoverable_in_client_unit_harness",
        "registry::tests::release_evidence_functions_are_discoverable_in_client_unit_harness",
    ),
    (
        "release_cli_unit_harness_discovery",
        "crates/reltio-cli/src/release.rs",
        "release_evidence_functions_are_discoverable_in_cli_unit_harness",
        "release::tests::release_evidence_functions_are_discoverable_in_cli_unit_harness",
    ),
    (
        "release_cli_integration_harness_discovery",
        "crates/reltio-cli/tests/cli.rs",
        "release_evidence_functions_are_discoverable_in_cli_integration_harness",
        "release_evidence_functions_are_discoverable_in_cli_integration_harness",
    ),
];

pub fn evidence_claim_bindings_are_disjoint(
    inventory_ids: &[&str],
    guard_ids: &[&str],
    implementation_ids: &[&str],
    bindings: &[(&str, &str, &str, &str)],
) -> bool {
    let inventory_ids = inventory_ids.iter().copied().collect::<BTreeSet<_>>();
    let guard_ids = guard_ids.iter().copied().collect::<BTreeSet<_>>();
    let implementation_ids = implementation_ids.iter().copied().collect::<BTreeSet<_>>();
    let inventory_bindings = bindings
        .iter()
        .filter(|(id, _, _, _)| inventory_ids.contains(id))
        .map(|(_, path, function, _)| (*path, *function))
        .collect::<BTreeSet<_>>();
    let guard_bindings = bindings
        .iter()
        .filter(|(id, _, _, _)| guard_ids.contains(id))
        .map(|(_, path, function, _)| (*path, *function))
        .collect::<BTreeSet<_>>();
    let inventory_harnesses = bindings
        .iter()
        .filter(|(id, _, _, _)| inventory_ids.contains(id))
        .map(|(_, _, _, harness)| *harness)
        .collect::<BTreeSet<_>>();
    let implementation_bindings = bindings
        .iter()
        .filter(|(id, _, _, _)| implementation_ids.contains(id))
        .map(|(_, path, function, _)| (*path, *function))
        .collect::<BTreeSet<_>>();
    let guard_harnesses = bindings
        .iter()
        .filter(|(id, _, _, _)| guard_ids.contains(id))
        .map(|(_, _, _, harness)| *harness)
        .collect::<BTreeSet<_>>();
    let implementation_harnesses = bindings
        .iter()
        .filter(|(id, _, _, _)| implementation_ids.contains(id))
        .map(|(_, _, _, harness)| *harness)
        .collect::<BTreeSet<_>>();
    inventory_ids.is_disjoint(&guard_ids)
        && inventory_ids.is_disjoint(&implementation_ids)
        && guard_ids.is_disjoint(&implementation_ids)
        && inventory_bindings.is_disjoint(&guard_bindings)
        && inventory_bindings.is_disjoint(&implementation_bindings)
        && guard_bindings.is_disjoint(&implementation_bindings)
        && inventory_harnesses.is_disjoint(&guard_harnesses)
        && inventory_harnesses.is_disjoint(&implementation_harnesses)
        && guard_harnesses.is_disjoint(&implementation_harnesses)
}

pub const V0_1_CAPABILITY_EVIDENCE: [(&str, &[&str]); 1] =
    [("auth.provider.authorization-code", &[])];

pub const V0_1_OPERATION_SAFETY: [(&str, &str); 50] = [
    ("profile.list", "read"),
    ("profile.show", "read"),
    ("profile.add", "local_write"),
    ("profile.update", "local_write"),
    ("profile.use", "local_write"),
    ("profile.remove", "local_write"),
    ("auth.login", "authentication"),
    ("auth.status", "read"),
    ("auth.check", "read"),
    ("auth.token", "secret_disclosure"),
    ("auth.logout", "local_write"),
    ("entity.get", "read"),
    ("entity.get-many", "read"),
    ("entity.by-crosswalk", "read"),
    ("entity.search", "read"),
    ("entity.scan", "read"),
    ("entity.create", "remote_write"),
    ("entity.upsert", "remote_write"),
    ("entity.update", "remote_write"),
    ("entity.delete", "remote_high_impact"),
    ("entity.history", "read"),
    ("entity.matches", "read"),
    ("relation.get", "read"),
    ("relation.search", "read"),
    ("relation.scan", "read"),
    ("relation.create", "remote_write"),
    ("relation.update", "remote_write"),
    ("relation.delete", "remote_high_impact"),
    ("config.get", "read"),
    ("config.pull", "read"),
    ("config.validate", "read"),
    ("config.diff", "read"),
    ("config.apply", "remote_high_impact"),
    ("config.backup", "read"),
    ("task.get", "read"),
    ("task.list", "read"),
    ("task.wait", "read"),
    ("task.cancel", "remote_high_impact"),
    ("api.request", "dynamic"),
    ("api.practices.list", "read"),
    ("api.practices.show", "read"),
    ("api.practices.check", "read"),
    ("skills.list", "read"),
    ("skills.get", "read"),
    ("skills.path", "read"),
    ("agent.guide", "read"),
    ("command.schema", "read"),
    ("completion.generate", "read"),
    ("completion.install", "local_write"),
    ("doctor", "read"),
];

pub const V0_1_WRITE_OPERATIONS: [&str; 5] = [
    "entity.create",
    "entity.upsert",
    "entity.update",
    "relation.create",
    "relation.update",
];

pub const V0_1_DYNAMIC_MUTATION_ADAPTERS: [&str; 1] = ["api.request"];

pub const V0_1_HIGH_IMPACT_OPERATIONS: [&str; 4] = [
    "entity.delete",
    "relation.delete",
    "config.apply",
    "task.cancel",
];

pub const V0_1_ENDPOINT_REQUIREMENTS: [(&str, &str); 31] = [
    ("auth.login", "typed_primary"),
    ("auth.check", "workflow_component"),
    ("auth.token", "auth_dependency"),
    ("entity.get", "typed_primary"),
    ("entity.get-many", "typed_primary"),
    ("entity.by-crosswalk", "typed_primary"),
    ("entity.search", "typed_primary"),
    ("entity.scan", "typed_primary"),
    ("entity.create", "typed_primary"),
    ("entity.upsert", "typed_primary"),
    ("entity.update", "typed_primary"),
    ("entity.delete", "typed_primary"),
    ("entity.history", "typed_primary"),
    ("entity.matches", "typed_primary"),
    ("relation.get", "typed_primary"),
    ("relation.search", "typed_primary"),
    ("relation.scan", "typed_primary"),
    ("relation.create", "typed_primary"),
    ("relation.update", "typed_primary"),
    ("relation.delete", "typed_primary"),
    ("config.get", "typed_primary"),
    ("config.pull", "typed_primary"),
    ("config.validate", "typed_primary"),
    ("config.diff", "typed_primary"),
    ("config.apply", "typed_primary"),
    ("config.backup", "typed_primary"),
    ("task.get", "typed_primary"),
    ("task.list", "typed_primary"),
    ("task.wait", "typed_primary"),
    ("task.cancel", "typed_primary"),
    ("doctor", "healthcheck_dependency"),
];

pub const REVIEWED_ENDPOINT_BINDINGS: [(&str, &str); 10] = [
    ("auth.login", "auth.client_credentials"),
    ("auth.check", "entity.search"),
    ("auth.token", "auth.client_credentials"),
    ("entity.get", "entity.get"),
    ("entity.by-crosswalk", "entity.by-crosswalk"),
    ("entity.search", "entity.search"),
    ("entity.scan", "entity.scan"),
    ("entity.history", "entity.history"),
    ("entity.matches", "entity.matches"),
    ("doctor", "entity.search"),
];

pub const MVP_ACCEPTANCE_SCENARIOS: [&str; 19] = [
    "MVP-ACCEPT-001",
    "MVP-ACCEPT-002",
    "MVP-ACCEPT-003",
    "MVP-ACCEPT-004",
    "MVP-ACCEPT-005",
    "MVP-ACCEPT-006",
    "MVP-ACCEPT-007",
    "MVP-ACCEPT-008",
    "MVP-ACCEPT-009",
    "MVP-ACCEPT-010",
    "MVP-ACCEPT-011",
    "MVP-ACCEPT-012",
    "MVP-ACCEPT-013",
    "MVP-ACCEPT-014",
    "MVP-ACCEPT-015",
    "MVP-ACCEPT-016",
    "MVP-ACCEPT-017",
    "MVP-ACCEPT-018",
    "MVP-ACCEPT-019",
];

pub const MVP_ACCEPTANCE_EVIDENCE: [(&str, &[&str]); 19] = [
    ("MVP-ACCEPT-001", &[]),
    ("MVP-ACCEPT-002", &[]),
    ("MVP-ACCEPT-003", &[]),
    ("MVP-ACCEPT-004", &[]),
    ("MVP-ACCEPT-005", &[]),
    ("MVP-ACCEPT-006", &[]),
    ("MVP-ACCEPT-007", &[]),
    ("MVP-ACCEPT-008", &[]),
    ("MVP-ACCEPT-009", &[]),
    ("MVP-ACCEPT-010", &[]),
    ("MVP-ACCEPT-011", &[]),
    ("MVP-ACCEPT-012", &[]),
    ("MVP-ACCEPT-013", &[]),
    ("MVP-ACCEPT-014", &[]),
    ("MVP-ACCEPT-015", &[]),
    ("MVP-ACCEPT-016", &[]),
    ("MVP-ACCEPT-017", &[]),
    ("MVP-ACCEPT-018", &[]),
    ("MVP-ACCEPT-019", &[]),
];

pub const MUTATION_AUDIT_FIELDS: [&str; 16] = [
    "operation_id",
    "request_ids",
    "command",
    "cli_version",
    "profile",
    "environment",
    "tenant",
    "service",
    "principal",
    "input_sha256",
    "affected_resources",
    "started_at",
    "ended_at",
    "result",
    "backup_reference",
    "task_reference",
];

pub const MUTATION_AUDIT_RESULTS: [&str; 7] = [
    "not_sent",
    "failed",
    "partial",
    "accepted",
    "succeeded",
    "canceled",
    "completion_unknown",
];

pub const MUTATION_AUDIT_GUARD_EVIDENCE: [&str; 2] = [
    "mutation_audit_absence_fails_closed",
    "mutation_method_safety_fail_closed",
];

pub const MUTATION_AUDIT_FIELD_EVIDENCE: [(&str, &[&str]); 16] = [
    ("operation_id", &[]),
    ("request_ids", &[]),
    ("command", &[]),
    ("cli_version", &[]),
    ("profile", &[]),
    ("environment", &[]),
    ("tenant", &[]),
    ("service", &[]),
    ("principal", &[]),
    ("input_sha256", &[]),
    ("affected_resources", &[]),
    ("started_at", &[]),
    ("ended_at", &[]),
    ("result", &[]),
    ("backup_reference", &[]),
    ("task_reference", &[]),
];

pub const MUTATION_AUDIT_RESULT_EVIDENCE: [(&str, &[&str]); 7] = [
    ("not_sent", &[]),
    ("failed", &[]),
    ("partial", &[]),
    ("accepted", &[]),
    ("succeeded", &[]),
    ("canceled", &[]),
    ("completion_unknown", &[]),
];
use std::collections::BTreeSet;

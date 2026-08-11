use reltio_client::registry::Registry;

pub const MUTATION_AUDIT_CONTRACT_ID: &str = "mutation_audit_v1";

// Set only when mutation execution constructs schema-v1 audit results on every outcome path.
const MUTATION_AUDIT_RUNTIME_SCHEMA_VERSION: Option<u32> = None;

pub fn mutation_audit_available(registry: &Registry) -> bool {
    MUTATION_AUDIT_RUNTIME_SCHEMA_VERSION == Some(1)
        && registry
            .requirements()
            .contracts
            .iter()
            .find(|contract| contract.id == MUTATION_AUDIT_CONTRACT_ID)
            .is_some_and(reltio_client::registry::ReleaseContract::implementation_evidence_complete)
}

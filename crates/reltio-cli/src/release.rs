use std::collections::{BTreeMap, BTreeSet};

use reltio_client::config::AuthMethod;
use reltio_client::error::Result;
use reltio_client::registry::Registry;
use serde_json::{Value, json};

use crate::audit;
use crate::metadata;

pub fn readiness(registry: &Registry) -> Result<Value> {
    let requirements = registry.requirements();
    let commands = metadata::all()
        .iter()
        .map(|entry| entry.name)
        .collect::<BTreeSet<_>>();
    let contracts = requirements
        .contracts
        .iter()
        .map(|contract| (contract.id.as_str(), contract))
        .collect::<BTreeMap<_, _>>();
    let mut blockers = Vec::new();
    let mut command_present_count = 0usize;
    let mut operation_complete_count = 0usize;

    let operations = requirements
        .operations
        .iter()
        .map(|operation| {
            let command_present = commands.contains(operation.command.as_str());
            command_present_count += usize::from(command_present);
            let endpoint_binding_defined = operation.required_endpoint_role.is_none()
                || !operation.required_endpoint_ids.is_empty();
            let endpoint_role_satisfied = operation.required_endpoint_role.is_none_or(|role| {
                endpoint_binding_defined
                    && operation.required_endpoint_ids.iter().all(|endpoint_id| {
                        registry.endpoint(endpoint_id).is_some_and(|endpoint| {
                            endpoint.has_command_role(&operation.command, role)
                        })
                    })
            });
            let incomplete_contracts = operation
                .contract_ids
                .iter()
                .filter(|id| {
                    contracts
                        .get(id.as_str())
                        .is_none_or(|contract| !contract_implemented(registry, contract))
                })
                .cloned()
                .collect::<Vec<_>>();
            let implementation_evidence_complete = !operation.implementation_test_ids.is_empty();
            let complete = command_present
                && endpoint_role_satisfied
                && implementation_evidence_complete
                && incomplete_contracts.is_empty();
            operation_complete_count += usize::from(complete);

            let mut reasons = Vec::new();
            if !command_present {
                reasons.push(json!({"code": "missing_command_leaf"}));
            }
            if !endpoint_role_satisfied {
                if !endpoint_binding_defined {
                    reasons.push(json!({"code": "missing_endpoint_binding_definition"}));
                }
                reasons.push(json!({
                    "code": "missing_endpoint_role",
                    "role": operation.required_endpoint_role,
                    "endpoint_ids": operation.required_endpoint_ids
                }));
            }
            for contract_id in &incomplete_contracts {
                reasons.push(json!({
                    "code": "acceptance_contract_unimplemented",
                    "contract_id": contract_id
                }));
            }
            if !implementation_evidence_complete {
                reasons.push(json!({"code": "missing_implementation_evidence"}));
            }
            if !complete {
                blockers.push(json!({
                    "type": "operation",
                    "id": operation.id,
                    "command": operation.command,
                    "reasons": reasons
                }));
            }

            json!({
                "id": operation.id,
                "command": operation.command,
                "kind": operation.kind,
                "safety": operation.safety,
                "source_section": operation.source_section,
                "command_present": command_present,
                "required_endpoint_role": operation.required_endpoint_role,
                "required_endpoint_ids": operation.required_endpoint_ids,
                "endpoint_binding_defined": endpoint_binding_defined,
                "endpoint_role_satisfied": endpoint_role_satisfied,
                "contract_ids": operation.contract_ids,
                "incomplete_contracts": incomplete_contracts,
                "implementation_test_ids": operation.implementation_test_ids,
                "implementation_evidence_complete": implementation_evidence_complete,
                "complete": complete
            })
        })
        .collect::<Vec<_>>();

    let capabilities = requirements
        .capabilities
        .iter()
        .map(|capability| {
            let advertised = if commands.contains(capability.command.as_str()) {
                capability_supported(
                    &capability.command,
                    &capability.argument,
                    &capability.required_value,
                )?
            } else {
                false
            };
            let supported = advertised && !capability.implementation_test_ids.is_empty();
            if !supported {
                let mut reasons = Vec::new();
                if !advertised {
                    reasons.push(json!({
                        "code": "missing_command_argument_value",
                        "argument": capability.argument,
                        "required_value": capability.required_value
                    }));
                }
                if capability.implementation_test_ids.is_empty() {
                    reasons.push(json!({"code": "missing_implementation_evidence"}));
                }
                blockers.push(json!({
                    "type": "capability",
                    "id": capability.id,
                    "command": capability.command,
                    "reasons": reasons
                }));
            }
            Ok(json!({
                "id": capability.id,
                "command": capability.command,
                "argument": capability.argument,
                "required_value": capability.required_value,
                "source_section": capability.source_section,
                "advertised": advertised,
                "implementation_test_ids": capability.implementation_test_ids,
                "supported": supported
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    let acceptance_scenarios = requirements
        .acceptance_scenarios
        .iter()
        .map(|scenario| {
            let demonstrated = !scenario.implementation_test_ids.is_empty();
            if !demonstrated {
                blockers.push(json!({
                    "type": "acceptance_scenario",
                    "id": scenario.id,
                    "reasons": [{"code": "missing_implementation_evidence"}]
                }));
            }
            json!({
                "id": scenario.id,
                "summary": scenario.summary,
                "source_section": scenario.source_section,
                "implementation_test_ids": scenario.implementation_test_ids,
                "demonstrated": demonstrated
            })
        })
        .collect::<Vec<_>>();

    let contract_status = requirements
        .contracts
        .iter()
        .map(|contract| {
            let evidence_complete = contract.implementation_evidence_complete();
            let runtime_supported = contract.id != audit::MUTATION_AUDIT_CONTRACT_ID
                || audit::mutation_audit_available(registry);
            let implemented = evidence_complete && runtime_supported;
            if !implemented {
                let mut reasons = Vec::new();
                if !evidence_complete {
                    reasons.push(json!({"code": "missing_field_or_result_evidence"}));
                }
                if !runtime_supported {
                    reasons.push(json!({"code": "runtime_contract_unavailable"}));
                }
                blockers.push(json!({
                    "type": "contract",
                    "id": contract.id,
                    "reasons": reasons
                }));
            }
            json!({
                "id": contract.id,
                "source_section": contract.source_section,
                "required_result_fields": contract.required_result_fields,
                "allowed_results": contract.allowed_results,
                "guard_test_ids": contract.guard_test_ids,
                "field_test_ids": contract.field_test_ids,
                "result_test_ids": contract.result_test_ids,
                "guarded": !contract.guard_test_ids.is_empty(),
                "evidence_complete": evidence_complete,
                "runtime_supported": runtime_supported,
                "implemented": implemented
            })
        })
        .collect::<Vec<_>>();

    let release_ready = operation_complete_count == requirements.operations.len()
        && capabilities
            .iter()
            .all(|capability| capability["supported"] == true)
        && acceptance_scenarios
            .iter()
            .all(|scenario| scenario["demonstrated"] == true)
        && contract_status
            .iter()
            .all(|contract| contract["implemented"] == true);

    Ok(json!({
        "schema_version": requirements.schema_version,
        "scope": "v0.1.0_product_mvp",
        "target_release": requirements.target_release,
        "product_contract": requirements.product_contract,
        "inventory_test_ids": requirements.inventory_test_ids,
        "required_operation_count": requirements.operations.len(),
        "command_present_count": command_present_count,
        "operation_complete_count": operation_complete_count,
        "missing_command_count": requirements.operations.len() - command_present_count,
        "release_ready": release_ready,
        "operations": operations,
        "capabilities": capabilities,
        "acceptance_scenarios": acceptance_scenarios,
        "contracts": contract_status,
        "blockers": blockers
    }))
}

fn contract_implemented(
    registry: &Registry,
    contract: &reltio_client::registry::ReleaseContract,
) -> bool {
    contract.implementation_evidence_complete()
        && (contract.id != audit::MUTATION_AUDIT_CONTRACT_ID
            || audit::mutation_audit_available(registry))
}

fn capability_supported(command: &str, argument: &str, required_value: &str) -> Result<bool> {
    let schema = metadata::schema(Some(command))?;
    let advertised = schema["arguments"]
        .as_array()
        .and_then(|arguments| {
            arguments
                .iter()
                .find(|entry| entry["name"].as_str() == Some(argument))
        })
        .and_then(|entry| entry["possible_values"].as_array())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(required_value))
        });
    let executable_provider = command != "auth.login"
        || argument != "method"
        || required_value.parse::<AuthMethod>().is_ok();
    Ok(advertised && executable_provider)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use reltio_client::registry::EndpointCommandRole;

    use super::*;

    #[::std::prelude::v1::test]
    fn release_evidence_functions_are_discoverable_in_cli_unit_harness() {
        let executable = std::env::current_exe().expect("current test executable");
        let output = Command::new(&executable)
            .args(["--list", "--format", "terse"])
            .output()
            .expect("list CLI unit tests");
        assert!(output.status.success(), "test listing failed: {output:?}");
        let listed = String::from_utf8(output.stdout).expect("UTF-8 test listing");
        let dep_info = fs::read_to_string(executable.with_extension("d"))
            .expect("CLI unit-test dep-info is readable")
            .replace('\\', "/");
        for (_, path, _, expected) in reltio_client::release_evidence_bindings_for_validation()
            .iter()
            .filter(|(_, path, _, _)| path.starts_with("crates/reltio-cli/src/"))
        {
            assert!(
                listed
                    .lines()
                    .any(|line| line == format!("{expected}: test")),
                "release evidence test {expected} is absent from the CLI unit harness"
            );
            assert!(
                dep_info
                    .split_ascii_whitespace()
                    .map(|entry| entry.trim_end_matches(':'))
                    .any(|entry| entry == *path),
                "release evidence source {path} is absent from CLI unit-test dep-info"
            );
        }
    }

    #[::std::prelude::v1::test]
    fn release_readiness_reports_the_independent_prd_inventory() {
        let report = readiness(Registry::embedded().expect("registry parses")).expect("report");
        assert_eq!(report["required_operation_count"], 50);
        assert_eq!(report["command_present_count"], 28);
        assert_eq!(report["missing_command_count"], 22);
        assert_eq!(report["operation_complete_count"], 0);
        assert_eq!(
            report["acceptance_scenarios"].as_array().map(Vec::len),
            Some(19)
        );
        assert_eq!(report["release_ready"], false);
        assert!(report["blockers"].as_array().is_some_and(|blockers| {
            blockers.iter().any(|blocker| {
                blocker["type"] == "operation"
                    && blocker["id"] == "profile.list"
                    && blocker["reasons"].as_array().is_some_and(|reasons| {
                        reasons
                            .iter()
                            .any(|reason| reason["code"] == "missing_implementation_evidence")
                    })
            }) && blockers
                .iter()
                .any(|blocker| blocker["type"] == "operation" && blocker["id"] == "entity.get-many")
                && blockers.iter().any(|blocker| {
                    blocker["type"] == "capability"
                        && blocker["id"] == "auth.provider.authorization-code"
                })
                && blockers.iter().any(|blocker| {
                    blocker["type"] == "contract" && blocker["id"] == "mutation_audit_v1"
                })
                && blockers.iter().any(|blocker| {
                    blocker["type"] == "acceptance_scenario" && blocker["id"] == "MVP-ACCEPT-001"
                })
        }));
    }

    #[::std::prelude::v1::test]
    fn endpoint_roles_do_not_count_dependencies_as_typed_ownership() {
        let registry = Registry::embedded().expect("registry parses");
        let auth = registry
            .endpoint("auth.client_credentials")
            .expect("auth endpoint");
        assert!(auth.has_command_role("entity.get", EndpointCommandRole::AuthDependency));
        assert!(!auth.has_command_role("entity.get", EndpointCommandRole::TypedPrimary));
        let entity_get = registry
            .requirements()
            .operations
            .iter()
            .find(|operation| operation.id == "entity.get")
            .expect("entity get requirement");
        assert_eq!(entity_get.required_endpoint_ids, ["entity.get"]);
        assert!(
            registry
                .endpoint(&entity_get.required_endpoint_ids[0])
                .is_some_and(|endpoint| endpoint
                    .has_command_role("entity.get", EndpointCommandRole::TypedPrimary))
        );
    }
}

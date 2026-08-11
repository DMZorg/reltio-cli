use std::collections::BTreeMap;
use std::time::Instant;

use reltio_client::auth::TokenManagerOptions;
use reltio_client::entities::EntitySearchRequest;
use reltio_client::error::{ErrorCategory, ReltioError, Result};
use reltio_client::registry::{Consistency, PracticeCoverage, Registry};
use reltio_client::service::{Service, ServiceResolver};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::DoctorArgs;
use crate::commands::Runtime;
use crate::output::{Meta, write_success_guarded};

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    status: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

pub async fn run(runtime: &Runtime, arguments: DoctorArgs) -> Result<()> {
    let started = Instant::now();
    let mut checks = Vec::new();
    let mut online_response = None;
    let mut diagnostic_failure = None;
    let mut output_guard = runtime.local_output_guard();
    let config = match runtime.store.load() {
        Ok(config) => config,
        Err(error) => {
            if let Some(guard) = error.output_guard() {
                output_guard.merge(guard);
            }
            checks.push(Check {
                name: if error.category == ErrorCategory::Safety {
                    "config.permissions".to_owned()
                } else {
                    "config.parse".to_owned()
                },
                status: "fail",
                message: error.message.clone(),
                details: Some(json!({
                    "code": error.code,
                    "hint": error.hint,
                    "path": runtime.store.path().display().to_string()
                })),
            });
            let report = doctor_report(
                arguments.online,
                &Value::Null,
                &BTreeMap::new(),
                &Value::Null,
                &checks,
            );
            return Err(doctor_unhealthy(report, Some(error), output_guard));
        }
    };
    checks.push(Check {
        name: "config.parse".to_owned(),
        status: "pass",
        message: "configuration parsed successfully".to_owned(),
        details: Some(json!({ "path": runtime.store.path().display().to_string() })),
    });
    match runtime.store.permissions_are_private() {
        Ok(Some(true)) => checks.push(Check {
            name: "config.permissions".to_owned(),
            status: "pass",
            message: "configuration is owner-only".to_owned(),
            details: None,
        }),
        Ok(Some(false)) => checks.push(Check {
            name: "config.permissions".to_owned(),
            status: "warn",
            message: "configuration is accessible by other users".to_owned(),
            details: Some(json!({ "hint": "Restrict it to the owner (for example, chmod 600)." })),
        }),
        Ok(None) => checks.push(Check {
            name: "config.permissions".to_owned(),
            status: "warn",
            message: "configuration file does not exist yet".to_owned(),
            details: None,
        }),
        Err(error) => {
            if let Some(guard) = error.output_guard() {
                output_guard.merge(guard);
            }
            diagnostic_failure.get_or_insert_with(|| error.clone());
            checks.push(Check {
                name: "config.permissions".to_owned(),
                status: "fail",
                message: error.message.clone(),
                details: Some(json!({ "code": error.code, "hint": error.hint })),
            });
        }
    }

    let target = match reltio_client::config::resolve_target(
        &config,
        &runtime.environment,
        &reltio_client::config::ResolutionOverrides {
            profile: runtime.globals.profile.clone(),
            environment: runtime.globals.environment.clone(),
            tenant: runtime.globals.tenant.clone(),
        },
    ) {
        Ok(target) => target,
        Err(error) => {
            if let Some(guard) = error.output_guard() {
                output_guard.merge(guard);
            }
            diagnostic_failure.get_or_insert_with(|| error.clone());
            checks.push(Check {
                name: "target.resolve".to_owned(),
                status: "fail",
                message: error.message.clone(),
                details: Some(json!({ "code": error.code, "hint": error.hint })),
            });
            let report = doctor_report(
                arguments.online,
                &Value::Null,
                &BTreeMap::new(),
                &Value::Null,
                &checks,
            );
            return Err(doctor_unhealthy(report, diagnostic_failure, output_guard));
        }
    };
    checks.push(Check {
        name: "target.resolve".to_owned(),
        status: "pass",
        message: "profile, environment, and tenant resolved deterministically".to_owned(),
        details: Some(json!({ "sources": target.sources })),
    });

    let resolver = ServiceResolver::new(target.clone());
    let mut services = BTreeMap::new();
    for service in Service::ALL {
        match resolver.base_url(service) {
            Ok(url) => {
                services.insert(service.to_string(), Value::String(url.to_string()));
                checks.push(Check {
                    name: format!("service.{service}"),
                    status: "pass",
                    message: "service URL resolved".to_owned(),
                    details: None,
                });
            }
            Err(error) => {
                services.insert(service.to_string(), Value::Null);
                checks.push(Check {
                    name: format!("service.{service}"),
                    status: "warn",
                    message: error.message.clone(),
                    details: Some(json!({ "code": error.code, "hint": error.hint })),
                });
            }
        }
    }

    let manager = match runtime.token_manager(&target, TokenManagerOptions::default()) {
        Ok(manager) => match manager.output_guard() {
            Ok(manager_guard) => {
                output_guard.merge(&manager_guard);
                Ok(manager)
            }
            Err(error) => {
                if let Some(guard) = error.output_guard() {
                    output_guard.merge(guard);
                }
                Err(error)
            }
        },
        Err(error) => {
            if let Some(guard) = error.output_guard() {
                output_guard.merge(guard);
            }
            Err(error)
        }
    };
    let auth_data = match &manager {
        Ok(manager) => match manager.status() {
            Ok(status) => {
                let check_status = if status.cache_state == "expired" {
                    "warn"
                } else {
                    "pass"
                };
                checks.push(Check {
                    name: "auth.offline".to_owned(),
                    status: check_status,
                    message: format!(
                        "provider {} configured; cache state {}",
                        status.provider, status.cache_state
                    ),
                    details: None,
                });
                serde_json::to_value(status).unwrap_or(Value::Null)
            }
            Err(error) => {
                diagnostic_failure.get_or_insert_with(|| error.clone());
                checks.push(Check {
                    name: "auth.offline".to_owned(),
                    status: "fail",
                    message: error.message.clone(),
                    details: Some(json!({ "code": error.code, "hint": error.hint })),
                });
                json!({ "configured": true, "error_code": error.code })
            }
        },
        Err(error) => {
            diagnostic_failure.get_or_insert_with(|| error.clone());
            checks.push(Check {
                name: "auth.offline".to_owned(),
                status: "fail",
                message: error.message.clone(),
                details: Some(json!({ "code": error.code, "hint": error.hint })),
            });
            json!({ "configured": false, "error_code": error.code })
        }
    };

    match Registry::embedded().and_then(|registry| {
        registry
            .review_age_days()
            .map(|review_age| (registry, review_age))
    }) {
        Ok((registry, review_age)) => checks.push(Check {
            name: "practices.freshness".to_owned(),
            status: if review_age <= 14 { "pass" } else { "warn" },
            message: format!("API-practice review is {review_age} day(s) old"),
            details: Some(json!({
                "reviewed_at": registry.metadata().reviewed_at,
                "corpus_commit": registry.metadata().corpus_commit,
                "release_notes_through": registry.metadata().release_notes_through,
                "release_freshness_max_days": 14
            })),
        }),
        Err(error) => {
            diagnostic_failure.get_or_insert_with(|| error.clone());
            checks.push(Check {
                name: "practices.freshness".to_owned(),
                status: "fail",
                message: error.message.clone(),
                details: Some(json!({ "code": error.code, "hint": error.hint })),
            });
        }
    }

    if arguments.online {
        match &manager {
            Ok(manager) => match runtime.entities_client(&target, manager.clone()) {
                Ok(client) => match client
                    .search(&EntitySearchRequest {
                        select: Some("URI".to_owned()),
                        max: 1,
                        ..EntitySearchRequest::default()
                    })
                    .await
                {
                    Ok(page) => {
                        output_guard.merge(&page.response.output_guard());
                        online_response = Some((
                            page.response.request_id.clone(),
                            page.response.status,
                            page.response.attempts,
                            page.response.applied_practice_ids.clone(),
                        ));
                        checks.push(Check {
                            name: "tenant.read".to_owned(),
                            status: "pass",
                            message: "authenticated tenant read succeeded".to_owned(),
                            details: Some(json!({
                                "request_id": page.response.request_id,
                                "attempts": page.response.attempts
                            })),
                        });
                    }
                    Err(error) => {
                        diagnostic_failure.get_or_insert_with(|| error.clone());
                        if let Some(guard) = error.output_guard() {
                            output_guard.merge(guard);
                        }
                        checks.push(Check {
                            name: "tenant.read".to_owned(),
                            status: "fail",
                            message: error.message.clone(),
                            details: Some(json!({
                                "code": error.code,
                                "http_status": error.http_status,
                                "request_id": error.request_id,
                                "hint": error.hint
                            })),
                        });
                    }
                },
                Err(error) => {
                    diagnostic_failure.get_or_insert_with(|| error.clone());
                    if let Some(guard) = error.output_guard() {
                        output_guard.merge(guard);
                    }
                    checks.push(Check {
                        name: "tenant.read".to_owned(),
                        status: "fail",
                        message: error.message.clone(),
                        details: Some(json!({ "code": error.code, "hint": error.hint })),
                    });
                }
            },
            Err(_) => checks.push(Check {
                name: "tenant.read".to_owned(),
                status: "fail",
                message: "online check skipped because authentication is not configured".to_owned(),
                details: None,
            }),
        }
    }

    let healthy = checks.iter().all(|check| check.status == "pass");
    let mut meta = Meta::new("doctor").with_target(&target, arguments.online.then_some("data"));
    meta.elapsed_ms = started.elapsed().as_millis();
    if let Some((request_id, status, attempts, practice_ids)) = online_response {
        meta.request_id = request_id;
        meta.http_status = Some(status);
        meta.attempts = Some(attempts);
        meta.practice_ids = practice_ids;
        meta.practice_coverage = Some(PracticeCoverage::Reviewed);
        meta.consistency = Some(Consistency::Eventual);
    }
    let target_data = json!({
        "profile": target.profile,
        "environment": target.environment,
        "tenant": target.tenant,
        "production": target.production,
        "target_overridden": target.target_overridden,
        "sources": target.sources
    });
    let data = doctor_report(
        arguments.online,
        &target_data,
        &services,
        &auth_data,
        &checks,
    );
    if !healthy {
        return Err(doctor_unhealthy(data, diagnostic_failure, output_guard));
    }
    write_success_guarded(&data, &meta, runtime.render, &output_guard)
}

fn doctor_report(
    online: bool,
    target: &Value,
    services: &BTreeMap<String, Value>,
    authentication: &Value,
    checks: &[Check],
) -> Value {
    let healthy = checks.iter().all(|check| check.status == "pass");
    json!({
        "healthy": healthy,
        "online": online,
        "cli_version": env!("CARGO_PKG_VERSION"),
        "target": target,
        "services": services,
        "authentication": authentication,
        "checks": checks,
        "computing_credits": "unknown"
    })
}

fn doctor_unhealthy(
    report: Value,
    cause: Option<ReltioError>,
    mut output_guard: reltio_client::redaction::OutputGuard,
) -> ReltioError {
    if let Some(guard) = cause.as_ref().and_then(ReltioError::output_guard) {
        output_guard.merge(guard);
    }
    let category = cause
        .as_ref()
        .map_or(ErrorCategory::Internal, |error| error.category);
    let mut error = ReltioError::new(
        "doctor_unhealthy",
        category,
        "one or more doctor checks require attention",
    )
    .with_details(report)
    .with_hint("Review error.details.checks, correct every warning or failure, and rerun doctor.");
    if let Some(cause) = cause {
        error = error
            .retryable(cause.retryable)
            .with_request_id(cause.request_id.clone());
        if let Some(status) = cause.http_status {
            error = error.with_http_status(status);
        }
    }
    error.with_output_guard(output_guard)
}

use std::time::Instant;

use reqwest::Method;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::auth::TokenManager;
use crate::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use crate::http::{ApiResponse, HttpClient, RequestSpec};
use crate::registry::{Consistency, Registry};
use crate::service::{Service, ServiceResolver, normalize_entity_uri};

pub const SEARCH_RESULT_BOUNDARY: u32 = 10_000;
pub const SEARCH_BOUNDARY_WARNING: &str = "the 10,000-result offset boundary was reached; more matching entities may exist, so use entity scan for exhaustive retrieval";
pub const QUERY_FILTER_CHARACTER_LIMIT: usize = 256;
const ENTITY_GET_OPTIONS: &[&str] = &[
    "sendHidden",
    "ovOnly",
    "nonOvOnly",
    "serializeInitialSourcesInCrosswalks",
    "cleanEntity",
    "showAppliedSurvivorshipRules",
    "showEndDatedReferenceAttributes",
    "explainOv",
];
const ENTITY_GET_SELECT_FIELDS: &[&str] = &[
    "uri",
    "type",
    "tags",
    "createdBy",
    "createdTime",
    "updatedBy",
    "updatedTime",
    "isFavorite",
    "analyticsAttributes",
    "label",
    "secondaryLabel",
    "crosswalks",
    "attributes",
];

#[derive(Debug, Clone, Default)]
pub struct EntityGetOptions {
    pub select: Option<String>,
    pub time: Option<u64>,
    pub options: Vec<String>,
    pub merge_duplicate_crosswalks: bool,
    pub default_max_values: Option<u32>,
    pub explicit_survivorship_group: Option<String>,
    pub reverse_transcode_lookups: Option<String>,
    pub send_masked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EntitySearchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<String>,
    pub max: u32,
    pub offset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_options",
        deserialize_with = "deserialize_options"
    )]
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_values: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activeness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_enabled: Option<bool>,
}

impl Default for EntitySearchRequest {
    fn default() -> Self {
        Self {
            filter: None,
            select: None,
            max: 50,
            offset: 0,
            sort: None,
            order: None,
            options: Vec::new(),
            default_max_values: None,
            activeness: None,
            score_enabled: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntityResult {
    pub entity: Value,
    pub response: ApiResponse,
    pub consistency: Consistency,
}

#[derive(Debug, Clone)]
pub struct EntitySearchPage {
    pub entities: Vec<Value>,
    pub offset: u32,
    pub max: u32,
    pub next_offset: Option<u32>,
    pub boundary_reached: bool,
    pub response: ApiResponse,
    pub consistency: Consistency,
}

#[derive(Debug, Clone)]
pub struct EntityScanRequest {
    pub filter: Option<String>,
    pub cursor: Option<String>,
    pub max: u32,
    pub select: Option<String>,
    pub options: Vec<String>,
    pub activeness: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EntityScanPage {
    pub objects: Vec<Value>,
    pub cursor: String,
    pub response: ApiResponse,
    pub consistency: Consistency,
}

#[derive(Debug, Clone)]
pub struct EntitiesClient {
    resolver: ServiceResolver,
    http: HttpClient,
    auth: TokenManager,
}

impl EntitiesClient {
    pub fn new(resolver: ServiceResolver, http: HttpClient, auth: TokenManager) -> Self {
        Self {
            resolver,
            http,
            auth,
        }
    }

    pub async fn get(&self, entity: &str, options: &EntityGetOptions) -> Result<EntityResult> {
        let canonical = normalize_entity_uri(entity)?;
        validate_get_select(options.select.as_deref())?;
        validate_get_options(&options.options)?;
        let mut url = self
            .resolver
            .request_url(Service::Data, &format!("/{canonical}"))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(select) = options.select.as_deref() {
                query.append_pair("select", select);
            }
            if let Some(time) = options.time {
                query.append_pair("time", &time.to_string());
            }
            if !options.options.is_empty() {
                query.append_pair("options", &options.options.join(","));
            }
            if options.merge_duplicate_crosswalks {
                query.append_pair("mergeDuplicateCrosswalks", "true");
            }
            if let Some(maximum) = options.default_max_values {
                query.append_pair("defaultMaxValues", &maximum.to_string());
            }
            if let Some(group) = options.explicit_survivorship_group.as_deref() {
                query.append_pair("explicitSurvivorshipGroup", group);
            }
            if let Some(system) = options.reverse_transcode_lookups.as_deref() {
                query.append_pair("reverseTranscodeLookups", system);
            }
            if options.send_masked {
                query.append_pair("sendMasked", "true");
            }
        }
        let endpoint = endpoint("entity.get")?;
        let mut request = RequestSpec::new(Method::GET, url, "entity.get");
        request.headers = json_headers(false);
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = self.http.execute(&self.auth, request).await?;
        let entity = response.json()?;
        if !entity.is_object() {
            return Err(unexpected_shape("entity.get", "a JSON object", &response));
        }
        Ok(EntityResult {
            entity,
            response,
            consistency: endpoint.consistency,
        })
    }

    pub async fn search(&self, search: &EntitySearchRequest) -> Result<EntitySearchPage> {
        validate_search(search)?;
        let url = self
            .resolver
            .request_url(Service::Data, "/entities/_search")?;
        let body = serde_json::to_vec(search).map_err(|error| {
            ReltioError::internal(format!("failed to encode entity search: {error}"))
        })?;
        let endpoint = endpoint("entity.search")?;
        let mut request = RequestSpec::new(Method::POST, url, "entity.search");
        request.headers = json_headers(true);
        request.body = Some(body);
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = self.http.execute(&self.auth, request).await?;
        let entities = parse_array(&response, "entity.search")?;
        let returned = u32::try_from(entities.len()).unwrap_or(u32::MAX);
        let candidate = search.offset.saturating_add(returned);
        let next_offset =
            (returned == search.max && candidate < SEARCH_RESULT_BOUNDARY).then_some(candidate);
        let boundary_reached = returned == search.max && candidate >= SEARCH_RESULT_BOUNDARY;
        Ok(EntitySearchPage {
            entities,
            offset: search.offset,
            max: search.max,
            next_offset,
            boundary_reached,
            response,
            consistency: endpoint.consistency,
        })
    }

    pub async fn scan_page(&self, scan: &EntityScanRequest) -> Result<EntityScanPage> {
        self.scan_page_with_deadline(scan, None).await
    }

    pub async fn scan_page_until(
        &self,
        scan: &EntityScanRequest,
        deadline: Instant,
    ) -> Result<EntityScanPage> {
        self.scan_page_with_deadline(scan, Some(deadline)).await
    }

    async fn scan_page_with_deadline(
        &self,
        scan: &EntityScanRequest,
        deadline: Option<Instant>,
    ) -> Result<EntityScanPage> {
        validate_scan(scan)?;
        let mut url = self
            .resolver
            .request_url(Service::Data, "/entities/_scan")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("max", &scan.max.to_string());
            if scan.cursor.is_none() {
                if let Some(filter) = scan.filter.as_deref() {
                    query.append_pair("filter", filter);
                }
                if let Some(select) = scan.select.as_deref() {
                    query.append_pair("select", select);
                }
                if !scan.options.is_empty() {
                    query.append_pair("options", &scan.options.join(","));
                }
                if let Some(activeness) = scan.activeness.as_deref() {
                    query.append_pair("activeness", activeness);
                }
            }
        }
        let body = scan
            .cursor
            .as_ref()
            .map(|cursor| {
                serde_json::to_vec(&json!({ "cursor": { "value": cursor } })).map_err(|error| {
                    ReltioError::internal(format!("failed to encode scan cursor: {error}"))
                })
            })
            .transpose()?;
        let endpoint = endpoint("entity.scan")?;
        let mut request = RequestSpec::new(Method::POST, url, "entity.scan");
        request.headers = json_headers(true);
        request.body = body;
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = if let Some(deadline) = deadline {
            self.http
                .execute_until(&self.auth, request, deadline)
                .await?
        } else {
            self.http.execute(&self.auth, request).await?
        };
        let parsed: ScanResponse = serde_json::from_value(response.json()?).map_err(|error| {
            ReltioError::new(
                "api_response_invalid_json",
                ErrorCategory::Api,
                "entity scan returned an invalid response shape",
            )
            .with_http_status(response.status)
            .with_request_id(response.request_id.clone())
            .with_details(json_parse_details(&error))
            .with_output_guard(response.output_guard())
        })?;
        if parsed.cursor.value.is_empty() {
            return Err(unexpected_shape(
                "entity.scan",
                "a non-empty cursor",
                &response,
            ));
        }
        Ok(EntityScanPage {
            objects: parsed.objects,
            cursor: parsed.cursor.value,
            response,
            consistency: endpoint.consistency,
        })
    }
}

#[derive(Deserialize)]
struct ScanResponse {
    cursor: Cursor,
    #[serde(default)]
    objects: Vec<Value>,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

#[derive(Deserialize)]
struct Cursor {
    value: String,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

pub fn validate_search(search: &EntitySearchRequest) -> Result<()> {
    if search.max == 0 {
        return Err(ReltioError::usage(
            "invalid_page_size",
            "entity search max must be greater than zero",
        ));
    }
    if search.offset.saturating_add(search.max) > SEARCH_RESULT_BOUNDARY {
        return Err(ReltioError::usage(
            "entity_search_boundary_exceeded",
            format!(
                "offset {} plus max {} exceeds Reltio's {}-result search boundary",
                search.offset, search.max, SEARCH_RESULT_BOUNDARY
            ),
        )
        .with_hint("Use `reltio entity scan` for exhaustive retrieval."));
    }
    if let Some(filter) = search.filter.as_deref() {
        validate_query_filter(filter)?;
        validate_optional_text(Some(filter), "filter")?;
    }
    validate_optional_text(search.select.as_deref(), "select")?;
    validate_optional_text(search.sort.as_deref(), "sort")?;
    validate_options(&search.options)?;
    if let Some(order) = search.order.as_deref() {
        if !matches!(order, "asc" | "desc") {
            return Err(ReltioError::usage(
                "invalid_sort_order",
                "entity search order must be asc or desc",
            ));
        }
        if search.sort.is_none() {
            return Err(ReltioError::usage(
                "sort_required",
                "entity search order requires a sort field",
            ));
        }
    }
    validate_activeness(search.activeness.as_deref())
}

pub fn validate_get(entity: &str, options: &EntityGetOptions) -> Result<()> {
    normalize_entity_uri(entity)?;
    validate_get_select(options.select.as_deref())?;
    validate_get_options(&options.options)?;
    validate_nonempty_query_text(
        options.explicit_survivorship_group.as_deref(),
        "explicitSurvivorshipGroup",
    )?;
    validate_nonempty_query_text(
        options.reverse_transcode_lookups.as_deref(),
        "reverseTranscodeLookups",
    )
}

pub fn validate_scan(scan: &EntityScanRequest) -> Result<()> {
    if scan.max == 0 {
        return Err(ReltioError::usage(
            "invalid_page_size",
            "entity scan page size must be greater than zero",
        ));
    }
    if scan.cursor.is_none() && scan.filter.as_deref().is_none_or(str::is_empty) {
        return Err(ReltioError::usage(
            "scan_filter_required",
            "the first entity scan request requires a filter",
        ));
    }
    if scan.cursor.as_deref().is_some_and(str::is_empty) {
        return Err(ReltioError::usage(
            "scan_cursor_empty",
            "a continued scan requires a non-empty cursor value",
        ));
    }
    if scan.cursor.is_some()
        && (scan.filter.is_some()
            || scan.select.is_some()
            || !scan.options.is_empty()
            || scan.activeness.is_some())
    {
        return Err(ReltioError::usage(
            "scan_cursor_parameter_conflict",
            "a continued scan sends only the cursor and page size, not first-request parameters",
        ));
    }
    if let Some(filter) = scan.filter.as_deref() {
        validate_query_filter(filter)?;
        validate_optional_text(Some(filter), "filter")?;
    }
    validate_optional_text(scan.select.as_deref(), "select")?;
    validate_options(&scan.options)?;
    validate_activeness(scan.activeness.as_deref())
}

pub fn validate_query_filter(filter: &str) -> Result<()> {
    let characters = filter.chars().count();
    if characters > QUERY_FILTER_CHARACTER_LIMIT {
        return Err(ReltioError::usage(
            "query_filter_too_long",
            format!(
                "filter has {characters} characters; Reltio processes only the first {QUERY_FILTER_CHARACTER_LIMIT} characters"
            ),
        )
        .with_hint("Simplify the filter or use an export workflow; truncation is never allowed."));
    }
    Ok(())
}

fn validate_optional_text(value: Option<&str>, field: &str) -> Result<()> {
    if value.is_some_and(|text| text.contains(['\r', '\n', '\0'])) {
        Err(ReltioError::usage(
            "invalid_query_value",
            format!("{field} contains a control character"),
        ))
    } else {
        Ok(())
    }
}

fn validate_nonempty_query_text(value: Option<&str>, field: &str) -> Result<()> {
    validate_optional_text(value, field)?;
    if value.is_some_and(str::is_empty) {
        return Err(ReltioError::usage(
            "invalid_query_value",
            format!("{field} must not be empty when supplied"),
        ));
    }
    Ok(())
}

fn validate_get_select(select: Option<&str>) -> Result<()> {
    validate_optional_text(select, "select")?;
    let Some(select) = select else {
        return Ok(());
    };
    if select.is_empty()
        || select
            .split(',')
            .any(|field| field.is_empty() || field.trim() != field)
    {
        return Err(ReltioError::usage(
            "invalid_query_value",
            "select must be a non-empty comma-separated property list without empty or padded fields",
        ));
    }
    if let Some(field) = select.split(',').find(|field| {
        !ENTITY_GET_SELECT_FIELDS.contains(field)
            && !field.strip_prefix("attributes.").is_some_and(|path| {
                !path.is_empty()
                    && path.split('.').all(|segment| {
                        !segment.is_empty() && !segment.chars().any(char::is_whitespace)
                    })
            })
    }) {
        return Err(ReltioError::usage(
            "invalid_query_value",
            format!("select field {field:?} is not in the reviewed Get Entity contract"),
        )
        .with_details(json!({
            "allowed_top_level": ENTITY_GET_SELECT_FIELDS,
            "allowed_attribute_path": "attributes.<non-empty path>"
        })));
    }
    Ok(())
}

fn validate_get_options(options: &[String]) -> Result<()> {
    validate_options(options)?;
    if let Some(option) = options
        .iter()
        .find(|option| !ENTITY_GET_OPTIONS.contains(&option.as_str()))
    {
        return Err(ReltioError::usage(
            "invalid_entity_option",
            format!("entity get option {option:?} is not in the reviewed Get Entity contract"),
        )
        .with_details(json!({ "allowed": ENTITY_GET_OPTIONS })));
    }
    Ok(())
}

fn validate_options(options: &[String]) -> Result<()> {
    if options
        .iter()
        .any(|option| option.is_empty() || option.contains([',', '\r', '\n', '\0']))
    {
        Err(ReltioError::usage(
            "invalid_entity_option",
            "entity options must be non-empty individual values without commas or controls",
        ))
    } else {
        Ok(())
    }
}

fn validate_activeness(activeness: Option<&str>) -> Result<()> {
    if activeness.is_some_and(|value| !matches!(value, "active" | "all" | "not_active")) {
        Err(ReltioError::usage(
            "invalid_activeness",
            "activeness must be active, all, or not_active",
        ))
    } else {
        Ok(())
    }
}

fn serialize_options<S>(options: &[String], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&options.join(","))
}

fn deserialize_options<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
        .map(|options| options.split(',').map(ToOwned::to_owned).collect())
}

fn endpoint(id: &str) -> Result<crate::registry::Endpoint> {
    Registry::embedded()?
        .endpoint(id)
        .cloned()
        .ok_or_else(|| ReltioError::internal(format!("endpoint {id} is not registered")))
}

fn json_headers(has_body: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if has_body {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    headers
}

fn parse_array(response: &ApiResponse, operation: &str) -> Result<Vec<Value>> {
    let parsed = response.json()?;
    parsed
        .as_array()
        .cloned()
        .ok_or_else(|| unexpected_shape(operation, "a JSON array", response))
}

fn unexpected_shape(operation: &str, expected: &str, response: &ApiResponse) -> ReltioError {
    ReltioError::new(
        "api_response_unexpected_shape",
        ErrorCategory::Api,
        format!("{operation} expected {expected}"),
    )
    .with_http_status(response.status)
    .with_request_id(response.request_id.clone())
    .with_output_guard(response.output_guard())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_search_boundary() {
        let valid = EntitySearchRequest {
            offset: 9_900,
            max: 100,
            ..EntitySearchRequest::default()
        };
        assert!(validate_search(&valid).is_ok());
        let invalid = EntitySearchRequest {
            offset: 9_901,
            max: 100,
            ..EntitySearchRequest::default()
        };
        assert_eq!(
            validate_search(&invalid)
                .expect_err("boundary must fail")
                .code,
            "entity_search_boundary_exceeded"
        );
    }

    #[test]
    fn refuses_silently_truncated_search_filter() {
        let valid = EntitySearchRequest {
            filter: Some("x".repeat(QUERY_FILTER_CHARACTER_LIMIT)),
            ..EntitySearchRequest::default()
        };
        assert!(validate_search(&valid).is_ok());

        let invalid = EntitySearchRequest {
            filter: Some("x".repeat(QUERY_FILTER_CHARACTER_LIMIT + 1)),
            ..EntitySearchRequest::default()
        };
        assert_eq!(
            validate_search(&invalid)
                .expect_err("long search filter fails")
                .code,
            "query_filter_too_long"
        );
    }

    #[test]
    fn refuses_silently_truncated_scan_filter() {
        let request = EntityScanRequest {
            filter: Some("x".repeat(QUERY_FILTER_CHARACTER_LIMIT + 1)),
            cursor: None,
            max: 100,
            select: None,
            options: Vec::new(),
            activeness: None,
        };
        assert_eq!(
            validate_scan(&request).expect_err("long filter fails").code,
            "query_filter_too_long"
        );
    }

    #[test]
    fn plus_is_percent_encoded_by_url_query_serializer() {
        let mut url = url::Url::parse("https://example.test/").unwrap();
        url.query_pairs_mut()
            .append_pair("filter", "equals(attributes.ID,'A+B')");
        assert!(url.as_str().contains("A%2BB"));
    }

    #[test]
    fn entity_payload_remains_lossless() {
        let source = json!({
            "uri": "entities/1",
            "attributes": {"TenantDefined": [{"value": {"future": true}}]},
            "ovDetails": {"winnerCrosswalks": ["entities/1/crosswalks/2"]},
            "futureTopLevel": 42
        });
        let roundtrip: Value =
            serde_json::from_slice(&serde_json::to_vec(&source).unwrap()).unwrap();
        assert_eq!(source, roundtrip);
    }

    #[test]
    fn search_options_follow_the_official_string_schema() {
        let request: EntitySearchRequest = serde_json::from_value(json!({
            "options": "sortByOV,ovOnly",
            "defaultMaxValues": 10
        }))
        .expect("official search body parses");
        assert_eq!(request.options, ["sortByOV", "ovOnly"]);
        assert_eq!(request.default_max_values, Some(10));
        assert_eq!(
            serde_json::to_value(request).expect("search body serializes")["options"],
            "sortByOV,ovOnly"
        );
        assert!(
            serde_json::from_value::<EntitySearchRequest>(json!({"options": ["ovOnly"]})).is_err()
        );
    }

    #[test]
    fn get_select_and_options_match_the_reviewed_contract() {
        for select in [
            "uri",
            "uri,label,attributes",
            "attributes.FirstName,attributes.Address.City",
            "attributes._lookupCodes,attributes._lookupValues",
        ] {
            validate_get_select(Some(select)).expect("documented select is accepted");
        }
        for select in [
            "",
            "URI",
            "uri, label",
            "attributes.",
            "attributes..Name",
            "unknown",
        ] {
            assert_eq!(
                validate_get_select(Some(select))
                    .expect_err("undocumented select must fail")
                    .code,
                "invalid_query_value"
            );
        }
        validate_get_options(
            &ENTITY_GET_OPTIONS
                .iter()
                .map(|option| (*option).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("documented options are accepted");
        assert_eq!(
            validate_get_options(&["sortByOV".to_owned()])
                .expect_err("search-only option must fail")
                .code,
            "invalid_entity_option"
        );
    }
}

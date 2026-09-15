use std::time::Instant;

use reqwest::Method;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::auth::TokenManager;
use crate::error::{ErrorCategory, ReltioError, Result, json_parse_details};
use crate::http::{ApiResponse, HttpClient, RequestSpec};
use crate::registry::{Consistency, Registry, ReplayPolicy};
use crate::service::{Service, ServiceResolver, normalize_entity_uri};

pub const SEARCH_RESULT_BOUNDARY: u32 = 10_000;
pub const SEARCH_BOUNDARY_WARNING: &str = "the 10,000-result offset boundary was reached; more matching entities may exist, so use entity scan for exhaustive retrieval";
pub const QUERY_FILTER_CHARACTER_LIMIT: usize = 256;
pub const ENTITY_SCAN_PAGE_LIMIT: u32 = 200;
pub const ENTITY_SCAN_OPTIONS: &[&str] = &["sendHidden", "searchByOv", "ovOnly", "nonOvOnly"];
pub const ENTITY_SCAN_OPTIONS_PROVISIONAL_WARNING: &str = "scan options are documented only for conflicting route variants; verify behavior in a non-production tenant before depending on options for /entities/_scan";
pub const HISTORY_RESULT_BOUNDARY: u32 = 1_000;
pub const HISTORY_BOUNDARY_WARNING: &str = "the 1,000-event entity-history boundary was reached; Reltio does not support pagination beyond the most recent 1,000 events";
pub const HISTORY_CANONICAL_VALUES_WARNING: &str = "entity history contains stored canonical values and does not retranscode them for Accept-Language; values can differ from a current entity read";
pub const POTENTIAL_MATCHES_FRESHNESS_WARNING: &str = "stored potential matches may be empty or out of date when matching is ON_REQUEST, disabled by strategy NONE, or handled without SuspectMatchHandler persistence; this read does not force recalculation";
pub const CROSSWALK_ID_FALLBACK_WARNING: &str = "Reltio returned an entity without the requested crosswalk tuple; the documented ID-fallback behavior may have selected the entity by its Reltio ID";
const ENTITY_CROSSWALK_OPTIONS: &[&str] = &["sendHidden", "ovOnly", "nonOvOnly"];
pub const ENTITY_MATCH_TYPES: &[&str] = &["automatic", "relevance_based", "suspect"];
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

#[derive(Debug, Clone)]
pub struct EntityByCrosswalkRequest {
    pub value: String,
    pub source_type: String,
    pub source_table: Option<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EntityHistoryRequest {
    pub max: u32,
    pub offset: u32,
    pub order: String,
    pub filter: Option<String>,
    pub show_all: bool,
    pub show_major_events_only: Option<bool>,
    pub skip_reference_attributes_processing: bool,
}

impl Default for EntityHistoryRequest {
    fn default() -> Self {
        Self {
            max: 50,
            offset: 0,
            order: "desc".to_owned(),
            filter: None,
            show_all: false,
            show_major_events_only: None,
            skip_reference_attributes_processing: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntityMatchesRequest {
    pub max: u32,
    pub offset: u32,
    pub match_type: Option<String>,
}

impl Default for EntityMatchesRequest {
    fn default() -> Self {
        Self {
            max: 50,
            offset: 0,
            match_type: None,
        }
    }
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
pub struct EntityByCrosswalkResult {
    pub entries: Vec<Value>,
    pub id_fallback_detected: bool,
    pub response: ApiResponse,
    pub consistency: Consistency,
}

#[derive(Debug, Clone)]
pub struct EntityHistoryPage {
    pub changes: Vec<Value>,
    pub offset: u32,
    pub max: u32,
    pub next_offset: Option<u32>,
    pub boundary_reached: bool,
    pub response: ApiResponse,
    pub consistency: Consistency,
}

#[derive(Debug, Clone)]
pub struct EntityMatchesPage {
    pub matches: Value,
    pub offset: u32,
    pub max: u32,
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

    pub async fn by_crosswalk(
        &self,
        lookup: &EntityByCrosswalkRequest,
    ) -> Result<EntityByCrosswalkResult> {
        validate_by_crosswalk(lookup)?;
        let mut url = self.resolver.request_url(
            Service::Data,
            &format!("/entities/_byCrosswalk/{}", lookup.value),
        )?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("type", &lookup.source_type);
            if let Some(source_table) = lookup.source_table.as_deref() {
                query.append_pair("sourceTable", source_table);
            }
            if !lookup.options.is_empty() {
                query.append_pair("options", &lookup.options.join(","));
            }
        }
        let endpoint = endpoint("entity.by-crosswalk")?;
        let mut request = RequestSpec::new(Method::GET, url, "entity.by-crosswalk");
        request.headers = json_headers(false);
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = self.http.execute(&self.auth, request).await?;
        let entries = parse_array(&response, "entity.by-crosswalk")?;
        let id_fallback_detected = entity_by_crosswalk_id_fallback_detected(&entries, lookup);
        Ok(EntityByCrosswalkResult {
            entries,
            id_fallback_detected,
            response,
            consistency: endpoint.consistency,
        })
    }

    pub async fn history(
        &self,
        entity: &str,
        history: &EntityHistoryRequest,
    ) -> Result<EntityHistoryPage> {
        validate_history(entity, history)?;
        let canonical = normalize_entity_uri(entity)?;
        let mut url = self
            .resolver
            .request_url(Service::Data, &format!("/{canonical}/_changes"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("max", &history.max.to_string());
            query.append_pair("offset", &history.offset.to_string());
            query.append_pair("order", &history.order);
            if let Some(filter) = history.filter.as_deref() {
                query.append_pair("filter", filter);
            }
            if history.show_all {
                query.append_pair("showAll", "true");
            }
            if let Some(show_major_events_only) = history.show_major_events_only {
                query.append_pair(
                    "showMajorEventsOnly",
                    if show_major_events_only {
                        "true"
                    } else {
                        "false"
                    },
                );
            }
            if history.skip_reference_attributes_processing {
                query.append_pair("options", "skipReferenceAttributesProcessing");
            }
        }
        let endpoint = endpoint("entity.history")?;
        let mut request = RequestSpec::new(Method::GET, url, "entity.history");
        request.headers = json_headers(false);
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = self.http.execute(&self.auth, request).await?;
        let changes = parse_array(&response, "entity.history")?;
        let returned = u32::try_from(changes.len()).unwrap_or(u32::MAX);
        let candidate = history.offset.saturating_add(returned);
        let next_offset =
            (returned == history.max && candidate < HISTORY_RESULT_BOUNDARY).then_some(candidate);
        let boundary_reached = returned == history.max && candidate >= HISTORY_RESULT_BOUNDARY;
        Ok(EntityHistoryPage {
            changes,
            offset: history.offset,
            max: history.max,
            next_offset,
            boundary_reached,
            response,
            consistency: endpoint.consistency,
        })
    }

    pub async fn matches(
        &self,
        entity: &str,
        matches: &EntityMatchesRequest,
    ) -> Result<EntityMatchesPage> {
        validate_matches(entity, matches)?;
        let canonical = normalize_entity_uri(entity)?;
        let mut url = self
            .resolver
            .request_url(Service::Data, &format!("/{canonical}/_matches"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("transitive", "false");
            query.append_pair("forceMatch", "false");
            query.append_pair("deep", "1");
            query.append_pair("max", &matches.max.to_string());
            query.append_pair("offset", &matches.offset.to_string());
            if let Some(match_type) = matches.match_type.as_deref() {
                query.append_pair("type", match_type);
            }
        }
        let endpoint = endpoint("entity.matches")?;
        let mut request = RequestSpec::new(Method::GET, url, "entity.matches");
        request.headers = json_headers(false);
        request.replay = endpoint.replay;
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = self.http.execute(&self.auth, request).await?;
        let matches_payload = response.json()?;
        let groups = matches_payload.as_object().ok_or_else(|| {
            unexpected_shape(
                "entity.matches",
                "a JSON object grouped by match rule",
                &response,
            )
        })?;
        if groups.values().any(|group| !group.is_array()) {
            return Err(unexpected_shape(
                "entity.matches",
                "arrays of potential matches grouped by match rule",
                &response,
            ));
        }
        Ok(EntityMatchesPage {
            matches: matches_payload,
            offset: matches.offset,
            max: matches.max,
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
        request.replay = scan_replay_policy(scan, endpoint.replay);
        request.practice_ids.clone_from(&endpoint.practice_ids);
        let response = if let Some(deadline) = deadline {
            self.http
                .execute_until(&self.auth, request, deadline)
                .await?
        } else {
            self.http.execute(&self.auth, request).await?
        };
        let key_presence = response.unredacted_top_level_key_presence(&["objects", "entities"])?;
        let has_objects = key_presence.first().copied().unwrap_or(false);
        let has_entities = key_presence.get(1).copied().unwrap_or(false);
        if has_entities {
            return Err(ReltioError::new(
                "scan_response_route_mismatch",
                ErrorCategory::Api,
                "entity scan returned the conflicting v2 response collection",
            )
            .with_http_status(response.status)
            .with_request_id(response.request_id.clone())
            .with_details(json!({
                "expected_collection": "objects",
                "unexpected_collection": "entities",
                "expected_collection_present": has_objects,
                "documented_route": "/entities/_scan",
                "conflicting_route": "/entities/v2/_scan"
            }))
            .with_hint("Do not treat this response as cursor exhaustion; verify the tenant route contract before retrying.")
            .with_output_guard(response.output_guard()));
        }
        let response_value = response.json()?;
        if has_objects && response_value.get("objects").is_none() {
            return Err(response.redaction_error("entity_scan_objects_key_matched_credential"));
        }
        let parsed: ScanResponse = serde_json::from_value(response_value).map_err(|error| {
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

pub fn validate_by_crosswalk(lookup: &EntityByCrosswalkRequest) -> Result<()> {
    if lookup.value.is_empty() {
        return Err(ReltioError::usage(
            "crosswalk_value_required",
            "crosswalk value must not be empty",
        ));
    }
    if !lookup
        .value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        || matches!(lookup.value.as_str(), "." | "..")
    {
        return Err(ReltioError::usage(
            "crosswalk_value_requires_post",
            "this CLI conservatively routes crosswalk values outside the RFC 3986 unreserved subset to Reltio's POST-by-crosswalk variant, which is not yet a reviewed typed command",
        )
        .with_hint("Use this typed GET only for unreserved crosswalk values until Reltio defines the GET special-character set precisely."));
    }
    validate_required_query_text(&lookup.source_type, "type")?;
    validate_nonempty_query_text(lookup.source_table.as_deref(), "sourceTable")?;
    validate_options(&lookup.options)?;
    if let Some(option) = lookup
        .options
        .iter()
        .find(|option| !ENTITY_CROSSWALK_OPTIONS.contains(&option.as_str()))
    {
        return Err(ReltioError::usage(
            "invalid_crosswalk_option",
            format!("entity by-crosswalk option {option:?} is not in the reviewed GET contract"),
        )
        .with_details(json!({ "allowed": ENTITY_CROSSWALK_OPTIONS })));
    }
    if lookup.options.iter().any(|option| option == "ovOnly")
        && lookup.options.iter().any(|option| option == "nonOvOnly")
    {
        return Err(ReltioError::usage(
            "crosswalk_option_conflict",
            "ovOnly and nonOvOnly are mutually exclusive",
        ));
    }
    Ok(())
}

pub fn validate_history(entity: &str, history: &EntityHistoryRequest) -> Result<()> {
    normalize_entity_uri(entity)?;
    if history.max == 0 {
        return Err(ReltioError::usage(
            "invalid_page_size",
            "entity history max must be greater than zero",
        ));
    }
    if u64::from(history.offset) + u64::from(history.max) > u64::from(HISTORY_RESULT_BOUNDARY) {
        return Err(ReltioError::usage(
            "entity_history_boundary_exceeded",
            format!(
                "offset {} plus max {} exceeds Reltio's {}-event entity-history boundary",
                history.offset, history.max, HISTORY_RESULT_BOUNDARY
            ),
        )
        .with_hint(
            "Narrow the history filter or request a window within the most recent 1,000 events.",
        ));
    }
    if !matches!(history.order.as_str(), "asc" | "desc") {
        return Err(ReltioError::usage(
            "invalid_history_order",
            "entity history order must be asc or desc",
        ));
    }
    validate_nonempty_query_text(history.filter.as_deref(), "filter")?;
    if history.show_all && history.filter.is_some() {
        return Err(ReltioError::usage(
            "history_filter_ignored",
            "entity history filter cannot be combined with showAll=true because Reltio ignores the filter",
        ));
    }
    Ok(())
}

pub fn validate_matches(entity: &str, matches: &EntityMatchesRequest) -> Result<()> {
    normalize_entity_uri(entity)?;
    if matches.max == 0 {
        return Err(ReltioError::usage(
            "invalid_matches_page_size",
            "entity matches max must be greater than zero",
        ));
    }
    if let Some(match_type) = matches.match_type.as_deref() {
        if !ENTITY_MATCH_TYPES.contains(&match_type) {
            return Err(ReltioError::usage(
                "invalid_match_type",
                format!("match type {match_type:?} is not in the reviewed typed contract"),
            )
            .with_details(json!({ "allowed": ENTITY_MATCH_TYPES })));
        }
    }
    Ok(())
}

pub fn entity_by_crosswalk_id_fallback_detected(
    entries: &[Value],
    lookup: &EntityByCrosswalkRequest,
) -> bool {
    entries
        .iter()
        .any(|entry| successful_entry_lacks_crosswalk(entry, lookup))
}

fn successful_entry_lacks_crosswalk(entry: &Value, lookup: &EntityByCrosswalkRequest) -> bool {
    if entry.get("successful").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    let Some(crosswalks) = entry
        .get("object")
        .and_then(|object| object.get("crosswalks"))
        .and_then(Value::as_array)
    else {
        return true;
    };
    !crosswalks.iter().any(|crosswalk| {
        crosswalk.get("value").and_then(Value::as_str) == Some(lookup.value.as_str())
            && crosswalk
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|source_type| {
                    normalized_source_type(source_type)
                        == normalized_source_type(&lookup.source_type)
                })
            && lookup.source_table.as_deref().is_none_or(|source_table| {
                crosswalk.get("sourceTable").and_then(Value::as_str) == Some(source_table)
            })
    })
}

fn normalized_source_type(source_type: &str) -> &str {
    source_type
        .strip_prefix("configuration/sources/")
        .unwrap_or(source_type)
}

fn scan_replay_policy(scan: &EntityScanRequest, initial_policy: ReplayPolicy) -> ReplayPolicy {
    if scan.cursor.is_some() {
        ReplayPolicy::Unsafe
    } else {
        initial_policy
    }
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
    if scan.max > ENTITY_SCAN_PAGE_LIMIT {
        return Err(ReltioError::usage(
            "scan_page_size_too_large",
            format!(
                "entity scan page size must not exceed the reviewed {ENTITY_SCAN_PAGE_LIMIT}-entity response ceiling"
            ),
        )
        .with_details(json!({
            "requested_page_size": scan.max,
            "maximum_page_size": ENTITY_SCAN_PAGE_LIMIT,
            "practice_id": "ENTITY-SCAN-PAGE-LIMIT-001"
        })));
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
    validate_scan_options(&scan.options)?;
    validate_activeness(scan.activeness.as_deref())
}

pub fn validate_scan_option_acknowledgement(
    options: &[String],
    allow_unverified_options: bool,
) -> Result<()> {
    if options.is_empty() {
        if allow_unverified_options {
            return Err(ReltioError::usage(
                "scan_option_acknowledgement_inapplicable",
                "--allow-unverified-scan-options requires at least one scan option",
            ));
        }
        return Ok(());
    }
    if allow_unverified_options {
        return Ok(());
    }
    Err(ReltioError::new(
        "unverified_scan_options_refused",
        ErrorCategory::Safety,
        "entity scan options are not enabled without explicit acknowledgement of the unresolved route contract",
    )
    .with_details(json!({
        "options": options,
        "documented_route": "/entities/_scan",
        "option_schema_route": "/entities/v2/_scan",
        "network_request_sent": false,
        "local_state_committed": false,
        "safe_to_replay": true
    }))
    .with_hint("Pilot the option against a non-production tenant, then repeat with --allow-unverified-scan-options."))
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

fn validate_required_query_text(value: &str, field: &str) -> Result<()> {
    validate_nonempty_query_text(Some(value), field)?;
    if value.trim() != value || value.chars().all(char::is_whitespace) {
        return Err(ReltioError::usage(
            "invalid_query_value",
            format!("{field} must not have leading or trailing whitespace"),
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

fn validate_scan_options(options: &[String]) -> Result<()> {
    validate_options(options)?;
    if let Some(option) = options
        .iter()
        .find(|option| !ENTITY_SCAN_OPTIONS.contains(&option.as_str()))
    {
        return Err(ReltioError::usage(
            "invalid_scan_option",
            format!(
                "entity scan option {option:?} is outside the conservative locked-OpenAPI allowlist"
            ),
        )
        .with_details(json!({ "allowed": ENTITY_SCAN_OPTIONS })));
    }
    if options.iter().any(|option| option == "ovOnly")
        && options.iter().any(|option| option == "nonOvOnly")
    {
        return Err(ReltioError::usage(
            "scan_option_conflict",
            "ovOnly and nonOvOnly are mutually exclusive",
        ));
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
    fn entity_scan_page_limit_is_enforced() {
        let valid = EntityScanRequest {
            filter: Some("equals(type,'configuration/entityTypes/Organization')".to_owned()),
            cursor: None,
            max: ENTITY_SCAN_PAGE_LIMIT,
            select: None,
            options: Vec::new(),
            activeness: None,
        };
        validate_scan(&valid).expect("the reviewed scan ceiling is accepted");

        let invalid = EntityScanRequest {
            max: ENTITY_SCAN_PAGE_LIMIT + 1,
            ..valid
        };
        let error = validate_scan(&invalid).expect_err("oversized scan pages fail locally");
        assert_eq!(error.code, "scan_page_size_too_large");
        assert_eq!(error.details["practice_id"], "ENTITY-SCAN-PAGE-LIMIT-001");
    }

    #[test]
    fn entity_scan_options_match_the_reviewed_openapi_intersection() {
        let valid = EntityScanRequest {
            filter: Some("equals(type,'configuration/entityTypes/Organization')".to_owned()),
            cursor: None,
            max: 100,
            select: None,
            options: ENTITY_SCAN_OPTIONS
                .iter()
                .map(|option| (*option).to_owned())
                .collect(),
            activeness: None,
        };
        let mut each_option = valid.clone();
        for option in ENTITY_SCAN_OPTIONS {
            each_option.options = vec![(*option).to_owned()];
            validate_scan(&each_option).expect("reviewed scan option");
        }

        let mut unknown = valid.clone();
        unknown.options = vec!["futureOption".to_owned()];
        assert_eq!(
            validate_scan(&unknown)
                .expect_err("unknown option fails")
                .code,
            "invalid_scan_option"
        );

        let mut conflict = valid;
        conflict.options = vec!["ovOnly".to_owned(), "nonOvOnly".to_owned()];
        assert_eq!(
            validate_scan(&conflict)
                .expect_err("conflicting options fail")
                .code,
            "scan_option_conflict"
        );
    }

    #[test]
    fn entity_scan_continuations_are_never_replayed_automatically() {
        let initial = EntityScanRequest {
            filter: Some("equals(type,'configuration/entityTypes/Organization')".to_owned()),
            cursor: None,
            max: 100,
            select: None,
            options: Vec::new(),
            activeness: None,
        };
        assert_eq!(
            scan_replay_policy(&initial, ReplayPolicy::Conditional),
            ReplayPolicy::Conditional
        );

        let continuation = EntityScanRequest {
            filter: None,
            cursor: Some("cursor-value".to_owned()),
            ..initial
        };
        assert_eq!(
            scan_replay_policy(&continuation, ReplayPolicy::Conditional),
            ReplayPolicy::Unsafe
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

    #[test]
    fn crosswalk_lookup_rejects_special_values_and_disjoint_ov_options() {
        let valid = EntityByCrosswalkRequest {
            value: "source-id_1.2~3".to_owned(),
            source_type: "configuration/sources/CRM".to_owned(),
            source_table: Some("contacts".to_owned()),
            options: vec!["sendHidden".to_owned(), "ovOnly".to_owned()],
        };
        validate_by_crosswalk(&valid).expect("narrowed GET contract is accepted");

        let mut special = valid.clone();
        special.value = "source|id".to_owned();
        assert_eq!(
            validate_by_crosswalk(&special)
                .expect_err("special values require POST")
                .code,
            "crosswalk_value_requires_post"
        );

        let mut conflict = valid;
        conflict.options = vec!["ovOnly".to_owned(), "nonOvOnly".to_owned()];
        assert_eq!(
            validate_by_crosswalk(&conflict)
                .expect_err("OV options are mutually exclusive")
                .code,
            "crosswalk_option_conflict"
        );
    }

    #[test]
    fn crosswalk_fallback_detection_normalizes_source_type_shorthand() {
        let lookup = EntityByCrosswalkRequest {
            value: "customer-123".to_owned(),
            source_type: "CRM".to_owned(),
            source_table: Some("contacts".to_owned()),
            options: Vec::new(),
        };
        let entries = vec![json!({
            "successful": true,
            "object": {
                "crosswalks": [{
                    "value": "customer-123",
                    "type": "configuration/sources/CRM",
                    "sourceTable": "contacts"
                }]
            }
        })];

        assert!(!entity_by_crosswalk_id_fallback_detected(&entries, &lookup));
    }

    #[test]
    fn history_bounds_the_retrievable_window_and_rejects_ignored_filters() {
        let valid = EntityHistoryRequest {
            offset: 950,
            max: 50,
            ..EntityHistoryRequest::default()
        };
        validate_history("entities/1", &valid).expect("last retrievable window is accepted");

        let beyond_boundary = EntityHistoryRequest {
            offset: 951,
            max: 50,
            ..EntityHistoryRequest::default()
        };
        assert_eq!(
            validate_history("1", &beyond_boundary)
                .expect_err("history cannot paginate beyond 1,000")
                .code,
            "entity_history_boundary_exceeded"
        );

        let ignored_filter = EntityHistoryRequest {
            filter: Some("equals(type,'ENTITY_CHANGED')".to_owned()),
            show_all: true,
            ..EntityHistoryRequest::default()
        };
        assert_eq!(
            validate_history("1", &ignored_filter)
                .expect_err("showAll would ignore the filter")
                .code,
            "history_filter_ignored"
        );
    }

    #[test]
    fn matches_enforce_the_positive_direct_contract() {
        let valid = EntityMatchesRequest {
            max: 10_000,
            offset: 10,
            match_type: Some("suspect".to_owned()),
        };
        validate_matches("entities/1", &valid).expect("positive max and reviewed match type");

        let zero = EntityMatchesRequest {
            max: 0,
            ..EntityMatchesRequest::default()
        };
        assert_eq!(
            validate_matches("1", &zero)
                .expect_err("zero match page must fail")
                .code,
            "invalid_matches_page_size"
        );

        let custom_action = EntityMatchesRequest {
            match_type: Some("custom_action".to_owned()),
            ..EntityMatchesRequest::default()
        };
        assert_eq!(
            validate_matches("1", &custom_action)
                .expect_err("custom actions are deferred")
                .code,
            "invalid_match_type"
        );
    }
}

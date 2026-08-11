use std::{borrow::Cow, sync::OnceLock};

use memchr::memmem;
use percent_encoding::percent_decode_str;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use url::Url;

use crate::streaming_redaction::{inspect_canonical_bytes, inspect_canonical_iter};

const REDACTED: &str = "[REDACTED]";
const MAX_CANONICAL_TEXT_BYTES: usize = 1024 * 1024;
const MAX_TWO_LAYER_SOURCE_EXPANSION: usize = 36;
const MIN_CANONICAL_WINDOW_RADIUS: usize = 512;

#[derive(Clone, Default)]
pub struct OutputGuard {
    secrets: Vec<SecretString>,
    deny_all: bool,
}

impl std::fmt::Debug for OutputGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutputGuard")
            .field("secret_count", &self.secrets.len())
            .field("deny_all", &self.deny_all)
            .finish()
    }
}

impl OutputGuard {
    pub(crate) fn new(secrets: Vec<SecretString>) -> Self {
        Self {
            secrets,
            deny_all: false,
        }
    }

    pub fn deny_all() -> Self {
        Self {
            secrets: Vec::new(),
            deny_all: true,
        }
    }

    pub fn from_known_secrets(secrets: &[&str]) -> Self {
        Self::new(
            ordered_secrets(secrets)
                .into_iter()
                .map(|secret| secret.to_owned().into())
                .collect(),
        )
    }

    pub fn merge(&mut self, other: &Self) {
        self.deny_all |= other.deny_all;
        for secret in &other.secrets {
            let exposed = secret.expose_secret();
            if !self
                .secrets
                .iter()
                .any(|current| current.expose_secret() == exposed)
            {
                self.secrets.push(exposed.to_owned().into());
            }
        }
    }

    #[must_use]
    pub fn excluding_secret(&self, excluded: &str) -> Self {
        Self {
            secrets: self
                .secrets
                .iter()
                .filter(|secret| secret.expose_secret() != excluded)
                .cloned()
                .collect(),
            deny_all: self.deny_all,
        }
    }

    pub fn permits(&self, bytes: &[u8]) -> bool {
        if self.deny_all {
            return false;
        }
        let secrets = self.known_secrets();
        !contains_known_secret(bytes, &secrets)
    }

    pub fn permits_with_suffix(&self, bytes: &[u8], suffix: &[u8]) -> bool {
        if self.deny_all {
            return false;
        }
        if suffix.is_empty() {
            return self.permits(bytes);
        }
        let known_secrets = self.known_secrets();
        let secrets = ordered_secrets(&known_secrets);
        if secrets.is_empty() {
            return true;
        }
        if !self.permits(bytes) {
            return false;
        }
        let radius = canonical_window_radius(bytes.len(), &secrets);
        let input = bytes[bytes.len().saturating_sub(radius)..]
            .iter()
            .copied()
            .chain(suffix.iter().copied());
        let (sensitive, fully_decoded) = inspect_canonical_iter(&input, &secrets);
        !sensitive && fully_decoded
    }

    pub fn safe_json_fallback(&self) -> Vec<u8> {
        self.safe_json_fallback_with_suffix(&[])
    }

    pub fn safe_json_fallback_with_suffix(&self, suffix: &[u8]) -> Vec<u8> {
        for number in 0_u64..=1_024 {
            let bytes = number.to_string().into_bytes();
            if self.permits_with_suffix(&bytes, suffix) {
                return bytes;
            }
        }
        Vec::new()
    }

    pub(crate) fn append_secrets_to(&self, target: &mut Vec<SecretString>) {
        for secret in &self.secrets {
            let exposed = secret.expose_secret();
            if !target
                .iter()
                .any(|current| current.expose_secret() == exposed)
            {
                target.push(exposed.to_owned().into());
            }
        }
    }

    fn known_secrets(&self) -> Vec<&str> {
        self.secrets
            .iter()
            .map(ExposeSecret::expose_secret)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionOutcome {
    changed: bool,
    complete: bool,
}

impl RedactionOutcome {
    const UNCHANGED: Self = Self {
        changed: false,
        complete: true,
    };

    const fn changed() -> Self {
        Self {
            changed: true,
            complete: true,
        }
    }

    const fn incomplete() -> Self {
        Self {
            changed: true,
            complete: false,
        }
    }

    fn merge(&mut self, other: Self) {
        self.changed |= other.changed;
        self.complete &= other.complete;
    }

    pub const fn was_changed(self) -> bool {
        self.changed
    }

    pub const fn is_complete(self) -> bool {
        self.complete
    }
}

pub fn redact_json(value: &mut Value, known_secrets: &[&str]) -> RedactionOutcome {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    redact_json_for(value, &secrets, marker)
}

fn redact_json_for(value: &mut Value, secrets: &[&str], marker: &str) -> RedactionOutcome {
    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            let mut next_suffix = 2_u64;
            let mut outcome = RedactionOutcome::UNCHANGED;
            for (key, mut child) in entries {
                if sensitive_key(&key) {
                    let replacement = Value::String(marker.to_owned());
                    outcome.changed |= child != replacement;
                    child = replacement;
                } else {
                    outcome.merge(redact_json_for(&mut child, secrets, marker));
                    if !outcome.is_complete() {
                        return outcome;
                    }
                }
                let (redacted_key, key_changed) = redact_json_key(key, secrets, marker);
                outcome.changed |= key_changed;
                outcome.merge(insert_unique(
                    object,
                    &mut next_suffix,
                    redacted_key,
                    child,
                    secrets,
                    marker,
                ));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::Array(values) => {
            let mut outcome = RedactionOutcome::UNCHANGED;
            for child in values {
                outcome.merge(redact_json_for(child, secrets, marker));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::String(text) => {
            let redacted = redact_text_for(text, secrets, marker);
            if redacted == *text {
                RedactionOutcome::UNCHANGED
            } else {
                *text = redacted;
                RedactionOutcome::changed()
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            redact_known_secret_scalar_for(value, secrets, marker)
        }
    }
}

pub fn redact_known_secrets_json(value: &mut Value, known_secrets: &[&str]) -> RedactionOutcome {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    redact_known_secrets_json_for(value, &secrets, marker)
}

fn redact_known_secrets_json_for(
    value: &mut Value,
    secrets: &[&str],
    marker: &str,
) -> RedactionOutcome {
    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            let mut next_suffix = 2_u64;
            let mut outcome = RedactionOutcome::UNCHANGED;
            for (key, mut child) in entries {
                outcome.merge(redact_known_secrets_json_for(&mut child, secrets, marker));
                if !outcome.is_complete() {
                    return outcome;
                }
                let (redacted_key, key_changed) = redact_json_key(key, secrets, marker);
                outcome.changed |= key_changed;
                outcome.merge(insert_unique(
                    object,
                    &mut next_suffix,
                    redacted_key,
                    child,
                    secrets,
                    marker,
                ));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::Array(values) => {
            let mut outcome = RedactionOutcome::UNCHANGED;
            for child in values {
                outcome.merge(redact_known_secrets_json_for(child, secrets, marker));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::String(text) => redact_json_string(text, secrets, marker),
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            redact_known_secret_scalar_for(value, secrets, marker)
        }
    }
}

/// Redact exact credentials plus credential-shaped fields from a raw structured response.
///
/// This deliberately excludes broad diagnostic heuristics such as `password=...`, which
/// would corrupt ordinary Reltio entity data.
pub fn redact_response_json(value: &mut Value, known_secrets: &[&str]) -> RedactionOutcome {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    redact_response_json_for(value, &secrets, marker)
}

fn redact_response_json_for(value: &mut Value, secrets: &[&str], marker: &str) -> RedactionOutcome {
    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            let mut next_suffix = 2_u64;
            let mut outcome = RedactionOutcome::UNCHANGED;
            for (key, mut child) in entries {
                if response_credential_key(&key) {
                    let replacement = Value::String(marker.to_owned());
                    outcome.changed |= child != replacement;
                    child = replacement;
                } else {
                    outcome.merge(redact_response_json_for(&mut child, secrets, marker));
                    if !outcome.is_complete() {
                        return outcome;
                    }
                }
                let (redacted_key, key_changed) = redact_json_key(key, secrets, marker);
                outcome.changed |= key_changed;
                outcome.merge(insert_unique(
                    object,
                    &mut next_suffix,
                    redacted_key,
                    child,
                    secrets,
                    marker,
                ));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::Array(values) => {
            let mut outcome = RedactionOutcome::UNCHANGED;
            for child in values {
                outcome.merge(redact_response_json_for(child, secrets, marker));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::String(text) => redact_json_string(text, secrets, marker),
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            redact_known_secret_scalar_for(value, secrets, marker)
        }
    }
}

pub fn redact_text(text: &str, known_secrets: &[&str]) -> String {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    redact_text_for(text, &secrets, marker)
}

fn redact_text_for(text: &str, secrets: &[&str], marker: &str) -> String {
    let redacted = redact_known_secrets_text_for(text, secrets, marker);
    let (sensitive, fully_decoded) = inspect_canonical_forms(&redacted, |canonical| {
        redact_unencoded_text(canonical) != canonical
    });
    if sensitive || !fully_decoded {
        return marker.to_owned();
    }
    let redacted = redact_unencoded_text(&redacted);
    redact_known_secrets_text_for(&redacted, secrets, marker)
}

fn redact_unencoded_text(text: &str) -> String {
    let redacted = bearer_regex()
        .replace_all(text, "Bearer [REDACTED]")
        .into_owned();
    let redacted = basic_regex()
        .replace_all(&redacted, "Basic [REDACTED]")
        .into_owned();
    let redacted = sensitive_double_quoted_assignment_regex()
        .replace_all(&redacted, "${prefix}[REDACTED]")
        .into_owned();
    let redacted = sensitive_single_quoted_assignment_regex()
        .replace_all(&redacted, "${prefix}[REDACTED]")
        .into_owned();
    let redacted = sensitive_assignment_regex()
        .replace_all(&redacted, "${key}${separator}[REDACTED]")
        .into_owned();
    url_regex()
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            Url::parse(&captures[0]).map_or_else(
                |_| captures[0].to_owned(),
                |url| redact_url(&url).to_string(),
            )
        })
        .into_owned()
}

fn decode_json_escapes(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = String::with_capacity(text.len());
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if bytes[offset] != b'\\' {
            let character = text[offset..]
                .chars()
                .next()
                .unwrap_or_else(|| unreachable!("offset is on a UTF-8 boundary"));
            decoded.push(character);
            offset += character.len_utf8();
            continue;
        }
        let Some(escaped) = bytes.get(offset + 1).copied() else {
            decoded.push('\\');
            break;
        };
        let simple = match escaped {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            _ => None,
        };
        if let Some(character) = simple {
            decoded.push(character);
            offset += 2;
            continue;
        }
        if escaped == b'u' {
            if let Some((character, consumed)) = decode_unicode_escape(&bytes[offset..]) {
                decoded.push(character);
                offset += consumed;
                continue;
            }
        }
        decoded.push('\\');
        offset += 1;
    }
    decoded
}

fn decode_unicode_escape(bytes: &[u8]) -> Option<(char, usize)> {
    let first = decode_hex_quad(bytes.get(2..6)?)?;
    if (0xd800..=0xdbff).contains(&first) {
        if bytes.get(6..8) != Some(br"\u") {
            return None;
        }
        let second = decode_hex_quad(bytes.get(8..12)?)?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return None;
        }
        let scalar = 0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
        return char::from_u32(scalar).map(|character| (character, 12));
    }
    if (0xdc00..=0xdfff).contains(&first) {
        return None;
    }
    char::from_u32(u32::from(first)).map(|character| (character, 6))
}

fn decode_hex_quad(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0_u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a' + 10),
            b'A'..=b'F' => u16::from(byte - b'A' + 10),
            _ => return None,
        };
        Some((value << 4) | digit)
    })
}

pub fn redact_bytes(bytes: &[u8], known_secrets: &[&str]) -> Vec<u8> {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    if let Ok(text) = std::str::from_utf8(bytes) {
        return redact_known_secrets_text_for(text, &secrets, marker).into_bytes();
    }
    let mut redacted = bytes.to_vec();
    for secret in &secrets {
        if memmem::find(&redacted, secret.as_bytes()).is_some() {
            redacted = replace_bytes(&redacted, secret.as_bytes(), marker.as_bytes());
        }
    }
    if secrets
        .iter()
        .any(|secret| memmem::find(&redacted, secret.as_bytes()).is_some())
    {
        return marker.as_bytes().to_vec();
    }
    let Ok(text) = std::str::from_utf8(&redacted) else {
        let lossy = String::from_utf8_lossy(&redacted);
        if contains_encoded_secret_for(&lossy, &secrets) {
            return marker.as_bytes().to_vec();
        }
        return redacted;
    };
    redact_known_secrets_text_for(text, &secrets, marker).into_bytes()
}

fn redact_known_secrets_text_for(text: &str, secrets: &[&str], marker: &str) -> String {
    redact_known_secrets_text_cow(text, secrets, marker).into_owned()
}

fn redact_known_secrets_text_cow<'a>(
    text: &'a str,
    secrets: &[&str],
    marker: &str,
) -> Cow<'a, str> {
    if secrets.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut redacted = Cow::Borrowed(text);
    for secret in secrets {
        if redacted.contains(secret) {
            redacted = Cow::Owned(redacted.replace(secret, marker));
        }
    }
    if secrets.iter().any(|secret| redacted.contains(secret)) {
        return Cow::Owned(marker.to_owned());
    }
    if contains_encoded_secret_for(&redacted, secrets) {
        return Cow::Owned(marker.to_owned());
    }
    redacted
}

fn redact_json_key(key: String, secrets: &[&str], marker: &str) -> (String, bool) {
    match redact_known_secrets_text_cow(&key, secrets, marker) {
        Cow::Borrowed(_) => (key, false),
        Cow::Owned(redacted) => {
            let changed = redacted != key;
            (redacted, changed)
        }
    }
}

fn redact_json_string(text: &mut String, secrets: &[&str], marker: &str) -> RedactionOutcome {
    match redact_known_secrets_text_cow(text, secrets, marker) {
        Cow::Borrowed(_) => RedactionOutcome::UNCHANGED,
        Cow::Owned(redacted) => {
            if redacted == *text {
                RedactionOutcome::UNCHANGED
            } else {
                *text = redacted;
                RedactionOutcome::changed()
            }
        }
    }
}

fn contains_encoded_secret_for(text: &str, secrets: &[&str]) -> bool {
    let (sensitive, fully_decoded) = inspect_canonical_forms(text, |canonical| {
        secrets.iter().any(|secret| canonical.contains(secret))
    });
    sensitive || !fully_decoded
}

pub(crate) fn contains_known_secret(bytes: &[u8], known_secrets: &[&str]) -> bool {
    let secrets = ordered_secrets(known_secrets);
    if secrets.is_empty() {
        return false;
    }
    if secrets
        .iter()
        .any(|secret| memmem::find(bytes, secret.as_bytes()).is_some())
    {
        return true;
    }
    if !bytes.iter().any(|byte| matches!(byte, b'\\' | b'%' | b'+')) {
        return false;
    }
    let (sensitive, fully_decoded) = inspect_canonical_windows(bytes, &secrets);
    sensitive || !fully_decoded
}

fn inspect_canonical_windows(bytes: &[u8], secrets: &[&str]) -> (bool, bool) {
    let radius = canonical_window_radius(bytes.len(), secrets);
    let mut window = None::<(usize, usize)>;
    let mut fully_decoded = true;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'\\' | b'%' | b'+') {
            continue;
        }
        let start = offset.saturating_sub(radius);
        let end = offset
            .saturating_add(radius)
            .saturating_add(1)
            .min(bytes.len());
        if let Some((window_start, window_end)) = window {
            if start <= window_end {
                window = Some((window_start, window_end.max(end)));
                continue;
            }
            let (sensitive, complete) =
                inspect_canonical_bytes(&bytes[window_start..window_end], secrets);
            if sensitive {
                return (true, true);
            }
            fully_decoded &= complete;
        }
        window = Some((start, end));
    }
    if let Some((start, end)) = window {
        let (sensitive, complete) = inspect_canonical_bytes(&bytes[start..end], secrets);
        if sensitive {
            return (true, true);
        }
        fully_decoded &= complete;
    }
    (false, fully_decoded)
}

fn canonical_window_radius(input_len: usize, secrets: &[&str]) -> usize {
    let maximum_secret = secrets
        .iter()
        .map(|secret| secret.len())
        .max()
        .unwrap_or_default();
    // A two-layer JSON/percent/form representation consumes at most 36 source
    // bytes per decoded byte. Any newly decoded match must overlap encoding
    // syntax, so this padding contains the complete source for that match. The
    // fixed minimum also contains any syntax that remains after two layers.
    maximum_secret
        .saturating_mul(MAX_TWO_LAYER_SOURCE_EXPANSION)
        .saturating_add(24)
        .max(MIN_CANONICAL_WINDOW_RADIUS)
        .min(input_len)
}

pub(crate) fn sanitize_json_serialization(
    value: &mut Value,
    known_secrets: &[&str],
) -> Option<bool> {
    sanitize_json_serialization_for(value, known_secrets, true)
}

pub(crate) fn sanitize_json_compact_serialization(
    value: &mut Value,
    known_secrets: &[&str],
) -> Option<bool> {
    sanitize_json_serialization_for(value, known_secrets, false)
}

fn sanitize_json_serialization_for(
    value: &mut Value,
    known_secrets: &[&str],
    check_pretty: bool,
) -> Option<bool> {
    let secrets = ordered_secrets(known_secrets);
    let marker = redaction_marker_for(&secrets);
    let outcome = redact_json_serialization_fragments(value, &secrets, marker);
    if !outcome.is_complete() {
        return None;
    }
    if serialized_value_is_safe(value, known_secrets, check_pretty) {
        return Some(outcome.was_changed());
    }
    for number in 0_u64..=1_024 {
        let candidate = Value::from(number);
        if serialized_value_is_safe(&candidate, known_secrets, check_pretty) {
            *value = candidate;
            return Some(true);
        }
    }
    for candidate in [
        Value::Null,
        Value::Bool(false),
        Value::Bool(true),
        Value::String(String::new()),
        Value::Array(Vec::new()),
        Value::Object(Map::new()),
    ] {
        if serialized_value_is_safe(&candidate, known_secrets, check_pretty) {
            *value = candidate;
            return Some(true);
        }
    }
    None
}

fn redact_json_serialization_fragments(
    value: &mut Value,
    secrets: &[&str],
    marker: &str,
) -> RedactionOutcome {
    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            let mut next_suffix = 2_u64;
            let mut outcome = RedactionOutcome::UNCHANGED;
            for (key, mut child) in entries {
                outcome.merge(redact_json_serialization_fragments(
                    &mut child, secrets, marker,
                ));
                if !outcome.is_complete() {
                    return outcome;
                }
                let (redacted_key, key_changed) =
                    if json_string_fragment_contains_secret(&key, secrets) {
                        (marker.to_owned(), key != marker)
                    } else {
                        (key, false)
                    };
                outcome.changed |= key_changed;
                outcome.merge(insert_unique(
                    object,
                    &mut next_suffix,
                    redacted_key,
                    child,
                    secrets,
                    marker,
                ));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::Array(values) => {
            let mut outcome = RedactionOutcome::UNCHANGED;
            for child in values {
                outcome.merge(redact_json_serialization_fragments(child, secrets, marker));
                if !outcome.is_complete() {
                    return outcome;
                }
            }
            outcome
        }
        Value::String(text) => {
            if json_string_fragment_contains_secret(text, secrets) {
                marker.clone_into(text);
                RedactionOutcome::changed()
            } else {
                RedactionOutcome::UNCHANGED
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            let serialized = serde_json::to_vec(value)
                .unwrap_or_else(|_| unreachable!("a JSON scalar is always serializable"));
            if contains_known_secret(&serialized, secrets) {
                *value = Value::String(marker.to_owned());
                RedactionOutcome::changed()
            } else {
                RedactionOutcome::UNCHANGED
            }
        }
    }
}

fn json_string_fragment_contains_secret(text: &str, secrets: &[&str]) -> bool {
    if secrets.is_empty() {
        return false;
    }
    if !text
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || matches!(byte, b'"' | b'\\' | b'%' | b'+'))
    {
        return plain_json_string_contains_secret(text, secrets);
    }
    let serialized = serde_json::to_vec(text)
        .unwrap_or_else(|_| unreachable!("a UTF-8 string is always JSON serializable"));
    contains_known_secret(&serialized, secrets)
}

fn plain_json_string_contains_secret(text: &str, secrets: &[&str]) -> bool {
    let bytes = text.as_bytes();
    let virtual_len = bytes.len().saturating_add(2);
    secrets.iter().any(|secret| {
        let secret = secret.as_bytes();
        if secret.is_empty() || secret.len() > virtual_len {
            return false;
        }
        if memmem::find(bytes, secret).is_some() {
            return true;
        }
        virtual_json_match(bytes, secret, 0)
            || virtual_json_match(bytes, secret, virtual_len - secret.len())
    })
}

fn virtual_json_match(text: &[u8], secret: &[u8], start: usize) -> bool {
    secret
        .iter()
        .copied()
        .enumerate()
        .all(|(offset, expected)| {
            let index = start + offset;
            let actual = if index == 0 || index == text.len() + 1 {
                b'"'
            } else {
                text[index - 1]
            };
            actual == expected
        })
}

fn serialized_value_is_safe(value: &Value, known_secrets: &[&str], check_pretty: bool) -> bool {
    let compact = serde_json::to_vec(value)
        .unwrap_or_else(|_| unreachable!("a serde_json::Value is always serializable"));
    if contains_known_secret(&compact, known_secrets) {
        return false;
    }
    if !check_pretty {
        return true;
    }
    drop(compact);
    let pretty = serde_json::to_vec_pretty(value)
        .unwrap_or_else(|_| unreachable!("a serde_json::Value is always serializable"));
    !contains_known_secret(&pretty, known_secrets)
}

fn canonicalize_encoded_text(text: &str) -> (String, bool) {
    canonicalize_with(text, false)
}

fn inspect_canonical_forms(text: &str, mut inspect: impl FnMut(&str) -> bool) -> (bool, bool) {
    if !has_encoding_syntax(text) {
        return (false, true);
    }
    if text.len() > MAX_CANONICAL_TEXT_BYTES {
        return (false, false);
    }
    let mut decoded_any = false;
    let mut fully_decoded = true;
    for variant in DECODE_VARIANTS {
        let first = decode_variant(text, variant);
        if first == text {
            continue;
        }
        decoded_any = true;
        if inspect(&first) {
            return (true, true);
        }
        for second_variant in DECODE_VARIANTS {
            let second = decode_variant(&first, second_variant);
            if second == first {
                continue;
            }
            if inspect(&second) {
                return (true, true);
            }
            if has_decodable_variant(&second) {
                fully_decoded = false;
            }
        }
    }
    (false, !decoded_any || fully_decoded)
}

fn canonicalize_with(text: &str, plus_as_space: bool) -> (String, bool) {
    if text.len() > MAX_CANONICAL_TEXT_BYTES && has_encoding_syntax(text) {
        return (String::new(), false);
    }
    let mut canonical = text.to_owned();
    for _ in 0..2 {
        let decoded = decode_combined_layer(&canonical, plus_as_space);
        if decoded == canonical {
            return (canonical, true);
        }
        canonical = decoded;
    }
    let fully_decoded = decode_combined_layer(&canonical, plus_as_space) == canonical;
    (canonical, fully_decoded)
}

fn has_encoding_syntax(text: &str) -> bool {
    text.as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\\' | b'%' | b'+'))
}

#[derive(Clone, Copy)]
enum DecodeVariant {
    Json,
    Percent,
    Form,
}

const DECODE_VARIANTS: [DecodeVariant; 3] = [
    DecodeVariant::Json,
    DecodeVariant::Percent,
    DecodeVariant::Form,
];

fn decode_variant(text: &str, variant: DecodeVariant) -> String {
    match variant {
        DecodeVariant::Json => decode_json_escapes(text),
        DecodeVariant::Percent => percent_decode_str(text).decode_utf8_lossy().into_owned(),
        DecodeVariant::Form => percent_decode_str(&text.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned(),
    }
}

fn has_decodable_variant(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        match bytes[offset] {
            b'+' => return true,
            b'%' if bytes.get(offset + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(offset + 2).is_some_and(u8::is_ascii_hexdigit) =>
            {
                return true;
            }
            b'\\' => {
                if matches!(
                    bytes.get(offset + 1),
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't')
                ) || bytes.get(offset + 1) == Some(&b'u')
                    && decode_unicode_escape(&bytes[offset..]).is_some()
                {
                    return true;
                }
            }
            _ => {}
        }
        offset += 1;
    }
    false
}

fn decode_combined_layer(text: &str, plus_as_space: bool) -> String {
    let mut json_decoded = decode_json_escapes(text);
    if plus_as_space {
        json_decoded = json_decoded.replace('+', " ");
    }
    percent_decode_str(&json_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

fn redaction_marker_for(secrets: &[&str]) -> &'static str {
    if secrets
        .iter()
        .any(|secret| secret.len() < REDACTED.len() || REDACTED.contains(secret))
    {
        ""
    } else {
        REDACTED
    }
}

fn redact_known_secret_scalar_for(
    value: &mut Value,
    secrets: &[&str],
    marker: &str,
) -> RedactionOutcome {
    let rendered = match value {
        Value::Null => "null".to_owned(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(_) | Value::Array(_) | Value::Object(_) => {
            return RedactionOutcome::UNCHANGED;
        }
    };
    if secrets.iter().any(|secret| rendered.contains(secret)) {
        *value = Value::String(marker.to_owned());
        RedactionOutcome::changed()
    } else {
        RedactionOutcome::UNCHANGED
    }
}

fn ordered_secrets<'a>(known_secrets: &'a [&'a str]) -> Vec<&'a str> {
    let mut secrets = known_secrets
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    secrets
        .sort_unstable_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    secrets.dedup();
    secrets
}

fn insert_unique(
    object: &mut Map<String, Value>,
    next_suffix: &mut u64,
    key: String,
    value: Value,
    secrets: &[&str],
    marker: &str,
) -> RedactionOutcome {
    if !object.contains_key(&key) {
        object.insert(key, value);
        return RedactionOutcome::UNCHANGED;
    }
    let attempts = object.len().saturating_add(1);
    for _ in 0..attempts {
        let suffix = *next_suffix;
        *next_suffix = next_suffix
            .checked_add(1)
            .unwrap_or_else(|| unreachable!("a finite JSON object cannot exhaust key suffixes"));
        let candidate = redact_known_secrets_text_for(&format!("{key}#{suffix}"), secrets, marker);
        if !object.contains_key(&candidate) {
            object.insert(candidate, value);
            return RedactionOutcome::changed();
        }
    }
    RedactionOutcome::incomplete()
}

fn response_credential_key(key: &str) -> bool {
    let Some(normalized) = normalized_key_summary(key) else {
        return true;
    };
    [
        "authorization",
        "cookie",
        "setcookie",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "statetoken",
        "authorizationcode",
        "apikey",
        "xapikey",
    ]
    .into_iter()
    .any(|candidate| normalized.equals(candidate))
        || normalized.ends_with("signature")
        || normalized.ends_with("credential")
}

pub fn redact_url(url: &Url) -> Url {
    let mut redacted = url.clone();
    if !redacted.username().is_empty() {
        let _ = redacted.set_username(REDACTED);
    }
    if redacted.password().is_some() {
        let _ = redacted.set_password(Some(REDACTED));
    }
    let pairs = redacted
        .query_pairs()
        .map(|(key, value)| {
            let value = if sensitive_query_key(&key) {
                REDACTED.to_owned()
            } else {
                value.into_owned()
            };
            (key.into_owned(), value)
        })
        .collect::<Vec<_>>();
    if redacted.query().is_some() {
        redacted.set_query(None);
        let mut query = redacted.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(&key, &value);
        }
    }
    if redacted.fragment().is_some() {
        redacted.set_fragment(Some(REDACTED));
    }
    redacted
}

pub fn sensitive_header(name: &str) -> bool {
    let normalized = normalize_key(name);
    sensitive_normalized_key(&normalized)
        || matches!(
            normalized.as_str(),
            "proxyauthorization" | "xapikey" | "xauthcredential"
        )
        || normalized.ends_with("credential")
        || normalized.ends_with("signature")
}

pub fn sensitive_query_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    sensitive_normalized_key(&normalized)
        || matches!(
            normalized.as_str(),
            "code"
                | "apikey"
                | "credential"
                | "signature"
                | "sig"
                | "xamzcredential"
                | "xamzsignature"
                | "xgoogcredential"
                | "xgoogsignature"
                | "xapikey"
        )
        || normalized.ends_with("signature")
}

fn sensitive_key(key: &str) -> bool {
    let Some(normalized) = normalized_key_summary(key) else {
        return true;
    };
    [
        "authorization",
        "cookie",
        "setcookie",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "password",
        "otp",
        "statetoken",
        "authorizationcode",
        "apikey",
        "credential",
    ]
    .into_iter()
    .any(|candidate| normalized.equals(candidate))
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
}

const NORMALIZED_KEY_EDGE_BYTES: usize = 32;

struct NormalizedKeySummary {
    first: [u8; NORMALIZED_KEY_EDGE_BYTES],
    first_len: usize,
    tail: [u8; NORMALIZED_KEY_EDGE_BYTES],
    tail_next: usize,
    tail_len: usize,
    len: usize,
}

impl NormalizedKeySummary {
    fn new(text: &str) -> Self {
        let mut summary = Self {
            first: [0; NORMALIZED_KEY_EDGE_BYTES],
            first_len: 0,
            tail: [0; NORMALIZED_KEY_EDGE_BYTES],
            tail_next: 0,
            tail_len: 0,
            len: 0,
        };
        for byte in text.bytes().filter(u8::is_ascii_alphanumeric) {
            let byte = byte.to_ascii_lowercase();
            if summary.first_len < summary.first.len() {
                summary.first[summary.first_len] = byte;
                summary.first_len += 1;
            }
            summary.tail[summary.tail_next] = byte;
            summary.tail_next = (summary.tail_next + 1) % summary.tail.len();
            summary.tail_len = summary.tail_len.saturating_add(1).min(summary.tail.len());
            summary.len += 1;
        }
        summary
    }

    fn equals(&self, expected: &str) -> bool {
        self.len == expected.len() && &self.first[..self.first_len] == expected.as_bytes()
    }

    fn ends_with(&self, expected: &str) -> bool {
        let expected = expected.as_bytes();
        if expected.len() > self.tail_len {
            return false;
        }
        expected
            .iter()
            .rev()
            .copied()
            .enumerate()
            .all(|(distance, byte)| {
                let index = (self.tail_next + self.tail.len() - 1 - distance) % self.tail.len();
                self.tail[index] == byte
            })
    }
}

fn normalized_key_summary(key: &str) -> Option<NormalizedKeySummary> {
    if !has_encoding_syntax(key) {
        return Some(NormalizedKeySummary::new(key));
    }
    let (canonical, fully_decoded) = canonicalize_encoded_text(key);
    fully_decoded.then(|| NormalizedKeySummary::new(&canonical))
}

fn normalize_key(key: &str) -> String {
    let (canonical, fully_decoded) = canonicalize_encoded_text(key);
    if !fully_decoded {
        return "credential".to_owned();
    }
    canonical
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn sensitive_normalized_key(normalized: &str) -> bool {
    matches!(
        normalized,
        "authorization"
            | "cookie"
            | "setcookie"
            | "accesstoken"
            | "refreshtoken"
            | "clientsecret"
            | "password"
            | "otp"
            | "statetoken"
            | "authorizationcode"
            | "apikey"
            | "credential"
    ) || normalized.ends_with("secret")
        || normalized.ends_with("token")
}

fn bearer_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+").expect("static regex is valid")
    })
}

fn basic_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)Basic\s+[A-Za-z0-9._~+/=-]+").expect("static regex is valid")
    })
}

fn sensitive_assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)(?<key>(?:access[_\s-]?token|refresh[_\s-]?token|state[_\s-]?token|client[_\s-]?secret|api[_\s-]?key|x-api-key|password|authorization[_\s-]?code|authorization|code|otp|credential|signature|x-amz-(?:credential|signature|security-token)|x-goog-(?:credential|signature)))(?<separator>\s*[=:]\s*)[^&\s,;>"']+"#,
        )
        .expect("static regex is valid")
    })
}

fn sensitive_double_quoted_assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)(?<prefix>"?(?:access[_\s-]?token|refresh[_\s-]?token|state[_\s-]?token|client[_\s-]?secret|api[_\s-]?key|x-api-key|password|authorization[_\s-]?code|authorization|code|otp|credential|signature|x-amz-(?:credential|signature|security-token)|x-goog-(?:credential|signature))"?\s*[=:]\s*")[^"]*"#,
        )
        .expect("static regex is valid")
    })
}

fn sensitive_single_quoted_assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(?<prefix>'?(?:access[_\s-]?token|refresh[_\s-]?token|state[_\s-]?token|client[_\s-]?secret|api[_\s-]?key|x-api-key|password|authorization[_\s-]?code|authorization|code|otp|credential|signature|x-amz-(?:credential|signature|security-token)|x-goog-(?:credential|signature))'?\s*[=:]\s*')[^']*",
        )
        .expect("static regex is valid")
    })
}

fn url_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"https?://[^\s<>\"']+"#).expect("static regex is valid"))
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut offset = 0;
    let finder = memmem::Finder::new(needle);
    while let Some(position) = finder.find(&haystack[offset..]) {
        let position = offset + position;
        output.extend_from_slice(&haystack[offset..position]);
        output.extend_from_slice(replacement);
        offset = position + needle.len();
    }
    output.extend_from_slice(&haystack[offset..]);
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redacts_opaque_multikilobyte_token() {
        let token = format!("s.{}", "a".repeat(4096));
        let mut value = json!({
            "message": format!("request used Bearer {token}"),
            "access_token": token,
            "safe": "visible"
        });
        redact_json(&mut value, &[]);
        let rendered = value.to_string();
        assert!(!rendered.contains("s.aaaa"));
        assert!(rendered.contains("visible"));
    }

    #[test]
    fn redacts_signed_urls_userinfo_and_fragments() {
        let text =
            "redirect https://user:pass@example.test/path?safe=yes&X-Amz-Signature=secret#token";
        let redacted = redact_text(text, &[]);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("#token"));
        assert!(redacted.contains("safe=yes"));
    }

    #[test]
    fn redacts_relative_query_assignments() {
        let redacted = redact_text(
            "/callback?code=one&state_token=two&otp=three&access_token=four",
            &[],
        );
        assert!(!redacted.contains("code=one"));
        assert!(!redacted.contains("state_token=two"));
        assert!(!redacted.contains("otp=three"));
        assert!(!redacted.contains("access_token=four"));
        assert!(sensitive_query_key("X-Amz-Signature"));
        assert!(sensitive_query_key("authorization_code"));
    }

    #[test]
    fn redacts_basic_credentials_and_token_like_headers() {
        let redacted = redact_text("proxy echoed Basic Y2xpZW50OnNlY3JldA==", &[]);
        assert_eq!(redacted, "proxy echoed Basic [REDACTED]");
        assert!(sensitive_header("Refresh-Token"));
        assert!(sensitive_header("X-Amz-Security-Token"));
        assert!(sensitive_header("Request-Signature"));
    }

    #[test]
    fn redacts_quoted_secret_assignments_and_generic_api_keys() {
        let redacted = redact_text(
            r#"malformed {"refresh_token":"upstream-refresh-secret", api_key='query-secret'"#,
            &[],
        );
        assert!(!redacted.contains("upstream-refresh-secret"));
        assert!(!redacted.contains("query-secret"));
        assert!(sensitive_query_key("api_key"));
        assert!(sensitive_query_key("X-API-Key"));
    }

    #[test]
    fn redacts_nested_json_escaped_known_secrets_in_text_diagnostics() {
        let redacted = redact_text(
            r"proxy echoed secret\u002dtoken and secret\\u002dtoken",
            &["secret-token"],
        );
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn percent_decoding_and_url_normalization_cannot_reintroduce_a_secret() {
        let redacted = redact_text(
            "request https://example.test/path?safe=secret%2Dtoken",
            &["secret-token"],
        );
        assert_eq!(redacted, "[REDACTED]");
        assert!(!redacted.contains("secret-token"));
    }

    #[test]
    fn encoded_known_secrets_and_diagnostic_assignments_fail_closed() {
        assert_eq!(
            redact_bytes(b"secret%2Dtoken", &["secret-token"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(b"secret+token", &["secret token"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(b"secret%2Btoken", &["secret+token"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(b"secret%252Dtoken", &["secret%2Dtoken"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(
                &[b"\xff".as_slice(), b"secret%2Dtoken"].concat(),
                &["secret-token"],
            ),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(br"secret\\u002dtoken", &[r"secret\u002dtoken"],),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(br"secret%2Dtoken\/suffix", &["secret%2Dtoken/suffix"],),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(br"secret\u00255Cu002dtoken", &["secret-token"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(b"secret%25252Dtoken", &["secret-token"]),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(
                &[b"\xff".as_slice(), br"secret\u00255Cu002dtoken"].concat(),
                &["secret-token"],
            ),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_bytes(
                &[b"\xff".as_slice(), br"secret%2Dtoken\/suffix"].concat(),
                &["secret%2Dtoken/suffix"],
            ),
            b"[REDACTED]"
        );
        assert_eq!(
            redact_text("refresh%5Ftoken=upstream-refresh-secret", &[]),
            "[REDACTED]"
        );
        assert_eq!(
            redact_text("refresh+token=upstream-refresh-secret", &[]),
            "[REDACTED]"
        );
        assert_eq!(
            redact_text(r"refresh_\\u0074oken=upstream-refresh-secret", &[]),
            "[REDACTED]"
        );
    }

    #[test]
    fn overencoded_success_data_is_redacted_conservatively() {
        let ordinary = b"ordinary=%252541";
        assert_eq!(redact_bytes(ordinary, &["unrelated-token"]), b"[REDACTED]");

        let mut value = json!({"ordinary": "ordinary=%252541"});
        redact_known_secrets_json(&mut value, &["unrelated-token"]);
        assert_eq!(value["ordinary"], "[REDACTED]");
    }

    #[test]
    fn nested_encoded_keys_values_and_credential_names_fail_closed() {
        let mut value = json!({
            r"secret\u002dtoken": "key value",
            "ordinary": r"secret\u002dtoken",
            r"refresh_\u0074oken": "upstream-refresh-secret"
        });
        redact_response_json(&mut value, &["secret-token"]);
        let rendered = value.to_string();
        assert!(!rendered.contains(r"secret\u002dtoken"));
        assert!(!rendered.contains("upstream-refresh-secret"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn deeply_nested_encoding_is_bounded_and_redacted_conservatively() {
        let mut encoded = "secret-token".to_owned();
        for _ in 0..20 {
            encoded = encoded.replace('\\', r"\\").replace('-', r"\u002d");
        }
        assert_eq!(redact_text(&encoded, &["secret-token"]), "[REDACTED]");

        let mut diagnostic = Value::Object(Map::from_iter([(
            encoded,
            Value::String("credential-value".to_owned()),
        )]));
        redact_json(&mut diagnostic, &[]);
        assert!(!diagnostic.to_string().contains("credential-value"));
    }

    #[test]
    fn collapsed_encoded_keys_are_preserved_with_linear_suffix_probing() {
        let mut value = Value::Object(
            (0..2_000)
                .map(|index| {
                    (
                        format!(r"refresh_\\\\u0074oken_{index}"),
                        Value::String(format!("credential-{index}")),
                    )
                })
                .collect(),
        );

        redact_response_json(&mut value, &["active-token"]);

        let object = value.as_object().expect("redacted object");
        assert_eq!(object.len(), 2_000);
        assert!(
            object
                .values()
                .all(|child| child == &Value::String("[REDACTED]".to_owned()))
        );
    }

    #[test]
    fn redaction_marker_never_reemits_a_short_active_secret() {
        assert_eq!(redact_text("credential RED", &["RED"]), "credential ");
        let mut value = json!({"access_token": "anything"});
        redact_response_json(&mut value, &["RED"]);
        assert_eq!(value["access_token"], "");
    }

    #[test]
    fn short_active_secret_cannot_expand_a_dense_response() {
        let text = "x".repeat(256 * 1024);
        assert!(redact_text(&text, &["x"]).is_empty());
        assert!(redact_bytes(text.as_bytes(), &["x"]).is_empty());
    }

    #[test]
    fn one_token_replacement_cannot_synthesize_another_active_token() {
        let secrets = ["RED", "prefixsuffix"];
        assert_eq!(redact_text("prefixREDsuffix", &secrets), "");
        assert_eq!(redact_bytes(b"prefixREDsuffix", &secrets), b"");

        let mut value = json!({"value": "prefixREDsuffix"});
        redact_known_secrets_json(&mut value, &secrets);
        assert_eq!(value["value"], "");
    }

    #[test]
    fn collision_suffixes_cannot_synthesize_active_tokens() {
        let secrets = ["first-secret", "second-secret", "[REDACTED]#2"];
        let mut value = json!({
            "first-secret": "left",
            "second-secret": "right"
        });
        redact_known_secrets_json(&mut value, &secrets);
        let rendered = value.to_string();
        assert!(secrets.iter().all(|secret| !rendered.contains(secret)));
        assert!(value.get("[REDACTED]#3").is_some());

        let mut short = json!({"2a": "left", "a2": "right"});
        redact_known_secrets_json(&mut short, &["2"]);
        assert!(!short.to_string().contains('2'));
        assert!(short.get("a#").is_some());
    }

    #[test]
    fn collision_probing_preserves_data_or_reports_incomplete_redaction() {
        let mut occupied = Map::new();
        occupied.insert(
            "[REDACTED]".to_owned(),
            Value::String("safe-original".to_owned()),
        );
        for suffix in 2..=65 {
            occupied.insert(
                format!("[REDACTED]#{suffix}"),
                Value::String(format!("safe-{suffix}")),
            );
        }
        occupied.insert(
            "zzzzzzzzzz".to_owned(),
            Value::String("redacted-key-value".to_owned()),
        );
        let mut value = Value::Object(occupied);
        let outcome = redact_known_secrets_json(&mut value, &["zzzzzzzzzz"]);
        assert!(outcome.is_complete());
        let object = value.as_object().expect("redacted object");
        assert_eq!(object.len(), 66);
        assert_eq!(object["[REDACTED]"], "safe-original");
        assert_eq!(object["[REDACTED]#66"], "redacted-key-value");

        let digit_secrets = (0..=9).map(|digit| digit.to_string()).collect::<Vec<_>>();
        let digit_secrets = digit_secrets.iter().map(String::as_str).collect::<Vec<_>>();
        let mut exhausted = json!({"0a": "left", "1a": "middle", "2a": "right"});
        let outcome = redact_known_secrets_json(&mut exhausted, &digit_secrets);
        assert!(!outcome.is_complete());
        assert_eq!(exhausted["a"], "left");
        assert_eq!(exhausted["a#"], "middle");
    }

    #[test]
    fn json_serialization_cannot_recreate_an_active_token() {
        let token = r#"longprefix\"longsuffix"#;
        let mut value = json!({"value": "longprefix\"longsuffix"});
        let outcome = redact_known_secrets_json(&mut value, &[token]);
        assert!(outcome.is_complete());
        assert_eq!(
            sanitize_json_serialization(&mut value, &[token]),
            Some(true)
        );
        let rendered = serde_json::to_vec_pretty(&value).expect("JSON");
        assert!(!contains_known_secret(&rendered, &[token]));
    }

    #[test]
    fn plain_json_string_boundary_matches_need_no_full_serialization_copy() {
        for token in [r#"""#, r#""a"#, r#"c""#, r#""abc""#, "abc"] {
            assert!(json_string_fragment_contains_secret("abc", &[token]));
        }
        assert!(!json_string_fragment_contains_secret(
            "abc",
            &["unrelated-token"]
        ));
    }

    #[test]
    fn giant_ordinary_keys_use_bounded_sensitive_key_classification() {
        let ordinary = "k".repeat(2 * 1024 * 1024);
        assert!(!sensitive_key(&ordinary));
        assert!(!response_credential_key(&ordinary));
        assert!(sensitive_key(&format!("{ordinary}-token")));
        assert!(response_credential_key(&format!("{ordinary}-signature")));
    }

    #[test]
    fn bounded_key_summary_matches_normalized_key_policy() {
        let giant = "x".repeat(2 * 1024 * 1024);
        for key in [
            "Authorization",
            "refresh_token",
            "ordinary-key",
            "prefix-client-secret",
            r"access\u005ftoken",
            giant.as_str(),
        ] {
            assert_eq!(
                sensitive_key(key),
                sensitive_normalized_key(&normalize_key(key)),
                "key {key:?}"
            );
        }
    }

    #[test]
    fn plain_json_string_fast_path_matches_serialized_bytes() {
        let texts = [
            "",
            "abc",
            "ordinary Unicode café",
            "a very long plain value",
        ];
        let secrets = ["\"", "\"a", "c\"", "abc", "café", "unrelated"];
        for text in texts {
            let serialized = serde_json::to_vec(text).expect("JSON string");
            for secret in secrets {
                assert_eq!(
                    json_string_fragment_contains_secret(text, &[secret]),
                    contains_known_secret(&serialized, &[secret]),
                    "text {text:?}, secret {secret:?}"
                );
            }
        }
    }

    #[test]
    fn oversized_encoded_values_are_redacted_without_canonical_copies() {
        let value = format!(r"\u0041%41{}", "x".repeat(MAX_CANONICAL_TEXT_BYTES + 1));
        assert_eq!(redact_text(&value, &["unrelated-token"]), "[REDACTED]");
        assert_eq!(
            redact_bytes(value.as_bytes(), &["unrelated-token"]),
            b"[REDACTED]"
        );
    }

    #[test]
    fn large_pretty_documents_are_not_treated_as_one_encoded_value() {
        let mut nested = Value::Array(vec![Value::from(0); 10_000]);
        for _ in 0..60 {
            nested = Value::Array(vec![nested]);
        }
        let mut value = json!({"ordinary": "+", "nested": nested});
        assert!(
            serde_json::to_vec_pretty(&value)
                .expect("pretty JSON")
                .len()
                > MAX_CANONICAL_TEXT_BYTES
        );
        assert_eq!(
            sanitize_json_serialization(&mut value, &["unrelated-token"]),
            Some(false)
        );
        assert!(value.is_object());
        assert_eq!(value["ordinary"], "+");
    }

    #[test]
    fn success_redaction_preserves_data_and_redacts_secret_keys() {
        let mut typed = json!({
            "password": "upstream-value",
            "message": "password=ordinary-data",
            "known-secret": "key-value",
            "value": "known-secret"
        });
        redact_known_secrets_json(&mut typed, &["known-secret"]);
        assert_eq!(typed["password"], "upstream-value");
        assert_eq!(typed["message"], "password=ordinary-data");
        assert_eq!(typed["[REDACTED]"], "key-value");
        assert_eq!(typed["value"], "[REDACTED]");

        let mut raw = json!({
            "password": "upstream-value",
            "refresh_token": "unrecognized-secret",
            "safe": "visible"
        });
        redact_response_json(&mut raw, &[]);
        assert_eq!(raw["password"], "upstream-value");
        assert_eq!(raw["refresh_token"], "[REDACTED]");
        assert_eq!(raw["safe"], "visible");
    }

    #[test]
    fn diagnostic_redaction_cannot_emit_a_secret_object_key() {
        let mut value = json!({
            "super-secret": "value",
            "[REDACTED]": "existing"
        });
        redact_json(&mut value, &["super-secret"]);
        let rendered = value.to_string();
        assert!(!rendered.contains("super-secret"));
        assert_eq!(value["[REDACTED]"], "existing");
        assert_eq!(value["[REDACTED]#2"], "[REDACTED]");
    }

    #[test]
    fn overlapping_token_generations_are_redacted_longest_first() {
        let secrets = ["token-prefix", "token-prefixNEWSECRET", "NEWSECRET"];
        let redacted = redact_text(
            "old=token-prefix new=token-prefixNEWSECRET suffix=NEWSECRET",
            &secrets,
        );
        assert_eq!(redacted, "old= new= suffix=");
        assert_eq!(redact_bytes(b"token-prefixNEWSECRET", &secrets), b"");
    }

    #[test]
    fn numeric_boolean_and_null_shaped_credentials_remain_valid_json_when_redacted() {
        let mut value = json!({
            "number": 12345,
            "boolean": true,
            "nothing": null,
            "safe": 678
        });
        redact_response_json(&mut value, &["123", "true", "null"]);
        assert_eq!(value["number"], "");
        assert_eq!(value["boolean"], "");
        assert_eq!(value["nothing"], "");
        assert_eq!(value["safe"], 678);
        serde_json::to_vec(&value).expect("redacted structured response remains JSON");
    }

    #[test]
    fn streaming_scan_matches_the_bounded_reference_on_generated_inputs() {
        const ALPHABET: &[u8] = br#"abAB09%+\u2D\" -_"#;
        let secrets = ["a b", "a-b", "A", r"\u"];
        let alphabet_len = u64::try_from(ALPHABET.len()).expect("alphabet length fits u64");
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for case in 0..5_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = usize::try_from((state >> 32) % 40).expect("bounded length");
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let index =
                    usize::try_from(state % alphabet_len).expect("alphabet index fits usize");
                bytes.push(ALPHABET[index]);
            }
            let text = std::str::from_utf8(&bytes).expect("ASCII fixture");
            let raw_match = secrets.iter().any(|secret| text.contains(secret));
            let expected = if raw_match {
                (true, true)
            } else {
                inspect_canonical_forms(text, |canonical| {
                    secrets.iter().any(|secret| canonical.contains(secret))
                })
            };
            let actual = inspect_canonical_bytes(&bytes, &secrets);
            let windowed = if raw_match {
                (true, true)
            } else {
                inspect_canonical_windows(&bytes, &secrets)
            };
            assert_eq!(actual, expected, "generated case {case}: {text:?}");
            assert_eq!(windowed, expected, "windowed case {case}: {text:?}");
        }
    }

    #[test]
    fn sparse_canonical_windows_match_full_document_scans() {
        let mut ordinary = vec![b'x'; 64 * 1024];
        ordinary[32 * 1024] = b'+';
        assert_eq!(
            inspect_canonical_windows(&ordinary, &["unrelated-token"]),
            inspect_canonical_bytes(&ordinary, &["unrelated-token"])
        );

        let mut encoded_match = vec![b'x'; 64 * 1024];
        encoded_match.splice(32 * 1024..32 * 1024 + 3, *b"x+y");
        assert_eq!(
            inspect_canonical_windows(&encoded_match, &["x y"]),
            (true, true)
        );

        let mut overdepth = vec![b'x'; 64 * 1024];
        overdepth.splice(32 * 1024..32 * 1024 + 18, *b"secret%25252Dtoken");
        assert_eq!(
            inspect_canonical_windows(&overdepth, &["secret-token"]),
            inspect_canonical_bytes(&overdepth, &["secret-token"])
        );
    }

    #[test]
    fn sparse_window_scan_matches_full_scan_on_large_generated_inputs() {
        const INSERTIONS: [&[u8]; 6] = [
            b"+",
            b"%20",
            b"%252D",
            br"\u0041",
            b"%255Cu0041",
            b"%25252D",
        ];
        let secrets = ["a b", "a-b", "A B", "q-token"];
        let mut state = 0xa409_3822_299f_31d0_u64;
        for case in 0..200 {
            let mut bytes = vec![b'x'; 8 * 1024];
            for _ in 0..4 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let insertion =
                    INSERTIONS[usize::try_from(state % 6).expect("insertion index fits usize")];
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let maximum = bytes.len() - insertion.len();
                let offset = usize::try_from(state % u64::try_from(maximum).expect("length fits"))
                    .expect("offset fits usize");
                bytes[offset..offset + insertion.len()].copy_from_slice(insertion);
            }
            let raw_match = secrets
                .iter()
                .any(|secret| memmem::find(&bytes, secret.as_bytes()).is_some());
            let (sensitive, fully_decoded) = inspect_canonical_bytes(&bytes, &secrets);
            let expected = raw_match || sensitive || !fully_decoded;
            assert_eq!(
                contains_known_secret(&bytes, &secrets),
                expected,
                "generated case {case}"
            );
        }
    }
}

//! Error responses of `docs/sync-v1.md` §13: one `ApiError` per failed request, built from the
//! store's, authentication's and this layer's own refusals.
//!
//! Messages are English and fixed: they never repeat request content (a blob, a token, a
//! handle), so neither the response nor a log line can leak it.

use awm_proto::wire::{ErrorBody, ErrorCode, Id, Version};
use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::auth::AuthError;
use crate::authz::Refusal;
use crate::store::StoreError;

/// Internal-error text carried to the request log (the response has no body for a 500).
#[derive(Debug, Clone)]
pub(crate) struct ApiLog(pub String);

/// A failed request.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    /// `None` for an internal error: a bodiless 500.
    pub body: Option<Box<ErrorBody>>,
    /// The `Retry-After` header, equal to `retry_after_s` in the body.
    pub retry_after: Option<u32>,
    /// What the request log records for a 500.
    pub log: Option<String>,
}

impl ApiError {
    fn coded(code: ErrorCode, body: ErrorBody) -> ApiError {
        let status = code
            .status()
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(StatusCode::BAD_REQUEST);
        ApiError {
            status,
            retry_after: body.retry_after_s,
            body: Some(Box::new(body)),
            log: None,
        }
    }

    pub fn new(code: ErrorCode, message: &str) -> ApiError {
        ApiError::coded(code, ErrorBody::new(code, message))
    }

    pub fn with(code: ErrorCode, message: &str, f: impl FnOnce(&mut ErrorBody)) -> ApiError {
        let mut body = ErrorBody::new(code, message);
        f(&mut body);
        ApiError::coded(code, body)
    }

    pub fn malformed(message: &str) -> ApiError {
        ApiError::new(ErrorCode::Malformed, message)
    }

    pub fn unknown_field(field: String) -> ApiError {
        ApiError::with(ErrorCode::UnknownField, "unknown field", |b| {
            b.field = Some(field)
        })
    }

    pub fn invalid(field: &str, message: &str) -> ApiError {
        ApiError::with(ErrorCode::InvalidValue, message, |b| {
            b.field = Some(field.to_string())
        })
    }

    pub fn bad_client_header(message: &str) -> ApiError {
        ApiError::new(ErrorCode::BadClientHeader, message)
    }

    pub fn not_found(message: &str) -> ApiError {
        ApiError::new(ErrorCode::NotFound, message)
    }

    /// 413 `too_large`; `item` is the failing position of a push.
    pub fn too_large(limit: &str, max: u64, item: Option<u32>) -> ApiError {
        ApiError::with(ErrorCode::TooLarge, "request above a limit", |b| {
            b.limit = Some(limit.to_string());
            b.max = Some(max);
            b.item = item;
        })
    }

    pub fn bad_envelope(item: u32) -> ApiError {
        ApiError::with(
            ErrorCode::BadEnvelope,
            "blob is not an envelope of version 1",
            |b| b.item = Some(item),
        )
    }

    /// 429 `rate_limited`; `limit` is `records_per_day` for the daily quota.
    pub fn rate_limited(retry_after_s: u32, limit: Option<&str>) -> ApiError {
        ApiError::with(ErrorCode::RateLimited, "rate limit reached", |b| {
            b.retry_after_s = Some(retry_after_s);
            b.limit = limit.map(str::to_string);
        })
    }

    pub fn client_too_old(client: &Version, min: &Version) -> ApiError {
        ApiError::with(
            ErrorCode::ClientTooOld,
            &format!("awm {client} is below min_client {min}"),
            |b| b.min_client = Some(min.clone()),
        )
    }

    pub fn restore_pending(generation: Id, retry_after_s: u32) -> ApiError {
        ApiError::with(
            ErrorCode::RestorePending,
            "the server was restored from a backup; an admin must sync first",
            |b| {
                b.generation = Some(generation);
                b.retry_after_s = Some(retry_after_s);
            },
        )
    }

    pub fn internal(text: String) -> ApiError {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: None,
            retry_after: None,
            log: Some(text),
        }
    }
}

/// The response of a failed request. An internal error is a bodiless 500 whose text rides in the
/// [`ApiLog`] extension for the request log.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = match &self.body {
            Some(b) => {
                let bytes = serde_json::to_vec(b).unwrap_or_default();
                let mut r = Response::new(Body::from(bytes));
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
            None => Response::new(Body::empty()),
        };
        *resp.status_mut() = self.status;
        if let Some(s) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        if let Some(text) = self.log {
            resp.extensions_mut().insert(ApiLog(text));
        }
        resp
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> ApiError {
        match e.to_body() {
            Some(body) => {
                let code = body.error;
                ApiError::coded(code, body)
            }
            None => ApiError::internal(e.to_string()),
        }
    }
}

impl From<Refusal> for ApiError {
    fn from(r: Refusal) -> ApiError {
        ApiError::coded(r.code(), r.to_body())
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> ApiError {
        match e {
            AuthError::Refused(r) => r.into(),
            AuthError::Store(s) => s.into(),
            AuthError::Random => ApiError::internal(e.to_string()),
        }
    }
}

impl From<crate::delete::DeleteError> for ApiError {
    fn from(e: crate::delete::DeleteError) -> ApiError {
        match e.to_body() {
            Some(body) => ApiError {
                status: StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST),
                retry_after: e.retry_after(),
                body: Some(Box::new(body)),
                log: None,
            },
            None => ApiError::internal(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing bodies and query strings

/// The name between the first pair of backticks of serde's "unknown field `x`" message.
fn unknown_field_of(msg: &str) -> Option<(String, Vec<String>)> {
    let rest = msg.split_once("unknown field `")?.1;
    let (name, rest) = rest.split_once('`')?;
    let expected = rest
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    Some((name.to_string(), expected))
}

fn pointer_escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// The JSON pointer of the first object that holds `name` although `expected` does not list
/// it (serde's error names the field but not where it is).
fn find_unknown(v: &Value, name: &str, expected: &[String], path: &str) -> Option<String> {
    match v {
        Value::Object(m) => {
            if m.contains_key(name) && !expected.iter().any(|e| e == name) {
                return Some(format!("{path}/{}", pointer_escape(name)));
            }
            m.iter().find_map(|(k, child)| {
                find_unknown(
                    child,
                    name,
                    expected,
                    &format!("{path}/{}", pointer_escape(k)),
                )
            })
        }
        Value::Array(a) => a
            .iter()
            .enumerate()
            .find_map(|(i, child)| find_unknown(child, name, expected, &format!("{path}/{i}"))),
        _ => None,
    }
}

/// Deserialises a request body. An unknown field is 400 `unknown_field` with its JSON pointer;
/// every other failure is 400 `malformed` with a fixed message (serde's text can quote the
/// input, a blob among it).
pub fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    match serde_json::from_slice::<T>(bytes) {
        Ok(v) => Ok(v),
        Err(e) if e.is_data() => {
            if let Some((name, expected)) = unknown_field_of(&e.to_string()) {
                let field = serde_json::from_slice::<Value>(bytes)
                    .ok()
                    .and_then(|v| find_unknown(&v, &name, &expected, ""))
                    .unwrap_or_else(|| format!("/{}", pointer_escape(&name)));
                return Err(ApiError::unknown_field(field));
            }
            Err(ApiError::malformed("body does not match the schema"))
        }
        Err(_) => Err(ApiError::malformed("body is not JSON")),
    }
}

/// The message of a rejected query string, reduced to what the response may say.
pub fn query_error(text: &str) -> ApiError {
    match unknown_field_of(text) {
        Some((name, _)) => ApiError::unknown_field(name),
        None => ApiError::malformed("query string does not match the schema"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awm_proto::wire::PushRequest;

    #[test]
    fn unknown_fields_are_named_by_pointer() {
        let body = br#"{"records":[{"tag":"rec","idx":0,"id":"7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918","deleted":true,"sig":"x"}]}"#;
        let e = parse_json::<PushRequest>(body).unwrap_err();
        assert_eq!(e.status, 400);
        let b = e.body.unwrap();
        assert_eq!(b.error, ErrorCode::UnknownField);
        assert_eq!(b.field.as_deref(), Some("/records/0/sig"));
    }

    #[test]
    fn a_top_level_unknown_field_and_malformed_json() {
        let e = parse_json::<PushRequest>(br#"{"records":[],"x":1}"#).unwrap_err();
        assert_eq!(e.body.unwrap().field.as_deref(), Some("/x"));
        let e = parse_json::<PushRequest>(b"{").unwrap_err();
        assert_eq!(e.body.unwrap().error, ErrorCode::Malformed);
        let e = parse_json::<PushRequest>(br#"{"records":"x"}"#).unwrap_err();
        assert_eq!(e.body.unwrap().error, ErrorCode::Malformed);
    }

    #[test]
    fn a_malformed_message_never_quotes_the_input() {
        let e = parse_json::<PushRequest>(br#"{"records":"SECRET-BLOB-BYTES"}"#).unwrap_err();
        assert!(!e.body.unwrap().message.contains("SECRET"));
    }
}

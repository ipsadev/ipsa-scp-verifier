use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{
        header::{
            ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, CONTENT_TYPE, ORIGIN, VARY,
        },
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::{
    api,
    error::{Error, Result},
    network::Network,
};

const MAX_BODY_BYTES: usize = 8 * 1024;

const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

const CACHED_CHECKPOINTS: usize = 4;

pub struct Options {
    pub port: u16,
    pub network: Network,
    pub archives: Vec<String>,
    pub archives_pinned: bool,
    pub origins: Vec<String>,
    pub trust_root_xdr: Option<Vec<u8>>,
}

struct Shared {
    options: Options,
    permits: Semaphore,
    cache: api::CheckpointCache,
}

pub async fn run(options: Options) -> Result<()> {
    let address = format!("0.0.0.0:{}", options.port);

    println!("ipsa-scp-verify serving on {address}");

    if options.origins.is_empty() {
        println!("  no CORS origins configured; browsers will be refused");
    } else {
        println!("  CORS origins: {}", options.origins.join(", "));
    }

    match &options.trust_root_xdr {
        Some(_) => println!(
            "  trust root: --trust-root, for {} requests that do not bring their own",
            options.network.label()
        ),
        None => println!("  no --trust-root: every request must carry its own trust_root"),
    }

    println!(
        "  at most {MAX_CONCURRENT_VERIFICATIONS} verifications at once, {}s each, {CACHED_CHECKPOINTS} checkpoints cached",
        REQUEST_TIMEOUT.as_secs()
    );

    let state = Arc::new(Shared {
        options,
        permits: Semaphore::new(MAX_CONCURRENT_VERIFICATIONS),
        cache: api::CheckpointCache::new(CACHED_CHECKPOINTS),
    });
    let router = Router::new()
        .route("/health", get(health).options(preflight))
        .route("/mutations", get(mutations).options(preflight))
        .route("/verify", post(verify).options(preflight))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|error| Error::ServeBind {
            address: address.clone(),
            detail: error.to_string(),
        })?;

    axum::serve(listener, router)
        .await
        .map_err(|error| Error::Serve {
            detail: error.to_string(),
        })
}

fn cors_headers(options: &Options, incoming: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let origin = incoming
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| options.origins.iter().any(|allowed| allowed == origin));

    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("POST,GET,OPTIONS"),
            );
            headers.insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type"),
            );
            headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
            headers.insert(VARY, HeaderValue::from_static("Origin"));
        }
    }

    headers
}

fn error_response(status: StatusCode, headers: HeaderMap, detail: &str) -> Response {
    (status, headers, Json(json!({"error": detail}))).into_response()
}

async fn preflight(State(shared): State<Arc<Shared>>, incoming: HeaderMap) -> Response {
    let mut headers = cors_headers(&shared.options, &incoming);

    headers.remove(CONTENT_TYPE);

    (StatusCode::NO_CONTENT, headers).into_response()
}

async fn health(State(shared): State<Arc<Shared>>, incoming: HeaderMap) -> Response {
    (
        StatusCode::OK,
        cors_headers(&shared.options, &incoming),
        Json(json!({"status": "ok"})),
    )
        .into_response()
}

async fn mutations(State(shared): State<Arc<Shared>>, incoming: HeaderMap) -> Response {
    (
        StatusCode::OK,
        cors_headers(&shared.options, &incoming),
        Json(api::mutations()),
    )
        .into_response()
}

async fn verify(State(shared): State<Arc<Shared>>, incoming: HeaderMap, body: String) -> Response {
    let options = &shared.options;
    let headers = cors_headers(options, &incoming);
    let request: api::Request = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error) => {
            let detail = Error::ServeParseBody {
                detail: error.to_string(),
            };

            return error_response(StatusCode::BAD_REQUEST, headers, &detail.to_string());
        }
    };

    let Ok(_permit) = shared.permits.try_acquire() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            headers,
            "every verification slot is busy, try again shortly",
        );
    };

    let api_options = api::Options {
        network: options.network,
        archives: options.archives.clone(),
        archives_pinned: options.archives_pinned,
        trust_root_xdr: options.trust_root_xdr.clone(),
    };
    let outcome = tokio::time::timeout(
        REQUEST_TIMEOUT,
        api::verify_with_cache(&request, &api_options, Some(&shared.cache)),
    )
    .await;

    match outcome {
        Ok(Ok(report)) => (StatusCode::OK, headers, Json(report)).into_response(),
        Ok(Err(error)) => error_response(StatusCode::BAD_REQUEST, headers, &error.to_string()),
        Err(_) => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            headers,
            &format!(
                "verification took longer than {}s",
                REQUEST_TIMEOUT.as_secs()
            ),
        ),
    }
}

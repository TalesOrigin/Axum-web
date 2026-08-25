pub mod admin;
pub mod auth;
pub mod health;
pub mod licenses;
pub mod reseller;

use crate::{security, state::AppState};
use axum::{
    http::{header, HeaderName, HeaderValue, Method},
    middleware,
    routing::{get, patch, post},
    Router,
};
use std::str::FromStr;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    services::ServeDir,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

pub fn router(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");
    let cors = cors_layer(&state);

    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/licenses/verify", post(licenses::verify_license))
        .route("/api/v1/licenses/release", post(licenses::release_license))
        .route("/api/v1/admin/users", get(admin::list_users).post(admin::create_reseller))
        .route("/api/v1/admin/users/:id/status", patch(admin::set_user_status))
        .route("/api/v1/admin/licenses", get(admin::list_licenses).post(admin::generate_licenses))
        .route("/api/v1/admin/licenses/:id/status", patch(admin::set_license_status))
        .route("/api/v1/admin/key-requests", get(admin::list_key_requests))
        .route("/api/v1/admin/key-requests/:id/approve", post(admin::approve_key_request))
        .route("/api/v1/admin/key-requests/:id/reject", post(admin::reject_key_request))
        .route("/api/v1/reseller/key-requests", get(reseller::my_key_requests).post(reseller::create_key_request))
        .route("/api/v1/reseller/licenses", get(reseller::my_licenses))
        .route("/api/v1/reseller/licenses/:id/status", patch(reseller::set_my_license_status))
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        .with_state(state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(security::security_headers))
                .layer(TraceLayer::new_for_http())
                .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
                .layer(SetRequestIdLayer::new(
                    request_id_header,
                    MakeRequestUuid::default(),
                ))
                .layer(CompressionLayer::new())
                .layer(RequestBodyLimitLayer::new(state.config.request_body_limit_bytes))
                .layer(TimeoutLayer::new(state.config.request_timeout()))
                .layer(cors),
        )
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            HeaderName::from_static("x-request-id"),
        ]);

    if state.config.allowed_origins.iter().any(|origin| origin == "*") {
        base.allow_origin(Any)
    } else {
        let origins = state
            .config
            .allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect::<Vec<_>>();
        base.allow_origin(origins)
    }
}

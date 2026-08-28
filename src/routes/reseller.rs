use crate::{
    db,
    error::{AppError, AppResult},
    models::{
        LicenseKey, LicenseRequest, LicenseWithOwner, Pagination, LICENSE_ACTIVE, LICENSE_REVOKED,
        LICENSE_SUSPENDED, REQUEST_PENDING,
    },
    security,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize)]
pub struct MyRequestsQuery {
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateKeyRequest {
    #[validate(range(min = 1, max = 1000))]
    pub quantity: i32,
    #[validate(range(min = 1, max = 100000))]
    pub max_devices: i32,
    #[validate(range(min = 1, max = 36500))]
    pub ttl_days: i32,
    #[validate(length(max = 2000))]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MyLicensesQuery {
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct SetMyLicenseStatusRequest {
    pub status: String,
}

pub async fn create_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateKeyRequest>,
) -> AppResult<Json<LicenseRequest>> {
    payload.validate()?;
    let user = security::require_user(&state, &headers).await?;
    if !user.is_reseller() {
        return Err(AppError::Forbidden);
    }

    if payload.quantity > state.config.max_key_batch_size {
        return Err(AppError::BadRequest(format!(
            "quantity exceeds MAX_KEY_BATCH_SIZE ({})",
            state.config.max_key_batch_size
        )));
    }

    let request_id = Uuid::new_v4();
    let reseller_id = state.config.uuid_cast("$2");
    let request = sqlx::query_as::<_, LicenseRequest>(&format!(
        r#"
        INSERT INTO license_requests (
            id, reseller_id, quantity, max_devices, ttl_days, note, status
        )
        VALUES ($1, {reseller_id}, $3, $4, $5, $6, $7)
        RETURNING
            CAST(id AS TEXT) AS id,
            CAST(reseller_id AS TEXT) AS reseller_id,
            CAST(NULL AS TEXT) AS reseller_email,
            quantity,
            max_devices,
            ttl_days,
            note,
            status,
            CAST(reviewed_by AS TEXT) AS reviewed_by,
            CAST(reviewed_at AS TEXT) AS reviewed_at,
            admin_note,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        "#,
    ))
    .bind(request_id.to_string())
    .bind(user.id.to_string())
    .bind(payload.quantity)
    .bind(payload.max_devices)
    .bind(payload.ttl_days)
    .bind(payload.note.clone())
    .bind(REQUEST_PENDING)
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(user.id),
        Some(user.id),
        None,
        Some(request.id),
        "reseller.key_request.created",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"quantity": payload.quantity, "max_devices": payload.max_devices, "ttl_days": payload.ttl_days}),
    )
    .await;

    Ok(Json(request))
}

pub async fn my_key_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MyRequestsQuery>,
) -> AppResult<Json<Vec<LicenseRequest>>> {
    let user = security::require_user(&state, &headers).await?;
    if !user.is_reseller() {
        return Err(AppError::Forbidden);
    }

    if let Some(status) = &query.status {
        validate_request_status(status)?;
    }

    let reseller_id = state.config.uuid_cast("$1");
    let requests = sqlx::query_as::<_, LicenseRequest>(&format!(
        r#"
        SELECT
            CAST(id AS TEXT) AS id,
            CAST(reseller_id AS TEXT) AS reseller_id,
            CAST(NULL AS TEXT) AS reseller_email,
            quantity,
            max_devices,
            ttl_days,
            note,
            status,
            CAST(reviewed_by AS TEXT) AS reviewed_by,
            CAST(reviewed_at AS TEXT) AS reviewed_at,
            admin_note,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM license_requests
        WHERE reseller_id = {reseller_id}
          AND ($2 IS NULL OR status = $2)
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    ))
    .bind(user.id.to_string())
    .bind(query.status.clone())
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(requests))
}

pub async fn my_licenses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MyLicensesQuery>,
) -> AppResult<Json<Vec<LicenseWithOwner>>> {
    let user = security::require_user(&state, &headers).await?;
    if !user.is_reseller() {
        return Err(AppError::Forbidden);
    }

    if let Some(status) = &query.status {
        validate_license_status(status)?;
    }

    let owner_id = state.config.uuid_cast("$1");
    let active_since = state.config.active_since("da.last_seen_at", "$3");
    let cutoff = Utc::now() - Duration::seconds(state.config.license_heartbeat_window_seconds);
    let licenses = sqlx::query_as::<_, LicenseWithOwner>(&format!(
        r#"
        SELECT
            CAST(lk.id AS TEXT) AS id,
            lk.key_prefix,
            CAST(lk.owner_id AS TEXT) AS owner_id,
            owner.email AS owner_email,
            CAST(lk.created_by AS TEXT) AS created_by,
            lk.status,
            lk.max_devices,
            CAST(lk.expires_at AS TEXT) AS expires_at,
            lk.notes,
            CAST(lk.metadata AS TEXT) AS metadata,
            CAST(lk.last_verified_at AS TEXT) AS last_verified_at,
            COUNT(CASE
                WHEN da.revoked_at IS NULL AND {active_since} THEN 1
            END) AS active_devices,
            CAST(lk.created_at AS TEXT) AS created_at,
            CAST(lk.updated_at AS TEXT) AS updated_at
        FROM license_keys lk
        LEFT JOIN users owner ON owner.id = lk.owner_id
        LEFT JOIN device_activations da ON da.license_id = lk.id
        WHERE lk.owner_id = {owner_id}
          AND ($2 IS NULL OR lk.status = $2)
        GROUP BY lk.id, owner.email
        ORDER BY lk.created_at DESC
        LIMIT $4 OFFSET $5
        "#,
    ))
    .bind(user.id.to_string())
    .bind(query.status.clone())
    .bind(cutoff.to_rfc3339())
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(licenses))
}

pub async fn set_my_license_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetMyLicenseStatusRequest>,
) -> AppResult<Json<LicenseKey>> {
    let user = security::require_user(&state, &headers).await?;
    if !user.is_reseller() {
        return Err(AppError::Forbidden);
    }
    validate_license_status(&payload.status)?;

    let license_id = state.config.uuid_cast("$1");
    let owner_id = state.config.uuid_cast("$2");
    let license = sqlx::query_as::<_, LicenseKey>(&format!(
        r#"
        UPDATE license_keys
        SET status = $3
        WHERE id = {license_id} AND owner_id = {owner_id}
        RETURNING
            CAST(id AS TEXT) AS id,
            key_prefix,
            key_hash,
            CAST(owner_id AS TEXT) AS owner_id,
            CAST(created_by AS TEXT) AS created_by,
            status,
            max_devices,
            CAST(expires_at AS TEXT) AS expires_at,
            notes,
            CAST(metadata AS TEXT) AS metadata,
            CAST(last_verified_at AS TEXT) AS last_verified_at,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        "#,
    ))
    .bind(id.to_string())
    .bind(user.id.to_string())
    .bind(payload.status.as_str())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("license not found".to_string()))?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(user.id),
        Some(user.id),
        Some(license.id),
        None,
        "reseller.license.status_changed",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"status": payload.status}),
    )
    .await;

    Ok(Json(license))
}

fn validate_license_status(status: &str) -> AppResult<()> {
    match status {
        LICENSE_ACTIVE | LICENSE_SUSPENDED | LICENSE_REVOKED => Ok(()),
        _ => Err(AppError::BadRequest("invalid license status".to_string())),
    }
}

fn validate_request_status(status: &str) -> AppResult<()> {
    match status {
        "pending" | "approved" | "rejected" => Ok(()),
        _ => Err(AppError::BadRequest("invalid request status".to_string())),
    }
}

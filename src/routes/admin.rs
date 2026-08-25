use crate::{
    db,
    error::{AppError, AppResult},
    models::{
        LicenseKey, LicenseRequest, LicenseWithOwner, Pagination, PublicUser, User, LICENSE_ACTIVE,
        LICENSE_REVOKED, LICENSE_SUSPENDED, REQUEST_APPROVED, REQUEST_PENDING, REQUEST_REJECTED,
        ROLE_ADMIN, ROLE_RESELLER,
    },
    security,
    services::{
        auth::hash_password,
        crypto::{generate_license_key, hash_license_key, license_key_prefix},
    },
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub role: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateResellerRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12, max = 256))]
    pub password: String,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SetUserStatusRequest {
    pub is_active: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListLicensesQuery {
    pub owner_id: Option<Uuid>,
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GenerateLicensesRequest {
    pub owner_id: Option<Uuid>,
    #[validate(range(min = 1))]
    pub quantity: Option<i32>,
    #[validate(range(min = 1, max = 100000))]
    pub max_devices: i32,
    pub expires_at: Option<DateTime<Utc>>,
    #[validate(range(min = 1, max = 36500))]
    pub ttl_days: Option<i64>,
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct GeneratedLicense {
    pub id: Uuid,
    pub license_key: String,
    pub key_prefix: String,
    pub owner_id: Option<Uuid>,
    pub status: String,
    pub max_devices: i32,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct GeneratedLicensesResponse {
    pub licenses: Vec<GeneratedLicense>,
}

#[derive(Debug, Deserialize)]
pub struct SetLicenseStatusRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ListKeyRequestsQuery {
    pub status: Option<String>,
    pub reseller_id: Option<Uuid>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct ReviewKeyRequest {
    pub admin_note: Option<String>,
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListUsersQuery>,
) -> AppResult<Json<Vec<PublicUser>>> {
    let user = security::require_user(&state, &headers).await?;
    security::require_admin(&user)?;

    if let Some(role) = &query.role {
        validate_role(role)?;
    }

    let users = sqlx::query_as::<_, User>(
        r#"
        SELECT id, email, password_hash, role, is_active, created_at, updated_at
        FROM users
        WHERE ($1::text IS NULL OR role = $1)
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(query.role.as_deref())
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(users.into_iter().map(Into::into).collect()))
}

pub async fn create_reseller(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateResellerRequest>,
) -> AppResult<Json<PublicUser>> {
    payload.validate()?;
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    let password_hash = hash_password(&payload.password).map_err(AppError::Internal)?;
    let reseller = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (email, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, password_hash, role, is_active, created_at, updated_at
        "#,
    )
    .bind(payload.email.trim().to_ascii_lowercase())
    .bind(password_hash)
    .bind(ROLE_RESELLER)
    .bind(payload.is_active.unwrap_or(true))
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        Some(reseller.id),
        None,
        None,
        "admin.reseller.created",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"email": reseller.email.clone()}),
    )
    .await;

    Ok(Json(reseller.into()))
}

pub async fn set_user_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetUserStatusRequest>,
) -> AppResult<Json<PublicUser>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    if admin.id == id && !payload.is_active {
        return Err(AppError::BadRequest(
            "administrators cannot deactivate themselves".to_string(),
        ));
    }

    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET is_active = $2
        WHERE id = $1
        RETURNING id, email, password_hash, role, is_active, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(payload.is_active)
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        Some(user.id),
        None,
        None,
        "admin.user.status_changed",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"is_active": payload.is_active}),
    )
    .await;

    Ok(Json(user.into()))
}

pub async fn list_licenses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListLicensesQuery>,
) -> AppResult<Json<Vec<LicenseWithOwner>>> {
    let user = security::require_user(&state, &headers).await?;
    security::require_admin(&user)?;

    if let Some(status) = &query.status {
        validate_license_status(status)?;
    }

    let licenses = sqlx::query_as::<_, LicenseWithOwner>(
        r#"
        SELECT
            lk.id,
            lk.key_prefix,
            lk.owner_id,
            owner.email AS owner_email,
            lk.created_by,
            lk.status,
            lk.max_devices,
            lk.expires_at,
            lk.notes,
            lk.metadata,
            lk.last_verified_at,
            COUNT(da.id) FILTER (
                WHERE da.revoked_at IS NULL
                  AND da.last_seen_at > NOW() - make_interval(secs => $3::int)
            ) AS active_devices,
            lk.created_at,
            lk.updated_at
        FROM license_keys lk
        LEFT JOIN users owner ON owner.id = lk.owner_id
        LEFT JOIN device_activations da ON da.license_id = lk.id
        WHERE ($1::uuid IS NULL OR lk.owner_id = $1)
          AND ($2::text IS NULL OR lk.status = $2)
        GROUP BY lk.id, owner.email
        ORDER BY lk.created_at DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(query.owner_id)
    .bind(query.status.as_deref())
    .bind(state.config.license_heartbeat_window_seconds as i32)
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(licenses))
}

pub async fn generate_licenses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<GenerateLicensesRequest>,
) -> AppResult<Json<GeneratedLicensesResponse>> {
    payload.validate()?;
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    let licenses = create_licenses_for_owner(&state, &payload, admin.id, payload.owner_id).await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        payload.owner_id,
        None,
        None,
        "admin.licenses.generated",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"count": licenses.len(), "owner_id": payload.owner_id}),
    )
    .await;

    Ok(Json(GeneratedLicensesResponse { licenses }))
}

pub async fn set_license_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetLicenseStatusRequest>,
) -> AppResult<Json<LicenseKey>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;
    validate_license_status(&payload.status)?;

    let license = sqlx::query_as::<_, LicenseKey>(
        r#"
        UPDATE license_keys
        SET status = $2
        WHERE id = $1
        RETURNING id, key_prefix, key_hash, owner_id, created_by, status, max_devices,
                  expires_at, notes, metadata, last_verified_at, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(payload.status.as_str())
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        license.owner_id,
        Some(license.id),
        None,
        "admin.license.status_changed",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"status": payload.status}),
    )
    .await;

    Ok(Json(license))
}

pub async fn list_key_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListKeyRequestsQuery>,
) -> AppResult<Json<Vec<LicenseRequest>>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    if let Some(status) = &query.status {
        validate_request_status(status)?;
    }

    let requests = sqlx::query_as::<_, LicenseRequest>(
        r#"
        SELECT
            lr.id, lr.reseller_id, reseller.email AS reseller_email, lr.quantity,
            lr.max_devices, lr.ttl_days, lr.note, lr.status, lr.reviewed_by,
            lr.reviewed_at, lr.admin_note, lr.created_at, lr.updated_at
        FROM license_requests lr
        JOIN users reseller ON reseller.id = lr.reseller_id
        WHERE ($1::text IS NULL OR lr.status = $1)
          AND ($2::uuid IS NULL OR lr.reseller_id = $2)
        ORDER BY lr.created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(query.status.as_deref())
    .bind(query.reseller_id)
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(requests))
}

pub async fn approve_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<ReviewKeyRequest>,
) -> AppResult<Json<GeneratedLicensesResponse>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    let mut tx = state.pool.begin().await?;

    let request = sqlx::query_as::<_, LicenseRequest>(
        r#"
        SELECT
            lr.id, lr.reseller_id, NULL::text AS reseller_email, lr.quantity,
            lr.max_devices, lr.ttl_days, lr.note, lr.status, lr.reviewed_by,
            lr.reviewed_at, lr.admin_note, lr.created_at, lr.updated_at
        FROM license_requests lr
        WHERE lr.id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("key request not found".to_string()))?;

    if request.status != REQUEST_PENDING {
        return Err(AppError::Conflict("key request is already reviewed".to_string()));
    }

    if request.quantity > state.config.max_key_batch_size {
        return Err(AppError::BadRequest(format!(
            "request quantity exceeds MAX_KEY_BATCH_SIZE ({})",
            state.config.max_key_batch_size
        )));
    }

    let expires_at = Utc::now() + Duration::days(i64::from(request.ttl_days));
    let mut generated = Vec::with_capacity(request.quantity as usize);

    for _ in 0..request.quantity {
        let license_key = generate_license_key();
        let key_hash = hash_license_key(&state.config.license_key_pepper, &license_key)
            .map_err(AppError::Internal)?;
        let key_prefix = license_key_prefix(&license_key);
        let metadata = json!({"source": "reseller_request", "request_id": request.id});

        let license = sqlx::query_as::<_, LicenseKey>(
            r#"
            INSERT INTO license_keys (
                key_prefix, key_hash, owner_id, created_by, status,
                max_devices, expires_at, notes, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, key_prefix, key_hash, owner_id, created_by, status, max_devices,
                      expires_at, notes, metadata, last_verified_at, created_at, updated_at
            "#,
        )
        .bind(&key_prefix)
        .bind(key_hash)
        .bind(request.reseller_id)
        .bind(admin.id)
        .bind(LICENSE_ACTIVE)
        .bind(request.max_devices)
        .bind(expires_at)
        .bind(request.note.clone())
        .bind(metadata)
        .fetch_one(&mut *tx)
        .await?;

        generated.push(GeneratedLicense {
            id: license.id,
            license_key,
            key_prefix: license.key_prefix,
            owner_id: license.owner_id,
            status: license.status,
            max_devices: license.max_devices,
            expires_at: license.expires_at,
        });
    }

    sqlx::query(
        r#"
        UPDATE license_requests
        SET status = $2, reviewed_by = $3, reviewed_at = NOW(), admin_note = $4
        WHERE id = $1
        "#,
    )
    .bind(request.id)
    .bind(REQUEST_APPROVED)
    .bind(admin.id)
    .bind(payload.admin_note)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        Some(request.reseller_id),
        None,
        Some(request.id),
        "admin.key_request.approved",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"generated_count": generated.len()}),
    )
    .await;

    Ok(Json(GeneratedLicensesResponse { licenses: generated }))
}

pub async fn reject_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<ReviewKeyRequest>,
) -> AppResult<Json<LicenseRequest>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    let mut tx = state.pool.begin().await?;
    let request = sqlx::query_as::<_, LicenseRequest>(
        r#"
        SELECT
            lr.id, lr.reseller_id, NULL::text AS reseller_email, lr.quantity,
            lr.max_devices, lr.ttl_days, lr.note, lr.status, lr.reviewed_by,
            lr.reviewed_at, lr.admin_note, lr.created_at, lr.updated_at
        FROM license_requests lr
        WHERE lr.id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("key request not found".to_string()))?;

    if request.status != REQUEST_PENDING {
        return Err(AppError::Conflict("key request is already reviewed".to_string()));
    }

    let reviewed = sqlx::query_as::<_, LicenseRequest>(
        r#"
        WITH updated AS (
            UPDATE license_requests
            SET status = $2, reviewed_by = $3, reviewed_at = NOW(), admin_note = $4
            WHERE id = $1
            RETURNING id, reseller_id, quantity, max_devices, ttl_days, note, status,
                      reviewed_by, reviewed_at, admin_note, created_at, updated_at
        )
        SELECT updated.id, updated.reseller_id, reseller.email AS reseller_email,
               updated.quantity, updated.max_devices, updated.ttl_days, updated.note,
               updated.status, updated.reviewed_by, updated.reviewed_at,
               updated.admin_note, updated.created_at, updated.updated_at
        FROM updated
        JOIN users reseller ON reseller.id = updated.reseller_id
        "#,
    )
    .bind(request.id)
    .bind(REQUEST_REJECTED)
    .bind(admin.id)
    .bind(payload.admin_note.clone())
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        Some(admin.id),
        Some(request.reseller_id),
        None,
        Some(request.id),
        "admin.key_request.rejected",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"admin_note": payload.admin_note}),
    )
    .await;

    Ok(Json(reviewed))
}

async fn create_licenses_for_owner(
    state: &AppState,
    payload: &GenerateLicensesRequest,
    created_by: Uuid,
    owner_id: Option<Uuid>,
) -> AppResult<Vec<GeneratedLicense>> {
    let quantity = payload.quantity.unwrap_or(1);
    if quantity > state.config.max_key_batch_size {
        return Err(AppError::BadRequest(format!(
            "quantity exceeds MAX_KEY_BATCH_SIZE ({})",
            state.config.max_key_batch_size
        )));
    }

    if payload.expires_at.is_some() && payload.ttl_days.is_some() {
        return Err(AppError::BadRequest(
            "provide either expires_at or ttl_days, not both".to_string(),
        ));
    }

    if let Some(owner_id) = owner_id {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_active = true)",
        )
        .bind(owner_id)
        .fetch_one(&state.pool)
        .await?;
        if !exists {
            return Err(AppError::BadRequest("owner_id must reference an active user".to_string()));
        }
    }

    let expires_at = match (payload.expires_at, payload.ttl_days) {
        (Some(expires_at), None) => Some(expires_at),
        (None, Some(ttl_days)) => Some(Utc::now() + Duration::days(ttl_days)),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };

    let metadata = payload.metadata.clone().unwrap_or_else(|| json!({}));
    let mut tx = state.pool.begin().await?;
    let mut generated = Vec::with_capacity(quantity as usize);

    for _ in 0..quantity {
        let license_key = generate_license_key();
        let key_hash = hash_license_key(&state.config.license_key_pepper, &license_key)
            .map_err(AppError::Internal)?;
        let key_prefix = license_key_prefix(&license_key);

        let license = sqlx::query_as::<_, LicenseKey>(
            r#"
            INSERT INTO license_keys (
                key_prefix, key_hash, owner_id, created_by, status,
                max_devices, expires_at, notes, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, key_prefix, key_hash, owner_id, created_by, status, max_devices,
                      expires_at, notes, metadata, last_verified_at, created_at, updated_at
            "#,
        )
        .bind(&key_prefix)
        .bind(key_hash)
        .bind(owner_id)
        .bind(created_by)
        .bind(LICENSE_ACTIVE)
        .bind(payload.max_devices)
        .bind(expires_at)
        .bind(payload.notes.clone())
        .bind(metadata.clone())
        .fetch_one(&mut *tx)
        .await?;

        generated.push(GeneratedLicense {
            id: license.id,
            license_key,
            key_prefix: license.key_prefix,
            owner_id: license.owner_id,
            status: license.status,
            max_devices: license.max_devices,
            expires_at: license.expires_at,
        });
    }

    tx.commit().await?;
    Ok(generated)
}

fn validate_role(role: &str) -> AppResult<()> {
    match role {
        ROLE_ADMIN | ROLE_RESELLER => Ok(()),
        _ => Err(AppError::BadRequest("invalid role".to_string())),
    }
}

fn validate_license_status(status: &str) -> AppResult<()> {
    match status {
        LICENSE_ACTIVE | LICENSE_SUSPENDED | LICENSE_REVOKED => Ok(()),
        _ => Err(AppError::BadRequest("invalid license status".to_string())),
    }
}

fn validate_request_status(status: &str) -> AppResult<()> {
    match status {
        REQUEST_PENDING | REQUEST_APPROVED | REQUEST_REJECTED => Ok(()),
        _ => Err(AppError::BadRequest("invalid request status".to_string())),
    }
}

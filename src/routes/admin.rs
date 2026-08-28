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
pub struct CreateUserRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12, max = 256))]
    pub password: String,
    pub role: Option<String>,
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

#[derive(Debug, Serialize)]
pub struct BulkUserLicenseStatusResponse {
    pub owner_id: Uuid,
    pub status: String,
    pub updated_count: u64,
}

#[derive(Debug, Serialize)]
pub struct DeletedUserResponse {
    pub deleted: bool,
    pub user: PublicUser,
    pub suspended_key_count: u64,
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

    let role = query
        .role
        .as_deref()
        .map(|role| normalize_role(Some(role)))
        .transpose()?;

    let users = sqlx::query_as::<_, User>(
        r#"
        SELECT
            CAST(id AS TEXT) AS id,
            email,
            password_hash,
            role,
            is_active,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM users
        WHERE ($1 IS NULL OR role = $1)
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(role)
    .bind(query.pagination.limit())
    .bind(query.pagination.offset())
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(users.into_iter().map(Into::into).collect()))
}

pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<Json<PublicUser>> {
    payload.validate()?;
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    let role = normalize_role(payload.role.as_deref())?;
    let password_hash = hash_password(&payload.password).map_err(AppError::Internal)?;
    let user_id = Uuid::new_v4();
    let id = state.config.uuid_cast("$1");
    let created_user = sqlx::query_as::<_, User>(&format!(
        r#"
        INSERT INTO users (id, email, password_hash, role, is_active)
        VALUES ({id}, $2, $3, $4, $5)
        RETURNING
            CAST(id AS TEXT) AS id,
            email,
            password_hash,
            role,
            is_active,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        "#,
    ))
    .bind(user_id.to_string())
    .bind(payload.email.trim().to_ascii_lowercase())
    .bind(password_hash)
    .bind(role.as_str())
    .bind(payload.is_active.unwrap_or(true))
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(admin.id),
        Some(created_user.id),
        None,
        None,
        "admin.user.created",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"email": created_user.email.clone(), "role": created_user.role.clone()}),
    )
    .await;

    Ok(Json(created_user.into()))
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

    let user_id = state.config.uuid_cast("$1");
    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        UPDATE users
        SET is_active = $2
        WHERE id = {user_id}
        RETURNING
            CAST(id AS TEXT) AS id,
            email,
            password_hash,
            role,
            is_active,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        "#,
    ))
    .bind(id.to_string())
    .bind(payload.is_active)
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
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

pub async fn set_user_license_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetLicenseStatusRequest>,
) -> AppResult<Json<BulkUserLicenseStatusResponse>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;
    validate_license_status(&payload.status)?;

    let target = fetch_user_by_id(&state, id).await?;
    let owner_id = state.config.uuid_cast("$1");
    let status_filter = match payload.status.as_str() {
        // Resuming a seller only re-activates keys that are currently paused.
        // Revoked keys stay revoked unless an admin changes each one explicitly.
        LICENSE_ACTIVE => "AND status = 'suspended'",
        LICENSE_SUSPENDED => "AND status = 'active'",
        LICENSE_REVOKED => "AND status <> 'revoked'",
        _ => unreachable!("license status was already validated"),
    };
    let result = sqlx::query(&format!(
        r#"
        UPDATE license_keys
        SET status = $2
        WHERE owner_id = {owner_id}
          {status_filter}
        "#,
    ))
    .bind(id.to_string())
    .bind(payload.status.as_str())
    .execute(&state.pool)
    .await?;

    let updated_count = result.rows_affected();
    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(admin.id),
        Some(target.id),
        None,
        None,
        "admin.user.licenses.status_changed",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({
            "email": target.email.clone(),
            "role": target.role.clone(),
            "status": payload.status.clone(),
            "updated_count": updated_count,
        }),
    )
    .await;

    Ok(Json(BulkUserLicenseStatusResponse {
        owner_id: id,
        status: payload.status,
        updated_count,
    }))
}

pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<DeletedUserResponse>> {
    let admin = security::require_user(&state, &headers).await?;
    security::require_admin(&admin)?;

    if admin.id == id {
        return Err(AppError::BadRequest(
            "administrators cannot delete themselves".to_string(),
        ));
    }

    let target = fetch_user_by_id(&state, id).await?;
    let public_user: PublicUser = target.clone().into();

    let mut tx = state.pool.begin().await?;
    let owner_id = state.config.uuid_cast("$1");
    let suspended = sqlx::query(&format!(
        r#"
        UPDATE license_keys
        SET status = $2
        WHERE owner_id = {owner_id}
          AND status = $3
        "#,
    ))
    .bind(id.to_string())
    .bind(LICENSE_SUSPENDED)
    .bind(LICENSE_ACTIVE)
    .execute(&mut *tx)
    .await?;
    let suspended_key_count = suspended.rows_affected();

    let user_id = state.config.uuid_cast("$1");
    let deleted = sqlx::query(&format!("DELETE FROM users WHERE id = {user_id}"))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound("user not found".to_string()));
    }

    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(admin.id),
        None,
        None,
        None,
        "admin.user.deleted",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({
            "deleted_user_id": id,
            "email": target.email.clone(),
            "role": target.role.clone(),
            "suspended_key_count": suspended_key_count,
        }),
    )
    .await;

    Ok(Json(DeletedUserResponse {
        deleted: true,
        user: public_user,
        suspended_key_count,
    }))
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
        WHERE ({owner_id} IS NULL OR lk.owner_id = {owner_id})
          AND ($2 IS NULL OR lk.status = $2)
        GROUP BY lk.id, owner.email
        ORDER BY lk.created_at DESC
        LIMIT $4 OFFSET $5
        "#,
    ))
    .bind(query.owner_id.map(|value| value.to_string()))
    .bind(query.status.clone())
    .bind(cutoff.to_rfc3339())
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
        &state.config,
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

    let license_id = state.config.uuid_cast("$1");
    let license = sqlx::query_as::<_, LicenseKey>(&format!(
        r#"
        UPDATE license_keys
        SET status = $2
        WHERE id = {license_id}
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
    .bind(payload.status.as_str())
    .fetch_one(&state.pool)
    .await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
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

    let reseller_id = state.config.uuid_cast("$2");
    let requests = sqlx::query_as::<_, LicenseRequest>(&format!(
        r#"
        SELECT
            CAST(lr.id AS TEXT) AS id,
            CAST(lr.reseller_id AS TEXT) AS reseller_id,
            reseller.email AS reseller_email,
            lr.quantity,
            lr.max_devices,
            lr.ttl_days,
            lr.note,
            lr.status,
            CAST(lr.reviewed_by AS TEXT) AS reviewed_by,
            CAST(lr.reviewed_at AS TEXT) AS reviewed_at,
            lr.admin_note,
            CAST(lr.created_at AS TEXT) AS created_at,
            CAST(lr.updated_at AS TEXT) AS updated_at
        FROM license_requests lr
        JOIN users reseller ON reseller.id = lr.reseller_id
        WHERE ($1 IS NULL OR lr.status = $1)
          AND ({reseller_id} IS NULL OR lr.reseller_id = {reseller_id})
        ORDER BY lr.created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    ))
    .bind(query.status.clone())
    .bind(query.reseller_id.map(|value| value.to_string()))
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
    let request_id = state.config.uuid_cast("$1");
    let lock = state.config.row_lock_clause();
    let request = sqlx::query_as::<_, LicenseRequest>(&format!(
        r#"
        SELECT
            CAST(lr.id AS TEXT) AS id,
            CAST(lr.reseller_id AS TEXT) AS reseller_id,
            CAST(NULL AS TEXT) AS reseller_email,
            lr.quantity,
            lr.max_devices,
            lr.ttl_days,
            lr.note,
            lr.status,
            CAST(lr.reviewed_by AS TEXT) AS reviewed_by,
            CAST(lr.reviewed_at AS TEXT) AS reviewed_at,
            lr.admin_note,
            CAST(lr.created_at AS TEXT) AS created_at,
            CAST(lr.updated_at AS TEXT) AS updated_at
        FROM license_requests lr
        WHERE lr.id = {request_id}
        {lock}
        "#,
    ))
    .bind(id.to_string())
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
        let license_id = Uuid::new_v4();
        let id = state.config.uuid_cast("$1");
        let owner_id = state.config.uuid_cast("$4");
        let created_by = state.config.uuid_cast("$5");
        let expires_at_param = state.config.timestamp_cast("$8");
        let metadata_param = state.config.json_cast("$10");

        let license = sqlx::query_as::<_, LicenseKey>(&format!(
            r#"
            INSERT INTO license_keys (
                id, key_prefix, key_hash, owner_id, created_by, status,
                max_devices, expires_at, notes, metadata
            )
            VALUES ({id}, $2, $3, {owner_id}, {created_by}, $6, $7,
                    {expires_at_param}, $9, {metadata_param})
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
        .bind(license_id.to_string())
        .bind(&key_prefix)
        .bind(key_hash)
        .bind(request.reseller_id.to_string())
        .bind(admin.id.to_string())
        .bind(LICENSE_ACTIVE)
        .bind(request.max_devices)
        .bind(Some(expires_at.to_rfc3339()))
        .bind(request.note.clone())
        .bind(metadata.to_string())
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

    let request_id = state.config.uuid_cast("$1");
    let reviewed_by = state.config.uuid_cast("$3");
    sqlx::query(&format!(
        r#"
        UPDATE license_requests
        SET status = $2, reviewed_by = {reviewed_by},
            reviewed_at = CURRENT_TIMESTAMP, admin_note = $4
        WHERE id = {request_id}
        "#,
    ))
    .bind(request.id.to_string())
    .bind(REQUEST_APPROVED)
    .bind(admin.id.to_string())
    .bind(payload.admin_note)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
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
    let request_id = state.config.uuid_cast("$1");
    let lock = state.config.row_lock_clause();
    let request = sqlx::query_as::<_, LicenseRequest>(&format!(
        r#"
        SELECT
            CAST(lr.id AS TEXT) AS id,
            CAST(lr.reseller_id AS TEXT) AS reseller_id,
            CAST(NULL AS TEXT) AS reseller_email,
            lr.quantity,
            lr.max_devices,
            lr.ttl_days,
            lr.note,
            lr.status,
            CAST(lr.reviewed_by AS TEXT) AS reviewed_by,
            CAST(lr.reviewed_at AS TEXT) AS reviewed_at,
            lr.admin_note,
            CAST(lr.created_at AS TEXT) AS created_at,
            CAST(lr.updated_at AS TEXT) AS updated_at
        FROM license_requests lr
        WHERE lr.id = {request_id}
        {lock}
        "#,
    ))
    .bind(id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("key request not found".to_string()))?;

    if request.status != REQUEST_PENDING {
        return Err(AppError::Conflict("key request is already reviewed".to_string()));
    }

    let request_id = state.config.uuid_cast("$1");
    let reviewed_by = state.config.uuid_cast("$3");
    sqlx::query(&format!(
        r#"
        UPDATE license_requests
        SET status = $2, reviewed_by = {reviewed_by},
            reviewed_at = CURRENT_TIMESTAMP, admin_note = $4
        WHERE id = {request_id}
        "#,
    ))
    .bind(request.id.to_string())
    .bind(REQUEST_REJECTED)
    .bind(admin.id.to_string())
    .bind(payload.admin_note.clone())
    .execute(&mut *tx)
    .await?;

    let reviewed = sqlx::query_as::<_, LicenseRequest>(
        r#"
        SELECT
            CAST(lr.id AS TEXT) AS id,
            CAST(lr.reseller_id AS TEXT) AS reseller_id,
            reseller.email AS reseller_email,
            lr.quantity,
            lr.max_devices,
            lr.ttl_days,
            lr.note,
            lr.status,
            CAST(lr.reviewed_by AS TEXT) AS reviewed_by,
            CAST(lr.reviewed_at AS TEXT) AS reviewed_at,
            lr.admin_note,
            CAST(lr.created_at AS TEXT) AS created_at,
            CAST(lr.updated_at AS TEXT) AS updated_at
        FROM license_requests lr
        JOIN users reseller ON reseller.id = lr.reseller_id
        WHERE CAST(lr.id AS TEXT) = $1
        "#,
    )
    .bind(request.id.to_string())
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
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
        let owner = state.config.uuid_cast("$1");
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM users WHERE id = {owner} AND is_active = $2"
        ))
        .bind(owner_id.to_string())
        .bind(true)
        .fetch_one(&state.pool)
        .await?;
        if count == 0 {
            return Err(AppError::BadRequest(
                "owner_id must reference an active user".to_string(),
            ));
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
        let license_id = Uuid::new_v4();
        let id = state.config.uuid_cast("$1");
        let owner = state.config.uuid_cast("$4");
        let creator = state.config.uuid_cast("$5");
        let expires = state.config.timestamp_cast("$8");
        let metadata_param = state.config.json_cast("$10");

        let license = sqlx::query_as::<_, LicenseKey>(&format!(
            r#"
            INSERT INTO license_keys (
                id, key_prefix, key_hash, owner_id, created_by, status,
                max_devices, expires_at, notes, metadata
            )
            VALUES ({id}, $2, $3, {owner}, {creator}, $6, $7,
                    {expires}, $9, {metadata_param})
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
        .bind(license_id.to_string())
        .bind(&key_prefix)
        .bind(key_hash)
        .bind(owner_id.map(|value| value.to_string()))
        .bind(created_by.to_string())
        .bind(LICENSE_ACTIVE)
        .bind(payload.max_devices)
        .bind(expires_at.map(|value| value.to_rfc3339()))
        .bind(payload.notes.clone())
        .bind(metadata.to_string())
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

async fn fetch_user_by_id(state: &AppState, id: Uuid) -> AppResult<User> {
    let user_id = state.config.uuid_cast("$1");
    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        SELECT
            CAST(id AS TEXT) AS id,
            email,
            password_hash,
            role,
            is_active,
            CAST(created_at AS TEXT) AS created_at,
            CAST(updated_at AS TEXT) AS updated_at
        FROM users
        WHERE id = {user_id}
        "#,
    ))
    .bind(id.to_string())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

    Ok(user)
}

fn normalize_role(role: Option<&str>) -> AppResult<String> {
    let role = role
        .unwrap_or(ROLE_RESELLER)
        .trim()
        .to_ascii_lowercase();
    validate_role(&role)?;
    Ok(role)
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

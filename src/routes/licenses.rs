use crate::{
    db,
    error::{AppError, AppResult},
    models::{DeviceActivation, LicenseKey, LICENSE_ACTIVE},
    security,
    services::crypto::{hash_device_id, hash_license_key, normalize_license_key},
    state::AppState,
};
use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyLicenseRequest {
    #[validate(length(min = 8, max = 256))]
    pub license_key: String,
    #[validate(length(min = 2, max = 512))]
    pub device_id: String,
    #[validate(length(max = 256))]
    pub device_label: Option<String>,
    #[validate(length(max = 128))]
    pub app_id: Option<String>,
    #[validate(length(max = 64))]
    pub app_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyLicenseResponse {
    pub allowed: bool,
    pub code: String,
    pub message: String,
    pub license_id: Option<Uuid>,
    pub key_prefix: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub server_time: DateTime<Utc>,
    pub max_devices: Option<i32>,
    pub active_devices: Option<i64>,
    pub heartbeat_after_seconds: i64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ReleaseLicenseRequest {
    #[validate(length(min = 8, max = 256))]
    pub license_key: String,
    #[validate(length(min = 2, max = 512))]
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct ReleaseLicenseResponse {
    pub released: bool,
    pub server_time: DateTime<Utc>,
}

pub async fn verify_license(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyLicenseRequest>,
) -> AppResult<Json<VerifyLicenseResponse>> {
    payload.validate()?;

    if normalize_license_key(&payload.license_key).is_empty() || payload.device_id.trim().is_empty() {
        return Err(AppError::BadRequest("license_key and device_id are required".to_string()));
    }

    let key_hash = hash_license_key(&state.config.license_key_pepper, &payload.license_key)
        .map_err(AppError::Internal)?;
    let device_hash = hash_device_id(&state.config.device_id_pepper, &payload.device_id)
        .map_err(AppError::Internal)?;
    let heartbeat_window = state.config.license_heartbeat_window_seconds;

    let mut tx = state.pool.begin().await?;

    let Some(license) = sqlx::query_as::<_, LicenseKey>(
        r#"
        SELECT id, key_prefix, key_hash, owner_id, created_by, status, max_devices,
               expires_at, notes, metadata, last_verified_at, created_at, updated_at
        FROM license_keys
        WHERE key_hash = $1
        FOR UPDATE
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(&mut *tx)
    .await?
    else {
        tx.commit().await?;
        return Ok(Json(denied("invalid_key", "license key was not found", heartbeat_window)));
    };

    if license.status != LICENSE_ACTIVE {
        tx.commit().await?;
        return Ok(Json(denied_with_license(
            "license_not_active",
            "license key is suspended or revoked",
            &license,
            heartbeat_window,
            None,
        )));
    }

    if let Some(expires_at) = license.expires_at.as_ref() {
        if expires_at <= &Utc::now() {
            tx.commit().await?;
            return Ok(Json(denied_with_license(
                "license_expired",
                "license key has expired",
                &license,
                heartbeat_window,
                None,
            )));
        }
    }

    let existing_activation = sqlx::query_as::<_, DeviceActivation>(
        r#"
        SELECT id, license_id, device_id_hash, device_label, app_id, app_version,
               ip_address, user_agent, last_seen_at, created_at, revoked_at
        FROM device_activations
        WHERE license_id = $1 AND device_id_hash = $2
        FOR UPDATE
        "#,
    )
    .bind(license.id)
    .bind(&device_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(activation) = existing_activation {
        if activation.revoked_at.is_some() {
            tx.commit().await?;
            return Ok(Json(denied_with_license(
                "device_revoked",
                "this device has been revoked for the license key",
                &license,
                heartbeat_window,
                None,
            )));
        }

        let activation_is_current =
            activation.last_seen_at > Utc::now() - Duration::seconds(heartbeat_window);
        if !activation_is_current {
            let other_active_devices = active_device_count_excluding(
                &mut tx,
                license.id,
                activation.id,
                heartbeat_window,
            )
            .await?;

            if other_active_devices >= i64::from(license.max_devices) {
                tx.commit().await?;
                return Ok(Json(denied_with_license(
                    "device_limit_reached",
                    "device limit is already in use; release another device or wait for heartbeat expiry",
                    &license,
                    heartbeat_window,
                    Some(other_active_devices),
                )));
            }
        }

        sqlx::query(
            r#"
            UPDATE device_activations
            SET last_seen_at = NOW(), device_label = $3, app_id = $4, app_version = $5,
                ip_address = $6, user_agent = $7
            WHERE id = $1 AND license_id = $2
            "#,
        )
        .bind(activation.id)
        .bind(license.id)
        .bind(trim_optional(payload.device_label.as_deref()))
        .bind(trim_optional(payload.app_id.as_deref()))
        .bind(trim_optional(payload.app_version.as_deref()))
        .bind(security::client_ip(&headers))
        .bind(security::user_agent(&headers))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE license_keys SET last_verified_at = NOW() WHERE id = $1")
            .bind(license.id)
            .execute(&mut *tx)
            .await?;

        let active_devices = active_device_count(&mut tx, license.id, heartbeat_window).await?;
        tx.commit().await?;

        return Ok(Json(allowed(&license, active_devices, heartbeat_window)));
    }

    let active_devices = active_device_count(&mut tx, license.id, heartbeat_window).await?;
    if active_devices >= i64::from(license.max_devices) {
        tx.commit().await?;
        return Ok(Json(denied_with_license(
            "device_limit_reached",
            "device limit is already in use; release another device or wait for heartbeat expiry",
            &license,
            heartbeat_window,
            Some(active_devices),
        )));
    }

    sqlx::query(
        r#"
        INSERT INTO device_activations (
            license_id, device_id_hash, device_label, app_id, app_version,
            ip_address, user_agent, last_seen_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        "#,
    )
    .bind(license.id)
    .bind(&device_hash)
    .bind(trim_optional(payload.device_label.as_deref()))
    .bind(trim_optional(payload.app_id.as_deref()))
    .bind(trim_optional(payload.app_version.as_deref()))
    .bind(security::client_ip(&headers))
    .bind(security::user_agent(&headers))
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE license_keys SET last_verified_at = NOW() WHERE id = $1")
        .bind(license.id)
        .execute(&mut *tx)
        .await?;

    let active_devices = active_device_count(&mut tx, license.id, heartbeat_window).await?;
    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        None,
        license.owner_id,
        Some(license.id),
        None,
        "license.device.activated",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"key_prefix": license.key_prefix.clone(), "active_devices": active_devices}),
    )
    .await;

    Ok(Json(allowed(&license, active_devices, heartbeat_window)))
}

pub async fn release_license(
    State(state): State<AppState>,
    Json(payload): Json<ReleaseLicenseRequest>,
) -> AppResult<Json<ReleaseLicenseResponse>> {
    payload.validate()?;

    let key_hash = hash_license_key(&state.config.license_key_pepper, &payload.license_key)
        .map_err(AppError::Internal)?;
    let device_hash = hash_device_id(&state.config.device_id_pepper, &payload.device_id)
        .map_err(AppError::Internal)?;

    let stale_seconds = state.config.license_heartbeat_window_seconds + 1;
    let result = sqlx::query(
        r#"
        UPDATE device_activations da
        SET last_seen_at = NOW() - make_interval(secs => $3::int)
        FROM license_keys lk
        WHERE lk.id = da.license_id
          AND lk.key_hash = $1
          AND da.device_id_hash = $2
          AND da.revoked_at IS NULL
        "#,
    )
    .bind(key_hash)
    .bind(device_hash)
    .bind(stale_seconds as i32)
    .execute(&state.pool)
    .await?;

    Ok(Json(ReleaseLicenseResponse {
        released: result.rows_affected() > 0,
        server_time: Utc::now(),
    }))
}

async fn active_device_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    license_id: Uuid,
    heartbeat_window_seconds: i64,
) -> AppResult<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM device_activations
        WHERE license_id = $1
          AND revoked_at IS NULL
          AND last_seen_at > NOW() - make_interval(secs => $2::int)
        "#,
    )
    .bind(license_id)
    .bind(heartbeat_window_seconds as i32)
    .fetch_one(&mut **tx)
    .await?;

    Ok(count)
}

async fn active_device_count_excluding(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    license_id: Uuid,
    excluded_activation_id: Uuid,
    heartbeat_window_seconds: i64,
) -> AppResult<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM device_activations
        WHERE license_id = $1
          AND id <> $2
          AND revoked_at IS NULL
          AND last_seen_at > NOW() - make_interval(secs => $3::int)
        "#,
    )
    .bind(license_id)
    .bind(excluded_activation_id)
    .bind(heartbeat_window_seconds as i32)
    .fetch_one(&mut **tx)
    .await?;

    Ok(count)
}

fn allowed(license: &LicenseKey, active_devices: i64, heartbeat_window: i64) -> VerifyLicenseResponse {
    VerifyLicenseResponse {
        allowed: true,
        code: "ok".to_string(),
        message: "license verified".to_string(),
        license_id: Some(license.id),
        key_prefix: Some(license.key_prefix.clone()),
        expires_at: license.expires_at,
        server_time: Utc::now(),
        max_devices: Some(license.max_devices),
        active_devices: Some(active_devices),
        heartbeat_after_seconds: heartbeat_window / 2,
    }
}

fn denied(code: &str, message: &str, heartbeat_window: i64) -> VerifyLicenseResponse {
    VerifyLicenseResponse {
        allowed: false,
        code: code.to_string(),
        message: message.to_string(),
        license_id: None,
        key_prefix: None,
        expires_at: None,
        server_time: Utc::now(),
        max_devices: None,
        active_devices: None,
        heartbeat_after_seconds: heartbeat_window / 2,
    }
}

fn denied_with_license(
    code: &str,
    message: &str,
    license: &LicenseKey,
    heartbeat_window: i64,
    active_devices: Option<i64>,
) -> VerifyLicenseResponse {
    VerifyLicenseResponse {
        allowed: false,
        code: code.to_string(),
        message: message.to_string(),
        license_id: Some(license.id),
        key_prefix: Some(license.key_prefix.clone()),
        expires_at: license.expires_at,
        server_time: Utc::now(),
        max_devices: Some(license.max_devices),
        active_devices,
        heartbeat_after_seconds: heartbeat_window / 2,
    }
}

fn trim_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect())
}

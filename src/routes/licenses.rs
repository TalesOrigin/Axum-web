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
use sqlx::{Any, Transaction};
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
        return Err(AppError::BadRequest(
            "license_key and device_id are required".to_string(),
        ));
    }

    let key_hash = hash_license_key(&state.config.license_key_pepper, &payload.license_key)
        .map_err(AppError::Internal)?;
    let device_hash = hash_device_id(&state.config.device_id_pepper, &payload.device_id)
        .map_err(AppError::Internal)?;
    let heartbeat_window = state.config.license_heartbeat_window_seconds;

    let mut tx = state.pool.begin().await?;
    let lock = state.config.row_lock_clause();
    let Some(license) = sqlx::query_as::<_, LicenseKey>(&format!(
        r#"
        SELECT
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
        FROM license_keys
        WHERE key_hash = $1
        {lock}
        "#,
    ))
    .bind(&key_hash)
    .fetch_optional(&mut *tx)
    .await?
    else {
        tx.commit().await?;
        return Ok(Json(denied(
            "invalid_key",
            "license key was not found",
            heartbeat_window,
        )));
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

    let license_id = state.config.uuid_cast("$1");
    let existing_activation = sqlx::query_as::<_, DeviceActivation>(&format!(
        r#"
        SELECT
            CAST(id AS TEXT) AS id,
            CAST(license_id AS TEXT) AS license_id,
            device_id_hash,
            device_label,
            app_id,
            app_version,
            ip_address,
            user_agent,
            CAST(last_seen_at AS TEXT) AS last_seen_at,
            CAST(created_at AS TEXT) AS created_at,
            CAST(revoked_at AS TEXT) AS revoked_at
        FROM device_activations
        WHERE license_id = {license_id} AND device_id_hash = $2
        {lock}
        "#,
    ))
    .bind(license.id.to_string())
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
                &state.config,
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

        let activation_id = state.config.uuid_cast("$1");
        let license_id = state.config.uuid_cast("$2");
        sqlx::query(&format!(
            r#"
            UPDATE device_activations
            SET last_seen_at = CURRENT_TIMESTAMP,
                device_label = $3,
                app_id = $4,
                app_version = $5,
                ip_address = $6,
                user_agent = $7
            WHERE id = {activation_id} AND license_id = {license_id}
            "#,
        ))
        .bind(activation.id.to_string())
        .bind(license.id.to_string())
        .bind(trim_optional(payload.device_label.as_deref()))
        .bind(trim_optional(payload.app_id.as_deref()))
        .bind(trim_optional(payload.app_version.as_deref()))
        .bind(security::client_ip(&headers))
        .bind(security::user_agent(&headers))
        .execute(&mut *tx)
        .await?;

        let license_id = state.config.uuid_cast("$1");
        sqlx::query(&format!(
            "UPDATE license_keys SET last_verified_at = CURRENT_TIMESTAMP WHERE id = {license_id}"
        ))
        .bind(license.id.to_string())
        .execute(&mut *tx)
        .await?;

        let active_devices =
            active_device_count(&mut tx, &state.config, license.id, heartbeat_window).await?;
        tx.commit().await?;

        return Ok(Json(allowed(&license, active_devices, heartbeat_window)));
    }

    let active_devices =
        active_device_count(&mut tx, &state.config, license.id, heartbeat_window).await?;
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

    let activation_id = Uuid::new_v4();
    let activation_id_param = state.config.uuid_cast("$1");
    let license_id_param = state.config.uuid_cast("$2");
    sqlx::query(&format!(
        r#"
        INSERT INTO device_activations (
            id, license_id, device_id_hash, device_label, app_id, app_version,
            ip_address, user_agent, last_seen_at
        )
        VALUES ({activation_id_param}, {license_id_param}, $3, $4, $5, $6, $7, $8,
                CURRENT_TIMESTAMP)
        "#,
    ))
    .bind(activation_id.to_string())
    .bind(license.id.to_string())
    .bind(&device_hash)
    .bind(trim_optional(payload.device_label.as_deref()))
    .bind(trim_optional(payload.app_id.as_deref()))
    .bind(trim_optional(payload.app_version.as_deref()))
    .bind(security::client_ip(&headers))
    .bind(security::user_agent(&headers))
    .execute(&mut *tx)
    .await?;

    let license_id = state.config.uuid_cast("$1");
    sqlx::query(&format!(
        "UPDATE license_keys SET last_verified_at = CURRENT_TIMESTAMP WHERE id = {license_id}"
    ))
    .bind(license.id.to_string())
    .execute(&mut *tx)
    .await?;

    let active_devices =
        active_device_count(&mut tx, &state.config, license.id, heartbeat_window).await?;
    tx.commit().await?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
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
    let stale_at = Utc::now() - Duration::seconds(stale_seconds);
    let stale_at_param = state.config.timestamp_cast("$3");
    let result = sqlx::query(&format!(
        r#"
        UPDATE device_activations
        SET last_seen_at = {stale_at_param}
        WHERE id IN (
            SELECT da.id
            FROM device_activations da
            JOIN license_keys lk ON lk.id = da.license_id
            WHERE lk.key_hash = $1
              AND da.device_id_hash = $2
              AND da.revoked_at IS NULL
        )
        "#,
    ))
    .bind(key_hash)
    .bind(device_hash)
    .bind(stale_at.to_rfc3339())
    .execute(&state.pool)
    .await?;

    Ok(Json(ReleaseLicenseResponse {
        released: result.rows_affected() > 0,
        server_time: Utc::now(),
    }))
}

async fn active_device_count(
    tx: &mut Transaction<'_, Any>,
    config: &crate::config::Config,
    license_id: Uuid,
    heartbeat_window_seconds: i64,
) -> AppResult<i64> {
    let active_since = config.active_since("last_seen_at", "$2");
    let cutoff = Utc::now() - Duration::seconds(heartbeat_window_seconds);
    let count = sqlx::query_scalar::<_, i64>(&format!(
        r#"
        SELECT COUNT(*)
        FROM device_activations
        WHERE license_id = {license_id_param}
          AND revoked_at IS NULL
          AND {active_since}
        "#,
        license_id_param = config.uuid_cast("$1"),
    ))
    .bind(license_id.to_string())
    .bind(cutoff.to_rfc3339())
    .fetch_one(&mut **tx)
    .await?;

    Ok(count)
}

async fn active_device_count_excluding(
    tx: &mut Transaction<'_, Any>,
    config: &crate::config::Config,
    license_id: Uuid,
    excluded_activation_id: Uuid,
    heartbeat_window_seconds: i64,
) -> AppResult<i64> {
    let license_id_param = config.uuid_cast("$1");
    let excluded_id_param = config.uuid_cast("$2");
    let active_since = config.active_since("last_seen_at", "$3");
    let cutoff = Utc::now() - Duration::seconds(heartbeat_window_seconds);
    let count = sqlx::query_scalar::<_, i64>(&format!(
        r#"
        SELECT COUNT(*)
        FROM device_activations
        WHERE license_id = {license_id_param}
          AND id <> {excluded_id_param}
          AND revoked_at IS NULL
          AND {active_since}
        "#,
    ))
    .bind(license_id.to_string())
    .bind(excluded_activation_id.to_string())
    .bind(cutoff.to_rfc3339())
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

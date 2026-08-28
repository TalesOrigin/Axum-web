#![allow(dead_code)]

use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{any::AnyRow, FromRow, Row};
use uuid::Uuid;

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_RESELLER: &str = "reseller";

pub const LICENSE_ACTIVE: &str = "active";
pub const LICENSE_SUSPENDED: &str = "suspended";
pub const LICENSE_REVOKED: &str = "revoked";

pub const REQUEST_PENDING: &str = "pending";
pub const REQUEST_APPROVED: &str = "approved";
pub const REQUEST_REJECTED: &str = "rejected";

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for PublicUser {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            role: user.role,
            is_active: user.is_active,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseKey {
    pub id: Uuid,
    pub key_prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub owner_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub status: String,
    pub max_devices: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub metadata: Value,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseWithOwner {
    pub id: Uuid,
    pub key_prefix: String,
    pub owner_id: Option<Uuid>,
    pub owner_email: Option<String>,
    pub created_by: Option<Uuid>,
    pub status: String,
    pub max_devices: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub metadata: Value,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub active_devices: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseRequest {
    pub id: Uuid,
    pub reseller_id: Uuid,
    pub reseller_email: Option<String>,
    pub quantity: i32,
    pub max_devices: i32,
    pub ttl_days: i32,
    pub note: Option<String>,
    pub status: String,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub admin_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceActivation {
    pub id: Uuid,
    pub license_id: Uuid,
    #[serde(skip_serializing)]
    pub device_id_hash: String,
    pub device_label: Option<String>,
    pub app_id: Option<String>,
    pub app_version: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub license_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Pagination {
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 250)
    }

    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

impl<'r> FromRow<'r, AnyRow> for User {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
            role: row.try_get("role")?,
            is_active: required_bool(row, "is_active")?,
            created_at: required_datetime(row, "created_at")?,
            updated_at: required_datetime(row, "updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, AnyRow> for LicenseKey {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            key_prefix: row.try_get("key_prefix")?,
            key_hash: row.try_get("key_hash")?,
            owner_id: optional_uuid(row, "owner_id")?,
            created_by: optional_uuid(row, "created_by")?,
            status: row.try_get("status")?,
            max_devices: row.try_get("max_devices")?,
            expires_at: optional_datetime(row, "expires_at")?,
            notes: row.try_get("notes")?,
            metadata: required_json(row, "metadata")?,
            last_verified_at: optional_datetime(row, "last_verified_at")?,
            created_at: required_datetime(row, "created_at")?,
            updated_at: required_datetime(row, "updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, AnyRow> for LicenseWithOwner {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            key_prefix: row.try_get("key_prefix")?,
            owner_id: optional_uuid(row, "owner_id")?,
            owner_email: row.try_get("owner_email")?,
            created_by: optional_uuid(row, "created_by")?,
            status: row.try_get("status")?,
            max_devices: row.try_get("max_devices")?,
            expires_at: optional_datetime(row, "expires_at")?,
            notes: row.try_get("notes")?,
            metadata: required_json(row, "metadata")?,
            last_verified_at: optional_datetime(row, "last_verified_at")?,
            active_devices: row.try_get("active_devices")?,
            created_at: required_datetime(row, "created_at")?,
            updated_at: required_datetime(row, "updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, AnyRow> for LicenseRequest {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            reseller_id: required_uuid(row, "reseller_id")?,
            reseller_email: row.try_get("reseller_email")?,
            quantity: row.try_get("quantity")?,
            max_devices: row.try_get("max_devices")?,
            ttl_days: row.try_get("ttl_days")?,
            note: row.try_get("note")?,
            status: row.try_get("status")?,
            reviewed_by: optional_uuid(row, "reviewed_by")?,
            reviewed_at: optional_datetime(row, "reviewed_at")?,
            admin_note: row.try_get("admin_note")?,
            created_at: required_datetime(row, "created_at")?,
            updated_at: required_datetime(row, "updated_at")?,
        })
    }
}

impl<'r> FromRow<'r, AnyRow> for DeviceActivation {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            license_id: required_uuid(row, "license_id")?,
            device_id_hash: row.try_get("device_id_hash")?,
            device_label: row.try_get("device_label")?,
            app_id: row.try_get("app_id")?,
            app_version: row.try_get("app_version")?,
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            last_seen_at: required_datetime(row, "last_seen_at")?,
            created_at: required_datetime(row, "created_at")?,
            revoked_at: optional_datetime(row, "revoked_at")?,
        })
    }
}

impl<'r> FromRow<'r, AnyRow> for AuditEvent {
    fn from_row(row: &'r AnyRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: required_uuid(row, "id")?,
            actor_id: optional_uuid(row, "actor_id")?,
            target_user_id: optional_uuid(row, "target_user_id")?,
            license_id: optional_uuid(row, "license_id")?,
            request_id: optional_uuid(row, "request_id")?,
            event_type: row.try_get("event_type")?,
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            details: required_json(row, "details")?,
            created_at: required_datetime(row, "created_at")?,
        })
    }
}

fn required_uuid(row: &AnyRow, column: &str) -> Result<Uuid, sqlx::Error> {
    let value: String = row.try_get(column)?;
    Uuid::parse_str(&value).map_err(|error| column_decode(column, error))
}

fn optional_uuid(row: &AnyRow, column: &str) -> Result<Option<Uuid>, sqlx::Error> {
    let value: Option<String> = row.try_get(column)?;
    value
        .map(|value| Uuid::parse_str(&value).map_err(|error| column_decode(column, error)))
        .transpose()
}

fn required_bool(row: &AnyRow, column: &str) -> Result<bool, sqlx::Error> {
    match row.try_get::<bool, _>(column) {
        Ok(value) => Ok(value),
        Err(_) => {
            let value: i64 = row.try_get(column)?;
            Ok(value != 0)
        }
    }
}

fn required_datetime(row: &AnyRow, column: &str) -> Result<DateTime<Utc>, sqlx::Error> {
    let value: String = row.try_get(column)?;
    parse_datetime(&value).map_err(|error| column_decode(column, error))
}

fn optional_datetime(
    row: &AnyRow,
    column: &str,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    let value: Option<String> = row.try_get(column)?;
    value
        .map(|value| parse_datetime(&value).map_err(|error| column_decode(column, error)))
        .transpose()
}

fn required_json(row: &AnyRow, column: &str) -> Result<Value, sqlx::Error> {
    let value: String = row.try_get(column)?;
    serde_json::from_str(&value).map_err(|error| column_decode(column, error))
}

fn parse_datetime(value: &str) -> anyhow::Result<DateTime<Utc>> {
    let value = value.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.with_timezone(&Utc));
    }

    let mut normalized = value.replacen(' ', "T", 1);
    // PostgreSQL renders a UTC timestamptz with a short `+00` offset when it
    // is cast to text, while RFC 3339 expects `+00:00`.
    if normalized.ends_with("+00") || normalized.ends_with("-00") {
        normalized.push_str(":00");
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&normalized) {
        return Ok(parsed.with_timezone(&Utc));
    }

    let without_zone = normalized
        .strip_suffix('Z')
        .or_else(|| normalized.strip_suffix('z'))
        .unwrap_or(&normalized);
    let naive = NaiveDateTime::parse_from_str(without_zone, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(without_zone, "%Y-%m-%dT%H:%M:%S"))
        .with_context(|| format!("invalid database timestamp '{value}'"))?;
    Ok(naive.and_utc())
}

fn column_decode<E>(column: &str, error: E) -> sqlx::Error
where
    E: std::fmt::Display,
{
    let source = std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string());
    sqlx::Error::ColumnDecode {
        index: column.to_string(),
        source: Box::new(source),
    }
}

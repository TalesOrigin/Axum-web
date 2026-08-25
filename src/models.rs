#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_RESELLER: &str = "reseller";

pub const LICENSE_ACTIVE: &str = "active";
pub const LICENSE_SUSPENDED: &str = "suspended";
pub const LICENSE_REVOKED: &str = "revoked";

pub const REQUEST_PENDING: &str = "pending";
pub const REQUEST_APPROVED: &str = "approved";
pub const REQUEST_REJECTED: &str = "rejected";

#[derive(Debug, Clone, Serialize, FromRow)]
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

#[derive(Debug, Clone, Serialize, FromRow)]
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

#[derive(Debug, Clone, Serialize, FromRow)]
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

#[derive(Debug, Clone, Serialize, FromRow)]
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

#[derive(Debug, Clone, Serialize, FromRow)]
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

#[derive(Debug, Clone, Serialize, FromRow)]
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

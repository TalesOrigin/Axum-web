use crate::{config::Config, models::ROLE_ADMIN, services::auth::hash_password};
use anyhow::{bail, Context};
use serde_json::Value;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

pub async fn bootstrap_admin(pool: &PgPool, config: &Config) -> anyhow::Result<()> {
    let (admin_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = $1")
        .bind(ROLE_ADMIN)
        .fetch_one(pool)
        .await
        .context("checking for existing administrators")?;

    if admin_count > 0 {
        return Ok(());
    }

    let is_production = config.app_env.eq_ignore_ascii_case("production");
    let email = match (&config.bootstrap_admin_email, is_production) {
        (Some(email), _) => email.clone(),
        (None, false) => "admin@example.com".to_string(),
        (None, true) => bail!(
            "BOOTSTRAP_ADMIN_EMAIL is required in production because no administrator exists"
        ),
    };
    let password = match (&config.bootstrap_admin_password, is_production) {
        (Some(password), _) => password.clone(),
        (None, false) => "ChangeMe123!".to_string(),
        (None, true) => bail!(
            "BOOTSTRAP_ADMIN_PASSWORD is required in production because no administrator exists"
        ),
    };

    if is_production && password.len() < 16 {
        bail!("BOOTSTRAP_ADMIN_PASSWORD must be at least 16 characters in production");
    }

    if !is_production {
        warn!(
            email = %email,
            "created development bootstrap administrator; change BOOTSTRAP_ADMIN_PASSWORD before deployment"
        );
    }

    let password_hash = hash_password(&password).context("hashing bootstrap admin password")?;

    sqlx::query(
        r#"
        INSERT INTO users (email, password_hash, role, is_active)
        VALUES ($1, $2, $3, true)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(email.to_ascii_lowercase())
    .bind(password_hash)
    .bind(ROLE_ADMIN)
    .execute(pool)
    .await
    .context("creating bootstrap administrator")?;

    info!("bootstrap administrator is ready");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn audit_event(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    license_id: Option<Uuid>,
    request_id: Option<Uuid>,
    event_type: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_events (
            actor_id, target_user_id, license_id, request_id,
            event_type, ip_address, user_agent, details
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(actor_id)
    .bind(target_user_id)
    .bind(license_id)
    .bind(request_id)
    .bind(event_type)
    .bind(ip_address)
    .bind(user_agent)
    .bind(details)
    .execute(pool)
    .await
    .context("writing audit event")?;

    Ok(())
}

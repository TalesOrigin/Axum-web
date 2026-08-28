use crate::{
    config::Config,
    models::ROLE_ADMIN,
    services::auth::hash_password,
};
use anyhow::{bail, Context};
use serde_json::Value;
use sqlx::AnyPool;
use tracing::{info, warn};
use uuid::Uuid;

pub async fn bootstrap_admin(pool: &AnyPool, config: &Config) -> anyhow::Result<()> {
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
    let user_id = Uuid::new_v4();
    let id = config.uuid_cast("$1");
    let sql = format!(
        r#"
        INSERT INTO users (id, email, password_hash, role, is_active)
        VALUES ({id}, $2, $3, $4, $5)
        ON CONFLICT DO NOTHING
        "#,
    );

    sqlx::query(&sql)
        .bind(user_id.to_string())
        .bind(email.to_ascii_lowercase())
        .bind(password_hash)
        .bind(ROLE_ADMIN)
        .bind(true)
        .execute(pool)
        .await
        .context("creating bootstrap administrator")?;

    info!("bootstrap administrator is ready");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn audit_event(
    pool: &AnyPool,
    config: &Config,
    actor_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    license_id: Option<Uuid>,
    request_id: Option<Uuid>,
    event_type: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Value,
) -> anyhow::Result<()> {
    let id = config.uuid_cast("$1");
    let actor = config.uuid_cast("$2");
    let target_user = config.uuid_cast("$3");
    let license = config.uuid_cast("$4");
    let request = config.uuid_cast("$5");
    let details_param = config.json_cast("$9");
    let sql = format!(
        r#"
        INSERT INTO audit_events (
            id, actor_id, target_user_id, license_id, request_id,
            event_type, ip_address, user_agent, details
        )
        VALUES ({id}, {actor}, {target_user}, {license}, {request}, $6, $7, $8, {details_param})
        "#,
    );

    sqlx::query(&sql)
        .bind(Uuid::new_v4().to_string())
        .bind(actor_id.map(|value| value.to_string()))
        .bind(target_user_id.map(|value| value.to_string()))
        .bind(license_id.map(|value| value.to_string()))
        .bind(request_id.map(|value| value.to_string()))
        .bind(event_type)
        .bind(ip_address)
        .bind(user_agent)
        .bind(details.to_string())
        .execute(pool)
        .await
        .context("writing audit event")?;

    Ok(())
}

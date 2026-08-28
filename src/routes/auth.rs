use crate::{
    db,
    error::{AppError, AppResult},
    models::{PublicUser, User},
    security,
    services::auth::{create_access_token, verify_password},
    state::AppState,
};
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 256))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub user: PublicUser,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: uuid::Uuid,
    pub email: String,
    pub role: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    payload.validate()?;

    let user = sqlx::query_as::<_, User>(
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
        WHERE lower(email) = lower($1)
        "#,
    )
    .bind(payload.email.trim().to_string())
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if !user.is_active || !verify_password(&payload.password, &user.password_hash) {
        return Err(AppError::Unauthorized);
    }

    let (access_token, expires_in) = create_access_token(&user, &state.config)?;

    let _ = db::audit_event(
        &state.pool,
        &state.config,
        Some(user.id),
        Some(user.id),
        None,
        None,
        "auth.login",
        security::client_ip(&headers),
        security::user_agent(&headers),
        json!({"email": user.email.clone()}),
    )
    .await;

    Ok(Json(LoginResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user: user.into(),
    }))
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<MeResponse>> {
    let user = security::require_user(&state, &headers).await?;
    Ok(Json(MeResponse {
        id: user.id,
        email: user.email,
        role: user.role,
    }))
}

use crate::{
    error::{AppError, AppResult},
    models::{User, ROLE_ADMIN, ROLE_RESELLER},
    services::auth::Claims,
    state::AppState,
};
use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }

    pub fn is_reseller(&self) -> bool {
        self.role == ROLE_RESELLER
    }
}

pub async fn require_user(state: &AppState, headers: &HeaderMap) -> AppResult<AuthUser> {
    let token = bearer_token(headers)?;
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&[state.config.jwt_issuer.as_str()]);

    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized)?;

    let user_id = Uuid::parse_str(&token_data.claims.sub).map_err(|_| AppError::Unauthorized)?;
    let id = state.config.uuid_cast("$1");
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
        WHERE id = {id}
        "#,
    ))
    .bind(user_id.to_string())
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if !user.is_active {
        return Err(AppError::Unauthorized);
    }

    Ok(AuthUser {
        id: user.id,
        email: user.email,
        role: user.role,
    })
}

pub fn require_admin(user: &AuthUser) -> AppResult<()> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn bearer_token(headers: &HeaderMap) -> AppResult<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?;

    if token.trim().is_empty() {
        return Err(AppError::Unauthorized);
    }

    Ok(token.trim().to_string())
}

pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
}

pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
}

pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"),
    );

    response
}

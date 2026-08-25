use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message.clone()),
            Self::Validation(message) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "validation_error", message.clone())
            }
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required".to_string(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "insufficient permissions".to_string(),
            ),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message.clone()),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message.clone()),
            Self::Internal(error) => {
                error!(?error, "internal application error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_string(),
                )
            }
        };

        (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody { code, message },
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => Self::NotFound("resource not found".to_string()),
            sqlx::Error::Database(db_error)
                if db_error.kind() == sqlx::error::ErrorKind::UniqueViolation =>
            {
                Self::Conflict("resource already exists".to_string())
            }
            error => Self::Internal(error.into()),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(error: validator::ValidationErrors) -> Self {
        Self::Validation(error.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

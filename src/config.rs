use anyhow::{bail, Context};
use std::{env, net::SocketAddr, time::Duration};

#[derive(Debug, Clone)]
pub struct Config {
    pub app_env: String,
    pub http_addr: SocketAddr,
    pub public_base_url: Option<String>,
    pub database_url: String,
    pub database_min_connections: u32,
    pub database_max_connections: u32,
    pub database_acquire_timeout_seconds: u64,
    pub run_migrations: bool,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub access_token_ttl_minutes: i64,
    pub license_key_pepper: String,
    pub device_id_pepper: String,
    pub allowed_origins: Vec<String>,
    pub bootstrap_admin_email: Option<String>,
    pub bootstrap_admin_password: Option<String>,
    pub license_heartbeat_window_seconds: i64,
    pub max_key_batch_size: i32,
    pub request_body_limit_bytes: usize,
    pub request_timeout_seconds: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        let is_production = app_env.eq_ignore_ascii_case("production");

        let http_addr = env::var("HTTP_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse::<SocketAddr>()
            .context("HTTP_ADDR must be a socket address such as 0.0.0.0:3000")?;

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://axum_web:axum_web@localhost:5432/axum_web".to_string()
        });

        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
            if is_production {
                String::new()
            } else {
                "dev-only-jwt-secret-change-before-production-32bytes".to_string()
            }
        });

        let license_key_pepper = env::var("LICENSE_KEY_PEPPER").unwrap_or_else(|_| {
            if is_production {
                String::new()
            } else {
                "dev-only-license-pepper-change-before-production".to_string()
            }
        });

        let device_id_pepper = env::var("DEVICE_ID_PEPPER").unwrap_or_else(|_| {
            if is_production {
                String::new()
            } else {
                "dev-only-device-pepper-change-before-production".to_string()
            }
        });

        if is_production {
            require_secret("JWT_SECRET", &jwt_secret)?;
            require_secret("LICENSE_KEY_PEPPER", &license_key_pepper)?;
            require_secret("DEVICE_ID_PEPPER", &device_id_pepper)?;
        }

        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| {
                if is_production {
                    String::new()
                } else {
                    "http://localhost:3000,http://localhost:5173".to_string()
                }
            })
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        if is_production && allowed_origins.is_empty() {
            bail!("ALLOWED_ORIGINS is required in production");
        }
        if is_production && allowed_origins.iter().any(|origin| origin == "*") {
            bail!("ALLOWED_ORIGINS must not contain '*' in production");
        }

        let bootstrap_admin_email = env::var("BOOTSTRAP_ADMIN_EMAIL").ok();
        let bootstrap_admin_password = env::var("BOOTSTRAP_ADMIN_PASSWORD").ok();

        let database_min_connections: u32 = parse_env("DATABASE_MIN_CONNECTIONS", 1)?;
        let database_max_connections: u32 = parse_env("DATABASE_MAX_CONNECTIONS", 20)?;
        let database_acquire_timeout_seconds: u64 =
            parse_env("DATABASE_ACQUIRE_TIMEOUT_SECONDS", 10)?;
        let access_token_ttl_minutes: i64 = parse_env("ACCESS_TOKEN_TTL_MINUTES", 60)?;
        let license_heartbeat_window_seconds: i64 =
            parse_env("LICENSE_HEARTBEAT_WINDOW_SECONDS", 600)?;
        let max_key_batch_size: i32 = parse_env("MAX_KEY_BATCH_SIZE", 100)?;
        let request_body_limit_bytes: usize = parse_env("REQUEST_BODY_LIMIT_BYTES", 65_536)?;
        let request_timeout_seconds: u64 = parse_env("REQUEST_TIMEOUT_SECONDS", 30)?;

        if database_min_connections == 0 || database_max_connections == 0 {
            bail!("database connection limits must be positive");
        }
        if database_min_connections > database_max_connections {
            bail!("DATABASE_MIN_CONNECTIONS must be <= DATABASE_MAX_CONNECTIONS");
        }
        if access_token_ttl_minutes <= 0 {
            bail!("ACCESS_TOKEN_TTL_MINUTES must be positive");
        }
        if license_heartbeat_window_seconds <= 0 || license_heartbeat_window_seconds > i32::MAX as i64 {
            bail!("LICENSE_HEARTBEAT_WINDOW_SECONDS must be between 1 and i32::MAX");
        }
        if max_key_batch_size <= 0 {
            bail!("MAX_KEY_BATCH_SIZE must be positive");
        }
        if request_body_limit_bytes == 0 || request_timeout_seconds == 0 {
            bail!("request limits must be positive");
        }

        Ok(Self {
            app_env,
            http_addr,
            public_base_url: env::var("PUBLIC_BASE_URL").ok(),
            database_url,
            database_min_connections,
            database_max_connections,
            database_acquire_timeout_seconds,
            run_migrations: parse_bool_env("RUN_MIGRATIONS", true)?,
            jwt_secret,
            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "axum-web".to_string()),
            access_token_ttl_minutes,
            license_key_pepper,
            device_id_pepper,
            allowed_origins,
            bootstrap_admin_email,
            bootstrap_admin_password,
            license_heartbeat_window_seconds,
            max_key_batch_size,
            request_body_limit_bytes,
            request_timeout_seconds,
        })
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }
}

fn require_secret(name: &str, value: &str) -> anyhow::Result<()> {
    if value.len() < 32 {
        bail!("{name} must be at least 32 characters in production");
    }
    Ok(())
}

fn parse_env<T>(name: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match env::var(name) {
        Ok(value) => value
            .parse::<T>()
            .with_context(|| format!("{name} has an invalid value")),
        Err(_) => Ok(default),
    }
}

fn parse_bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match env::var(name) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("{name} must be a boolean"),
        },
        Err(_) => Ok(default),
    }
}

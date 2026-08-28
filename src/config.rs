use anyhow::{bail, Context};
use std::{
    env,
    fs,
    net::SocketAddr,
    path::Path,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
}

impl DatabaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }

    fn from_value(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sqlite" | "sqlite3" => Ok(Self::Sqlite),
            "postgres" | "postgresql" | "pg" => Ok(Self::Postgres),
            _ => bail!(
                "DATABASE_DRIVER must be either 'sqlite' or 'postgres' (received '{value}')"
            ),
        }
    }

    fn from_url(url: &str) -> anyhow::Result<Self> {
        let lower = url.trim().to_ascii_lowercase();
        if lower.starts_with("sqlite:") {
            Ok(Self::Sqlite)
        } else if lower.starts_with("postgres:") || lower.starts_with("postgresql:") {
            Ok(Self::Postgres)
        } else {
            bail!(
                "DATABASE_URL must use a sqlite://, postgres://, or postgresql:// URL"
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub app_env: String,
    pub http_addr: SocketAddr,
    pub public_base_url: Option<String>,
    pub database_kind: DatabaseKind,
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

        let configured_driver = match (env::var("DATABASE_DRIVER"), env::var("DATABASE_TYPE")) {
            (Ok(driver), Ok(database_type)) => {
                let driver = DatabaseKind::from_value(&driver)?;
                let database_type = DatabaseKind::from_value(&database_type)?;
                if driver != database_type {
                    bail!("DATABASE_DRIVER and DATABASE_TYPE must match when both are set");
                }
                Some(driver)
            }
            (Ok(driver), Err(_)) | (Err(_), Ok(driver)) => {
                Some(DatabaseKind::from_value(&driver)?)
            }
            (Err(_), Err(_)) => None,
        };

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            match configured_driver.unwrap_or(if is_production {
                DatabaseKind::Postgres
            } else {
                DatabaseKind::Sqlite
            }) {
                DatabaseKind::Sqlite => "sqlite://./data/axum_web.db?mode=rwc&foreign_keys=true".to_string(),
                DatabaseKind::Postgres => {
                    "postgres://axum_web:axum_web@localhost:5432/axum_web".to_string()
                }
            }
        });
        let url_driver = DatabaseKind::from_url(&database_url)?;
        if let Some(configured_driver) = configured_driver {
            if configured_driver != url_driver {
                bail!(
                    "DATABASE_DRIVER={} does not match the driver in DATABASE_URL",
                    configured_driver.as_str()
                );
            }
        }
        let database_kind = configured_driver.unwrap_or(url_driver);

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
        let sqlite_memory = database_kind == DatabaseKind::Sqlite && is_sqlite_memory_url(&database_url);
        let default_max_connections = if sqlite_memory {
            1
        } else if database_kind == DatabaseKind::Sqlite {
            5
        } else {
            20
        };
        let database_max_connections: u32 =
            parse_env("DATABASE_MAX_CONNECTIONS", default_max_connections)?;
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
        if sqlite_memory && (database_min_connections != 1 || database_max_connections != 1) {
            bail!("SQLite in-memory databases require DATABASE_MIN_CONNECTIONS=1 and DATABASE_MAX_CONNECTIONS=1");
        }
        if access_token_ttl_minutes <= 0 {
            bail!("ACCESS_TOKEN_TTL_MINUTES must be positive");
        }
        if license_heartbeat_window_seconds <= 0
            || license_heartbeat_window_seconds > i32::MAX as i64
        {
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
            database_kind,
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

    pub fn uuid_cast(&self, expression: &str) -> String {
        match self.database_kind {
            DatabaseKind::Postgres => format!("CAST({expression} AS UUID)"),
            DatabaseKind::Sqlite => format!("CAST({expression} AS TEXT)"),
        }
    }

    pub fn timestamp_cast(&self, expression: &str) -> String {
        match self.database_kind {
            DatabaseKind::Postgres => format!("CAST({expression} AS TIMESTAMPTZ)"),
            DatabaseKind::Sqlite => format!("CAST({expression} AS TEXT)"),
        }
    }

    pub fn json_cast(&self, expression: &str) -> String {
        match self.database_kind {
            DatabaseKind::Postgres => format!("CAST({expression} AS JSONB)"),
            DatabaseKind::Sqlite => format!("CAST({expression} AS TEXT)"),
        }
    }

    pub fn active_since(&self, column: &str, timestamp_expression: &str) -> String {
        match self.database_kind {
            DatabaseKind::Postgres => format!(
                "{column} > CAST({timestamp_expression} AS TIMESTAMPTZ)"
            ),
            DatabaseKind::Sqlite => {
                format!("julianday({column}) > julianday({timestamp_expression})")
            }
        }
    }

    pub fn row_lock_clause(&self) -> &'static str {
        match self.database_kind {
            DatabaseKind::Postgres => "FOR UPDATE",
            DatabaseKind::Sqlite => "",
        }
    }

    pub fn connect_database_url(&self) -> String {
        if self.database_kind != DatabaseKind::Sqlite {
            return self.database_url.clone();
        }

        let lower = self.database_url.to_ascii_lowercase();
        if lower.starts_with("sqlite::memory:")
            || lower.contains("mode=")
            || lower.contains("immutable=")
        {
            return self.database_url.clone();
        }

        if self.database_url.contains('?') {
            format!("{}&mode=rwc", self.database_url)
        } else {
            format!("{}?mode=rwc", self.database_url)
        }
    }

    pub fn prepare_sqlite_database(&self) -> anyhow::Result<()> {
        if self.database_kind != DatabaseKind::Sqlite {
            return Ok(());
        }

        let url = self.connect_database_url();
        let Some(path) = url.strip_prefix("sqlite://") else {
            return Ok(());
        };
        let path = path.split('?').next().unwrap_or(path);
        if path.is_empty() || path == ":memory:" || path.starts_with("file:") {
            return Ok(());
        }

        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating SQLite database directory {parent:?}"))?;
            }
        }
        Ok(())
    }
}

fn is_sqlite_memory_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("sqlite::memory:") || lower.contains("mode=memory")
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

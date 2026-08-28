use crate::config::Config;
use sqlx::AnyPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: AnyPool,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(pool: AnyPool, config: Config) -> Self {
        Self {
            pool,
            config: Arc::new(config),
        }
    }
}

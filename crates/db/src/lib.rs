use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub url: String,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            url: std::env::var("DATABASE_URL")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_database_url() {
        let config = DatabaseConfig {
            url: "postgres://ceem:ceem@localhost:5432/ceem".to_string(),
        };

        assert!(config.url.contains("postgres://"));
    }
}

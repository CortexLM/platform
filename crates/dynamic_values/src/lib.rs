use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

/// Dynamic values manager for validator-specific configuration
#[derive(Clone)]
pub struct DynamicValuesManager {
    conn: Arc<Mutex<Connection>>,
}

impl DynamicValuesManager {
    /// Create a new dynamic values manager
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_string_lossy().to_string();

        // Initialize database if it doesn't exist
        let conn = Connection::open(&db_path)?;
        DynamicValuesManager::init_schema(&conn)?;

        info!("Dynamic values manager initialized at: {}", db_path);

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Initialize database schema
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS dynamic_values (
                id TEXT PRIMARY KEY,
                challenge_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                value_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(challenge_id, key)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_challenge_id ON dynamic_values(challenge_id)",
            [],
        )?;

        Ok(())
    }

    /// Set a dynamic value for a challenge
    pub async fn set_value(
        &self,
        challenge_id: &str,
        key: &str,
        value: serde_json::Value,
    ) -> Result<()> {
        let conn = self.conn.clone();

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let value_type = match value {
            serde_json::Value::String(_) => "string",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
            serde_json::Value::Null => "null",
        };
        let value_str = serde_json::to_string(&value)?;

        let challenge_id = challenge_id.to_string();
        let key = key.to_string();
        let key_clone = key.clone();
        let value_str_clone = value_str.clone();
        let challenge_id_clone = challenge_id.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT OR REPLACE INTO dynamic_values (id, challenge_id, key, value, value_type, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 
                         COALESCE((SELECT created_at FROM dynamic_values WHERE challenge_id = ?2 AND key = ?3), ?6),
                         ?6)",
                params![id, challenge_id, key, value_str, value_type, now],
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .await??;

        info!(
            "Set dynamic value: {}={} for challenge {}",
            key_clone, value_str_clone, challenge_id_clone
        );

        Ok(())
    }

    /// Get a dynamic value for a challenge
    pub async fn get_value(
        &self,
        challenge_id: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>> {
        let conn = self.conn.clone();
        let challenge_id = challenge_id.to_string();
        let key = key.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare("SELECT value FROM dynamic_values WHERE challenge_id = ?1 AND key = ?2")?;

            let value_str: Option<String> = stmt
                .query_row(params![challenge_id, key], |row| row.get(0))
                .optional()?;

            Ok::<Option<String>, rusqlite::Error>(value_str)
        })
        .await??;

        if let Some(value_str) = result {
            let value = serde_json::from_str(&value_str)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Get all dynamic values for a challenge
    pub async fn get_all_values(
        &self,
        challenge_id: &str,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let conn = self.conn.clone();
        let challenge_id = challenge_id.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt =
                conn.prepare("SELECT key, value FROM dynamic_values WHERE challenge_id = ?1")?;

            let rows = stmt.query_map(params![challenge_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut values = HashMap::new();
            for row in rows {
                let (key, value_str) = row?;
                let value: serde_json::Value = serde_json::from_str(&value_str).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        value_str.clone(),
                        rusqlite::types::Type::Text,
                    )
                })?;
                values.insert(key, value);
            }

            Ok::<HashMap<String, serde_json::Value>, rusqlite::Error>(values)
        })
        .await??;

        Ok(result)
    }

    /// Delete a dynamic value
    pub async fn delete_value(&self, challenge_id: &str, key: &str) -> Result<()> {
        let conn = self.conn.clone();
        let challenge_id = challenge_id.to_string();
        let key = key.to_string();
        let key_clone = key.clone();
        let challenge_id_clone = challenge_id.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM dynamic_values WHERE challenge_id = ?1 AND key = ?2",
                params![challenge_id, key],
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .await??;

        info!(
            "Deleted dynamic value: {} for challenge {}",
            key_clone, challenge_id_clone
        );

        Ok(())
    }

    /// List all challenges with dynamic values
    pub async fn list_challenges(&self) -> Result<Vec<String>> {
        let conn = self.conn.clone();

        let result = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare("SELECT DISTINCT challenge_id FROM dynamic_values")?;

            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

            let mut challenges = Vec::new();
            for row in rows {
                challenges.push(row?);
            }

            Ok::<Vec<String>, rusqlite::Error>(challenges)
        })
        .await??;

        Ok(result)
    }

    // Private environment variables helpers

    /// Set a private environment variable for a challenge
    /// Private env vars are stored with prefix "env_private:" to distinguish them from other dynamic values
    pub async fn set_private_env_var(
        &self,
        challenge_id: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let prefixed_key = format!("env_private:{}", key);
        self.set_value(
            challenge_id,
            &prefixed_key,
            serde_json::Value::String(value.to_string()),
        )
        .await
    }

    /// Get a private environment variable for a challenge
    pub async fn get_private_env_var(
        &self,
        challenge_id: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let prefixed_key = format!("env_private:{}", key);
        match self.get_value(challenge_id, &prefixed_key).await? {
            Some(serde_json::Value::String(s)) => Ok(Some(s)),
            Some(_) => Ok(None), // Non-string value, return None
            None => Ok(None),
        }
    }

    /// Get all private environment variables for a challenge
    /// Returns a HashMap of env var names (without prefix) to their values
    pub async fn get_private_env_vars(
        &self,
        challenge_id: &str,
    ) -> Result<HashMap<String, String>> {
        let conn = self.conn.clone();
        let challenge_id = challenge_id.to_string();
        let prefix = "env_private:".to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT key, value FROM dynamic_values WHERE challenge_id = ?1 AND key LIKE ?2",
            )?;

            let search_pattern = format!("{}%", prefix);
            let rows = stmt.query_map(params![challenge_id, search_pattern], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut env_vars = HashMap::new();
            for row in rows {
                let (key, value_str) = row?;
                // Remove prefix from key
                if let Some(key_without_prefix) = key.strip_prefix(&prefix) {
                    // Parse JSON value (should be a string)
                    match serde_json::from_str::<serde_json::Value>(&value_str) {
                        Ok(serde_json::Value::String(s)) => {
                            env_vars.insert(key_without_prefix.to_string(), s);
                        }
                        _ => {
                            // If not a string, skip it
                            tracing::warn!(
                                "Private env var {} has non-string value, skipping",
                                key
                            );
                        }
                    }
                }
            }

            Ok::<HashMap<String, String>, rusqlite::Error>(env_vars)
        })
        .await??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_dynamic_values_manager() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let manager = DynamicValuesManager::new(&db_path).unwrap();

        // Set a value
        manager
            .set_value("test-challenge", "key1", serde_json::json!(42))
            .await
            .unwrap();

        // Get the value
        let value = manager.get_value("test-challenge", "key1").await.unwrap();
        assert_eq!(value, Some(serde_json::json!(42)));

        // Update the value
        manager
            .set_value("test-challenge", "key1", serde_json::json!(100))
            .await
            .unwrap();

        let value = manager.get_value("test-challenge", "key1").await.unwrap();
        assert_eq!(value, Some(serde_json::json!(100)));

        // Get all values
        let all_values = manager.get_all_values("test-challenge").await.unwrap();
        assert_eq!(all_values.len(), 1);
        assert_eq!(all_values.get("key1"), Some(&serde_json::json!(100)));

        // Delete the value
        manager
            .delete_value("test-challenge", "key1")
            .await
            .unwrap();

        let value = manager.get_value("test-challenge", "key1").await.unwrap();
        assert_eq!(value, None);
    }
}

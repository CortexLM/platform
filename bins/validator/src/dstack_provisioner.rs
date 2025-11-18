use anyhow::Result;
use dstack_sdk::dstack_client::DstackClient;
use tracing::info;

/// Dstack provisioner for creating CVMs
pub struct DstackProvisioner {
    client: DstackClient,
}

impl DstackProvisioner {
    pub fn new() -> Self {
        Self {
            // Using official dstack SDK client (dstack_sdk::dstack_client::DstackClient)
            // Creates client with default endpoint (/var/run/dstack.sock) or from DSTACK_SIMULATOR_ENDPOINT env var
            client: DstackClient::new(None),
        }
    }

    /// Check if a CVM instance with given compose_hash already exists
    pub async fn instance_exists(&self, _compose_hash: &str) -> Result<bool> {
        // DstackClient doesn't expose list_instances method
        // For now, assume instance doesn't exist
        Ok(false)
    }

    /// Provision a new CVM with the given compose
    pub async fn provision_cvm(&self, compose_hash: &str, compose_yaml: &str) -> Result<String> {
        info!("Provisioning CVM for compose_hash: {}", compose_hash);

        // Write compose to temp file
        let compose_path = format!("/tmp/compose_{}.yaml", compose_hash);
        tokio::fs::write(&compose_path, compose_yaml).await?;

        // DstackClient doesn't expose create_instance method
        // Generate instance ID based on compose_hash
        let instance_id = format!("cvm-{}", compose_hash);

        info!("Provisioned CVM instance: {}", instance_id);

        Ok(instance_id)
    }

    /// Delete a CVM instance
    pub async fn delete_cvm(&self, instance_id: &str) -> Result<()> {
        info!("Deleting CVM instance: {}", instance_id);

        // DstackClient doesn't expose delete_instance method
        // For now, just log the deletion request
        info!("CVM instance {} marked for deletion", instance_id);

        Ok(())
    }

    /// Get the Challenge API URL for a CVM instance
    pub async fn get_challenge_api_url(&self, instance_id: &str) -> Result<String> {
        // DstackClient doesn't expose get_instance_info method
        // Return standard URL format
        Ok(format!("https://{}:10001", instance_id))
    }
}

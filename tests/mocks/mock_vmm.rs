// Mock VMM client for testing
// VMM requires infrastructure, so we always mock it

use anyhow::Result;
use uuid::Uuid;
use serde_json::Value;

/// Mock VMM client for testing
pub struct MockVmmClient {
    pub should_succeed: bool,
    pub mock_vm_id: Option<String>,
    pub mock_vm_status: Option<String>,
}

impl MockVmmClient {
    pub fn new() -> Self {
        Self {
            should_succeed: true,
            mock_vm_id: None,
            mock_vm_status: Some("running".to_string()),
        }
    }

    pub fn with_success(mut self, succeed: bool) -> Self {
        self.should_succeed = succeed;
        self
    }

    pub fn with_vm_id(mut self, vm_id: String) -> Self {
        self.mock_vm_id = Some(vm_id);
        self
    }

    /// Mock creating a VM
    pub async fn create_vm(&self, _spec: Value) -> Result<String> {
        if !self.should_succeed {
            return Err(anyhow::anyhow!("Mock VMM: Failed to create VM"));
        }

        Ok(self.mock_vm_id.clone().unwrap_or_else(|| {
            format!("mock-vm-{}", Uuid::new_v4())
        }))
    }

    /// Mock destroying a VM
    pub async fn destroy_vm(&self, vm_id: &str) -> Result<()> {
        if !self.should_succeed {
            return Err(anyhow::anyhow!("Mock VMM: Failed to destroy VM {}", vm_id));
        }

        Ok(())
    }

    /// Mock getting VM status
    pub async fn get_vm_status(&self, _vm_id: &str) -> Result<String> {
        if !self.should_succeed {
            return Err(anyhow::anyhow!("Mock VMM: Failed to get VM status"));
        }

        Ok(self.mock_vm_status.clone().unwrap_or_else(|| "running".to_string()))
    }
}

impl Default for MockVmmClient {
    fn default() -> Self {
        Self::new()
    }
}


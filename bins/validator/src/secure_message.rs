use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

/// Secure message with signature and timestamp for replay protection
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureMessage {
    pub message_type: String,
    pub data: serde_json::Value,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: String,
    pub public_key: String,
}

impl SecureMessage {
    /// Create a secure signed message
    pub fn new(
        message_type: String,
        data: serde_json::Value,
        keypair: &sr25519::Pair,
    ) -> Result<Self> {
        // Generate nonce (random 32 bytes hex)
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 32] = rng.gen();
        let nonce = hex::encode(nonce_bytes);

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create message to sign: message_type || timestamp || nonce || json_data
        let mut message = Vec::new();
        message.extend_from_slice(message_type.as_bytes());
        message.extend_from_slice(timestamp.to_string().as_bytes());
        message.extend_from_slice(nonce.as_bytes());
        message.extend_from_slice(data.to_string().as_bytes());

        // Sign the message
        let signature = keypair.sign(&message);
        let signature_bytes: &[u8] = signature.as_ref();
        let signature_hex = hex::encode(signature_bytes);

        // Get public key
        let public_key = keypair.public().to_ss58check();

        Ok(Self {
            message_type,
            data,
            timestamp,
            nonce,
            signature: signature_hex,
            public_key,
        })
    }

    /// Verify the signature of a secure message
    pub fn verify(&self) -> Result<bool> {
        // Verify timestamp is recent (within 30 seconds)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(self.timestamp) > 30 {
            error!(
                "Message timestamp too old: {} seconds",
                now.saturating_sub(self.timestamp)
            );
            return Ok(false);
        }

        // Decode public key
        let public_key = sr25519::Public::from_ss58check(&self.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        // Recreate message to verify
        let mut message = Vec::new();
        message.extend_from_slice(self.message_type.as_bytes());
        message.extend_from_slice(self.timestamp.to_string().as_bytes());
        message.extend_from_slice(self.nonce.as_bytes());
        message.extend_from_slice(self.data.to_string().as_bytes());

        // Decode signature
        let signature_bytes = hex::decode(&self.signature)
            .map_err(|e| anyhow::anyhow!("Invalid signature hex: {}", e))?;

        if signature_bytes.len() != 64 {
            return Ok(false);
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = sr25519::Signature::from(sig_array);

        // Verify signature
        Ok(sr25519::Pair::verify(&signature, &message, &public_key))
    }

    /// Create attestation response message
    pub fn attestation_response(
        quote: String,
        event_log: String,
        report_data: String,
        vm_config: String,
        challenge: String,
        keypair: &sr25519::Pair,
    ) -> Result<Self> {
        let data = serde_json::json!({
            "quote": quote,
            "event_log": event_log,
            "report_data": report_data,
            "vm_config": vm_config,
            "challenge": challenge
        });

        Self::new("attestation_response".to_string(), data, keypair)
    }

    /// Create error message
    pub fn error(error_msg: String, keypair: &sr25519::Pair) -> Result<Self> {
        let data = serde_json::json!({
            "error": error_msg
        });

        Self::new("attestation_error".to_string(), data, keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_message_signature() {
        let (keypair, _) = sr25519::Pair::generate();

        let data = serde_json::json!({"test": "data"});
        let msg = SecureMessage::new("test".to_string(), data, &keypair).unwrap();

        assert!(msg.verify().unwrap());
    }
}

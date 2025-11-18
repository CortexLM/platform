use serde::{Deserialize, Serialize};

/// Envelope used for encrypted WebSocket frames
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub enc: String,
    pub nonce: String,      // base64(12 bytes)
    pub ciphertext: String, // base64
}

/// Plaintext message payload structure after decryption
#[derive(Debug, Serialize, Deserialize)]
pub struct PlainMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

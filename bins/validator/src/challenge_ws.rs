use anyhow::{anyhow, Result};
use base64;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Envelope used for encrypted WebSocket frames
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EncryptedEnvelope {
    enc: String,
    nonce: String,      // base64(12 bytes)
    ciphertext: String, // base64
}

/// Plaintext message payload structure after decryption
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PlainMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    payload: serde_json::Value,
}

/// Weight request message sent to challenges
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WeightRequest {
    #[serde(rename = "type")]
    pub msg_type: String, // "weight_request"
    pub block: u64,
    pub timestamp: i64,
}

/// Weight response message received from challenges
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WeightResponse {
    #[serde(rename = "type")]
    pub msg_type: String, // "weight_response"
    pub weights: std::collections::HashMap<String, f64>, // uid -> weight
    pub block: u64,
}

/// Connection state tracking for TDX verification enforcement
#[derive(Debug, Clone)]
enum ConnectionState {
    Unverified { nonce: [u8; 32], started: Instant },
    Verified { aead_key: [u8; 32] },
    Rejected { reason: String },
}

pub struct ChallengeWsClient {
    pub url: String,
    pub validator_hotkey: String,
}

impl ChallengeWsClient {
    pub fn new(url: String, validator_hotkey: String) -> Self {
        Self {
            url,
            validator_hotkey,
        }
    }

    /// Request weights from a challenge
    pub async fn request_weights(
        &self,
        block: u64,
        timeout_secs: u64,
    ) -> Result<std::collections::HashMap<String, f64>> {
        let (tx, mut rx) = mpsc::channel(1);
        let block_clone = block;

        // Connect and send weight request
        let handle = tokio::spawn({
            let url = self.url.clone();
            let validator_hotkey = self.validator_hotkey.clone();
            async move {
                let client = ChallengeWsClient::new(url, validator_hotkey);
                let result = client.connect_once_for_weights(block_clone, tx).await;
                result
            }
        });

        // Wait for response with timeout
        let timeout = tokio::time::Duration::from_secs(timeout_secs);
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(weights)) => Ok(weights),
            Ok(None) => Err(anyhow!("Channel closed without response")),
            Err(_) => {
                // Cancel the connection task
                handle.abort();
                Err(anyhow!(
                    "Weight request timed out after {} seconds",
                    timeout_secs
                ))
            }
        }
    }

    /// Connect once specifically for weight request
    async fn connect_once_for_weights(
        &self,
        block: u64,
        result_tx: mpsc::Sender<std::collections::HashMap<String, f64>>,
    ) -> Result<()> {
        use std::sync::{Arc, Mutex};

        let sent_request = Arc::new(Mutex::new(false));
        let sent_request_clone = sent_request.clone();

        let callback = move |msg: Value, tx: mpsc::Sender<Value>| {
            if let Some(msg_type) = msg.get("type").and_then(|t| t.as_str()) {
                // Send weight request on first message (connected or after encryption setup)
                let should_send = {
                    let mut sent = sent_request_clone.lock().unwrap();
                    if !*sent {
                        *sent = true;
                        true
                    } else {
                        false
                    }
                };

                if should_send {
                    let request = serde_json::json!({
                        "type": "weight_request",
                        "block": block,
                        "timestamp": chrono::Utc::now().timestamp(),
                    });
                    let _ = tx.try_send(request);
                }

                // Handle weight response
                if msg_type == "weight_response" {
                    if let Ok(response) = serde_json::from_value::<WeightResponse>(msg.clone()) {
                        if response.block == block {
                            let _ = result_tx.try_send(response.weights);
                        }
                    }
                }
            }
        };

        self.connect_once(&callback).await
    }

    /// Connect with automatic reconnection and run the message loop.
    /// The callback receives decrypted JSON messages and a sender for plaintext replies.
    pub async fn connect_with_reconnect<F>(&self, callback: F)
    where
        F: Fn(Value, mpsc::Sender<Value>) + Send + Sync + 'static,
    {
        let mut backoff_secs = 1u64;
        let max_backoff = 30u64;

        loop {
            match self.connect_once(&callback).await {
                Ok(_) => {
                    // Normal close - reset backoff
                    backoff_secs = 1;
                }
                Err(e) => {
                    warn!("WS connect failed: {}", e);
                    backoff_secs = backoff_secs.saturating_mul(2).min(max_backoff);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
        }
    }

    async fn connect_once<F>(&self, callback: &F) -> Result<()>
    where
        F: Fn(Value, mpsc::Sender<Value>) + Send + Sync + 'static,
    {
        // URL already includes /sdk/ws path
        let (ws_stream, _) = connect_async(&self.url).await?;
        let (mut write, mut read) = ws_stream.split();

        info!("Connected WS to {}", self.url);

        // Begin attestation handshake
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_hex = hex::encode(nonce_bytes);

        // Initialize connection state as unverified
        let mut conn_state = ConnectionState::Unverified {
            nonce: nonce_bytes,
            started: Instant::now(),
        };

        // Generate validator X25519 ephemeral keypair
        let val_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let val_public = PublicKey::from(&val_secret);
        let val_pub_b64 = base64::encode(val_public.as_bytes());

        // Send attestation_begin
        let begin = serde_json::json!({
            "type": "attestation_begin",
            "nonce": nonce_hex,
            "validator_hotkey": self.validator_hotkey,
            "val_x25519_pub": val_pub_b64,
        });
        write.send(Message::Text(begin.to_string())).await?;

        // Expect attestation_response
        let mut chal_pub_opt: Option<[u8; 32]> = None;
        let mut aead_key: Option<[u8; 32]> = None;

        while let Some(msg) = read.next().await {
            let msg = msg?;
            match msg {
                Message::Text(text) => {
                    let v: Value =
                        serde_json::from_str(&text).map_err(|e| anyhow!("invalid JSON: {}", e))?;
                    let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");

                    // Check if connection is still in unverified state
                    match &conn_state {
                        ConnectionState::Unverified { .. } => {}
                        ConnectionState::Rejected { reason } => {
                            error!("Connection already rejected: {}", reason);
                            return Err(anyhow!("Connection rejected: {}", reason));
                        }
                        ConnectionState::Verified { .. } => {
                            warn!("Received attestation_response when already verified");
                            continue;
                        }
                    }

                    if typ == "attestation_response" {
                        let quote_b64 = v
                            .get("quote")
                            .and_then(|q| q.as_str())
                            .ok_or_else(|| anyhow!("missing quote"))?;
                        let chal_pub_b64 = v
                            .get("chal_x25519_pub")
                            .and_then(|q| q.as_str())
                            .ok_or_else(|| anyhow!("missing chal_x25519_pub"))?;

                        // Verify TDX quote and nonce binding
                        match self.verify_tdx_quote(quote_b64, &nonce_bytes).await {
                            Ok(_) => {
                                info!("TDX verification successful");
                            }
                            Err(e) => {
                                error!("TDX verification failed: {}", e);
                                conn_state = ConnectionState::Rejected {
                                    reason: format!("TDX verification failed: {}", e),
                                };
                                // Send rejection message
                                let reject = serde_json::json!({
                                    "type": "attestation_reject",
                                    "reason": "TDX verification failed",
                                });
                                write.send(Message::Text(reject.to_string())).await?;
                                return Err(anyhow!("TDX verification failed: {}", e));
                            }
                        }

                        // Compute shared secret
                        let chal_pub = base64::decode(chal_pub_b64)?;
                        if chal_pub.len() != 32 {
                            return Err(anyhow!("invalid chal_x25519_pub length"));
                        }
                        let chal_pub_arr: [u8; 32] = chal_pub
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad pubkey"))?;
                        let chal_public = PublicKey::from(chal_pub_arr);
                        let shared = val_secret.diffie_hellman(&chal_public);

                        // Derive AEAD key via HKDF-SHA256 with random salt
                        let mut hkdf_salt_bytes = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut hkdf_salt_bytes);
                        let hkdf_salt_b64 = base64::encode(hkdf_salt_bytes);
                        let hk =
                            Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_bytes), shared.as_bytes());
                        let mut key = [0u8; 32];
                        hk.expand(b"validator-sdk-v1", &mut key)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        // Update connection state to verified
                        conn_state = ConnectionState::Verified { aead_key: key };

                        // Send attestation_ok with parameters
                        let ok = serde_json::json!({
                            "type": "attestation_ok",
                            "aead": "chacha20poly1305",
                            "hkdf_salt": hkdf_salt_b64,
                        });
                        write.send(Message::Text(ok.to_string())).await?;

                        chal_pub_opt = Some(chal_pub_arr);
                        aead_key = Some(key);

                        // Move to encrypted mode
                        break;
                    } else {
                        // Reject any other message before TDX verification
                        error!(
                            "Received non-attestation message before TDX verification: {}",
                            typ
                        );
                        conn_state = ConnectionState::Rejected {
                            reason: format!("Unexpected message type before verification: {}", typ),
                        };
                        let reject = serde_json::json!({
                            "type": "error",
                            "message": "TDX verification required before any other communication",
                        });
                        write.send(Message::Text(reject.to_string())).await?;
                        return Err(anyhow!("TDX verification required"));
                    }
                }
                Message::Close(_c) => {
                    info!("WS closed during handshake");
                    return Ok(());
                }
                _ => {}
            }
        }

        // Verify we're in verified state before proceeding
        let final_aead_key = match conn_state {
            ConnectionState::Verified { aead_key } => aead_key,
            ConnectionState::Rejected { reason } => {
                return Err(anyhow!("Connection rejected: {}", reason));
            }
            ConnectionState::Unverified { .. } => {
                return Err(anyhow!("Connection still unverified after handshake"));
            }
        };

        let aead_key = aead_key.ok_or_else(|| anyhow!("handshake did not establish AEAD key"))?;
        let key_for_send = aead_key;

        // Sender for plaintext JSON that will be encrypted and sent
        let (tx, mut rx) = mpsc::channel::<Value>(100);

        // Spawn task to send encrypted messages; move write into the task
        let mut write_sink = write;
        tokio::spawn(async move {
            while let Some(plain) = rx.recv().await {
                match serde_json::to_vec(&plain) {
                    Ok(plaintext) => {
                        // 12-byte nonce for ChaCha20-Poly1305
                        let mut nonce = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut nonce);
                        let nonce_bytes = nonce;
                        let cipher = ChaCha20Poly1305::new(&key_for_send.into());
                        let ct = match cipher.encrypt(&nonce_bytes.into(), plaintext.as_ref()) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("AEAD encrypt error: {:?}", e);
                                continue;
                            }
                        };
                        let env = EncryptedEnvelope {
                            enc: "chacha20poly1305".to_string(),
                            nonce: base64::encode(nonce_bytes),
                            ciphertext: base64::encode(ct),
                        };
                        let line = match serde_json::to_string(&env) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Envelope serialize error: {}", e);
                                continue;
                            }
                        };
                        if let Err(e) = write_sink.send(Message::Text(line)).await {
                            error!("WS send error: {}", e);
                            break;
                        }
                    }
                    Err(e) => error!("Serialize error: {}", e),
                }
            }
        });

        // Read encrypted frames and deliver plaintext callback
        let tx_for_cb = tx.clone();
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => match serde_json::from_str::<EncryptedEnvelope>(&text) {
                    Ok(env) => {
                        if env.enc != "chacha20poly1305" {
                            warn!("Unknown enc: {}", env.enc);
                            continue;
                        }
                        let nonce = match base64::decode(&env.nonce) {
                            Ok(n) => n,
                            Err(_) => continue,
                        };
                        if nonce.len() != 12 {
                            warn!("Bad nonce len: {}", nonce.len());
                            continue;
                        }
                        let mut nonce_arr = [0u8; 12];
                        nonce_arr.copy_from_slice(&nonce);
                        let ct = match base64::decode(&env.ciphertext) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let cipher = ChaCha20Poly1305::new(&aead_key.into());
                        match cipher.decrypt(&nonce_arr.into(), ct.as_ref()) {
                            Ok(pt) => match serde_json::from_slice::<Value>(&pt) {
                                Ok(json) => {
                                    (callback)(json, tx_for_cb.clone());
                                }
                                Err(e) => warn!("Decrypted JSON parse error: {}", e),
                            },
                            Err(e) => warn!("AEAD decrypt error: {:?}", e),
                        }
                    }
                    Err(_) => {
                        warn!("Received non-envelope message after handshake");
                    }
                },
                Ok(Message::Close(_)) => {
                    info!("WS closed by peer");
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("WS read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn verify_tdx_quote(&self, quote_b64: &str, nonce_bytes: &[u8; 32]) -> Result<()> {
        use dcap_qvl::{collateral, verify::verify};

        let quote_bytes = base64::decode(quote_b64)?;
        let collateral_data = collateral::get_collateral_from_pcs(&quote_bytes).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow!("time error"))?
            .as_secs();

        let _tcb = verify(&quote_bytes, &collateral_data, now)?;

        // Verify report_data matches sha256(nonce)
        let mut hasher = Sha256::new();
        hasher.update(nonce_bytes);
        let expected = hasher.finalize();

        // TDX report_data location can vary slightly between quote versions.
        // Try common offsets and accept a match against SHA256(nonce).
        let candidate_offsets: [usize; 3] = [568, 576, 584];
        let mut matched = false;
        let mut matched_off: Option<usize> = None;
        for off in candidate_offsets.iter() {
            if quote_bytes.len() >= off + 32 {
                let rd = &quote_bytes[*off..*off + 32];
                if rd == expected.as_slice() {
                    matched = true;
                    matched_off = Some(*off);
                    break;
                }
            }
        }
        if !matched {
            return Err(anyhow!("report_data mismatch"));
        }
        if let Some(off) = matched_off {
            info!("Matched report_data at offset {}", off);
        }

        Ok(())
    }
}

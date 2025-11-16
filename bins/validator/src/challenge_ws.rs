use anyhow::{anyhow, Context, Result};
use base64;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use futures_util::{SinkExt, StreamExt};
use hex;
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use uuid;
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

        // For weights, we don't need on_ready callback
        self.connect_once(
            &callback,
            None::<&fn(tokio::sync::mpsc::Sender<serde_json::Value>)>,
        )
        .await
    }

    /// Connect with automatic reconnection and run the message loop.
    /// The callback receives decrypted JSON messages and a sender for plaintext replies.
    /// The on_ready callback (if provided) is called once when the sender becomes available after attestation.
    pub async fn connect_with_reconnect<F>(&self, callback: F)
    where
        F: Fn(Value, mpsc::Sender<Value>) + Send + Sync + 'static,
    {
        self.connect_with_reconnect_and_ready(
            callback,
            None::<fn(tokio::sync::mpsc::Sender<serde_json::Value>)>,
            None::<fn()>,
        )
        .await
    }

    /// Connect with automatic reconnection, calling `on_ready` once the sender
    /// becomes available and `on_disconnect` whenever a connection attempt ends.
    pub async fn connect_with_reconnect_and_ready<F, R, D>(
        &self,
        callback: F,
        on_ready: Option<R>,
        on_disconnect: Option<D>,
    ) where
        F: Fn(Value, mpsc::Sender<Value>) + Send + Sync + 'static,
        R: Fn(mpsc::Sender<Value>) + Send + Sync + 'static,
        D: Fn() + Send + Sync + 'static,
    {
        let mut backoff_secs = 1u64;
        let max_backoff = 30u64;

        loop {
            match self.connect_once(&callback, on_ready.as_ref()).await {
                Ok(_) => {
                    // Normal close - reset backoff
                    backoff_secs = 1;
                }
                Err(e) => {
                    warn!("WS connect failed: {}", e);
                    backoff_secs = backoff_secs.saturating_mul(2).min(max_backoff);
                }
            }

            if let Some(disconnect_cb) = on_disconnect.as_ref() {
                disconnect_cb();
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
        }
    }

    async fn connect_once<F, R>(&self, callback: &F, on_ready: Option<&R>) -> Result<()>
    where
        F: Fn(Value, mpsc::Sender<Value>) + Send + Sync + 'static,
        R: Fn(mpsc::Sender<Value>) + Send + Sync + 'static,
    {
        // URL already includes /sdk/ws path
        let (ws_stream, _) = connect_async(&self.url).await?;
        let (mut write, mut read) = ws_stream.split();

        info!("Connected WS to {}", self.url);

        // Generate validator X25519 ephemeral keypair
        let val_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let val_public = PublicKey::from(&val_secret);

        let val_pub_b64 = base64::encode(val_public.as_bytes());

        // Validator initiates attestation handshake
        // Generate validator nonce
        let mut validator_nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut validator_nonce_bytes);
        let validator_nonce_hex = hex::encode(validator_nonce_bytes);

        info!("Initiating attestation handshake with validator nonce");

        // Calculate report_data from validator's own nonce
        let mut hasher = Sha256::new();
        hasher.update(&validator_nonce_bytes);
        let report_data = hasher.finalize()[..32].to_vec();

        // Generate validator quote with validator's nonce
        let mock_vmm =
            std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true";

        let validator_quote = match self.get_validator_quote(&report_data).await {
            Ok(quote) => {
                info!("Got validator TDX quote for mutual attestation");
                quote
            }
            Err(e) => {
                if mock_vmm {
                    debug!("MOCK VMM MODE: Using mock quote structure");
                    self.create_mock_quote(&report_data)
                } else {
                    error!(
                        "Security error: Cannot get validator TDX quote in production mode: {}",
                        e
                    );
                    return Err(anyhow!(
                        "Validator TDX quote required for mutual attestation. Error: {}",
                        e
                    ));
                }
            }
        };

        // Send attestation_begin with validator quote
        let begin_msg = serde_json::json!({
            "type": "attestation_begin",
            "nonce": validator_nonce_hex,
            "val_x25519_pub": val_pub_b64,
            "val_quote": validator_quote.quote_b64,
            "val_event_log": validator_quote.event_log,
            "val_rtmrs": validator_quote.rtmrs,
        });
        write.send(Message::Text(begin_msg.to_string())).await?;
        info!("Sent attestation_begin with validator quote");

        // Initialize connection state
        let mut conn_state = ConnectionState::Unverified {
            nonce: validator_nonce_bytes,
            started: Instant::now(),
        };
        let mut chal_pub_opt: Option<[u8; 32]> = None;
        let mut aead_key: Option<[u8; 32]> = None;

        // Wait for challenge's attestation_response
        while let Some(msg) = read.next().await {
            let msg = msg?;
            match msg {
                Message::Text(text) => {
                    let v: Value =
                        serde_json::from_str(&text).map_err(|e| anyhow!("invalid JSON: {}", e))?;
                    let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");

                    // Handle challenge's attestation_response (challenge sends its quote after verifying ours)
                    if typ == "attestation_response" {
                        let quote_b64 =
                            v.get("quote").and_then(|q| q.as_str()).ok_or_else(|| {
                                anyhow!("missing quote in challenge attestation_response")
                            })?;
                        let chal_pub_b64 = v
                            .get("chal_x25519_pub")
                            .and_then(|q| q.as_str())
                            .ok_or_else(|| {
                                anyhow!("missing chal_x25519_pub in challenge attestation_response")
                            })?;
                        let event_log = v.get("event_log").and_then(|e| e.as_str());

                        // Verify challenge TDX quote and nonce binding
                        // Challenge uses validator's nonce to generate its quote (report_data = SHA256(validator_nonce))
                        match self
                            .verify_tdx_quote(quote_b64, &validator_nonce_bytes)
                            .await
                        {
                            Ok(_) => {
                                info!("Challenge TDX quote structure and signature verified");
                            }
                            Err(e) => {
                                // In dev mode, be more lenient with mock quotes
                                let mock_vmm = std::env::var("VALIDATOR_MOCK_VMM")
                                    .unwrap_or_else(|_| "false".to_string())
                                    == "true";

                                if mock_vmm {
                                    warn!("DEV MODE: Challenge quote verification failed but accepting mock quote: {}", e);
                                } else {
                                    error!("Challenge TDX verification failed: {}", e);
                                    conn_state = ConnectionState::Rejected {
                                        reason: format!("Challenge TDX verification failed: {}", e),
                                    };
                                    let reject = serde_json::json!({
                                        "type": "attestation_reject",
                                        "reason": "Challenge TDX verification failed",
                                    });
                                    write.send(Message::Text(reject.to_string())).await?;
                                    return Err(anyhow!(
                                        "Challenge TDX verification failed: {}",
                                        e
                                    ));
                                }
                            }
                        }

                        // Verify environment mode isolation (dev/prod)
                        if let Some(env_err) = self.verify_environment_match(event_log).await {
                            error!("Environment verification failed: {}", env_err);
                            conn_state = ConnectionState::Rejected {
                                reason: format!("Environment mismatch: {}", env_err),
                            };
                            let reject = serde_json::json!({
                                "type": "attestation_reject",
                                "reason": format!("Environment mismatch: {}", env_err),
                            });
                            write.send(Message::Text(reject.to_string())).await?;
                            return Err(anyhow!("Environment verification failed: {}", env_err));
                        }

                        // Decode challenge public key
                        let chal_pub = base64::decode(chal_pub_b64)?;
                        if chal_pub.len() != 32 {
                            return Err(anyhow!("invalid chal_x25519_pub length"));
                        }
                        let chal_pub_arr: [u8; 32] = chal_pub
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad pubkey"))?;
                        let chal_public = PublicKey::from(chal_pub_arr);

                        // Compute shared secret
                        let shared = val_secret.diffie_hellman(&chal_public);

                        // Always use encryption
                        let dev_mode = std::env::var("VALIDATOR_MOCK_VMM")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";
                        let tdx_simulation_mode = std::env::var("TDX_SIMULATION_MODE")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";

                        // Log mode for debugging
                        if dev_mode || tdx_simulation_mode {
                            info!("DEV MODE: Using encrypted session with mock TDX attestation");
                        } else {
                            info!("Production mode: Using encrypted session with real TDX attestation");
                        }

                        // Always send attestation_ok and derive keys
                        let mut hkdf_salt_bytes = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut hkdf_salt_bytes);
                        let hkdf_salt_b64 = base64::encode(hkdf_salt_bytes);

                        // Derive AEAD key via HKDF-SHA256
                        let hk =
                            Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_bytes), shared.as_bytes());
                        let mut key = [0u8; 32];
                        hk.expand(b"platform-api-sdk-v1", &mut key)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        // Send attestation_ok
                        let ok = serde_json::json!({
                            "type": "attestation_ok",
                            "aead": "chacha20poly1305",
                            "hkdf_salt": hkdf_salt_b64,
                        });
                        write.send(Message::Text(ok.to_string())).await?;

                        // Update connection state to verified
                        conn_state = ConnectionState::Verified { aead_key: key };
                        chal_pub_opt = Some(chal_pub_arr);
                        aead_key = Some(key);

                        info!("Attestation completed successfully, moving to encrypted mode");
                        break;
                    }

                    // Handle challenge's attestation_ok (should not happen in normal flow, but handle it)
                    if typ == "attestation_ok" {
                        let challenge_pub_b64 = v
                            .get("chal_x25519_pub")
                            .and_then(|p| p.as_str())
                            .ok_or_else(|| {
                            anyhow!("missing chal_x25519_pub in attestation_ok")
                        })?;

                        let hkdf_salt_b64 = v
                            .get("hkdf_salt")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| anyhow!("missing hkdf_salt in attestation_ok"))?;

                        // Decode challenge public key
                        let chal_pub = base64::decode(challenge_pub_b64)?;
                        if chal_pub.len() != 32 {
                            return Err(anyhow!("invalid chal_x25519_pub length"));
                        }
                        let chal_pub_arr: [u8; 32] = chal_pub
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad pubkey"))?;
                        let chal_public = PublicKey::from(chal_pub_arr);

                        // Decode HKDF salt
                        let hkdf_salt_bytes = base64::decode(hkdf_salt_b64)?;
                        if hkdf_salt_bytes.len() != 32 {
                            return Err(anyhow!("invalid hkdf_salt length"));
                        }
                        let hkdf_salt_arr: [u8; 32] = hkdf_salt_bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad salt"))?;

                        // Compute shared secret
                        let shared = val_secret.diffie_hellman(&chal_public);

                        // Derive AEAD key via HKDF-SHA256
                        let hk = Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_arr), shared.as_bytes());
                        let mut key = [0u8; 32];
                        hk.expand(b"platform-api-sdk-v1", &mut key)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        // Update connection state to verified
                        conn_state = ConnectionState::Verified { aead_key: key };
                        chal_pub_opt = Some(chal_pub_arr);
                        aead_key = Some(key);

                        info!("Attestation completed successfully, moving to encrypted mode");
                        break;
                    }

                    // Handle challenge's attestation_reject
                    if typ == "attestation_reject" {
                        let reason = v
                            .get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or("Unknown reason");
                        error!("Challenge rejected attestation: {}", reason);
                        conn_state = ConnectionState::Rejected {
                            reason: reason.to_string(),
                        };
                        return Err(anyhow!("Attestation rejected by challenge: {}", reason));
                    }

                    // Check if connection is still in unverified state
                    match &conn_state {
                        ConnectionState::Unverified { .. } => {
                            // Reject any other message before TDX verification
                            error!(
                                "Received unexpected message type before verification: {}",
                                typ
                            );
                            conn_state = ConnectionState::Rejected {
                                reason: format!(
                                    "Unexpected message type before verification: {}",
                                    typ
                                ),
                            };
                            let reject = serde_json::json!({
                                "type": "error",
                                "message": "TDX verification required before any other communication",
                            });
                            write.send(Message::Text(reject.to_string())).await?;
                            return Err(anyhow!("TDX verification required"));
                        }
                        ConnectionState::Rejected { reason } => {
                            error!("Connection already rejected: {}", reason);
                            return Err(anyhow!("Connection rejected: {}", reason));
                        }
                        ConnectionState::Verified { .. } => {
                            warn!("Received message when already verified");
                            continue;
                        }
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

        // Call on_ready callback if provided (sender is now available after attestation)
        if let Some(ready_cb) = on_ready {
            ready_cb(tx.clone());
            info!("WebSocket sender ready callback called (connection established and attested)");
        }

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
                        let plaintext_len = plaintext.len();
                        let msg_type = plain
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let cipher = ChaCha20Poly1305::new(&key_for_send.into());
                        let ct = match cipher.encrypt(&nonce_bytes.into(), plaintext.as_ref()) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("AEAD encrypt error: {:?}", e);
                                continue;
                            }
                        };
                        if msg_type == "job_execute" {
                            let job_id = plain
                                .get("job_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            debug!(
                                "🔐 Encrypting job_execute message job_id={} nonce={} plaintext_len={} ciphertext_len={}",
                                job_id,
                                hex::encode(nonce_bytes),
                                plaintext_len,
                                ct.len()
                            );
                        }
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
        let expected_slice: &[u8] = expected.as_ref();

        // TDX report_data location can vary slightly between quote versions.
        // Try common offsets and accept a match against SHA256(nonce).
        let candidate_offsets: [usize; 3] = [568, 576, 584];
        let mut matched = false;
        let mut matched_off: Option<usize> = None;
        for off in candidate_offsets.iter() {
            if quote_bytes.len() >= off + 32 {
                let rd = &quote_bytes[*off..*off + 32];
                if rd == expected_slice {
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

    /// Verify environment mode match between validator and challenge
    async fn verify_environment_match(&self, challenge_event_log: Option<&str>) -> Option<String> {
        // Get validator environment mode
        let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
            // Auto-detect from VALIDATOR_MOCK_VMM
            if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
            {
                "dev".to_string()
            } else {
                "prod".to_string()
            }
        });

        // Extract challenge environment mode from event_log
        if let Some(event_log_str) = challenge_event_log {
            if let Ok(event_log_json) = serde_json::from_str::<serde_json::Value>(event_log_str) {
                if let Some(challenge_env_mode) = event_log_json
                    .get("environment_mode")
                    .and_then(|v| v.as_str())
                {
                    // Verify environment match (dev cannot connect to prod and vice versa)
                    if challenge_env_mode != validator_env_mode {
                        return Some(format!(
                            "Challenge environment is '{}' but validator environment is '{}'. Dev and prod environments cannot communicate.",
                            challenge_env_mode, validator_env_mode
                        ));
                    }
                } else if let Some(dev_mode) =
                    event_log_json.get("dev_mode").and_then(|v| v.as_bool())
                {
                    // Fallback: check dev_mode flag
                    let challenge_env = if dev_mode { "dev" } else { "prod" };
                    if challenge_env != validator_env_mode {
                        return Some(format!(
                            "Challenge environment is '{}' (from dev_mode flag) but validator environment is '{}'. Dev and prod environments cannot communicate.",
                            challenge_env, validator_env_mode
                        ));
                    }
                }
            }
        }

        None // Environment match verified or could not determine (non-blocking)
    }

    /// Get validator TDX quote from dstack (if running in TDX CVM)
    async fn get_validator_quote(&self, report_data: &[u8]) -> Result<ValidatorQuoteData> {
        use dstack_sdk::dstack_client::DstackClient;

        let dstack_client = DstackClient::new(None); // Uses /var/run/dstack.sock by default

        let quote_response = dstack_client
            .get_quote(report_data.to_vec())
            .await
            .context("Failed to get validator TDX quote from dstack")?;

        // Get environment mode and add to event_log for isolation
        let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
            if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
            {
                "dev".to_string()
            } else {
                "prod".to_string()
            }
        });

        // Convert RTMRs from BTreeMap to Vec<String> (before using event_log)
        let rtmrs = quote_response
            .replay_rtmrs()
            .map(|rtmrs_map| {
                let mut rtmrs_vec = Vec::new();
                for i in 0..4 {
                    if let Some(rtmr) = rtmrs_map.get(&i) {
                        rtmrs_vec.push(rtmr.clone());
                    } else {
                        rtmrs_vec.push("0".repeat(96).to_string());
                    }
                }
                rtmrs_vec
            })
            .unwrap_or_else(|_| {
                vec![
                    "0".repeat(96).to_string(),
                    "0".repeat(96).to_string(),
                    "0".repeat(96).to_string(),
                    "0".repeat(96).to_string(),
                ]
            });

        // Add environment_mode to event_log
        let mut event_log = quote_response.event_log;
        if let Ok(event_log_json) = serde_json::from_str::<serde_json::Value>(&event_log) {
            let mut event_log_dict = event_log_json.as_object().cloned().unwrap_or_default();
            event_log_dict.insert(
                "environment_mode".to_string(),
                serde_json::Value::String(validator_env_mode),
            );
            event_log =
                serde_json::to_string(&event_log_dict).unwrap_or_else(|_| event_log.clone());
        } else {
            // If event_log is not JSON, create new JSON with environment_mode
            let original_event_log = event_log.clone();
            event_log = serde_json::json!({
                "environment_mode": validator_env_mode,
                "original": original_event_log,
            })
            .to_string();
        }

        Ok(ValidatorQuoteData {
            quote_b64: base64::encode(quote_response.quote),
            event_log,
            rtmrs,
        })
    }

    /// Create a mock quote structure for dev/mock mode
    /// The structure is valid but not cryptographically verified
    /// Enhanced to generate realistic event logs with compose_hash, app_id, instance_id
    fn create_mock_quote(&self, report_data: &[u8]) -> ValidatorQuoteData {
        use rand::RngCore;
        use sha2::{Digest, Sha256, Sha384};

        // Get environment mode for isolation
        let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
            if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
            {
                "dev".to_string()
            } else {
                "prod".to_string()
            }
        });

        // Try to get compose_hash from environment or use default
        let compose_hash = std::env::var("COMPOSE_HASH").unwrap_or_else(|_| {
            // Generate a deterministic hash based on validator hotkey
            let mut hasher = Sha256::new();
            hasher.update(self.validator_hotkey.as_bytes());
            format!("dev-{}", hex::encode(&hasher.finalize()[..16]))
        });

        // Generate app_id and instance_id
        let app_id = format!("validator-{}", &self.validator_hotkey[..16]);
        let instance_id = format!(
            "instance-{}",
            uuid::Uuid::new_v4().to_string()[..8].to_string()
        );

        // Create a mock quote with correct size (1024 bytes minimum for TDX quotes)
        let mut mock_quote = vec![0u8; 1024];
        rand::thread_rng().fill_bytes(&mut mock_quote);

        // Embed report_data at known offsets (must match challenge SDK offsets: [568, 576, 584])
        // The challenge SDK checks these offsets, so we embed at all of them to ensure compatibility
        let report_offsets: [usize; 3] = [568, 576, 584];
        for offset in &report_offsets {
            if mock_quote.len() >= *offset + 32 {
                mock_quote[*offset..*offset + 32].copy_from_slice(report_data);
            }
        }

        // Generate realistic RTMRs using SHA384
        let generate_rtmr = |content: &[&[u8]]| -> String {
            const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            if content.is_empty() {
                return INIT_MR.to_string();
            }
            let mut mr = hex::decode(INIT_MR).unwrap_or_else(|_| vec![0u8; 48]);
            for item in content {
                let mut item_bytes = item.to_vec();
                if item_bytes.len() < 48 {
                    item_bytes.resize(48, 0);
                }
                let mut hasher = Sha384::new();
                hasher.update(&mr);
                hasher.update(&item_bytes);
                mr = hasher.finalize().to_vec();
            }
            hex::encode(mr)
        };

        // Build event log events array
        let mut events = Vec::new();

        // Add app-id event
        let app_id_event = serde_json::json!({
            "imr": 3,
            "event_type": 1,
            "event": "app-id",
            "event_payload": app_id.clone(),
        });
        events.push(app_id_event);

        // Add instance-id event
        let instance_id_event = serde_json::json!({
            "imr": 3,
            "event_type": 2,
            "event": "instance-id",
            "event_payload": instance_id.clone(),
        });
        events.push(instance_id_event);

        // Add compose-hash event
        let compose_hash_event = serde_json::json!({
            "imr": 3,
            "event_type": 3,
            "event": "compose-hash",
            "event_payload": compose_hash.clone(),
        });
        events.push(compose_hash_event);

        // Add dev-mode marker
        let dev_mode_event = serde_json::json!({
            "imr": 3,
            "event_type": 4,
            "event": "dev-mode",
            "event_payload": "true",
        });
        events.push(dev_mode_event);

        // Calculate digests for events
        for event in &mut events {
            if let Some(event_type) = event.get("event_type").and_then(|e| e.as_u64()) {
                if let Some(event_name) = event.get("event").and_then(|e| e.as_str()) {
                    if let Some(payload) = event.get("event_payload").and_then(|p| p.as_str()) {
                        let mut hasher = Sha384::new();
                        hasher.update(event_type.to_le_bytes());
                        hasher.update(b":");
                        hasher.update(event_name.as_bytes());
                        hasher.update(b":");
                        hasher.update(payload.as_bytes());
                        let digest = hex::encode(hasher.finalize());
                        event["digest"] = serde_json::Value::String(digest);
                    }
                }
            }
        }

        // Generate RTMRs
        let rt_mr0 = generate_rtmr(&[]);
        let rt_mr1 = generate_rtmr(&[b"kernel"]);
        let rt_mr2 = generate_rtmr(&[b"initrd"]);

        // RTMR3 from event log events
        let rt_mr3_content: Vec<&[u8]> = events
            .iter()
            .filter_map(|e| {
                e.get("digest")
                    .and_then(|d| d.as_str())
                    .map(|s| s.as_bytes())
            })
            .collect();
        let rt_mr3 = generate_rtmr(&rt_mr3_content);

        ValidatorQuoteData {
            quote_b64: base64::encode(mock_quote),
            event_log: serde_json::to_string(&events).unwrap_or_else(|_| {
                // Fallback to simple JSON if serialization fails
                serde_json::json!({
                "dev_mode": true,
                "environment_mode": validator_env_mode,
                    "app_id": app_id,
                    "instance_id": instance_id,
                    "compose_hash": compose_hash,
                })
                .to_string()
            }),
            rtmrs: vec![rt_mr0, rt_mr1, rt_mr2, rt_mr3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypts_and_decrypts_job_execute_payload() {
        let key = [7u8; 32];
        let plaintext = json!({
            "type": "job_execute",
            "job_id": "test-job",
            "payload": { "foo": "bar" }
        });
        let serialized = serde_json::to_vec(&plaintext).expect("serialize job_execute");
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher
            .encrypt(&nonce.into(), serialized.as_ref())
            .expect("encrypt job_execute");

        let verifier = ChaCha20Poly1305::new(&key.into());
        let decrypted = verifier
            .decrypt(&nonce.into(), ciphertext.as_ref())
            .expect("decrypt job_execute");
        let decoded: Value =
            serde_json::from_slice(&decrypted).expect("decode decrypted job_execute");

        assert_eq!(decoded, plaintext);
    }
}
/// Validator quote data for mutual attestation
#[derive(Debug, Clone)]
struct ValidatorQuoteData {
    quote_b64: String,
    event_log: String,
    rtmrs: Vec<String>,
}

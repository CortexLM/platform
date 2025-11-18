use anyhow::{anyhow, Context, Result};
use base64;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use hex;
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::EncryptedEnvelope;
use crate::verification::{verify_challenge_compose_hash, verify_environment_match, verify_tdx_quote, ValidatorQuoteData};

/// Weight request message sent to challenges
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WeightRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub block: u64,
    pub timestamp: i64,
}

/// Weight response message received from challenges
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WeightResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub weights: HashMap<String, f64>,
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
    pub expected_compose_hash: String,
}

impl ChallengeWsClient {
    pub fn new(url: String, validator_hotkey: String, expected_compose_hash: String) -> Self {
        Self {
            url,
            validator_hotkey,
            expected_compose_hash,
        }
    }

    pub async fn request_weights(
        &self,
        block: u64,
        timeout_secs: u64,
    ) -> Result<HashMap<String, f64>> {
        let (tx, mut rx) = mpsc::channel(1);
        let block_clone = block;

        let handle = tokio::spawn({
            let url = self.url.clone();
            let validator_hotkey = self.validator_hotkey.clone();
            let expected_compose_hash = self.expected_compose_hash.clone();
            async move {
                let client = ChallengeWsClient::new(url, validator_hotkey, expected_compose_hash);
                let result = client.connect_once_for_weights(block_clone, tx).await;
                result
            }
        });

        let timeout = tokio::time::Duration::from_secs(timeout_secs);
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(weights)) => Ok(weights),
            Ok(None) => Err(anyhow!("Channel closed without response")),
            Err(_) => {
                handle.abort();
                Err(anyhow!("Weight request timed out after {} seconds", timeout_secs))
            }
        }
    }

    async fn connect_once_for_weights(
        &self,
        block: u64,
        result_tx: mpsc::Sender<HashMap<String, f64>>,
    ) -> Result<()> {
        let sent_request = Arc::new(Mutex::new(false));
        let sent_request_clone = sent_request.clone();

        let callback = move |msg: Value, tx: mpsc::Sender<Value>| {
            if let Some(msg_type) = msg.get("type").and_then(|t| t.as_str()) {
                let should_send = {
                    let mut sent = sent_request_clone.lock().unwrap_or_else(|poisoned| {
                        warn!("Mutex poisoned in weight request, recovering");
                        poisoned.into_inner()
                    });
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
                        "timestamp": Utc::now().timestamp(),
                    });
                    let _ = tx.try_send(request);
                }

                if msg_type == "weight_response" {
                    if let Ok(response) = serde_json::from_value::<WeightResponse>(msg.clone()) {
                        if response.block == block {
                            let _ = result_tx.try_send(response.weights);
                        }
                    }
                }
            }
        };

        self.connect_once(
            &callback,
            None::<&fn(tokio::sync::mpsc::Sender<serde_json::Value>)>,
        )
        .await
    }

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
        let (ws_stream, _) = connect_async(&self.url).await?;
        let (mut write, mut read) = ws_stream.split();

        info!("Connected WS to {}", self.url);

        let val_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let val_public = PublicKey::from(&val_secret);

        let val_pub_b64 = base64::encode(val_public.as_bytes());

        let mut validator_nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut validator_nonce_bytes);
        let validator_nonce_hex = hex::encode(validator_nonce_bytes);

        info!("Initiating attestation handshake with validator nonce");

        let mut hasher = Sha256::new();
        hasher.update(&validator_nonce_bytes);
        let report_data = hasher.finalize()[..32].to_vec();

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
                    error!("Security error: Cannot get validator TDX quote in production mode: {}", e);
                    return Err(anyhow!("Validator TDX quote required for mutual attestation. Error: {}", e));
                }
            }
        };

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

        let mut conn_state = ConnectionState::Unverified {
            nonce: validator_nonce_bytes,
            started: Instant::now(),
        };
        let mut chal_pub_opt: Option<[u8; 32]> = None;
        let mut aead_key: Option<[u8; 32]> = None;

        while let Some(msg) = read.next().await {
            let msg = msg?;
            match msg {
                Message::Text(text) => {
                    let v: Value =
                        serde_json::from_str(&text).map_err(|e| anyhow!("invalid JSON: {}", e))?;
                    let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");

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

                        match verify_tdx_quote(quote_b64, &validator_nonce_bytes).await {
                            Ok(_) => {
                                info!("Challenge TDX quote structure and signature verified");
                            }
                            Err(e) => {
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
                                    return Err(anyhow!("Challenge TDX verification failed: {}", e));
                                }
                            }
                        }

                        if let Some(env_err) = verify_environment_match(event_log).await {
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

                        if let Err(e) = verify_challenge_compose_hash(event_log, &self.expected_compose_hash).await {
                            error!("Challenge compose_hash verification failed: {}", e);
                            conn_state = ConnectionState::Rejected {
                                reason: format!("Compose hash mismatch: {}", e),
                            };
                            let reject = serde_json::json!({
                                "type": "attestation_reject",
                                "reason": format!("Compose hash mismatch: {}", e),
                            });
                            write.send(Message::Text(reject.to_string())).await?;
                            return Err(anyhow!("Challenge compose_hash verification failed: {}", e));
                        }

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

                        let dev_mode = std::env::var("VALIDATOR_MOCK_VMM")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";
                        let tdx_simulation_mode = std::env::var("TDX_SIMULATION_MODE")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";

                        if dev_mode || tdx_simulation_mode {
                            info!("DEV MODE: Using encrypted session with mock TDX attestation");
                        } else {
                            info!("Production mode: Using encrypted session with real TDX attestation");
                        }

                        let mut hkdf_salt_bytes = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut hkdf_salt_bytes);
                        let hkdf_salt_b64 = base64::encode(hkdf_salt_bytes);

                        let hk =
                            Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_bytes), shared.as_bytes());
                        let mut key = [0u8; 32];
                        hk.expand(b"platform-api-sdk-v1", &mut key)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        let ok = serde_json::json!({
                            "type": "attestation_ok",
                            "aead": "chacha20poly1305",
                            "hkdf_salt": hkdf_salt_b64,
                        });
                        write.send(Message::Text(ok.to_string())).await?;

                        conn_state = ConnectionState::Verified { aead_key: key };
                        chal_pub_opt = Some(chal_pub_arr);
                        aead_key = Some(key);

                        info!("Attestation completed successfully, moving to encrypted mode");
                        break;
                    }

                    if typ == "attestation_ok" {
                        let challenge_pub_b64 = v
                            .get("chal_x25519_pub")
                            .and_then(|p| p.as_str())
                            .ok_or_else(|| anyhow!("missing chal_x25519_pub in attestation_ok"))?;

                        let hkdf_salt_b64 = v
                            .get("hkdf_salt")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| anyhow!("missing hkdf_salt in attestation_ok"))?;

                        let chal_pub = base64::decode(challenge_pub_b64)?;
                        if chal_pub.len() != 32 {
                            return Err(anyhow!("invalid chal_x25519_pub length"));
                        }
                        let chal_pub_arr: [u8; 32] = chal_pub
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad pubkey"))?;
                        let chal_public = PublicKey::from(chal_pub_arr);

                        let hkdf_salt_bytes = base64::decode(hkdf_salt_b64)?;
                        if hkdf_salt_bytes.len() != 32 {
                            return Err(anyhow!("invalid hkdf_salt length"));
                        }
                        let hkdf_salt_arr: [u8; 32] = hkdf_salt_bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("bad salt"))?;

                        let shared = val_secret.diffie_hellman(&chal_public);

                        let hk = Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_arr), shared.as_bytes());
                        let mut key = [0u8; 32];
                        hk.expand(b"platform-api-sdk-v1", &mut key)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        conn_state = ConnectionState::Verified { aead_key: key };
                        chal_pub_opt = Some(chal_pub_arr);
                        aead_key = Some(key);

                        info!("Attestation completed successfully, moving to encrypted mode");
                        break;
                    }

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

                    match &conn_state {
                        ConnectionState::Unverified { .. } => {
                            error!("Received unexpected message type before verification: {}", typ);
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

        let (tx, mut rx) = mpsc::channel::<Value>(100);

        if let Some(ready_cb) = on_ready {
            ready_cb(tx.clone());
            info!("WebSocket sender ready callback called (connection established and attested)");
        }

        let mut write_sink = write;
        tokio::spawn(async move {
            while let Some(plain) = rx.recv().await {
                match serde_json::to_vec(&plain) {
                    Ok(plaintext) => {
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
                        let cipher = ChaCha20Poly1305::new(&final_aead_key.into());
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

    async fn get_validator_quote(&self, report_data: &[u8]) -> Result<ValidatorQuoteData> {
        use dstack_sdk::dstack_client::DstackClient;

        let dstack_client = DstackClient::new(None);

        let quote_response = dstack_client
            .get_quote(report_data.to_vec())
            .await
            .context("Failed to get validator TDX quote from dstack")?;

        let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
            if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
            {
                "dev".to_string()
            } else {
                "prod".to_string()
            }
        });

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

        let mut event_log = quote_response.event_log.clone();
        if let Ok(event_log_json) = serde_json::from_str::<serde_json::Value>(&event_log) {
            let mut event_log_dict = event_log_json.as_object().cloned().unwrap_or_default();
            event_log_dict.insert(
                "environment_mode".to_string(),
                serde_json::Value::String(validator_env_mode),
            );
            event_log =
                serde_json::to_string(&event_log_dict).unwrap_or_else(|_| event_log.clone());
        } else {
            let original_event_log = event_log.clone();
            event_log = serde_json::json!({
                "environment_mode": validator_env_mode,
                "original": original_event_log,
            })
            .to_string();
        }

        let quote_bytes = quote_response
            .decode_quote()
            .context("Failed to decode quote from hex")?;
        let quote_b64 = base64::encode(&quote_bytes);

        Ok(ValidatorQuoteData {
            quote_b64,
            event_log,
            rtmrs,
        })
    }

    fn create_mock_quote(&self, report_data: &[u8]) -> ValidatorQuoteData {
        let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
            if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
            {
                "dev".to_string()
            } else {
                "prod".to_string()
            }
        });

        let compose_hash = std::env::var("COMPOSE_HASH").unwrap_or_else(|_| {
            let mut hasher = Sha256::new();
            hasher.update(self.validator_hotkey.as_bytes());
            format!("dev-{}", hex::encode(&hasher.finalize()[..16]))
        });

        let app_id = format!("validator-{}", &self.validator_hotkey[..16]);
        let instance_id = format!(
            "instance-{}",
            uuid::Uuid::new_v4().to_string()[..8].to_string()
        );

        let mut mock_quote = vec![0u8; 1024];
        rand::thread_rng().fill_bytes(&mut mock_quote);

        let report_offsets: [usize; 3] = [568, 576, 584];
        for offset in &report_offsets {
            if mock_quote.len() >= *offset + 32 {
                mock_quote[*offset..*offset + 32].copy_from_slice(report_data);
            }
        }

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

        let mut events = Vec::new();

        let app_id_event = serde_json::json!({
            "imr": 3,
            "event_type": 1,
            "event": "app-id",
            "event_payload": app_id.clone(),
        });
        events.push(app_id_event);

        let instance_id_event = serde_json::json!({
            "imr": 3,
            "event_type": 2,
            "event": "instance-id",
            "event_payload": instance_id.clone(),
        });
        events.push(instance_id_event);

        let compose_hash_event = serde_json::json!({
            "imr": 3,
            "event_type": 3,
            "event": "compose-hash",
            "event_payload": compose_hash.clone(),
        });
        events.push(compose_hash_event);

        let dev_mode_event = serde_json::json!({
            "imr": 3,
            "event_type": 4,
            "event": "dev-mode",
            "event_payload": "true",
        });
        events.push(dev_mode_event);

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

        let rt_mr0 = generate_rtmr(&[]);
        let rt_mr1 = generate_rtmr(&[b"kernel"]);
        let rt_mr2 = generate_rtmr(&[b"initrd"]);

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

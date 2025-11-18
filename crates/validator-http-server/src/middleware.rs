use crate::types::AppState;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use base64;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

/// Middleware to verify signed requests with session tokens
pub async fn verify_signed_request(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();

    // Extract headers first
    let session_token = req
        .headers()
        .get("X-Session-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let timestamp: u64 = req
        .headers()
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if now.abs_diff(timestamp) > 120 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let nonce = req
        .headers()
        .get("X-Nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let pubkey_b64 = req
        .headers()
        .get("X-Public-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let signature_b64 = req
        .headers()
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    // Read body bytes for hashing
    let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let body_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        hex::encode(hasher.finalize())
    };
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, body_hash, timestamp, nonce, session_token
    );

    // Lookup session and prevent replay
    let aead_key_option = {
        let mut sessions = state.sessions.write().await;
        if let Some(entry) = sessions.get_mut(&session_token) {
            if entry.expires_at <= now {
                return Err(StatusCode::UNAUTHORIZED);
            }
            if entry.nonces.contains_key(&nonce) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            entry.nonces.insert(nonce.clone(), now);
            // Verify pubkey matches
            let provided_pubkey =
                base64::decode(&pubkey_b64).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if provided_pubkey != entry.public_key {
                return Err(StatusCode::UNAUTHORIZED);
            }
            // Verify signature
            let sig_bytes = base64::decode(&signature_b64).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if sig_bytes.len() != 64 {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let signature_bytes: [u8; 64] =
                sig_bytes.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
            let signature = Signature::from_bytes(&signature_bytes);
            let pubkey_bytes: [u8; 32] = provided_pubkey
                .try_into()
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            let vk =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if vk.verify_strict(canonical.as_bytes(), &signature).is_err() {
                return Err(StatusCode::UNAUTHORIZED);
            }
            entry.aead_key
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Decrypt body if encrypted and session has AEAD key
    let final_body = if let Some(aead_key) = aead_key_option {
        // Try to parse as encrypted envelope
        if let Ok(envelope_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if let (Some(enc), Some(nonce_b64), Some(ciphertext_b64)) = (
                envelope_json.get("enc").and_then(|v| v.as_str()),
                envelope_json.get("nonce").and_then(|v| v.as_str()),
                envelope_json.get("ciphertext").and_then(|v| v.as_str()),
            ) {
                if enc == "xchacha20poly1305" || enc == "chacha20poly1305" {
                    // Decode nonce and ciphertext for ChaCha20-Poly1305
                    let nonce_bytes =
                        base64::decode(nonce_b64).map_err(|_| StatusCode::BAD_REQUEST)?;
                    if nonce_bytes.len() != 12 {
                        tracing::error!(
                            "Invalid ChaCha20 nonce length: expected 12 bytes, got {}",
                            nonce_bytes.len()
                        );
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    let nonce_array: [u8; 12] = nonce_bytes
                        .try_into()
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    let ciphertext_bytes =
                        base64::decode(ciphertext_b64).map_err(|_| StatusCode::BAD_REQUEST)?;

                    // Use ChaCha20Poly1305 for decryption
                    let cipher = ChaCha20Poly1305::new(&aead_key.into());

                    match cipher.decrypt(&nonce_array.into(), ciphertext_bytes.as_ref()) {
                        Ok(plaintext) => {
                            tracing::debug!(
                                "Successfully decrypted ChaCha20-Poly1305 request body"
                            );
                            axum::body::Body::from(plaintext)
                        }
                        Err(e) => {
                            tracing::error!("Failed to decrypt body: {:?}", e);
                            return Err(StatusCode::BAD_REQUEST);
                        }
                    }
                } else {
                    // Not encrypted, use original body
                    axum::body::Body::from(body_bytes)
                }
            } else {
                // Not encrypted envelope, use original body
                axum::body::Body::from(body_bytes)
            }
        } else {
            // Not JSON, use original body
            axum::body::Body::from(body_bytes)
        }
    } else {
        // No AEAD key, use original body
        axum::body::Body::from(body_bytes)
    };

    // Replace body with decrypted content
    *req.body_mut() = final_body;

    Ok(next.run(req).await)
}


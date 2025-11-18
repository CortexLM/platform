use anyhow::Result;
use chrono::Utc;
use platform_validator_core::ChallengeState;
use platform_validator_quota::ResourceRequest;
use platform_validator_websocket::ChallengeWsClient;
use serde_json;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::manager::ChallengeManager;
use crate::probe::probe_health;
use crate::provision::{check_docker_provisioning_status, check_provisioning_status, provision_cvm, provision_docker_container};
use crate::utils::{forward_heartbeat, forward_logs, forward_submit};

pub async fn reconcile(manager: &ChallengeManager) -> Result<()> {
    let challenges = manager.challenges().read().await;
    let specs = manager.challenge_specs().read().await;

    if !challenges.is_empty() {
        let states: Vec<(String, String)> = challenges
            .iter()
            .map(|(hash, inst)| (hash.clone(), format!("{:?}", inst.state)))
            .collect();
        debug!("Reconciling challenges: {:?}", states);
    }

    for (compose_hash, instance) in challenges.iter() {
        debug!("Processing challenge {} in state {:?}", compose_hash, instance.state);
        match instance.state {
            ChallengeState::Created => {
                if let Some(spec) = specs.get(compose_hash) {
                    if let Some(cvm_id) = &instance.cvm_instance_id {
                        warn!("Challenge {} already has CVM/container {}, skipping provisioning", compose_hash, cvm_id);
                        drop(challenges);
                        drop(specs);
                        return Ok(());
                    }

                    let spec_clone = spec.clone();
                    let compose_hash_clone = compose_hash.clone();
                    drop(challenges);
                    drop(specs);

                    if manager.use_docker() {
                        provision_docker_container(manager, spec_clone).await?;
                    } else {
                        provision_cvm(manager, spec_clone).await?;
                    }
                    return Ok(());
                }
            }
            ChallengeState::Provisioning => {
                if let Some(cvm_id) = &instance.cvm_instance_id {
                    let compose_hash_clone = compose_hash.clone();
                    let cvm_id_clone = cvm_id.clone();
                    drop(challenges);
                    drop(specs);

                    if manager.use_docker() {
                        check_docker_provisioning_status(manager, &compose_hash_clone, &cvm_id_clone).await?;
                    } else {
                        check_provisioning_status(manager, &compose_hash_clone, &cvm_id_clone).await?;
                    }
                    return Ok(());
                }
            }
            ChallengeState::Probing => {
                if let Some(api_url) = &instance.challenge_api_url {
                    let compose_hash_clone = compose_hash.clone();
                    let api_url_clone = api_url.clone();
                    drop(challenges);
                    drop(specs);
                    debug!("Starting health probe for challenge {} at {}", compose_hash_clone, api_url_clone);
                    probe_health(manager, &compose_hash_clone, &api_url_clone).await?;
                    return Ok(());
                } else {
                    warn!("Challenge {} in Probing state but no api_url set", compose_hash);
                }
            }
            ChallengeState::Active => {
                if let Some(api_url) = &instance.challenge_api_url {
                    let compose_hash_clone = compose_hash.clone();
                    let api_url_clone = api_url.clone();
                    let need_ws = !instance.ws_started;
                    drop(challenges);
                    drop(specs);

                    if need_ws {
                        let challenge_id_opt = {
                            let specs = manager.challenge_specs().read().await;
                            specs.get(&compose_hash_clone).map(|s| s.id.clone())
                        };

                        let ws_sender_arc = {
                            let challenges = manager.challenges().read().await;
                            if let Some(instance) = challenges.get(&compose_hash_clone) {
                                instance.ws_sender.clone()
                            } else {
                                return Ok(());
                            }
                        };

                        let ws_url = api_url_clone
                            .replace("https://", "wss://")
                            .replace("http://", "ws://")
                            + "/sdk/ws";
                        let client = ChallengeWsClient::new(
                            ws_url.clone(),
                            manager.platform_client().validator_hotkey.clone(),
                            compose_hash_clone.clone(),
                        );
                        let compose_hash_for_log = compose_hash_clone.clone();
                        let compose_hash_for_spawn = compose_hash_clone.clone();
                        let platform_client = manager.platform_client().clone();
                        let challenge_id_for_orm = challenge_id_opt.clone();
                        let ws_sender_for_store = ws_sender_arc.clone();
                        let platform_ws_sender_spawn = manager.platform_ws_sender().clone();
                        let orm_query_routing_spawn = manager.orm_query_routing().clone();

                        tokio::spawn(async move {
                            let ws_sender_for_ready = ws_sender_for_store.clone();
                            let compose_hash_for_ready = compose_hash_for_log.clone();
                            let on_ready_cb = move |sender: mpsc::Sender<serde_json::Value>| {
                                let sender_clone = sender.clone();
                                let ws_sender_store = ws_sender_for_ready.clone();
                                let compose_hash_log = compose_hash_for_ready.clone();

                                tokio::spawn(async move {
                                    let mut guard = ws_sender_store.lock().await;
                                    *guard = Some(sender_clone.clone());
                                    info!("✅ WebSocket sender stored/updated for challenge {} (ready for job_execute)", compose_hash_log);

                                    let orm_ready_msg = serde_json::json!({
                                        "type": "orm_ready"
                                    });

                                    if let Err(e) = sender_clone.send(orm_ready_msg).await {
                                        error!("Failed to send orm_ready to challenge {}: {}", compose_hash_log, e);
                                    } else {
                                        info!("✅ Sent orm_ready signal to challenge {} (schema will be resolved by platform-api)", compose_hash_log);
                                    }
                                });
                            };

                            let ws_sender_for_cleanup = ws_sender_for_store.clone();
                            let compose_hash_for_cleanup = compose_hash_for_spawn.clone();

                            {
                                let mut guard = ws_sender_for_cleanup.lock().await;
                                if guard.is_some() {
                                    *guard = None;
                                    info!("🔄 Cleared old WebSocket sender for challenge {} (preparing for reconnection)", compose_hash_for_cleanup);
                                }
                            }

                            let ws_sender_for_disconnect_loop = ws_sender_for_store.clone();
                            let compose_hash_for_disconnect = Arc::new(compose_hash_for_spawn.clone());
                            let on_disconnect_cb = {
                                let compose_hash_for_disconnect = compose_hash_for_disconnect.clone();
                                move || {
                                    let ws_sender_cleanup = ws_sender_for_disconnect_loop.clone();
                                    let compose_hash_log = compose_hash_for_disconnect.clone();
                                    tokio::spawn(async move {
                                        let mut guard = ws_sender_cleanup.lock().await;
                                        if guard.is_some() {
                                            *guard = None;
                                            info!("🔌 Cleared WebSocket sender for challenge {} (connection closed)", compose_hash_log.as_str());
                                        }
                                    });
                                }
                            };

                            let platform_ws_sender_for_orm = platform_ws_sender_spawn.clone();
                            let orm_query_routing_for_orm = orm_query_routing_spawn.clone();

                            client.connect_with_reconnect_and_ready(
                                move |json, sender| {
                                    if let Some(typ) = json.get("type").and_then(|t| t.as_str()) {
                                        match typ {
                                            "heartbeat" => {
                                                if let Some(payload) = json.get("payload") {
                                                    let payload_clone = payload.clone();
                                                    tokio::spawn(async move {
                                                        if let Err(e) = forward_heartbeat(payload_clone).await {
                                                            warn!("forward heartbeat error: {}", e);
                                                        }
                                                    });
                                                }
                                            }
                                            "logs" => {
                                                if let Some(payload) = json.get("payload") {
                                                    let payload_clone = payload.clone();
                                                    tokio::spawn(async move {
                                                        if let Err(e) = forward_logs(payload_clone).await {
                                                            warn!("forward logs error: {}", e);
                                                        }
                                                    });
                                                }
                                            }
                                            "submit" => {
                                                if let Some(payload) = json.get("payload") {
                                                    let payload_clone = payload.clone();
                                                    tokio::spawn(async move {
                                                        if let Err(e) = forward_submit(payload_clone).await {
                                                            warn!("forward submit error: {}", e);
                                                        }
                                                    });
                                                }
                                            }
                                            "orm_query" => {
                                                if let Some(query_payload) = json.get("payload").and_then(|p| p.get("query")) {
                                                    let query_clone = query_payload.clone();
                                                    let client_clone = platform_client.clone();
                                                    let challenge_id_clone = challenge_id_for_orm.clone();
                                                    let sender_clone = sender.clone();

                                                    let query_id = json.get("payload")
                                                        .and_then(|p| p.get("query_id"))
                                                        .and_then(|q| q.as_str())
                                                        .or_else(|| json.get("query_id").and_then(|q| q.as_str()))
                                                        .map(|s| s.to_string());

                                                    let compose_hash_spawn_clone = compose_hash_for_spawn.clone();

                                                    let platform_ws_sender = platform_ws_sender_for_orm.clone();
                                                    let orm_query_routing = orm_query_routing_for_orm.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        if let Some(challenge_id) = challenge_id_clone {
                                                            info!("Forwarding ORM query to platform-api via WebSocket for challenge {}", challenge_id);
                                                            
                                                            let ws_sender_guard = platform_ws_sender.lock().await;
                                                            if let Some(ref ws_sender) = *ws_sender_guard {
                                                                let final_query_id = query_id.clone()
                                                                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                                                                
                                                                {
                                                                    let mut routing_guard = orm_query_routing.write().await;
                                                                    routing_guard.insert(
                                                                        final_query_id.clone(),
                                                                        (compose_hash_spawn_clone.clone(), sender_clone.clone())
                                                                    );
                                                                }
                                                                
                                                                match client_clone.send_orm_query_via_websocket(
                                                                    ws_sender,
                                                                    &challenge_id,
                                                                    query_clone,
                                                                    &final_query_id
                                                                ).await {
                                                                    Ok(_) => {}
                                                                    Err(e) => {
                                                                        error!("Failed to send ORM query via WebSocket: {}", e);
                                                                        
                                                                        {
                                                                            let mut routing_guard = orm_query_routing.write().await;
                                                                            routing_guard.remove(&final_query_id);
                                                                        }

                                                                        let mut error_response = serde_json::json!({
                                                                            "type": "error",
                                                                            "message": format!("ORM query failed: {}", e)
                                                                        });

                                                                        error_response["query_id"] = serde_json::Value::String(final_query_id.clone());

                                                                        if let Err(send_err) = sender_clone.send(error_response).await {
                                                                            warn!("Failed to send ORM error to challenge: {}", send_err);
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                error!("Platform WebSocket not connected - cannot forward ORM query");
                                                                
                                                                let mut error_response = serde_json::json!({
                                                                    "type": "error",
                                                                    "message": "Platform WebSocket not connected"
                                                                });

                                                                if let Some(ref qid) = query_id {
                                                                    error_response["query_id"] = serde_json::Value::String(qid.clone());
                                                                }

                                                                if let Err(send_err) = sender_clone.send(error_response).await {
                                                                    warn!("Failed to send ORM error to challenge: {}", send_err);
                                                                }
                                                            }
                                                        } else {
                                                            warn!("Cannot forward ORM query: challenge_id not available for compose_hash {}", compose_hash_spawn_clone);

                                                            let mut error_response = serde_json::json!({
                                                                "type": "error",
                                                                "message": "Challenge ID not available for ORM query"
                                                            });

                                                            if let Some(ref qid) = query_id {
                                                                error_response["query_id"] = serde_json::Value::String(qid.clone());
                                                            }

                                                            if let Err(e) = sender_clone.send(error_response).await {
                                                                warn!("Failed to send ORM error to challenge: {}", e);
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    warn!("Received orm_query without query payload");
                                                }
                                            }
                                            _ => {
                                                info!("WS[{}] message type: {}", compose_hash_for_log, typ);
                                            }
                                        }
                                    }
                                },
                                Some(on_ready_cb),
                                Some(on_disconnect_cb)
                            ).await;
                        });

                        let mut challenges2 = manager.challenges().write().await;
                        if let Some(inst) = challenges2.get_mut(&compose_hash_clone) {
                            inst.ws_started = true;
                        }
                    }

                    probe_health(manager, &compose_hash_clone, &api_url_clone).await?;
                    return Ok(());
                }
            }
            ChallengeState::Recycling => {
                if let Some(cvm_id) = &instance.cvm_instance_id {
                    let compose_hash_clone = compose_hash.clone();
                    let cvm_id_clone = cvm_id.clone();
                    drop(challenges);
                    drop(specs);
                    recycle_cvm(manager, &compose_hash_clone, &cvm_id_clone).await?;
                    return Ok(());
                }
            }
            ChallengeState::Failed => {
                if let Some(cvm_id) = &instance.cvm_instance_id {
                    let compose_hash_clone = compose_hash.clone();
                    let cvm_id_clone = cvm_id.clone();
                    drop(challenges);
                    drop(specs);
                    recycle_cvm(manager, &compose_hash_clone, &cvm_id_clone).await?;
                    return Ok(());
                }
            }
            ChallengeState::Deprecated => {
                if let Some(deprecated_at) = instance.deprecated_at {
                    let elapsed = Utc::now().signed_duration_since(deprecated_at);
                    if elapsed.num_seconds() > 600 {
                        info!("Deprecated challenge {} timeout reached, forcing recycle", compose_hash);
                        if let Some(cvm_id) = &instance.cvm_instance_id {
                            let compose_hash_clone = compose_hash.clone();
                            let cvm_id_clone = cvm_id.clone();
                            drop(challenges);
                            drop(specs);
                            recycle_cvm(manager, &compose_hash_clone, &cvm_id_clone).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn recycle_cvm(manager: &ChallengeManager, compose_hash: &str, cvm_id: &str) -> Result<()> {
    info!("Recycling CVM: {}", cvm_id);

    let resources = match manager.vmm_client().get_vm_info(cvm_id).await {
        Ok(info) => {
            let vcpu = info
                .configuration
                .get("vcpu")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let memory = info
                .configuration
                .get("memory")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let disk = info
                .configuration
                .get("disk_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            (vcpu, memory, disk)
        }
        Err(_) => (0, 0, 0),
    };

    if let Err(e) = manager.vmm_client().stop_vm(cvm_id).await {
        warn!("Failed to stop CVM {}: {}", cvm_id, e);
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    if let Err(e) = manager.vmm_client().kill_vm(cvm_id).await {
        warn!("Failed to kill CVM {}: {}", cvm_id, e);
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    if let Err(e) = manager.vmm_client().remove_vm(cvm_id).await {
        warn!("Failed to remove CVM {}: {}", cvm_id, e);
    }

    if resources.0 > 0 {
        let _ = manager
            .quota_manager()
            .release(
                compose_hash,
                ResourceRequest {
                    cpu_cores: resources.0,
                    memory_mb: resources.1,
                    disk_mb: resources.2,
                },
            )
            .await;
    }

    let mut challenges = manager.challenges().write().await;
    if let Some(instance) = challenges.get_mut(compose_hash) {
        if instance.state != ChallengeState::Deprecated {
            instance.state = ChallengeState::Created;
            instance.cvm_instance_id = None;
            instance.challenge_api_url = None;
            instance.probe_attempts = 0;
            info!("CVM {} recycled, will be recreated", cvm_id);
        } else {
            instance.cvm_instance_id = None;
            instance.challenge_api_url = None;
            info!("CVM {} removed for deprecated challenge", cvm_id);
        }
    }

    Ok(())
}

use anyhow::{Context, Result};
use base64;
use chrono::Utc;
use platform_validator_core::ChallengeSpec;
use platform_validator_core::ChallengeState;
use platform_validator_docker::{ContainerConfig, DockerClient, PortMapping as DockerPortMapping, VolumeMapping};
use platform_validator_quota::{QuotaResult, ResourceRequest};
use platform_validator_vmm::{VmmClient, VmConfiguration};
use serde_json;
use serde_yaml;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::env::get_or_prompt_env_vars;
use crate::manager::ChallengeManager;
use crate::utils::{parse_disk_size, parse_memory};

pub async fn provision_cvm(manager: &ChallengeManager, spec: ChallengeSpec) -> Result<()> {
    info!("Provisioning CVM for challenge: {}", spec.compose_hash);

    let mut challenges = manager.challenges().write().await;

    if let Some(instance) = challenges.get_mut(&spec.compose_hash) {
        instance.state = ChallengeState::Provisioning;

        let compose_hash_clone = spec.compose_hash.clone();
        drop(challenges);

        let memory_mb = parse_memory(&spec.resources.memory)?;
        let disk_mb = spec
            .resources
            .disk
            .as_ref()
            .map(|d| parse_disk_size(d))
            .transpose()?
            .unwrap_or(20) as u64
            * 1024;

        let resource_request = ResourceRequest {
            cpu_cores: spec.resources.vcpu,
            memory_mb: memory_mb as u64,
            disk_mb,
        };

        match manager.quota_manager().reserve(&compose_hash_clone, resource_request).await {
            Ok(QuotaResult::Granted) => {
                info!("Quota granted for challenge {}", compose_hash_clone);
            }
            Ok(QuotaResult::Insufficient) => {
                warn!("Insufficient quota for challenge {}, backing off", compose_hash_clone);
                let mut challenges = manager.challenges().write().await;
                if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                    instance.state = ChallengeState::Failed;
                }
                return Err(anyhow::anyhow!("Insufficient quota for challenge"));
            }
            Err(e) => {
                error!("Quota check failed: {}", e);
                let mut challenges = manager.challenges().write().await;
                if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                    instance.state = ChallengeState::Failed;
                }
                return Err(e);
            }
        }

        let compose_yaml = base64::decode(&spec.compose_yaml)
            .map_err(|e| anyhow::anyhow!("Failed to decode compose_yaml from base64: {}", e))?;
        let compose_yaml_str = String::from_utf8(compose_yaml)
            .map_err(|e| anyhow::anyhow!("Failed to convert compose_yaml to string: {}", e))?;

        info!("Decoded docker-compose.yaml for challenge {}", compose_hash_clone);

        let memory_mb = parse_memory(&spec.resources.memory)?;
        let dstack_config = spec.dstack_config.as_ref();

        let compose_doc: serde_yaml::Value = serde_yaml::from_str(&compose_yaml_str)
            .context("Failed to parse docker-compose YAML")?;

        let modified_compose_yaml = serde_yaml::to_string(&compose_doc)
            .context("Failed to serialize modified docker-compose YAML")?;

        let mut app_compose = serde_json::json!({
            "manifest_version": 2,
            "name": compose_hash_clone.clone(),
            "runner": "docker-compose",
            "docker_compose_file": modified_compose_yaml,
            "docker_config": {},
            "kms_enabled": dstack_config.map(|c| c.kms_enabled).unwrap_or(true),
            "gateway_enabled": dstack_config.map(|c| c.gateway_enabled).unwrap_or(true),
            "public_logs": dstack_config.map(|c| c.public_logs).unwrap_or(true),
            "public_sysinfo": dstack_config.map(|c| c.public_sysinfo).unwrap_or(true),
            "public_tcbinfo": dstack_config.map(|c| c.public_tcbinfo).unwrap_or(true),
            "local_key_provider_enabled": dstack_config.map(|c| c.local_key_provider_enabled).unwrap_or(false),
            "key_provider_id": dstack_config.and_then(|c| c.key_provider_id.clone()).unwrap_or_else(|| "".to_string()),
            "allowed_envs": dstack_config.and_then(|c| c.allowed_envs.clone()).unwrap_or_default(),
            "no_instance_id": dstack_config.map(|c| c.no_instance_id).unwrap_or(false),
            "secure_time": dstack_config.map(|c| c.secure_time).unwrap_or(false),
        });

        if let Some(script) = dstack_config.and_then(|c| c.pre_launch_script.clone()) {
            app_compose["pre_launch_script"] = serde_json::Value::String(script);
        }

        let app_compose_str = serde_json::to_string(&app_compose)
            .map_err(|e| anyhow::anyhow!("Failed to serialize AppCompose JSON: {}", e))?;

        let dstack_image = spec.dstack_image.as_deref().unwrap_or("dstack-0.5.2");
        let user_config = String::new();
        let ports = vec![];

        let private_env_vars = get_or_prompt_env_vars(
            manager.dynamic_values(),
            &compose_hash_clone,
            &spec.name,
            spec.github_repo.as_ref(),
        )
        .await
        .context("Failed to get or prompt for private environment variables")?;

        let env_var_strings: Vec<String> = private_env_vars
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect();
        let encrypted_env = serde_json::to_vec(&env_var_strings)
            .context("Failed to serialize environment variables as JSON")?;

        info!("Prepared {} private environment variables for challenge {}", private_env_vars.len(), compose_hash_clone);

        let existing_vm = manager.vmm_client().list_vms().await.ok().and_then(|vms| {
            vms.iter()
                .find(|vm| vm.name == compose_hash_clone)
                .map(|vm| vm.id.clone())
        });

        let vm_result = if let Some(existing_vm_id) = existing_vm {
            info!(compose_hash = &compose_hash_clone, existing_vm_id = &existing_vm_id, "CVM with compose_hash already exists, reusing");
            Ok(existing_vm_id)
        } else {
            let vm_config = VmConfiguration {
                name: compose_hash_clone.clone(),
                image: dstack_image.to_string(),
                compose_file: app_compose_str,
                vcpu: spec.resources.vcpu,
                memory: memory_mb,
                disk_size: spec
                    .resources
                    .disk
                    .as_ref()
                    .map(|d| parse_disk_size(d))
                    .transpose()?
                    .unwrap_or(20),
                ports,
                encrypted_env,
                app_id: None,
                user_config,
                hugepages: dstack_config.map(|c| c.hugepages).unwrap_or(false),
                pin_numa: dstack_config.map(|c| c.pin_numa).unwrap_or(false),
                gpus: None,
                kms_urls: vec![],
                gateway_urls: vec![],
                stopped: false,
            };

            manager.vmm_client().create_vm(vm_config).await
        };

        let mut challenges = manager.challenges().write().await;
        if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
            match vm_result {
                Ok(vm_id) => {
                    instance.cvm_instance_id = Some(vm_id.clone());

                    let base_domain = manager
                        .get_gateway_base_domain_internal()
                        .await
                        .context("Failed to get gateway base_domain from VMM")?;
                    let gateway_port = manager
                        .get_gateway_port_internal()
                        .await
                        .context("Failed to get gateway port from VMM")?;

                    let mut instance_id = None;
                    if let Ok(vm_info) = manager.vmm_client().get_vm_info(&vm_id).await {
                        instance_id = vm_info.instance_id;
                    }

                    let host = if let Some(id) = &instance_id {
                        if !id.trim().is_empty() {
                            format!("{}-10000.{}:{}", id, base_domain, gateway_port)
                        } else {
                            format!("-10000.{}:{}", base_domain, gateway_port)
                        }
                    } else {
                        format!("-10000.{}:{}", base_domain, gateway_port)
                    };

                    let http_url = format!("https://{}", host);
                    instance.challenge_api_url = Some(http_url.clone());
                    info!("CVM provisioned: {} with gateway host: {}", vm_id, host);
                }
                Err(e) => {
                    error!("Failed to provision CVM: {}", e);
                    instance.state = ChallengeState::Failed;
                    drop(challenges);
                    let _ = manager
                        .quota_manager()
                        .release(
                            &compose_hash_clone,
                            ResourceRequest {
                                cpu_cores: spec.resources.vcpu,
                                memory_mb: memory_mb as u64,
                                disk_mb,
                            },
                        )
                        .await;
                }
            }
        }
    }

    Ok(())
}

pub async fn provision_docker_container(manager: &ChallengeManager, spec: ChallengeSpec) -> Result<()> {
    let compose_hash_clone = spec.compose_hash.clone();

    info!("Attempting to provision Docker container for challenge {} (use_docker: {}, docker_client available: {})", 
        compose_hash_clone, manager.use_docker(), manager.docker_client().is_some());

    let docker_client = match manager.docker_client() {
        Some(client) => {
            info!("Docker client is available for challenge {}", compose_hash_clone);
            client
        }
        None => {
            error!("Docker client not available for challenge {} (use_docker: {})", compose_hash_clone, manager.use_docker());
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                instance.state = ChallengeState::Failed;
            }
            return Err(anyhow::anyhow!("Docker client not available"));
        }
    };

    {
        let mut challenges = manager.challenges().write().await;
        if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
            instance.state = ChallengeState::Provisioning;
        }
    }

    let image = spec
        .images
        .first()
        .ok_or_else(|| anyhow::anyhow!("No image specified in challenge spec"))?
        .clone();

    info!("Provisioning Docker container for challenge {} with image: {}", compose_hash_clone, image);

    if let Err(e) = docker_client.ensure_network().await {
        error!("Failed to ensure Docker network exists: {}", e);
        return Err(anyhow::anyhow!("Failed to ensure Docker network: {}", e));
    }

    let mut env_vars = HashMap::new();

    for (key, value) in &spec.env {
        env_vars.insert(key.clone(), value.clone());
    }

    env_vars.insert("ENVIRONMENT_MODE".to_string(), "dev".to_string());
    env_vars.insert("CHALLENGE_ID".to_string(), spec.name.clone());
    env_vars.insert(
        "PLATFORM_API_URL".to_string(),
        std::env::var("PLATFORM_BASE_API")
            .unwrap_or_else(|_| "http://platform-api:15000".to_string()),
    );

    if let Ok(chutes_token) = std::env::var("CHUTES_API_TOKEN") {
        env_vars.insert("CHUTES_API_TOKEN".to_string(), chutes_token);
    }

    let validator_mock_vmm =
        std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true";

    if validator_mock_vmm {
        env_vars.insert("SDK_DEV_MODE".to_string(), "true".to_string());
        env_vars.insert("TEE_ENFORCED".to_string(), "false".to_string());

        let tdx_simulation_mode =
            std::env::var("TDX_SIMULATION_MODE").unwrap_or_else(|_| "true".to_string());

        env_vars.insert("TDX_SIMULATION_MODE".to_string(), tdx_simulation_mode.clone());
        info!("Setting dev mode environment variables for challenge container (SDK_DEV_MODE=true, TEE_ENFORCED=false, TDX_SIMULATION_MODE={})", tdx_simulation_mode);
    }

    let private_env_vars = get_or_prompt_env_vars(
        manager.dynamic_values(),
        &compose_hash_clone,
        &spec.name,
        spec.github_repo.as_ref(),
    )
    .await
    .context("Failed to get or prompt for private environment variables")?;

    for (key, value) in private_env_vars {
        env_vars.insert(key, value);
    }

    let mut port_mappings = Vec::new();
    for port in &spec.ports {
        port_mappings.push(DockerPortMapping {
            container_port: port.container,
            host_port: None,
            protocol: port.protocol.clone(),
        });
    }

    if port_mappings.is_empty() {
        port_mappings.push(DockerPortMapping {
            container_port: 10000,
            host_port: None,
            protocol: "tcp".to_string(),
        });
    }

    let container_name = format!("challenge-{}", compose_hash_clone);

    let volumes = vec![VolumeMapping {
        host_path: "/var/run/docker.sock".to_string(),
        container_path: "/var/run/docker.sock".to_string(),
        read_only: false,
    }];

    let container_config = ContainerConfig {
        name: container_name.clone(),
        image,
        env: env_vars,
        ports: port_mappings,
        network: manager.docker_network().to_string(),
        restart_policy: "unless-stopped".to_string(),
        volumes,
    };

    match docker_client.create_and_start_container(container_config).await {
        Ok(container_id) => {
            info!("✅ Docker container {} created and started", container_name);

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let container_ip = docker_client
                .get_container_ip(&container_name)
                .await
                .context("Failed to get container IP")?;

            let http_url = if let Some(ip) = container_ip {
                format!("http://{}:10000", ip)
            } else {
                format!("http://{}:10000", container_name)
            };

            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                instance.cvm_instance_id = Some(container_id);
                instance.challenge_api_url = Some(http_url.clone());
                instance.state = ChallengeState::Probing;
            }

            info!("Docker container {} ready at {}", container_name, http_url);
        }
        Err(e) => {
            error!("Failed to provision Docker container: {}", e);
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                instance.state = ChallengeState::Failed;
            }
            return Err(e);
        }
    }

    Ok(())
}

pub async fn check_provisioning_status(manager: &ChallengeManager, compose_hash: &str, cvm_id: &str) -> Result<()> {
    match manager.vmm_client().get_vm_info(cvm_id).await {
        Ok(info) => {
            if info.status == "running" {
                let mut challenges = manager.challenges().write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    instance.state = ChallengeState::Probing;
                    info!("CVM is running, starting health probe");
                }
            }
        }
        Err(e) => {
            error!("Failed to get VM info: {}", e);
        }
    }

    Ok(())
}

pub async fn check_docker_provisioning_status(
    manager: &ChallengeManager,
    compose_hash: &str,
    _container_id: &str,
) -> Result<()> {
    let docker_client = match manager.docker_client() {
        Some(client) => client,
        None => {
            error!("Docker client not available");
            return Err(anyhow::anyhow!("Docker client not available"));
        }
    };

    let container_name = format!("challenge-{}", compose_hash);
    match docker_client.is_container_running(&container_name).await {
        Ok(true) => {
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                instance.state = ChallengeState::Probing;
                info!("Docker container {} is running, starting health probe", container_name);
            }
        }
        Ok(false) => {
            warn!("Docker container {} is not running", container_name);
        }
        Err(e) => {
            error!("Failed to check Docker container status: {}", e);
        }
    }

    Ok(())
}

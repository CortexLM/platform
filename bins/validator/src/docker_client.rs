use anyhow::{Context, Result};
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions,
    ListContainersOptions, LogOutput, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::models::{ContainerStateStatusEnum, HostConfig, PortBinding};
use bollard::network::{CreateNetworkOptions, ListNetworksOptions};
use bollard::Docker;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use tracing::{error, info, warn};

/// Docker client wrapper for managing challenge containers
pub struct DockerClient {
    docker: Docker,
    network_name: String,
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
    pub env: HashMap<String, String>,
    pub ports: Vec<PortMapping>,
    pub network: String,
    pub restart_policy: String,
    pub volumes: Vec<VolumeMapping>,
}

#[derive(Debug, Clone)]
pub struct VolumeMapping {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct ContainerStatus {
    pub id: String,
    pub name: String,
    pub status: String,
    pub running: bool,
}

impl DockerClient {
    /// Create a new Docker client
    pub async fn new(socket_path: Option<String>, network_name: String) -> Result<Self> {
        let socket_to_use = socket_path
            .clone()
            .unwrap_or_else(|| "/var/run/docker.sock".to_string());
        info!(
            "Attempting to connect to Docker socket at: {}",
            socket_to_use
        );

        // Check if socket exists
        if !Path::new(&socket_to_use).exists() {
            return Err(anyhow::anyhow!(
                "Docker socket not found at {}",
                socket_to_use
            ));
        }

        info!("Docker socket found at {}", socket_to_use);

        // Connect to Docker using Unix socket
        // For bollard 0.19, use connect_with_unix with explicit path
        // Note: DOCKER_HOST env var should NOT be set when using Unix socket
        // Setting DOCKER_HOST=unix://... causes bollard to try HTTP connection
        info!("Connecting to Docker daemon at: {}", socket_to_use);

        // Use explicit path - bollard 0.19 requires the path as a string reference
        let docker = Docker::connect_with_unix(
            socket_to_use.as_str(),
            120, // timeout in seconds
            bollard::API_DEFAULT_VERSION,
        )
        .context(format!(
            "Failed to connect to Docker daemon at {}",
            socket_to_use
        ))?;

        info!("Docker client created successfully");

        let client = Self {
            docker,
            network_name: network_name.clone(),
        };

        // Test connection by pinging Docker daemon (lighter than listing containers)
        // This verifies the connection without triggering hyper legacy client issues
        // Note: We don't fail initialization if ping fails - the real test is when we try to use Docker
        match client.docker.ping().await {
            Ok(_) => info!("Docker connection verified - daemon is reachable"),
            Err(e) => {
                warn!("Warning: Docker ping test failed: {} (will continue and test during network creation)", e);
            }
        }

        // Don't call ensure_network() here - it will be called lazily when needed
        // This allows the client to be created even if the initial network check fails
        // The network will be created/verified when actually provisioning containers
        info!(
            "Docker client initialized (network {} will be created/verified on first use)",
            network_name
        );

        Ok(client)
    }

    /// Ensure the Docker network exists, create it if it doesn't
    /// This is called lazily when actually provisioning containers
    pub async fn ensure_network(&self) -> Result<()> {
        // Try to list networks - if this fails, we'll try to create the network anyway
        let list_options: ListNetworksOptions<String> = Default::default();
        let networks = match self.docker.list_networks(Some(list_options)).await {
            Ok(nets) => nets,
            Err(e) => {
                warn!(
                    "Failed to list networks: {} (will try to create network anyway)",
                    e
                );
                vec![] // Empty list, will try to create network
            }
        };

        let network_exists = networks
            .iter()
            .any(|n| n.name.as_ref() == Some(&self.network_name));

        if !network_exists {
            info!("Creating Docker network: {}", self.network_name);
            let network_config = CreateNetworkOptions {
                name: self.network_name.clone(),
                ..Default::default()
            };
            self.docker
                .create_network(network_config)
                .await
                .context(format!("Failed to create network {}", self.network_name))?;
            info!("✅ Docker network {} created", self.network_name);
        } else {
            info!("Docker network {} already exists", self.network_name);
        }

        Ok(())
    }

    /// Create and start a container
    pub async fn create_and_start_container(&self, config: ContainerConfig) -> Result<String> {
        // Check if container already exists
        let inspect_options = InspectContainerOptions {
            ..Default::default()
        };
        if self
            .docker
            .inspect_container(&config.name, Some(inspect_options))
            .await
            .is_ok()
        {
            warn!(
                "Container {} already exists, removing it first",
                config.name
            );
            self.remove_container(&config.name, true).await?;
        }

        // Build port bindings
        let mut port_bindings = HashMap::new();
        for port_mapping in &config.ports {
            let key = format!("{}/{}", port_mapping.container_port, port_mapping.protocol);
            let binding = PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: port_mapping.host_port.map(|p| p.to_string()),
            };
            port_bindings.insert(key, Some(vec![binding]));
        }

        // Build environment variables
        let env: Vec<String> = config
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // Build volume bindings for Docker socket and other volumes
        let binds: Option<Vec<String>> = if !config.volumes.is_empty() {
            Some(
                config
                    .volumes
                    .iter()
                    .map(|v| {
                        if v.read_only {
                            format!("{}:{}:ro", v.host_path, v.container_path)
                        } else {
                            format!("{}:{}", v.host_path, v.container_path)
                        }
                    })
                    .collect(),
            )
        } else {
            None
        };

        // Build host config
        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            restart_policy: Some(bollard::models::RestartPolicy {
                name: Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            network_mode: Some(config.network.clone()),
            binds,
            ..Default::default()
        };

        // Build container config
        let container_config = Config {
            image: Some(config.image.clone()),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

        // Create container
        info!(
            "Creating Docker container: {} with image: {}",
            config.name, config.image
        );
        let create_options = CreateContainerOptions {
            name: config.name.clone(),
            platform: None,
        };

        let create_result = self
            .docker
            .create_container(Some(create_options), container_config)
            .await
            .context(format!("Failed to create container {}", config.name))?;

        let container_id = create_result.id;
        info!(
            "✅ Container {} created with ID: {}",
            config.name,
            &container_id[..12]
        );

        // Start container
        info!("Starting container: {}", config.name);
        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await
            .context(format!("Failed to start container {}", config.name))?;

        info!("✅ Container {} started", config.name);

        Ok(container_id)
    }

    /// Stop a container
    pub async fn stop_container(&self, container_name: &str, timeout: Option<u32>) -> Result<()> {
        info!("Stopping container: {}", container_name);
        let stop_options = StopContainerOptions {
            t: timeout.map(|t| t as i64).unwrap_or(10),
        };
        self.docker
            .stop_container(container_name, Some(stop_options))
            .await
            .context(format!("Failed to stop container {}", container_name))?;
        info!("✅ Container {} stopped", container_name);
        Ok(())
    }

    /// Remove a container
    pub async fn remove_container(&self, container_name: &str, force: bool) -> Result<()> {
        info!("Removing container: {}", container_name);
        let remove_options = RemoveContainerOptions {
            force,
            ..Default::default()
        };
        self.docker
            .remove_container(container_name, Some(remove_options))
            .await
            .context(format!("Failed to remove container {}", container_name))?;
        info!("✅ Container {} removed", container_name);
        Ok(())
    }

    /// Get container status
    pub async fn get_container_status(
        &self,
        container_name: &str,
    ) -> Result<Option<ContainerStatus>> {
        let inspect_options = InspectContainerOptions {
            ..Default::default()
        };
        match self
            .docker
            .inspect_container(container_name, Some(inspect_options))
            .await
        {
            Ok(container) => {
                let state = container.state.context("Container state not found")?;
                let status = state.status.context("Container status not found")?;

                Ok(Some(ContainerStatus {
                    id: container.id.context("Container ID not found")?,
                    name: container_name.to_string(),
                    status: format!("{:?}", status),
                    running: matches!(status, ContainerStateStatusEnum::RUNNING),
                }))
            }
            Err(e) => {
                // Check if it's a "not found" error
                let error_str = format!("{}", e);
                if error_str.contains("No such container") || error_str.contains("404") {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to inspect container: {}", e))
                }
            }
        }
    }

    /// Get container IP address in the network
    pub async fn get_container_ip(&self, container_name: &str) -> Result<Option<String>> {
        let inspect_options = InspectContainerOptions {
            ..Default::default()
        };
        let container = self
            .docker
            .inspect_container(container_name, Some(inspect_options))
            .await?;

        if let Some(network_settings) = container.network_settings {
            if let Some(networks) = network_settings.networks {
                if let Some(network) = networks.get(&self.network_name) {
                    if let Some(ip_address) = &network.ip_address {
                        return Ok(Some(ip_address.clone()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check if container is running
    pub async fn is_container_running(&self, container_name: &str) -> Result<bool> {
        match self.get_container_status(container_name).await? {
            Some(status) => Ok(status.running),
            None => Ok(false),
        }
    }

    /// Get container logs (for debugging)
    pub async fn get_container_logs(
        &self,
        container_name: &str,
        tail: Option<u64>,
    ) -> Result<Vec<String>> {
        let tail_str = tail
            .map(|t| t.to_string())
            .unwrap_or_else(|| "100".to_string());
        let options = bollard::container::LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail_str,
            ..Default::default()
        };

        let mut logs = Vec::new();
        let mut stream = self.docker.logs(container_name, Some(options));

        while let Some(log_result) = stream.next().await {
            match log_result {
                Ok(log) => {
                    // LogOutput is an enum, extract bytes based on variant
                    match log {
                        LogOutput::StdOut { message }
                        | LogOutput::StdErr { message }
                        | LogOutput::StdIn { message } => {
                            let bytes: Vec<u8> = message.into();
                            if let Ok(log_str) = String::from_utf8(bytes) {
                                logs.push(log_str);
                            }
                        }
                        LogOutput::Console { message } => {
                            let bytes: Vec<u8> = message.into();
                            if let Ok(log_str) = String::from_utf8(bytes) {
                                logs.push(log_str);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading container logs: {}", e);
                    break;
                }
            }
        }

        Ok(logs)
    }

    /// List all containers with a given name prefix
    pub async fn list_containers_by_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let list_options: ListContainersOptions<String> = Default::default();
        let containers = self
            .docker
            .list_containers(Some(list_options))
            .await
            .context("Failed to list containers")?;

        let matching_containers: Vec<String> = containers
            .iter()
            .filter_map(|c| {
                if let Some(names) = &c.names {
                    names
                        .iter()
                        .find(|name| name.strip_prefix("/").unwrap_or(name).starts_with(prefix))
                        .map(|name| name.strip_prefix("/").unwrap_or(name).to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(matching_containers)
    }

    /// Stop and remove all containers with a given name prefix
    pub async fn cleanup_containers_by_prefix(&self, prefix: &str) -> Result<usize> {
        let containers = self.list_containers_by_prefix(prefix).await?;
        let mut cleaned = 0;

        // Use parallel cleanup for faster shutdown
        let mut handles = Vec::new();

        for container_name in containers {
            let docker = self.docker.clone();
            let name = container_name.clone();

            let handle = tokio::spawn(async move {
                use bollard::container::{KillContainerOptions, RemoveContainerOptions};

                // Kill container directly (faster than stop)
                let kill_options = KillContainerOptions {
                    signal: "SIGKILL".to_string(),
                };
                let kill_result = docker.kill_container(&name, Some(kill_options)).await;
                if let Err(e) = kill_result {
                    // Container might already be stopped, continue anyway
                    warn!(
                        "Failed to kill container {}: {} (may already be stopped)",
                        name, e
                    );
                }

                // Small delay
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // Remove container (force=true to remove even if running)
                let remove_options = RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                };
                match docker.remove_container(&name, Some(remove_options)).await {
                    Ok(_) => {
                        info!("Cleaned up container: {}", name);
                        true
                    }
                    Err(e) => {
                        warn!("Failed to remove container {}: {}", name, e);
                        false
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all cleanup tasks with timeout
        let timeout = tokio::time::Duration::from_secs(5);
        let start = std::time::Instant::now();

        for handle in handles {
            if start.elapsed() > timeout {
                warn!("Cleanup timeout reached, stopping remaining cleanup tasks");
                break;
            }

            if let Ok(success) = handle.await {
                if success {
                    cleaned += 1;
                }
            }
        }

        Ok(cleaned)
    }
}

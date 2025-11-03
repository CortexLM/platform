# Security Architecture

## Overview

The Platform Validator implements multiple layers of security to ensure safe and isolated execution of challenge evaluations in TDX-secured Confidential Virtual Machines.

## Security Features

### TDX Attestation

Hardware-backed attestation using Intel Trust Domain Extensions (TDX):

- **TDX CVMs**: All challenge executions run in TDX-secured VMs
- **Quote Verification**: TDX quotes verify VM integrity and platform configuration
- **Nonce-Based**: Nonces included in attestation to prevent replay attacks
- **Event Log**: Event logs provide measurement verification

### CVM Isolation

Complete isolation of challenge execution environments:

- **Separate VMs**: Each challenge runs in its own CVM
- **No Shared State**: CVMs have no access to each other or validator state
- **Network Isolation**: Whitelist-based network access control
- **Resource Limits**: Enforced CPU, memory, and disk quotas
- **Temporary Storage**: CVMs have no persistent disk access

### Network Security

Network whitelist policies enforce strict access control:

- **Whitelist Enforcement**: Only allowed hosts and ports are accessible
- **QEMU Network**: CVMs run on isolated QEMU user-mode network (`10.0.2.0/24`)
- **Gateway Access**: Controlled access via gateway host (`10.0.2.2`)
- **Protocol Filtering**: TCP/UDP port restrictions

### Communication Security

Secure communication between validator and challenge CVMs:

- **WebSocket Encryption**: X25519 key exchange with XChaCha20-Poly1305 AEAD encryption
- **Signed Requests**: Ed25519 signed HTTP requests for authentication
- **Nonce-Based**: Unique nonces per message prevent replay attacks
- **Forward Secrecy**: Ephemeral keys for forward secrecy

### Resource Security

Strict resource limits and monitoring:

- **Quota Management**: CVM quota manager tracks and enforces resource limits
- **Capacity Checks**: Validator checks capacity before claiming jobs
- **Resource Monitoring**: Real-time tracking of CPU, memory, and disk usage
- **Automatic Cleanup**: CVMs destroyed after job completion

## Security Architecture

### TDX Attestation Flow

```
1. Validator creates CVM via dstack VMM
   ↓
2. CVM generates TDX quote with nonce
   ↓
3. Validator verifies TDX quote
   ↓
4. Key exchange (X25519)
   ↓
5. Encrypted communication (XChaCha20-Poly1305)
```

### Network Isolation Flow

```
Challenge CVM
   ↓
Network Policy (whitelist)
   ↓
QEMU Gateway (10.0.2.2)
   ↓
Allowed Hosts Only
   ↓
External Network (if whitelisted)
```

### Resource Enforcement

```
Job Request
   ↓
Check CVM Quota
   ↓
Verify Capacity
   ↓
Allocate Resources
   ↓
Create CVM
   ↓
Track Usage
   ↓
Destroy CVM (release resources)
```

## Network Policies

### Whitelist Configuration

Network policies are defined in challenge specifications:

```toml
[resources.network_whitelist]
hosts = ["api.openai.com", "huggingface.co"]
ports = [443, 80]
```

### Policy Enforcement

- **Host Filtering**: Only whitelisted hosts are accessible
- **Port Filtering**: Only whitelisted ports are allowed
- **Protocol Enforcement**: TCP/UDP restrictions
- **DNS Resolution**: Controlled DNS servers

### Default Network Policy

```toml
[sandbox_config.network_policy]
allow_outbound = true
allowed_hosts = ["localhost", "127.0.0.1"]
allowed_ports = [80, 443, 3000, 9080, 9081, 9082]
dns_servers = ["8.8.8.8", "1.1.1.1"]
```

## Filesystem Security

### Filesystem Policies

- **Read-Only**: Optional read-only filesystem
- **Allowed Paths**: Whitelist of accessible paths
- **Denied Paths**: Blacklist of restricted paths
- **Temporary Storage**: tmpfs for temporary files (no persistence)

### Default Filesystem Policy

```toml
[sandbox_config.filesystem_policy]
read_only = false
allowed_paths = ["/tmp", "/var/tmp"]
denied_paths = ["/etc", "/usr/bin"]
tmpfs_size = 1048576
```

## Attestation and Verification

### Challenge CVM Attestation

Challenge CVMs provide TDX attestation:

1. **Quote Generation**: CVM generates TDX quote during startup
2. **Quote Verification**: Validator verifies quote before accepting connections
3. **Key Exchange**: X25519 key exchange after attestation
4. **Encrypted Channel**: All communication encrypted with derived keys

### Validator Attestation

When validator runs as CVM:

1. **Validator CVM**: Provides TDX attestation to Platform API
2. **Verification**: Platform API verifies validator integrity
3. **Trust Chain**: Establishes trust chain for challenge CVMs

## Threat Model

### Protected Against

- **Code Injection**: TDX isolation prevents code injection
- **Data Exfiltration**: Network whitelist prevents unauthorized data access
- **Resource Exhaustion**: Quota manager prevents resource exhaustion
- **Replay Attacks**: Nonce-based protocols prevent replay attacks
- **Man-in-the-Middle**: Encrypted communication with key exchange

### Security Assumptions

- **TDX Hardware**: Assumes TDX-capable hardware
- **dstack VMM**: Assumes secure dstack VMM implementation
- **Platform API**: Assumes Platform API security
- **Network Gateway**: Assumes secure QEMU network gateway

## Best Practices

### For Validator Operators

1. **Hardware Security**: Use TDX-capable hardware
2. **Network Security**: Configure network whitelist appropriately
3. **Resource Limits**: Set appropriate resource limits
4. **Monitoring**: Monitor resource usage and CVM health
5. **Updates**: Keep validator and dstack VMM updated

### For Challenge Developers

1. **Network Access**: Only request whitelist access for required hosts
2. **Resource Usage**: Optimize resource usage
3. **Error Handling**: Implement proper error handling
4. **Security**: Follow security best practices in challenge code

## See Also

- [Architecture](architecture.md) - System architecture
- [CVM Setup](cvm-setup.md) - CVM deployment guide
- [Usage](usage.md) - Usage guide
- [API Reference](api-reference.md) - API documentation


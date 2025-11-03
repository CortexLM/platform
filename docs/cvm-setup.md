# CVM Setup Guide

Complete guide for deploying the Platform Validator as a Confidential Virtual Machine (CVM).

## Overview

When deploying the validator as a CVM, challenge CVMs can communicate with it via the QEMU gateway host at `10.0.2.2:18080`. This enables secure CVM-to-CVM communication within the dstack network.

## Prerequisites

1. dstack VMM running on `http://127.0.0.1:11530`
2. Validator Docker image built (`platform-validator:latest`)
3. dstack base image available (`dstack-0.5.2`)
4. Environment variables configured

## Architecture

### Network Layout

```
┌──────────────────────────────────────────────────────┐
│ Host Machine                                         │
│  ┌──────────────────────────────────────────────┐   │
│  │ QEMU User-mode Network (10.0.2.0/24)         │   │
│  │                                                │   │
│  │  ┌────────────────┐      ┌────────────────┐  │   │
│  │  │ Validator CVM  │      │ Challenge CVM  │  │   │
│  │  │ Port: 18080    │◄─────┤                │  │   │
│  │  │                │      │                │  │   │
│  │  └───────┬────────┘      └────────────────┘  │   │
│  │          │                                      │   │
│  │  ┌───────▼──────────────────────────────────┐  │   │
│  │  │ Gateway Host (10.0.2.2)                  │  │   │
│  │  │ Port Mapping: 18080 -> Host:18080        │  │   │
│  │  └──────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

### Port Mapping

- **Internal CVM Port**: `18080`
- **Host Port**: `18080`
- **Gateway Access**: `10.0.2.2:18080` (accessible from other CVMs)

### Access URLs

| Environment | URL | Use Case |
|------------|-----|----------|
| **Local Host** | `http://127.0.0.1:18080` | Testing from your machine |
| **Remote Host** | `http://<IP>:18080` | External network access |
| **Other CVMs** | `http://10.0.2.2:18080` | CVM-to-CVM communication |

## Docker Compose Configuration

The validator CVM uses the following Docker Compose configuration (`validator-cvm-docker-compose.yml`):

```yaml
version: '3.8'

services:
  validator:
    image: platform-validator:latest
    ports:
      # Port mapping: host_port:vm_port
      # Access from host: http://127.0.0.1:18080
      # Access from other CVMs: http://10.0.2.2:18080
      - '18080:18080'
    environment:
      - VALIDATOR_HOTKEY=${VALIDATOR_HOTKEY}
      - PLATFORM_BASE_API=${PLATFORM_BASE_API}
      - DSTACK_VMM_URL=${DSTACK_VMM_URL}
      - VALIDATOR_PORT=18080
      - VALIDATOR_BASE_URL=http://10.0.2.2:18080
    volumes:
      - ./config.toml:/app/config.toml:ro
      - ./data:/data
```

## Creating the Validator CVM

### Method 1: Using VMM API (Recommended)

Create the validator CVM using the dstack VMM API:

```bash
# 1. Create compose file
cat > validator-compose.json << 'EOF'
{
  "manifest_version": 2,
  "name": "platform-validator",
  "runner": "docker-compose",
  "docker_compose_file": "version: '3.8'\nservices:\n  validator:\n    image: platform-validator:latest\n    ports:\n      - '18080:18080'\n    environment:\n      - VALIDATOR_HOTKEY=${VALIDATOR_HOTKEY}\n      - PLATFORM_BASE_API=${PLATFORM_BASE_API}\n      - DSTACK_VMM_URL=${DSTACK_VMM_URL}\n      - VALIDATOR_PORT=18080\n    volumes:\n      - ./config.toml:/app/config.toml:ro\n      - ./data:/data"
}
EOF

# 2. Call VMM API
curl -X POST http://127.0.0.1:11530/prpc/CreateVm?json \
  -H "Content-Type: application/json" \
  -d '{
    "name": "platform-validator",
    "image": "dstack-0.5.2",
    "compose_file": "$(cat validator-compose.json | jq -c)",
    "vcpu": 4,
    "memory": 4096,
    "disk_size": 50,
    "ports": [
      {
        "protocol": "tcp",
        "host_port": 18080,
        "vm_port": 18080,
        "host_address": "0.0.0.0"
      }
    ],
    "encrypted_env": "",
    "user_config": "",
    "hugepages": false,
    "pin_numa": false,
    "stopped": false
  }'
```

### Method 2: Using vmm-cli

```bash
cd /path/to/dstack/vmm/src

# Create compose file
python3 vmm-cli.py compose \
  --name "platform-validator" \
  --docker-compose /path/to/validator-cvm-docker-compose.yml \
  --output /tmp/validator-compose.json

# Deploy with port mapping
python3 vmm-cli.py --url http://127.0.0.1:11530 deploy \
  --name "platform-validator" \
  --image "dstack-0.5.2" \
  --compose /tmp/validator-compose.json \
  --vcpu 4 \
  --memory 4G \
  --disk 50G \
  --port "tcp:18080:18080"
```

## Configuration

### Environment Variables

Set the following environment variables before creating the CVM:

```bash
export VALIDATOR_HOTKEY="5DD..."
export PLATFORM_BASE_API="http://platform-api:8080"
export DSTACK_VMM_URL="http://127.0.0.1:11530"
export VALIDATOR_PORT=18080
export VALIDATOR_BASE_URL="http://10.0.2.2:18080"
```

### Challenge CVM Configuration

The validator automatically injects `VALIDATOR_BASE_URL` into challenge CVMs:

```rust
// In challenge_manager.rs
let user_config = format!("VALIDATOR_BASE_URL={}\n", self.validator_base_url);

let vm_config = VmConfiguration {
    // ...
    user_config, // Contains VALIDATOR_BASE_URL for challenge CVMs
    // ...
};
```

Challenge CVMs will have this variable in `/dstack/.user-config` and can connect to the validator at `http://10.0.2.2:18080`.

## Verification

### Check CVM Status

```bash
# Get VM info (replace <VM_ID> with the ID returned during creation)
curl http://127.0.0.1:11530/prpc/GetInfo?json \
  -d '{"id":"<VM_ID>"}' | jq .
```

### Check Port Mapping

```bash
curl http://127.0.0.1:11530/prpc/GetInfo?json \
  -d '{"id":"<VM_ID>"}' | jq '.info.configuration.ports'
```

### Test HTTP Access

```bash
# From host
curl http://127.0.0.1:18080/health

# From another CVM (use gateway)
curl http://10.0.2.2:18080/health
```

### Check Logs

```bash
curl "http://127.0.0.1:11530/logs?id=<VM_ID>&follow=false&lines=50"
```

## CVM Management

### Start CVM

```bash
curl -X POST http://127.0.0.1:11530/prpc/StartVm?json \
  -d '{"id":"<VM_ID>"}'
```

### Stop CVM

```bash
curl -X POST http://127.0.0.1:11530/prpc/StopVm?json \
  -d '{"id":"<VM_ID>"}'
```

### Remove CVM

```bash
curl -X POST http://127.0.0.1:11530/prpc/RemoveVm?json \
  -d '{"id":"<VM_ID>"}'
```

## Troubleshooting

### Port Already in Use

If port 18080 is already used:

```bash
# Change the port
export VALIDATOR_PORT=18081

# Or modify docker-compose
ports:
  - '18081:18081'
```

### CVM Won't Start

1. Check VMM logs for errors
2. Verify Docker image exists: `docker images | grep platform-validator`
3. Check available resources (RAM, CPU)
4. Verify dstack VMM is running: `curl http://127.0.0.1:11530/prpc/Status?json`

### Challenge CVMs Cannot Connect

1. Verify port mapping is correct in VM info
2. Check that `VALIDATOR_BASE_URL` is `http://10.0.2.2:18080` in challenge CVM config
3. Test connectivity from challenge CVM: `curl http://10.0.2.2:18080/health`
4. Check validator CVM logs for errors

### Network Issues

- Ensure all CVMs are on the same QEMU user-mode network (`10.0.2.0/24`)
- Gateway host IP is always `10.0.2.2` from within CVMs
- Port mappings must use `host_address: "0.0.0.0"` for external access

## Data Flow

1. **Challenge CVM** reads `/dstack/.user-config` on startup
2. Gets `VALIDATOR_BASE_URL=http://10.0.2.2:18080`
3. Connects to validator via `http://10.0.2.2:18080`
4. Secure communication via TDX attestation + X25519/XChaCha20-Poly1305 encryption

## Important Notes

1. **Port 18080**: Chosen to avoid conflicts with default port 8080
2. **Gateway Host**: `10.0.2.2` is the QEMU gateway IP accessible from all CVMs
3. **User Config**: The `/dstack/.user-config` file is copied from `user_config` during VM creation
4. **Communication**: Challenge CVMs must be on the same QEMU network as the validator CVM

## See Also

- [Architecture](architecture.md) - System architecture overview
- [Security](security.md) - Security and isolation details
- [Usage](usage.md) - Operational usage guide


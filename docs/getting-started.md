# Getting Started

## Prerequisites

- Rust 1.70 or higher
- Platform Network validator access
- dstack VMM instance running (for TDX VM execution)
- TDX-capable hardware (for production deployments)

## Installation

### Option 1: Install from Source

```bash
git clone https://github.com/PlatformNetwork/platform-validator.git
cd platform-validator
cargo build --release
```

### Option 2: Install with Dev Dependencies

```bash
cargo build --release
cargo install --path bins/validator
```

## Quick Start

### 1. Configure Environment Variables

```bash
export VALIDATOR_HOTKEY="5DD..."
export PLATFORM_BASE_API="http://platform-api:8080"
export DSTACK_VMM_URL="http://dstack-vmm:11530"
export VALIDATOR_CPU_CORES=4
export VALIDATOR_MEMORY_MB=2048
export VALIDATOR_DISK_MB=10240
export VALIDATOR_GPU_COUNT=1
```

### 2. Run the Validator

```bash
./target/release/validator
```

The validator will:
- Connect to Platform API via WebSocket
- Start polling for pending jobs
- Monitor active challenges
- Execute jobs in TDX-secured VMs

## Configuration

### Configuration File (`config.toml`)

Create a `config.toml` file in the validator directory:

```toml
[validator]
hotkey = "5DD..."
passphrase = "word1 word2 ... word24"

[platform_api]
url = "http://platform-api:8080"

[dstack]
vmm_url = "http://dstack-vmm:11530"

[resources]
cpu_cores = 4
memory_mb = 2048
disk_mb = 10240
gpu_count = 1
```

### Environment Variables

Required:
- `VALIDATOR_HOTKEY` - Validator hotkey (required)
- `PLATFORM_BASE_API` - Platform API URL (required)

Optional:
- `DSTACK_VMM_URL` - dstack VMM URL (default: `http://localhost:11530`)
- `VALIDATOR_CPU_CORES` - Available CPU cores (default: 4)
- `VALIDATOR_MEMORY_MB` - Available RAM in MB (default: 2048)
- `VALIDATOR_DISK_MB` - Available disk in MB (default: 10240)
- `VALIDATOR_GPU_COUNT` - Number of GPUs (default: 0)
- `VALIDATOR_DB_PATH` - Path to validator database (default: `./validator.db`)

## Running as CVM

For deploying the validator as a Confidential Virtual Machine (CVM), see [CVM Setup Guide](cvm-setup.md).

## Next Steps

- Learn about the [Architecture](architecture.md) to understand how the validator works
- Read the [Usage Guide](usage.md) for detailed operational instructions
- Check the [Security Guide](security.md) for security best practices
- See the [API Reference](api-reference.md) for all available endpoints


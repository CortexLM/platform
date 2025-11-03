# Usage Guide

## Validator Lifecycle

The Platform Validator runs continuously, performing several key operations:

### Startup Sequence

1. **Configuration Load**: Loads configuration from `config.toml` or environment variables
2. **Platform Client Initialization**: Connects to Platform API
3. **WebSocket Connection**: Establishes WebSocket connection for real-time notifications
4. **Component Initialization**: Initializes job manager, executor, challenge manager, and quota manager
5. **Background Tasks**: Starts polling loops for jobs and challenge monitoring

### Running the Validator

```bash
# Build release binary
cargo build --release

# Set required environment variables
export VALIDATOR_HOTKEY="5DD..."
export PLATFORM_BASE_API="http://platform-api:8080"
export DSTACK_VMM_URL="http://dstack-vmm:11530"

# Run validator
./target/release/validator
```

## Job Execution

### Job Polling

The validator polls for pending jobs every 5 seconds:

```rust
// Polling loop (runs every 5 seconds)
1. Fetch pending jobs → GET /jobs/pending
2. Check validator capacity → has_capacity()
3. Claim compatible job → POST /jobs/{id}/claim
4. Execute job → execute_job()
```

### Job Execution Flow

```
1. Download challenge code (GitHub)
   ↓
2. Create VM via dstack VMM
   ↓
3. Execute submission in TDX CVM
   ↓
4. Collect results from challenge SDK
   ↓
5. Submit results to platform-api
   ↓
6. Destroy VM
```

### Job Execution Example

```rust
// In executor.rs
pub async fn execute_job(&mut self, job: JobInfo) -> Result<()> {
    // 1. Download challenge code
    let challenge_code = self.download_challenge(&job.challenge_id).await?;
    
    // 2. Create VM
    let vm_id = self.create_vm(&job).await?;
    
    // 3. Execute evaluation
    let results = self.evaluate_submission(&vm_id, &challenge_code, &job).await?;
    
    // 4. Submit results
    client.submit_results(&job.id, results).await?;
    
    // 5. Cleanup
    self.destroy_vm(&vm_id).await?;
    
    Ok(())
}
```

## Challenge Management

### Challenge Monitoring

The validator monitors active challenges every 60 seconds:

```
1. GET /challenges/active
   ↓
2. Compare GitHub commits
   ↓
3. If commit changed → restart challenge CVM
   ↓
4. Provision new CVM with updated code
```

### Challenge Lifecycle

Challenges progress through these states:

- **Created**: Challenge specification loaded
- **Provisioning**: CVM is being created
- **Probing**: Validator testing challenge CVM connectivity
- **Active**: Challenge CVM is running and ready for jobs
- **Failed**: Challenge CVM failed to start or crashed
- **Recycling**: Challenge CVM is being recycled (updated code)

### Challenge Update Flow

```rust
// When GitHub commit changes
1. Validator detects commit change
2. Marks old CVM for recycling
3. Provisions new CVM with updated code
4. New CVM enters probing state
5. On success, new CVM becomes active
6. Old CVM completes active jobs and is destroyed
```

## WebSocket Notifications

The validator receives real-time notifications via WebSocket:

### Connection

```rust
ws://platform-api/validators/{hotkey}/ws
```

### Notification Types

**New Job Available**:
```json
{
  "type": "new_job",
  "job_id": "uuid",
  "challenge_id": "uuid"
}
```

**Challenge Updated**:
```json
{
  "type": "challenge_updated",
  "challenge_id": "uuid",
  "github_commit": "abc123..."
}
```

**Job Cancelled**:
```json
{
  "type": "job_cancelled",
  "job_id": "uuid"
}
```

## Configuration

### Configuration File (`config.toml`)

```toml
# Resource limits
[resource_limits]
cpu_cores = 4
memory_mb = 2048
disk_mb = 10240

# Sandbox configuration
[sandbox_config]
isolation_level = "Tee"
resource_monitoring = true

# Network policy
[sandbox_config.network_policy]
allow_outbound = true
allowed_hosts = ["api.openai.com", "huggingface.co"]
allowed_ports = [443, 80]

# Scoring configuration
[scoring_config]
algorithm = "Linear"
normalization = "MinMax"
```

### Environment Variables

**Required**:
- `VALIDATOR_HOTKEY` - Validator hotkey for authentication
- `PLATFORM_BASE_API` - Platform API base URL

**Optional**:
- `DSTACK_VMM_URL` - dstack VMM URL (default: `http://localhost:11530`)
- `VALIDATOR_CPU_CORES` - Available CPU cores (default: 4)
- `VALIDATOR_MEMORY_MB` - Available RAM in MB (default: 2048)
- `VALIDATOR_DISK_MB` - Available disk in MB (default: 10240)
- `VALIDATOR_GPU_COUNT` - Number of GPUs (default: 0)
- `VALIDATOR_DB_PATH` - Validator database path (default: `./validator.db`)
- `VALIDATOR_BASE_URL` - Validator base URL for challenge CVMs (default: `http://10.0.2.2:18080`)

## Resource Management

### CVM Quota Manager

The validator tracks resource usage across all CVMs:

```rust
// Quota manager tracks:
- Total CPU cores used
- Total memory used
- Total disk used
- Active CVM count

// Before creating new CVM:
- Check available resources
- Verify capacity for new CVM
- Allocate resources if available
```

### Capacity Checks

Before claiming a job, the validator checks:

1. **Resource Availability**: Enough CPU, memory, disk
2. **Active Job Limit**: Maximum concurrent jobs (configurable)
3. **CVM Quota**: Total resources not exceeded

## Dynamic Values

The validator provides secure key-value storage for challenge state:

```rust
// Store value
dynamic_values_manager.set("key", "value").await?;

// Get value
let value = dynamic_values_manager.get("key").await?;

// Challenge SDK can access via Context.values
```

## HTTP Server

The validator runs an HTTP server for health checks and metrics:

### Endpoints

- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics (if enabled)

### Example

```bash
curl http://localhost:18080/health
```

## Logging

The validator uses structured logging with `tracing`:

```bash
# Set log level
export RUST_LOG=info

# More verbose
export RUST_LOG=debug

# Specific module
export RUST_LOG=platform_validator=debug,api_client=info
```

## See Also

- [Getting Started](getting-started.md) - Installation and setup
- [Architecture](architecture.md) - System architecture
- [Security](security.md) - Security details
- [API Reference](api-reference.md) - Complete API documentation


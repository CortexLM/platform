# API Reference

Complete API documentation for the Platform Validator and Platform API integration.

## Platform API Endpoints

The validator communicates with Platform API via REST and WebSocket.

### GET /challenges/active

Get all active challenges with GitHub repository information.

**Request**:
```http
GET /challenges/active
X-Validator-Hotkey: 5DD...
```

**Response**:
```json
{
  "challenges": [
    {
      "id": "uuid",
      "name": "challenge-name",
      "status": "active",
      "github_repo": "https://github.com/...",
      "github_commit": "abc123...",
      "compose_hash": "sha256...",
      "mechanism_id": 1,
      "emission_share": 0.5
    }
  ]
}
```

### GET /jobs/pending

Get pending jobs for this validator.

**Request**:
```http
GET /jobs/pending
X-Validator-Hotkey: 5DD...
```

**Response**:
```json
{
  "jobs": [
    {
      "id": "uuid",
      "challenge_id": "uuid",
      "submission_id": "uuid",
      "miner_hotkey": "5DD...",
      "status": "pending",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

### POST /jobs/{id}/claim

Claim a specific job for execution.

**Request**:
```http
POST /jobs/{id}/claim
X-Validator-Hotkey: 5DD...
```

**Response**:
```json
{
  "id": "uuid",
  "challenge_id": "uuid",
  "submission_id": "uuid",
  "status": "claimed"
}
```

### POST /jobs/{id}/results

Submit evaluation results for a completed job.

**Request**:
```http
POST /jobs/{id}/results
X-Validator-Hotkey: 5DD...
Content-Type: application/json

{
  "score": 0.95,
  "metrics": {
    "accuracy": 0.95,
    "latency_ms": 150
  },
  "logs": ["Evaluation started", "Completed successfully"],
  "execution_time_ms": 5000,
  "error": null
}
```

**Response**: `204 No Content` on success

### POST /challenges/{id}/orm/query

Execute ORM query for a challenge (read-only).

**Request**:
```http
POST /challenges/{id}/orm/query
X-Validator-Hotkey: 5DD...
Content-Type: application/json

{
  "query": "SELECT * FROM agents WHERE status = 'validated'",
  "params": []
}
```

**Response**:
```json
{
  "rows": [
    {"id": "...", "miner_hotkey": "...", ...}
  ]
}
```

## WebSocket API

### Connection

```
ws://platform-api/validators/{hotkey}/ws
```

### Message Types

**New Job Notification**:
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

## Validator Components

### PlatformClient

HTTP and WebSocket client for Platform API.

**Methods**:
- `get_challenges()` - Get active challenges
- `get_pending_jobs()` - Get pending jobs
- `claim_job(job_id)` - Claim a job
- `submit_results(job_id, results)` - Submit results
- `execute_orm_query(challenge_id, query)` - Execute ORM query
- `connect_websocket(callback)` - Connect WebSocket

### JobManager

Manages job lifecycle and execution.

**Methods**:
- `fetch_pending_jobs()` - Fetch pending jobs from API
- `claim_job(job_id)` - Claim a job for execution
- `has_capacity(job)` - Check if validator has capacity
- `check_challenge_updates()` - Monitor challenge updates

### ChallengeManager

Manages challenge CVMs and lifecycle.

**Methods**:
- `provision_challenge(challenge_spec)` - Provision challenge CVM
- `update_challenge(challenge_id)` - Update challenge CVM
- `destroy_challenge(challenge_id)` - Destroy challenge CVM
- `get_challenge_status(challenge_id)` - Get challenge status

### DstackExecutor

Executes jobs in TDX CVMs.

**Methods**:
- `execute_job(job)` - Execute a job
- `create_vm(job)` - Create VM for job
- `evaluate_submission(vm_id, code, job)` - Evaluate submission
- `destroy_vm(vm_id)` - Destroy VM

### CVMQuotaManager

Manages resource quotas and capacity.

**Methods**:
- `check_capacity(resources)` - Check if resources available
- `allocate(resources)` - Allocate resources
- `release(resources)` - Release resources
- `get_usage()` - Get current usage

## dstack VMM API

### Create VM

```http
POST /prpc/CreateVm?json
Content-Type: application/json

{
  "name": "challenge-cvm",
  "image": "dstack-0.5.2",
  "compose_file": "...",
  "vcpu": 4,
  "memory": 4096,
  "disk_size": 50,
  "ports": [
    {
      "protocol": "tcp",
      "host_port": 8080,
      "vm_port": 8080,
      "host_address": "0.0.0.0"
    }
  ]
}
```

### Get VM Info

```http
POST /prpc/GetInfo?json
Content-Type: application/json

{
  "id": "vm-uuid"
}
```

### Start/Stop/Remove VM

```http
POST /prpc/StartVm?json
POST /prpc/StopVm?json
POST /prpc/RemoveVm?json

{
  "id": "vm-uuid"
}
```

## Configuration

### ValidatorConfig

Configuration structure loaded from `config.toml`:

```rust
pub struct ValidatorConfig {
    pub validator_hotkey: String,
    pub platform_api_url: String,
    pub dstack_vmm_url: String,
    pub resource_limits: ResourceLimits,
    // ...
}
```

### ResourceLimits

```rust
pub struct ResourceLimits {
    pub cpu_cores: u32,
    pub memory_mb: u32,
    pub disk_mb: u32,
    pub gpu_count: u32,
}
```

## Error Handling

All API methods return `Result<T>` for error handling:

- **Network Errors**: Connection failures, timeouts
- **API Errors**: HTTP errors, validation failures
- **Execution Errors**: Job execution failures
- **Resource Errors**: Capacity exceeded, quota limits

## See Also

- [Usage Guide](usage.md) - How to use the APIs
- [Architecture](architecture.md) - System architecture
- [Security](security.md) - Security details


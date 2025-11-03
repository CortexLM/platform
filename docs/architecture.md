# Architecture

## System Overview

The Platform Validator operates as a secure execution engine for Platform Network challenges, running challenge evaluations in TDX-secured Confidential Virtual Machines (CVMs) via dstack VMM.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    Platform Network                          │
│                                                              │
│  ┌──────────────┐                                           │
│  │   Miner 1    │──────┐                                    │
│  └──────────────┘      │                                    │
│                        │  Challenge submissions             │
│  ┌──────────────┐      │                                    │
│  │   Miner N    │──────┘                                    │
│  └──────┬───────┘                                           │
│         │                                                    │
│         │ HTTP (Signed requests)                             │
│         ▼                                                    │
│  ┌────────────────────────────┐                             │
│  │     Platform API           │                             │
│  │                            │                             │
│  │  - Manage challenges       │                             │
│  │  - Queue jobs             │                             │
│  │  - Store results          │                             │
│  │  - WebSocket notifications│                             │
│  └──────┬─────────────────────┘                             │
│         │                                                    │
│         │ WebSocket + HTTP                                   │
│         │  - Job notifications                               │
│         │  - Challenge updates                              │
│         │  - Result submission                              │
│         ▼                                                    │
│  ┌────────────────────────────┐                             │
│  │  Platform Validator         │                             │
│  │                            │                             │
│  │  ┌──────────────────────┐  │                             │
│  │  │  Job Manager         │  │                             │
│  │  │  - Poll for jobs     │  │                             │
│  │  │  - Claim jobs        │  │                             │
│  │  │  - Track execution   │  │                             │
│  │  └──────────────────────┘  │                             │
│  │                            │                             │
│  │  ┌──────────────────────┐  │                             │
│  │  │  Challenge Manager   │  │                             │
│  │  │  - Monitor challenges│  │                             │
│  │  │  - Manage CVMs        │  │                             │
│  │  │  - GitHub monitoring │  │                             │
│  │  └──────────────────────┘  │                             │
│  │                            │                             │
│  │  ┌──────────────────────┐  │                             │
│  │  │  Executor            │  │                             │
│  │  │  - Create CVMs        │  │                             │
│  │  │  - Execute jobs       │  │                             │
│  │  │  - Collect results    │  │                             │
│  │  └──────────────────────┘  │                             │
│  │                            │                             │
│  │  ┌──────────────────────┐  │                             │
│  │  │  CVM Quota Manager   │  │                             │
│  │  │  - Resource tracking │  │                             │
│  │  │  - Capacity checks   │  │                             │
│  │  └──────────────────────┘  │                             │
│  └──────┬─────────────────────┘                             │
│         │                                                    │
│         │ dstack VMM API                                     │
│         ▼                                                    │
│  ┌────────────────────────────┐                             │
│  │     dstack VMM              │                             │
│  │                            │                             │
│  │  - Create TDX CVMs         │                             │
│  │  - Network isolation      │                             │
│  │  - Resource allocation    │                             │
│  └──────┬─────────────────────┘                             │
│         │                                                    │
│         │ TDX-Secured VMs                                   │
│         ▼                                                    │
│  ┌────────────────────────────┐                             │
│  │  Challenge CVMs             │                             │
│  │                            │                             │
│  │  - Challenge SDK            │                             │
│  │  - Job execution          │                             │
│  │  - Result evaluation      │                             │
│  └────────────────────────────┘                             │
└──────────────────────────────────────────────────────────────┘
```

## Components

### Platform API

The Platform API manages challenges and coordinates job execution:

- **Challenge Management**: Stores challenge specifications, GitHub repository info, and active challenge status
- **Job Queue**: Manages pending jobs and job assignment to validators
- **WebSocket Server**: Provides real-time notifications for new jobs and challenge updates
- **Result Storage**: Receives and stores evaluation results from validators

### Platform Validator

The validator is the core execution engine:

#### Job Manager (`bins/validator/src/job_manager.rs`)

- **Job Polling**: Periodically fetches pending jobs from Platform API
- **Job Claiming**: Claims compatible jobs based on resource capacity
- **Execution Tracking**: Manages active job lifecycle
- **Result Submission**: Submits evaluation results back to Platform API

#### Challenge Manager (`bins/validator/src/challenge_manager.rs`)

- **Challenge Monitoring**: Monitors active challenges for updates
- **CVM Lifecycle**: Manages challenge CVM creation, updates, and destruction
- **GitHub Integration**: Tracks GitHub commits and restarts challenges on updates
- **WebSocket Client**: Maintains WebSocket connection to challenge CVMs

#### Executor (`bins/validator/src/executor.rs`)

- **CVM Provisioning**: Creates TDX-secured CVMs via dstack VMM
- **Job Execution**: Executes challenge evaluations in isolated CVMs
- **Result Collection**: Gathers evaluation results from challenge CVMs
- **Cleanup**: Destroys CVMs after job completion

#### CVM Quota Manager (`bins/validator/src/cvm_quota.rs`)

- **Resource Tracking**: Tracks CPU, memory, and disk usage across all CVMs
- **Capacity Management**: Ensures validator doesn't exceed resource limits
- **Allocation**: Allocates resources for new CVMs based on challenge requirements

#### API Client (`crates/api_client/`)

- **REST Client**: HTTP client for Platform API endpoints
- **WebSocket Client**: Real-time notification client
- **Signed Requests**: Ed25519 signed HTTP requests for authentication

#### Challenge Spec (`crates/challenge_spec/`)

- **Spec Parsing**: Parses `platform.toml` challenge specifications
- **Resource Validation**: Validates resource requirements (CPU, RAM, GPU)
- **Network Policies**: Manages network whitelist configuration

### dstack VMM

The dstack VMM provides TDX-secured VM infrastructure:

- **CVM Creation**: Creates isolated TDX CVMs from Docker Compose specifications
- **Network Isolation**: Enforces network whitelist policies
- **Resource Allocation**: Allocates CPU, memory, and disk resources
- **Attestation**: Provides TDX attestation for VM integrity verification

### Challenge CVMs

TDX-secured VMs running challenge evaluations:

- **Challenge SDK**: Runs the Platform Challenge SDK for job evaluation
- **Isolated Execution**: Executes in completely isolated environment
- **Network Policies**: Enforced network whitelist restrictions
- **Result Reporting**: Sends evaluation results back to validator

## Communication Flow

### 1. Challenge Registration

1. Platform API registers a new challenge with GitHub repository
2. Challenge Manager detects new challenge
3. Validator downloads challenge specification from GitHub
4. Validator provisions challenge CVM via dstack VMM

### 2. Job Execution Flow

1. Miner submits solution → Platform API
2. Platform API queues job → Job queue
3. Validator polls for jobs → Gets pending job
4. Validator claims job → Job status: claimed
5. Validator creates job VM → dstack VMM creates TDX CVM
6. Challenge CVM executes job → Evaluates submission
7. Challenge CVM returns results → Validator
8. Validator submits results → Platform API
9. Validator destroys job VM → Cleanup

### 3. Challenge Update Flow

1. Challenge code updated on GitHub → New commit
2. Validator monitors GitHub commits → Detects change
3. Validator restarts challenge CVM → New CVM with updated code
4. Active jobs continue → Old CVM completes jobs
5. New jobs use updated challenge → New CVM handles new jobs

## Data Flow

### Job Information Flow

```
Platform API → Validator → Challenge CVM → Validator → Platform API
```

### Challenge Specification Flow

```
GitHub → Validator → dstack VMM → Challenge CVM
```

### Result Flow

```
Challenge CVM → Validator → Platform API → Database
```

## Security Architecture

- **TDX Isolation**: All challenge executions in TDX-secured CVMs
- **Network Isolation**: Whitelist-based network access control
- **Resource Limits**: Enforced CPU, memory, and disk quotas
- **Attestation**: TDX attestation for VM integrity
- **Signed Requests**: Ed25519 signed API requests
- **No Persistent Storage**: CVMs have no persistent disk access

## See Also

- [Usage Guide](usage.md) - Learn how to use the validator
- [Security](security.md) - Detailed security architecture
- [API Reference](api-reference.md) - Complete API documentation
- [CVM Setup](cvm-setup.md) - CVM deployment guide


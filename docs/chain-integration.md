# Chain Integration Guide

This document describes how to configure the Platform validator to use either mock or real blockchain clients.

## Configuration

### Environment Variables

```bash
# Chain selection
CHAIN_CLIENT_TYPE=bittensor  # Options: mock, bittensor
BT_NETUID=100               # Bittensor subnet ID
BT_ENDPOINT=wss://entrypoint-finney.bittensor.com:443  # Optional: custom endpoint
VALIDATOR_HOTKEY=5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY  # Validator hotkey
```

## Using Mock Chain Client

For development and testing:

```rust
use platform_engine_chain::MockChainClient;

let client = MockChainClient::new();
```

## Using Real Bittensor Client

For production:

```rust
use platform_engine_chain::BittensorChainClient;

// From environment variables
let client = BittensorChainClient::from_env().await?;

// Or with specific configuration
let client = BittensorChainClient::new(100, Some(validator_hotkey)).await?;
```

## Factory Pattern (Recommended)

To switch between implementations based on configuration:

```rust
use platform_engine_chain::{ChainClient, MockChainClient, BittensorChainClient};
use std::sync::Arc;

async fn create_chain_client() -> anyhow::Result<Arc<dyn ChainClient>> {
    match std::env::var("CHAIN_CLIENT_TYPE").as_deref() {
        Ok("bittensor") => {
            let client = BittensorChainClient::from_env().await?;
            Ok(Arc::new(client) as Arc<dyn ChainClient>)
        }
        _ => {
            // Default to mock for development
            Ok(Arc::new(MockChainClient::new()) as Arc<dyn ChainClient>)
        }
    }
}
```

## Production Checklist

- [ ] Set `CHAIN_CLIENT_TYPE=bittensor` in production
- [ ] Configure `BT_NETUID` to correct subnet
- [ ] Set `VALIDATOR_HOTKEY` to your validator's hotkey
- [ ] Optionally set `BT_ENDPOINT` if not using mainnet finney
- [ ] Test connection before deploying
- [ ] Monitor chain connectivity and handle disconnections

## Features Comparison

| Feature | Mock Client | Bittensor Client |
|---------|------------|------------------|
| Weight Submission | ✅ Simulated | ⚠️ TODO: Implement commit/reveal |
| Get Weights | ✅ In-memory | ⚠️ TODO: Query from chain |
| Validator Set | ✅ Static list | ✅ Real neurons from chain |
| Subnet Info | ✅ Static info | ✅ Real subnet data |
| Current Block | ✅ Incremental | ✅ Real block number |

## Known Limitations

1. **Weight Submission**: The Bittensor client currently returns an error for weight submission. This needs to be implemented using the commit/reveal process.
2. **Weight Retrieval**: Getting weights for a specific validator is not yet implemented.
3. **Last Activity Tracking**: The `last_seen` field for validators is currently set to the current time. This should be derived from actual on-chain activity.

## Next Steps

1. Implement weight submission using bittensor-rs commit/reveal functions
2. Implement weight retrieval from chain storage
3. Add retry logic for chain disconnections
4. Add metrics for chain interaction performance
5. Implement caching for frequently accessed data

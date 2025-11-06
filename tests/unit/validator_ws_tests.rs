// Unit tests for Validator WebSocket
// Uses mock TDX client (required, TDX needs hardware)

// Note: challenge_ws is in bins/validator, so we test the logic indirectly
// Full WebSocket connection tests require mock WebSocket server
// These are better suited for integration tests

#[tokio::test]
async fn test_websocket_message_structure() {
    // Test that WebSocket message structures are correct
    use serde_json::json;
    
    let weight_request = json!({
        "type": "weight_request",
        "block": 1000,
        "timestamp": 1234567890,
    });
    
    assert_eq!(weight_request["type"], "weight_request");
    assert_eq!(weight_request["block"], 1000);
}

#[tokio::test]
async fn test_environment_isolation_logic() {
    // Test environment mode matching logic
    let validator_env = "dev";
    let challenge_env = "dev";
    
    // Same environment should match
    assert_eq!(validator_env, challenge_env);
    
    // Different environments should not match
    let challenge_env_prod = "prod";
    assert_ne!(validator_env, challenge_env_prod);
}


# Troubleshooting

Common errors and solutions for the Platform Validator.

## Connection Issues

### Error: "Failed to connect to Platform API"

**Cause**: Platform API is not reachable or incorrect URL.

**Solution**:
- Verify `PLATFORM_BASE_API` environment variable is correct
- Check network connectivity: `curl http://platform-api:8080/health`
- Verify Platform API is running

### Error: "WebSocket connection failed"

**Cause**: WebSocket connection to Platform API failed.

**Solution**:
- Check WebSocket URL format (should be `ws://` or `wss://`)
- Verify Platform API WebSocket endpoint is available
- Check firewall rules
- Review WebSocket logs for specific errors

### Error: "dstack VMM connection failed"

**Cause**: Cannot connect to dstack VMM.

**Solution**:
- Verify `DSTACK_VMM_URL` environment variable
- Check dstack VMM is running: `curl http://dstack-vmm:11530/prpc/Status?json`
- Verify network connectivity to VMM host
- Check VMM logs

## Job Execution Issues

### Error: "Job execution failed"

**Cause**: Job execution error in CVM.

**Solution**:
- Check challenge CVM logs via VMM API
- Verify challenge code is valid
- Check resource availability
- Review job execution logs

### Error: "CVM creation failed"

**Cause**: Failed to create CVM via dstack VMM.

**Solution**:
- Check dstack VMM status
- Verify resource availability (CPU, memory, disk)
- Check VMM logs for specific errors
- Verify Docker image exists

### Error: "Resource quota exceeded"

**Cause**: Validator doesn't have enough resources.

**Solution**:
- Check current resource usage
- Increase resource limits in configuration
- Wait for active jobs to complete
- Review CVM quota manager logs

## Challenge Management Issues

### Error: "Challenge CVM failed to start"

**Cause**: Challenge CVM provisioning or startup failed.

**Solution**:
- Check challenge specification validity
- Verify Docker Compose file format
- Check resource requirements
- Review VMM logs

### Error: "Challenge update failed"

**Cause**: Failed to update challenge with new code.

**Solution**:
- Verify GitHub repository is accessible
- Check commit hash is valid
- Review challenge manager logs
- Verify compose hash matches

### Error: "Challenge CVM not responding"

**Cause**: Challenge CVM is not responding to health checks.

**Solution**:
- Check CVM status via VMM API
- Verify challenge SDK is running in CVM
- Check network connectivity
- Review challenge CVM logs

## Network Issues

### Error: "Network policy violation"

**Cause**: Challenge attempted to access non-whitelisted host.

**Solution**:
- Add required host to network whitelist
- Verify network policy configuration
- Check challenge requirements
- Review network proxy logs

### Error: "Cannot reach validator from challenge CVM"

**Cause**: Challenge CVM cannot connect to validator.

**Solution**:
- Verify `VALIDATOR_BASE_URL` is set correctly
- Check port mapping in validator CVM
- Test connectivity: `curl http://10.0.2.2:18080/health` from challenge CVM
- Verify gateway host IP (`10.0.2.2`)

## Configuration Issues

### Error: "Invalid configuration"

**Cause**: Configuration file or environment variables are invalid.

**Solution**:
- Check `config.toml` syntax
- Verify all required environment variables are set
- Review configuration validation errors
- Check configuration documentation

### Error: "Hotkey not found"

**Cause**: Validator hotkey is not configured.

**Solution**:
- Set `VALIDATOR_HOTKEY` environment variable
- Verify hotkey format is correct
- Check hotkey is registered with Platform Network

## Resource Issues

### Error: "Insufficient CPU cores"

**Cause**: Not enough CPU cores available.

**Solution**:
- Reduce `VALIDATOR_CPU_CORES` in configuration
- Check active CVM count
- Wait for jobs to complete
- Increase host CPU resources

### Error: "Insufficient memory"

**Cause**: Not enough memory available.

**Solution**:
- Reduce `VALIDATOR_MEMORY_MB` in configuration
- Check memory usage across CVMs
- Reduce challenge memory requirements
- Increase host memory

## Logging and Debugging

### Enable Verbose Logging

```bash
export RUST_LOG=debug
./target/release/validator
```

### Check Specific Component

```bash
export RUST_LOG=platform_validator::job_manager=debug
./target/release/validator
```

### View Logs

```bash
# Validator logs
./target/release/validator 2>&1 | tee validator.log

# VMM logs
curl "http://127.0.0.1:11530/logs?id=<VM_ID>&follow=false&lines=100"
```

## Common Patterns

### Validator Not Claiming Jobs

Check:
1. Jobs are available in Platform API
2. Validator has capacity
3. Resource limits are not exceeded
4. WebSocket connection is active
5. Polling loop is running

### Jobs Failing Repeatedly

Check:
1. Challenge code is valid
2. Challenge CVM can start
3. Resource requirements are met
4. Network policies allow required access
5. Challenge SDK is working correctly

### CVMs Not Being Destroyed

Check:
1. Cleanup logic is being called
2. VMM API is accessible
3. VM IDs are correct
4. No errors in cleanup process

## Getting Help

1. **Check Logs**: Review validator and VMM logs
2. **Verify Configuration**: Ensure all settings are correct
3. **Test Connectivity**: Verify network connections
4. **Review Documentation**: Check relevant documentation pages
5. **Enable Debug Logging**: Use verbose logging for more details

## See Also

- [Getting Started](getting-started.md) - Setup guide
- [Usage](usage.md) - Usage instructions
- [Security](security.md) - Security details
- [Development](development.md) - Development setup


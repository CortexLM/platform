# Development Guide

Development setup and project structure for the Platform Validator.

## Project Structure

```
platform-validator/
├── bins/
│   ├── validator/          # Main validator binary
│   └── cli/                # CLI tools
├── crates/
│   ├── api_client/         # Platform API client
│   ├── challenge_spec/     # Challenge specification parser
│   ├── executor/           # Job execution engine
│   ├── chain/              # Blockchain integration
│   └── dynamic_values/     # Key-value storage
├── docs/                   # Documentation
├── Cargo.toml              # Workspace configuration
├── config.toml             # Validator configuration
└── Dockerfile              # Docker image
```

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- Cargo (Rust package manager)
- dstack VMM instance for testing
- TDX-capable hardware (for production)

### Installation

```bash
git clone https://github.com/PlatformNetwork/platform-validator.git
cd platform-validator
cargo build
```

### Development Dependencies

```bash
cargo build --release
```

## Code Quality

### Formatting

Format Rust code with `rustfmt`:

```bash
cargo fmt
```

### Linting

Check code with `clippy`:

```bash
cargo clippy --all-targets -- -D warnings
```

### Tests

Run tests:

```bash
cargo test
```

Run specific test:

```bash
cargo test --test test_name
```

## Adding Features

### Adding a New Crate

1. Create crate directory:
   ```bash
   mkdir -p crates/my_crate/src
   ```

2. Add to workspace in `Cargo.toml`:
   ```toml
   [workspace]
   members = [
       "crates/my_crate",
       # ...
   ]
   ```

3. Create `Cargo.toml` for crate:
   ```toml
   [package]
   name = "platform-engine-my-crate"
   version = "0.1.0"
   edition = "2021"
   ```

### Adding a New Component

1. Create module in `bins/validator/src/`
2. Add module to `main.rs`
3. Implement component logic
4. Add tests
5. Update documentation

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function() {
        // Test code
    }
}
```

### Integration Tests

Create tests in `tests/` directory:

```rust
#[tokio::test]
async fn test_integration() {
    // Integration test code
}
```

## Debugging

### Enable Debug Logging

```bash
export RUST_LOG=debug
./target/release/validator
```

### Specific Module Logging

```bash
export RUST_LOG=platform_validator::job_manager=debug
./target/release/validator
```

### Using GDB

```bash
cargo build
gdb target/debug/validator
```

## Configuration

### Local Development

Create `config.toml`:

```toml
[validator]
hotkey = "5DD..."
passphrase = "word1 word2 ..."

[platform_api]
url = "http://localhost:8080"

[dstack]
vmm_url = "http://localhost:11530"
```

## Docker Development

### Build Image

```bash
docker build -t platform-validator:dev .
```

### Run Container

```bash
docker run -it \
  -e VALIDATOR_HOTKEY="5DD..." \
  -e PLATFORM_BASE_API="http://platform-api:8080" \
  platform-validator:dev
```

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes and test
4. Run `cargo fmt` and `cargo clippy`
5. Commit changes: `git commit -m "feat: Add feature"`
6. Push and create pull request

## Code Style

### Rust Conventions

- Follow Rust naming conventions
- Use `Result<T>` for error handling
- Use `anyhow::Result` for application errors
- Add doc comments for public APIs
- Use `tracing` for logging

### Example

```rust
/// Execute a job in a TDX CVM.
///
/// # Arguments
/// * `job` - Job information
///
/// # Returns
/// Result indicating success or failure
pub async fn execute_job(&mut self, job: JobInfo) -> Result<()> {
    tracing::info!("Executing job: {}", job.id);
    // Implementation
    Ok(())
}
```

## See Also

- [Getting Started](getting-started.md) - Installation guide
- [Architecture](architecture.md) - System architecture
- [API Reference](api-reference.md) - API documentation


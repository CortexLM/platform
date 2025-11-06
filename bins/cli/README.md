# Platform Validator CLI

CLI to manage dynamic values and install challenges in the platform validator.

## Installation

```bash
cargo build --release --bin pv
```

The binary will be available in `target/release/pv`.

## Commands

### Dynamic Values

Manage dynamic values for a challenge.

#### Set
Set a dynamic value for a challenge:

```bash
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 8
```

#### Get
Retrieve a dynamic value:

```bash
pv dynamic get --challenge-id website-challenge --key resources.cpu_cores
```

#### List
List all dynamic values for a challenge:

```bash
pv dynamic list --challenge-id website-challenge
```

#### Delete
Delete a dynamic value:

```bash
pv dynamic delete --challenge-id website-challenge --key resources.cpu_cores
```

### Challenge Installation

#### Install
Install a challenge from a Git repository:

```bash
pv challenge install --repo-url https://github.com/user/challenge-repo.git --ref-name main
```

Options:
- `--repo-url`: Git repository URL
- `--ref-name`: Branch or commit hash (default: main)
- `--install-dir`: Installation directory (default: ./challenges)
- `--validator-url`: Validator URL (default: http://localhost:3030)

The CLI will:
1. Clone the repository
2. Checkout the specified commit
3. Load and display the `platform.json`
4. If `interactiveInstallation` is present, prompt for required values
5. Copy the challenge to the installation directory

#### Validate
Validate a challenge installation:

```bash
pv challenge validate --challenge-dir ./challenges/website-challenge
```

## Interactive Installation

The CLI supports interactive installation of challenges that require validator-specific configuration values.

### Configuration in platform.json

```json
{
  "interactive_installation": {
    "required_validator_values": [
      {
        "key": "resources.cpu_cores",
        "description": "Number of CPU cores available",
        "default_value": 4,
        "validation": {
          "type": "number",
          "min": 1,
          "max": 16
        }
      }
    ]
  }
}
```

### Validation types

- **number**: Numeric value with optional `min` and `max`
- **string**: String value with optional `pattern` regex
- **boolean**: Boolean value (true/false)

## Examples

### Complete challenge installation

```bash
# Clone and install with interactive configuration
pv challenge install --repo-url https://github.com/user/challenge.git

# The CLI will prompt for required values if interactiveInstallation is defined
# Then it downloads the challenge and configures the dynamic values
```

### Manually modify resources

```bash
# View current values
pv dynamic list --challenge-id website-challenge

# Modify CPU count
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 8

# Modify memory
pv dynamic set --challenge-id website-challenge --key resources.memory_mb --value 16384
```

## Integration with Validator

The CLI communicates with the validator HTTP server (port 3030 by default). Make sure the validator is started before using the CLI.

## Security

Validator dynamic values are stored locally in a SQLite database and can only be modified via the CLI or the validator HTTP API. Global dynamic values remain controlled by the platform API.

# Examples

## Basic commands

### List dynamic values

```bash
pv dynamic list --challenge-id website-challenge
```

### Set a value

```bash
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 8
```

### Download and install a challenge

```bash
pv challenge install --repo-url https://github.com/platform-network/website-challenge.git
```

## Complete interactive installation

When a challenge has `interactiveInstallation` configured, the installation becomes interactive:

```bash
$ pv challenge install --repo-url https://github.com/user/challenge.git

🔍 Cloning repository: https://github.com/user/challenge.git
✓ Checked out commit: abc123...
✓ Loaded platform.json for challenge: website-challenge
  Description: Challenge for generating luxury websites
  Version: 1.0.0

📋 Configuration:
  Global dynamic values: 9 keys
  Validator dynamic values: 3 keys

🔧 Interactive Installation Required

This challenge requires validator-specific configuration:

📝 Number of CPU cores available for challenge execution
Enter value for 'resources.cpu_cores' (default: 4): 8
✓ Set resources.cpu_cores = 8

📝 Memory (MB) available for challenge execution
Enter value for 'resources.memory_mb' (default: 8192): 16384
✓ Set resources.memory_mb = 16384

📝 Disk space (MB) available for challenge execution
Enter value for 'resources.disk_mb' (default: 10240): [Enter]
✓ Set resources.disk_mb = 10240

✓ Challenge installed successfully!
  Directory: ./challenges/website-challenge
  Commit: abc123...
```

## Input validation

If validation fails, the CLI prompts to retry:

```bash
📝 Number of CPU cores available for challenge execution
Enter value for 'resources.cpu_cores' (default: 4): 100
❌ Validation error: Must be <= 16
Do you want to try again? [y/n]: y
Enter value for 'resources.cpu_cores' (default: 4): 8
✓ Set resources.cpu_cores = 8
```

## Challenge validation

```bash
$ pv challenge validate --challenge-dir ./challenges/website-challenge

✓ Valid challenge configuration
  Name: website-challenge
  Version: 1.0.0
  Global values: 9 keys
  Validator values: 3 keys
  Interactive installation: 3 required values
```

## Manual value management

After installation, you can modify values:

```bash
# View all values
pv dynamic list --challenge-id website-challenge

# Modify a value
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 16

# Verify the modification
pv dynamic get --challenge-id website-challenge --key resources.cpu_cores

# Delete a value (return to default)
pv dynamic delete --challenge-id website-challenge --key resources.cpu_cores
```

## Installation from a specific commit

```bash
pv challenge install \
  --repo-url https://github.com/user/challenge.git \
  --ref-name abc123def456789
```

## Installation in a custom directory

```bash
pv challenge install \
  --repo-url https://github.com/user/challenge.git \
  --install-dir /custom/path/challenges
```

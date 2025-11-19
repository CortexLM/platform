# Launching a Validator

> **📖 For complete documentation, please visit the [validator-launcher repository](https://github.com/PlatformNetwork/validator-launcher)**

This document provides a brief overview of launching a Platform Network validator. The validator launcher is a separate service maintained in its own repository that handles:

- **Dstack installation and setup** (KMS, Gateway, VMM services)
- **Platform auto-updater** (automatic updates from GitHub)
- **Validator VM management** (automatic monitoring and updates)
- **Configuration management** (environment variables, VMM URL)

## Important: Check the validator-launcher Repository

The [validator-launcher repository](https://github.com/PlatformNetwork/validator-launcher) contains the **complete and up-to-date documentation** for:

✅ **Dstack Installation** - Complete guide for installing and configuring dstack services (KMS, Gateway, VMM)  
✅ **Platform Auto-Updater** - Setup for automatic updates from GitHub with systemd timers  
✅ **Installation Scripts** - Ansible-based installation for consistent setup  
✅ **Configuration** - Environment variables, VMM URL, and all settings  
✅ **Troubleshooting** - Common issues and solutions  
✅ **Service Management** - Starting, stopping, and monitoring the service

## Quick Start

The validator launcher automatically monitors and updates validator VMs in dstack VMM when compose configuration changes.

### Installation

```bash
git clone https://github.com/PlatformNetwork/validator-launcher.git
cd validator-launcher
sudo ./install.sh
```

The installation script will:
- Install Ansible and required collections
- Install build dependencies (Rust, build tools)
- **Install and configure dstack services** (KMS, Gateway, VMM)
- Build the release binary
- Install it to `/usr/local/bin/validator-launcher`
- Create a `platform` CLI alias
- Create a systemd service with automatic dstack startup

> **⚠️ Note:** For detailed dstack installation instructions, see the [validator-launcher README](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md#installation)

### Configuration

Set required environment variables:

```bash
# Set validator hotkey passphrase (required)
sudo platform config set-env HOTKEY_PASSPHRASE "your-12-word-mnemonic-passphrase"

# Set validator base URL (required)
sudo platform config set-env VALIDATOR_BASE_URL "http://10.0.2.2:18080"

# Set VMM URL (optional, defaults to http://10.0.2.2:10300/)
sudo platform config set-vmm-url "http://10.0.2.2:10300/"

# Verify configuration
sudo platform config show
```

### Starting the Service

```bash
# Enable and start the service
sudo systemctl enable validator-launcher
sudo systemctl start validator-launcher

# Check status
sudo systemctl status validator-launcher

# View logs
sudo journalctl -u validator-launcher -f
```

## Platform Auto-Updater

The validator-launcher includes an **automatic update system** that keeps your validator up-to-date with the latest code from GitHub.

To enable the auto-updater, follow the detailed instructions in the [validator-launcher auto-update section](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md#auto-update-setup).

The auto-updater:
- Checks for updates every 5 minutes
- Automatically rebuilds and restarts when updates are detected
- Only rebuilds when code actually changes (commit hash comparison)
- Runs as a systemd timer service

## Dstack Services

The validator launcher manages **dstack services** (KMS, Gateway, VMM) required for confidential computing.

For complete dstack installation and configuration instructions, see:
- [Dstack Services section in validator-launcher](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md#starting-the-service)
- [Troubleshooting dstack services](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md#service-wont-start)

## Full Documentation

**📚 All comprehensive documentation is available in the validator-launcher repository:**

👉 **[validator-launcher README](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md)**

Including:
- **Dstack installation and configuration** (KMS, Gateway, VMM)
- **Platform auto-updater setup** (GitHub integration with systemd)
- **Detailed installation steps** (Ansible playbooks)
- **Configuration management** (CLI commands)
- **CLI commands reference** (complete guide)
- **Troubleshooting guides** (common issues)
- **Development setup** (building from source)
- **Service management** (systemd integration)

## Key Features

- **Automatic polling**: Checks for configuration updates every 5 seconds
- **Change detection**: Compares compose content hash including image version
- **Graceful updates**: Stops existing VM with 60s timeout before recreation
- **Environment management**: Secure handling of environment variables with encryption
- **Auto-configuration**: Detects and validates required environment variables
- **CLI alias**: Easy access via `platform` command
- **Auto-update**: Optional systemd timer for automatic updates from GitHub

## Related Documentation

- [Platform Validator Architecture](architecture.md)
- [Platform Validator Usage](usage.md)
- [CVM Setup](cvm-setup.md)
- [Security](security.md)

## Support

**For all validator launching questions, always check the validator-launcher repository first:**

1. 📖 **[validator-launcher README](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md)** - Complete documentation
2. 🔧 **[Troubleshooting Guide](https://github.com/PlatformNetwork/validator-launcher/blob/main/README.md#troubleshooting)** - Dstack, service, and auto-update issues
3. 🐛 **[GitHub Issues](https://github.com/PlatformNetwork/validator-launcher/issues)** - Report bugs or ask questions
4. 📚 **[Platform Validator Documentation](getting-started.md)** - Additional validator documentation

---

**Remember:** The [validator-launcher repository](https://github.com/PlatformNetwork/validator-launcher) is the **authoritative source** for all validator launching documentation, including dstack installation and the platform auto-updater.


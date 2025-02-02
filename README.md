# Proxy Rust Service

## Overview

`proxy_rust` is a high-performance proxy server written in Rust, designed to be simple, efficient, and secure. This project includes the codebase, deployment scripts, and a systemd service configuration for running the proxy as a background service on a Linux server.

Currently, the proxy supports **SOCKS4** and **SOCKS5** protocols, making it suitable for a variety of use cases that require high-performance proxying.

The service is designed to be deployed on a remote server, where it will handle proxying tasks efficiently and securely while logging important events and errors.

## Features

- **SOCKS4 and SOCKS5 proxy support** for diverse proxying needs.
- Written in **Rust** for high performance and safety.
- Automated deployment using `Makefile` to handle building, deploying, and configuring the systemd service.
- Robust logging mechanism that stores logs in `/var/log/proxy_rust`.
- Memory and CPU usage limits for stability.
- Ensures security by running under a non-root user (`proxy_rust`).

## Prerequisites

To use this project, you need the following installed:

- **Rust** and `cargo` (Rust's package manager).
- **Make** (for building and deploying the project).
- **SSH access** to the remote server.
- **Systemd** on the server for service management.

## Setup and Installation

### 1. Clone the repository

First, clone the repository to your local machine:

```bash
git clone https://github.com/your-username/proxy_rust.git
cd proxy_rust
```

## 2. Deploy the service to the remote server

Once the build is complete, you can deploy the service to your remote server. The Makefile automates the process of creating necessary directories, uploading the binary, configuring the systemd service, and ensuring the service is running.

**Note:** Currently, we support only **Linux** for deployment.

```bash
make deploy-service
```

This command will:

- Ensure the necessary directories (like /var/log/proxy_rust) exist and have proper permissions.
- Create the proxy_rust system user if it does not exist.
- Upload the compiled binary to the remote server.
- Stop any currently running instance of the proxy_rust service.
- Upload the systemd service configuration file to /etc/systemd/system/.
- Set the correct permissions for the binary.
- Reload systemd and start the service.

## 4. Verifying the Service

After deployment, verify that the service is running by checking its status:

```bash
sudo systemctl status proxy_rust
```

## 5. Viewing Logs

You can check the logs of the proxy_rust service by looking at the log files stored in /var/log/proxy_rust/:

```bash
tail -f /var/log/proxy_rust/proxy.log
```

## Systemd Service Configuration

The following is the systemd service configuration used for running proxy_rust as a background service on Linux.

```ini
[Unit]
Description=Proxy Rust Service
After=network.target
StartLimitIntervalSec=0

[Service]

# Use a non-root user for security purposes

User=proxy_rust
Group=proxy_rust

# Working directory for the service

WorkingDirectory=/opt/proxy_rust

# Path to the executable

ExecStart=/opt/proxy_rust/proxy_rust

# Restart policy

Restart=on-failure
RestartSec=5

# Log settings

StandardOutput=append:/var/log/proxy_rust/proxy.log
StandardError=append:/var/log/proxy_rust/proxy_error.log

# Environment variables

Environment="RUST_BACKTRACE=1"
Environment="ENVIRONMENT=production"

# Limit resource usage for better stability

MemoryLimit=500M
CPUQuota=75%

# Security settings

ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ReadOnlyPaths=/etc
ReadWritePaths=/var/log/proxy_rust

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

If you encounter an issue with the service failing to start, check the system logs using journalctl:

```bash
journalctl -u proxy_rust.service
```

Make sure the /var/log/proxy_rust directory exists and has the correct permissions:

```bash
sudo mkdir -p /var/log/proxy_rust
sudo chown proxy_rust:proxy_rust /var/log/proxy_rust
sudo chmod 755 /var/log/proxy_rust
```

If the proxy_rust user does not exist, the deployment script will create it, but if necessary, you can create it manually:

```bash
sudo useradd --system --no-create-home --shell /bin/false proxy_rust
```

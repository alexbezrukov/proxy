# Include the environment variables file
# PLEASE ADD REMOTE_USER and REMOTE_HOST to your .env file!
-include .env

# Remote server configuration
REMOTE_DIR = /opt/proxy_rust
SERVICE_NAME = proxy_rust.service

# Cross-compilation targets
LINUX_TARGET = x86_64-unknown-linux-gnu
MACOS_TARGET = x86_64-apple-darwin
WINDOWS_TARGET = x86_64-pc-windows-msvc

# Build targets
build-linux:
	@echo "Building the release binary for Linux..."
	cargo build --release --target $(LINUX_TARGET)

build-macos:
	@echo "Building the release binary for macOS..."
	cargo build --release --target $(MACOS_TARGET)

build-windows:
	@echo "Building the release binary for Windows..."
	cargo build --release --target $(WINDOWS_TARGET)

# Deploy service to Linux server
deploy-service-linux:
	@echo "Creating necessary directories on the remote server..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) '\
		sudo mkdir -p /var/log/proxy_rust && \
		sudo chown root:root /var/log/proxy_rust && \
		sudo chmod 755 /var/log/proxy_rust'

	@echo "Checking if the proxy_rust user exists..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) '\
		if ! id "proxy_rust" &>/dev/null; then \
			echo "User proxy_rust does not exist. Creating..."; \
			sudo useradd --system --no-create-home --shell /bin/false proxy_rust; \
		else \
			echo "User proxy_rust already exists."; \
		fi'

	@echo "Checking if the service is already running..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) '\
		if systemctl is-active --quiet $(SERVICE_NAME); then \
			echo "Stopping the running service..."; \
			sudo systemctl stop $(SERVICE_NAME); \
		fi'

	@echo "Uploading release binary to the Linux server..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'mkdir -p $(REMOTE_DIR)'
	scp ./target/$(LINUX_TARGET)/release/proxy_rust $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/proxy_rust
	scp ./$(SERVICE_NAME) $(REMOTE_USER)@$(REMOTE_HOST):/etc/systemd/system/$(SERVICE_NAME)

	@echo "Setting correct permissions for the binary..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'chmod +x $(REMOTE_DIR)/proxy_rust'

	@echo "Reloading systemd and starting the service..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) '\
		sudo systemctl daemon-reload && \
		sudo systemctl enable $(SERVICE_NAME) --now'

	@echo "Service deployed and started successfully."


# A default target to build and deploy for the desired platform
deploy-service: build-linux deploy-service-linux

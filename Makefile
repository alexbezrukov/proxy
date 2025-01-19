# Remote server configuration
REMOTE_USER = <your_user>
REMOTE_HOST = <your_ip>
REMOTE_DIR = /opt/proxy_rust
SERVICE_NAME = proxy_rust.service

deploy-service:
	@echo "Building the release binary locally..."
	cargo build --release

	@echo "Creating remote directory if it doesn't exist..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'mkdir -p $(REMOTE_DIR)'

	@echo "Uploading release binary to the remote server..."
	scp ./target/release/vpn-rust $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/vpn-rust

	@echo "Uploading systemd service file to the remote server..."
	scp ./$(SERVICE_NAME) $(REMOTE_USER)@$(REMOTE_HOST):/etc/systemd/system/$(SERVICE_NAME)

	@echo "Setting correct permissions for the binary..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) 'chmod +x $(REMOTE_DIR)/vpn-rust'

	@echo "Reloading systemd and starting the service..."
	ssh $(REMOTE_USER)@$(REMOTE_HOST) '\
		sudo systemctl daemon-reload && \
		sudo systemctl enable $(SERVICE_NAME) --now'

	@echo "Service deployed and started successfully."

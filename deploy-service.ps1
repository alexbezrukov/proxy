$RemoteUser = "your_user"
$RemoteHost = "your_ip"
$RemoteDir = "/opt/proxy_rust"
$ServiceName = "proxy_rust.service"
$BinaryPath = "target/release/proxy_rust"

Write-Host "Building the release binary locally..."
cargo build --release

Write-Host "Creating remote directory if it doesn't exist..."
ssh "$RemoteUser@$RemoteHost" "mkdir -p $RemoteDir"

Write-Host "Uploading release binary to the remote server..."
scp $BinaryPath "$RemoteUser@${RemoteHost}:$RemoteDir/proxy_rust.exe"

Write-Host "Uploading systemd service file to the remote server..."
scp $ServiceName "$RemoteUser@${RemoteHost}:/etc/systemd/system/$ServiceName"

Write-Host "Setting correct permissions for the binary..."
ssh "$RemoteUser@$RemoteHost" "chmod +x $RemoteDir/proxy_rust"

Write-Host "Reloading systemd and starting the service..."
ssh "$RemoteUser@$RemoteHost" "sudo systemctl daemon-reload && sudo systemctl enable $ServiceName --now"

Write-Host "Service deployed and started successfully."

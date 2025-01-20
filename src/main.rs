use byteorder::{BigEndian, WriteBytesExt};
use core::str;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const PORT: u16 = 5001;
const BUFFER_SIZE: usize = 8192;

fn handle_client(mut conn: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut first_byte = [0; 1];
    conn.peek(&mut first_byte).expect("peek failed");

    match first_byte[0] {
        // Handle HTTPS/TLS (0x16 is start of TLS ClientHello)
        0x16 => handle_https(&mut conn)?,
        // Handle SOCKS5 (0x05 is start of a SOCKS5 handshake)
        0x05 => handle_socks5(&mut conn)?,
        // SOCKS4 handshake
        0x04 => handle_socks4(&mut conn)?, 
        // Handle HTTP CONNECT
        b'A'..=b'Z' | b'a'..=b'z' => {
            let mut buffer = [0; 4096];
            let bytes_read = conn.read(&mut buffer)?;
            let initial_data = str::from_utf8(&buffer[..bytes_read])?;

            if initial_data.starts_with("CONNECT") {
                handle_http_connect(&mut conn, initial_data).expect("failed to handle HTTP CONNECT");
            } else if initial_data.starts_with("GET") {
                handle_http_get(&mut conn, initial_data)?;
            } else if initial_data.starts_with("POST") {
                handle_http_post(&mut conn, initial_data)?;
            } else {
                eprintln!("Unknown HTTP method from {}", conn.peer_addr()?);
                conn.shutdown(Shutdown::Both)?;
            }
        }
        _ => {
            eprintln!("Unknown protocol from {}", conn.peer_addr()?);
            conn.shutdown(Shutdown::Both)?;
        }
    }

    Ok(())
}

fn handle_http_connect(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP CONNECT request: {}", initial_data);

    // Step 1: Parse the CONNECT request
    let parts: Vec<&str> = initial_data.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        eprintln!("Invalid HTTP CONNECT request: {}", initial_data);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let target_address = parts[1]; // This should be in the format "hostname:port"
    println!("Connecting to target address: {}", target_address);

    // Step 2: Establish a connection to the target server
    let remote_socket = TcpStream::connect(target_address).expect("failed to connect to remote host");
    
    // Step 3: Send the 200 Connection Established response to the client
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if let Err(e) = conn.write_all(response.as_bytes()) {
        eprintln!("Error sending connection established response: {}", e);
        conn.shutdown(Shutdown::Both)?;
        return Err(Box::new(e));
    }

    // Step 4: Forward traffic between the client and the remote server
    forward_traffic(conn, remote_socket);

    Ok(())
}

fn handle_http_get(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP GET request: {}", initial_data);

    // Step 1: Parse the HTTP GET request
    let mut parts = initial_data.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if method != "GET" {
        eprintln!("Unsupported HTTP method: {}", method);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    // Step 2: Extract the Host header (this is typically included in the request headers)
    let mut host = String::new();
    for line in initial_data.lines() {
        if line.to_lowercase().starts_with("host:") {
            host = line[5..].trim().to_string();
            break;
        }
    }

    if host.is_empty() {
        eprintln!("Host header missing or empty");
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    // Step 3: Connect to the remote server using the Host header (assuming HTTP)
    let remote_address = format!("{}:80", host); // Connect to the host on port 80 (HTTP)
    let mut remote_socket = TcpStream::connect(remote_address)?;

    // Step 4: Forward the HTTP GET request to the remote server
    let request = format!("{} {} {}\r\n", method, path, version);
    if let Err(e) = remote_socket.write_all(request.as_bytes()) {
        eprintln!("Error sending GET request to remote server: {}", e);
        conn.shutdown(Shutdown::Both)?;
        return Err(Box::new(e));
    }

    // Forward any additional headers from the client to the remote server
    let mut buffer = [0u8; BUFFER_SIZE];
    let bytes_read = conn.read(&mut buffer)?;
    let client_data = str::from_utf8(&buffer[..bytes_read])?;
    
    if let Err(e) = remote_socket.write_all(client_data.as_bytes()) {
        eprintln!("Error writing headers to remote server: {}", e);
        conn.shutdown(Shutdown::Both)?;
        return Err(Box::new(e));
    }

    // Step 5: Forward traffic between client and remote server
    forward_traffic(conn, remote_socket);

    Ok(())
}

#[allow(unused_variables)]
fn handle_http_post(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP POST request: {}", initial_data);
    // Handle the HTTP POST request here
    Ok(())
}

#[allow(unused_variables)]
fn handle_https(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTPS request...");
    // Placeholder for SSL/TLS handshake and HTTPS handling
    Ok(())
}

fn handle_socks5(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    // println!("Handling SOCKS request from: {}", conn.peer_addr().unwrap());
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf)
        .expect("Failed to read SOCKS version and method count");

    let socks_version = buf[0];
    let nmethods = buf[1];

    if socks_version != 5 {
        println!("Unsupported SOCKS version: {}", socks_version);
        conn.shutdown(Shutdown::Both)
            .expect("Failed to close connection");
        return Ok(());
    }

    let mut methods = vec![0u8; nmethods as usize];
    conn.read_exact(&mut methods)
        .expect("Failed to read authentication methods");

    // Send response to the client, selecting 'No authentication' (0)
    conn.write_all(&[5, 0])
        .expect("Failed to send authentication method response");

    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf)
        .expect("Failed to read SOCKS request");

    // Version of the request (should be 5)
    let request_version = buf[0]; 
    #[allow(unused_variables)]
    // Command (1 = connect)
    let cmd = buf[1]; 
    // Address type (1 = IPv4, 3 = domain)
    let addr_type = buf[3];

    if request_version != 5 {
        println!("Unsupported SOCKS version: {}", request_version);
        conn.shutdown(Shutdown::Both)
            .expect("Failed to close connection");
        return Ok(());
    }

    let address = match addr_type {
        1 => {
            let mut ipv4 = [0u8; 4];
            conn.read_exact(&mut ipv4)
                .expect("Failed to read IPv4 address");
            format!("{}.{}.{}.{}", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
        }
        3 => {
            let mut domain_length = [0u8; 1];
            conn.read_exact(&mut domain_length)
                .expect("Failed to read domain length");
            let mut domain = vec![0u8; domain_length[0] as usize];
            conn.read_exact(&mut domain).expect("Failed to read domain");
            str::from_utf8(&domain)
                .expect("Invalid UTF-8 domain")
                .to_string()
        }
        _ => {
            println!("Unsupported address type");
            conn.shutdown(Shutdown::Both)
                .expect("Failed to close connection");
            return Ok(());
        }
    };

    let port = {
        let mut buf = [0u8; 2];
        conn.read_exact(&mut buf).expect("Failed to read port");
        u16::from_be_bytes(buf)
    };

    let remote_socket =
        TcpStream::connect((address.as_str(), port)).expect("Failed to connect to remote server");
    println!("Connected to {}:{}", address, port);

    // Send success response to the client (SOCKS5 response)
    conn.write_u8(5).expect("Failed to send version byte");
    conn.write_u8(0)
        .expect("Failed to send no authentication response");
    conn.write_u8(0).expect("Failed to send reserved byte");
    conn.write_u8(1)
        .expect("Failed to send address type (IPv4)");

    // Sending IP address and port as 0.0.0.0:0 in the response
    // 127.0.0.1 (for example)
    conn.write_u32::<BigEndian>(0x7F000001)
        .expect("Failed to send IPv4 address in response"); 
    conn.write_u16::<BigEndian>(port)
        .expect("Failed to send port in response");

    println!(
        "Connection established with {}:{}, forwarding traffic.",
        address, port
    );

    forward_traffic(conn, remote_socket);

    Ok(())
}

fn handle_socks4(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf)
        .expect("Failed to read SOCKS4 request");

    let socks_version = buf[0];
    let cmd = buf[1];
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);

    if socks_version != 4 {
        println!("Unsupported SOCKS version: {}", socks_version);
        conn.shutdown(Shutdown::Both)
            .expect("Failed to close connection");
        return Ok(());
    }

    if cmd != 1 {
        println!("Unsupported SOCKS4 command: {}", cmd);
        conn.shutdown(Shutdown::Both)
            .expect("Failed to close connection");
        return Ok(());
    }

    // Read user ID (terminated by 0x00)
    let mut user_id = Vec::new();
    let mut byte = [0u8; 1];
    while conn.read_exact(&mut byte).is_ok() && byte[0] != 0 {
        user_id.push(byte[0]);
    }

    let user_id = String::from_utf8(user_id).unwrap_or_else(|_| "unknown".to_string());
    println!(
        "SOCKS4 request: version={}, command={}, ip={}, port={}, user_id={}",
        socks_version, cmd, ip, port, user_id
    );

    // Connect to the remote server
    match TcpStream::connect((ip, port)) {
        Ok(remote_socket) => {
            println!("Connected to {}:{}", ip, port);

            // SOCKS4 success response (0x5A)
            let response = [0x00, 0x5A, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
            conn.write_all(&response)
                .expect("Failed to send SOCKS4 success response");

            // Forward traffic between client and remote server
            forward_traffic(conn, remote_socket);
        }
        Err(e) => {
            println!("Failed to connect to {}:{} - {}", ip, port, e);

            // SOCKS4 failure response (0x5B)
            let response = [0x00, 0x5B, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
            conn.write_all(&response)
                .expect("Failed to send SOCKS4 failure response");
        }
    }

    Ok(())
}

fn forward_traffic(client_socket: &mut TcpStream, mut remote_socket: TcpStream) {
    client_socket
        .set_nonblocking(true)
        .expect("set_nonblocking call failed");
    remote_socket
        .set_nonblocking(true)
        .expect("set_nonblocking call failed");

    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        // Read from the client and forward to the remote server
        match client_socket.read(&mut buffer) {
            Ok(client_bytes_read) => {
                if client_bytes_read == 0 {
                    println!("Client closed the connection.");
                    break;
                }
                if let Err(e) = remote_socket.write_all(&buffer[..client_bytes_read]) {
                    eprintln!("Error writing to remote server: {}", e);
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }

        // Read from the remote server and forward to the client
        match remote_socket.read(&mut buffer) {
            Ok(remote_bytes_read) => {
                if remote_bytes_read == 0 {
                    println!("Server closed the connection.");
                    break;
                }
                if let Err(e) = client_socket.write_all(&buffer[..remote_bytes_read]) {
                    eprintln!("Error writing to client: {}", e);
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("Error reading from remote server: {}", e);
                break;
            }
        }

        // To prevent high CPU usage in the non-blocking loop, add a small sleep
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", PORT))?;
    println!("Server listening on port {}...", PORT);

    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(conn) {
                        eprintln!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Failed to accept connection: {}", e),
        }
    }

    Ok(())
}

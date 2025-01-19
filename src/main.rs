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
            // Possible HTTP method
            let mut buffer = [0; 4096];
            let bytes_read = conn.read(&mut buffer)?;
            let initial_data = str::from_utf8(&buffer[..bytes_read])?;

            if initial_data.starts_with("CONNECT") {
                handle_http_connect(&mut conn, initial_data)?;
            } else {
                eprintln!("Unknown HTTP method from {}", conn.peer_addr()?);
                conn.shutdown(Shutdown::Both)?;
            }
        }
        _ => {
            // Unknown protocol
            eprintln!("Unknown protocol from {}", conn.peer_addr()?);
            conn.shutdown(Shutdown::Both)?;
        }
    }

    Ok(())
}

#[allow(unused_variables)]
fn handle_http_connect(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP CONNECT request: {}", initial_data);
    // Placeholder for handling HTTP CONNECT requests
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

    let request_version = buf[0]; // Version of the request (should be 5)
    #[allow(unused_variables)]
    let cmd = buf[1]; // Command (1 = connect)
    let addr_type = buf[3]; // Address type (1 = IPv4, 3 = domain)

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
    conn.write_u32::<BigEndian>(0x7F000001)
        .expect("Failed to send IPv4 address in response"); // 127.0.0.1 (for example)
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

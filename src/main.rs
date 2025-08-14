use byteorder::{BigEndian, WriteBytesExt};
use core::str;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PORT: u16 = 5001;
const BUFFER_SIZE: usize = 8192;

fn log_connection_info(conn: &TcpStream, target: &str) {
    if let Ok(peer_addr) = conn.peer_addr() {
        if let Ok(since_the_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let timestamp = since_the_epoch.as_secs();
            println!(
                "Connection from IP: {}, Time: {}, Target: {}",
                peer_addr, timestamp, target
            );
        }
    }
}

fn handle_client(mut conn: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut first_byte = [0; 1];
    conn.peek(&mut first_byte)?;

    match first_byte[0] {
        0x16 => handle_https(&mut conn)?,
        0x05 => handle_socks5(&mut conn)?,
        0x04 => handle_socks4(&mut conn)?,
        b'A'..=b'Z' | b'a'..=b'z' => handle_http(&mut conn)?,
        _ => {
            eprintln!("Unknown protocol from {}", conn.peer_addr()?);
            conn.shutdown(Shutdown::Both)?;
        }
    }

    Ok(())
}

fn handle_http(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 4096];
    let bytes_read = conn.read(&mut buffer)?;
    let initial_data = str::from_utf8(&buffer[..bytes_read])?;

    if initial_data.starts_with("CONNECT") {
        log_connection_info(&conn, "HTTP CONNECT");
        handle_http_connect(conn, initial_data)?;
    } else if initial_data.starts_with("GET") {
        log_connection_info(&conn, "HTTP GET");
        handle_http_get(conn, initial_data)?;
    } else if initial_data.starts_with("POST") {
        log_connection_info(&conn, "HTTP POST");
        handle_http_post(conn, initial_data)?;
    } else {
        eprintln!("Unknown HTTP method from {}", conn.peer_addr()?);
        conn.shutdown(Shutdown::Both)?;
    }

    Ok(())
}

fn handle_http_connect(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP CONNECT request: {}", initial_data);

    let parts: Vec<&str> = initial_data.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        eprintln!("Invalid HTTP CONNECT request: {}", initial_data);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let target_address = parts[1];
    println!("Connecting to target address: {}", target_address);

    let remote_socket = TcpStream::connect(target_address)?;
    conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    forward_traffic(conn, remote_socket);

    Ok(())
}

fn handle_http_get(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP GET request: {}", initial_data);

    let mut parts = initial_data.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if method != "GET" {
        eprintln!("Unsupported HTTP method: {}", method);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let host = initial_data
        .lines()
        .find(|line| line.to_lowercase().starts_with("host:"))
        .map(|line| line[5..].trim().to_string())
        .unwrap_or_default();

    if host.is_empty() {
        eprintln!("Host header missing or empty");
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let remote_address = format!("{}:80", host);
    let mut remote_socket = TcpStream::connect(remote_address)?;

    let request = format!("{} {} {}\r\n", method, path, version);
    remote_socket.write_all(request.as_bytes())?;

    let mut buffer = [0u8; BUFFER_SIZE];
    let bytes_read = conn.read(&mut buffer)?;
    let client_data = str::from_utf8(&buffer[..bytes_read])?;
    remote_socket.write_all(client_data.as_bytes())?;

    forward_traffic(conn, remote_socket);

    Ok(())
}

fn handle_http_post(conn: &mut TcpStream, initial_data: &str) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTP POST request: {}", initial_data);
    Ok(())
}

fn handle_https(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    println!("Handling HTTPS request...");
    Ok(())
}

fn handle_socks5(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf)?;

    if buf[0] != 5 {
        println!("Unsupported SOCKS version: {}", buf[0]);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let nmethods = buf[1];
    let mut methods = vec![0u8; nmethods as usize];
    conn.read_exact(&mut methods)?;

    conn.write_all(&[5, 0])?;

    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf)?;

    if buf[0] != 5 {
        println!("Unsupported SOCKS version: {}", buf[0]);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let addr_type = buf[3];
    let address = match addr_type {
        1 => {
            let mut ipv4 = [0u8; 4];
            conn.read_exact(&mut ipv4)?;
            format!("{}.{}.{}.{}", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
        }
        3 => {
            let mut domain_length = [0u8; 1];
            conn.read_exact(&mut domain_length)?;
            let mut domain = vec![0u8; domain_length[0] as usize];
            conn.read_exact(&mut domain)?;
            str::from_utf8(&domain)?.to_string()
        }
        _ => {
            println!("Unsupported address type");
            conn.shutdown(Shutdown::Both)?;
            return Ok(());
        }
    };

    let port = {
        let mut buf = [0u8; 2];
        conn.read_exact(&mut buf)?;
        u16::from_be_bytes(buf)
    };

    let remote_socket = TcpStream::connect((address.as_str(), port))?;
    log_connection_info(&conn, &format!("SOCKS5 {}:{}", address, port));

    conn.write_all(&[5, 0, 0, 1])?;
    conn.write_u32::<BigEndian>(0x7F000001)?;
    conn.write_u16::<BigEndian>(port)?;

    println!(
        "Connection established with {}:{}, forwarding traffic.",
        address, port
    );

    forward_traffic(conn, remote_socket);

    Ok(())
}

fn handle_socks4(conn: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf)?;

    if buf[0] != 4 {
        println!("Unsupported SOCKS version: {}", buf[0]);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    if buf[1] != 1 {
        println!("Unsupported SOCKS4 command: {}", buf[1]);
        conn.shutdown(Shutdown::Both)?;
        return Ok(());
    }

    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);

    let mut user_id = Vec::new();
    let mut byte = [0u8; 1];
    while conn.read_exact(&mut byte).is_ok() && byte[0] != 0 {
        user_id.push(byte[0]);
    }

    let user_id = String::from_utf8(user_id).unwrap_or_else(|_| "unknown".to_string());
    log_connection_info(&conn, &format!("SOCKS4 {}:{}", ip, port));
    println!(
        "SOCKS4 request: version={}, command={}, ip={}, port={}, user_id={}",
        buf[0], buf[1], ip, port, user_id
    );

    match TcpStream::connect((ip, port)) {
        Ok(remote_socket) => {
            println!("Connected to {}:{}", ip, port);
            conn.write_all(&[0x00, 0x5A, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]])?;
            forward_traffic(conn, remote_socket);
        }
        Err(e) => {
            println!("Failed to connect to {}:{} - {}", ip, port, e);
            conn.write_all(&[0x00, 0x5B, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]])?;
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
        if let Err(e) = forward_data(client_socket, &mut remote_socket, &mut buffer) {
            eprintln!("Error forwarding data: {}", e);
            break;
        }

        if let Err(e) = forward_data(&mut remote_socket, client_socket, &mut buffer) {
            eprintln!("Error forwarding data: {}", e);
            break;
        }

        std::thread::sleep(Duration::from_millis(1));
    }
}

fn forward_data(
    source: &mut TcpStream,
    destination: &mut TcpStream,
    buffer: &mut [u8],
) -> io::Result<()> {
    match source.read(buffer) {
        Ok(bytes_read) if bytes_read > 0 => {
            destination.write_all(&buffer[..bytes_read])?;
        }
        Ok(_) => {
            println!("Connection closed.");
            return Err(io::Error::new(io::ErrorKind::Other, "Connection closed"));
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", PORT))?;
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

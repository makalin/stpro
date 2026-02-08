use crate::config::Config;
use crate::desync::DesyncEngine;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;

pub struct ProxyServer {
    config: Config,
    desync_engine: DesyncEngine,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        let desync_engine = DesyncEngine::new(config.desync.clone());
        Self {
            config,
            desync_engine,
        }
    }
    
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.listen))?;
        
        println!("[*] SOCKS5 Proxy listening on {}", self.config.listen);
        println!("[*] Configure your application to use Proxy: {}", self.config.listen);
        
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let desync_engine = self.desync_engine.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, client_addr, desync_engine).await {
                            eprintln!("Error handling client {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

async fn handle_client(
    mut client: TcpStream,
    client_addr: SocketAddr,
    desync_engine: DesyncEngine,
) -> Result<()> {
    eprintln!("\n[*] ===== New connection from: {} =====", client_addr);
    
    // Read first byte to detect protocol
    let mut first_byte = [0u8; 1];
    client.read_exact(&mut first_byte).await?;
    
    eprintln!("[*] First byte: {} (0x{:02X})", first_byte[0], first_byte[0]);
    
    // Check if this is HTTP CONNECT
    if first_byte[0] == b'C' {
        eprintln!("[*] Detected HTTP CONNECT request");
        return handle_http_connect(client, first_byte[0], desync_engine).await;
    }
    
    // SOCKS5 handshake
    if first_byte[0] != SOCKS5_VERSION {
        eprintln!("[!] Invalid SOCKS version: {} (expected {})", first_byte[0], SOCKS5_VERSION);
        anyhow::bail!("Invalid SOCKS version");
    }
    
    // Read number of methods
    let mut second_byte = [0u8; 1];
    client.read_exact(&mut second_byte).await?;
    let n_methods = second_byte[0] as usize;
    
    let mut methods = vec![0u8; n_methods];
    client.read_exact(&mut methods).await?;
    
    if !methods.contains(&SOCKS5_AUTH_NONE) {
        eprintln!("[!] Client does not support no authentication");
        anyhow::bail!("Client does not support no authentication");
    }
    
    eprintln!("[*] SOCKS5 handshake successful (no auth)");
    
    // Send auth response
    let auth_response = [SOCKS5_VERSION, SOCKS5_AUTH_NONE];
    client.write_all(&auth_response).await?;
    client.flush().await?;
    
    // Read connection request
    eprintln!("[*] Waiting for CONNECT request...");
    let mut request = vec![0u8; 4];
    client.read_exact(&mut request).await?;
    
    let ver = request[0];
    let cmd = request[1];
    let _rsv = request[2];
    let atyp = request[3];
    
    eprintln!("[*] Request header: VER={}, CMD={}, RSV={}, ATYP={}", ver, cmd, _rsv, atyp);
    
    if ver != SOCKS5_VERSION || cmd != SOCKS5_CMD_CONNECT {
        eprintln!("[!] Invalid request: ver={}, cmd={}", ver, cmd);
        anyhow::bail!("Invalid SOCKS5 request");
    }
    
    let target_addr = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            SocketAddr::from((addr, port))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut domain_len = [0u8; 1];
            client.read_exact(&mut domain_len).await?;
            let domain_len = domain_len[0] as usize;
            let mut domain = vec![0u8; domain_len];
            client.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            
            let domain_str = String::from_utf8(domain)
                .context("Invalid domain name")?;
            eprintln!("[*] Resolving SOCKS5 domain: {}:{}", domain_str, port);
            
            let mut addrs = tokio::net::lookup_host(format!("{}:{}", domain_str, port))
                .await
                .context("Failed to resolve domain")?;
            
            addrs.next()
                .context("No addresses found for domain")?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            SocketAddr::from((std::net::Ipv6Addr::from(addr), port))
        }
        _ => anyhow::bail!("Unsupported address type: {}", atyp),
    };
    
    eprintln!("[*] Connecting to: {}", target_addr);
    let target = TcpStream::connect(target_addr)
        .await
        .context("Failed to connect to target")?;
    
    target.set_nodelay(true).ok();
    
    println!("[*] Tunneling to: {}", target_addr);
    
    // Send SOCKS5 success response
    let response = vec![
        SOCKS5_VERSION,
        SOCKS5_REP_SUCCESS,
        0x00,
        SOCKS5_ATYP_IPV4,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    
    client.write_all(&response).await?;
    client.flush().await?;
    eprintln!("[*] SOCKS5 response sent, starting data forwarding");
    
    // Forward data with desync
    let (client_read, client_write) = split(client);
    let (target_read, target_write) = split(target);
    
    let client_to_target = tokio::spawn(async move {
        forward_with_desync(client_read, target_write, desync_engine).await
    });
    
    let target_to_client = tokio::spawn(async move {
        forward_normal(target_read, client_write).await
    });
    
    let (client_result, target_result) = tokio::join!(client_to_target, target_to_client);
    
    match client_result {
        Ok(Ok(())) => eprintln!("[*] Client->target forwarding completed"),
        Ok(Err(e)) => eprintln!("[!] Error forwarding client->target: {}", e),
        Err(e) => eprintln!("[!] Task error client->target: {}", e),
    }
    
    match target_result {
        Ok(Ok(())) => eprintln!("[*] Target->client forwarding completed"),
        Ok(Err(e)) => eprintln!("[!] Error forwarding target->client: {}", e),
        Err(e) => eprintln!("[!] Task error target->client: {}", e),
    }
    
    eprintln!("[*] Connection closed");
    Ok(())
}

async fn handle_http_connect(
    mut client: TcpStream,
    first_byte: u8,
    desync_engine: DesyncEngine,
) -> Result<()> {
    // Read the rest of the HTTP CONNECT request
    let mut buffer = vec![first_byte];
    let mut line_buf = vec![0u8; 1];
    
    // Read until we get the full request line
    loop {
        client.read_exact(&mut line_buf).await?;
        buffer.push(line_buf[0]);
        
        if buffer.len() >= 2 && buffer.ends_with(b"\r\n") {
            break;
        }
        
        if buffer.len() > 8192 {
            anyhow::bail!("HTTP CONNECT request too long");
        }
    }
    
    // Read remaining headers
    let mut header_buf = vec![0u8; 1];
    let mut last_four = vec![0u8; 4];
    
    loop {
        client.read_exact(&mut header_buf).await?;
        buffer.push(header_buf[0]);
        
        last_four.push(header_buf[0]);
        if last_four.len() > 4 {
            last_four.remove(0);
        }
        
        if last_four == b"\r\n\r\n" {
            break;
        }
        
        if buffer.len() > 8192 {
            anyhow::bail!("HTTP CONNECT headers too long");
        }
    }
    
    let request_str = String::from_utf8_lossy(&buffer);
    eprintln!("[*] HTTP CONNECT request:\n{}", request_str);
    
    // Parse target address
    let (host, port) = crate::packets::parse_http_connect(&buffer)
        .context("Failed to parse HTTP CONNECT target")?;
    
    eprintln!("[*] HTTP CONNECT target: {}:{}", host, port);
    
    let target_addr = format!("{}:{}", host, port);
    let mut addrs = tokio::net::lookup_host(&target_addr)
        .await
        .context("Failed to resolve HTTP CONNECT target")?;
    
    let target_addr = addrs.next()
        .context("No addresses found for HTTP CONNECT target")?;
    
    eprintln!("[*] Connecting to: {}", target_addr);
    let target = TcpStream::connect(target_addr)
        .await
        .context("Failed to connect to HTTP CONNECT target")?;
    
    target.set_nodelay(true).ok();
    
    println!("[*] Tunneling to: {}", target_addr);
    
    // Send HTTP 200 response
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(response).await?;
    client.flush().await?;
    
    eprintln!("[*] HTTP CONNECT response sent, starting data forwarding");
    
    // Forward data
    let (client_read, client_write) = split(client);
    let (target_read, target_write) = split(target);
    
    let client_to_target = tokio::spawn(async move {
        forward_with_desync(client_read, target_write, desync_engine).await
    });
    
    let target_to_client = tokio::spawn(async move {
        forward_normal(target_read, client_write).await
    });
    
    let (client_result, target_result) = tokio::join!(client_to_target, target_to_client);
    
    match client_result {
        Ok(Ok(())) => eprintln!("[*] Client->target forwarding completed"),
        Ok(Err(e)) => eprintln!("[!] Error forwarding client->target: {}", e),
        Err(e) => eprintln!("[!] Task error client->target: {}", e),
    }
    
    match target_result {
        Ok(Ok(())) => eprintln!("[*] Target->client forwarding completed"),
        Ok(Err(e)) => eprintln!("[!] Error forwarding target->client: {}", e),
        Err(e) => eprintln!("[!] Task error target->client: {}", e),
    }
    
    eprintln!("[*] Connection closed");
    Ok(())
}

async fn forward_with_desync<R, W>(
    mut reader: R,
    mut writer: W,
    desync_engine: DesyncEngine,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let mut buffer = vec![0u8; 8192];
    
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                eprintln!("[*] Connection reset");
                break;
            }
            Err(e) => return Err(e.into()),
        };
        
        // Apply desync techniques
        desync_engine.apply_desync(&mut writer, &buffer[..n]).await?;
    }
    
    Ok(())
}

async fn forward_normal<R, W>(
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let mut buffer = vec![0u8; 8192];
    
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                eprintln!("[*] Connection reset");
                break;
            }
            Err(e) => return Err(e.into()),
        };
        
        writer.write_all(&buffer[..n]).await?;
        writer.flush().await?;
    }
    
    Ok(())
}


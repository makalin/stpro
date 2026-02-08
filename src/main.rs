use anyhow::Result;
use clap::Parser;
use stpro::{Config, ProxyServer};

#[derive(Parser, Debug)]
#[command(name = "stpro")]
#[command(about = "A lightweight, high-performance SOCKS5 proxy server with DPI evasion")]
struct Args {
    /// Listening port (default: 1080)
    #[arg(short, long, default_value = "1080")]
    port: u16,
    
    /// Listening IP address (default: 127.0.0.1)
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,
    
    /// Enable split desync at position (can be specified multiple times)
    #[arg(short = 's', long)]
    split: Vec<String>,
    
    /// Enable disorder desync at position (can be specified multiple times)
    #[arg(short = 'd', long)]
    disorder: Vec<String>,
    
    /// Enable fake packet at position (can be specified multiple times)
    #[arg(short = 'f', long)]
    fake: Vec<String>,
    
    /// TTL for fake packets (default: 8)
    #[arg(short = 't', long)]
    ttl: Option<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Build configuration
    let mut config = Config::default();
    config.listen = format!("{}:{}", args.ip, args.port).parse()?;
    
    // Parse split configurations
    for split_str in &args.split {
        config.desync.split.push(parse_split_config(split_str)?);
    }
    
    // Parse disorder configurations
    for disorder_str in &args.disorder {
        config.desync.disorder.push(parse_split_config(disorder_str)?);
    }
    
    // Parse fake configurations
    for fake_str in &args.fake {
        config.desync.fake.push(stpro::FakeConfig {
            split: parse_split_config(fake_str)?,
            ttl: args.ttl,
            data: None,
        });
    }
    
    // Create and run proxy server
    let server = ProxyServer::new(config);
    server.run().await?;
    
    Ok(())
}

fn parse_split_config(s: &str) -> Result<stpro::SplitConfig> {
    // Simple parser for split configuration
    // Format: offset[+flags] or offset:repeats:skip[+flags]
    // Flags: s (SNI), h (host), e (end), m (middle)
    
    let mut offset_str = s;
    let mut flags = stpro::SplitFlags::default();
    let mut repeats = None;
    let mut skip = None;
    
    // Check for flags
    if let Some(plus_pos) = s.find('+') {
        offset_str = &s[..plus_pos];
        let flags_str = &s[plus_pos + 1..];
        
        for ch in flags_str.chars() {
            match ch {
                's' => flags.sni = true,
                'h' => flags.host = true,
                'e' => flags.end = true,
                'm' => flags.middle = true,
                _ => {}
            }
        }
    }
    
    // Check for repeats:skip format
    if let Some(colon_pos) = offset_str.find(':') {
        let parts: Vec<&str> = offset_str.split(':').collect();
        if parts.len() >= 2 {
            offset_str = parts[0];
            repeats = parts[1].parse().ok();
            if parts.len() >= 3 {
                skip = parts[2].parse().ok();
            }
        }
    }
    
    let offset = offset_str.parse()
        .map_err(|_| anyhow::anyhow!("Invalid offset: {}", offset_str))?;
    
    Ok(stpro::SplitConfig {
        offset,
        flags,
        repeats,
        skip,
    })
}

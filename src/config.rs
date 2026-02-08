use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub bind_addr: Option<SocketAddr>,
    pub max_connections: usize,
    pub buffer_size: usize,
    pub desync: DesyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncConfig {
    pub split: Vec<SplitConfig>,
    pub disorder: Vec<SplitConfig>,
    pub fake: Vec<FakeConfig>,
    pub tls_rec: Vec<SplitConfig>,
    pub ttl: Option<u8>,
    pub auto: Option<AutoConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitConfig {
    pub offset: i64,
    pub flags: SplitFlags,
    pub repeats: Option<usize>,
    pub skip: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SplitFlags {
    pub sni: bool,
    pub host: bool,
    pub end: bool,
    pub middle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeConfig {
    pub split: SplitConfig,
    pub ttl: Option<u8>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoConfig {
    pub detect: Vec<AutoDetect>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutoDetect {
    Torst,      // Timeout or reset
    Redirect,   // HTTP redirect
    SslErr,     // SSL error
    None,       // No detection
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().unwrap(),
            bind_addr: None,
            max_connections: 512,
            buffer_size: 16384,
            desync: DesyncConfig::default(),
        }
    }
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            split: vec![],
            disorder: vec![],
            fake: vec![],
            tls_rec: vec![],
            ttl: None,
            auto: None,
        }
    }
}


use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{debug, info, warn, error};

// SOCKS5 Protocol Constants
pub const SOCKS5_VERSION: u8 = 0x05;

// Authentication Methods
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_GSSAPI: u8 = 0x01;
pub const AUTH_PASSWORD: u8 = 0x02;
pub const AUTH_NO_ACCEPT: u8 = 0xFF;

// Commands
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOC: u8 = 0x03;

// Address Types
pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

// Reply Codes
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_SERVER_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACH: u8 = 0x03;
pub const REP_HOST_UNREACH: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub enum Socks5Error {
    Timeout,
    ConnectionFailed(String),
    AuthenticationFailed,
    InvalidAddress(String),
    ProxyError(String),
    Io(std::io::Error),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Error::Timeout => write!(f, "Connection timeout"),
            Socks5Error::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            Socks5Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Socks5Error::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            Socks5Error::ProxyError(s) => write!(f, "Proxy error: {}", s),
            Socks5Error::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for Socks5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Socks5Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Socks5Error {
    fn from(err: std::io::Error) -> Socks5Error {
        Socks5Error::Io(err)
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub require_auth: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout_seconds: u32,
    pub allowed_ips: Vec<String>,
    pub disallowed_ports: Vec<u16>,
    pub connection_timeout: Duration,
    pub max_connections: usize,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen_addr: String::from("127.0.0.1"),
            listen_port: 1080,
            require_auth: false,
            username: None,
            password: None,
            timeout_seconds: 30,
            allowed_ips: Vec::new(),
            disallowed_ports: Vec::new(),
            connection_timeout: Duration::from_secs(30),
            max_connections: 100,
        }
    }
}

#[derive(Clone)]
pub struct Socks5Client {
    proxy_addr: String,
    proxy_port: u16,
    username: Option<String>,
    password: Option<String>,
    timeout: Duration,
    connection_pool: Arc<Mutex<HashMap<String, Vec<TcpStream>>>>,
}

impl Socks5Client {
    pub fn new(proxy_addr: String, proxy_port: u16) -> Self {
        info!("[SOCKS5] Creating new client for proxy {}:{}", proxy_addr, proxy_port);
        Self {
            proxy_addr,
            proxy_port,
            username: None,
            password: None,
            timeout: Duration::from_secs(30),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        info!("[SOCKS5] Enabling authentication for user '{}'.", username);
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        info!("[SOCKS5] Setting timeout to {:?}.", timeout);
        self.timeout = timeout;
        self
    }

    async fn get_pooled_connection(&self, target: &str) -> Option<TcpStream> {
        debug!("[SOCKS5] Checking for pooled connection to {}", target);
        let mut pool = self.connection_pool.lock().await;
        if let Some(connections) = pool.get_mut(target) {
            if let Some(_) = connections.last() {
                debug!("[SOCKS5] Reusing pooled connection for {}", target);
            }
            connections.pop()
        } else {
            None
        }
    }

    #[allow(dead_code)] // Part of connection pooling - to be completed
    async fn store_connection(&self, target: String, conn: TcpStream) {
        debug!("[SOCKS5] Storing connection to pool for {}", target);
        let mut pool = self.connection_pool.lock().await;
        let connections = pool.entry(target).or_insert_with(Vec::new);
        if connections.len() < 10 { // Max 10 connections per target
            connections.push(conn);
        } else {
            debug!("[SOCKS5] Connection pool for target full, dropping connection.");
        }
    }

    pub async fn connect_to(&self, target_addr: String, target_port: u16) -> Result<TcpStream, Socks5Error> {
        let target_key = format!("{}:{}", target_addr, target_port);
        info!("[SOCKS5] Attempting to connect to {} via proxy {}:{}", target_key, self.proxy_addr, self.proxy_port);
        if let Some(conn) = self.get_pooled_connection(&target_key).await {
            info!("[SOCKS5] Using pooled connection for {}", target_key);
            return Ok(conn);
        }

        let proxy_addr = format!("{}:{}", self.proxy_addr, self.proxy_port);
        let addr = match proxy_addr.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                error!("[SOCKS5] Invalid proxy address: {}", e);
                return Err(Socks5Error::InvalidAddress(e.to_string()));
            }
        };
        let target = format!("{}:{}", target_addr, target_port);

        let stream = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => {
                info!("[SOCKS5] Connecting with authentication as user '{}'.", user);
                match tokio::time::timeout(
                    self.timeout,
                    Socks5Stream::connect_with_password(
                        addr,
                        target.clone(),
                        user,
                        pass,
                    )
                ).await {
                    Ok(Ok(s)) => {
                        info!("[SOCKS5] Authenticated SOCKS5 connection established to {}.", target);
                        s
                    },
                    Ok(Err(e)) => {
                        error!("[SOCKS5] SOCKS5 connection failed: {}", e);
                        return Err(Socks5Error::ConnectionFailed(e.to_string()));
                    },
                    Err(_) => {
                        error!("[SOCKS5] SOCKS5 connection to {} timed out.", target);
                        return Err(Socks5Error::Timeout);
                    }
                }
            },
            _ => {
                info!("[SOCKS5] Connecting without authentication.");
                match tokio::time::timeout(
                    self.timeout,
                    Socks5Stream::connect(
                        addr,
                        target.clone(),
                    )
                ).await {
                    Ok(Ok(s)) => {
                        info!("[SOCKS5] SOCKS5 connection established to {}.", target);
                        s
                    },
                    Ok(Err(e)) => {
                        error!("[SOCKS5] SOCKS5 connection failed: {}", e);
                        return Err(Socks5Error::ConnectionFailed(e.to_string()));
                    },
                    Err(_) => {
                        error!("[SOCKS5] SOCKS5 connection to {} timed out.", target);
                        return Err(Socks5Error::Timeout);
                    }
                }
            }
        };

        let tcp_stream = stream.into_inner();
        Ok(tcp_stream)
    }

    pub async fn connect_with_retries(&self, target_addr: String, target_port: u16, retries: u32) -> Result<TcpStream, Socks5Error> {
        let mut attempts = 0;
        let mut last_error = None;
        info!("[SOCKS5] Connecting to {}:{} with up to {} retries.", target_addr, target_port, retries);
        while attempts < retries {
            match self.connect_to(target_addr.clone(), target_port).await {
                Ok(stream) => {
                    info!("[SOCKS5] Connection to {}:{} succeeded on attempt {}.", target_addr, target_port, attempts + 1);
                    return Ok(stream);
                },
                Err(e) => {
                    warn!("[SOCKS5] Attempt {} failed: {}", attempts + 1, e);
                    last_error = Some(e);
                    attempts += 1;
                    if attempts < retries {
                        let delay = 1u64 << attempts.min(6); // Cap at 64s max
                        info!("[SOCKS5] Retrying in {} seconds...", delay);
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                }
            }
        }
        error!("[SOCKS5] All {} connection attempts failed.", retries);
        Err(last_error.unwrap_or(Socks5Error::ConnectionFailed("Max retries exceeded".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_connection() {
        let client = Socks5Client::new("127.0.0.1".to_string(), 1080)
            .with_timeout(Duration::from_secs(5));
        
        let result = client.connect_to("example.com".to_string(), 80).await;
        match result {
            Ok(_) => info!("Connection successful"),
            Err(e) => error!("Connection failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_socks5_auth_connection() {
        let client = Socks5Client::new("127.0.0.1".to_string(), 1080)
            .with_auth("user".to_string(), "pass".to_string())
            .with_timeout(Duration::from_secs(5));
        
        let result = client.connect_with_retries("example.com".to_string(), 80, 3).await;
        match result {
            Ok(_) => info!("Authenticated connection successful"),
            Err(e) => error!("Authenticated connection failed: {}", e),
        }
    }
}

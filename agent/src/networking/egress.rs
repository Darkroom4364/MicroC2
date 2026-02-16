use std::net::UdpSocket;

/// Returns the local IP address used to reach the given server.
/// Accepts either a bare IP/host or a full URL (e.g. "http://host:port").
/// Returns "Unknown" if it cannot be determined.
pub fn get_egress_ip(server_addr: &str) -> String {
    // Strip scheme if present
    let without_scheme = server_addr
        .strip_prefix("https://")
        .or_else(|| server_addr.strip_prefix("http://"))
        .unwrap_or(server_addr);

    // Strip port if present (e.g. "host:8080" -> "host")
    let host = without_scheme
        .split(':')
        .next()
        .unwrap_or(without_scheme);

    let server = format!("{}:80", host);
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect(&server).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                return local_addr.ip().to_string();
            }
        }
    }
    "Unknown".to_string()
}

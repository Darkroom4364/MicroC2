use std::net::UdpSocket;

/// Returns the local IP address used to reach the given server IP.
/// Returns "Unknown" if it cannot be determined.
pub fn get_egress_ip(server_ip: &str) -> String {
    let server = format!("{}:80", server_ip);
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect(&server).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                return local_addr.ip().to_string();
            }
        }
    }
    "Unknown".to_string()
}

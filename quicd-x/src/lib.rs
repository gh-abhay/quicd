use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use crossbeam_channel::{Sender, Receiver, bounded};

pub type StreamId = u64;

#[derive(Debug, Clone)]
pub enum StreamData {
    Data(Bytes),
    Fin,
}

pub struct RecvStream {
    pub id: StreamId,
    pub rx: Receiver<StreamData>,
    pub fc_tx: Sender<EgressCommand>,
    pub connection_id: Bytes,
}

// Manual Debug impl because Receiver doesn't implement Debug
impl std::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvStream")
            .field("id", &self.id)
            .finish()
    }
}

impl RecvStream {
    pub async fn read(&mut self) -> Option<Bytes> {
        // Use tokio blocking task to bridge sync channel to async
        let rx = self.rx.clone();
        match tokio::task::block_in_place(|| rx.recv().ok()) {
            Some(StreamData::Data(data)) => {
                let len = data.len() as u64;
                // Signal consumption to worker for flow control (non-blocking)
                let _ = self.fc_tx.try_send(EgressCommand::StreamConsumed { 
                    connection_id: self.connection_id.clone(),
                    stream_id: self.id, 
                    amount: len 
                });
                Some(data)
            },
            Some(StreamData::Fin) => None,
            None => None,
        }
    }
}

pub struct SendStream {
    pub id: StreamId,
    pub tx: Sender<StreamWriteCmd>,
}

impl std::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream")
            .field("id", &self.id)
            .finish()
    }
}

pub fn new_recv_stream(id: StreamId, rx: Receiver<StreamData>, fc_tx: Sender<EgressCommand>, connection_id: Bytes) -> RecvStream {
    RecvStream { id, rx, fc_tx, connection_id }
}

pub fn new_send_stream(id: StreamId, tx: Sender<StreamWriteCmd>) -> SendStream {
    SendStream { id, tx }
}

#[derive(Debug)]
pub enum AppEvent {
    NewStream { 
        stream_id: u64, 
        bidirectional: bool,
        recv_stream: RecvStream,
        send_stream: Option<SendStream>,
    },
    StreamData { stream_id: u64, data: Bytes, fin: bool },
    StreamFinished { stream_id: u64 },
    StreamClosed { stream_id: u64, error_code: u64, app_initiated: bool },
    ConnectionClosed,
}

#[derive(Debug)]
pub enum EgressCommand {
    WriteStream {
        connection_id: Bytes,
        cmd: StreamWriteCmd,
    },
    StreamConsumed {
        connection_id: Bytes,
        stream_id: u64,
        amount: u64,
    },
    CloseConnection {
        connection_id: Bytes,
        error_code: u64,
        reason: String,
    },
    OpenStream {
        connection_id: Bytes,
        bidirectional: bool,
        reply: Sender<Result<(u64, Option<Sender<StreamWriteCmd>>, Option<Receiver<StreamData>>), ConnectionError>>,
    },
}

#[derive(Debug)]
pub struct StreamWriteCmd {
    pub stream_id: u64,
    pub data: Bytes,
    pub fin: bool,
    pub reply: Sender<Result<usize, ConnectionError>>,
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Connection closed")]
    Closed,
    #[error("Channel closed")]
    ChannelClosed,
}

pub struct ConnectionHandle {
    pub connection_id: Bytes,
    pub ingress_rx: Receiver<AppEvent>,
    pub egress_tx: Sender<EgressCommand>,
}

impl ConnectionHandle {
    pub fn new(connection_id: Bytes, ingress_rx: Receiver<AppEvent>, egress_tx: Sender<EgressCommand>) -> Self {
        Self { connection_id, ingress_rx, egress_tx }
    }
    
    pub async fn recv_event(&mut self) -> Option<AppEvent> {
        // Bridge sync channel to async using block_in_place
        let rx = self.ingress_rx.clone();
        tokio::task::block_in_place(|| rx.recv().ok())
    }
    
    pub async fn send_command(&self, cmd: EgressCommand) -> Result<(), ConnectionError> {
        self.egress_tx.send(cmd).map_err(|_| ConnectionError::ChannelClosed)
    }

    /// Open a new bidirectional stream
    pub async fn open_bi_stream(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.send_command(EgressCommand::OpenStream { 
            connection_id: self.connection_id.clone(),
            bidirectional: true, 
            reply: tx 
        }).await?;
        
        // Wait for reply using block_in_place to bridge sync to async
        match tokio::task::block_in_place(|| rx.recv().ok()) {
            Some(Ok((id, Some(tx_cmd), Some(rx_data)))) => {
                Ok((
                    SendStream { id, tx: tx_cmd },
                    RecvStream { id, rx: rx_data, fc_tx: self.egress_tx.clone(), connection_id: self.connection_id.clone() }
                ))
            },
            Some(Err(e)) => Err(e),
            _ => Err(ConnectionError::ChannelClosed),
        }
    }
}

#[async_trait]
pub trait QuicApplication: Send + Sync {
    async fn on_connection(&self, conn: ConnectionHandle);
}

pub trait QuicAppFactory: Send + Sync {
    fn create(&self) -> Box<dyn QuicApplication>;
}

impl<F> QuicAppFactory for F
where
    F: Fn() -> Box<dyn QuicApplication> + Send + Sync,
{
    fn create(&self) -> Box<dyn QuicApplication> {
        self()
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct QuicTransportConfig {
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub recv_window: u64,
    pub stream_recv_window: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub disable_active_migration: bool,
    pub initial_rtt_ms: u64,
    pub enable_dgram: bool,
    pub max_dgram_size: u64,
    pub enable_pacing: bool,
    pub max_pacing_rate: u64,
}

impl QuicTransportConfig {
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

pub mod system_resources {
    pub struct SystemResources;
    impl SystemResources {
        pub fn query() -> Self { Self }
        pub fn optimal_worker_egress_capacity(&self) -> usize { 256 }
        pub fn optimal_connection_ingress_capacity(&self) -> usize { 256 }
        pub fn optimal_stream_channel_capacity(&self) -> usize { 256 }
        pub fn optimal_worker_threads(&self) -> usize { 1 }
        pub fn validate_system_limits(&self) -> Result<(), Vec<String>> { Ok(()) }
        pub fn optimal_buffers_per_worker(&self) -> usize { 1024 }
        pub fn optimal_netio_workers(&self) -> usize { 1 }
        pub fn optimal_io_uring_entries(&self) -> u32 { 1024 }
        pub fn optimal_udp_recv_buf(&self) -> usize { 1024 * 1024 }
        pub fn optimal_udp_send_buf(&self) -> usize { 1024 * 1024 }
    }
}

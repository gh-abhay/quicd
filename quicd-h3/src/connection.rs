use crate::error::{H3Error, Result};
use crate::frame::{H3Frame, FrameType};
use crate::stream::{StreamType, decode_stream_type};
use quicd_x::{ConnectionHandle, AppEvent, EgressCommand, RecvStream, SendStream, StreamWriteCmd, StreamId, StreamData, QuicApplication};
use quicd_qpack::{Encoder, Decoder};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use async_trait::async_trait;
use tokio_stream::{StreamMap, StreamExt};
use tokio_stream::wrappers::ReceiverStream;

pub struct Http3Connection {
    // QPACK
    encoder: Encoder,
    decoder: Decoder,
    
    // Streams
    control_stream_id: Option<StreamId>,
    qpack_enc_stream_id: Option<StreamId>,
    qpack_dec_stream_id: Option<StreamId>,
    
    // Peer Streams
    peer_control_stream_id: Option<StreamId>,
    peer_qpack_enc_stream_id: Option<StreamId>,
    peer_qpack_dec_stream_id: Option<StreamId>,
    
    // Pending reads for streams (buffering for frame decoding)
    pending_reads: HashMap<StreamId, BytesMut>,
    
    // Active SendStreams (to write responses)
    send_streams: HashMap<StreamId, SendStream>,
    
    // Stream Types (for uni streams)
    stream_types: HashMap<StreamId, StreamType>,
}

impl Http3Connection {
    pub fn new() -> Self {
        Self {
            encoder: Encoder::new(4096, 100),
            decoder: Decoder::new(4096, 100),
            control_stream_id: None,
            qpack_enc_stream_id: None,
            qpack_dec_stream_id: None,
            peer_control_stream_id: None,
            peer_qpack_enc_stream_id: None,
            peer_qpack_dec_stream_id: None,
            pending_reads: HashMap::new(),
            send_streams: HashMap::new(),
            stream_types: HashMap::new(),
        }
    }

    async fn initialize(&mut self, conn: &ConnectionHandle) -> Result<()> {
        // Open Control Stream
        let (mut tx, _) = self.open_uni_stream(conn).await?;
        self.control_stream_id = Some(tx.id);
        self.send_stream_type(&mut tx, StreamType::Control).await?;
        
        // Send SETTINGS
        let settings = vec![
            (0x06, 4096), // MAX_HEADER_LIST_SIZE
            (0x01, 4096), // QPACK_MAX_TABLE_CAPACITY
            (0x07, 100),  // QPACK_BLOCKED_STREAMS
        ];
        let frame = H3Frame::Settings(settings);
        self.send_frame(&mut tx, frame).await?;
        self.send_streams.insert(tx.id, tx);

        // Open QPACK Encoder Stream
        let (mut tx, _) = self.open_uni_stream(conn).await?;
        self.qpack_enc_stream_id = Some(tx.id);
        self.send_stream_type(&mut tx, StreamType::QpackEncoder).await?;
        self.send_streams.insert(tx.id, tx);

        // Open QPACK Decoder Stream
        let (mut tx, _) = self.open_uni_stream(conn).await?;
        self.qpack_dec_stream_id = Some(tx.id);
        self.send_stream_type(&mut tx, StreamType::QpackDecoder).await?;
        self.send_streams.insert(tx.id, tx);

        Ok(())
    }

    async fn open_uni_stream(&self, conn: &ConnectionHandle) -> Result<(SendStream, RecvStream)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        conn.send_command(EgressCommand::OpenStream { 
            connection_id: conn.connection_id.clone(),
            bidirectional: false, 
            reply: tx 
        }).await.map_err(|_| H3Error::InternalError)?;
        
        match rx.await {
            Ok(Ok((id, Some(tx_cmd), Some(rx_data)))) => {
                Ok((
                    quicd_x::new_send_stream(id, tx_cmd),
                    quicd_x::new_recv_stream(id, rx_data, conn.egress_tx.clone(), conn.connection_id.clone())
                ))
            },
            Ok(Err(e)) => Err(H3Error::Quic(anyhow::anyhow!("Connection Error: {:?}", e))),
            _ => Err(H3Error::InternalError),
        }
    }

    async fn send_stream_type(&self, stream: &mut SendStream, ty: StreamType) -> Result<()> {
        let mut buf = BytesMut::new();
        let val = ty as u64;
        if val <= 63 {
            buf.put_u8(val as u8);
        } else {
            buf.put_u8(val as u8); // Simplified
        }
        self.write_stream(stream, buf.freeze(), false).await
    }

    async fn send_frame(&self, stream: &mut SendStream, frame: H3Frame) -> Result<()> {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        self.write_stream(stream, buf.freeze(), false).await
    }

    async fn write_stream(&self, stream: &mut SendStream, data: Bytes, fin: bool) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        stream.tx.send(StreamWriteCmd {
            stream_id: stream.id,
            data,
            fin,
            reply: tx,
        }).await.map_err(|_| H3Error::InternalError)?;
        
        rx.await.map_err(|_| H3Error::InternalError)?
            .map_err(|e| H3Error::Quic(anyhow::anyhow!("Write Error: {:?}", e)))?;
        Ok(())
    }

    async fn handle_stream_data(&mut self, stream_id: StreamId, data: StreamData, conn: &ConnectionHandle) -> Result<()> {
        match data {
            StreamData::Data(bytes) => {
                {
                    let buf = self.pending_reads.entry(stream_id).or_insert_with(BytesMut::new);
                    buf.extend_from_slice(&bytes);
                }
                
                // If we don't know the type yet (and it's uni), try to decode it
                // ... (omitted for brevity, assuming we handle types elsewhere or implicitly)

                loop {
                    let frame = {
                        if let Some(buf) = self.pending_reads.get_mut(&stream_id) {
                            let mut temp_buf = buf.clone().freeze();
                            match H3Frame::decode(&mut temp_buf) {
                                Ok(Some(frame)) => {
                                    let consumed = buf.len() - temp_buf.len();
                                    buf.advance(consumed);
                                    Some(frame)
                                }
                                Ok(None) => None,
                                Err(e) => return Err(e),
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(frame) = frame {
                        self.handle_frame(stream_id, frame, conn).await?;
                    } else {
                        break;
                    }
                }
            }
            StreamData::Fin => {
                self.pending_reads.remove(&stream_id);
                self.send_streams.remove(&stream_id);
            }
        }
        Ok(())
    }

    async fn handle_frame(&mut self, stream_id: StreamId, frame: H3Frame, conn: &ConnectionHandle) -> Result<()> {
        match frame {
            H3Frame::Headers(payload) => {
                // Decode headers
                // For default handler: Respond 200 OK
                
                if let Some(mut send_stream) = self.send_streams.remove(&stream_id) {
                    let headers = vec![
                        (b":status".as_slice(), b"200".as_slice()),
                        (b"content-length".as_slice(), b"0".as_slice()),
                    ];
                    
                    let encoded = self.encoder.encode(stream_id, &headers).map_err(|_| H3Error::CompressionError)?;
                    let header_frame = H3Frame::Headers(encoded);
                    
                    self.send_frame(&mut send_stream, header_frame).await?;
                    self.write_stream(&mut send_stream, Bytes::new(), true).await?; // FIN
                }
            }
            H3Frame::Settings(settings) => {
                debug!("Received SETTINGS: {:?}", settings);
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl QuicApplication for Http3Connection {
    async fn on_connection(&self, mut conn: ConnectionHandle) {
        let mut h3_conn = Http3Connection::new();
        if let Err(e) = h3_conn.initialize(&conn).await {
            error!("H3 Initialization failed: {:?}", e);
            return;
        }
        
        let mut active_streams = StreamMap::new();
        
        loop {
            tokio::select! {
                Some(event) = conn.recv_event() => {
                    match event {
                        AppEvent::NewStream { stream_id, bidirectional, recv_stream, send_stream } => {
                            let stream = ReceiverStream::new(recv_stream.rx);
                            active_streams.insert(stream_id, stream);
                            
                            if bidirectional {
                                if let Some(ss) = send_stream {
                                    h3_conn.send_streams.insert(stream_id, ss);
                                }
                            } else {
                                // Unidirectional: We need to read type.
                                // We don't know type yet.
                            }
                        }
                        AppEvent::ConnectionClosed => {
                            info!("Connection closed");
                            break;
                        }
                        _ => {}
                    }
                }
                Some((stream_id, stream_data)) = active_streams.next() => {
                    if let Err(e) = h3_conn.handle_stream_data(stream_id, stream_data, &conn).await {
                        error!("Stream error on {}: {:?}", stream_id, e);
                    }
                }
            }
        }
    }
}

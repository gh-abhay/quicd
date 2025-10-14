//! QUIC I/O Abstraction
//!
//! Provides a `QuicStream` that implements `AsyncRead` and `AsyncWrite`,
//! acting as a bridge between the low-level `QuicEngine` and high-level
//! stream-based services (like gRPC and HTTP/3).

use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Commands sent from a `QuicStream` to the `ProtocolThread`.
#[derive(Debug)]
pub enum StreamCommand {
    /// Write data to the underlying QUIC stream.
    Write(Bytes),
    /// Shutdown the write-side of the stream.
    Shutdown,
    /// Close the stream entirely (sent on Drop).
    Close,
}

/// A handle to a single QUIC stream that behaves like a TCP socket.
///
/// Implements `AsyncRead` and `AsyncWrite` to be compatible with Tokio-based
/// networking libraries.
#[derive(Debug)]
pub struct QuicStream {
    /// Receives data from the `ProtocolThread`.
    pub(crate) read_rx: mpsc::Receiver<Bytes>,

    /// Sends commands back to the `ProtocolThread` for this specific stream.
    pub(crate) command_tx: mpsc::Sender<StreamCommand>,
}

impl QuicStream {
    /// Creates a new `QuicStream`.
    pub fn new(
        read_rx: mpsc::Receiver<Bytes>,
        command_tx: mpsc::Sender<StreamCommand>,
    ) -> Self {
        Self {
            read_rx,
            command_tx,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                // Data received. Copy it to the buffer.
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Stream has been closed by the remote.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // No data available right now.
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        match self.command_tx.try_send(StreamCommand::Write(data)) {
            Ok(_) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The command channel is full, which indicates backpressure.
                // We'll tell the caller to try again later.
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The receiving end (ProtocolThread) has been dropped.
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "QUIC connection closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Our writes are sent immediately to the ProtocolThread, which manages
        // the actual QUIC-level flushing. From the stream's perspective,
        // the flush is instantaneous.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.command_tx.try_send(StreamCommand::Shutdown) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "QUIC connection closed",
                )))
            }
        }
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        // Send a close command to ensure the ProtocolThread cleans up resources
        // for this stream. We ignore the result as the connection might already
        // be gone.
        let _ = self.command_tx.try_send(StreamCommand::Close);
    }
}

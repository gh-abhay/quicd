//! Implementation of h3::quic traits for quicd-x.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll};
use bytes::{Buf, Bytes};
use h3::quic::{self, BidiStream, Connection, OpenStreams, RecvStream, SendStream, StreamId as H3StreamId};
use pin_project_lite::pin_project;
use quicd_x::{AppEvent, ConnectionHandle, RecvStream as QdRecvStream, SendStream as QdSendStream, StreamData, StreamId};
use tokio::sync::Mutex;

/// Shared buffer for stream data.
#[derive(Default)]
struct StreamBuffer {
    data: VecDeque<Bytes>,
    fin_received: bool,
}

pin_project! {
    /// Wrapper for quicd-x RecvStream to implement h3::quic::RecvStream.
    pub struct H3RecvStream {
        #[pin]
        inner: QdRecvStream,
        stream_id: StreamId,
        buffer: Arc<Mutex<StreamBuffer>>,
    }
}

impl H3RecvStream {
    pub fn new(inner: QdRecvStream, stream_id: StreamId) -> Self {
        Self {
            inner,
            stream_id,
            buffer: Arc::new(Mutex::new(StreamBuffer::default())),
        }
    }

    /// Called by H3Connection when data is available.
    pub async fn buffer_data(&mut self) -> Result<(), quicd_x::ConnectionError> {
        let mut buf = self.buffer.try_lock().unwrap();
        if !buf.fin_received {
            match self.inner.read().await {
                Ok(Some(StreamData::Data(data))) => {
                    buf.data.push_back(data);
                }
                Ok(Some(StreamData::Fin)) => {
                    buf.fin_received = true;
                }
                Ok(None) => {
                    buf.fin_received = true;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl RecvStream for H3RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamErrorIncoming>> {
        let mut buf = match self.buffer.try_lock() {
            Ok(buf) => buf,
            Err(_) => return Poll::Pending, // Buffer is being written to
        };

        // If we have buffered data, return it
        if let Some(data) = buf.data.pop_front() {
            return Poll::Ready(Ok(Some(data)));
        }

        // If FIN received and no more data, return None
        if buf.fin_received {
            return Poll::Ready(Ok(None));
        }

        // No data available yet
        Poll::Pending
    }

    fn stop_sending(&mut self, _error_code: u64) {
        // TODO: implement reset
    }

    fn recv_id(&self) -> H3StreamId {
        H3StreamId::try_from(self.stream_id).unwrap()
    }
}

pin_project! {
    /// Wrapper for quicd-x SendStream to implement h3::quic::SendStream.
    pub struct H3SendStream {
        #[pin]
        inner: QdSendStream,
        stream_id: StreamId,
        pending_writes: VecDeque<Bytes>,
        fin_pending: bool,
    }
}

impl H3SendStream {
    pub fn new(inner: QdSendStream, stream_id: StreamId) -> Self {
        Self {
            inner,
            stream_id,
            pending_writes: VecDeque::new(),
            fin_pending: false,
        }
    }
}

impl SendStream<Bytes> for H3SendStream {
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), quic::StreamErrorIncoming> {
        let mut write_buf: h3::quic::WriteBuf<Bytes> = data.into();
        let data = write_buf.copy_to_bytes(write_buf.remaining());
        
        // Spawn a task to write the data asynchronously
        let inner = self.inner.clone();
        let fin = self.fin_pending && self.pending_writes.is_empty();
        if fin {
            self.fin_pending = false;
        }
        tokio::spawn(async move {
            let _ = inner.write(data, fin).await;
        });
        
        Ok(())
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        // Since we spawn tasks for writes, we consider the finish complete immediately
        // This is not ideal but works for basic HTTP/3 functionality
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, _reset_code: u64) {
        // TODO: implement reset
    }

    fn send_id(&self) -> H3StreamId {
        H3StreamId::try_from(self.stream_id).unwrap()
    }
}

/// Bidirectional stream wrapper.
pub struct H3BidiStream {
    recv: H3RecvStream,
    send: H3SendStream,
}

impl H3BidiStream {
    pub fn new(recv: QdRecvStream, send: QdSendStream, stream_id: StreamId) -> Self {
        Self {
            recv: H3RecvStream::new(recv, stream_id),
            send: H3SendStream::new(send, stream_id),
        }
    }
}

impl RecvStream for H3BidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, _error_code: u64) {
        self.recv.stop_sending(_error_code)
    }

    fn recv_id(&self) -> H3StreamId {
        self.recv.recv_id()
    }
}

impl SendStream<Bytes> for H3BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), quic::StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, _reset_code: u64) {
        self.send.reset(_reset_code)
    }

    fn send_id(&self) -> H3StreamId {
        self.send.send_id()
    }
}

impl BidiStream<Bytes> for H3BidiStream {
    type SendStream = H3SendStream;
    type RecvStream = H3RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

/// Shared state between H3Connection and H3OpenStreams.
#[derive(Default)]
struct H3ConnectionState {
    pending_recv: VecDeque<H3RecvStream>,
    pending_bidi: VecDeque<H3BidiStream>,
    pending_bidi_open: Option<u64>,
    pending_send_open: Option<u64>,
}

/// OpenStreams implementation.
pub struct H3OpenStreams {
    state: Arc<Mutex<H3ConnectionState>>,
    handle: ConnectionHandle,
}

impl H3OpenStreams {
    pub fn new(state: Arc<Mutex<H3ConnectionState>>, handle: ConnectionHandle) -> Self {
        Self { state, handle }
    }
}

impl OpenStreams<Bytes> for H3OpenStreams {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamErrorIncoming>> {
        let mut state = self.state.try_lock().unwrap();
        // If we have a pending stream ready, return it
        if let Some(stream) = state.pending_bidi.pop_front() {
            return Poll::Ready(Ok(stream));
        }

        // If we're not already opening a stream, start one
        if state.pending_bidi_open.is_none() {
            match self.handle.open_bi() {
                Ok(request_id) => {
                    state.pending_bidi_open = Some(request_id);
                }
                Err(_) => {
                    return Poll::Ready(Err(quic::StreamErrorIncoming::StreamTerminated { error_code: 0 }));
                }
            }
        }

        // Wait for the stream to be opened
        Poll::Pending
    }

    fn poll_open_send(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        // For HTTP/3, we might not need to open send-only streams
        Poll::Pending
    }

    fn close(&mut self, _code: h3::error::Code, _reason: &[u8]) {
        // TODO
    }
}

/// Connection implementation.
pub struct H3Connection {
    state: Arc<Mutex<H3ConnectionState>>,
    handle: ConnectionHandle,
}

impl H3Connection {
    pub fn new(handle: ConnectionHandle) -> Self {
        Self {
            state: Arc::new(Mutex::new(H3ConnectionState::default())),
            handle: handle.clone(),
        }
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        let mut state = self.state.try_lock().unwrap();
        match event {
            AppEvent::NewStream { stream_id, bidirectional, recv_stream, send_stream, .. } => {
                if bidirectional {
                    if let Some(send) = send_stream {
                        let bidi = H3BidiStream::new(recv_stream, send, stream_id);
                        state.pending_bidi.push_back(bidi);
                    }
                } else {
                    // Unidirectional stream from peer - only recv
                    let recv = H3RecvStream::new(recv_stream, stream_id);
                    state.pending_recv.push_back(recv);
                }
            }
            AppEvent::StreamOpened { request_id, result } => {
                if Some(request_id) == state.pending_bidi_open {
                    state.pending_bidi_open = None;
                    if let Ok((send, recv)) = result {
                        let stream_id = send.stream_id;
                        let bidi = H3BidiStream::new(recv, send, stream_id);
                        state.pending_bidi.push_back(bidi);
                    }
                }
            }
            AppEvent::UniStreamOpened { request_id, result } => {
                if Some(request_id) == state.pending_send_open {
                    state.pending_send_open = None;
                    if let Ok(send) = result {
                        let stream_id = send.stream_id;
                        let send_stream = H3SendStream::new(send, stream_id);
                        // For now, ignore - HTTP/3 might not need outgoing uni streams
                        drop(send_stream);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn opener(&self) -> H3OpenStreams {
        H3OpenStreams::new(self.state.clone(), self.handle.clone())
    }
}

impl OpenStreams<Bytes> for H3Connection {
    type BidiStream = H3BidiStream;
    type SendStream = H3SendStream;

    fn poll_open_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamErrorIncoming>> {
        let mut state = self.state.try_lock().unwrap();
        // If we have a pending stream ready, return it
        if let Some(stream) = state.pending_bidi.pop_front() {
            return Poll::Ready(Ok(stream));
        }

        // If we're not already opening a stream, start one
        if state.pending_bidi_open.is_none() {
            match self.handle.open_bi() {
                Ok(request_id) => {
                    state.pending_bidi_open = Some(request_id);
                }
                Err(_) => {
                    return Poll::Ready(Err(quic::StreamErrorIncoming::StreamTerminated { error_code: 0 }));
                }
            }
        }

        // Wait for the stream to be opened
        Poll::Pending
    }

    fn poll_open_send(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        // For HTTP/3, we might not need to open send-only streams
        Poll::Pending
    }

    fn close(&mut self, _code: h3::error::Code, _reason: &[u8]) {
        // TODO
    }
}

impl Connection<Bytes> for H3Connection {
    type RecvStream = H3RecvStream;
    type OpenStreams = H3OpenStreams;

    fn poll_accept_recv(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        let mut state = self.state.try_lock().unwrap();
        if let Some(stream) = state.pending_recv.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            Poll::Pending
        }
    }

    fn poll_accept_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::ConnectionErrorIncoming>> {
        let mut state = self.state.try_lock().unwrap();
        if let Some(stream) = state.pending_bidi.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            Poll::Pending
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        self.opener()
    }
}
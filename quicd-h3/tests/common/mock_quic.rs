//! Mock QUIC implementation for testing H3Session without real QUIC layer

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Mock QUIC connection handle for testing
#[derive(Clone)]
pub struct MockConnectionHandle {
    /// Stream data queues
    streams: Arc<Mutex<HashMap<u64, StreamData>>>,
    /// Events to emit
    events: Arc<Mutex<VecDeque<MockEvent>>>,
    /// Configuration
    config: MockConfig,
}

#[derive(Debug, Clone)]
pub struct MockConfig {
    pub max_bidi_streams: u64,
    pub max_uni_streams: u64,
    pub max_stream_data: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            max_bidi_streams: 100,
            max_uni_streams: 100,
            max_stream_data: 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct StreamData {
    stream_id: u64,
    is_bidirectional: bool,
    read_buffer: VecDeque<Bytes>,
    write_buffer: Vec<Bytes>,
    fin_received: bool,
    fin_sent: bool,
}

#[derive(Debug, Clone)]
pub enum MockEvent {
    StreamOpened { stream_id: u64, is_bidirectional: bool },
    StreamData { stream_id: u64, data: Bytes, fin: bool },
    StreamClosed { stream_id: u64 },
    ConnectionClosed { error_code: u64, reason: String },
}

impl MockConnectionHandle {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(VecDeque::new())),
            config: MockConfig::default(),
        }
    }

    pub fn with_config(config: MockConfig) -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(VecDeque::new())),
            config,
        }
    }

    /// Open a new stream (simulates peer opening a stream)
    pub fn open_stream(&self, stream_id: u64, is_bidirectional: bool) {
        let mut streams = self.streams.lock().unwrap();
        streams.insert(stream_id, StreamData {
            stream_id,
            is_bidirectional,
            read_buffer: VecDeque::new(),
            write_buffer: Vec::new(),
            fin_received: false,
            fin_sent: false,
        });

        let mut events = self.events.lock().unwrap();
        events.push_back(MockEvent::StreamOpened { stream_id, is_bidirectional });
    }

    /// Send data on a stream (simulates receiving data from peer)
    pub fn receive_data(&self, stream_id: u64, data: Bytes, fin: bool) {
        let mut streams = self.streams.lock().unwrap();
        if let Some(stream) = streams.get_mut(&stream_id) {
            stream.read_buffer.push_back(data.clone());
            if fin {
                stream.fin_received = true;
            }

            let mut events = self.events.lock().unwrap();
            events.push_back(MockEvent::StreamData { stream_id, data, fin });
        }
    }

    /// Get data written to a stream (simulates what was sent to peer)
    pub fn get_written_data(&self, stream_id: u64) -> Vec<Bytes> {
        let streams = self.streams.lock().unwrap();
        if let Some(stream) = streams.get(&stream_id) {
            stream.write_buffer.clone()
        } else {
            Vec::new()
        }
    }

    /// Check if FIN was sent on a stream
    pub fn was_fin_sent(&self, stream_id: u64) -> bool {
        let streams = self.streams.lock().unwrap();
        streams.get(&stream_id).map(|s| s.fin_sent).unwrap_or(false)
    }

    /// Get next pending event
    pub fn next_event(&self) -> Option<MockEvent> {
        let mut events = self.events.lock().unwrap();
        events.pop_front()
    }

    /// Check if stream exists
    pub fn has_stream(&self, stream_id: u64) -> bool {
        let streams = self.streams.lock().unwrap();
        streams.contains_key(&stream_id)
    }

    /// Close a stream
    pub fn close_stream(&self, stream_id: u64) {
        let mut streams = self.streams.lock().unwrap();
        streams.remove(&stream_id);

        let mut events = self.events.lock().unwrap();
        events.push_back(MockEvent::StreamClosed { stream_id });
    }
}

/// Mock send stream
pub struct MockSendStream {
    stream_id: u64,
    handle: MockConnectionHandle,
}

impl MockSendStream {
    pub fn new(stream_id: u64, handle: MockConnectionHandle) -> Self {
        Self { stream_id, handle }
    }

    pub async fn write(&mut self, data: Bytes, fin: bool) -> Result<(), String> {
        let mut streams = self.handle.streams.lock().unwrap();
        if let Some(stream) = streams.get_mut(&self.stream_id) {
            stream.write_buffer.push(data);
            if fin {
                stream.fin_sent = true;
            }
            Ok(())
        } else {
            Err("stream not found".to_string())
        }
    }

    pub async fn finish(&mut self) -> Result<(), String> {
        self.write(Bytes::new(), true).await
    }
}

/// Mock receive stream
pub struct MockRecvStream {
    stream_id: u64,
    handle: MockConnectionHandle,
}

impl MockRecvStream {
    pub fn new(stream_id: u64, handle: MockConnectionHandle) -> Self {
        Self { stream_id, handle }
    }

    pub async fn read(&mut self) -> Result<Option<Bytes>, String> {
        let mut streams = self.handle.streams.lock().unwrap();
        if let Some(stream) = streams.get_mut(&self.stream_id) {
            if let Some(data) = stream.read_buffer.pop_front() {
                Ok(Some(data))
            } else if stream.fin_received {
                Ok(None)
            } else {
                // Simulate blocking - in real test, would use channels
                Ok(None)
            }
        } else {
            Err("stream not found".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_connection_creation() {
        let handle = MockConnectionHandle::new();
        assert!(!handle.has_stream(0));
    }

    #[test]
    fn test_mock_stream_open() {
        let handle = MockConnectionHandle::new();
        handle.open_stream(4, true);
        assert!(handle.has_stream(4));

        let event = handle.next_event().unwrap();
        match event {
            MockEvent::StreamOpened { stream_id, is_bidirectional } => {
                assert_eq!(stream_id, 4);
                assert!(is_bidirectional);
            }
            _ => panic!("Expected StreamOpened event"),
        }
    }

    #[test]
    fn test_mock_stream_data() {
        let handle = MockConnectionHandle::new();
        handle.open_stream(4, true);
        handle.receive_data(4, Bytes::from("hello"), false);

        let written = handle.get_written_data(4);
        assert_eq!(written.len(), 0);

        let event = handle.next_event(); // Skip StreamOpened
        let event = handle.next_event().unwrap();
        match event {
            MockEvent::StreamData { stream_id, data, fin } => {
                assert_eq!(stream_id, 4);
                assert_eq!(data, Bytes::from("hello"));
                assert!(!fin);
            }
            _ => panic!("Expected StreamData event"),
        }
    }

    #[tokio::test]
    async fn test_mock_send_stream() {
        let handle = MockConnectionHandle::new();
        handle.open_stream(4, true);

        let mut send_stream = MockSendStream::new(4, handle.clone());
        send_stream.write(Bytes::from("test"), false).await.unwrap();

        let written = handle.get_written_data(4);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0], Bytes::from("test"));
    }

    #[tokio::test]
    async fn test_mock_recv_stream() {
        let handle = MockConnectionHandle::new();
        handle.open_stream(4, true);
        handle.receive_data(4, Bytes::from("data"), false);

        let mut recv_stream = MockRecvStream::new(4, handle.clone());
        let data = recv_stream.read().await.unwrap();
        assert_eq!(data, Some(Bytes::from("data")));
    }

    #[test]
    fn test_mock_stream_close() {
        let handle = MockConnectionHandle::new();
        handle.open_stream(4, true);
        assert!(handle.has_stream(4));

        handle.close_stream(4);
        assert!(!handle.has_stream(4));
    }
}

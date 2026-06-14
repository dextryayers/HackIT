use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

pub struct WebStream {
    clients: Arc<Mutex<HashMap<u64, Sender<String>>>>,
    next_id: Arc<Mutex<u64>>,
    sse_buffer: Arc<Mutex<Vec<String>>>,
}

impl WebStream {
    pub fn new() -> Self {
        WebStream {
            clients: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            sse_buffer: Arc::new(Mutex::new(Vec::with_capacity(1000))),
        }
    }

    pub fn subscribe(&self) -> (u64, Receiver<String>) {
        let (tx, rx) = channel();
        let mut clients = self.clients.lock().unwrap();
        let mut id = self.next_id.lock().unwrap();
        let client_id = *id;
        *id += 1;
        clients.insert(client_id, tx);
        (client_id, rx)
    }

    pub fn unsubscribe(&self, client_id: u64) {
        let mut clients = self.clients.lock().unwrap();
        clients.remove(&client_id);
    }

    pub fn serialize_result(result: &Value) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn broadcast(&self, event: &str, data: &Value) -> usize {
        let json_str = Self::serialize_result(data);
        let sse_message = if event.is_empty() {
            format!("data: {}\n\n", json_str)
        } else {
            format!("event: {}\ndata: {}\n\n", event, json_str)
        };

        let mut buffer = self.sse_buffer.lock().unwrap();
        buffer.push(sse_message.clone());
        if buffer.len() > 1000 {
            buffer.remove(0);
        }
        drop(buffer);

        let clients = self.clients.lock().unwrap();
        let mut delivered = 0usize;
        for (_, tx) in clients.iter() {
            if tx.send(sse_message.clone()).is_ok() {
                delivered += 1;
            }
        }
        delivered
    }

    pub fn stream_results(&self, results: &[Value]) -> Value {
        let mut delivered_count = 0usize;
        let mut event_index = 0u64;

        for result in results {
            let event = match result.get("type").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => "result",
            };
            let recipients = self.broadcast(event, result);
            delivered_count += recipients;
            event_index += 1;
        }

        let client_count = self.clients.lock().unwrap().len();
        json!({
            "events_streamed": event_index,
            "total_recipients": delivered_count,
            "active_clients": client_count,
            "status": "streaming_complete"
        })
    }

    pub fn stream_scan_result(&self, scan_data: &Value) -> Value {
        let recipients = self.broadcast("scan", scan_data);
        let client_count = self.clients.lock().unwrap().len();

        json!({
            "type": "scan_result_streamed",
            "recipients": recipients,
            "active_clients": client_count,
            "scan_data": scan_data,
            "timestamp": chrono_now()
        })
    }

    pub fn stream_attack_result(&self, attack_data: &Value) -> Value {
        let recipients = self.broadcast("attack", attack_data);
        json!({
            "type": "attack_result_streamed",
            "recipients": recipients,
            "data": attack_data,
            "timestamp": chrono_now()
        })
    }

    pub fn get_client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    pub fn get_recent_events(&self, count: usize) -> Value {
        let buffer = self.sse_buffer.lock().unwrap();
        let start = if buffer.len() > count {
            buffer.len() - count
        } else {
            0
        };
        let recent: Vec<&str> = buffer[start..].iter().map(|s| s.as_str()).collect();
        json!({
            "total_buffered": buffer.len(),
            "returned": recent.len(),
            "events": recent
        })
    }

    pub fn serialize_json(value: &Value) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    }

    pub fn serialize_json_pretty(value: &Value) -> String {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
    }
}

fn chrono_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// mod web_stream;

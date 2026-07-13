use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct ConnPool {
    inner: Arc<Mutex<PoolInner>>,
}

struct PoolEntry {
    stream: TcpStream,
    created: Instant,
    protocol: String,
    target: String,
    port: u16,
}

struct PoolInner {
    entries: Vec<PoolEntry>,
    max_size: usize,
    ttl: Duration,
}

impl ConnPool {
    pub fn new(max_size: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                entries: Vec::with_capacity(max_size),
                max_size,
                ttl: Duration::from_secs(ttl_secs),
            })),
        }
    }

    pub async fn acquire(&self, protocol: &str, target: &str, port: u16) -> Option<TcpStream> {
        let mut inner = self.inner.lock().await;
        let cutoff = Instant::now() - inner.ttl;
        inner.entries.retain(|e| e.created > cutoff);
        if let Some(pos) = inner.entries.iter().position(|e| {
            e.protocol == protocol && e.target == target && e.port == port
        }) {
            let entry = inner.entries.remove(pos);
            return Some(entry.stream);
        }
        None
    }

    pub async fn release(&self, protocol: &str, target: &str, port: u16, stream: TcpStream) {
        let mut inner = self.inner.lock().await;
        if inner.entries.len() < inner.max_size {
            inner.entries.push(PoolEntry {
                stream,
                created: Instant::now(),
                protocol: protocol.to_string(),
                target: target.to_string(),
                port,
            });
        }
    }

    pub async fn cleanup(&self) {
        let mut inner = self.inner.lock().await;
        let cutoff = Instant::now() - inner.ttl;
        inner.entries.retain(|e| e.created > cutoff);
    }
}

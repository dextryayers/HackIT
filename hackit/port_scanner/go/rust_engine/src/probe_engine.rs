use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use base64::Engine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDefinition {
    pub id: String,
    pub protocol: String,
    pub ports: Vec<u16>,
    pub payload_b64: Option<String>,
    pub payload_text: Option<String>,
    pub read_limit: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub matchers: Vec<ProbeMatcher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeMatcher {
    pub kind: String,
    pub pattern: String,
    pub weight: f64,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct LoadedProbes {
    pub probes: Vec<ProbeDefinition>,
    pub by_port: HashMap<u16, Vec<usize>>,
}

impl LoadedProbes {
    pub fn new(probes: Vec<ProbeDefinition>) -> Self {
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();
        for (idx, p) in probes.iter().enumerate() {
            for port in p.ports.iter().copied() {
                by_port.entry(port).or_default().push(idx);
            }
        }
        Self { probes, by_port }
    }

    pub fn probes_for_port(&self, port: u16) -> impl Iterator<Item = &ProbeDefinition> {
        let indices = self.by_port.get(&port);
        indices
            .into_iter()
            .flat_map(|v| v.iter())
            .filter_map(|&idx| self.probes.get(idx))
    }
}

pub fn decode_probe_payload(def: &ProbeDefinition) -> Vec<u8> {
    if let Some(text) = def.payload_text.as_ref() {
        return text.as_bytes().to_vec();
    }
    if let Some(b64) = def.payload_b64.as_ref() {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
            return bytes;
        }
    }
    Vec::new()
}

pub fn probe_timeout(def: &ProbeDefinition, fallback: Duration) -> Duration {
    def.timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(fallback)
}

use crate::probe_engine::{decode_probe_payload, probe_timeout, LoadedProbes, ProbeDefinition, ProbeMatcher};
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeObservation {
    pub probe_id: String,
    pub port: u16,
    pub protocol: String,
    pub success: bool,
    pub rtt_ms: u64,
    pub response_sample_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintHit {
    pub label: String,
    pub score: f64,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortProbeReport {
    pub port: u16,
    pub observations: Vec<ProbeObservation>,
    pub hits: Vec<FingerprintHit>,
}

pub async fn run_probes_for_port(
    host: &str,
    port: u16,
    probes: &LoadedProbes,
    fallback_timeout: Duration,
) -> PortProbeReport {
    let mut observations: Vec<ProbeObservation> = Vec::new();

    for probe in probes.probes_for_port(port) {
        let obs = run_single_probe(host, port, probe, fallback_timeout).await;
        observations.push(obs);
    }

    let hits = match_observations(probes, port, &observations);

    PortProbeReport {
        port,
        observations,
        hits,
    }
}

async fn run_single_probe(
    host: &str,
    port: u16,
    probe: &ProbeDefinition,
    fallback_timeout: Duration,
) -> ProbeObservation {
    let t0 = Instant::now();
    let payload = decode_probe_payload(probe);
    let max_read = probe.read_limit.unwrap_or(2048).min(16384);
    let to = probe_timeout(probe, fallback_timeout);

    let (success, sample) = match probe.protocol.to_lowercase().as_str() {
        "tcp" => tcp_probe(host, port, &payload, max_read, to).await,
        "udp" => udp_probe(host, port, &payload, max_read, to).await,
        _ => (false, Vec::new()),
    };

    let rtt = t0.elapsed().as_millis() as u64;

    ProbeObservation {
        probe_id: probe.id.clone(),
        port,
        protocol: probe.protocol.clone(),
        success,
        rtt_ms: rtt,
        response_sample_b64: base64::engine::general_purpose::STANDARD.encode(sample),
    }
}

async fn tcp_probe(
    host: &str,
    port: u16,
    payload: &[u8],
    max_read: usize,
    to: Duration,
) -> (bool, Vec<u8>) {
    let addr = format!("{}:{}", host, port);
    let stream = match timeout(to, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return (false, Vec::new()),
    };

    let mut stream = stream;

    if !payload.is_empty() {
        let _ = timeout(to, stream.write_all(payload)).await;
    }

    let mut buf = vec![0u8; max_read];
    let n = match timeout(to, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    buf.truncate(n);
    (true, buf)
}

async fn udp_probe(
    host: &str,
    port: u16,
    payload: &[u8],
    max_read: usize,
    to: Duration,
) -> (bool, Vec<u8>) {
    let socket = match timeout(to, UdpSocket::bind("0.0.0.0:0")).await {
        Ok(Ok(s)) => s,
        _ => return (false, Vec::new()),
    };

    let addr = format!("{}:{}", host, port);
    if timeout(to, socket.send_to(payload, &addr)).await.is_err() {
        return (false, Vec::new());
    }

    let mut buf = vec![0u8; max_read];
    let (n, _) = match timeout(to, socket.recv_from(&mut buf)).await {
        Ok(Ok(v)) => v,
        _ => return (true, Vec::new()),
    };

    buf.truncate(n);
    (true, buf)
}

fn match_observations(probes: &LoadedProbes, port: u16, obs: &[ProbeObservation]) -> Vec<FingerprintHit> {
    let mut scores: HashMap<String, (f64, HashMap<String, String>)> = HashMap::new();

    // Build response samples per observation
    let decoded_samples: Vec<(String, Vec<u8>)> = obs
        .iter()
        .map(|o| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&o.response_sample_b64)
                .unwrap_or_default();
            (o.probe_id.clone(), bytes)
        })
        .collect();

    for probe in probes.probes_for_port(port) {
        for matcher in probe.matchers.iter() {
            let matched = apply_matcher(matcher, &decoded_samples);
            if matched {
                let label = matcher
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("label").cloned())
                    .unwrap_or_else(|| format!("{}:{}", probe.id, matcher.kind));

                let entry = scores.entry(label).or_insert_with(|| (0.0, HashMap::new()));
                entry.0 += matcher.weight.max(0.0);

                if let Some(md) = matcher.metadata.as_ref() {
                    for (k, v) in md.iter() {
                        entry.1.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }
    }

    let max_score: f64 = scores
        .values()
        .map(|(s, _)| *s)
        .fold(0.0_f64, |a, b| a.max(b));

    let mut hits: Vec<FingerprintHit> = scores
        .into_iter()
        .map(|(label, (score, metadata))| {
            let confidence = if max_score <= 0.0 { 0.0 } else { score / max_score };
            FingerprintHit {
                label,
                score,
                confidence,
                metadata,
            }
        })
        .collect();

    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hits
}

fn apply_matcher(m: &ProbeMatcher, samples: &[(String, Vec<u8>)]) -> bool {
    let kind = m.kind.to_lowercase();

    if kind == "contains" {
        let needle = m.pattern.as_bytes();
        return samples.iter().any(|(_, s)| s.windows(needle.len()).any(|w| w == needle));
    }

    if kind == "regex" {
        let re = match Regex::new(&m.pattern) {
            Ok(r) => r,
            Err(_) => return false,
        };
        return samples.iter().any(|(_, s)| re.is_match(&String::from_utf8_lossy(s)));
    }

    if kind == "prefix" {
        let needle = m.pattern.as_bytes();
        return samples.iter().any(|(_, s)| s.starts_with(needle));
    }

    false
}

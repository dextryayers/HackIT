use rumqttc::{AsyncClient, MqttOptions, Transport, TlsConfiguration};
use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let mut mqtt_opts = MqttOptions::new("keystrike", target, port);
    mqtt_opts.set_credentials(user, pass);
    mqtt_opts.set_keep_alive(Duration::from_secs(to));

    if port == 8883 {
        let tls = TlsConfiguration::Simple {
            ca: Vec::new(),
            alpn: None,
            client_auth: None,
        };
        mqtt_opts.set_transport(Transport::Tls(tls));
    }

    let (client, mut eventloop) = AsyncClient::new(mqtt_opts, 10);
    let connect_result = tokio::time::timeout(Duration::from_secs(to), async {
        loop {
            match eventloop.poll().await {
                Ok(rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_))) => return Ok(true),
                Ok(_) => continue,
                Err(e) => return Err(format!("mqtt: {}", e)),
            }
        }
    })
    .await
    .map_err(|_| "timeout".to_string())?;

    let _ = client.disconnect().await;
    connect_result
}

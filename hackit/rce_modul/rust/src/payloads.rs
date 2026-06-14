pub struct RCEPayload<'a> {
    pub payload: String,
    pub technique: &'a str,
    pub os: &'a str,
    pub echo_str: Option<&'a str>,
    pub sleep_time: u32,
    pub category: &'a str,
    pub severity: &'a str,
}

pub fn echo_marker() -> String {
    "HACKIT_RCE_MARKER_1749".to_string()
}

pub fn echo_cmd() -> String {
    format!("echo {}", echo_marker())
}

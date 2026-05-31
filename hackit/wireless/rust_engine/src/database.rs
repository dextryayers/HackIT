pub fn connect_db(connection_string: &str) {
    println!("[RUST-DB] Connecting to async database (SQLx/Sqlite): {}", connection_string);
}

pub fn save_telemetry(data: &str) {
    println!("[RUST-DB] Serializing data with Serde and saving to DB: {}", data);
}

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DBDetails {
    pub db_type: String,
    pub version: String,
    pub confidence: i32,
    pub detection_method: String,
}

pub fn detect_database(headers: &HashMap<String, String>, body: &str) -> Option<DBDetails> {
    // 1. Error-based Detection (Passive)
    let error_patterns = [
        ("MySQL", r"(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.)"),
        ("PostgreSQL", r"(PostgreSQL.*ERROR|Warning.*\bpg_.*|valid PostgreSQL result|Npgsql\.)"),
        ("MongoDB", r"(MongoDB\.Driver|MongoError|db\.collection\.find)"),
        ("Redis", r"(Redis\.Client|RedisError|ERR unknown command.*'auth')"),
        ("MSSQL", r"(Driver.*SQL Server|OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server)"),
        ("Oracle", r"(ORA-\d{5}|Oracle error|Oracle.*Driver)"),
        ("SQLite", r"(SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException)"),
        ("Firebase", r"(firebaseio\.com|firebase-database\.js|x-firebase-auth-token)"),
        ("Cassandra", r"(org\.apache\.cassandra\.exceptions|Cassandra timeout during read query)"),
        ("Elasticsearch", r"(\bElasticsearch\b|cluster_name|nodes_stats|indices_stats)"),
    ];

    for (db_name, pattern) in error_patterns.iter() {
        if body.contains(db_name) || regex::Regex::new(pattern).map_or(false, |re| re.is_match(body)) {
            return Some(DBDetails {
                db_type: db_name.to_string(),
                version: "Unknown".to_string(),
                confidence: 80,
                detection_method: "Error Pattern".to_string(),
            });
        }
    }

    // 2. Header-based Detection
    if headers.contains_key("x-mongodb-server") {
        return Some(DBDetails {
            db_type: "MongoDB".to_string(),
            version: headers.get("x-mongodb-server").cloned().unwrap_or_default(),
            confidence: 95,
            detection_method: "Specific Header".to_string(),
        });
    }

    // 3. Technology Fingerprint association (e.g. WP usually MySQL)
    if body.contains("wp-content") {
        return Some(DBDetails {
            db_type: "MySQL".to_string(),
            version: "Unknown".to_string(),
            confidence: 60,
            detection_method: "Platform Association (WordPress)".to_string(),
        });
    }

    None
}

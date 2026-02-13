use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CloudAudit {
    pub provider: String,
    pub exposed_metadata: bool,
    pub security_score: u8,
}

pub fn audit_cloud_infra(headers: &std::collections::HashMap<String, String>) -> CloudAudit {
    let mut audit = CloudAudit::default();
    audit.security_score = 100;

    // 1. AWS Detection
    if headers.contains_key("x-amz-request-id") || headers.contains_key("x-amz-id-2") {
        audit.provider = "Amazon Web Services (AWS)".to_string();
    }
    
    // 2. Google Cloud Detection
    if headers.contains_key("x-goog-generation") || headers.contains_key("x-goog-metageneration") {
        audit.provider = "Google Cloud Platform (GCP)".to_string();
    }

    // 3. Azure Detection
    if headers.contains_key("x-ms-request-id") {
        audit.provider = "Microsoft Azure".to_string();
    }

    audit
}

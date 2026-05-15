pub struct DNSSecurityReport {
    pub spf_status: String,
    pub dmarc_status: String,
    pub caa_status: String,
    pub recommendations: Vec<String>,
}

pub fn analyze_dns_security(txt_records: &Vec<String>) -> DNSSecurityReport {
    let mut spf_status = "Missing".to_string();
    let mut dmarc_status = "Missing".to_string();
    let mut caa_status = "Unknown".to_string();
    let mut recommendations = Vec::new();

    for record in txt_records {
        if record.contains("v=spf1") {
            spf_status = "Found".to_string();
            if record.contains("+all") {
                recommendations.push("SPF: Dangerous '+all' detected (Permissive)".to_string());
            }
        }
        if record.contains("v=DMARC1") {
            dmarc_status = "Found".to_string();
            if record.contains("p=none") {
                recommendations.push("DMARC: Policy set to 'none' (Monitoring only)".to_string());
            }
        }
    }

    if spf_status == "Missing" {
        recommendations.push("Security: SPF record missing (Email Spoofing Risk)".to_string());
    }

    DNSSecurityReport {
        spf_status,
        dmarc_status,
        caa_status,
        recommendations,
    }
}

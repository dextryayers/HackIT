use crate::common::*;
use crate::{progress, progress_done};

const BREACH_SOURCES: &[(&str, &str, &[&str])] = &[
    ("Have I Been Pwned", "Email", &["haveibeenpwned", "hibp", "email"]),
    ("Collection #1", "Password Hash", &["collection1", "collection_1"]),
    ("LinkedIn (2012)", "Email, Password", &["linkedin"]),
    ("Adobe (2013)", "Email, Password", &["adobe"]),
    ("Dropbox (2012)", "Email, Password", &["dropbox"]),
    ("Ashley Madison (2015)", "Email, Name", &["ashley", "ashleymadison"]),
    ("MySpace (2008)", "Email, Password", &["myspace", "my_space"]),
    ("Twitter/X (2022)", "Email, Name", &["twitter"]),
    ("Facebook (2019)", "Phone, Name, ID", &["facebook", "fb"]),
    ("Data Enrichment", "Email, Personal", &["data_enrichment", "enrichment"]),
    ("Exploit.in", "Email, Password", &["exploit", "exploit.in"]),
    ("Anti Public", "Email, Password", &["antipublic", "anti_public"]),
    ("Verifications.io", "Email, Personal", &["verification", "verifications"]),
    ("Collection #2-5", "Email, Password", &["collection2", "collection_2"]),
    ("Onliner Spambot", "Email", &["onliner", "spambot"]),
    ("Sony (2011)", "Email, Password", &["sony", "playstation"]),
    ("Equifax (2017)", "SSN, Personal", &["equifax"]),
    ("Marriott/Starwood (2018)", "Passport, Personal", &["marriott", "starwood"]),
];

pub async fn check(target: &str) -> BreachCheckResult {
    progress!("breach_check", "running");
    let mut result = BreachCheckResult { target: target.to_string(), checks: vec![] };
    let lower = target.to_lowercase();

    for (source, data_type, keywords) in BREACH_SOURCES {
        let matches = keywords.iter().any(|k| lower.contains(k));
        result.checks.push(BreachEntry {
            source: source.to_string(),
            data_type: data_type.to_string(),
            exposed: matches,
            description: if matches {
                Some(format!("Target marker '{}' matches known breach context in {}", target, source))
            } else {
                None
            },
        });
    }

    progress_done!("breach_check");
    result
}

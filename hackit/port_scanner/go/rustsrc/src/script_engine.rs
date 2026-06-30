use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScriptContext {
    pub target: String,
    pub port: u16,
    pub banner: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptResult {
    pub findings: Vec<String>,
    pub risk_score: f64,
    pub tags: Vec<String>,
}

pub trait Script: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &ScriptContext) -> ScriptResult;
}

pub struct HttpTitleGrabber;

impl Script for HttpTitleGrabber {
    fn name(&self) -> &'static str {
        "http-title-grabber"
    }

    fn run(&self, ctx: &ScriptContext) -> ScriptResult {
        let mut findings = Vec::new();
        let mut tags = Vec::new();
        if let Ok(re) = Regex::new(r"(?i)<title>([^<]+)</title>") {
            if let Some(caps) = re.captures(&ctx.banner) {
                if let Some(title) = caps.get(1) {
                    let title_str = title.as_str().trim().to_string();
                    if !title_str.is_empty() {
                        findings.push(format!("Title: {}", title_str));
                        tags.push("title-found".to_string());
                    }
                }
            }
        }
        let risk_score = if findings.is_empty() { 0.0 } else { 1.0 };
        ScriptResult {
            findings,
            risk_score,
            tags,
        }
    }
}

pub struct BannerVersionCheck;

impl Script for BannerVersionCheck {
    fn name(&self) -> &'static str {
        "banner-version-check"
    }

    fn run(&self, ctx: &ScriptContext) -> ScriptResult {
        let mut findings = Vec::new();
        let mut tags = Vec::new();
        let patterns = [
            (r"(\d+\.\d+\.\d+)", "generic-semver"),
            (r"(\d+\.\d+)", "generic-two-part"),
            (r"OpenSSH[_-](\d+[\.\d]+)", "openssh"),
            (r"Apache/(\d+[\.\d]+)", "apache"),
            (r"nginx/(\d+[\.\d]+)", "nginx"),
            (r"PHP[ /](\d+[\.\d]+)", "php"),
            (r"MySQL[ /](\d+[\.\d]+)", "mysql"),
            (r"PostgreSQL[ /](\d+[\.\d]+)", "postgresql"),
        ];
        for (pattern, tag) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(&ctx.banner) {
                    if let Some(ver) = caps.get(1) {
                        let version = ver.as_str().to_string();
                        findings.push(format!("{} version: {}", tag, version));
                        tags.push(tag.to_string());
                    }
                }
            }
        }
        let risk_score = if tags.is_empty() { 0.0 } else { 2.0 };
        ScriptResult {
            findings,
            risk_score,
            tags,
        }
    }
}

pub struct ScriptEngine {
    scripts: Vec<Box<dyn Script>>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = ScriptEngine {
            scripts: Vec::new(),
        };
        engine.register(Box::new(HttpTitleGrabber));
        engine.register(Box::new(BannerVersionCheck));
        engine
    }

    pub fn register(&mut self, script: Box<dyn Script>) {
        self.scripts.push(script);
    }

    pub fn run_all(&self, ctx: &ScriptContext) -> Vec<(String, ScriptResult)> {
        self.scripts
            .iter()
            .map(|s| (s.name().to_string(), s.run(ctx)))
            .collect()
    }
}

pub struct Logic;

impl Logic {
    pub fn is_tactical(&self, url: &str) -> bool {
        // Advanced heuristic: look for high-value parameters like id, file, path, cmd
        let high_value = ["id=", "file=", "path=", "cmd=", "url=", "redirect=", "user=", "admin="];
        high_value.iter().any(|&p| url.contains(p))
    }

    pub fn sanitize_url(&self, url: &str) -> String {
        // Ensure URL is clean for the Go Shaper
        url.trim().to_string()
    }
}

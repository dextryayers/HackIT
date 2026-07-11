use crate::common::*;
use crate::{progress, progress_done};

const API_PATHS: &[&str] = &[
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/graphql", "/graphiql", "/playground",
    "/rest", "/rest/v1", "/rest/v2",
    "/swagger.json", "/swagger.yaml", "/swagger-resources",
    "/api-docs", "/api/swagger", "/api/docs",
    "/openapi.json", "/openapi.yaml",
    "/docs", "/docs/api",
    "/health", "/healthz", "/status", "/readyz",
    "/metrics", "/prometheus",
    "/ping", "/pong",
    "/auth", "/login", "/register", "/logout",
    "/token", "/oauth", "/oauth2", "/oauth/token",
    "/callback", "/webhook", "/webhooks",
    "/notification", "/notifications",
    "/push", "/push-notifications",
    "/socket", "/ws", "/wss", "/sse", "/events",
    "/public/api", "/internal/api",
    "/admin/api", "/admin/rest",
    "/v1", "/v2", "/v3",
    "/actuator", "/actuator/health", "/actuator/info",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
];

pub async fn discover(url: &str) -> ApiDiscoveryResult {
    progress!("api_discovery", "running");
    let mut result = ApiDiscoveryResult { url: url.to_string(), endpoints: vec![] };
    let base = normalize_url(url).trim_end_matches('/').to_string();

    if let Some(client) = build_client(10) {
        for path in API_PATHS {
            let full_url = format!("{}{}", base, path);
            match client.get(&full_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 201 || status == 401 || status == 403 {
                        result.endpoints.push(ApiEndpoint {
                            path: path.to_string(),
                            method: "GET".into(),
                            status,
                        });
                    }
                }
                Err(_) => {}
            }
        }
    }

    progress_done!("api_discovery");
    result
}

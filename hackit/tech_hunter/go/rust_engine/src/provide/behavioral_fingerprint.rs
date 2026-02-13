use std::collections::HashMap;

pub fn detect_expert_behavior(body: &str, headers: &HashMap<String, String>) -> Vec<String> {
    let mut techs = Vec::new();

    // 1. GraphQL Detection
    if body.contains("__schema") || body.contains("graphql") || body.contains("extensions") && body.contains("errors") {
        techs.push("GraphQL API Engine".to_string());
    }

    // 2. Microservices / Service Mesh Detection
    if headers.contains_key("x-envoy-upstream-service-time") || headers.contains_key("x-istio-attributes") {
        techs.push("Envoy/Istio Service Mesh".to_string());
    }

    // 3. Advanced Frontend Frameworks (Behavioral)
    if body.contains("data-v-") { techs.push("Vue.js (Scoped CSS)".to_string()); }
    if body.contains("_ngcontent-") { techs.push("Angular (Emulated Encapsulation)".to_string()); }
    
    // 4. Expert Server Side Tech
    if headers.contains_key("x-powered-by") {
        let val = headers.get("x-powered-by").unwrap().to_lowercase();
        if val.contains("express") { techs.push("Node.js (Express)".to_string()); }
        if val.contains("flask") || val.contains("werkzeug") { techs.push("Python (Flask)".to_string()); }
    }

    techs
}

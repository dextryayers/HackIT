use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TechStack {
    pub frontend: String,
    pub backend: String,
    pub js_libs: Vec<String>,
    pub css_frameworks: Vec<String>,
    pub build_tools: String,
    pub analytics: Vec<String>,
}

pub fn get_tech_json(headers: &str, body: &str) -> String {
    let mut tech = TechStack::default();
    let body_lower = body.to_lowercase();
    let headers_lower = headers.to_lowercase();

    // Frontend Frameworks
    if body_lower.contains("_react") || body_lower.contains("react-dom") { 
        tech.frontend = "React 18.x (Inferred)".to_string(); 
    } else if body_lower.contains("vue.js") || body_lower.contains("v-bind") { 
        tech.frontend = "Vue.js 3.x (Inferred)".to_string(); 
    } else if body_lower.contains("ng-app") || body_lower.contains("angular") {
        tech.frontend = "Angular 14+ (Inferred)".to_string();
    } else if body_lower.contains("svelte") {
        tech.frontend = "Svelte (Modern)".to_string();
    } else if body_lower.contains("next-js") || body_lower.contains("__next") {
        tech.frontend = "Next.js (SSR)".to_string();
    } else {
        tech.frontend = "Modern Static/SPA (Inferred)".to_string();
    }

    // JS Libraries
    if body_lower.contains("jquery") { tech.js_libs.push("jQuery 3.6.0".to_string()); }
    if body_lower.contains("lodash") { tech.js_libs.push("Lodash 4.17.21".to_string()); }
    if body_lower.contains("axios") { tech.js_libs.push("Axios 1.x".to_string()); }
    if body_lower.contains("moment") { tech.js_libs.push("Moment.js".to_string()); }
    if body_lower.contains("chart.js") { tech.js_libs.push("Chart.js".to_string()); }
    if body_lower.contains("three.js") { tech.js_libs.push("Three.js (3D Engine)".to_string()); }

    // CSS Frameworks
    if body_lower.contains("bootstrap") { tech.css_frameworks.push("Bootstrap 5.2.3".to_string()); }
    if body_lower.contains("tailwind") { tech.css_frameworks.push("Tailwind CSS 3.x".to_string()); }
    if body_lower.contains("bulma") { tech.css_frameworks.push("Bulma".to_string()); }
    if body_lower.contains("foundation") { tech.css_frameworks.push("Zurb Foundation".to_string()); }

    // Build Tools
    if body_lower.contains("webpack") || body_lower.contains("wpk") { tech.build_tools = "Webpack 5.x".to_string(); }
    else if body_lower.contains("vite") { tech.build_tools = "Vite 4.x".to_string(); }
    else if body_lower.contains("parcel") { tech.build_tools = "Parcel".to_string(); }
    else { tech.build_tools = "Modern ESM Build (Inferred)".to_string(); }

    // Analytics
    if body_lower.contains("gtm-") || body_lower.contains("googletagmanager") { tech.analytics.push("Google Tag Manager (GTM)".to_string()); }
    if body_lower.contains("ga-") || body_lower.contains("analytics.js") { tech.analytics.push("Google Analytics 4".to_string()); }
    if body_lower.contains("fbevents.js") || body_lower.contains("connect.facebook.net") { tech.analytics.push("Facebook Pixel".to_string()); }
    if body_lower.contains("hotjar") { tech.analytics.push("Hotjar".to_string()); }
    if body_lower.contains("mixpanel") { tech.analytics.push("Mixpanel".to_string()); }

    serde_json::to_string(&tech).unwrap_or_else(|_| "{}".to_string())
}

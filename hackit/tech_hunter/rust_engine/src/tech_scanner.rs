use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TechStack {
    pub frontend: Vec<String>,
    pub backend: Vec<String>,
    pub js_libs: Vec<String>,
    pub css_frameworks: Vec<String>,
    pub build_tools: Vec<String>,
    pub analytics: Vec<String>,
    pub hosting: Vec<String>,
    pub databases: Vec<String>,
    pub cms: Vec<String>,
    pub feature_flags: Vec<String>,
    pub languages: Vec<String>,
}

struct Detection {
    name: &'static str,
    category: &'static str,
    patterns: &'static [&'static str],
    version_hint: Option<&'static str>,
}

const DETECTIONS: &[Detection] = &[
    // Frontend Frameworks
    Detection { name: "React", category: "frontend",     patterns: &["react", "react-dom", "react.", "createElement", "ReactDOM", "__REACT_DEVTOOLS"], version_hint: Some("18.x (inferred)") },
    Detection { name: "Vue.js", category: "frontend",     patterns: &["vue.js", "vue", "v-bind", "v-model", "v-if", "v-for", "v-on:", "vue-router"], version_hint: Some("3.x (inferred)") },
    Detection { name: "Angular", category: "frontend",     patterns: &["ng-app", "ng-app", "angular", "ng-", "_ngcontent", "NgModule"], version_hint: Some("15+ (inferred)") },
    Detection { name: "Svelte", category: "frontend",     patterns: &["svelte", "__svelte"], version_hint: Some("3.x (inferred)") },
    Detection { name: "Next.js", category: "frontend",     patterns: &["next-js", "next.js", "__next", "__NEXT_DATA__"], version_hint: Some("SSR mode") },
    Detection { name: "Nuxt.js", category: "frontend",     patterns: &["_nuxt", "nuxt"], version_hint: Some("3.x (inferred)") },
    Detection { name: "Gatsby", category: "frontend",     patterns: &["gatsby"], version_hint: Some("Static site generator") },
    Detection { name: "Preact", category: "frontend",     patterns: &["preact"], version_hint: Some("PReact") },
    Detection { name: "Ember.js", category: "frontend",     patterns: &["ember", "Ember"], version_hint: Some("Classic framework") },
    Detection { name: "Alpine.js", category: "frontend",     patterns: &["alpinejs", "x-data", "x-init", "x-show", "x-bind"], version_hint: Some("3.x") },
    Detection { name: "Stimulus", category: "frontend",     patterns: &["stimulus", "data-controller", "data-action"], version_hint: Some("Hotwired") },
    Detection { name: "LitElement", category: "frontend",     patterns: &["lit-element", "lit-html", "@lit"], version_hint: Some("Web Components") },
    Detection { name: "HTMX", category: "frontend",     patterns: &["htmx", "hx-get", "hx-post", "hx-target", "hx-swap"], version_hint: Some("1.x") },
    Detection { name: "Mithril", category: "frontend",     patterns: &["mithril"], version_hint: Some("2.x") },

    // Backend hints from headers
    Detection { name: "PHP", category: "backend",     patterns: &["x-powered-by: php", "php/", "php"], version_hint: None },
    Detection { name: "Python", category: "backend",     patterns: &["x-powered-by: python", "python/", "wsgi", "asgi"], version_hint: None },
    Detection { name: "Ruby", category: "backend",     patterns: &["x-powered-by: ruby", "rack", "phusion", "passenger"], version_hint: None },
    Detection { name: "Java", category: "backend",     patterns: &["x-powered-by: java", "java/", "jakarta", "tomcat", "jboss", "jetty"], version_hint: None },
    Detection { name: "Node.js", category: "backend",     patterns: &["node", "node.js", "x-powered-by: express"], version_hint: None },
    Detection { name: "ASP.NET", category: "backend",     patterns: &["x-aspnet", "asp.net", "asp.net_sessionid", "iis"], version_hint: Some("C# / .NET") },
    Detection { name: "Go", category: "backend",     patterns: &["go", "golang"], version_hint: None },

    // JS Libraries
    Detection { name: "jQuery", category: "js_libs",     patterns: &["jquery", "jquery.js", "jquery.min.js", "$.fn"], version_hint: Some("3.x (inferred)") },
    Detection { name: "Lodash", category: "js_libs",     patterns: &["lodash", "_.each", "_.map"], version_hint: Some("4.x (inferred)") },
    Detection { name: "Axios", category: "js_libs",     patterns: &["axios"], version_hint: Some("1.x") },
    Detection { name: "Moment.js", category: "js_libs",     patterns: &["moment", "moment.js"], version_hint: Some("2.x (legacy)") },
    Detection { name: "Day.js", category: "js_libs",     patterns: &["dayjs", "day.js"], version_hint: Some("1.x (modern)") },
    Detection { name: "date-fns", category: "js_libs",     patterns: &["date-fns"], version_hint: Some("2.x (modern)") },
    Detection { name: "Chart.js", category: "js_libs",     patterns: &["chart.js", "chart.min.js"], version_hint: Some("4.x") },
    Detection { name: "D3.js", category: "js_libs",     patterns: &["d3.js", "d3.min", "d3."], version_hint: Some("7.x") },
    Detection { name: "Three.js", category: "js_libs",     patterns: &["three.js", "three.min", "three."], version_hint: Some("r150+") },
    Detection { name: "GSAP", category: "js_libs",     patterns: &["gsap", "tweenmax", "tweenlite"], version_hint: Some("3.x") },
    Detection { name: "Swiper", category: "js_libs",     patterns: &["swiper"], version_hint: Some("10.x") },
    Detection { name: "Anime.js", category: "js_libs",     patterns: &["anime.js", "anime.min"], version_hint: Some("3.x") },
    Detection { name: "Bootstrap JS", category: "js_libs",     patterns: &["bootstrap.js", "bootstrap.min.js", "bootstrap.bundle"], version_hint: Some("5.x") },
    Detection { name: "Socket.IO", category: "js_libs",     patterns: &["socket.io", "socket.io.js"], version_hint: Some("4.x") },
    Detection { name: "Prism.js", category: "js_libs",     patterns: &["prism.js", "prism"], version_hint: Some("Syntax highlighter") },
    Detection { name: "Highlight.js", category: "js_libs",     patterns: &["highlight.js", "hljs"], version_hint: None },
    Detection { name: "TinyMCE", category: "js_libs",     patterns: &["tinymce"], version_hint: Some("Rich text editor") },
    Detection { name: "CKEditor", category: "js_libs",     patterns: &["ckeditor"], version_hint: None },
    Detection { name: "Algolia", category: "js_libs",     patterns: &["algolia", "algoliasearch"], version_hint: Some("Search") },
    Detection { name: "Swagger UI", category: "js_libs",     patterns: &["swagger-ui", "swagger"], version_hint: Some("API docs") },

    // CSS Frameworks
    Detection { name: "Bootstrap", category: "css_frameworks",     patterns: &["bootstrap", "bootstrap.css", "bootstrap.min.css", "col-md-", "col-xs-"], version_hint: Some("5.x (inferred)") },
    Detection { name: "Tailwind CSS", category: "css_frameworks",     patterns: &["tailwind", "tailwindcss"], version_hint: Some("3.x (inferred)") },
    Detection { name: "Bulma", category: "css_frameworks",     patterns: &["bulma"], version_hint: Some("0.9.x") },
    Detection { name: "Foundation", category: "css_frameworks",     patterns: &["foundation", "zurb"], version_hint: Some("6.x") },
    Detection { name: "Materialize", category: "css_frameworks",     patterns: &["materialize", "materializecss"], version_hint: Some("1.x") },
    Detection { name: "UIKit", category: "css_frameworks",     patterns: &["uikit"], version_hint: Some("3.x") },
    Detection { name: "PureCSS", category: "css_frameworks",     patterns: &["purecss", "pure-min.css", "pure."], version_hint: Some("3.x") },
    Detection { name: "Semantic UI", category: "css_frameworks",     patterns: &["semantic"], version_hint: Some("2.x") },
    Detection { name: "Chakra UI", category: "css_frameworks",     patterns: &["chakra"], version_hint: Some("React") },
    Detection { name: "MUI", category: "css_frameworks",     patterns: &["@mui", "material-ui"], version_hint: Some("5.x") },
    Detection { name: "Ant Design", category: "css_frameworks",     patterns: &["antd", "ant-design"], version_hint: Some("5.x") },

    // Build Tools
    Detection { name: "Webpack", category: "build_tools",     patterns: &["webpack", "wpk"], version_hint: Some("5.x") },
    Detection { name: "Vite", category: "build_tools",     patterns: &["vite", "vitejs"], version_hint: Some("4.x") },
    Detection { name: "Parcel", category: "build_tools",     patterns: &["parcel"], version_hint: Some("2.x") },
    Detection { name: "esbuild", category: "build_tools",     patterns: &["esbuild"], version_hint: None },
    Detection { name: "Rollup", category: "build_tools",     patterns: &["rollup"], version_hint: None },
    Detection { name: "Gulp", category: "build_tools",     patterns: &["gulp."], version_hint: None },
    Detection { name: "Grunt", category: "build_tools",     patterns: &["grunt"], version_hint: None },
    Detection { name: "Snowpack", category: "build_tools",     patterns: &["snowpack"], version_hint: None },

    // Analytics (extended)
    Detection { name: "Google Tag Manager", category: "analytics",     patterns: &["gtm-", "googletagmanager"], version_hint: None },
    Detection { name: "Google Analytics", category: "analytics",     patterns: &["ga-", "analytics.js", "gtag"], version_hint: Some("GA4/UA") },
    Detection { name: "Facebook Pixel", category: "analytics",     patterns: &["fbevents.js", "connect.facebook.net"], version_hint: None },
    Detection { name: "Hotjar", category: "analytics",     patterns: &["hotjar"], version_hint: None },
    Detection { name: "Mixpanel", category: "analytics",     patterns: &["mixpanel"], version_hint: None },
    Detection { name: "Amplitude", category: "analytics",     patterns: &["amplitude"], version_hint: None },
    Detection { name: "Segment", category: "analytics",     patterns: &["segment"], version_hint: None },
    Detection { name: "FullStory", category: "analytics",     patterns: &["fullstory", "fullstory"], version_hint: None },
    Detection { name: "Heap", category: "analytics",     patterns: &["heap"], version_hint: None },
    Detection { name: "LinkedIn Insight", category: "analytics",     patterns: &["linkedin.com/analytics"], version_hint: None },
    Detection { name: "HubSpot", category: "analytics",     patterns: &["hs-analytics", "hs-script"], version_hint: None },
    Detection { name: "Matomo", category: "analytics",     patterns: &["matomo", "piwik"], version_hint: None },
    Detection { name: "Criteo", category: "analytics",     patterns: &["criteo"], version_hint: None },
    Detection { name: "TikTok Pixel", category: "analytics",     patterns: &["tiktok.com/analytics"], version_hint: None },
    Detection { name: "Reddit Pixel", category: "analytics",     patterns: &["reddit.com/analytics"], version_hint: None },
    Detection { name: "Twitter Pixel", category: "analytics",     patterns: &["twitter.com/analytics"], version_hint: None },
    Detection { name: "Pinterest Tag", category: "analytics",     patterns: &["pinterest.com/analytics"], version_hint: None },
    Detection { name: "Snapchat Pixel", category: "analytics",     patterns: &["snapchat.com/analytics"], version_hint: None },
    Detection { name: "Optimizely", category: "analytics",     patterns: &["optimizely"], version_hint: Some("A/B testing") },
    Detection { name: "VWO", category: "analytics",     patterns: &["vwo"], version_hint: Some("A/B testing") },

    // Hosting
    Detection { name: "AWS", category: "hosting",     patterns: &["aws", "amazonaws", "cloudfront", "ec2-"], version_hint: None },
    Detection { name: "Google Cloud", category: "hosting",     patterns: &["googleapis", "gstatic", "google.cloud"], version_hint: None },
    Detection { name: "Azure", category: "hosting",     patterns: &["azure", "windows.net", "azureedge"], version_hint: None },
    Detection { name: "Cloudflare", category: "hosting",     patterns: &["cloudflare", "cf-"], version_hint: None },
    Detection { name: "Netlify", category: "hosting",     patterns: &["netlify"], version_hint: None },
    Detection { name: "Vercel", category: "hosting",     patterns: &["vercel"], version_hint: None },
    Detection { name: "Heroku", category: "hosting",     patterns: &["heroku"], version_hint: None },
    Detection { name: "DigitalOcean", category: "hosting",     patterns: &["digitalocean"], version_hint: None },
    Detection { name: "GitHub Pages", category: "hosting",     patterns: &["github.io"], version_hint: None },
    Detection { name: "Firebase", category: "hosting",     patterns: &["firebase", "firebaseio"], version_hint: None },
    Detection { name: "Fastly", category: "hosting",     patterns: &["fastly"], version_hint: None },
    Detection { name: "Akamai", category: "hosting",     patterns: &["akamai"], version_hint: None },
    Detection { name: "OVH", category: "hosting",     patterns: &["ovh"], version_hint: None },
    Detection { name: "Hetzner", category: "hosting",     patterns: &["hetzner"], version_hint: None },

    // Databases (from patterns)
    Detection { name: "MySQL", category: "databases",     patterns: &["mysql", "mysqli", "pdo_mysql"], version_hint: None },
    Detection { name: "PostgreSQL", category: "databases",     patterns: &["postgresql", "pgsql", "pg_"], version_hint: None },
    Detection { name: "MongoDB", category: "databases",     patterns: &["mongodb", "mongo"], version_hint: None },
    Detection { name: "Redis", category: "databases",     patterns: &["redis"], version_hint: None },
    Detection { name: "Elasticsearch", category: "databases",     patterns: &["elasticsearch", "elastic"], version_hint: None },
    Detection { name: "SQLite", category: "databases",     patterns: &["sqlite"], version_hint: None },
    Detection { name: "MariaDB", category: "databases",     patterns: &["mariadb"], version_hint: None },

    // Feature flags
    Detection { name: "LaunchDarkly", category: "feature_flags",     patterns: &["launchdarkly"], version_hint: None },
    Detection { name: "Split.io", category: "feature_flags",     patterns: &["split.io"], version_hint: None },
    Detection { name: "GrowthBook", category: "feature_flags",     patterns: &["growthbook"], version_hint: None },
    Detection { name: "Flagsmith", category: "feature_flags",     patterns: &["flagsmith"], version_hint: None },

    // Additional JS Frameworks
    Detection { name: "Lit", category: "frontend",     patterns: &["@lit/reactive-element", "lit-html", "lit-element", "lit."], version_hint: Some("3.x") },
    Detection { name: "Marko", category: "frontend",     patterns: &["marko", "markojs"], version_hint: Some("5.x") },
    Detection { name: "Riot.js", category: "frontend",     patterns: &["riot.js", "riot.min", "riot.mount"], version_hint: Some("9.x") },
    Detection { name: "Solid.js", category: "frontend",     patterns: &["solid-js", "solidjs"], version_hint: Some("1.x") },
    Detection { name: "Qwik", category: "frontend",     patterns: &["qwik"], version_hint: Some("1.x") },
    Detection { name: "Remix", category: "frontend",     patterns: &["remix"], version_hint: Some("2.x") },

    // Additional CSS Frameworks
    Detection { name: "UnoCSS", category: "css_frameworks",     patterns: &["unocss", "@unocss"], version_hint: Some("0.50+") },
    Detection { name: "Open Props", category: "css_frameworks",     patterns: &["open-props", "openprops"], version_hint: Some("1.x") },
    Detection { name: "Windi CSS", category: "css_frameworks",     patterns: &["windi", "windicss"], version_hint: Some("3.x") },

    // CMS
    Detection { name: "Sitecore", category: "cms",     patterns: &["sitecore", "/sitecore/", "sc_"], version_hint: None },
    Detection { name: "Kentico", category: "cms",     patterns: &["kentico", "CMSPreView", "CMSPortal"], version_hint: None },
    Detection { name: "Contentful", category: "cms",     patterns: &["contentful"], version_hint: Some("Headless CMS") },
    Detection { name: "Strapi", category: "cms",     patterns: &["strapi", "strapi.io"], version_hint: Some("Headless CMS") },
    Detection { name: "Directus", category: "cms",     patterns: &["directus"], version_hint: Some("Headless CMS") },
    Detection { name: "Ghost", category: "cms",     patterns: &["ghost"], version_hint: Some("Blogging platform") },
    Detection { name: "Wix", category: "cms",     patterns: &["wix", "wixstatic"], version_hint: None },
    Detection { name: "Squarespace", category: "cms",     patterns: &["squarespace", "static.squarespace"], version_hint: None },
    Detection { name: "Webflow", category: "cms",     patterns: &["webflow"], version_hint: None },
    Detection { name: "Duda", category: "cms",     patterns: &["dudacdn"], version_hint: None },

    // Additional Analytics
    Detection { name: "CrazyEgg", category: "analytics",     patterns: &["crazyegg", "crazegg"], version_hint: None },
    Detection { name: "Mouseflow", category: "analytics",     patterns: &["mouseflow"], version_hint: None },
    Detection { name: "LuckyOrange", category: "analytics",     patterns: &["luckyorange"], version_hint: None },
    Detection { name: "Microsoft Clarity", category: "analytics",     patterns: &["clarity.ms"], version_hint: None },
    Detection { name: "Snowplow", category: "analytics",     patterns: &["snowplow"], version_hint: None },
    Detection { name: "Plausible", category: "analytics",     patterns: &["plausible"], version_hint: Some("Privacy-first") },
    Detection { name: "Fathom", category: "analytics",     patterns: &["fathom"], version_hint: Some("Privacy-first") },

    // Languages (direct detection)
    Detection { name: "Kotlin", category: "languages",     patterns: &["kotlin"], version_hint: None },
    Detection { name: "Rust", category: "languages",     patterns: &["rust"], version_hint: None },
    Detection { name: "Swift", category: "languages",     patterns: &["swift"], version_hint: None },
    Detection { name: "TypeScript", category: "languages",     patterns: &["typescript", "ts."], version_hint: None },
    Detection { name: "Scala", category: "languages",     patterns: &["scala"], version_hint: None },
    Detection { name: "Haskell", category: "languages",     patterns: &["haskell"], version_hint: None },
    Detection { name: "Dart", category: "languages",     patterns: &["dart"], version_hint: Some("Flutter") },
    Detection { name: "Perl", category: "languages",     patterns: &["perl"], version_hint: None },
    Detection { name: "Deno", category: "languages",     patterns: &["deno"], version_hint: Some("Runtime") },

    // Additional Backend
    Detection { name: "Deno", category: "backend",     patterns: &["x-powered-by: deno", "deno"], version_hint: Some("Runtime") },
    Detection { name: "Dart", category: "backend",     patterns: &["x-powered-by: dart", "dart"], version_hint: Some("Flutter") },

    // Additional JS Libs
    Detection { name: "Zod", category: "js_libs",     patterns: &["zod"], version_hint: Some("Schema validation") },
    Detection { name: "TanStack Query", category: "js_libs",     patterns: &["@tanstack/react-query", "tanstack.com/query"], version_hint: Some("5.x") },
    Detection { name: "React Router", category: "js_libs",     patterns: &["react-router", "reactrouter"], version_hint: Some("6.x") },
    Detection { name: "Framer Motion", category: "js_libs",     patterns: &["framer-motion", "framer motion"], version_hint: Some("10.x") },
    Detection { name: "tRPC", category: "js_libs",     patterns: &["trpc", "@trpc/"], version_hint: Some("10.x") },
    Detection { name: "Zustand", category: "js_libs",     patterns: &["zustand"], version_hint: Some("4.x") },
    Detection { name: "Playwright", category: "js_libs",     patterns: &["playwright"], version_hint: Some("Testing") },
    Detection { name: "Storybook", category: "js_libs",     patterns: &["storybook"], version_hint: Some("Component explorer") },
    Detection { name: "i18next", category: "js_libs",     patterns: &["i18next"], version_hint: Some("Internationalization") },

    // Additional Databases
    Detection { name: "Cassandra", category: "databases",     patterns: &["cassandra"], version_hint: None },
    Detection { name: "CockroachDB", category: "databases",     patterns: &["cockroachdb"], version_hint: None },
    Detection { name: "CouchDB", category: "databases",     patterns: &["couchdb"], version_hint: None },
    Detection { name: "Neo4j", category: "databases",     patterns: &["neo4j"], version_hint: Some("Graph database") },
    Detection { name: "Supabase", category: "databases",     patterns: &["supabase"], version_hint: None },
    Detection { name: "PlanetScale", category: "databases",     patterns: &["planetscale"], version_hint: None },

    // Additional Hosting
    Detection { name: "Railway", category: "hosting",     patterns: &["railway"], version_hint: None },
    Detection { name: "Render", category: "hosting",     patterns: &["render"], version_hint: None },
    Detection { name: "Fly.io", category: "hosting",     patterns: &["fly.io"], version_hint: None },
    Detection { name: "Cloudflare Pages", category: "hosting",     patterns: &["pages.dev", "cloudflare pages"], version_hint: None },

    // Additional Build Tools
    Detection { name: "Turbopack", category: "build_tools",     patterns: &["turbopack"], version_hint: None },
    Detection { name: "Nx", category: "build_tools",     patterns: &["nx"], version_hint: Some("Monorepo") },
    Detection { name: "Lerna", category: "build_tools",     patterns: &["lerna"], version_hint: None },
    Detection { name: "Bun", category: "build_tools",     patterns: &["bun"], version_hint: Some("Runtime") },
    Detection { name: "pnpm", category: "build_tools",     patterns: &["pnpm"], version_hint: None },

    // Additional Feature Flags
    Detection { name: "PostHog", category: "feature_flags",     patterns: &["posthog"], version_hint: Some("Product analytics") },
    Detection { name: "ConfigCat", category: "feature_flags",     patterns: &["configcat"], version_hint: None },
    Detection { name: "Unleash", category: "feature_flags",     patterns: &["unleash"], version_hint: None },
];

fn detect(category: &str, body_lower: &str, headers_lower: &str, detections: &[Detection]) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    for d in detections {
        if d.category != category { continue; }
        for p in d.patterns {
            if body_lower.contains(p) || headers_lower.contains(p) {
                let entry = match d.version_hint {
                    Some(v) => format!("{} ({})", d.name, v),
                    None => d.name.to_string(),
                };
                if !results.contains(&entry) {
                    results.push(entry);
                }
                break;
            }
        }
    }
    results
}

pub fn get_tech_json(headers: &str, body: &str) -> String {
    let body_lower = body.to_lowercase();
    let headers_lower = headers.to_lowercase();

    let mut tech = TechStack {
        frontend: detect("frontend", &body_lower, &headers_lower, DETECTIONS),
        backend: detect("backend", &body_lower, &headers_lower, DETECTIONS),
        js_libs: detect("js_libs", &body_lower, &headers_lower, DETECTIONS),
        css_frameworks: detect("css_frameworks", &body_lower, &headers_lower, DETECTIONS),
        build_tools: detect("build_tools", &body_lower, &headers_lower, DETECTIONS),
        analytics: detect("analytics", &body_lower, &headers_lower, DETECTIONS),
        hosting: detect("hosting", &body_lower, &headers_lower, DETECTIONS),
        databases: detect("databases", &body_lower, &headers_lower, DETECTIONS),
        cms: detect("cms", &body_lower, &headers_lower, DETECTIONS),
        feature_flags: detect("feature_flags", &body_lower, &headers_lower, DETECTIONS),
        languages: detect("languages", &body_lower, &headers_lower, DETECTIONS),
    };

    // Backend language detection from frontend/backend context
    for lib in &tech.js_libs {
        let lib_lower = lib.to_lowercase();
        if lib_lower.contains("php") { tech.languages.push("PHP".into()); }
        if lib_lower.contains("python") { tech.languages.push("Python".into()); }
        if lib_lower.contains("ruby") { tech.languages.push("Ruby".into()); }
        if lib_lower.contains("java") { tech.languages.push("Java".into()); }
        if lib_lower.contains("c#") || lib_lower.contains(".net") { tech.languages.push("C#/.NET".into()); }
        if lib_lower.contains("javascript") || lib_lower.contains("node") { tech.languages.push("JavaScript".into()); }
        if lib_lower.contains("go") || lib_lower.contains("golang") { tech.languages.push("Go".into()); }
    }
    tech.languages.dedup();

    if tech.frontend.is_empty() {
        tech.frontend.push("Unknown / Static HTML".into());
    }

    if tech.backend.is_empty() {
        tech.backend.push("Not directly identified".into());
    }

    serde_json::to_string(&tech).unwrap_or_else(|_| "{}".to_string())
}

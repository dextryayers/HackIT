-- Technology Fingerprint Detector from HTML/JS
local body = arg[1] or ""
local body_lower = string.lower(body)

local tech_signatures = {
    {"WordPress", "WordPress CMS", {"/wp-content/", "/wp-admin/", "/wp-includes/", "wp-json"}},
    {"Drupal", "Drupal CMS", {"drupal", "Drupal.settings", "drupal.js"}},
    {"Joomla", "Joomla CMS", {"joomla", "com_content", "com_users"}},
    {"Magento", "Magento E-commerce", {"mage/", "Magento_", "requirejs"}},
    {"Shopify", "Shopify Store", {"shopify", "myshopify", "shopifycdn"}},
    {"Laravel", "Laravel Framework", {"laravel", "csrf-token", "livewire"}},
    {"Symfony", "Symfony Framework", {"symfony", "sf_app", "_sf2"}},
    {"Django", "Django Framework", {"django", "csrfmiddlewaretoken", "__admin"}},
    {"Rails", "Ruby on Rails", {"rails", "csrf-param", "authenticity_token"}},
    {"Express", "Express.js", {"express", "x-powered-by.*express"}},
    {"React", "React JS", {"react", "reactjs", "react-dom", "createElement"}},
    {"Vue", "Vue.js", {"vue", "vuejs", "v-bind", "v-model", "vue-router"}},
    {"Angular", "Angular JS", {"angular", "ng-app", "ng-controller", "ng-model"}},
    {"Next.js", "Next.js", {"next", "__NEXT_DATA__", "_next/static"}},
    {"Nuxt", "Nuxt.js", {"nuxt", "__NUXT__", "_nuxt/"}},
    {"Gatsby", "Gatsby.js", {"gatsby", "___gatsby"}},
    {"jQuery", "jQuery Library", {"jquery", "jQuery", "$.ajax"}},
    {"Bootstrap", "Bootstrap CSS", {"bootstrap", "bootstrap.min"}},
    {"Tailwind", "Tailwind CSS", {"tailwind", "tailwindcss"}},
    {"FontAwesome", "FontAwesome", {"fontawesome", "fa-", "font-awesome"}},
    {"Google Analytics", "Google Analytics", {"google-analytics", "ga(", "gtag("}},
    {"Hotjar", "Hotjar Analytics", {"hotjar", "hj("}},
    {"Cloudflare", "Cloudflare CDN", {"cloudflare", "__cfduid", "cf-ray"}},
    {"Fastly", "Fastly CDN", {"fastly", "fastly-.*"}},
    {"Akamai", "Akamai CDN", {"akamai", "akamaiedge"}},
    {"Nginx", "Nginx Server", {"nginx"}},
    {"Apache", "Apache Server", {"apache", "mod_"}},
    {"IIS", "IIS Server", {"iis", "asp.net", "aspx"}},
    {"Material Icons", "Material Icons Library", {"material-icons", "MaterialIcons", "googleapis.*icon"}},
    {"Ionicons", "Ionicons Library", {"ionicons", "ion-icon"}},
    {"Feather Icons", "Feather Icons Library", {"feather-icons", "feather.min.js"}},
    {"Heroicons", "Heroicons Library", {"heroicons"}},
    {"Google Tag Manager", "Google Tag Manager", {"googletagmanager", "gtm.js", "gtm.start"}},
    {"GA4", "Google Analytics 4", {"gtag", "GA4_MEASUREMENT_ID", "gtag.js"}},
    {"Facebook Pixel", "Facebook Pixel", {"fbevents.js", "fbq(", "connect.facebook.*pixel"}},
    {"TikTok Pixel", "TikTok Pixel", {"tiktok.com/analytics", "ttq.", "tiktok-pixel"}},
    {"Alpine.js", "Alpine.js Framework", {"x-data", "x-init", "x-on:", "x-bind", "alpinejs"}},
    {"Stimulus", "Stimulus Framework", {"data-controller", "data-action", "stimulus"}},
    {"HTMX", "HTMX Library", {"htmx", "hx-get", "hx-post", "hx-target", "hx-swap"}},
    {"Preact", "Preact Library", {"preact"}},
    {"Lit", "Lit Library", {"lit-element", "lit-html"}},
    {"CookieConsent", "Cookie Consent Banner", {"cookie-consent", "cookieconsent", "cc-window", "cookieconsent.min", "cookie-notice", "cookie-banner", "cc-banner"}},
    {"PWA Manifest", "PWA Manifest Link", {"manifest.json", "apple-touch-icon", "serviceworker", "service-worker"}},
    {"OpenGraph", "OpenGraph Meta Tags", {"og:title", "og:description", "og:image", "og:url", "og:type"}},
    {"Twitter Cards", "Twitter Card Meta Tags", {"twitter:card", "twitter:site", "twitter:creator", "twitter:image"}},
}

local results = {}
for _, sig in ipairs(tech_signatures) do
    local name, desc, patterns = sig[1], sig[2], sig[3]
    local matched = false
    for _, pat in ipairs(patterns) do
        if string.find(body_lower, pat, 1, true) or string.find(body, pat) then
            matched = true
        end
    end
    if matched then
        table.insert(results, string.format("%s|%s", name, desc))
    end
end

if #results > 0 then
    print(table.concat(results, "\n"))
else
    print("NO_TECHNOLOGIES_DETECTED")
end

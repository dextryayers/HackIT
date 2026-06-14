local http = require("socket.http")
local https = require("ssl.https")
local ltn12 = require("ltn12")
local json = require("json")

local plugin = {
    name = "Web Technology Detection",
    version = "1.0.0",
    description = "Detects CMS, JS frameworks, analytics, CDN, server headers and web technologies",
    author = "HackIT Team"
}

local cms_patterns = {
    wordpress = {
        { pattern = "wp%-content", name = "WordPress" },
        { pattern = "wp%-includes", name = "WordPress" },
        { pattern = "WordPress", name = "WordPress" },
        { pattern = "/wp%-json/", name = "WordPress REST API" }
    },
    drupal = {
        { pattern = "Drupal", name = "Drupal" },
        { pattern = "drupal", name = "Drupal" },
        { pattern = "sites%/default%/", name = "Drupal" },
        { pattern = "drupal%-settings", name = "Drupal" }
    },
    joomla = {
        { pattern = "Joomla", name = "Joomla" },
        { pattern = "joomla", name = "Joomla" },
        { pattern = "/media%/joomla%/", name = "Joomla" },
        { pattern = "com_content", name = "Joomla" }
    },
    magento = {
        { pattern = "Magento", name = "Magento" },
        { pattern = "magento", name = "Magento" },
        { pattern = "Mage", name = "Magento" }
    },
    shopify = {
        { pattern = "Shopify", name = "Shopify" },
        { pattern = "myshopify", name = "Shopify" },
        { pattern = "shopify", name = "Shopify" }
    }
}

local js_patterns = {
    { pattern = "react", name = "React" },
    { pattern = "React", name = "React" },
    { pattern = "vue", name = "Vue.js" },
    { pattern = "Vue", name = "Vue.js" },
    { pattern = "angular", name = "Angular" },
    { pattern = "ng%-version", name = "Angular" },
    { pattern = "jQuery", name = "jQuery" },
    { pattern = "jquery", name = "jQuery" },
    { pattern = "backbone", name = "Backbone.js" },
    { pattern = "ember", name = "Ember.js" },
    { pattern = "svelte", name = "Svelte" },
    { pattern = "next%-data", name = "Next.js" },
    { pattern = "__NEXT_DATA", name = "Next.js" },
    { pattern = "nuxt", name = "Nuxt.js" },
    { pattern = "gatsby", name = "Gatsby" },
    { pattern = "d3%.js", name = "D3.js" },
    { pattern = "chart%.js", name = "Chart.js" }
}

local cdn_patterns = {
    { pattern = "cloudflare", name = "Cloudflare" },
    { pattern = "Cloudflare", name = "Cloudflare" },
    { pattern = "cloudfront", name = "AWS CloudFront" },
    { pattern = "CloudFront", name = "AWS CloudFront" },
    { pattern = "akamai", name = "Akamai" },
    { pattern = "Akamai", name = "Akamai" },
    { pattern = "fastly", name = "Fastly" },
    { pattern = "Fastly", name = "Fastly" },
    { pattern = "stackpath", name = "StackPath" },
    { pattern = "cdn%-", name = "Generic CDN" },
    { pattern = "maxcdn", name = "MaxCDN" }
}

local analytics_patterns = {
    { pattern = "google%-analytics", name = "Google Analytics" },
    { pattern = "gtag", name = "Google Analytics/GTag" },
    { pattern = "ga%(", name = "Google Analytics" },
    { pattern = "facebook%-pixel", name = "Facebook Pixel" },
    { pattern = "fbq%(", name = "Facebook Pixel" },
    { pattern = "hotjar", name = "Hotjar" },
    { pattern = "mixpanel", name = "Mixpanel" },
    { pattern = "amplitude", name = "Amplitude" },
    { pattern = "segment", name = "Segment" },
    { pattern = "matomo", name = "Matomo/Piwik" },
    { pattern = "piwik", name = "Piwik/Matomo" },
    { pattern = "new%-relic", name = "New Relic" },
    { pattern = "newrelic", name = "New Relic" }
}

local function check_patterns(content, patterns, findings)
    for _, item in ipairs(patterns) do
        if content:find(item.pattern, 1, true) then
            table.insert(findings, "Technology detected: " .. item.name)
        end
    end
end

local function parse_headers(headers, findings, risk_score)
    if not headers then return risk_score end

    if headers["server"] then
        table.insert(findings, "Server: " .. headers["server"])
        if headers["server"]:lower():find("apache") then
            local ver = headers["server"]:match("[%d.]+")
            if ver then table.insert(findings, "Apache version: " .. ver) end
        end
        if headers["server"]:lower():find("nginx") then
            local ver = headers["server"]:match("[%d.]+")
            if ver then table.insert(findings, "Nginx version: " .. ver) end
        end
        if headers["server"]:lower():find("iis") then
            local ver = headers["server"]:match("[%d.]+")
            if ver then table.insert(findings, "IIS version: " .. ver) end
            risk_score = math.min(100, risk_score + 5)
        end
    end

    if headers["x-powered-by"] then
        table.insert(findings, "X-Powered-By: " .. headers["x-powered-by"])
        risk_score = math.min(100, risk_score + 3)
    end

    if headers["x-aspnet-version"] then
        table.insert(findings, "ASP.NET Version: " .. headers["x-aspnet-version"])
        risk_score = math.min(100, risk_score + 3)
    end

    if headers["x-generator"] then
        table.insert(findings, "Generator: " .. headers["x-generator"])
    end

    if headers["set-cookie"] then
        if headers["set-cookie"]:find("PHPSESSID") then
            table.insert(findings, "PHP Session cookie detected")
        end
        if headers["set-cookie"]:find("ASP%.NET") or headers["set-cookie"]:find("ASPSESSION") then
            table.insert(findings, "ASP.NET Session cookie detected")
        end
        if headers["set-cookie"]:find("JSESSIONID") then
            table.insert(findings, "Java/J2EE Session cookie detected")
        end
    end

    if headers["x-frame-options"] then
        table.insert(findings, "X-Frame-Options: " .. headers["x-frame-options"])
    else
        table.insert(findings, "Missing X-Frame-Options header")
        risk_score = math.min(100, risk_score + 5)
    end

    if headers["x-content-type-options"] then
        table.insert(findings, "X-Content-Type-Options: " .. headers["x-content-type-options"])
    end

    if headers["strict-transport-security"] then
        table.insert(findings, "HSTS: " .. headers["strict-transport-security"])
    end

    if headers["x-xss-protection"] then
        table.insert(findings, "X-XSS-Protection: " .. headers["x-xss-protection"])
    end

    if headers["content-security-policy"] then
        table.insert(findings, "CSP: " .. headers["content-security-policy"])
    end

    if headers["cf-ray"] then
        table.insert(findings, "Cloudflare detected (CF-Ray header)")
    end

    return risk_score
end

local function fetch_url(target, port, use_ssl)
    local url_str = (use_ssl and "https" or "http") .. "://" .. target
    if (use_ssl and port ~= 443) or (not use_ssl and port ~= 80) then
        url_str = url_str .. ":" .. port
    end

    local response_body = {}
    local response_headers = {}
    local _, status = http.request {
        url = url_str,
        method = "GET",
        headers = {
            ["User-Agent"] = "HackIT Security Scanner/1.0",
            ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ["Accept-Language"] = "en-US,en;q=0.5"
        },
        sink = ltn12.sink.table(response_body),
        create = use_ssl and https.request or nil,
        redirect = false,
        timeout = 10000
    }

    if not status then return nil, nil end

    if response_body[1] then
        return table.concat(response_body), response_headers
    end
    return "", response_headers
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    table.insert(findings, "Target: " .. target .. ":" .. port)

    local content, headers = fetch_url(target, port, false)

    if not content then
        content, headers = fetch_url(target, port, true)
        if content then
            table.insert(findings, "HTTPS supported, TLS enabled")
        end
    else
        table.insert(findings, "HTTP available (no TLS)")
        risk_score = math.min(100, risk_score + 3)
    end

    if content and headers then
        risk_score = parse_headers(headers, findings, risk_score)

        check_patterns(content, cms_patterns.wordpress, findings)
        check_patterns(content, cms_patterns.drupal, findings)
        check_patterns(content, cms_patterns.joomla, findings)
        check_patterns(content, cms_patterns.magento, findings)
        check_patterns(content, cms_patterns.shopify, findings)

        for _, cms in pairs(cms_patterns) do
            check_patterns(content, cms, findings)
        end

        check_patterns(content, js_patterns, findings)
        check_patterns(content, cdn_patterns, findings)
        check_patterns(content, analytics_patterns, findings)

        local generator = content:match('<meta%s+name="generator"%s+content="([^"]+)"')
        if generator then
            table.insert(findings, "Generator meta tag: " .. generator)
        end

        local title = content:match('<title>([^<]+)</title>')
        if title then
            table.insert(findings, "Page title: " .. title)
        end

        if content:find("wp%-admin") or content:find("/wp%-login") then
            table.insert(findings, "WordPress admin interface exposed")
            risk_score = math.min(100, risk_score + 10)
        end

        if content:find("robots%-meta") then
            table.insert(findings, "Robots meta tag found")
        end

        if content:find("webpack") then
            table.insert(findings, "Webpack bundler detected")
        end

        local api_endpoints = content:find("/api/") and "/api/ endpoint found" or
            content:find("/graphql") and "GraphQL endpoint found" or nil
        if api_endpoints then
            table.insert(findings, api_endpoints)
        end
    end

    if banner and #banner > 0 then
        table.insert(findings, "Raw banner: " .. banner:sub(1, 200))
        if banner:find("HTTP/") then
            local http_ver = banner:match("HTTP/([%d.]+)")
            if http_ver then
                table.insert(findings, "HTTP version: " .. http_ver)
            end
        end
    end

    if #findings == 1 then
        table.insert(findings, "No web technologies detected")
    end

    return {
        status = #findings > 1 and "completed" or "no_results",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin

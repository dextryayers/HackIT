-- Advanced HTTP Response Header Analyzer
local headers_str = arg[1] or ""

local severity_map = {
    {"X-Powered-By", "medium", "Technology disclosure"},
    {"X-AspNet-Version", "high", "ASP.NET version disclosure"},
    {"X-Runtime", "medium", "Ruby/Rails version disclosure"},
    {"X-Version", "high", "Internal version disclosure"},
    {"X-Debug", "high", "Debug mode enabled"},
    {"X-Debug-Token", "high", "Debug token exposed"},
    {"X-Forwarded-For", "low", "Proxy header present"},
    {"X-Real-IP", "low", "Internal IP header"},
    {"X-Original-URL", "medium", "Internal routing header"},
    {"X-Rewrite-URL", "medium", "Internal URL rewrite"},
    {"X-Request-ID", "low", "Request tracking header"},
    {"X-Server-Name", "medium", "Internal hostname leak"},
    {"X-Download-Options", "low", "Download options header"},
    {"X-Frame-Options", "info", "Clickjacking protection"},
    {"Content-Security-Policy", "info", "CSP header present"},
    {"Strict-Transport-Security", "info", "HSTS present"},
    {"X-Content-Type-Options", "info", "MIME sniffing protection"},
    {"Set-Cookie", "info", "Cookie present"},
}

local missing_security = {
    "X-Frame-Options", "Content-Security-Policy",
    "X-Content-Type-Options", "Strict-Transport-Security",
}

local headers_lower = string.lower(headers_str)
local findings = {}

for _, rule in ipairs(severity_map) do
    local hdr, sev, desc = rule[1], rule[2], rule[3]
    if string.find(headers_lower, string.lower(hdr), 1, true) then
        table.insert(findings, string.format("%s|%s|%s", hdr, sev, desc))
    end
end

for _, hdr in ipairs(missing_security) do
    local found = false
    for _, rule in ipairs(severity_map) do
        if rule[1] == hdr and string.find(headers_lower, string.lower(hdr), 1, true) then
            found = true; break
        end
    end
    if not found then
        table.insert(findings, string.format("%s|info|MISSING_SECURITY_HEADER", hdr))
    end
end

if #findings > 0 then
    print(table.concat(findings, "\n"))
else
    print("NO_ISSUES")
end

-- Cookie Security Analyzer
local headers = arg[1] or ""

local cookie_flags = {
    {"Secure",       "Missing Secure flag - cookie sent over HTTP"},
    {"HttpOnly",     "Missing HttpOnly flag - accessible via JS"},
    {"SameSite",     "Missing SameSite flag - CSRF risk"},
    {"Domain",       "Domain attribute set - broad scope"},
    {"Path",         "Path attribute set - restricted scope"},
    {"Max-Age",      "Max-Age attribute present"},
    {"Expires",      "Expires attribute present"},
}

local findings = {}
local cookie_lines = {}

for line in string.gmatch(headers .. "\n", "[^\r\n]+") do
    if string.find(string.lower(line), "^set%-cookie:", 1, true) then
        table.insert(cookie_lines, line)
    end
end

if #cookie_lines == 0 then
    print("NO_COOKIES|No cookies set in response")
    return
end

for _, cookie in ipairs(cookie_lines) do
    local cookie_lower = string.lower(cookie)
    local cookie_name = ""
    local name_end = string.find(cookie, "=")
    if name_end then
        cookie_name = string.sub(cookie, 13, name_end - 1) -- after "Set-Cookie: "
    end

    local cookie_issues = {}
    for _, flag in ipairs(cookie_flags) do
        if not string.find(cookie_lower, string.lower(flag[1]), 1, true) then
            table.insert(cookie_issues, flag[2])
        end
    end

    if #cookie_issues > 0 then
        table.insert(findings, string.format("Cookie[%s]: %s", cookie_name, table.concat(cookie_issues, "; ")))
    end
end

if #findings > 0 then
    print(table.concat(findings, "\n"))
else
    print("COOKIES_SECURE|All cookies have security flags")
end

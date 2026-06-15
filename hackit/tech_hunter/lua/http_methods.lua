-- HTTP Method Tester & Security Analyzer
local headers = arg[1] or ""
local body = arg[2] or ""

-- Parse Allow header
local allow_header = ""
for line in string.gmatch(headers .. "\n" .. body, "[^\r\n]+") do
    local lower = string.lower(line)
    if string.find(lower, "^allow:", 1, true) or string.find(lower, "^access-control-allow-methods:", 1, true) then
        allow_header = line
        break
    end
end

local dangerous_methods = {
    {"PUT",     "File upload risk"},
    {"DELETE",  "Resource deletion risk"},
    {"PATCH",   "Partial modification risk"},
    {"TRACE",   "Cross-Site Tracing (XST) risk"},
    {"CONNECT", "Proxy tunnel risk"},
    {"OPTIONS", "Method enumeration possible"},
}

local allowed = string.lower(allow_header)
local findings = {}

for _, m in ipairs(dangerous_methods) do
    if string.find(allowed, string.lower(m[1]), 1, true) then
        table.insert(findings, string.format("%s_ENABLED|%s", m[1], m[2]))
    end
end

-- Check for missing security methods
local safe_methods = {"GET", "HEAD", "POST"}
for _, m in ipairs(safe_methods) do
    if not string.find(allowed, string.lower(m), 1, true) then
        table.insert(findings, string.format("%s_MISSING|Normal method not in Allow header", m))
    end
end

if #findings > 0 then
    print(table.concat(findings, "\n"))
else
    print("NO_DANGEROUS_METHODS|Only safe methods allowed")
end

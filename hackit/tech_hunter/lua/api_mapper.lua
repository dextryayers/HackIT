-- API Endpoint Mapper from Response Body
local body = arg[1] or ""
local base_url = arg[2] or ""

local patterns = {
    {pat = '"/api/',       title = "API Endpoint"},
    {pat = '"/v[0-9]/',    title = "Versioned API"},
    {pat = '"/graphql',    title = "GraphQL Endpoint"},
    {pat = '"/rest/',      title = "REST API"},
    {pat = '"/swagger',    title = "Swagger UI"},
    {pat = '"openapi',     title = "OpenAPI Spec"},
    {pat = '"redoc',       title = "Redoc UI"},
    {pat = '"/.well-known', title = "Well-Known"},
    {pat = '"/oauth',      title = "OAuth Endpoint"},
    {pat = '"/auth',       title = "Auth Endpoint"},
    {pat = '"/token',      title = "Token Endpoint"},
    {pat = '"/login',      title = "Login Endpoint"},
    {pat = '"/logout',     title = "Logout Endpoint"},
    {pat = '"/register',   title = "Register Endpoint"},
    {pat = '"/reset',      title = "Password Reset"},
    {pat = '"/webhook',    title = "Webhook"},
    {pat = '"/callback',   title = "OAuth Callback"},
    {pat = '"/sso',        title = "SSO Endpoint"},
    {pat = '"/saml',       title = "SAML Endpoint"},
    {pat = '"/ws',         title = "WebSocket"},
    {pat = '"/socket.io',  title = "Socket.IO"},
    {pat = '"/upload',     title = "File Upload"},
    {pat = '"/export',     title = "Data Export"},
    {pat = '"/import',     title = "Data Import"},
    {pat = '"/health',     title = "Health Check"},
    {pat = '"/metrics',    title = "Metrics Endpoint"},
    {pat = '"/debug',      title = "Debug Endpoint"},
    {pat = '"/admin',      title = "Admin Panel"},
    {pat = '"/console',    title = "Console"},
    {pat = '"/actuator',   title = "Spring Actuator"},
}

local found_endpoints = {}
for _, p in ipairs(patterns) do
    local _, count = string.gsub(body, p.pat, "")
    if count > 0 then
        table.insert(found_endpoints, string.format("%s|%s", p.title, p.pat))
    end
end

if #found_endpoints > 0 then
    print(table.concat(found_endpoints, "\n"))
else
    print("NO_API_ENDPOINTS")
end

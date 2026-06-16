local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local json = require "json"

description = [[Discovers OAuth 2.0 endpoints and configurations on web servers. Probes standard OAuth paths, .well-known endpoints, and OpenID Connect discovery URLs. Parses OAuth metadata from JSON responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local oauth_paths = {
    "/oauth", "/oauth/", "/oauth2", "/oauth2/",
    "/oauth/authorize", "/oauth/token", "/oauth/revoke",
    "/oauth/authorization", "/oauth/access_token",
    "/authorize", "/token", "/auth",
    "/api/oauth", "/api/oauth/",
    "/api/oauth2", "/api/oauth2/",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/openid-discovery",
    "/.well-known/oauth-authorization-server.json",
    "/openid", "/openid/",
    "/auth/realms/master/.well-known/openid-configuration",
    "/auth/realms/myrealm/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",
    "/.well-known/webfinger?resource=acct:admin@" .. (host.name or host.ip),
    "/oauth/health", "/oauth/info",
    "/oauth/status", "/oauth/version",
    "/token/info", "/token/revoke",
    "/oauth/userinfo", "/userinfo",
    "/connect/token", "/connect/authorize",
    "/connect/userinfo", "/connect/endsession",
    "/connect/checksession",
}

local required_oauth_keys = {
    "issuer", "authorization_endpoint", "token_endpoint",
    "userinfo_endpoint", "jwks_uri", "jwks",
}

local optional_oauth_keys = {
    "revocation_endpoint", "end_session_endpoint",
    "scopes_supported", "response_types_supported",
    "grant_types_supported", "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "code_challenge_methods_supported",
    "token_endpoint_auth_methods_supported",
    "claims_supported", "request_uri_parameter_supported",
    "registration_endpoint", "check_session_iframe",
    "introspection_endpoint", "backchannel_authentication_endpoint",
    "device_authorization_endpoint",
}

action = function(host, port)
    local result = stdnse.output_table()
    local endpoints = {}

    for _, path in ipairs(oauth_paths) do
        local ok, response = pcall(http.get, host, port, path, {
            timeout = 5000,
            header = {
                ["Accept"] = "application/json, application/xml, text/html",
            }
        })

        if ok and response and response.status then
            local ep_info = {
                path = path,
                status = response.status,
            }

            local body = response.body or ""

            local ok2, parsed = pcall(json.parse, body)
            if ok2 and parsed then
                ep_info.json_parsed = true
                ep_info.oauth_metadata = {}

                for _, key in ipairs(required_oauth_keys) do
                    if parsed[key] then
                        ep_info.oauth_metadata[key] = parsed[key]
                    end
                end

                for _, key in ipairs(optional_oauth_keys) do
                    if parsed[key] then
                        ep_info.oauth_metadata[key] = parsed[key]
                    end
                end

                if next(ep_info.oauth_metadata) then
                    local has_required = false
                    for _, key in ipairs(required_oauth_keys) do
                        if ep_info.oauth_metadata[key] then has_required = true end
                    end
                    ep_info.oauth_detected = has_required
                    if has_required then
                        table.insert(endpoints, ep_info)
                    end
                end
            end

            if not ep_info.oauth_detected then
                local indicators = {}
                local oauth_terms = {
                    "issuer", "authorization_endpoint", "token_endpoint",
                    "client_id", "response_type", "grant_type",
                    "access_token", "refresh_token", "bearer",
                    "OAuth", "oauth", "openid",
                    "scopes_supported", "redirect_uri",
                }
                for _, term in ipairs(oauth_terms) do
                    if body:find(term) then
                        table.insert(indicators, term)
                        if #indicators >= 3 then break end
                    end
                end

                if response.status == 200 and #indicators >= 2 then
                    ep_info.oauth_detected = true
                    ep_info.indicators = indicators
                    table.insert(endpoints, ep_info)
                elseif response.status == 401 or response.status == 302 then
                    local www_auth = (response.header and response.header["www-authenticate"]) or ""
                    if www_auth:find("Bearer") or www_auth:find("OAuth") then
                        ep_info.oauth_detected = true
                        ep_info.auth_header = www_auth
                        table.insert(endpoints, ep_info)
                    end
                else
                    for _, term in ipairs(oauth_terms) do
                        if body:find(term) and #indicators >= 1 then
                            ep_info.oauth_hint = true
                            ep_info.indicators = indicators
                            table.insert(endpoints, ep_info)
                            break
                        end
                    end
                end
            end
        end
    end

    if #endpoints == 0 then
        return stdnse.format_output(false, "No OAuth endpoints discovered")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints

    return stdnse.format_output(true, result)
end

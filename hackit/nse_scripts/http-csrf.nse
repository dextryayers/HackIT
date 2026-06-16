local http = require "http"
local stdnse = require "stdnse"

description = [[Scans forms in the target page for CSRF tokens (hidden input fields with anti-forgery names).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return stdnse.format_output(false, "No response body")
    end
    local forms = {}
    for form in response.body:gmatch("<form.-</form>") do
        forms[#forms + 1] = form
    end
    if #forms == 0 then
        return stdnse.format_output(false, "No forms found on page")
    end
    local results = {}
    for i, form in ipairs(forms) do
        local action_attr = form:match('action%s*=%s*["\'](.-)["\']') or "(no action)"
        local has_csrf = false
        for token_pattern in pairs({["csrf"] = true, ["token"] = true, ["_token"] = true, ["csrf_token"] = true, ["authenticity_token"] = true, ["__csrf"] = true, ["nonce"] = true}) do
            if form:match('type%s*=%s*["\']hidden["\']') and (form:match('name%s*=%s*["\'].-csrf') or form:match('name%s*=%s*["\'].-token') or form:match('name%s*=%s*["\'].-nonce')) then
                has_csrf = true
                break
            end
        end
        if not has_csrf then
            has_csrf = form:match('name%s*=%s*["\']_csrf') and true
        end
        local status = has_csrf and "CSRF token present" or "NO CSRF token"
        results[#results + 1] = "Form #" .. i .. " (action=" .. action_attr .. "): " .. status
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end

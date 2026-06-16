local http = require "http"
local stdnse = require "stdnse"

description = [[Scans for file upload endpoints by probing common upload paths and analyzing forms that accept file inputs.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local upload_paths = {"/upload", "/uploads", "/file/upload", "/upload.php", "/upload.aspx", "/upload.jsp", "/file-upload", "/api/upload", "/media/upload"}
    local results = {}
    for _, path in ipairs(upload_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.body then
                if resp.body:find('type%s*=%s*["\']file["\']') or resp.body:find('enctype%s*=%s*["\']multipart/form%-data["\']') then
                    results[#results + 1] = "Upload form at " .. path
                end
            end
            if resp.status < 300 then
                results[#results + 1] = "Upload endpoint accessible: " .. path
            end
        end
    end
    local home_resp = http.get(host, port, "/")
    if home_resp and home_resp.body then
        for form in home_resp.body:gmatch("<form.-</form>") do
            if form:find('type%s*=%s*["\']file["\']') then
                local action = form:match('action%s*=%s*["\'](.-)["\']') or "?"
                results[#results + 1] = "File upload form found on / (action: " .. action .. ")"
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No file upload endpoints found")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end

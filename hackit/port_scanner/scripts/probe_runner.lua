--[[
    Lua Probe Runner for HackIt Port Scanner
    Lightweight, fast probe scripts for embedded execution
    Compatible with Lua 5.1+ / LuaJIT
]]

local socket = require("socket")

local ProbeRunner = {}
ProbeRunner.__index = ProbeRunner

function ProbeRunner.new()
    local self = setmetatable({}, ProbeRunner)
    self.results = {}
    self.timeout = 5
    return self
end

function ProbeRunner:set_timeout(seconds)
    self.timeout = seconds or 5
end

function ProbeRunner:tcp_connect(host, port, timeout)
    local client = socket.tcp()
    client:settimeout(timeout or self.timeout)
    local ok, err = client:connect(host, tostring(port))
    if not ok then
        return nil, err
    end
    return client, nil
end

function ProbeRunner:send_payload(host, port, payload, timeout)
    local client, err = self:tcp_connect(host, port, timeout)
    if not client then
        return nil, err
    end
    
    if payload then
        local ok, err = client:send(payload)
        if not ok then
            client:close()
            return nil, err
        end
    end
    
    client:settimeout(0.1)
    local response = {}
    while true do
        local data, err = client:receive("*a")
        if not data or #data == 0 then
            break
        end
        table.insert(response, data)
        if #response > 10 then
            break
        end
    end
    client:close()
    
    return table.concat(response), nil
end

function ProbeRunner:probe_http(host, port)
    local payload = "GET / HTTP/1.0\r\nHost: " .. host .. "\r\n\r\n"
    local response, err = self:send_payload(host, port, payload)
    if not response then
        return nil, err
    end
    
    local result = {
        protocol = "http",
        banner = response:sub(1, 2048),
        headers = {}
    }
    
    for k, v in response:gmatch("([^\r\n]+): ([^\r\n]+)") do
        result.headers[k:lower()] = v
    end
    
    return result
end

function ProbeRunner:probe_ssh(host, port)
    local client, err = self:tcp_connect(host, port)
    if not client then
        return nil, err
    end
    
    client:settimeout(self.timeout)
    local banner, err = client:receive("*l")
    client:close()
    
    if not banner then
        return nil, err
    end
    
    local version = banner:match("SSH%-(%d%.%d+)%-(.+)")
    return {
        protocol = "ssh",
        banner = banner,
        version = version,
        raw = banner
    }
end

function ProbeRunner:probe_ftp(host, port)
    local client, err = self:tcp_connect(host, port)
    if not client then
        return nil, err
    end
    
    client:settimeout(self.timeout)
    local banner, err = client:receive("*l")
    client:close()
    
    if not banner then
        return nil, err
    end
    
    return {
        protocol = "ftp",
        banner = banner,
        raw = banner
    }
end

function ProbeRunner:probe_smtp(host, port)
    local client, err = self:tcp_connect(host, port)
    if not client then
        return nil, err
    end
    
    client:settimeout(self.timeout)
    local banner, err = client:receive("*l")
    client:close()
    
    if not banner then
        return nil, err
    end
    
    return {
        protocol = "smtp",
        banner = banner,
        raw = banner
    }
end

function ProbeRunner:probe_generic(host, port)
    local client, err = self:tcp_connect(host, port)
    if not client then
        return nil, err
    end
    
    client:settimeout(self.timeout)
    local data, err = client:receive("*a")
    client:close()
    
    if not data then
        return nil, err
    end
    
    return {
        protocol = "unknown",
        banner = data:sub(1, 1024),
        raw = data
    }
end

function ProbeRunner:run_probe(host, port, probe_type)
    local method = "probe_" .. (probe_type or "generic")
    if self[method] then
        return self[method](self, host, port)
    end
    return self:probe_generic(host, port)
end

function ProbeRunner:match_pattern(text, pattern, kind)
    kind = kind or "contains"
    
    if kind == "contains" then
        return text:find(pattern, 1, true) ~= nil
    elseif kind == "prefix" then
        return text:sub(1, #pattern) == pattern
    elseif kind == "regex" then
        local ok, result = pcall(function()
            return text:match(pattern)
        end)
        return ok and result ~= nil
    end
    
    return false
end

function ProbeRunner:score_match(hits, label, weight)
    for _, h in ipairs(hits) do
        if h.label == label then
            h.score = h.score + weight
            return
        end
    end
    table.insert(hits, {label = label, score = weight})
end

-- FFI-compatible exports
local function create_runner()
    return ProbeRunner.new()
end

local function run_http_probe(host, port)
    local runner = ProbeRunner.new()
    return runner:probe_http(host, port)
end

local function run_ssh_probe(host, port)
    local runner = ProbeRunner.new()
    return runner:probe_ssh(host, port)
end

-- Module exports
return {
    ProbeRunner = ProbeRunner,
    create_runner = create_runner,
    run_http_probe = run_http_probe,
    run_ssh_probe = run_ssh_probe
}

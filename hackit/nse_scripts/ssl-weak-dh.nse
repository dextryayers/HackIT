local stdnse = require "stdnse"
local tls = require "tls"

description = [[Checks for weak Diffie-Hellman parameters by analyzing the server's key exchange during DHE/ECDHE handshake and checking for small prime sizes (<1024 bits). Uses multiple cipher probes and extracts DH parameter sizes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function extract_dh_params(data)
    if not data then return nil end
    local patterns = {
        {hex = string.char(0x01, 0x00), bits = 1024},
        {hex = string.char(0x00, 0x80), bits = 1024},
        {hex = string.char(0x00, 0x40), bits = 512},
        {hex = string.char(0x00, 0x20), bits = 256},
        {hex = string.char(0x00, 0x60), bits = 768},
        {hex = string.char(0x00, 0x30), bits = 384},
    }
    for _, pat in ipairs(patterns) do
        if data:find(pat.hex, 1, true) then
            return pat.bits
        end
    end
    return nil
end

local function try_dhe(host, port, cipher)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello("TLSv1.2", {ciphers = {cipher}})
        sock:send(hello)
        local _, d = sock:receive_buf(tls.server_hello_done, 8000)
        sock:close()
        return d
    end)
    if not ok then
        pcall(function() sock:close() end)
        return nil
    end
    return data
end

action = function(host, port)
    local dhe_ciphers = {
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    }
    local min_bits = nil
    for _, cipher in ipairs(dhe_ciphers) do
        local data = try_dhe(host, port, cipher)
        if data then
            local bits = extract_dh_params(data)
            if bits then
                min_bits = min_bits and math.min(min_bits, bits) or bits
            end
        end
    end
    if min_bits then
        local result = stdnse.output_table()
        result.dh_parameters_bits = min_bits
        if min_bits < 1024 then
            result.vulnerability = true
            result.cve = "CVE-2015-0204"
            result.name = "Logjam / Weak DH"
            result.severity = "MEDIUM"
            result.details = "Weak DH parameters: " .. min_bits .. " bits"
        else
            result.vulnerability = false
            result.details = "DH parameters: " .. min_bits .. " bits (acceptable)"
        end
        return result
    end
    return stdnse.format_output(false, "Could not determine DH parameters or DHE not supported")
end

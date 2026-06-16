local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Retrieves and parses full SSL certificate information including issuer, subject, validity, and SANs.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function ssl_connect_and_grab(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local sock = socket:start_tls(host.ip, host.ip, port)
        if not sock then socket:close() return nil end
        sock:send("GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
        local _, resp = sock:receive_bytes(4096)
        sock:close()
        local result = {}
        if resp then
            result.response = resp
            local cert_raw = resp:match("-----BEGIN CERTIFICATE-----%s*(.-)%s*-----END CERTIFICATE-----")
            if cert_raw then
                result.certificate_found = true
                local subject = resp:match("subject=([^\r\n]+)")
                if subject then result.subject = subject end
                local issuer = resp:match("issuer=([^\r\n]+)")
                if issuer then result.issuer = issuer end
                local not_before = resp:match("notBefore=([^\r\n]+)")
                if not_before then result.not_before = not_before end
                local not_after = resp:match("notAfter=([^\r\n]+)")
                if not_after then result.not_after = not_after end
                local serial = resp:match("serial=([^\r\n]+)")
                if serial then result.serial = serial end
                local san_match = resp:match("subjectAltName=([^\r\n]+)")
                if san_match then
                    result.san = {}
                    for san in san_match:gmatch("[%w%.%*]+%.%a+") do
                        result.san[#result.san + 1] = san
                    end
                    if #result.san == 0 then
                        result.san_str = san_match
                    end
                end
                local alg = resp:match("Public Key Algorithm: ([^\r\n]+)")
                if alg then result.public_key_algorithm = alg end
                local sig_alg = resp:match("Signature Algorithm: ([^\r\n]+)")
                if sig_alg then result.signature_algorithm = sig_alg end
                local version = resp:match("Version: (%d)")
                if version then result.version = tonumber(version) end
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 443 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "SSL Certificate Info"
    out.target = host.ip
    out.port = port.number
    local result = ssl_connect_and_grab(host, port)
    if result and result.response then
        out.response_received = true
        if result.certificate_found then
            out.status = "CERTIFICATE_FOUND"
            if result.subject then out.subject = result.subject end
            if result.issuer then out.issuer = result.issuer end
            if result.not_before then out.valid_from = result.not_before end
            if result.not_after then out.valid_until = result.not_after end
            if result.serial then out.serial = result.serial end
            if result.san then out.subject_alt_names = result.san end
            if result.san_str then out.subject_alt_names_string = result.san_str end
            if result.public_key_algorithm then out.public_key_algorithm = result.public_key_algorithm end
            if result.signature_algorithm then out.signature_algorithm = result.signature_algorithm end
            if result.version then out.certificate_version = result.version end
        else
            out.status = "CERTIFICATE_EMBEDDED"
            out.message = "SSL response received but no embedded certificate found in HTTP response"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "SSL certificate info not available"
    end
    return out
end

local stdnse = require "stdnse"
local sslcert = require "sslcert"
local tls = require "tls"

description = [[Fetches and parses the SSL/TLS certificate from the server, extracting subject, issuer, validity dates, and fingerprint with version extraction and multiple probe attempts.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cert = sslcert.getCertificate(host, port)
    if not cert then
        local sock = nmap.new_socket()
        sock:set_timeout(10000)
        local ok = sock:connect(host.ip, port)
        if not ok then
            local _, e = pcall(function() sock:close() end)
            return stdnse.format_output(false, "Could not fetch SSL certificate")
        end
        local hellos = {
            tls.client_hello("TLSv1.2"),
            tls.client_hello("TLSv1.1"),
            tls.client_hello("TLSv1.0"),
        }
        local data
        for _, hello in ipairs(hellos) do
            local ok2, _ = pcall(function()
                sock:send(hello)
                local _, d = sock:receive_buf(tls.server_hello_done, 5000)
                data = d
            end)
            if ok2 and data then break end
        end
        pcall(function() sock:close() end)
        if not data then
            return stdnse.format_output(false, "Could not fetch SSL certificate")
        end
        return stdnse.format_output(false, "Certificate could not be parsed from handshake")
    end
    local result = stdnse.output_table()
    result.subject = cert.subject
    result.issuer = cert.issuer
    result.valid_from = cert.validFrom
    result.valid_to = cert.validTo
    result.serial = cert.serial
    result.fingerprint_sha1 = cert.fingerprint
    if cert.pubkey then
        result.pubkey_algorithm = cert.pubkey.algorithm
        result.pubkey_bits = cert.pubkey.bits
        local ver = tostring(cert.pubkey.bits)
        if cert.pubkey.algorithm then
            ver = cert.pubkey.algorithm .. "_" .. (cert.pubkey.bits or "unknown")
        end
        result.pubkey_version = ver
    end
    if cert.san and #cert.san > 0 then
        result.subject_alt_names = cert.san
    end
    if cert.validTo then
        local year = cert.validTo:match("(%d%d%d%d)")
        result.expiry_year = year
    end
    return result
end

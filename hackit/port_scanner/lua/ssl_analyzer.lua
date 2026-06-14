local ssl = require("ssl")
local socket = require("socket")
local json = require("json")

local plugin = {
    name = "SSL/TLS Analyzer",
    version = "1.1.0",
    description = "SSL/TLS protocol analyzer: version detection, cipher suites, certificate info, vulnerability checks (Heartbleed, POODLE, FREAK, Logjam)",
    author = "HackIT Team"
}

local ssl_versions = {
    { id = 0x0300, name = "SSL 3.0", insecure = true },
    { id = 0x0301, name = "TLS 1.0", insecure = true },
    { id = 0x0302, name = "TLS 1.1", insecure = true },
    { id = 0x0303, name = "TLS 1.2", insecure = false },
    { id = 0x0304, name = "TLS 1.3", insecure = false }
}

local insecure_ciphers = {
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON", "IDEA",
    "SEED", "CAMELLIA", "PSK", "SRP", "KRB5", "TLS_FALLBACK_SCSV"
}

local weak_ciphers = {
    "AES128", "AES256", "AESGCM", "CHACHA20"
}

local function scan_ssl_versions(target, port)
    local findings = {}
    for _, ver in ipairs(ssl_versions) do
        local ok, err = pcall(function()
            local sock = socket.tcp()
            sock:settimeout(5000)
            sock:connect(target, port)

            local params = {
                mode = "client",
                protocol = "tlsv1_2",
                verify = "none",
                options = "no_sslv2,no_sslv3"
            }

            if ver.name == "SSL 3.0" then
                params.protocol = "sslv3"
                params.options = nil
            elseif ver.name == "TLS 1.0" then
                params.protocol = "tlsv1"
            elseif ver.name == "TLS 1.1" then
                params.protocol = "tlsv1_1"
            elseif ver.name == "TLS 1.2" then
                params.protocol = "tlsv1_2"
            end

            local ssl_sock, ssl_err = ssl.wrap(sock, params)
            if ssl_sock then
                ssl_sock:dohandshake()
                local cert = ssl_sock:getpeercertificate()
                local cipher = ssl_sock:getciphername()
                ssl_sock:close()
                sock:close()
                return { version = ver.name, supported = true, cipher = cipher, cert = cert }
            end
            sock:close()
            return { version = ver.name, supported = false }
        end)

        if ok and err and err.supported then
            local msg = err.version .. " supported"
            if err.cipher then
                msg = msg .. " (cipher: " .. tostring(err.cipher) .. ")"
            end
            table.insert(findings, msg)
        elseif ok and err and not err.supported then
            table.insert(findings, err.version .. " not supported")
        else
            table.insert(findings, ver.name .. ": not supported")
        end
    end
    return findings
end

local function analyze_certificate(cert_string, findings)
    if not cert_string then return end

    if type(cert_string) == "table" then
        if cert_string.issuer then
            local issuer_str = type(cert_string.issuer) == "table" and tostring(cert_string.issuer) or cert_string.issuer
            table.insert(findings, "Certificate issuer: " .. issuer_str)
        end
        if cert_string.subject then
            local subject_str = type(cert_string.subject) == "table" and tostring(cert_string.subject) or cert_string.subject
            table.insert(findings, "Certificate subject: " .. subject_str)
        end
        if cert_string.validfrom then
            table.insert(findings, "Certificate valid from: " .. tostring(cert_string.validfrom))
        end
        if cert_string.validto then
            table.insert(findings, "Certificate valid until: " .. tostring(cert_string.validto))
        end
        if cert_string.serial then
            table.insert(findings, "Certificate serial: " .. tostring(cert_string.serial))
        end
        if cert_string.san or cert_string.subjectAltName then
            local san = cert_string.san or cert_string.subjectAltName
            local san_str = type(san) == "table" and table.concat(san, ", ") or tostring(san)
            table.insert(findings, "SAN: " .. san_str)
        end
        if cert_string.algorithm then
            table.insert(findings, "Signature algorithm: " .. tostring(cert_string.algorithm))
        end
        if cert_string.pubkey then
            table.insert(findings, "Public key: " .. tostring(cert_string.pubkey))
        end
    else
        table.insert(findings, "Certificate info: " .. cert_string)
    end
end

local function check_heartbleed(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "tlsv1_2",
            verify = "none"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            ssl_sock:dohandshake()

            local heartbeat_request = string.char(0x01, 0x00, 0x40, 0x00) .. string.rep("A", 16384)
            local ok_send, send_err = ssl_sock:send(heartbeat_request)
            if ok_send then
                local response, recv_err = ssl_sock:receive(16384)
                ssl_sock:close()
                sock:close()
                if response and #response > 50 then
                    return true
                end
                return false
            end
            ssl_sock:close()
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2014-0160", description = "Heartbleed: server returns memory beyond heartbeat payload" }
    end
    return { vulnerable = false }
end

local function check_poodle(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "sslv3",
            verify = "none"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            local ok_hand, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
            ssl_sock:close()
            sock:close()
            return ok_hand
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2014-3566", description = "POODLE: SSL 3.0 fallback vulnerability" }
    end
    return { vulnerable = false }
end

local function check_freak(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "tlsv1",
            verify = "none",
            options = "no_sslv2,no_sslv3",
            ciphers = "EXPORT"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            local ok_hand, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
            ssl_sock:close()
            sock:close()
            return ok_hand
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2015-0204", description = "FREAK: export-grade RSA key exchange" }
    end
    return { vulnerable = false }
end

local function check_logjam(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "tlsv1_2",
            verify = "none",
            ciphers = "DHE"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            local ok_hand, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
            ssl_sock:close()
            sock:close()
            return ok_hand
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2015-4000", description = "Logjam: weak Diffie-Hellman parameters" }
    end
    return { vulnerable = false }
end

local function check_drown(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "sslv2",
            verify = "none"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            local ok_hand, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
            ssl_sock:close()
            sock:close()
            return ok_hand
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2016-0800", description = "DROWN: SSLv2 downgrade vulnerability" }
    end
    return { vulnerable = false }
end

local function check_breach(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "tlsv1_2",
            verify = "none"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            ssl_sock:dohandshake()
            local cipher = ssl_sock:getciphername() or ""
            ssl_sock:close()
            sock:close()
            if cipher:find("COMPRESSION") then
                return true
            end
            return false
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2013-3587", description = "BREACH: TLS compression attack" }
    end
    return { vulnerable = false }
end

local function check_rc4(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        sock:connect(target, port)

        local params = {
            mode = "client",
            protocol = "tlsv1",
            verify = "none",
            ciphers = "RC4"
        }

        local ssl_sock, err = ssl.wrap(sock, params)
        if ssl_sock then
            local ok_hand, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
            ssl_sock:close()
            sock:close()
            return ok_hand
        end
        sock:close()
        return false
    end)

    if ok and result then
        return { vulnerable = true, cve = "CVE-2013-2566", description = "RC4 cipher suite supported (insecure)" }
    end
    return { vulnerable = false }
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    table.insert(findings, "SSL/TLS Analysis for " .. target .. ":" .. port)

    local ver_findings = scan_ssl_versions(target, port)
    for _, vf in ipairs(ver_findings) do
        table.insert(findings, vf)
        if vf:find("SSL 3%.0") and vf:find("supported") then
            risk_score = math.min(100, risk_score + 20)
        end
        if vf:find("TLS 1%.0") and vf:find("supported") then
            risk_score = math.min(100, risk_score + 10)
        end
        if vf:find("TLS 1%.1") and vf:find("supported") then
            risk_score = math.min(100, risk_score + 5)
        end
    end

    local heartbleed = check_heartbleed(target, port)
    if heartbleed.vulnerable then
        table.insert(findings, "VULNERABLE: " .. heartbleed.cve .. " - " .. heartbleed.description)
        risk_score = math.min(100, risk_score + 30)
    else
        table.insert(findings, "Heartbleed: Not vulnerable")
    end

    local poodle = check_poodle(target, port)
    if poodle.vulnerable then
        table.insert(findings, "VULNERABLE: " .. poodle.cve .. " - " .. poodle.description)
        risk_score = math.min(100, risk_score + 25)
    else
        table.insert(findings, "POODLE: Not vulnerable")
    end

    local freak = check_freak(target, port)
    if freak.vulnerable then
        table.insert(findings, "VULNERABLE: " .. freak.cve .. " - " .. freak.description)
        risk_score = math.min(100, risk_score + 20)
    else
        table.insert(findings, "FREAK: Not vulnerable")
    end

    local logjam = check_logjam(target, port)
    if logjam.vulnerable then
        table.insert(findings, "VULNERABLE: " .. logjam.cve .. " - " .. logjam.description)
        risk_score = math.min(100, risk_score + 15)
    else
        table.insert(findings, "Logjam: Not vulnerable")
    end

    local drown = check_drown(target, port)
    if drown.vulnerable then
        table.insert(findings, "VULNERABLE: " .. drown.cve .. " - " .. drown.description)
        risk_score = math.min(100, risk_score + 30)
    else
        table.insert(findings, "DROWN: Not vulnerable")
    end

    local breach = check_breach(target, port)
    if breach.vulnerable then
        table.insert(findings, "VULNERABLE: " .. breach.cve .. " - " .. breach.description)
        risk_score = math.min(100, risk_score + 15)
    else
        table.insert(findings, "BREACH: Not vulnerable")
    end

    local rc4 = check_rc4(target, port)
    if rc4.vulnerable then
        table.insert(findings, "VULNERABLE: " .. rc4.cve .. " - " .. rc4.description)
        risk_score = math.min(100, risk_score + 15)
    else
        table.insert(findings, "RC4: Not supported")
    end

    if banner and #banner > 0 then
        table.insert(findings, "Raw banner: " .. banner:sub(1, 200))
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin

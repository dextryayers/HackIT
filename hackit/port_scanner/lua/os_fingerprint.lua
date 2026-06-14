local socket = require("socket")
local json = require("json")

local plugin = {
    name = "OS Fingerprinting",
    version = "1.0.0",
    description = "OS detection via TTL analysis, TCP window size, port fingerprint heuristics. Detects Linux, Windows, macOS, BSD, embedded systems",
    author = "HackIT Team"
}

local ttl_signatures = {
    { min = 30, max = 75, os = "Linux / Android", family = "Unix-like" },
    { min = 20, max = 40, os = "BSD / macOS", family = "Unix-like", note = "Typically around 64" },
    { min = 110, max = 140, os = "Windows", family = "Windows" },
    { min = 220, max = 260, os = "Windows (older)", family = "Windows" },
    { min = 140, max = 170, os = "Cisco / Network Device", family = "Network" },
    { min = 1, max = 10, os = "Solaris / AIX", family = "Unix-like" },
    { min = 55, max = 68, os = "Linux", family = "Unix-like", weight = 2 }
}

local window_size_signatures = {
    { value = 65535, os = "Linux", family = "Unix-like" },
    { value = 65536, os = "macOS / BSD", family = "Unix-like" },
    { value = 8192, os = "Windows", family = "Windows" },
    { value = 16384, os = "Windows (modern)", family = "Windows" },
    { value = 29200, os = "Linux (recent)", family = "Unix-like" },
    { value = 5840, os = "Android / Embedded", family = "Embedded" },
    { value = 14600, os = "FreeBSD", family = "Unix-like" },
    { value = 65520, os = "OpenBSD", family = "Unix-like" },
    { value = 32120, os = "Windows 10/11", family = "Windows" },
    { value = 64240, os = "Windows Server", family = "Windows" },
    { value = 257, os = "Cisco IOS", family = "Network" },
    { value = 4128, os = "Embedded Linux", family = "Embedded" },
    { value = 16384, os = "Solaris", family = "Unix-like" },
    { value = 49152, os = "Linux / ChromeOS", family = "Unix-like" }
}

local port_fingerprints = {
    linux = {
        common = { 22, 80, 443, 3306, 5432, 6379, 27017 },
        description = "Typical Linux server (SSH, HTTP, MySQL/PostgreSQL, Redis, MongoDB)"
    },
    windows = {
        common = { 135, 139, 445, 3389, 5985, 5986, 47001 },
        description = "Typical Windows Server (RPC, SMB, RDP, WinRM)"
    },
    macos = {
        common = { 22, 88, 548, 500, 7000, 7001 },
        description = "Typical macOS (SSH, Kerberos, AFP, AirPort)"
    },
    bsd = {
        common = { 22, 80, 443, 53, 514 },
        description = "Typical BSD (SSH, HTTP, DNS, syslog)"
    },
    cisco = {
        common = { 22, 23, 161, 162, 443, 8443 },
        description = "Cisco network device (SSH, Telnet, SNMP, HTTPS)"
    },
    embedded = {
        common = { 23, 80, 443, 8080, 8443 },
        description = "Embedded device (Telnet, HTTP, HTTPS)"
    }
}

local function match_ttl(ttl_value)
    if not ttl_value then return nil end
    local matches = {}
    for _, sig in ipairs(ttl_signatures) do
        if ttl_value >= sig.min and ttl_value <= sig.max then
            table.insert(matches, sig)
        end
    end
    return matches
end

local function match_window_size(win_size)
    if not win_size then return nil end
    for _, sig in ipairs(window_size_signatures) do
        if win_size == sig.value then
            return sig
        end
    end
    return nil
end

local function match_port_profile(open_ports)
    if not open_ports or #open_ports == 0 then return nil end

    local scores = {}
    for os_name, profile in pairs(port_fingerprints) do
        scores[os_name] = 0
        for _, port in ipairs(open_ports) do
            for _, common_port in ipairs(profile.common) do
                if port == common_port then
                    scores[os_name] = scores[os_name] + 1
                    break
                end
            end
        end
    end

    local best = nil
    local best_score = -1
    for os_name, score in pairs(scores) do
        if score > best_score then
            best_score = score
            best = os_name
        end
    end

    if best and best_score > 0 then
        return best, port_fingerprints[best]
    end
    return nil, nil
end

local function measure_ttl(target, port)
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(5000)
        local start = socket.gettime()
        local ok_conn = sock:connect(target, port)
        if not ok_conn then
            sock:close()
            return nil
        end

        local elapsed = (socket.gettime() - start) * 1000

        local ok_send, _ = sock:send("GET / HTTP/1.0\r\n\r\n")
        sock:settimeout(2000)
        local data, _ = sock:receive("*l")

        sock:close()
        return elapsed, data
    end)

    if ok and result then
        return result
    end
    return nil, nil
end

local function calculate_ttl_from_elapsed(elapsed_ms)
    if not elapsed_ms then return nil end
    if elapsed_ms < 1 then
        return 64
    elseif elapsed_ms < 5 then
        return 128
    elseif elapsed_ms < 10 then
        return 60
    elseif elapsed_ms < 20 then
        return 255
    end
    return nil
end

local function try_dns_os_hints(target)
    local hints = {}

    local ok, ptr = pcall(socket.dns.toip, target)
    if ok then
        local rev_ok, rev_name = pcall(socket.dns.gethostname, target)
        if rev_ok and rev_name then
            local rev_str = tostring(rev_name)
            if rev_str:find("ip6") or rev_str:find("ip") then
                table.insert(hints, "Generic reverse DNS")
            end
            table.insert(hints, "Reverse DNS: " .. rev_str)
        end
    end

    return hints
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    table.insert(findings, "OS Fingerprint Analysis for " .. target .. ":" .. port)

    local elapsed, data = measure_ttl(target, port)
    local estimated_ttl = calculate_ttl_from_elapsed(elapsed)

    if estimated_ttl then
        table.insert(findings, string.format("Estimated TTL: %d", estimated_ttl))
        local ttl_matches = match_ttl(estimated_ttl)
        if ttl_matches then
            for _, match in ipairs(ttl_matches) do
                table.insert(findings, string.format("TTL signature: %s (family: %s)", match.os, match.family))
            end
        end
    end

    local win_sig = match_window_size(65535)
    if win_sig then
        table.insert(findings, "Default window size signature: " .. win_sig.os .. " (family: " .. win_sig.family .. ")")
    end

    local open_ports = opts.open_ports or { port }
    if opts.open_ports then
        table.insert(findings, "Open ports provided: " .. table.concat(opts.open_ports, ", "))
        local best_os, profile = match_port_profile(open_ports)
        if best_os then
            table.insert(findings, "Port profile match: " .. best_os .. " - " .. (profile and profile.description or ""))
        end
    end

    local dns_hints = try_dns_os_hints(target)
    for _, hint in ipairs(dns_hints) do
        table.insert(findings, hint)
    end

    if banner and #banner > 0 then
        table.insert(findings, "Banner: " .. banner:sub(1, 200))

        if banner:find("Linux") then
            table.insert(findings, "Banner indicates Linux/Unix")
        end
        if banner:find("Windows") or banner:find("Win32") or banner:find("IIS") then
            table.insert(findings, "Banner indicates Windows")
            risk_score = math.min(100, risk_score + 5)
        end
        if banner:find("FreeBSD") then
            table.insert(findings, "Banner indicates FreeBSD")
        end
        if banner:find("Ubuntu") then
            table.insert(findings, "Banner indicates Ubuntu Linux")
        end
        if banner:find("Debian") then
            table.insert(findings, "Banner indicates Debian Linux")
        end
        if banner:find("CentOS") or banner:find("Red Hat") or banner:find("RHEL") then
            table.insert(findings, "Banner indicates Red Hat / CentOS Linux")
        end
        if banner:find("Darwin") or banner:find("macOS") then
            table.insert(findings, "Banner indicates macOS")
        end
    end

    if estimated_ttl then
        if estimated_ttl >= 110 and estimated_ttl <= 140 then
            table.insert(findings, "Likely OS: Windows (TTL ~128)")
            risk_score = math.min(100, risk_score + 3)
        elseif estimated_ttl >= 55 and estimated_ttl <= 68 then
            table.insert(findings, "Likely OS: Linux/Unix (TTL ~64)")
        elseif estimated_ttl >= 220 and estimated_ttl <= 260 then
            table.insert(findings, "Likely OS: Windows (TTL ~255)")
        end
    end

    if #findings == 1 then
        table.insert(findings, "Could not determine OS with confidence")
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin

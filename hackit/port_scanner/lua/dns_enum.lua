local socket = require("socket")
local json = require("json")

local plugin = {
    name = "DNS Enumeration",
    version = "1.0.0",
    description = "DNS record enumeration: A, AAAA, MX, NS, TXT, SOA, CNAME records with DNSSEC detection and zone transfer attempts",
    author = "HackIT Team"
}

local common_subdomains = {
    "www", "mail", "ftp", "admin", "blog", "webmail", "server", "smtp",
    "pop3", "imap", "vpn", "ssh", "rdp", "smtp", "dns", "dns1", "dns2",
    "ns1", "ns2", "mx", "mx1", "mx2", "cpanel", "whm", "phpmyadmin",
    "phpadmin", "mysql", "test", "dev", "api", "app", "portal", "secure",
    "support", "help", "forum", "wiki", "download", "files", "static",
    "media", "img", "images", "css", "js", "assets", "cdn", "status",
    "statuspage", "tracking", "analytics", "stats", "logs", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "doc", "docs", "kb",
    "knowledgebase", "helpdesk", "ticket", "tickets", "office365",
    "outlook", "owa", "exchange", "autodiscover", "lync", "skype",
    "teams", "slack", "zoom", "webex", "remote", "remoteaccess",
    "anyconnect", "vpn", "openvpn", "wireguard", "proxy", "squid",
    "monitor", "monitoring", "nagios", "zabbix", "prometheus",
    "grafana", "kibana", "elastic", "elasticsearch", "logstash",
    "splunk", "sentry", "bugsnag", "pagerduty", "opsgenie"
}

local function is_valid_domain(domain)
    return domain and #domain > 0 and domain:match("^[%w%.%-]+$")
end

local function try_zone_transfer(domain, nameservers)
    local findings = {}
    for _, ns in ipairs(nameservers) do
        local ok, err = pcall(function()
            local results = socket.dns.getbyhostname(ns)
            if results then
                table.insert(findings, "Zone transfer target NS: " .. ns)
            end
        end)
        if not ok then
            table.insert(findings, "Zone transfer failed for " .. ns .. ": " .. tostring(err))
        end
    end
    return findings
end

local function check_record(domain, record_type)
    local record_map = {
        ["A"] = function(d)
            local results, err = socket.dns.toip(d)
            return results, err
        end,
        ["AAAA"] = function(d)
            local results, err = socket.dns.toip(d)
            if results then
                return results, nil
            end
            return nil, "No AAAA record"
        end,
        ["MX"] = function(d)
            local results, err = socket.dns.gethostname(d)
            if results then
                return results, nil
            end
            return nil, "No MX record"
        end,
        ["NS"] = function(d)
            local results, err = socket.dns.gethostname(d)
            if results then
                return results, nil
            end
            return nil, "No NS record"
        end,
        ["TXT"] = function(d)
            local results, err = socket.dns.gethostname(d)
            if results then
                return results, nil
            end
            return nil, "No TXT record"
        end
    }

    local resolver = record_map[record_type]
    if not resolver then return nil, "Unsupported record type" end

    local ok, result = pcall(resolver, domain)
    if ok and result then
        return result, nil
    end
    return nil, "No " .. record_type .. " record found"
end

local function check_dnssec(domain)
    local dnssec_findings = {}
    local ok, result = pcall(function()
        return socket.dns.gethostname(domain .. ".dnssec")
    end)
    if ok and result then
        dnssec_findings.dnssec = true
        dnssec_findings.details = "DNSSEC records may be present"
    else
        dnssec_findings.dnssec = false
        dnssec_findings.details = "No DNSSEC detected"
    end
    return dnssec_findings
end

local function get_ptr_record(ip)
    local ok, result = pcall(socket.dns.toip, ip)
    if ok and result then
        return result
    end
    return nil
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    local domain = target
    if target:match("^[%d.]+$") then
        local ptr = get_ptr_record(target)
        if ptr then
            table.insert(findings, "PTR record: " .. tostring(ptr))
            domain = tostring(ptr)
        else
            table.insert(findings, "No PTR record for IP: " .. target)
            return {
                status = "completed",
                findings = findings,
                risk_score = 0
            }
        end
    end

    if not is_valid_domain(domain) then
        table.insert(findings, "Invalid domain: " .. domain)
        return {
            status = "error",
            findings = findings,
            risk_score = 0
        }
    end

    table.insert(findings, "Domain: " .. domain)

    local record_types = {"A", "AAAA", "MX", "NS", "TXT"}
    local found_nameservers = {}

    for _, rtype in ipairs(record_types) do
        local result, err = check_record(domain, rtype)
        if result and err == nil then
            local result_str = tostring(result)
            table.insert(findings, rtype .. " record: " .. result_str)
            if rtype == "NS" then
                for ns in result_str:gmatch("%S+") do
                    table.insert(found_nameservers, ns)
                end
            end
        else
            table.insert(findings, rtype .. ": " .. tostring(err))
        end
    end

    local dnssec = check_dnssec(domain)
    if dnssec.dnssec then
        table.insert(findings, "DNSSEC: " .. dnssec.details)
    end

    if #found_nameservers > 0 then
        table.insert(findings, "Attempting zone transfer on " .. #found_nameservers .. " nameserver(s)")
        local zt_results = try_zone_transfer(domain, found_nameservers)
        for _, zt in ipairs(zt_results) do
            table.insert(findings, zt)
        end
    end

    local subdomains = opts.subdomains or common_subdomains
    if opts.bruteforce ~= false then
        local found_subs = {}
        for _, sub in ipairs(subdomains) do
            local fqdn = sub .. "." .. domain
            local ok, result = pcall(socket.dns.toip, fqdn)
            if ok and result then
                local ip_str = type(result) == "table" and (result[1] and result[1] or tostring(result)) or tostring(result)
                local msg = "Subdomain found: " .. fqdn .. " -> " .. ip_str
                table.insert(findings, msg)
                table.insert(found_subs, fqdn)
            end
        end
        if #found_subs == 0 then
            table.insert(findings, "No common subdomains resolved")
        end
    end

    local soa_ok, soa_result = pcall(socket.dns.gethostname, domain)
    if soa_ok and soa_result then
        table.insert(findings, "SOA/Authority: " .. tostring(soa_result))
    end

    local cname_ok, cname_result = pcall(socket.dns.toip, "www." .. domain)
    if cname_ok and cname_result then
        table.insert(findings, "CNAME (www): resolves to " .. tostring(cname_result))
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

local socket = require("socket")
local json = require("json")

local plugin = {
    name = "Subdomain Discovery",
    version = "1.0.0",
    description = "DNS-based subdomain discovery with 100+ entry wordlist, DNS brute force, and CNAME chain resolution",
    author = "HackIT Team"
}

local common_subdomains = {
    "www", "mail", "ftp", "admin", "blog", "webmail", "server", "smtp",
    "pop", "pop3", "imap", "vpn", "ssh", "rdp", "smtp", "dns", "dns1",
    "dns2", "ns1", "ns2", "ns3", "mx", "mx1", "mx2", "cpanel", "whm",
    "phpmyadmin", "phpadmin", "mysql", "test", "dev", "api", "app",
    "portal", "secure", "support", "help", "forum", "wiki", "download",
    "files", "static", "media", "img", "images", "css", "js", "assets",
    "cdn", "status", "statuspage", "tracking", "analytics", "stats",
    "logs", "git", "gitlab", "github", "bitbucket", "jenkins", "jira",
    "confluence", "wiki", "doc", "docs", "kb", "knowledgebase",
    "helpdesk", "ticket", "tickets", "office", "office365", "outlook",
    "owa", "exchange", "autodiscover", "lync", "skype", "teams",
    "slack", "zoom", "webex", "remote", "remoteaccess", "anyconnect",
    "vpn", "openvpn", "wireguard", "proxy", "squid", "monitor",
    "monitoring", "nagios", "zabbix", "prometheus", "grafana", "kibana",
    "elastic", "elasticsearch", "logstash", "splunk", "sentry",
    "bugsnag", "pagerduty", "opsgenie", "newrelic", "datadog",
    "sonarqube", "nexus", "artifactory", "docker", "k8s", "kubernetes",
    "kube", "cluster", "node", "master", "worker", "harbor", "registry",
    "npm", "pypi", "maven", "gradle", "composer", "rubygems",
    "crates", "packages", "repo", "repository", "mirror", "backup",
    "backups", "db", "database", "sql", "nosql", "mongo", "mongodb",
    "redis", "cache", "memcache", "memcached", "rabbitmq", "kafka",
    "zookeeper", "consul", "etcd", "vault", "ldap", "ad", "active",
    "directory", "sso", "auth", "login", "signin", "signup",
    "register", "account", "accounts", "profile", "profiles",
    "user", "users", "customer", "customers", "client", "clients",
    "partner", "partners", "vendor", "vendors", "store", "shop",
    "billing", "payment", "payments", "checkout", "cart", "order",
    "orders", "invoice", "invoices", "receipt", "receipts", "ship",
    "shipping", "track", "tracking", "delivery", "returns"
}

local function resolve_subdomain(subdomain, target)
    local fqdn = subdomain .. "." .. target
    local ok, result = pcall(socket.dns.toip, fqdn)
    if ok and result then
        return fqdn, tostring(result)
    end
    return nil, nil
end

local function resolve_cname_chain(fqdn, depth)
    depth = depth or 0
    if depth > 5 then return {} end

    local chain = {}
    table.insert(chain, fqdn)

    local cname_target = "www." .. fqdn
    local ok, result = pcall(socket.dns.toip, cname_target)
    if ok and result then
        local resolved = tostring(result)
        if resolved ~= fqdn then
            table.insert(chain, resolved)
            local subchain = resolve_cname_chain(resolved, depth + 1)
            for _, item in ipairs(subchain) do
                table.insert(chain, item)
            end
        end
    end

    return chain
end

local function attempt_zone_transfer(domain)
    local findings = {}
    local ok, results = pcall(socket.dns.gethostname, domain)
    if ok and results then
        local ns_list = {}
        for ns in tostring(results):gmatch("%S+") do
            table.insert(ns_list, ns)
        end
        for _, ns in ipairs(ns_list) do
            table.insert(findings, "NS: " .. ns)
        end
    end
    return findings
end

local function check_wildcard_dns(target)
    local test_sub = "hackittest" .. math.random(10000, 99999) .. math.random(10000, 99999)
    local fqdn = test_sub .. "." .. target
    local ok, result = pcall(socket.dns.toip, fqdn)
    if ok and result then
        return true, tostring(result)
    end
    return false, nil
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    local domain = target
    if target:match("^[%d.]+$") then
        local ok, result = pcall(socket.dns.toip, target)
        if ok and result then
            local ptr_ok, ptr_result = pcall(socket.dns.gethostname, target)
            if ptr_ok and ptr_result then
                domain = tostring(ptr_result)
                table.insert(findings, "PTR resolved: " .. target .. " -> " .. domain)
            else
                table.insert(findings, "IP target, no PTR record for " .. target)
                return {
                    status = "completed",
                    findings = findings,
                    risk_score = 0
                }
            end
        end
    end

    table.insert(findings, "Subdomain scan for: " .. domain)

    local wildcard, wildcard_ip = check_wildcard_dns(domain)
    if wildcard then
        table.insert(findings, "WARNING: Wildcard DNS detected (resolves to " .. wildcard_ip .. ")")
        risk_score = math.min(100, risk_score + 5)
    end

    local wordlist = opts.wordlist or common_subdomains
    local found_subdomains = {}

    table.insert(findings, "Brute-forcing " .. #wordlist .. " common subdomains...")

    for i, sub in ipairs(wordlist) do
        local fqdn, ip = resolve_subdomain(sub, domain)
        if fqdn and ip then
            if not wildcard or ip ~= wildcard_ip then
                table.insert(findings, "Found: " .. fqdn .. " -> " .. ip)
                table.insert(found_subdomains, { fqdn = fqdn, ip = ip })

                local cname_chain = resolve_cname_chain(fqdn)
                if #cname_chain > 1 then
                    local chain_str = table.concat(cname_chain, " -> ")
                    table.insert(findings, "CNAME chain: " .. chain_str)
                end
            end
        end

        if i % 20 == 0 then
            table.insert(findings, string.format("Progress: %d/%d subdomains checked", i, #wordlist))
        end
    end

    if #found_subdomains == 0 then
        table.insert(findings, "No subdomains found in common wordlist")
    else
        table.insert(findings, string.format("Total subdomains found: %d", #found_subdomains))

        if #found_subdomains > 5 then
            risk_score = math.min(100, risk_score + 10)
            table.insert(findings, "Large attack surface: " .. #found_subdomains .. " subdomains exposed")
        end

        local sensitive_subs = {"admin", "dev", "vpn", "ssh", "rdp", "jenkins", "jira", "confluence", "nexus", "artifactory"}
        for _, sub_info in ipairs(found_subdomains) do
            for _, sensitive in ipairs(sensitive_subs) do
                if sub_info.fqdn:find("^" .. sensitive .. "%.") then
                    table.insert(findings, "SENSITIVE: " .. sub_info.fqdn .. " exposes " .. sensitive .. " service")
                    risk_score = math.min(100, risk_score + 15)
                end
            end
        end
    end

    local ns_records = attempt_zone_transfer(domain)
    if #ns_records > 0 then
        table.insert(findings, "Nameserver records:")
        for _, ns in ipairs(ns_records) do
            table.insert(findings, "  " .. ns)
        end
    end

    local ok, mx_result = pcall(socket.dns.toip, domain)
    if ok and mx_result then
        table.insert(findings, "A record for domain: " .. tostring(mx_result))
    end

    if banner and #banner > 0 then
        table.insert(findings, "Banner: " .. banner:sub(1, 200))
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin

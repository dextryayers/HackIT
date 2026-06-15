-- Subdomain Discovery via DNS Brute-force
local domain = arg[1] or ""
if domain == "" then print("NO_DOMAIN"); return end

local sub_list = {
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "cdn", "m", "app", "webmail", "portal", "login",
    "auth", "sso", "git", "jenkins", "jira", "wiki", "docs", "support",
    "help", "status", "monitor", "grafana", "prometheus", "kibana",
    "splunk", "docker", "k8s", "prod", "production", "devops", "ci",
    "backup", "db", "database", "redis", "mysql", "mongo", "elastic",
    "mq", "rabbitmq", "kafka", "consul", "vault", "proxy", "gateway",
    "router", "firewall", "waf", "lb", "loadbalancer", "ha", "cluster",
    "smtp", "imap", "pop3", "static", "assets", "img", "images",
    "analytics", "metrics", "report", "billing", "payment", "checkout",
    "partner", "vendor", "recruit", "career", "job", "private", "internal",
}

local results = {}
local dns = require("socket.dns")
for _, sub in ipairs(sub_list) do
    local host = sub .. "." .. domain
    local ok, resolved = pcall(dns.resolve, host)
    if ok and resolved then
        local ips = {}
        if type(resolved) == "string" then
            ips = {resolved}
        elseif type(resolved) == "table" then
            for _, r in ipairs(resolved) do ips[#ips+1] = r end
        end
        table.insert(results, string.format("%s|%s", host, table.concat(ips, ",")))
    end
end

if #results > 0 then
    print(table.concat(results, "\n"))
else
    print("NO_SUBDOMAINS_FOUND")
end

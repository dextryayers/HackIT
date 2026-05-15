-- Service Identification Rules
local rules = {
    {port = 22, pattern = "SSH", service = "OpenSSH"},
    {port = 80, pattern = "nginx", service = "Nginx Web Server"},
    {port = 80, pattern = "Apache", service = "Apache HTTPD"},
    {port = 443, pattern = "Cloudflare", service = "Cloudflare Edge Node"},
    {port = 3306, pattern = "", service = "MySQL Database"},
}

function identify(port, banner)
    for _, rule in ipairs(rules) do
        if rule.port == port then
            if rule.pattern == "" or (banner and string.find(banner, rule.pattern)) then
                return rule.service
            end
        end
    end
    return "Unknown Service"
end

-- Entry point for CLI call
local port = tonumber(arg[1])
local banner = arg[2]
print(identify(port, banner))

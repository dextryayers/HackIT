-- NSE-style script for HackIt
-- Detection for common web servers

description = "Detects web server type and version from banner"
author = "HackIt Team"
severity = "info"

function run(host, port, service, banner)
    if port == 80 or port == 443 or port == 8080 then
        if banner ~= "" then
            if string.find(string.lower(banner), "nginx") then
                return "Nginx Web Server detected"
            elseif string.find(string.lower(banner), "apache") then
                return "Apache HTTP Server detected"
            elseif string.find(string.lower(banner), "microsoft-iis") then
                return "Microsoft IIS detected"
            end
        end
    end
    return nil
end

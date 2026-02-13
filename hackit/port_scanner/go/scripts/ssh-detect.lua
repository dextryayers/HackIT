-- NSE-style script for HackIt
-- Detection for SSH server version

description = "Extracts version information from SSH banners"
author = "HackIt Team"
severity = "info"

function run(host, port, service, banner)
    if port == 22 or string.lower(service) == "ssh" then
        if banner ~= "" then
            -- SSH banner format is typically SSH-2.0-OpenSSH_8.2p1...
            local match = string.match(banner, "SSH%-%d%.%d%-(%S+)")
            if match then
                return "SSH Version: " .. match
            end
        end
    end
    return nil
end

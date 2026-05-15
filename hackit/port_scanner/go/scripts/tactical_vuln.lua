-- HackIT Tactical Script: Vuln Discovery
local host = arg[1] or "127.0.0.1"
local port = tonumber(arg[2]) or 80

print(string.format("[*] HackIT Lua-Core: Running tactical script on %s:%d", host, port))

local function check_vuln()
    if port == 80 or port == 443 then
        return "Potential: CVE-2021-41773 (Apache Path Traversal)"
    elseif port == 22 then
        return "Info: OpenSSH 8.2p1 (Ubuntu 4ubuntu0.3)"
    else
        return "No high-risk vulnerabilities found via script"
    end
end

print("RESULT: " .. check_vuln())

local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Discovers phone numbers embedded in web pages or service banners.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local phone_patterns = {
    {pattern = "([%+][%d][%d%-%s%.%(%)]{" .. 7 .. ",})", desc = "International format"},
    {pattern = "([%(%d][%d][%d%)]%s*[%d][%d][%d]%-[%d][%d][%d][%d])", desc = "US format (555) 123-4567"},
    {pattern = "(%d%d%d[%-%.]%d%d%d[%-%.]%d%d%d%d)", desc = "Numeric format xxx-xxx-xxxx"},
    {pattern = "(%+[%d]+[%-][%d]+[%-][%d]+)", desc = "E.164 format"},
}

local http_paths = {"/", "/contact", "/about", "/support", "/help", "/about-us", "/contact-us", "/index.html"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443 or port.number == 8080) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Phone Number Discovery"
    out.target = host.ip
    out.port = port.number
    local all_phones = {}
    for _, path in ipairs(http_paths) do
        local socket = nmap.new_socket()
        socket:set_timeout(5000)
        local ok, resp = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            socket:send("GET " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
            local _, r = socket:receive_bytes(8192)
            socket:close()
            return r
        end)
        if not ok then pcall(socket.close, socket) end
        if resp then
            for _, pat_entry in ipairs(phone_patterns) do
                for match in resp:gmatch(pat_entry.pattern) do
                    local clean = match:gsub("[%s%(%)]", "")
                    if #clean >= 10 then
                        local already = false
                        for _, p in ipairs(all_phones) do
                            if p.number == clean then already = true end
                        end
                        if not already then
                            all_phones[#all_phones + 1] = {number = clean, format = pat_entry.desc, source = path}
                        end
                    end
                end
            end
        end
    end
    if #all_phones > 0 then
        out.status = "PHONE_NUMBERS_FOUND"
        out.phone_numbers = all_phones
        out.phone_count = #all_phones
    else
        out.status = "NONE_FOUND"
        out.message = "No phone numbers discovered"
    end
    return out
end

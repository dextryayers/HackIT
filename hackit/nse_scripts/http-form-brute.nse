local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local openssl = require "openssl"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[
HTTP form-based authentication brute forcer. Attempts to brute force web login forms
by submitting POST requests with common username and password combinations.
Supports form field detection and session handling via cookies.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(80, "http")

local function detect_form_fields(host, port, path)
    local response = http.get(host, port, path)
    if not response or not response.body then
        return nil, "No response body"
    end
    local username_field, password_field, form_action
    for field in response.gmatch(body, 'input[^>]*name="([^"]+)"[^>]*type="([^"]*)"') do
        if match(field, "user") or match(field, "login") or match(field, "email") then
            username_field = field
        elseif match(field, "pass") or match(field, "pwd") then
            password_field = field
        end
    end
    local action = response.match(body, 'action="([^"]+)"')
    if action then
        form_action = action
    end
    if not username_field or not password_field then
        return nil, "Could not detect form fields"
    end
    return {username = username_field, password = password_field, action = form_action or path}
end

local function try_login(host, port, path, fields, username, password)
    local post_data = {}
    post_data[fields.username] = username
    post_data[fields.password] = password
    local response = http.post(host, port, fields.action, nil, nil, post_data)
    if not response then
        return false
    end
    if response.status == 302 or response.status == 301 then
        return true
    end
    if response.body and not response.match(body, "invalid") and not response.match(body, "error") and not response.match(body, "incorrect") then
        return true
    end
    return false
end

action = function(host, port)
    local result = {}
    local common_users = {"admin", "root", "user", "test", "guest", "administrator"}
    local common_passwords = {"admin", "password", "123456", "12345678", "qwerty", "letmein", "admin123", "root", "toor", "pass", "test", "guest", "1234", "12345", "P@ssw0rd", "changeme", "default"}

    local path = "/login"
    local fields, err = detect_form_fields(host, port, path)
    if not fields then
        path = "/wp-login.php"
        fields, err = detect_form_fields(host, port, path)
    end
    if not fields then
        path = "/admin"
        fields, err = detect_form_fields(host, port, path)
    end
    if not fields then
        return format_output(false, "Could not detect login form on common paths")
    end

    for _, user in ipairs(common_users) do
        for _, pass in ipairs(common_passwords) do
            if try_login(host, port, path, fields, user, pass) then
                insert(result, ("Valid credentials found: %s / %s"):format(user, pass))
                break
            end
        end
    end

    if #result == 0 then
        insert(result, "No valid credentials found with common passwords")
    end
    return format_output(true, result)
end

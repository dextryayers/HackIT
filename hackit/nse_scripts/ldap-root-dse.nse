local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"

description = [[Fetches the LDAP Root DSE (DSA-specific Entry) information. Extracts naming contexts, supported capabilities, LDAP versions, vendor info, and AD-specific attributes like domain/forest GUIDs.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and (port.number == 389 or port.number == 636 or port.number == 3268)
end

local function ber_encode_integer(val)
    if val < 128 then
        return string.char(0x02, val)
    end
    local bytes = {}
    while val > 0 do
        table.insert(bytes, 1, string.char(val % 256))
        val = math.floor(val / 256)
    end
    return string.char(0x02, #bytes) .. table.concat(bytes)
end

local function ber_encode_string(s)
    return string.char(0x04, #s) .. s
end

local function ber_encode_sequence(contents)
    return string.char(0x30, #contents) .. contents
end

local requested_attributes = {
    "namingContexts", "supportedCapabilities", "supportedLDAPVersion",
    "supportedLDAPPolicies", "supportedControl", "supportedExtension",
    "supportedFeatures", "supportedSASLMechanisms",
    "vendorName", "vendorVersion",
    "rootDomainNamingContext", "defaultNamingContext",
    "schemaNamingContext", "configurationNamingContext",
    "serverName", "dnsHostName",
    "currentTime", "subschemaSubentry",
    "domainControllerFunctionality", "domainFunctionality",
    "forestFunctionality", "highestCommittedUSN",
    "isGlobalCatalogReady", "ldapServiceName",
    "objectGUID", "serverStartTime",
}

local function build_rootdse_request()
    local msg_id = ber_encode_integer(1)
    local scope = string.char(0x0a, 0x01, 0x00)
    local deref = string.char(0x0a, 0x01, 0x00)
    local size_limit = ber_encode_integer(0)
    local time_limit = ber_encode_integer(0)
    local types_only = string.char(0x01, 0x01, 0x00)
    local base_object = ber_encode_string("")
    local filter = ber_encode_sequence(string.char(0x05, 0x00))

    local attr_seq = ""
    for _, attr in ipairs(requested_attributes) do
        attr_seq = attr_seq .. ber_encode_string(attr)
    end
    local attributes = ber_encode_sequence(attr_seq)

    local search_body = base_object .. scope .. deref .. size_limit .. time_limit .. types_only .. filter .. attributes
    local search_request = ber_encode_sequence(string.char(0x63, #search_body) .. search_body)
    local ldap_message = ber_encode_sequence(msg_id .. search_request)
    return ber_encode_sequence(ldap_message)
end

local function parse_ldap_response(response)
    local results = {}

    local patterns = {
        namingContexts = "namingContexts",
        supportedLDAPVersion = "supportedLDAPVersion",
        vendorName = "vendorName",
        vendorVersion = "vendorVersion",
        rootDomainNamingContext = "rootDomainNamingContext",
        defaultNamingContext = "defaultNamingContext",
        schemaNamingContext = "schemaNamingContext",
        configurationNamingContext = "configurationNamingContext",
        dnsHostName = "dnsHostName",
        serverName = "serverName",
        currentTime = "currentTime",
        ldapServiceName = "ldapServiceName",
        subschemaSubentry = "subschemaSubentry",
        domainControllerFunctionality = "domainControllerFunctionality",
        domainFunctionality = "domainFunctionality",
        forestFunctionality = "forestFunctionality",
        highestCommittedUSN = "highestCommittedUSN",
        isGlobalCatalogReady = "isGlobalCatalogReady",
    }

    for key, pattern in pairs(patterns) do
        local _, epos = response:find(pattern .. "\x04")
        if epos then
            local remaining = response:sub(epos + 1)
            local len = string.byte(remaining, 1)
            if len then
                local val = remaining:sub(2, 1 + len)
                if val and #val > 0 then
                    results[key] = val
                end
            end
        end
    end

    local _, cpos = response:find("currentTime\x04")
    if cpos then
        local remaining = response:sub(cpos + 1)
        local len = string.byte(remaining, 1)
        if len then
            results.currentTime = remaining:sub(2, 1 + len)
        end
    end

    return results
end

action = function(host, port)
    local result = stdnse.output_table()
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
        return stdnse.format_output(false, "Connection failed: " .. tostring(err))
    end

    local req = build_rootdse_request()
    local ok2, serr = pcall(socket.send, socket, req)
    if not ok2 then
        socket:close()
        return stdnse.format_output(false, "Send failed: " .. tostring(serr))
    end

    local ok3, response = pcall(socket.receive_buf, socket, "\x30", 10)
    socket:close()

    if not ok3 or not response or #response < 10 then
        return stdnse.format_output(false, "No valid LDAP response")
    end

    local root_dse = parse_ldap_response(response)

    if not root_dse or not next(root_dse) then
        local has_low = false
        for _, attr in ipairs(requested_attributes) do
            if response:find(attr) then
                has_low = true
                break
            end
        end
        if has_low then
            result.attributes_mentioned = true
        else
            return stdnse.format_output(false, "LDAP Root DSE not accessible or no attributes returned")
        end
    end

    for k, v in pairs(root_dse) do
        local key = k:gsub("([A-Z])", "_%1"):lower():gsub("^_", "")
        result[key] = v
    end

    if root_dse.namingContexts then
        result.naming_contexts = root_dse.namingContexts
    end

    if root_dse.isGlobalCatalogReady then
        result.global_catalog_ready = root_dse.isGlobalCatalogReady
    end

    if root_dse.domainControllerFunctionality then
        local levels = {
            ["0"] = "Windows 2000",
            ["1"] = "Windows Server 2003",
            ["2"] = "Windows Server 2008",
            ["3"] = "Windows Server 2008 R2",
            ["4"] = "Windows Server 2012",
            ["5"] = "Windows Server 2012 R2",
            ["6"] = "Windows Server 2016",
            ["7"] = "Windows Server 2019/2022",
        }
        result.dc_functionality_level = levels[root_dse.domainControllerFunctionality] or root_dse.domainControllerFunctionality
    end

    return stdnse.format_output(true, result)
end

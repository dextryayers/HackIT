-- Unexpected/Debug Header Rules
local sensitive_headers = {
    "X-Debug-Token", "X-Generator", "X-Powered-By", "X-Aspnet-Version",
    "X-Runtime", "X-Varnish", "X-Cache", "Server"
}

function check_header(header_name)
    for _, pattern in ipairs(sensitive_headers) do
        if string.find(string.lower(header_name), string.lower(pattern)) then
            return true
        end
    end
    return false
end

-- Entry point
local header_name = arg[1]
if check_header(header_name) then
    print("SENSITIVE")
else
    print("NORMAL")
end

-- SSH Version & Algorithm Auditor
-- Target: Port 22
function action()
    if port ~= 22 then return nil end
    
    local conn, err = connect(host, port, 3000)
    if not conn then return nil end

    local banner = receive(conn, 1024, 3000)
    close(conn)

    if not banner then return nil end
    
    local version = banner:match("SSH%-([0-9.]+)%-")
    local software = banner:match("SSH%-[0-9.]+%-([^\\r\\n]+)")
    
    if version or software then
        return "SSH Protocol: " .. (version or "?") .. " | Software: " .. (software or "?")
    end
    return "Raw Banner: " .. banner:sub(1, 50)
end

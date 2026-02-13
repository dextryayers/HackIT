-- NSE-style script for HackIt
-- Checks for generic directory listing (misconfiguration)

function action()
    if service == "http" or port == 80 or port == 8080 or port == 443 then
        local conn, err = connect(host, port, 3000)
        if not conn then return nil end

        -- Request a non-existent directory or root to check for common listing patterns
        local req = "GET /icons/ HTTP/1.1\r\nHost: " .. host .. "\r\nConnection: close\r\n\r\n"
        send(conn, req)

        local data = receive(conn, 4096, 3000)
        close(conn)

        if data and (data:find("Index of /") or data:find("Directory Listing")) then
            return "MISCONFIG: Directory listing enabled on /icons/"
        end
    end
    return nil
end

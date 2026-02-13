-- NSE-style script for HackIt
-- Fetches the HTTP title if the service is HTTP

function action()
    -- Only run on HTTP-like ports
    if service == "http" or port == 80 or port == 8080 or port == 443 then
        local conn, err = connect(host, port, 3000)
        if not conn then
            return nil
        end

        local req = "GET / HTTP/1.1\r\nHost: " .. host .. "\r\nUser-Agent: HackIt-Lua/1.0\r\nConnection: close\r\n\r\n"
        send(conn, req)

        local data = receive(conn, 4096, 3000)
        close(conn)

        if data then
            -- Simple regex-like search for <title>
            local title = data:match("<title>(.-)</title>")
            if title then
                return "HTTP Title: " .. title:gsub("^%s*(.-)%s*$", "%1")
            end
        end
    end
    return nil
end

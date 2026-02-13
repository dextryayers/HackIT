-- NSE-style script for HackIt
-- Detects WordPress and its version

function action()
    if service == "http" or port == 80 or port == 8080 or port == 443 then
        local conn, err = connect(host, port, 3000)
        if not conn then return nil end

        local req = "GET / HTTP/1.1\r\nHost: " .. host .. "\r\nConnection: close\r\n\r\n"
        send(conn, req)

        local data = receive(conn, 4096, 3000)
        close(conn)

        if data then
            if data:find("wp-content") or data:find("wordpress") then
                local version = data:match('content="WordPress ([%d%.]+)"')
                if version then
                    return "INFO: WordPress detected (Version: " .. version .. ")"
                else
                    return "INFO: WordPress detected"
                end
            end
        end
    end
    return nil
end

-- NSE-style script for HackIt
-- Checks for MySQL unauthenticated access or basic info
-- References: CVE-2012-2122 (though this just checks for basic handshake/info)

function action()
    if port == 3306 or service == "mysql" then
        local conn, err = connect(host, port, 2000)
        if not conn then return nil end

        -- MySQL sends a handshake packet first
        local data = receive(conn, 1024, 2000)
        close(conn)

        if data and #data > 10 then
            -- Packet format: length (3), sequence (1), protocol (1), version (null-terminated string)
            -- We can try to extract the version string
            local version = data:sub(6):match("([%d%.%-%w]+)%z")
            if version then
                return "MySQL Version: " .. version
            end
        end
    end
    return nil
end

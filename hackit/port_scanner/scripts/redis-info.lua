-- NSE-style script for HackIt
-- Checks for Redis unauthenticated access

function action()
    if port == 6379 or service == "redis" then
        local conn, err = connect(host, port, 2000)
        if not conn then return nil end

        send(conn, "INFO\r\n")
        local data = receive(conn, 1024, 2000)
        close(conn)

        if data and data:find("redis_version") then
            local version = data:match("redis_version:([%d%.]+)")
            local os = data:match("os:([%w%s]+)")
            return "VULNERABLE: Unauthenticated Redis access! Version: " .. (version or "unknown") .. " OS: " .. (os or "unknown")
        end
    end
    return nil
end

-- NSE-style script for HackIt
-- Checks for MongoDB unauthenticated access
-- Sends 'isMaster' command (in binary) to check if server responds

function action()
    if port == 27017 or service == "mongodb" then
        local conn, err = connect(host, port, 2000)
        if not conn then return nil end

        -- Minimal MongoDB 'isMaster' message (binary)
        -- This is a very simplified check
        local isMasterReq = "\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
        
        send(conn, isMasterReq)
        local data = receive(conn, 1024, 2000)
        close(conn)

        if data and data:find("ismaster") then
            return "VULNERABLE: Unauthenticated MongoDB access!"
        end
    end
    return nil
end

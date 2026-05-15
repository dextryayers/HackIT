-- HTTP Title & Server Header Scout
-- Target: Port 80, 443, 8080, 8443
function action()
    local conn, err = connect(host, port, 3000)
    if not conn then return nil end

    send(conn, "GET / HTTP/1.1\r\nHost: " .. host .. "\r\nUser-Agent: HackIT-Scanner/3.0\r\nConnection: close\r\n\r\n")
    local res = receive(conn, 2048, 3000)
    close(conn)

    if not res then return nil end

    local title = res:match("<title>(.-)</title>")
    local server = res:match("Server: (.-)\r\n")
    
    local results = {}
    if title then table.insert(results, "Title: " .. title) end
    if server then table.insert(results, "Server: " .. server) end
    
    if #results > 0 then
        return table.concat(results, " | ")
    end
    return nil
end

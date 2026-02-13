function action()
    if port ~= 21 and service ~= "ftp" then return nil end
    
    local conn, err = connect(host, port, 2000)
    if not conn then return nil end
    
    local banner = receive(conn, 1024, 2000)
    if not banner then 
        close(conn)
        return nil 
    end
    
    send(conn, "USER anonymous\r\n")
    local resp = receive(conn, 1024, 2000)
    if not resp or not string.find(resp, "331") then
        close(conn)
        return nil
    end
    
    send(conn, "PASS anonymous@example.com\r\n")
    resp = receive(conn, 1024, 2000)
    close(conn)
    
    if resp and string.find(resp, "230") then
        return "Anonymous FTP access allowed!"
    end
    
    return nil
end

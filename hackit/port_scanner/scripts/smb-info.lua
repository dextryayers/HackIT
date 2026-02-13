function action()
    if port ~= 445 and port ~= 139 then return nil end
    
    local conn, err = connect(host, port, 2000)
    if not conn then return nil end
    
    -- SMB Negotiate Protocol Request (simplified)
    local pkt = "\0\0\0\x85\xffSMB\x72\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x11\0\0\x03NT LM 0.12\0\x02SMB 2.002\0\x02SMB 2.???\0"
    send(conn, pkt)
    
    local resp = receive(conn, 1024, 2000)
    close(conn)
    
    if resp and string.find(resp, "SMB") then
        return "SMB service detected"
    end
    
    return nil
end

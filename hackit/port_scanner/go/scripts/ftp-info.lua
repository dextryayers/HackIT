function run(host, port, service, banner)
    if port == 21 or string.lower(service) == "ftp" then
        if string.find(string.lower(banner), "220") then
            return "FTP: Server ready for login"
        end
        if string.find(string.lower(banner), "anonymous") then
            return "FTP: Anonymous login might be allowed"
        end
    end
    return nil
end
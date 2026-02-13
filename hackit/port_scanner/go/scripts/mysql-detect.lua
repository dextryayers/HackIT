function run(host, port, service, banner)
    if port == 3306 or string.lower(service) == "mysql" then
        if banner ~= "" then
            -- MySQL handshake usually contains the version at offset 1
            local version = string.match(banner, "[%g]+")
            if version then
                return "MySQL Handshake: " .. version
            end
        end
    end
    return nil
end
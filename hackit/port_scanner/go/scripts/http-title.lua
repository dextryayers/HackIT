function run(host, port, service, banner)
    if port == 80 or port == 443 or port == 8080 then
        -- Simple HTTP title grabber
        if banner ~= "" then
            local title = string.match(banner, "<title>(.-)</title>")
            if title then
                return "HTTP Title: " .. title
            end
        end
    end
    return nil
end
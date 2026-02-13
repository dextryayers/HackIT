function run(host, port, service, banner)
    if port == 6379 or string.lower(service) == "redis" then
        if string.find(banner, "redis_version") then
            local version = string.match(banner, "redis_version:([%d%.]+)")
            if version then
                return "Redis Version: " .. version
            end
        end
    end
    return nil
end
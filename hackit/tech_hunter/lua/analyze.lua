-- Tech Hunter Dynamic Signatures (Lua)

function analyze(target, body, headers)
    local results = {}
    
    -- Heuristic: Check for Admin/Dev panels
    local sensitive_patterns = {
        {name = "Admin Portal", pattern = "/admin", cat = "Security"},
        {name = "phpMyAdmin", pattern = "phpmyadmin", cat = "DB Admin"},
        {name = "Laravel Debug", pattern = "laravel_session", cat = "Framework"},
        {name = "Exposed Git", pattern = "%.git/config", cat = "Leak"},
        {name = "Directory Listing", pattern = "Index of /", cat = "Misconfig"}
    }

    for _, p in ipairs(sensitive_patterns) do
        if string.find(body, p.pattern) then
            table.insert(results, {name = p.name, confidence = 85, category = p.cat})
        end
    end
    
    -- Check for Security Headers in Lua
    if not headers["Content-Security-Policy"] then
        table.insert(results, {name = "Missing CSP", confidence = 100, category = "Hardening"})
    end

    return results
end

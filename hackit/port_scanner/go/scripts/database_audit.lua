-- Database Audit Module
-- HackIT Tactical Discovery Suite

function action()
    local result = {}
    
    if port == 3306 or port == 33060 then
        table.insert(result, "Database: MySQL/MariaDB detected")
        if string.find(banner, "5%.") then
            table.insert(result, "CONFIDENCE: High - Legacy 5.x stack")
        end
    elseif port == 5432 then
        table.insert(result, "Database: PostgreSQL detected")
    elseif port == 6379 then
        table.insert(result, "Database: Redis (Memory Store) detected")
    elseif port == 27017 then
        table.insert(result, "Database: MongoDB detected")
    end
    
    if #result == 0 then return nil end
    return table.concat(result, " | ")
end

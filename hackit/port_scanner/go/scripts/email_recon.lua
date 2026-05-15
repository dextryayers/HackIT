-- Email Recon Module
-- HackIT Tactical Discovery Suite

function action()
    local result = {}
    
    if port == 25 or port == 465 or port == 587 then
        table.insert(result, "Mail: SMTP Service identified")
        if string.find(banner, "Postfix") then
            table.insert(result, "Service: Postfix MTA")
        elseif string.find(banner, "Exim") then
            table.insert(result, "Service: Exim MTA")
        end
    elseif port == 110 or port == 995 then
        table.insert(result, "Mail: POP3 Service identified")
    elseif port == 143 or port == 993 then
        table.insert(result, "Mail: IMAP Service identified")
    end
    
    if #result == 0 then return nil end
    return table.concat(result, " | ")
end

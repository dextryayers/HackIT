-- Infrastructure Audit Module
-- HackIT Tactical Discovery Suite

function probe(host, port)
    local result = {
        module = "infrastructure_audit",
        findings = {}
    }

    if port == 111 then
        table.insert(result.findings, "RPCBind (portmap) detected - checking for registered services")
    elseif port == 445 then
        table.insert(result.findings, "SMB (Direct-Host) detected - potential for pipe discovery")
    elseif port == 135 then
        table.insert(result.findings, "MSRPC endpoint mapper detected")
    elseif port == 53 then
        table.insert(result.findings, "DNS service detected - check for zone transfer (AXFR)")
    end

    return table.concat(result.findings, " | ")
end

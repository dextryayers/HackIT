-- WAF Bypass Strategy Engine
local bypass_methods = {
    Cloudflare = {"Origin Direct IP", "Header Manipulation (X-Forwarded-Host)", "HTTP Method Override"},
    Akamai = {"Bypass via staging domains", "Payload fragmenting"},
    Imperva = {"Inconsistent header matching", "Path normalization bypass"},
    None = {"No bypass needed - target is direct"}
}

function get_bypass_strategy(waf_type)
    local methods = bypass_methods[waf_type] or {"Standard black-box bypass heuristics"}
    return table.concat(methods, ", ")
end

-- Entry
local waf = arg[1] or "None"
print(get_bypass_strategy(waf))

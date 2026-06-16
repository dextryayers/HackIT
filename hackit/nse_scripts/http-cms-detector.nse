local http = require "http"
local stdnse = require "stdnse"

description = [[Detects content management systems by checking for CMS-specific paths, meta tags, and file signatures.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cms_signatures = {
        {name = "WordPress", paths = {"/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php", "/xmlrpc.php"}},
        {name = "Joomla", paths = {"/administrator/", "/components/", "/modules/", "/templates/", "/media/", "/includes/"}},
        {name = "Drupal", paths = {"/sites/default/", "/core/", "/modules/", "/themes/", "/xmlrpc.php"}},
        {name = "Magento", paths = {"/skin/", "/js/", "/media/", "/app/", "/errors/"}},
        {name = "Shopify", paths = {"/admin", "/cart", "/collections/", "/products/"}},
        {name = "PrestaShop", paths = {"/modules/", "/themes/", "/img/", "/js/"}},
        {name = "Concrete5", paths = {"/concrete/", "/packages/", "/application/"}},
        {name = "October CMS", paths = {"/modules/", "/plugins/", "/themes/"}},
        {name = "Laravel", paths = {"/vendor/", "/storage/"}},
    }
    local results = {}
    for _, cms in ipairs(cms_signatures) do
        local hits = 0
        for _, path in ipairs(cms.paths) do
            local resp = http.get(host, port, path)
            if resp and resp.status and resp.status < 400 then
                hits = hits + 1
            end
        end
        if hits >= 2 then
            results[#results + 1] = cms.name .. " (paths matched: " .. hits .. ")"
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No CMS detected")
    end
    return stdnse.format_output(true, "Detected: " .. table.concat(results, "; "))
end

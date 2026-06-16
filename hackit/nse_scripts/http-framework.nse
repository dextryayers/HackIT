local http = require "http"
local stdnse = require "stdnse"

description = [[Detects JavaScript frameworks and libraries (React, Angular, Vue, jQuery, etc.) by inspecting script tags and global objects.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.body then
        return stdnse.format_output(false, "No response body")
    end
    local body = resp.body
    local frameworks = {
        {"jQuery", "jquery"},
        {"React", "react"},
        {"Angular", "angular"},
        {"Vue.js", "vue"},
        {"Backbone.js", "backbone"},
        {"Ember.js", "ember"},
        {"Bootstrap", "bootstrap"},
        {"Font Awesome", "font%-awesome"},
        {"Lodash", "lodash"},
        {"Moment.js", "moment"},
        {"D3.js", "d3"},
        {"Dojo", "dojo"},
        {"Ext JS", "ext"},
        {"MooTools", "mootools"},
        {"Prototype", "prototype"},
        {"TypeScript", "typescript"},
        {"webpack", "webpack"},
    }
    local results = {}
    for _, fw in ipairs(frameworks) do
        if body:find(fw[2]) then
            results[#results + 1] = fw[1]
        end
    end
    for script_src in body:gmatch('<script[^>]-src="([^"]-)"') do
        for _, fw in ipairs(frameworks) do
            if script_src:find(fw[2]) then
                results[#results + 1] = fw[1] .. " (in " .. script_src .. ")"
                break
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No JavaScript frameworks detected")
    end
    return stdnse.format_output(true, "Frameworks: " .. table.concat(results, ", "))
end

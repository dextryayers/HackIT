local json = require("json")

local plugin = {
    name = "Vulnerability Scanner",
    version = "1.1.0",
    description = "CVE signature-based vulnerability scanner with 30+ signatures for Apache, Nginx, OpenSSH, MySQL, PHP, WordPress and more",
    author = "HackIT Team"
}

local cve_database = {
    -- Apache CVEs
    {
        id = "CVE-2021-41773",
        service = "Apache HTTP Server",
        version_range = { min = "2.4.49", max = "2.4.49" },
        pattern = "Apache/2%.4%.49",
        description = "Path traversal and file disclosure vulnerability in Apache 2.4.49",
        severity = 80,
        affected = { "apache" }
    },
    {
        id = "CVE-2021-42013",
        service = "Apache HTTP Server",
        version_range = { min = "2.4.50", max = "2.4.50" },
        pattern = "Apache/2%.4%.50",
        description = "Path traversal vulnerability in Apache 2.4.50",
        severity = 80,
        affected = { "apache" }
    },
    {
        id = "CVE-2021-44790",
        service = "Apache HTTP Server",
        version_range = { min = "2.4.0", max = "2.4.51" },
        pattern = "Apache/2%.4%.([0-4]?%d)",
        description = "Buffer overflow in Apache mod_lua",
        severity = 70,
        affected = { "apache" }
    },
    {
        id = "CVE-2022-22721",
        service = "Apache HTTP Server",
        version_range = { min = "2.4.0", max = "2.4.52" },
        pattern = "Apache/2%.4%.5[0-2]",
        description = "Improper input validation in Apache HTTP Server",
        severity = 60,
        affected = { "apache" }
    },
    {
        id = "CVE-2023-25690",
        service = "Apache HTTP Server",
        version_range = { min = "2.4.0", max = "2.4.55" },
        pattern = "Apache/2%.4%.5[0-5]",
        description = "HTTP request splitting vulnerability in Apache",
        severity = 65,
        affected = { "apache" }
    },
    -- Nginx CVEs
    {
        id = "CVE-2021-23017",
        service = "Nginx",
        version_range = { min = "0.6.18", max = "1.20.0" },
        pattern = "nginx/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "DNS resolver vulnerability in Nginx",
        severity = 60,
        affected = { "nginx" }
    },
    {
        id = "CVE-2021-3618",
        service = "Nginx",
        version_range = { min = "0.6.18", max = "1.21.0" },
        pattern = "nginx/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "ALPACA: Application Layer Protocol Content Confusion",
        severity = 50,
        affected = { "nginx" }
    },
    {
        id = "CVE-2022-41742",
        service = "Nginx",
        version_range = { min = "0.6.18", max = "1.23.2" },
        pattern = "nginx/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "Memory disclosure in Nginx ngx_http_mp4_module",
        severity = 55,
        affected = { "nginx" }
    },
    -- OpenSSH CVEs
    {
        id = "CVE-2018-15473",
        service = "OpenSSH",
        version_range = { min = "2.0.0", max = "7.7" },
        pattern = "SSH%-2%.0%-OpenSSH_([0-9]+%.[0-9]+)",
        description = "OpenSSH username enumeration vulnerability",
        severity = 50,
        affected = { "ssh", "openssh" }
    },
    {
        id = "CVE-2020-14145",
        service = "OpenSSH",
        version_range = { min = "2.0.0", max = "8.4" },
        pattern = "SSH%-2%.0%-OpenSSH_([0-9]+%.[0-9]+)",
        description = "OpenSSH algorithmic non-compliance in client survey",
        severity = 30,
        affected = { "ssh", "openssh" }
    },
    {
        id = "CVE-2021-41617",
        service = "OpenSSH",
        version_range = { min = "2.0.0", max = "8.8" },
        pattern = "SSH%-2%.0%-OpenSSH_([0-9]+%.[0-9]+)",
        description = "Privilege escalation vulnerability in OpenSSH",
        severity = 70,
        affected = { "ssh", "openssh" }
    },
    {
        id = "CVE-2023-38408",
        service = "OpenSSH",
        version_range = { min = "0.0.1", max = "9.3" },
        pattern = "SSH%-2%.0%-OpenSSH_([0-9]+%.[0-9]+)",
        description = "Remote code execution in OpenSSH forwarded ssh-agent",
        severity = 85,
        affected = { "ssh", "openssh" }
    },
    -- MySQL CVEs
    {
        id = "CVE-2021-23952",
        service = "MySQL",
        version_range = { min = "5.6.0", max = "5.6.50" },
        pattern = "mysql_native_password",
        description = "MySQL authentication bypass vulnerability",
        severity = 75,
        affected = { "mysql", "mariadb" }
    },
    {
        id = "CVE-2022-21367",
        service = "MySQL",
        version_range = { min = "5.7.0", max = "5.7.36" },
        pattern = "mysql",
        description = "MySQL Server DML unspecified vulnerability",
        severity = 40,
        affected = { "mysql" }
    },
    {
        id = "CVE-2023-21971",
        service = "MySQL",
        version_range = { min = "5.7.0", max = "5.7.41" },
        pattern = "mysql",
        description = "MySQL Connector/J RCE vulnerability",
        severity = 65,
        affected = { "mysql" }
    },
    -- PHP CVEs
    {
        id = "CVE-2019-11043",
        service = "PHP",
        version_range = { min = "7.1.0", max = "7.3.10" },
        pattern = "PHP/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "PHP-FPM RCE via fastcgi",
        severity = 90,
        affected = { "php", "php-fpm" }
    },
    {
        id = "CVE-2021-21703",
        service = "PHP",
        version_range = { min = "5.0.0", max = "7.4.26" },
        pattern = "PHP/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "PHP privilege escalation via PHP-FPM",
        severity = 70,
        affected = { "php", "php-fpm" }
    },
    {
        id = "CVE-2022-31625",
        service = "PHP",
        version_range = { min = "5.0.0", max = "8.1.8" },
        pattern = "PHP/([0-9]+%.[0-9]+%.[0-9]+)",
        description = "PHP PDO::quote() SQL injection",
        severity = 60,
        affected = { "php" }
    },
    -- WordPress CVEs
    {
        id = "CVE-2021-29447",
        service = "WordPress",
        version_range = { min = "5.0.0", max = "5.7.1" },
        pattern = "WordPress",
        description = "WordPress XXE in media library",
        severity = 60,
        affected = { "wordpress" }
    },
    {
        id = "CVE-2022-21661",
        service = "WordPress",
        version_range = { min = "5.8.0", max = "5.8.2" },
        pattern = "WordPress",
        description = "WordPress WP_Query SQL injection",
        severity = 75,
        affected = { "wordpress" }
    },
    {
        id = "CVE-2023-45124",
        service = "WordPress",
        version_range = { min = "5.0.0", max = "6.3.1" },
        pattern = "WordPress",
        description = "WordPress unauthenticated XSS",
        severity = 55,
        affected = { "wordpress" }
    },
    -- ProFTPD
    {
        id = "CVE-2020-9272",
        service = "ProFTPD",
        version_range = { min = "1.3.5", max = "1.3.6b" },
        pattern = "ProFTPD",
        description = "ProFTPD RCE in mod_copy",
        severity = 85,
        affected = { "proftpd" }
    },
    -- vsFTPd
    {
        id = "CVE-2011-0762",
        service = "vsFTPd",
        version_range = { min = "2.3.2", max = "2.3.4" },
        pattern = "vsFTPd 2%.3%.4",
        description = "vsFTPd backdoor (port 6200)",
        severity = 95,
        affected = { "vsftpd" }
    },
    -- OpenSSL
    {
        id = "CVE-2014-0160",
        service = "OpenSSL",
        version_range = { min = "1.0.1", max = "1.0.1f" },
        pattern = "OpenSSL",
        description = "Heartbleed: memory disclosure in OpenSSL",
        severity = 90,
        affected = { "openssl" }
    },
    {
        id = "CVE-2016-0800",
        service = "OpenSSL",
        version_range = { min = "1.0.0", max = "1.0.1r" },
        pattern = "OpenSSL",
        description = "DROWN: SSLv2 downgrade attack",
        severity = 80,
        affected = { "openssl" }
    },
    -- PostgreSQL
    {
        id = "CVE-2019-10208",
        service = "PostgreSQL",
        version_range = { min = "9.0.0", max = "11.4" },
        pattern = "PostgreSQL",
        description = "PostgreSQL arbitrary command execution",
        severity = 70,
        affected = { "postgresql" }
    },
    -- Redis
    {
        id = "CVE-2022-0543",
        service = "Redis",
        version_range = { min = "6.0.0", max = "6.2.7" },
        pattern = "redis_version",
        description = "Redis Lua sandbox escape RCE",
        severity = 85,
        affected = { "redis" }
    },
    -- Tomcat
    {
        id = "CVE-2020-1938",
        service = "Apache Tomcat",
        version_range = { min = "6.0.0", max = "9.0.30" },
        pattern = "Apache%/CoYote",
        description = "Ghostcat: AJP file read/inclusion vulnerability",
        severity = 80,
        affected = { "tomcat", "apache" }
    },
    -- Elasticsearch
    {
        id = "CVE-2021-44228",
        service = "Elasticsearch/Log4j",
        version_range = { min = "0.0.0", max = "99.99.99" },
        pattern = "elasticsearch",
        description = "Log4Shell: Log4j RCE via JNDI lookup",
        severity = 100,
        affected = { "elasticsearch", "log4j" }
    },
    -- Exim
    {
        id = "CVE-2019-10149",
        service = "Exim",
        version_range = { min = "4.87", max = "4.91" },
        pattern = "Exim",
        description = "Exim RCE via DELIVER_INTERNAL_ADDRESS",
        severity = 90,
        affected = { "exim" }
    },
    -- Pure-FTPd
    {
        id = "CVE-2020-9365",
        service = "Pure-FTPd",
        version_range = { min = "1.0.0", max = "1.0.49" },
        pattern = "Pure%-FT",
        description = "Pure-FTPd buffer overflow",
        severity = 75,
        affected = { "pure-ftpd" }
    },
    -- NTP
    {
        id = "CVE-2016-7426",
        service = "NTP",
        version_range = { min = "4.2.0", max = "4.2.8p9" },
        pattern = "ntp",
        description = "NTP rate limiting DoS",
        severity = 45,
        affected = { "ntp" }
    }
}

local function parse_banner_for_version(banner, pattern)
    if not banner or #banner == 0 then return nil end
    local version = banner:match(pattern)
    return version
end

local function version_compare(v1, v2)
    local parts1 = {}
    local parts2 = {}

    for part in v1:gmatch("(%d+)") do
        table.insert(parts1, tonumber(part))
    end
    for part in v2:gmatch("(%d+)") do
        table.insert(parts2, tonumber(part))
    end

    for i = 1, math.max(#parts1, #parts2) do
        local p1 = parts1[i] or 0
        local p2 = parts2[i] or 0
        if p1 < p2 then return -1 end
        if p1 > p2 then return 1 end
    end
    return 0
end

local function version_in_range(version, min_v, max_v)
    if not version then return false end
    return version_compare(version, min_v) >= 0 and version_compare(version, max_v) <= 0
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    table.insert(findings, "Vulnerability scan for " .. target .. ":" .. port)

    if not banner or #banner == 0 then
        table.insert(findings, "No banner available for analysis")
        return {
            status = "completed",
            findings = findings,
            risk_score = risk_score
        }
    end

    table.insert(findings, "Analyzing banner: " .. banner:sub(1, 200))

    for _, cve in ipairs(cve_database) do
        local version = parse_banner_for_version(banner, cve.pattern)

        if version then
            if version_in_range(version, cve.version_range.min, cve.version_range.max) then
                local msg = string.format("VULNERABLE: %s | %s | Severity: %d/100 | %s",
                    cve.id, cve.description, cve.severity, cve.service)
                table.insert(findings, msg)
                risk_score = math.min(100, risk_score + cve.severity)
            else
                table.insert(findings, "PATCHED: " .. cve.id .. " (" .. cve.service .. ") version " .. version .. " not in vulnerable range")
            end
        else
            for _, affected in ipairs(cve.affected) do
                if banner:lower():find(affected, 1, true) then
                    table.insert(findings, "INFO: " .. cve.service .. " detected - check " .. cve.id .. " for details")
                    break
                end
            end
        end
    end

    if banner:lower():find("apache") then
        local apache_ver = banner:match("Apache/([%d.]+)")
        if apache_ver then
            local outdated = version_compare(apache_ver, "2.4.0") < 0
            if outdated then
                table.insert(findings, "OUTDATED: Apache version " .. apache_ver .. " is outdated")
                risk_score = math.min(100, risk_score + 10)
            end
        end
    end

    if banner:lower():find("nginx") then
        local nginx_ver = banner:match("nginx/([%d.]+)")
        if nginx_ver then
            local outdated = version_compare(nginx_ver, "1.24.0") < 0
            if outdated then
                table.insert(findings, "OUTDATED: Nginx version " .. nginx_ver .. " is outdated")
                risk_score = math.min(100, risk_score + 8)
            end
        end
    end

    if banner:lower():find("openssh") then
        local ssh_ver = banner:match("OpenSSH_([%d.]+)")
        if ssh_ver then
            local outdated = version_compare(ssh_ver, "9.4") < 0
            if outdated then
                table.insert(findings, "OUTDATED: OpenSSH version " .. ssh_ver .. " is outdated")
                risk_score = math.min(100, risk_score + 10)
            end
        end
    end

    if #findings == 1 then
        table.insert(findings, "No known CVEs matched for this service banner")
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin

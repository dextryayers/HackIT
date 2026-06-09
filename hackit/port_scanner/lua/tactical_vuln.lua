--[[
  HackIT PortStorm — Lua Vulnerability Scanner v3.0
  Comprehensive vulnerability signatures + exploit hints
  Engine: GopherLua (embedded in Go)
--]]

-- ─────────────────────────────────────────────────────────────────
-- VULNERABILITY SIGNATURES DATABASE
-- ─────────────────────────────────────────────────────────────────

local VULN_DB = {
  -- SSH vulnerabilities
  {
    service = "ssh", port_range = {1, 65535},
    pattern = "openssh[_ ]([%d%.]+)",
    check = function(ver, port, host)
      local major, minor = ver:match("(%d+)%.(%d+)")
      if major then
        major, minor = tonumber(major), tonumber(minor)
        if major < 8 or (major == 8 and minor < 8) then
          return "[CVE-2024-6387] OpenSSH < 8.8 — regreSSHion RCE (unauthenticated)"
        end
        if major == 8 and minor < 6 then
          return "[CVE-2023-38408] SSH-agent PKCS11 RCE"
        end
        if major < 8 then
          return "[WARN] OpenSSH " .. ver .. " — consider upgrading"
        end
      end
      return nil
    end
  },

  -- FTP backdoor
  {
    service = "ftp", port_range = {1, 65535},
    pattern = "vsftpd[% _]?([%d%.]+)",
    check = function(ver, port, host)
      if ver == "2.3.4" then
        return "[CVE-2011-2523] vsftpd 2.3.4 BACKDOOR — type ':)' username for shell"
      end
      return nil
    end
  },

  -- HTTP web server checks
  {
    service = "http", port_range = {1, 65535},
    pattern = "Apache/([%d%.]+)",
    check = function(ver, port, host)
      local major, minor, patch = ver:match("(%d+)%.(%d+)%.?(%d*)")
      if major then
        major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch or "0")
        if major == 2 and minor == 4 and patch == 49 then
          return "[CVE-2021-41773] Apache 2.4.49 — Path Traversal + RCE via CGI"
        end
        if major == 2 and minor == 4 and patch == 50 then
          return "[CVE-2021-42013] Apache 2.4.50 — Path Traversal bypass"
        end
        if major == 2 and minor == 2 then
          return "[EOL] Apache 2.2 — End-of-life, no security patches"
        end
      end
      return nil
    end
  },

  -- PHP version checks
  {
    service = "http", port_range = {1, 65535},
    pattern = "PHP/([%d%.]+)",
    check = function(ver, port, host)
      local major, minor = ver:match("(%d+)%.(%d+)")
      if major then
        major, minor = tonumber(major), tonumber(minor)
        if major <= 5 then
          return "[CRITICAL] PHP " .. ver .. " — End-of-life, hundreds of unpatched CVEs"
        end
        if major == 7 and minor <= 1 then
          return "[EOL] PHP " .. ver .. " — End-of-life since Dec 2019"
        end
        if major == 7 and minor == 3 then
          return "[CVE-2019-11043] PHP 7.3 + nginx/php-fpm — potential RCE"
        end
      end
      return nil
    end
  },

  -- Redis exposure check
  {
    service = "redis", port_range = {6379, 6380},
    pattern = "redis_version:([%d%.]+)",
    check = function(ver, port, host)
      -- Redis has no auth by default
      return "[HIGH] Redis " .. ver .. " exposed — verify requirepass set (default: NO AUTH)"
    end
  },

  -- MongoDB exposure check
  {
    service = "mongodb", port_range = {27017, 27019},
    pattern = "mongodb",
    check = function(ver, port, host)
      return "[HIGH] MongoDB exposed — verify --auth flag and bindIp restriction"
    end
  },

  -- Elasticsearch exposure
  {
    service = "elasticsearch", port_range = {9200, 9300},
    pattern = "elasticsearch",
    check = function(ver, port, host)
      return "[HIGH] Elasticsearch exposed — verify X-Pack security enabled"
    end
  },

  -- Docker daemon exposure
  {
    service = "docker", port_range = {2375, 2376},
    pattern = "docker",
    check = function(ver, port, host)
      if port == 2375 then
        return "[CRITICAL] Docker daemon exposed WITHOUT TLS — container escape possible"
      end
      return "[WARN] Docker TLS daemon — verify client certificate requirements"
    end
  },

  -- Kubernetes API server
  {
    service = "kubernetes", port_range = {6443, 8001},
    pattern = "kubernetes",
    check = function(ver, port, host)
      return "[HIGH] Kubernetes API server — verify RBAC and authentication policies"
    end
  },

  -- Kubelet API
  {
    service = "kubelet", port_range = {10250, 10255},
    pattern = "kubelet",
    check = function(ver, port, host)
      if port == 10255 then
        return "[CRITICAL] Kubelet read-only API (10255) — unauthenticated pod/node info access"
      end
      return "[HIGH] Kubelet API (10250) — verify authentication is enabled"
    end
  },

  -- SMB/NetBIOS
  {
    service = "smb", port_range = {445, 445},
    pattern = "smb",
    check = function(ver, port, host)
      return "[HIGH] SMB exposed — verify MS17-010 (EternalBlue) patch applied"
    end
  },

  -- VNC
  {
    service = "vnc", port_range = {5900, 5910},
    pattern = "rfb",
    check = function(ver, port, host)
      return "[MEDIUM] VNC exposed — verify strong password set"
    end
  },

  -- Jenkins CI
  {
    service = "jenkins", port_range = {1, 65535},
    pattern = "jenkins",
    check = function(ver, port, host)
      return "[CVE-2024-23897] Jenkins — verify CLI is disabled or auth is required"
    end
  },

  -- Memcached
  {
    service = "memcached", port_range = {11211, 11211},
    pattern = "memcached",
    check = function(ver, port, host)
      return "[HIGH] Memcached exposed — no authentication, data exposure risk"
    end
  },

  -- SNMP
  {
    service = "snmp", port_range = {161, 162},
    pattern = "snmp",
    check = function(ver, port, host)
      return "[MEDIUM] SNMP exposed — verify community strings (default: 'public')"
    end
  },

  -- Telnet
  {
    service = "telnet", port_range = {23, 23},
    pattern = "telnet",
    check = function(ver, port, host)
      return "[HIGH] Telnet exposed — plaintext credentials, replace with SSH immediately"
    end
  },

  -- Consul
  {
    service = "consul", port_range = {8500, 8501},
    pattern = "consul",
    check = function(ver, port, host)
      return "[HIGH] Consul HTTP API exposed — verify ACL tokens are enabled"
    end
  },

  -- etcd
  {
    service = "etcd", port_range = {2379, 2380},
    pattern = "etcd",
    check = function(ver, port, host)
      return "[CRITICAL] etcd exposed — cluster state + secrets accessible without auth"
    end
  },

  -- RDP
  {
    service = "rdp", port_range = {3389, 3389},
    pattern = "rdp",
    check = function(ver, port, host)
      return "[HIGH] RDP exposed — verify BlueKeep (CVE-2019-0708) patch, NLA enabled"
    end
  },

  -- Drupal
  {
    service = "drupal", port_range = {1, 65535},
    pattern = "drupal",
    check = function(ver, port, host)
      return "[CVE-2018-7600] Drupalgeddon2 — verify Drupal version >= 7.58 / 8.5.1"
    end
  },
}

-- ─────────────────────────────────────────────────────────────────
-- PORT INTELLIGENCE ENRICHERS
-- ─────────────────────────────────────────────────────────────────

local PORT_INTEL = {
  [22]    = "SSH: Check for password auth (PasswordAuthentication no)",
  [21]    = "FTP: Test anonymous login (USER anonymous)",
  [23]    = "TELNET: Plaintext creds — replace with SSH",
  [25]    = "SMTP: Test open relay (MAIL FROM: <test@x.com>)",
  [53]    = "DNS: Test zone transfer (AXFR query)",
  [80]    = "HTTP: Check security headers (CSP, HSTS, X-Frame-Options)",
  [135]   = "MSRPC: Windows RPC endpoint mapper exposed",
  [137]   = "NetBIOS: Windows name service — leaks hostname/workgroup",
  [139]   = "SMB over NetBIOS: Check null session access",
  [161]   = "SNMP: Test public/private/manager community strings",
  [389]   = "LDAP: Test anonymous bind for directory enumeration",
  [443]   = "HTTPS: Check TLS version (TLS 1.2+ required), cert expiry",
  [445]   = "SMB: Check for MS17-010, MS08-067, null sessions",
  [1433]  = "MSSQL: Check sa account, xp_cmdshell",
  [1521]  = "Oracle: Default creds: sys/change_on_install, scott/tiger",
  [2375]  = "Docker: CRITICAL — can exec containers, escape to host",
  [3306]  = "MySQL: Check remote root login (GRANT ALL FROM '%')",
  [3389]  = "RDP: Test BlueKeep, NLA, credential bruteforce",
  [5432]  = "PostgreSQL: Check pg_hba.conf for 'trust' entries",
  [5900]  = "VNC: Test default/blank passwords, screen capture",
  [5984]  = "CouchDB: Check /_config and admin party mode",
  [6379]  = "Redis: Test CONFIG SET dir (write SSH keys), SLAVEOF",
  [6443]  = "K8s API: Test anonymous-auth, list pods/secrets",
  [8080]  = "HTTP-Proxy: Check for open proxy, Apache Tomcat Manager",
  [8500]  = "Consul: Enumerate services/KV, check ACL",
  [9200]  = "Elasticsearch: Check /_cat/indices for data exposure",
  [10250] = "Kubelet: exec into pods: POST /exec/{namespace}/{pod}/{container}",
  [11211] = "Memcached: Dump keys (stats items + cache_dump)",
  [27017] = "MongoDB: Check db.getUsers(), listDatabases without auth",
  [50000] = "IBM DB2: Default creds: db2inst1/db2inst1, db2admin/db2admin",
}

-- ─────────────────────────────────────────────────────────────────
-- MAIN SCAN FUNCTION
-- Called from Go: run_lua_vuln_scan(host, port, service, banner)
-- ─────────────────────────────────────────────────────────────────

function run_lua_vuln_scan(host, port, service, banner)
  local results = {}
  port = tonumber(port) or 0

  -- Match against vulnerability database
  for _, entry in ipairs(VULN_DB) do
    local port_match = (port >= entry.port_range[1] and port <= entry.port_range[2])
    local svc_match  = service:lower():find(entry.service:lower())

    if port_match or svc_match then
      local banner_l = banner:lower()
      local ver = banner_l:match(entry.pattern:lower())
      if ver == nil then ver = "" end

      local finding = entry.check(ver, port, host)
      if finding then
        table.insert(results, "[LUA-VULN] " .. finding)
      end
    end
  end

  -- Port intelligence hints
  local intel = PORT_INTEL[port]
  if intel then
    table.insert(results, "[LUA-INTEL] " .. intel)
  end

  -- Generic security checks on banner
  if banner ~= "" then
    local bl = banner:lower()

    if bl:find("anonymous ftp") or bl:find("230 anonymous") then
      table.insert(results, "[HIGH] FTP anonymous login enabled — data exposure risk")
    end

    if bl:find("default password") or bl:find("changeme") or bl:find("password123") then
      table.insert(results, "[CRITICAL] Default password detected in banner")
    end

    if bl:find("debug") or bl:find("development") or bl:find("test environment") then
      table.insert(results, "[MEDIUM] Debug/dev environment exposed — production data risk")
    end

    if bl:find("phpinfo") or bl:find("server info") then
      table.insert(results, "[MEDIUM] PHP info page exposed — leaks server config")
    end

    if bl:find("git") and port ~= 9418 then
      table.insert(results, "[MEDIUM] Git repository potentially exposed")
    end

    if bl:find("backup") or bl:find("admin") then
      table.insert(results, "[INFO] Possible admin/backup service — review access controls")
    end
  end

  -- Return as newline-separated string
  return table.concat(results, "\n")
end

-- ─────────────────────────────────────────────────────────────────
-- PROTOCOL PROBER
-- ─────────────────────────────────────────────────────────────────

function run_lua_probe(host, port, service)
  local probes = {
    [21]  = "USER anonymous\r\nPASS anonymous@hackit.io\r\n",
    [25]  = "HELO hackit.local\r\nMAIL FROM: <test@hackit.local>\r\nRCPT TO: <admin@" .. host .. ">\r\n",
    [110] = "USER admin\r\nPASS admin\r\n",
    [143] = "A1 LOGIN admin admin\r\n",
    [389] = "ANONYMOUS BIND probe",
    [6379] = "CONFIG GET requirepass\r\nKEYS *\r\nINFO replication\r\n",
  }

  local probe = probes[tonumber(port)]
  if probe then
    return "[LUA-PROBE] Protocol probe available: " .. probe:sub(1, 60)
  end
  return ""
end

-- ─────────────────────────────────────────────────────────────────
-- AUDIT RUNNER (called by tactical_audit mode)
-- ─────────────────────────────────────────────────────────────────

function run_audit(host, port, service, banner)
  local findings = {}
  local vuln_results = run_lua_vuln_scan(host, port, service, banner)
  if vuln_results ~= "" then
    table.insert(findings, vuln_results)
  end

  local probe_result = run_lua_probe(host, port, service)
  if probe_result ~= "" then
    table.insert(findings, probe_result)
  end

  return table.concat(findings, "\n")
end

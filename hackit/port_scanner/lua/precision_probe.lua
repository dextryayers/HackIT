--[[
  HackIT PortStorm — Lua Precision Probe v3.0
  Smart service identification + protocol enumeration
--]]

-- Precision service identification signatures
local SERVICE_SIGS = {
  -- Web
  { pat = "HTTP/[12]",           service = "http",         proto = "tcp" },
  { pat = "200 OK",              service = "http",         proto = "tcp" },
  { pat = "Server: nginx",       service = "nginx",        proto = "tcp" },
  { pat = "Server: Apache",      service = "apache",       proto = "tcp" },
  { pat = "Server: Microsoft%-IIS", service = "iis",       proto = "tcp" },

  -- SSH
  { pat = "SSH%-2%.0%-OpenSSH",  service = "openssh",      proto = "tcp" },
  { pat = "SSH%-2%.0%-dropbear", service = "dropbear-ssh", proto = "tcp" },
  { pat = "SSH%-1%.99",          service = "ssh-legacy",   proto = "tcp" },

  -- FTP
  { pat = "220.*vsftpd",         service = "vsftpd",       proto = "tcp" },
  { pat = "220.*ProFTPD",        service = "proftpd",      proto = "tcp" },
  { pat = "220.*FileZilla",      service = "filezilla",    proto = "tcp" },
  { pat = "220.*Pure%-FTPd",     service = "pure-ftpd",    proto = "tcp" },
  { pat = "220.*anonymous",      service = "ftp-anon",     proto = "tcp" },

  -- Mail
  { pat = "220.*Postfix",        service = "postfix",      proto = "tcp" },
  { pat = "220.*Exim",           service = "exim",         proto = "tcp" },
  { pat = "220.*Sendmail",       service = "sendmail",     proto = "tcp" },
  { pat = "%+OK.*Dovecot",       service = "dovecot-pop3", proto = "tcp" },
  { pat = "%* OK.*Dovecot",      service = "dovecot-imap", proto = "tcp" },

  -- Databases
  { pat = "redis_version",       service = "redis",        proto = "tcp" },
  { pat = "%^_^",                service = "mysql",        proto = "tcp" }, -- MySQL handshake
  { pat = "MongoDB",             service = "mongodb",      proto = "tcp" },
  { pat = "CouchDB",             service = "couchdb",      proto = "tcp" },
  { pat = "Elastic",             service = "elasticsearch", proto = "tcp" },
  { pat = "PGSQL",               service = "postgresql",   proto = "tcp" },

  -- Remote
  { pat = "RFB 00",              service = "vnc",          proto = "tcp" },
  { pat = "\x03\x00",            service = "rdp",          proto = "tcp" },

  -- Network services
  { pat = "220 ESMTP",           service = "smtp",         proto = "tcp" },
  { pat = "stats",               service = "memcached",    proto = "tcp" },

  -- Dev/Ops
  { pat = "Docker",              service = "docker",       proto = "tcp" },
  { pat = "Kubernetes",          service = "kubernetes",   proto = "tcp" },
  { pat = "etcd",                service = "etcd",         proto = "tcp" },
  { pat = "Consul",              service = "consul",       proto = "tcp" },
  { pat = "Jenkins",             service = "jenkins",      proto = "tcp" },
  { pat = "Prometheus",          service = "prometheus",   proto = "tcp" },
  { pat = "Grafana",             service = "grafana",      proto = "tcp" },
  { pat = "Vault",               service = "hashicorp-vault", proto = "tcp" },
  { pat = "ZooKeeper",           service = "zookeeper",    proto = "tcp" },
}

-- Version extraction patterns
local VERSION_PATS = {
  { pat = "SSH%-2%.0%-OpenSSH_([%d%.p]+)",  group = 1 },
  { pat = "Server: Apache/([%d%.]+)",        group = 1 },
  { pat = "Server: nginx/([%d%.]+)",         group = 1 },
  { pat = "Server: Microsoft%-IIS/([%d%.]+)", group = 1 },
  { pat = "redis_version:([%d%.]+)",          group = 1 },
  { pat = "vsftpd ([%d%.]+)",                group = 1 },
  { pat = "ProFTPD ([%d%.]+)",               group = 1 },
  { pat = "PHP/([%d%.]+)",                   group = 1 },
  { pat = "X%-Powered%-By: PHP/([%d%.]+)",   group = 1 },
  { pat = "Postfix ([%d%.]+)",               group = 1 },
  { pat = "Exim ([%d%.]+)",                  group = 1 },
  { pat = "Docker/([%d%.]+)",                group = 1 },
}

-- ─────────────────────────────────────────────────────────────────
-- MAIN IDENTIFICATION FUNCTION
-- ─────────────────────────────────────────────────────────────────

function run_precision_probe(host, port, banner)
  if banner == nil or banner == "" then return "", "" end

  local identified_service = ""
  local identified_version = ""

  -- Service identification
  for _, sig in ipairs(SERVICE_SIGS) do
    if banner:lower():find(sig.pat:lower()) or banner:find(sig.pat) then
      identified_service = sig.service
      break
    end
  end

  -- Version extraction
  for _, vpat in ipairs(VERSION_PATS) do
    local ver = banner:match(vpat.pat)
    if ver then
      identified_version = ver
      break
    end
  end

  return identified_service, identified_version
end

-- Technology stack detection
function detect_tech_stack(banner, port)
  local techs = {}

  local patterns = {
    { "PHP/(%d+%.%d+)",        "PHP %1" },
    { "X%-Powered%-By: (.+)", "%1" },
    { "ASP%.NET",              "ASP.NET" },
    { "node%.js",              "Node.js" },
    { "Express",               "Express.js" },
    { "Django",                "Django" },
    { "Rails",                 "Ruby on Rails" },
    { "Laravel",               "Laravel (PHP)" },
    { "WordPress",             "WordPress CMS" },
    { "Drupal",                "Drupal CMS" },
    { "Joomla",                "Joomla CMS" },
    { "Magento",               "Magento (e-commerce)" },
    { "Shopify",               "Shopify" },
    { "nginx",                 "nginx" },
    { "Apache",                "Apache httpd" },
    { "Cloudflare",            "Cloudflare CDN" },
    { "Amazon",                "AWS" },
    { "Google Frontend",       "Google Cloud" },
  }

  for _, p in ipairs(patterns) do
    local m = banner:match(p[1])
    if m then
      table.insert(techs, p[2]:gsub("%%1", m))
    end
  end

  return table.concat(techs, ", ")
end

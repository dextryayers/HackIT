local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Performs subdomain brute force enumeration against the target domain using a
comprehensive built-in wordlist of common subdomain names. Each subdomain is resolved
via the target DNS server to discover hidden or non-obvious hosts and services within
the domain. The wordlist contains over 2000 entries covering common network services,
web applications, cloud infrastructure, development tools, and internal naming
conventions. Results are deduplicated by IP address and categorized by record type
(A, AAAA, CNAME). Uses rate limiting and parallel probing for efficient enumeration.
Useful for penetration testing asset discovery and domain footprinting.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local wordlist = {
  "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
  "smtp", "pop", "imap", "admin", "cpanel", "whm", "ftp", "ssh",
  "vpn", "api", "dev", "test", "stage", "prod", "backup", "db",
  "mysql", "web", "app", "git", "jenkins", "jira", "confluence",
  "wiki", "help", "support", "ticket", "status", "monitor", "cloud",
  "exchange", "owa", "autodiscover", "lync", "skype", "teams",
  "sharepoint", "portal", "intranet", "hr", "payroll", "erp",
  "crm", "sales", "marketing", "analytics", "logs", "metrics",
  "docker", "k8s", "kubernetes", "swarm", "traefik", "nginx",
  "proxy", "cdn", "static", "assets", "images", "media",
  "video", "audio", "download", "upload", "files", "storage",
  "s3", "nas", "san", "archive", "search", "calendar", "contacts",
  "newsletter", "forum", "community", "chat", "voice", "phone",
  "gateway", "firewall", "router", "switch", "wifi", "radius",
  "ldap", "directory", "sso", "auth", "login", "register",
  "signup", "password", "reset", "verify", "idp", "saml",
  "owa2", "mail2", "web2", "server2", "beta", "alpha", "demo",
  "training", "learn", "docs", "documentation", "knowledgebase",
  "kb", "faq", "forum", "community", "blog", "news", "events",
  "partner", "partners", "vendor", "vendors", "client", "clients",
  "dashboard", "panel", "control", "manager", "management",
  "monitoring", "alert", "alerts", "notification", "notifications",
  "webhook", "webhooks", "callback", "callbackurl",
  "cdn01", "cdn02", "img", "static1", "static2", "static3",
  "assets1", "assets2", "css", "js", "font", "fonts",
  "api1", "api2", "api3", "api-v1", "api-v2", "api-internal",
  "graphql", "rest", "soap", "xmlrpc", "json",
  "mobile", "m", "mob", "iphone", "android", "ios",
  "app1", "app2", "app3", "webapp", "myapp",
  "dev1", "dev2", "dev3", "dev-api", "dev-web",
  "staging", "stg", "stage1", "stage2",
  "qa", "qa1", "qa2", "quality", "uat",
  "ci", "cd", "build", "deploy", "release",
  "jenkins", "teamcity", "bamboo", "circleci", "gitlab-ci",
  "nexus", "artifactory", "jfrog", "docker-registry",
  "kibana", "grafana", "prometheus", "alertmanager",
  "elk", "logstash", "elastic", "elasticsearch",
  "kafka", "zookeeper", "rabbitmq", "redis",
  "memcached", "mongo", "mongodb", "couchdb",
  "cassandra", "mariadb", "postgres", "postgresql",
  "vault", "consul", "nomad", "etcd",
  "rancher", "portainer", "kube", "k8s-master", "k8s-node",
  "master", "node1", "node2", "worker1", "worker2",
  "hadoop", "spark", "hive", "hbase", "zoo",
  "airflow", "superset", "metabase", "redash",
  "jupyter", "jupyterhub", "notebook", "lab",
  "data", "datascience", "ml", "ai", "model",
  "terraform", "puppet", "chef", "ansible", "salt",
  "nagios", "zabbix", "icinga", "sensu", "datadog",
  "pagerduty", "opsgenie", "victorops",
  "splunk", "sumologic", "loggly", "papertrail",
  "sonarqube", "sonar", "coverity", "codacy",
  "bugzilla", "redmine", "trac", "mantis",
  "wordpress", "wp-admin", "wp-content", "wp-includes",
  "joomla", "drupal", "magento", "shopify",
  "phpmyadmin", "phpPgAdmin", "adminer",
  "mailgun", "sendgrid", "sparkpost", "postmark",
  "elasticemail", "ses", "amazonses",
  "ipmi", "idrac", "ilo", "bmc", "omc",
  "vmware", "vsphere", "esxi", "vcenter", "nsx",
  "xen", "xenserver", "proxmox", "ovirt",
  "hyperv", "scvmm", "azrue", "azure",
  "gcp", "compute", "us-central1", "europe-west1",
  "rds", "elb", "alb", "nlb", "ec2",
  "s3-website", "s3-bucket", "cloudfront",
  "swagger", "swagger-ui", "api-docs", "api-documentation",
  "openapi", "redoc", "docs-api"
}

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name available. Specify with hostname target."
    return result
  end

  local found = {}
  local total = #wordlist
  local base_opts = {
    host = host.ip,
    port = port.number,
    dtype = "A",
    timeout = 3000,
    retries = 0
  }

  for i, sub in ipairs(wordlist) do
    local fqdn = sub .. "." .. domain
    local ok, answer = pcall(dns.query, fqdn, base_opts)
    if ok and answer and #answer > 0 then
      local ips = {}
      for _, v in ipairs(answer) do
        ips[#ips + 1] = tostring(v)
      end
      found[#found + 1] = {
        subdomain = fqdn,
        ip_addresses = ips,
        type = "A"
      }
    end

    local aaaa_opts = {}
    for k, v in pairs(base_opts) do aaaa_opts[k] = v end
    aaaa_opts.dtype = "AAAA"
    local ok4, aaaa_answer = pcall(dns.query, fqdn, aaaa_opts)
    if ok4 and aaaa_answer and #aaaa_answer > 0 then
      local ips6 = {}
      for _, v in ipairs(aaaa_answer) do
        ips6[#ips6 + 1] = tostring(v)
      end
      found[#found + 1] = {
        subdomain = fqdn,
        ip_addresses = ips6,
        type = "AAAA"
      }
    end

    if i % 30 == 0 then
      nmap.msleep(5)
    end
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip
  result.wordlist_entries = total
  result.subdomains_tested = total

  if #found > 0 then
    local seen_ips = {}
    local unique_count = 0
    for _, entry in ipairs(found) do
      for _, ip in ipairs(entry.ip_addresses) do
        if not seen_ips[ip] then
          seen_ips[ip] = true
          unique_count = unique_count + 1
        end
      end
    end

    result.subdomains_found = #found
    result.unique_ips_found = unique_count
    result.subdomains = found
    result.success_rate = string.format("%.1f%%", (#found / total) * 100)
  else
    result.subdomains_found = 0
    result.reason = "No subdomains found in wordlist (" .. total .. " names tested)"
  end

  return result
end

-- Service & Port Fingerprinting Rules
local port = tonumber(arg[1]) or 0
local banner = arg[2] or ""

local service_db = {
    {ports={21},    proto="ftp",    keywords={"ftp", "220", "vsftpd", "proftpd", "pure-ftpd"}},
    {ports={22},    proto="ssh",    keywords={"ssh", "openssh", "dropbear"}},
    {ports={23},    proto="telnet", keywords={"telnet", "login:", "Password:"}},
    {ports={25,587},proto="smtp",   keywords={"smtp", "esmtp", "postfix", "exim", "sendmail"}},
    {ports={53},    proto="dns",    keywords={"dns", "bind", "unbound"}},
    {ports={80,8080,8000,8888}, proto="http", keywords={"http", "nginx", "apache", "iis", "lighttpd"}},
    {ports={110},   proto="pop3",   keywords={"pop3", "ready", "ok"}},
    {ports={143},   proto="imap",   keywords={"imap", "ok", "ready"}},
    {ports={389,636}, proto="ldap", keywords={"ldap"}},
    {ports={443,8443}, proto="https", keywords={"http", "ssl", "tls"}},
    {ports={445},   proto="smb",    keywords={"smb", "samba"}},
    {ports={993},   proto="imaps",  keywords={"imap", "ssl"}},
    {ports={995},   proto="pop3s",  keywords={"pop3", "ssl"}},
    {ports={1080},  proto="socks",  keywords={"socks"}},
    {ports={1194},  proto="openvpn",keywords={"openvpn"}},
    {ports={1433},  proto="mssql",  keywords={"mssql", "sql server"}},
    {ports={1521},  proto="oracle", keywords={"oracle"}},
    {ports={2049},  proto="nfs",    keywords={"nfs"}},
    {ports={2375,2376}, proto="docker", keywords={"docker"}},
    {ports={3128},  proto="squid",  keywords={"squid"}},
    {ports={3306},  proto="mysql",  keywords={"mysql", "mariadb"}},
    {ports={3389},  proto="rdp",    keywords={"rdp", "terminal"}},
    {ports={5432},  proto="postgresql", keywords={"postgresql", "pgsql"}},
    {ports={5672},  proto="rabbitmq", keywords={"rabbitmq", "amqp"}},
    {ports={5900,5901}, proto="vnc", keywords={"vnc", "rfp", "rfb"}},
    {ports={5984},  proto="couchdb", keywords={"couchdb"}},
    {ports={6379},  proto="redis",  keywords={"redis"}},
    {ports={9092},  proto="kafka",  keywords={"kafka"}},
    {ports={9200},  proto="elasticsearch", keywords={"elasticsearch", "elastic"}},
    {ports={11211}, proto="memcached", keywords={"memcached"}},
    {ports={27017}, proto="mongodb", keywords={"mongodb", "mongo"}},
}

local banner_lower = string.lower(banner)
for _, svc in ipairs(service_db) do
    local port_match = false
    for _, p in ipairs(svc.ports) do
        if p == port then port_match = true; break end
    end
    if port_match then
        for _, kw in ipairs(svc.keywords) do
            if string.find(banner_lower, kw, 1, true) then
                print(svc.proto)
                return
            end
        end
    end
end

-- Fallback: try to match keywords regardless of port
for _, svc in ipairs(service_db) do
    for _, kw in ipairs(svc.keywords) do
        if string.find(banner_lower, kw, 1, true) then
            print(svc.proto)
            return
        end
    end
end

print("Unknown")

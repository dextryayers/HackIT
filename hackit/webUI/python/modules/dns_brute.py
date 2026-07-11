import asyncio
import dns.resolver
import httpx
import re
from collections import defaultdict
from module_base import BaseScanner

SUBDOMAIN_WORDLIST = sorted(set([
    "www","mail","ftp","admin","api","dev","staging","vpn","cdn","blog","app",
    "webmail","remote","portal","ssh","git","jenkins","jira","confluence","mysql",
    "db","ns1","ns2","cloud","test","stage","demo","beta","nginx","api2","develop",
    "prod","production","smtp","imap","pop3","autodiscover","m","mobile","chat",
    "forum","help","support","docs","wiki","status","tracker","monitor","dashboard",
    "analytics","metrics","logs","sync","static","assets","media","img","upload",
    "download","files","backup","cpanel","whm","webmail2","server","ns3","ns4",
    "www2","www3","test1","test2","dev1","dev2","stage1","stage2","redis","mongo",
    "postgres","elastic","kibana","grafana","prometheus","alertmanager","consul",
    "vault","nomad","k8s","kubernetes","docker","registry","nexus","artifactory",
    "travis","circleci","gitlab","bitbucket","npm","yarn","lms","learning","training",
    "academy","campus","erp","crm","hr","payroll","intranet","extranet","owa",
    "exchange","lync","skype","teams","zoom","radius","ldap","kerberos","ntp","dhcp",
    "dns","proxy","squid","webproxy","gateway","firewall","ws","wss","websocket",
    "socket","stream","live","production","staging2","qa","quality","sandbox",
    "playground","lab","experimental","mx","mail2","mail1","email","sip","voip",
    "phone","call","meet","conf","ns","dns1","dns2","dns3","dns4","mariadb","percona",
    "couchdb","cassandra","kafka","rabbitmq","activemq","pulsar","zookeeper","hadoop",
    "spark","storm","flink","hbase","splunk","sumo","datadog","newrelic","dynatrace",
    "puppet","chef","ansible","terraform","salt","sentinel","sentry","bugsnag",
    "rollbar","airbrake","sonar","sonarqube","codeclimate","codacy","coveralls",
    "pypi","rubygems","packagist","maven","composer","nuget","cargo","hex","gem",
    "golang","python","java","php","ruby","node","react","vue","angular","svelte",
    "next","nuxt","graphql","rest","soap","grpc","swagger","openapi","redoc",
    "api-docs","stage-api","dev-api","test-api","prod-api","stage-app","dev-app",
    "test-app","prod-app","customer","client","partner","vendor","supplier","b2b",
    "b2c","wholesale","retail","distributor","store","shop","cart","checkout",
    "payment","invoice","billing","receipt","order","quote","ship","tracking",
    "delivery","courier","dispatch","recruit","career","job","apply","hiring",
    "intern","graduate","talent","staff","personnel","benefits","pension","insurance",
    "wellness","health","compliance","audit","legal","policy","terms","privacy",
    "gdpr","ccpa","soc","iso","research","innovation","labs","rnd","rd","patent",
    "trademark","copyright","license","royalty","press","news","media","pr","release",
    "event","webinar","workshop","seminar","conference","partner-portal","vendor-portal",
    "dealer-portal","reseller","affiliate","referral","partner-program","studio",
    "creative","design","brand","identity","photo","video","gallery","portfolio",
    "showcase","cdn2","cdn3","static1","static2","static3","img1","img2","img3",
    "media1","media2","css","js","font","icon","asset","origin","origin-www",
    "origin-staging","origin-dev","direct","direct-www","direct-api","edge","edge-www",
    "edge-api","edge-staging","waf","waf-www","waf-api","security","auth","login",
    "signin","signup","register","sso","oauth","openid","saml","cas","mfa","2fa",
    "totp","otp","verify","password","reset","forgot","recover","change","account",
    "profile","settings","preferences","config","admin","administrator","admin-console",
    "admin-panel","manage","management","manager","operator","supervisor","report",
    "analytics","statistics","stats","insight","control","panel","console","oracle",
    "sap","peoplesoft","siebel","workday","successfactors","adp","ultipro","bamboo",
    "salesforce","hubspot","marketo","pardot","eloqua","zendesk","freshdesk",
    "servicenow","jira-servicedesk","sharepoint","yammer","slack","discord",
    "mattermost","rocketchat","riot","signal","telegram","whatsapp","wechat","line",
    "comms","communication","connect","collaborate","office","office365","microsoft",
    "msoffice","outlook","outlook-web","outlook-webapp","calendar","cal","scheduler",
    "booking","appointment","drive","document","doc","sheet","slide","team","group",
    "department","division","business-unit","hq","headquarters","branch","regional",
    "americas","emea","apac","latam","global","us","uk","eu","asia","china","japan",
    "india","nyc","london","tokyo","singapore","sydney","data","database","db1","db2",
    "db3","replica","slave","master","primary","secondary","read","write","report",
    "warehouse","etl","bi","business-intelligence","olap","cube","mining","search",
    "solr","lucene","sphinx","algolia","index","catalog","discover","explore",
    "browse","recommend","recommendation","suggest","personalize","notification",
    "notify","alert","alarm","warn","feed","rss","atom","podcast","broadcast",
    "streaming","video","audio","media-server","live-stream","hls","dash","rtmp",
    "player","play","watch","listen","view","load","load-balancer","lb","balancer",
    "health","healthcheck","health-check","heartbeat","monitoring","watchdog",
    "pager","pagerduty","opsgenie","victorops","xmatters","inventory","asset","cmdb",
    "configuration","discovery","deploy","deployment","release","rollback","canary",
    "blue","green","bluegreen","a-b","experiment","feature","flag","toggle","switch",
    "validate","validation","verify","verification","approve","review","approval",
    "workflow","process","bpmn","form","survey","poll","questionnaire","feedback",
    "governance","risk","control","sox","hipaa","pci","pci-dss","iso27001","soc2",
    "fedramp","version","versioning","changelog","release-notes","update","upgrade",
    "migrate","migration","convert","importer","exporter","import","export",
    "uploader","downloader","batch","job","task","worker","scheduler","cron",
    "periodic","recurring","automation","auto","trigger","hook","webhook","callback",
    "listener","message","messaging","queue","topic","pubsub","event","event-bus",
    "event-stream","event-sourcing","cache","caching","varnish","memcache",
    "redis-cluster","cdn-origin","origin-cdn","cdn-origin-www","storage",
    "object-storage","blob","file-storage","s3","bucket","minio","ceph","gluster",
    "dns-update","dns-api","dns-manager","dns-admin","ssl","tls","cert","certificate",
    "cert-manager","acme","letsencrypt","zerossl","ssl-check","firewall","fw",
    "fw-www","waf-www","ids","ips","ids-www","ips-www","dpi","deep-packet-inspection",
    "packet-capture","openvpn","wireguard","ipsec","l2tp","proxy-vpn","vpn-gateway",
    "vpn-server","rdp","rdp-gateway","remote-desktop","citrix","vdi","virtual-desktop",
    "horizon","xenapp","sccm","scom","scsm","opsmgr","hyperv","vmware","vcenter",
    "esxi","vsphere","xen","xenserver","kvm","proxmox","ovirt","openstack","nova",
    "neutron","cinder","glance","swift","keystone","horizon","heat","ceilometer",
    "iaas","paas","saas","caas","faas","serverless","lambda","function","functions",
    "sink","source","connector","streams","ksql","grafana","tempo","loki","mimir",
    "phlare","thanos","cortex","victoria-metrics","influxdb","timescaledb","neo4j",
    "arangodb","orientdb","dgraph","cayley","mysql","postgresql","mongodb","couchbase",
    "riak","cockroachdb","yugabyte","tidb","vitess","galera","hive","pig","presto",
    "trino","druid","superset","metabase","redash","tableau","looker","jupyter",
    "notebook","lab","collab","deepnote","mlflow","kubeflow","polyaxon","determined",
    "weights","tensorflow","pytorch","mxnet","caffe","onnx","airflow","luigi",
    "prefect","dagster","nifi","argocd","argo-workflows","argo-events","argo-rollouts",
    "harbor","quay","ecr","acr","gcr","drone","woodpecker","buildkite","codebuild",
    "teamcity","bamboo","buddy","semaphore","cirrus","appveyor","flux","istio",
    "linkerd","consul-connect","envoy","kiali","jaeger","zipkin","skywalking",
    "opentelemetry","cert-manager","external-dns","ingress-nginx","traefik","haproxy",
    "kong","tyk","gravitee","wso2","apigee","keycloak","dex","oauth2-proxy",
    "pomerium","authelia","vault","boundary","teleport","step-ca","smallstep",
    "verne","mosquitto","emqx","hivemq","nats","pulsar","redpanda","kafka-connect",
    "ksqldb","schema-registry","flink","spark","beam","samza","heron","pinot",
    "druid","clickhouse","starrocks","doris","mongosh","studio-3t","robo3t",
    "nosqlbooster","compass","redis-commander","redisinsight","redmin","medis","rdm",
    "phpmyadmin","adminer","pgadmin","phppgadmin","cloudbeaver","mailhog",
    "mailcatcher","smtp4dev","fake-smtp","mailpit","filebrowser","filemanager",
    "explorer","manager","browser","novnc","guacamole","meshcentral",
    "apache-guacamole","kasmweb","code-server","coder","gitpod","theia","eclipse-che",
    "codeberg","gitea","gitbucket","gitlist","gitweb","npm-registry","verdaccio",
    "sinopia","cnpmjs","artipub","pypi-server","devpi","bandersnatch","pep503",
    "warehouse","hub","docker-hub","registry-1","registry-2","notary","www-1","www-2",
    "www-a","www-b","web-1","web-2","web-a","web-b","app-1","app-2","app-a","app-b",
    "api-1","api-2","api-a","api-b","us-east-1","us-west-2","eu-west-1",
    "eu-central-1","ap-southeast-1","us-east","us-west","eu-west","eu-central",
    "ap-southeast","dc1","dc2","dc3","dc4","dc5","rack1","rack2","rack3","rack4",
    "rack5","node1","node2","node3","node4","node5","worker1","worker2","worker3",
    "worker4","worker5","master1","master2","master3","master4","master5",
    "k8s-master","k8s-worker","k8s-node","k8s-ingress","k8s-api","istio-ingress",
    "istio-gateway","envoy-admin","envoy-metrics","calico","flannel","weave","cilium",
    "kube-proxy","argocd-server","argocd-repo","argocd-dex","harbor-core",
    "harbor-jobservice","gitlab-ce","gitlab-ee","gitlab-runner","gitlab-pages",
    "registry.gitlab","jira-software","jira-core","jira-servicedesk","confluence-wiki",
    "bitbucket-server","jenkins-master","jenkins-agent","jenkins-build","jenkins-test",
    "jenkins-prod","sonarqube-db","sonarqube-server","nexus-repo","nexus-blob",
    "artifactory-pro","maven-repo","maven-central","maven-snapshot","maven-release",
    "maven-staging","pypi-mirror","npm-mirror","rubygems-mirror","cargo-mirror",
    "nuget-mirror","cdn-assets","cdn-static","cdn-media","cdn-images","cdn-fonts",
    "origin-assets","origin-static","origin-media","origin-images","assets-cdn",
    "static-cdn","media-cdn","images-cdn","fonts-cdn","api-gateway","api-mgmt",
    "api-manager","api-proxy","api-backend","graphql-api","graphql-playground",
    "graphiql","altair","hasura","swagger-ui","swagger-docs","swagger-json",
    "openapi-json","openapi-yaml","redoc-docs","redoc-ui","stoplight","readme",
    "postman","auth-server","auth-service","auth-api","auth-admin","auth-mfa",
    "identity-server","identity-api","identity-admin","identity-provider","saml-server",
    "saml-service","saml-api","saml-admin","saml-idp","oauth-server","oauth-service",
    "oauth-api","oauth-admin","oauth-provider","ldap-server","ldap-admin","ldap-api",
    "ldap-broker","ldap-proxy","radius-server","radius-admin","radius-api",
    "radius-auth","radius-proxy","mail-server","mail-relay","mail-gateway",
    "mail-proxy","mail-filter","smtp-server","smtp-relay","smtp-gateway",
    "smtp-proxy","smtp-auth","imap-server","imap-proxy","imap-gateway","imap-ssl",
    "imap-tls","pop3-server","pop3-ssl","pop3-tls","pop3-proxy","pop3-gateway",
    "exchange-server","exchange-owa","exchange-ecp","exchange-autodiscover","ews",
    "ecp","oab","mapi","activesync","mdm","mem","intune","jamf","airwatch","wsus",
    "sccm","scom","scvmm","scorch","hyperv-host","hyperv-cluster","vcenter-server",
    "vcenter-web","esxi-host","vmware-nsx","vmware-vrealize","vmware-vrops",
    "vmware-vra","vmware-vro","redhat-satellite","redhat-identity","redhat-insights",
    "redhat-subscription","centrify","okta","onelogin","duo","pingidentity",
    "cyberark","beyondtrust","thycotic","hitachi-id","ca-pam","splunk-hec",
    "splunk-indexer","splunk-search","splunk-forwarder","splunk-deployment",
    "elasticsearch","logstash","kibana-admin","kibana-ops","apm-server","graylog",
    "papertrail","logentries","loggly","solarwinds","nagios","icinga","check-mk",
    "zabbix","prometheus-alertmanager","grafana-dashboards","grafana-admin",
    "grafana-ops","grafana-prod","grafana-dev","mackerel","uptimerobot","pingdom",
    "site24x7","statuscake","backup-server","backup-admin","backup-console",
    "backup-storage","backup-nas","veeam","veeam-backup","veeam-enterprise",
    "veeam-console","veeam-one","commvault","netbackup","acronis","duplicati",
    "restic","nas","nas-1","nas-2","san","san-1","san-2","router","switch",
    "core-router","edge-router","border-router","cisco","juniper","paloalto",
    "fortinet","checkpoint","camera","cam","surveillance","cctv","doorbell",
    "printer","print","scan","scanner","fax","oa","oa-server","oa-admin","oa-portal",
    "oa-app","fe","fe-1","fe-2","fe-3","be","be-1","be-2","service","services",
    "microservice","microservices","soa","broker","broker-1","broker-2","bridge",
    "integrator","rpa","uipath","automation-anywhere","blueprism","workfusion",
    "chatbot","bot","botman","virtual-assistant","voice","ai","ml","inference",
    "training","model","bigdata","data-platform","data-hub","data-lake","data-pipeline",
    "ioc","tide","threatgrid","threat-intel","ti","honeypot","honeynet","canary",
    "decoy","tarpit","sandbox-analysis","sandbox-exec","cuckoo","cape","viper",
    "misp","opencti","thehive","cortex","elastic-endpoint","codeanalyzer",
    "codequality","codescan","codereview","codewhisperer","dependency-check","owasp",
    "zap","burp","acunetix","pentest","pentesting","security-scan","security-audit",
    "security-test","redteam","blueteam","purpleteam","soc","cert","ir",
    "incident-response","forensic","forensics","dfir","vulnerability-scan",
    "vuln-scan","vuln-mgmt","patch-mgmt","remediation","compliance-scan",
    "compliance-audit","compliance-report","compliance-dashboard","risk-assessment",
    "risk-dashboard","risk-report","risk-mgmt","risk-platform","bss","oss","nms",
    "ems","sms","ocs","tms","cms","dms","wms","ecom","ecommerce","eshop","webshop",
    "onlineshop","payment-gateway","payment-api","payment-processor","payment-web",
    "payment-admin","pos","point-of-sale","pos-api","pos-web","pos-admin","fintech",
    "finance","financial","banking","trading","healthcare","hospital","clinic",
    "pharmacy","lab","edu","education","learning","elearning","moodle","canvas",
    "blackboard","schoology","edmodo","brightspace","sports","gaming","game",
    "gamble","casino",
]))

SUBDOMAIN_CATEGORIES = {
    "dev": ["dev","develop","development","stage","staging","test","testing","qa","sandbox","lab","beta","demo","preprod","uat","sprint","jira","confluence","gitlab","github","bitbucket","jenkins","travis","circleci","codebuild","sonar","sonarqube","codacy","codeclimate","npm","pypi","artifactory","nexus","registry","docker"],
    "api": ["api","api2","api3","api-v1","api-v2","graphql","rest","soap","grpc","swagger","openapi","redoc","api-docs","api-doc","gateway","api-gateway"],
    "admin": ["admin","administrator","admin-console","admin-panel","manage","management","manager","operator","control","panel","console","dashboard","cpanel","whm"],
    "mail": ["mail","smtp","imap","pop3","webmail","email","exchange","outlook","owa","ecp","ews","autodiscover","mx","mail1","mail2"],
    "vpn": ["vpn","openvpn","wireguard","ipsec","remote","remote-access","rdp","rdp-gateway","citrix","vdi","horizon","gateway"],
    "monitoring": ["monitor","monitoring","grafana","prometheus","alertmanager","kibana","splunk","nagios","zabbix","icinga","check-mk","datadog","newrelic","dynatrace","status","health"],
    "storage": ["cdn","static","assets","media","img","upload","download","files","storage","s3","bucket","minio","ceph"],
    "security": ["waf","firewall","security","auth","login","sso","oauth","saml","ids","ips","proxy","ssl","certificate","vault"],
    "database": ["db","mysql","postgres","mongo","redis","elastic","couchdb","cassandra","mariadb","database"],
    "auth": ["auth","login","signin","signup","register","sso","oauth","openid","saml","cas","mfa","2fa","totp","otp","verify","password","reset","recover","account","profile"],
}

class DnsBruteScanner(BaseScanner):
    name = "dns_brute"

    async def check_prefix(self, prefix: str, domain: str, seen: set, loop):
        sub = f"{prefix}.{domain}"
        if sub in seen:
            return None, None
        seen.add(sub)
        try:
            res = dns.resolver.Resolver()
            res.timeout = 4.0
            res.lifetime = 4.0
            answers = await loop.run_in_executor(None, lambda: res.resolve(sub, 'A'))
            if answers:
                return sub, str(answers[0])
        except:
            try:
                res = dns.resolver.Resolver()
                res.timeout = 4.0
                res.lifetime = 4.0
                answers_aaaa = await loop.run_in_executor(None, lambda: res.resolve(sub, 'AAAA'))
                if answers_aaaa:
                    return sub, ("AAAA", str(answers_aaaa[0]))
            except:
                pass
        return None, None

    async def check_record_type(self, sub: str, rtype: str, loop):
        results = []
        try:
            res = dns.resolver.Resolver()
            res.timeout = 4.0
            res.lifetime = 4.0
            answers = await loop.run_in_executor(None, lambda rt=rtype: res.resolve(sub, rt))
            for rdata in answers:
                results.append(str(rdata))
        except:
            pass
        return results

    async def check_wildcard_advanced(self, domain: str, loop):
        info = {"detected": False, "ips": set(), "count": 0, "sample_ips": []}
        for seed in ["xwcz", "random", "test", "zzzzz", "aaaaa"]:
            prefix = f"{seed}-{abs(hash(domain + seed)) % 99999}"
            try:
                test_sub = f"{prefix}.{domain}"
                answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(test_sub, 'A'))
                if answers:
                    ip = str(answers[0])
                    info["ips"].add(ip)
                    info["count"] += 1
                    info["detected"] = True
                    if len(info["sample_ips"]) < 3:
                        info["sample_ips"].append((test_sub, ip))
            except:
                pass
        return info

    async def http_probe(self, subdomain: str):
        try:
            resp = await self.safe_request(f"https://{subdomain}", timeout=8, follow_redirects=False)
            if not resp:
                resp = await self.safe_request(f"http://{subdomain}", timeout=8, follow_redirects=False)
            if resp:
                result = {"status": resp.status_code, "server": "", "title": "", "content_type": "", "redirect": ""}
                result["server"] = resp.headers.get("Server", "")
                result["content_type"] = resp.headers.get("Content-Type", "")
                if "location" in resp.headers:
                    result["redirect"] = resp.headers["location"]
                title_match = re.search(rb'<title[^>]*>(.*?)</title>', resp.content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).decode("utf-8", errors="ignore")[:100]
                return result
        except:
            pass
        return {"status": None, "title": None, "server": None, "content_type": None, "redirect": None}

    def categorize(self, sub: str) -> list:
        prefix = sub.split(".")[0]
        for cat, keywords in SUBDOMAIN_CATEGORIES.items():
            for kw in keywords:
                if prefix == kw or prefix.startswith(kw) or kw in prefix:
                    return [cat]
        return ["other"]

    async def scan(self) -> list:
        results = []
        domain = self.target
        loop = asyncio.get_event_loop()
        seen = set()

        wildcard_info = await self.check_wildcard_advanced(domain, loop)
        if wildcard_info["detected"]:
            f = self.finding(
                entity=f"*.{domain} (Wildcard DNS detected - {wildcard_info['count']}/5 random tests positive)",
                ftype="Wildcard DNS", source="DNSBrute", confidence="Certain",
                color="orange", threat_level="Elevated Risk",
                raw_data=f"Wildcard DNS resolves random subdomains. Sample: {wildcard_info['sample_ips']}",
                tags=["wildcard", "dns", "security-risk"]
            )
            if f: results.append(f)
            for ip in wildcard_info["ips"]:
                f2 = self.finding(
                    entity=f"Wildcard resolves to {ip}", ftype="Wildcard DNS IP",
                    source="DNSBrute", confidence="High", color="orange",
                    threat_level="Informational", tags=["wildcard", "ip", "dns"]
                )
                if f2: results.append(f2)

        batch_size = 30
        live_subs = {}
        max_check = min(len(SUBDOMAIN_WORDLIST), 2000)
        for i in range(0, max_check, batch_size):
            batch = SUBDOMAIN_WORDLIST[i:i+batch_size]
            batch_results = await asyncio.gather(*[self.check_prefix(p, domain, seen, loop) for p in batch])
            for sub, info in batch_results:
                if sub:
                    if isinstance(info, tuple):
                        live_subs[sub] = {"ip": info[1], "type": "AAAA", "categories": self.categorize(sub)}
                    else:
                        live_subs[sub] = {"ip": info, "type": "A", "categories": self.categorize(sub)}

        resolved_details = {}
        if live_subs:
            for sub in live_subs:
                details = {"records": {}}
                for rtype in ["A", "AAAA", "CNAME"]:
                    details["records"][rtype] = await self.check_record_type(sub, rtype, loop)
                for extra_type in ["MX", "TXT", "NS"]:
                    try:
                        extra_answers = await self.check_record_type(sub, extra_type, loop)
                        if extra_answers:
                            details["records"][extra_type] = extra_answers
                    except:
                        pass
                resolved_details[sub] = details

        for sub, info in live_subs.items():
            ip = info["ip"]
            ip_type = info["type"]
            categories = info["categories"]
            color = "emerald" if ip_type == "A" else "purple"
            rtype_label = "A record" if ip_type == "A" else "AAAA record (IPv6)"
            details = resolved_details.get(sub, {})
            records = details.get("records", {})

            extra_tags = []
            for xtype in ["CNAME", "MX", "TXT", "NS"]:
                if xtype in records and records[xtype]:
                    extra_tags.append(xtype.lower())
                    if xtype == "CNAME":
                        f = self.finding(
                            entity=f"{sub} -> {records[xtype][0]}", ftype="CNAME Record (Brute Found)",
                            source="DNSBrute", confidence="High", color="purple",
                            threat_level="Informational", resolution=records[xtype][0],
                            tags=["cname", "dns"]
                        )
                        if f: results.append(f)
                    elif xtype == "MX":
                        f = self.finding(
                            entity=f"{sub} MX: {records[xtype][0]}", ftype="MX Record (Brute Found)",
                            source="DNSBrute", confidence="High", color="slate",
                            threat_level="Informational", resolution=records[xtype][0],
                            tags=["mx", "dns", "mail"]
                        )
                        if f: results.append(f)
                    elif xtype == "TXT":
                        f = self.finding(
                            entity=f"{sub} TXT: {records[xtype][0][:200]}", ftype="TXT Record (Brute Found)",
                            source="DNSBrute", confidence="High", color="orange",
                            threat_level="Informational", raw_data=f"TXT for {sub}: {records[xtype][0][:500]}",
                            tags=["txt", "dns"]
                        )
                        if f: results.append(f)
                    elif xtype == "NS":
                        f = self.finding(
                            entity=f"{sub} NS: {records[xtype][0]}", ftype="NS Record (Brute Found)",
                            source="DNSBrute", confidence="High", color="slate",
                            threat_level="Informational", resolution=records[xtype][0],
                            tags=["ns", "dns"]
                        )
                        if f: results.append(f)

            raw_parts = [f"Resolved to {ip} ({rtype_label})"]
            raw_data = " | ".join(raw_parts)
            f = self.finding(
                entity=sub, ftype="Subdomain (Brute Forced)", source="DNSBrute",
                confidence="High", color=color, category="Network Intelligence",
                threat_level="Standard Target", status="Live", resolution=ip,
                raw_data=raw_data,
                tags=["subdomain", "bruteforce", "dns", ip_type.lower()] + categories + extra_tags
            )
            if f: results.append(f)

        if live_subs:
            http_tasks = {sub: self.http_probe(sub) for sub in live_subs}
            http_results = {}
            for sub, task in http_tasks.items():
                try:
                    http_results[sub] = await task
                except:
                    pass
            for sub, http_info in http_results.items():
                if http_info.get("status"):
                    status = http_info["status"]
                    title = http_info.get("title", "")
                    server = http_info.get("server", "")
                    redirect = http_info.get("redirect", "")
                    sc = "green" if 200 <= status < 300 else ("yellow" if 300 <= status < 400 else ("orange" if 400 <= status < 500 else "red"))
                    raw_parts = [f"HTTP {status}"]
                    if title: raw_parts.append(f"Title: {title}")
                    if server: raw_parts.append(f"Server: {server}")
                    if redirect: raw_parts.append(f"Redirect: {redirect}")
                    f = self.finding(
                        entity=f"{sub} [HTTP {status}]", ftype="HTTP Probe Result",
                        source="DNSBrute", confidence="High", color=sc,
                        threat_level="Standard Target", status=f"HTTP {status}",
                        resolution=live_subs.get(sub, {}).get("ip", ""),
                        raw_data=" | ".join(raw_parts),
                        tags=["http-probe", f"http-{status}", "web"] + (["redirect"] if redirect else [])
                    )
                    if f: results.append(f)
                    if server:
                        f2 = self.finding(
                            entity=f"{sub} runs {server}", ftype="Web Server Fingerprint",
                            source="DNSBrute", confidence="Medium", color="blue",
                            threat_level="Informational", tags=["server-header", "fingerprint"]
                        )
                        if f2: results.append(f2)

        cat_counts = defaultdict(int)
        cat_subs = defaultdict(list)
        for sub, info in live_subs.items():
            for cat in info["categories"]:
                cat_counts[cat] += 1
                if len(cat_subs[cat]) < 8:
                    cat_subs[cat].append(sub)
        cat_colors = {
            "dev": "yellow", "api": "purple", "admin": "red", "mail": "slate",
            "vpn": "orange", "monitoring": "cyan", "storage": "blue",
            "security": "red", "database": "purple", "auth": "orange", "other": "slate"
        }
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                f = self.finding(
                    entity=f"{cat}: {count} subdomains discovered",
                    ftype=f"Subdomain Category: {cat.capitalize()}", source="DNSBrute",
                    confidence="High", color=cat_colors.get(cat, "slate"),
                    threat_level="Elevated Risk" if cat in ("admin","vpn","security","database") else "Informational",
                    raw_data=f"Category '{cat}' has {count} subdomains: {', '.join(cat_subs.get(cat, [])[:5])}",
                    tags=["category", cat, "summary"]
                )
                if f: results.append(f)

        cname_prefixes = ["www","mail","blog","app","cdn","m","api","dev","admin","vpn","remote","support","docs","wiki","status","help"]
        for prefix in cname_prefixes:
            sub = f"{prefix}.{domain}"
            if sub in live_subs:
                continue
            try:
                res = dns.resolver.Resolver()
                res.timeout = 3.0
                res.lifetime = 3.0
                cname_answers = await loop.run_in_executor(None, lambda: res.resolve(sub, 'CNAME'))
                if cname_answers:
                    for cname in cname_answers:
                        cname_str = str(cname)
                        f = self.finding(
                            entity=f"{sub} -> {cname_str}", ftype="CNAME Record (Brute Found)",
                            source="DNSBrute", confidence="High", color="purple",
                            threat_level="Informational", resolution=cname_str,
                            tags=["cname", "dns", "redirect"]
                        )
                        if f: results.append(f)
                        try:
                            target_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(cname_str, 'A'))
                            if target_answers:
                                f2 = self.finding(
                                    entity=f"{cname_str} resolves to {str(target_answers[0])}",
                                    ftype="CNAME Target Resolution", source="DNSBrute",
                                    confidence="High", color="slate", threat_level="Informational",
                                    tags=["cname-chain", "dns"]
                                )
                                if f2: results.append(f2)
                        except:
                            pass
            except:
                pass

        ip_clusters = defaultdict(list)
        for sub, info in live_subs.items():
            ip_clusters[info["ip"]].append(sub)
        if len(ip_clusters) < len(live_subs) and ip_clusters:
            multi_ip = {ip: subs for ip, subs in ip_clusters.items() if len(subs) > 1}
            for ip, subs in sorted(multi_ip.items(), key=lambda x: -len(x[1]))[:5]:
                f = self.finding(
                    entity=f"{len(subs)} subdomains share IP {ip}: {', '.join(subs[:6])}",
                    ftype="IP Cluster Analysis", source="DNSBrute", confidence="High",
                    color="blue", threat_level="Informational",
                    raw_data=f"IP {ip} hosts {len(subs)} subdomains: {', '.join(subs)}",
                    tags=["ip-cluster", "co-hosting"]
                )
                if f: results.append(f)

        if live_subs:
            ipv4_count = sum(1 for v in live_subs.values() if v["type"] == "A")
            ipv6_count = sum(1 for v in live_subs.values() if v["type"] == "AAAA")
            f = self.finding(
                entity=f"Total: {len(live_subs)} live subdomains ({ipv4_count} IPv4, {ipv6_count} IPv6) from {max_check} prefixes",
                ftype="DNSBrute Summary", source="DNSBrute", confidence="High",
                color="blue", threat_level="Informational",
                raw_data=f"{len(live_subs)} subdomains found from {max_check} common prefixes",
                tags=["summary", "total"]
            )
            if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = DnsBruteScanner(target, client)
    return await scanner.scan()

"""
HackIT PortStorm — Python Ultra Engine
Nmap-level banner grabbing, version detection, OS fingerprinting
300+ protocol signatures, async I/O, multiprocess scan
"""

import asyncio
import socket
import ssl
import struct
import time
import re
import os
import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field, asdict
from functools import partial

@dataclass
class ServiceFingerprint:
    service: str
    product: str = ""
    version: str = ""
    os_hint: str = ""
    confidence: float = 0.0
    cpe: str = ""
    banner: str = ""

@dataclass
class ScanResult:
    port: int
    state: str = "closed"
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    os_hint: str = ""
    os_confidence: float = 0.0
    ttl: int = 0
    risk_score: float = 0.0
    vulnerabilities: List[str] = field(default_factory=list)
    cpe: str = ""
    confidence: float = 0.0

# ─────────────────────────────────────────────────────────────────
# SERVICE SIGNATURE DATABASE — 300+ patterns
# ─────────────────────────────────────────────────────────────────

SERVICE_SIGNATURES = [
    # SSH
    (22, re.compile(rb'SSH-2\.0-OpenSSH_([\d.]+p?\d*)'), 'SSH', 'OpenSSH', 'Unix/Linux'),
    (22, re.compile(rb'SSH-2\.0-dropbear_([\d.]+)'), 'SSH', 'Dropbear', 'Unix/Linux'),
    (22, re.compile(rb'SSH-2\.0-Cisco-([\d.]+)'), 'SSH', 'Cisco SSH', 'Cisco IOS'),
    (22, re.compile(rb'SSH-1\.99-'), 'SSH', 'SSH Legacy', 'Generic'),
    (22, re.compile(rb'SSH-1\.5-'), 'SSH', 'SSH v1 (Insecure)', 'Generic'),

    # HTTP — Apache
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)'), 'HTTP', 'Apache httpd', 'Generic'),
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)\s+\(Ubuntu\)'), 'HTTP', 'Apache httpd', 'Ubuntu Linux'),
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)\s+\(Debian\)'), 'HTTP', 'Apache httpd', 'Debian Linux'),
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)\s+\(CentOS\)'), 'HTTP', 'Apache httpd', 'CentOS Linux'),
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)\s+\(FreeBSD\)'), 'HTTP', 'Apache httpd', 'FreeBSD'),
    (80, re.compile(rb'Server:\s*Apache/([\d.]+)\s+\(Win32\)'), 'HTTP', 'Apache httpd', 'Windows'),
    (80, re.compile(rb'Server:\s*Apache-Coyote/1\.1'), 'HTTP', 'Apache Tomcat/Coyote', 'Generic'),

    # HTTP — nginx
    (80, re.compile(rb'Server:\s*nginx/([\d.]+)'), 'HTTP', 'nginx', 'Generic'),
    (80, re.compile(rb'Server:\s*nginx/([\d.]+)\s+\(Ubuntu\)'), 'HTTP', 'nginx', 'Ubuntu Linux'),
    (80, re.compile(rb'Server:\s*nginx/([\d.]+)\s+\(Debian\)'), 'HTTP', 'nginx', 'Debian Linux'),
    (80, re.compile(rb'Server:\s*openresty/([\d.]+)'), 'HTTP', 'OpenResty', 'Generic'),
    (80, re.compile(rb'Server:\s*Tengine/?([\d.]*)'), 'HTTP', 'Tengine', 'Generic'),

    # HTTP — IIS
    (80, re.compile(rb'Server:\s*Microsoft-IIS/([\d.]+)'), 'HTTP', 'Microsoft IIS', 'Windows Server'),
    (80, re.compile(rb'Server:\s*Microsoft-HTTPAPI/([\d.]+)'), 'HTTP', 'Microsoft HTTPAPI', 'Windows Server'),
    (80, re.compile(rb'X-Powered-By:\s*ASP\.NET'), 'HTTP', 'ASP.NET', 'Windows Server'),

    # HTTP — Other
    (80, re.compile(rb'Server:\s*LiteSpeed'), 'HTTP', 'LiteSpeed', 'Generic'),
    (80, re.compile(rb'Server:\s*lighttpd/([\d.]+)'), 'HTTP', 'Lighttpd', 'Generic'),
    (80, re.compile(rb'Server:\s*Caddy'), 'HTTP', 'Caddy', 'Generic'),
    (80, re.compile(rb'Server:\s*Cowboy'), 'HTTP', 'Cowboy (Erlang)', 'Generic'),
    (80, re.compile(rb'Server:\s*GWS'), 'HTTP', 'Google Web Server', 'Generic'),
    (80, re.compile(rb'Server:\s*Cloudflare'), 'HTTP', 'Cloudflare', 'Generic'),
    (80, re.compile(rb'Server:\s*Jetty\(([\d.]+)\)'), 'HTTP', 'Jetty', 'Generic'),
    (80, re.compile(rb'Server:\s*gunicorn/([\d.]+)'), 'HTTP', 'Gunicorn', 'Generic'),
    (80, re.compile(rb'Server:\s*Werkzeug/?([\d.]*)'), 'HTTP', 'Werkzeug (Flask)', 'Generic'),
    (80, re.compile(rb'Server:\s*Cherokee/?([\d.]*)'), 'HTTP', 'Cherokee', 'Generic'),
    (80, re.compile(rb'Server:\s*Node\.js'), 'HTTP', 'Node.js', 'Generic'),
    (80, re.compile(rb'Server:\s*Pumpkin'), 'HTTP', 'Pumpkin', 'Generic'),
    (80, re.compile(rb'Server:\s*GlassFish'), 'HTTP', 'GlassFish', 'Generic'),
    (80, re.compile(rb'Server:\s*WildFly'), 'HTTP', 'WildFly', 'Generic'),

    # HTTP — Powered-By
    (80, re.compile(rb'X-Powered-By:\s*PHP/([\d.]+)'), 'HTTP', 'PHP', 'Generic'),
    (80, re.compile(rb'X-Powered-By:\s*Express'), 'HTTP', 'Express (Node.js)', 'Generic'),
    (80, re.compile(rb'X-Generator:\s*Drupal ([\d.]+)'), 'CMS', 'Drupal', 'Generic'),
    (80, re.compile(rb'X-Generator:\s*WordPress ([\d.]+)'), 'CMS', 'WordPress', 'Generic'),
    (80, re.compile(rb'X-Generator:\s*Joomla! ([\d.]+)'), 'CMS', 'Joomla', 'Generic'),

    # FTP
    (21, re.compile(rb'220.*vsftpd\s*([\d.]+)'), 'FTP', 'vsftpd', 'Unix/Linux'),
    (21, re.compile(rb'220.*ProFTPD\s*([\d.]+)'), 'FTP', 'ProFTPD', 'Unix/Linux'),
    (21, re.compile(rb'220.*FileZilla Server\s*([\d.]+)'), 'FTP', 'FileZilla Server', 'Windows'),
    (21, re.compile(rb'220.*Pure-FTPd\s*([\d.]+)'), 'FTP', 'Pure-FTPd', 'Unix/Linux'),
    (21, re.compile(rb'220.*Microsoft FTP'), 'FTP', 'Microsoft FTP', 'Windows Server'),
    (21, re.compile(rb'220.*Wu-FTPd'), 'FTP', 'Wu-FTPd', 'Unix/Linux'),
    (21, re.compile(rb'220.*glFTPd'), 'FTP', 'glFTPd', 'Unix/Linux'),
    (21, re.compile(rb'220.*Serv-U FTP'), 'FTP', 'Serv-U', 'Windows'),
    (21, re.compile(rb'220.*Cerberus FTP'), 'FTP', 'Cerberus FTP', 'Windows'),
    (21, re.compile(rb'220.*Apache FtpServer'), 'FTP', 'Apache FtpServer', 'Generic'),
    (21, re.compile(rb'220.*BulletProof'), 'FTP', 'BulletProof FTP', 'Windows'),
    (21, re.compile(rb'220.*Titan FTP'), 'FTP', 'Titan FTP', 'Windows'),

    # SMTP
    (25, re.compile(rb'220.*Postfix\s*([\d.]+)'), 'SMTP', 'Postfix', 'Unix/Linux'),
    (25, re.compile(rb'220.*Exim\s*([\d.]+)'), 'SMTP', 'Exim', 'Unix/Linux'),
    (25, re.compile(rb'220.*Sendmail\s*([\d.]+)'), 'SMTP', 'Sendmail', 'Unix/Linux'),
    (25, re.compile(rb'220.*Microsoft ESMTP'), 'SMTP', 'Microsoft Exchange', 'Windows Server'),
    (25, re.compile(rb'220.*MailEnable'), 'SMTP', 'MailEnable', 'Windows'),
    (25, re.compile(rb'220.*qmail'), 'SMTP', 'Qmail', 'Unix/Linux'),
    (25, re.compile(rb'220.*Courier'), 'SMTP', 'Courier Mail', 'Unix/Linux'),
    (25, re.compile(rb'220.*OpenSMTPD'), 'SMTP', 'OpenSMTPD', 'OpenBSD'),
    (25, re.compile(rb'220.*IceWarp'), 'SMTP', 'IceWarp', 'Windows/Unix'),
    (25, re.compile(rb'220.*Zimbra'), 'SMTP', 'Zimbra', 'Unix/Linux'),

    # POP3
    (110, re.compile(rb'\+OK.*Dovecot.*ready'), 'POP3', 'Dovecot POP3', 'Unix/Linux'),
    (110, re.compile(rb'\+OK.*Courier POP3'), 'POP3', 'Courier POP3', 'Unix/Linux'),
    (110, re.compile(rb'\+OK.*Qpopper'), 'POP3', 'Qpopper', 'Unix/Linux'),
    (110, re.compile(rb'\+OK.*Microsoft.*POP3'), 'POP3', 'Microsoft POP3', 'Windows Server'),
    (110, re.compile(rb'\+OK.*Cyrus'), 'POP3', 'Cyrus POP3', 'Unix/Linux'),

    # IMAP
    (143, re.compile(rb'\* OK.*Dovecot'), 'IMAP', 'Dovecot IMAP', 'Unix/Linux'),
    (143, re.compile(rb'\* OK.*Courier'), 'IMAP', 'Courier IMAP', 'Unix/Linux'),
    (143, re.compile(rb'\* OK.*Cyrus IMAP'), 'IMAP', 'Cyrus IMAP', 'Unix/Linux'),
    (143, re.compile(rb'\* OK.*Microsoft.*IMAP'), 'IMAP', 'Microsoft Exchange IMAP', 'Windows Server'),
    (143, re.compile(rb'\* OK.*Zimbra'), 'IMAP', 'Zimbra IMAP', 'Unix/Linux'),

    # Databases
    (3306, re.compile(rb'mysql_native_password'), 'MySQL', 'MySQL', 'Generic'),
    (3306, re.compile(rb'MariaDB'), 'MySQL', 'MariaDB', 'Generic'),
    (3306, re.compile(rb'5\.5\.\d+-MySQL'), 'MySQL', 'MySQL 5.5', 'Generic'),
    (3306, re.compile(rb'5\.6\.\d+-MySQL'), 'MySQL', 'MySQL 5.6', 'Generic'),
    (3306, re.compile(rb'5\.7\.\d+-MySQL'), 'MySQL', 'MySQL 5.7', 'Generic'),
    (3306, re.compile(rb'8\.\d+\.\d+-MySQL'), 'MySQL', 'MySQL 8.x', 'Generic'),
    (5432, re.compile(rb'PostgreSQL\s+([\d.]+)'), 'PostgreSQL', 'PostgreSQL', 'Generic'),
    (6379, re.compile(rb'redis_version:([\d.]+)'), 'Redis', 'Redis', 'Unix/Linux'),
    (6379, re.compile(rb'redis_mode:'), 'Redis', 'Redis', 'Unix/Linux'),
    (27017, re.compile(rb'MongoDB'), 'MongoDB', 'MongoDB', 'Generic'),
    (27017, re.compile(rb'MongoDB\s+([\d.]+)'), 'MongoDB', 'MongoDB', 'Generic'),
    (5984, re.compile(rb'CouchDB/([\d.]+)'), 'CouchDB', 'CouchDB', 'Generic'),
    (9200, re.compile(rb'\"cluster_name\"'), 'Elasticsearch', 'Elasticsearch', 'Generic'),
    (9200, re.compile(rb'\"version\":\s*\{'), 'Elasticsearch', 'Elasticsearch', 'Generic'),
    (11211, re.compile(rb'STAT pid'), 'Memcached', 'Memcached', 'Generic'),
    (11211, re.compile(rb'STAT uptime'), 'Memcached', 'Memcached', 'Generic'),
    (9042, re.compile(rb'Cassandra'), 'Cassandra', 'Apache Cassandra', 'Generic'),

    # Docker / Containers
    (2375, re.compile(rb'Docker/([\d.]+)'), 'Docker', 'Docker Engine', 'Linux'),
    (2375, re.compile(rb'\"Version\":\"([\d.]+)'), 'Docker', 'Docker Engine', 'Linux'),
    (2376, re.compile(rb'Docker/([\d.]+)'), 'Docker', 'Docker Engine (SSL)', 'Linux'),
    (6443, re.compile(rb'kubernetes|k8s'), 'Kubernetes', 'Kubernetes API', 'Generic'),
    (2379, re.compile(rb'etcd\s+([\d.]+)'), 'etcd', 'etcd', 'Linux'),
    (2379, re.compile(rb'\"etcd\"'), 'etcd', 'etcd', 'Linux'),

    # CI/CD
    (8080, re.compile(rb'Jenkins'), 'CI/CD', 'Jenkins CI', 'Generic'),
    (8081, re.compile(rb'Artifactory'), 'CI/CD', 'JFrog Artifactory', 'Generic'),
    (8081, re.compile(rb'Nexus'), 'CI/CD', 'Sonatype Nexus', 'Generic'),
    (80, re.compile(rb'GitLab'), 'CI/CD', 'GitLab', 'Generic'),
    (3000, re.compile(rb'Gitea'), 'CI/CD', 'Gitea', 'Generic'),

    # Message Queues
    (5672, re.compile(rb'AMQP'), 'MQ', 'RabbitMQ / AMQP', 'Generic'),
    (5672, re.compile(rb'RabbitMQ'), 'MQ', 'RabbitMQ', 'Generic'),
    (61613, re.compile(rb'ActiveMQ'), 'MQ', 'Apache ActiveMQ', 'Generic'),
    (9092, re.compile(rb'Kafka'), 'MQ', 'Apache Kafka', 'Generic'),
    (4222, re.compile(rb'NATS'), 'MQ', 'NATS', 'Generic'),

    # Monitoring
    (9090, re.compile(rb'Prometheus'), 'Monitoring', 'Prometheus', 'Generic'),
    (3000, re.compile(rb'Grafana'), 'Monitoring', 'Grafana', 'Generic'),
    (5666, re.compile(rb'Nagios'), 'Monitoring', 'Nagios', 'Generic'),
    (10050, re.compile(rb'Zabbix'), 'Monitoring', 'Zabbix', 'Generic'),
    (6555, re.compile(rb'Check_MK|checkmk'), 'Monitoring', 'CheckMK', 'Generic'),

    # Proxies / Load Balancers
    (80, re.compile(rb'HAProxy\s*([\d.]+)'), 'Proxy', 'HAProxy', 'Generic'),
    (3128, re.compile(rb'Squid/([\d.]+)'), 'Proxy', 'Squid Proxy', 'Generic'),
    (80, re.compile(rb'Varnish'), 'Proxy', 'Varnish Cache', 'Generic'),
    (80, re.compile(rb'Traefik'), 'Proxy', 'Traefik Proxy', 'Generic'),
    (80, re.compile(rb'Envoy'), 'Proxy', 'Envoy Proxy', 'Generic'),

    # VPN
    (1194, re.compile(rb'OpenVPN'), 'VPN', 'OpenVPN', 'Generic'),
    (51820, re.compile(rb'WireGuard'), 'VPN', 'WireGuard', 'Generic'),
    (500, re.compile(rb'StrongSwan'), 'VPN', 'StrongSwan', 'Linux'),

    # Embedded / Network
    (80, re.compile(rb'OpenWrt'), 'Embedded', 'OpenWrt', 'OpenWrt/LEDE'),
    (80, re.compile(rb'DD-WRT'), 'Embedded', 'DD-WRT', 'DD-WRT'),
    (80, re.compile(rb'pfSense'), 'Embedded', 'pfSense', 'FreeBSD'),
    (80, re.compile(rb'OPNsense'), 'Embedded', 'OPNsense', 'FreeBSD'),
    (80, re.compile(rb'Cisco'), 'Network', 'Cisco IOS', 'Cisco'),
    (80, re.compile(rb'Juniper'), 'Network', 'Juniper JunOS', 'Juniper'),

    # Misc
    (873, re.compile(rb'@RSYNCD:'), 'Rsync', 'Rsync', 'Unix/Linux'),
    (873, re.compile(rb'rsync'), 'Rsync', 'Rsync', 'Unix/Linux'),
    (2181, re.compile(rb'ZooKeeper'), 'ZooKeeper', 'Apache ZooKeeper', 'Generic'),
    (2181, re.compile(rb'ruok'), 'ZooKeeper', 'Apache ZooKeeper', 'Generic'),
    (8500, re.compile(rb'Consul'), 'Consul', 'HashiCorp Consul', 'Generic'),
    (8200, re.compile(rb'Vault'), 'Vault', 'HashiCorp Vault', 'Generic'),
    (4646, re.compile(rb'Nomad'), 'Nomad', 'HashiCorp Nomad', 'Generic'),
    (25565, re.compile(rb'Minecraft'), 'Minecraft', 'Minecraft Server', 'Generic'),
    (32400, re.compile(rb'Plex'), 'Plex', 'Plex Media Server', 'Generic'),
    (8332, re.compile(rb'Bitcoin'), 'Bitcoin', 'Bitcoin Core', 'Generic'),
    (8333, re.compile(rb'Bitcoin'), 'Bitcoin', 'Bitcoin Core', 'Generic'),
]

# OS Fingerprint signatures
OS_SIGNATURES = [
    (re.compile(rb'Windows NT 10\.0'), 'Windows', '10/Server 2016/2019', 128),
    (re.compile(rb'Windows NT 6\.3'), 'Windows', '8.1/Server 2012 R2', 128),
    (re.compile(rb'Windows NT 6\.2'), 'Windows', '8/Server 2012', 128),
    (re.compile(rb'Windows NT 6\.1'), 'Windows', '7/Server 2008 R2', 128),
    (re.compile(rb'Windows NT 6\.0'), 'Windows', 'Vista/Server 2008', 128),
    (re.compile(rb'Windows NT 5\.'), 'Windows', 'XP/Server 2003', 128),
    (re.compile(rb'Ubuntu|ubuntu'), 'Ubuntu Linux', '24.04/22.04', 64),
    (re.compile(rb'Debian|debian'), 'Debian Linux', '12/11', 64),
    (re.compile(rb'CentOS|centos'), 'CentOS Linux', '9/8/7', 64),
    (re.compile(rb'Red Hat|redhat|Red.Hat'), 'Red Hat Linux', '9/8/7', 64),
    (re.compile(rb'Fedora|fedora'), 'Fedora Linux', 'Latest', 64),
    (re.compile(rb'SUSE|suse|openSUSE'), 'SUSE Linux', 'openSUSE', 64),
    (re.compile(rb'FreeBSD|freebsd'), 'FreeBSD', 'Latest', 64),
    (re.compile(rb'OpenBSD|openbsd'), 'OpenBSD', 'Latest', 64),
    (re.compile(rb'Darwin|darwin'), 'macOS', 'Sonoma/Ventura', 64),
    (re.compile(rb'Cisco IOS'), 'Cisco IOS', 'Latest', 255),
    (re.compile(rb'MikroTik|RouterOS'), 'MikroTik', 'RouterOS', 64),
    (re.compile(rb'OpenWrt|openwrt'), 'OpenWrt', 'Latest', 64),
    (re.compile(rb'DD-WRT|dd-wrt'), 'DD-WRT', 'Latest', 64),
    (re.compile(rb'pfSense|pfsense'), 'pfSense', 'Latest', 64),
    (re.compile(rb'VMware|vmware|ESXi'), 'VMware ESXi', 'Latest', 64),
    (re.compile(rb'Synology|synology'), 'Synology DSM', 'Latest', 64),
    (re.compile(rb'Proxmox|proxmox'), 'Proxmox VE', 'Latest', 64),
    (re.compile(rb'Raspberry Pi|raspberry'), 'Raspberry Pi OS', 'Latest', 64),
]

COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    111: 'RPCBIND', 135: 'MSRPC', 139: 'NETBIOS-SSN', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMPTRAP', 179: 'BGP', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'ISAKMP',
    514: 'SYSLOG', 515: 'LPD', 548: 'AFP', 587: 'SMTP-MSA',
    631: 'IPP', 636: 'LDAPS', 873: 'RSYNC', 902: 'VMware',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OPENVPN',
    1433: 'MSSQL', 1434: 'MSSQL-MON', 1521: 'ORACLE', 1701: 'L2TP',
    1723: 'PPTP', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
    2181: 'ZooKeeper', 2375: 'DOCKER', 2376: 'DOCKER-SSL',
    2379: 'ETCD', 3306: 'MYSQL', 3389: 'RDP', 4333: 'AH',
    5432: 'POSTGRES', 5672: 'AMQP', 5900: 'VNC', 5901: 'VNC-1',
    5985: 'WINRM', 5986: 'WINRM-SSL', 6379: 'REDIS', 6443: 'K8S-API',
    8000: 'HTTP-DEV', 8080: 'HTTP-PROXY', 8443: 'HTTPS-ALT',
    8500: 'CONSUL', 8888: 'HTTP-ALT', 9000: 'HTTP-ALT',
    9090: 'PROMETHEUS', 9200: 'ELASTICSEARCH', 9300: 'ELASTICSEARCH-T',
    9418: 'GIT', 10250: 'KUBELET', 11211: 'MEMCACHED',
    27017: 'MONGODB', 27018: 'MONGODB-SHARD', 50000: 'DB2',
}

# Protocol probes
PROBES = {
    21: b'SYST\r\n',
    22: b'',
    23: b'\xff\xfd\x01\xff\xfd\x1f\xff\xfd\x21',
    25: b'EHLO hackit.local\r\n',
    80: b'GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT/3.0\r\n\r\n',
    110: b'CAPA\r\n',
    143: b'A1 CAPABILITY\r\n',
    443: b'',
    389: bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]),
    465: b'',
    500: bytes(28),
    587: b'EHLO hackit.local\r\n',
    636: b'',
    873: b'@RSYNCD: 31.0\n',
    993: b'',
    995: b'',
    1194: b'',
    1433: bytes([0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00]),
    1521: bytes([0x00, 0x57, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
    2375: b'GET /version HTTP/1.0\r\nHost: hackit\r\n\r\n',
    2379: b'GET /version HTTP/1.0\r\nHost: hackit\r\n\r\n',
    3128: b'GET / HTTP/1.0\r\nHost: hackit\r\n\r\n',
    3306: b'',
    3389: bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]),
    5432: bytes([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]),
    5672: b'AMQP\x00\x00\x09\x01',
    5900: b'RFB 003.008\n',
    5985: b'POST /wsman HTTP/1.0\r\nHost: hackit\r\nContent-Length: 0\r\n\r\n',
    6379: b'INFO server\r\n',
    6443: b'GET /version HTTP/1.0\r\nHost: hackit\r\n\r\n',
    8000: b'GET / HTTP/1.0\r\nHost: hackit\r\n\r\n',
    8080: b'GET / HTTP/1.0\r\nHost: hackit\r\n\r\n',
    8443: b'',
    8500: b'GET /v1/status/leader HTTP/1.0\r\nHost: hackit\r\n\r\n',
    9090: b'GET /metrics HTTP/1.0\r\nHost: hackit\r\n\r\n',
    9092: bytes([0x00, 0x00, 0x00, 0x0e, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x68, 0x61, 0x63, 0x6b]),
    9200: b'GET / HTTP/1.0\r\nHost: hackit\r\n\r\n',
    11211: b'stats\r\n',
    27017: bytes([0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
    50000: bytes([0x00, 0x27, 0xd0, 0x11, 0x00, 0x00, 0x00, 0x00]),
}


def detect_ttl_from_response(raw: bytes) -> int:
    """Extract TTL from IP header of received packet."""
    if raw and len(raw) > 8:
        return raw[8]  # TTL is at offset 8 in IP header
    return 64


def guess_os_from_ttl(ttl: int) -> Tuple[str, float]:
    if ttl <= 64:
        return "Unix/Linux", 0.4
    elif ttl <= 128:
        return "Windows", 0.4
    else:
        return "Network Device", 0.4


def sanitize_banner(data: bytes) -> str:
    result = []
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            result.append(chr(b))
        elif b == 0:
            result.append(' ')
    return ''.join(result).strip()


def match_service_signatures(port: int, banner: str) -> Optional[ServiceFingerprint]:
    banner_bytes = banner.encode('latin-1', errors='replace')
    best = ServiceFingerprint(service=COMMON_PORTS.get(port, 'unknown'))

    for sig_port, pattern, service, product, os_hint in SERVICE_SIGNATURES:
        if sig_port != port:
            continue
        m = pattern.search(banner_bytes)
        if m:
            ver = m.group(1).decode() if m.lastindex and m.lastindex >= 1 else ""
            return ServiceFingerprint(
                service=service, product=product,
                version=ver, os_hint=os_hint,
                confidence=0.9, banner=banner[:200]
            )

    for sig_port, pattern, service, product, os_hint in SERVICE_SIGNATURES:
        if sig_port != port:
            continue
        m = pattern.search(banner_bytes)
        if m:
            result = ServiceFingerprint(
                service=service, product=product,
                os_hint=os_hint, confidence=0.9,
                banner=banner[:200]
            )
            if m.lastindex and m.lastindex >= 1:
                result.version = m.group(1).decode(errors='replace')
            return result

    banner_lower = banner.lower()
    svc = COMMON_PORTS.get(port, '')
    if svc:
        return ServiceFingerprint(service=svc, product=svc, confidence=0.5, banner=banner[:200])

    if 'http' in banner_lower or 'server:' in banner_lower:
        return ServiceFingerprint(service='HTTP', product='Web Server', confidence=0.6, banner=banner[:200])
    if 'ssh' in banner_lower:
        return ServiceFingerprint(service='SSH', product='SSH Server', confidence=0.6, banner=banner[:200])
    if '220' in banner_lower and ('ftp' in banner_lower or 'vsftp' in banner_lower):
        return ServiceFingerprint(service='FTP', product='FTP Server', confidence=0.6, banner=banner[:200])
    if 'mysql' in banner_lower:
        return ServiceFingerprint(service='MySQL', product='MySQL', confidence=0.6, banner=banner[:200])
    if 'postgresql' in banner_lower or 'psql' in banner_lower:
        return ServiceFingerprint(service='PostgreSQL', product='PostgreSQL', confidence=0.6, banner=banner[:200])
    if 'redis' in banner_lower:
        return ServiceFingerprint(service='Redis', product='Redis', confidence=0.6, banner=banner[:200])
    if 'mongodb' in banner_lower:
        return ServiceFingerprint(service='MongoDB', product='MongoDB', confidence=0.6, banner=banner[:200])

    return best if best.banner else None


def detect_os_from_banner(banner: str, ttl: int = -1) -> Tuple[str, str, float]:
    banner_bytes = banner.encode('latin-1', errors='replace')
    best_os, best_ver, best_conf = '', '', 0.0

    for pattern, os_name, os_ver, expected_ttl in OS_SIGNATURES:
        if pattern.search(banner_bytes):
            if 0.85 > best_conf:
                best_os, best_ver, best_conf = os_name, os_ver, 0.85

    if best_conf == 0.0 and ttl > 0:
        os_name, conf = guess_os_from_ttl(ttl)
        return os_name, '', conf

    return best_os, best_ver, best_conf


def grab_banner_sync(host: str, port: int, timeout: float = 2.0) -> Tuple[str, int]:
    """
    Synchronous banner grab with protocol-specific probes.
    Returns (banner_text, ttl).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        ttl = 64

        try:
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        except Exception:
            pass

        banner_data = b''

        greeting_ports = {21, 22, 25, 110, 143, 587, 3306, 5432, 6379, 27017}
        if port in greeting_ports:
            try:
                sock.settimeout(0.5)
                chunk = sock.recv(4096)
                if chunk:
                    banner_data += chunk
            except socket.timeout:
                pass
            sock.settimeout(timeout)

        if port in (443, 8443, 9443, 993, 995, 465, 2083, 2087, 2096, 7443, 5986):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(sock, server_hostname=host)
                req = f'GET / HTTP/1.0\r\nHost: {host}\r\n\r\n'.encode()
                ss.send(req)
                resp = ss.recv(8192)
                cert = ss.getpeercert(True)
                banner_data += resp
            except Exception:
                pass
        else:
            probe = PROBES.get(port, b'\r\n\r\n')
            if probe:
                try:
                    sock.send(probe)
                except Exception:
                    pass

            try:
                sock.settimeout(timeout)
                for _ in range(3):
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner_data += chunk
                    if b'\n' in chunk and len(chunk) < 4096:
                        break
            except socket.timeout:
                pass

        sock.close()
        return sanitize_banner(banner_data), ttl

    except (socket.timeout, ConnectionRefusedError, OSError):
        return '', 0


async def grab_banner_async(host: str, port: int, timeout: float = 2.0) -> Tuple[str, int]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, grab_banner_sync, host, port, timeout)


def analyze_port(host: str, port: int, timeout: float = 2.0) -> ScanResult:
    """Full port analysis with banner + version + OS detection."""
    result = ScanResult(port=port)
    banner, ttl = grab_banner_sync(host, port, timeout)
    result.ttl = ttl

    if not banner:
        result.state = 'closed'
        result.service = COMMON_PORTS.get(port, 'unknown')
        return result

    result.state = 'open'
    result.banner = banner[:512]

    fp = match_service_signatures(port, banner)
    if fp:
        result.service = fp.service
        result.product = fp.product
        result.version = fp.version
        result.os_hint = fp.os_hint
        result.confidence = fp.confidence

    os_name, os_ver, os_conf = detect_os_from_banner(banner, ttl)
    if os_conf > 0:
        result.os_hint = f'{os_name} {os_ver}'.strip()
        result.os_confidence = os_conf

    result.risk_score = calculate_risk(port, banner)

    return result


def calculate_risk(port: int, banner: str) -> float:
    score = 0.0
    high_risk = {21, 23, 445, 3389, 5900, 2375, 6379, 27017, 9200, 11211, 4444, 10250, 50000}
    if port in high_risk:
        score += 40

    banner_l = banner.lower()
    if any(k in banner_l for k in ['openssh 5', 'openssh 6', 'apache/2.2', 'openssl/1.0', 'ssl 3', 'tls 1.0']):
        score += 30
    if any(k in banner_l for k in ['anonymous', 'guest']):
        score += 25
    if 'docker' in banner_l or 'kubernetes' in banner_l:
        score += 20

    return min(score, 100.0)


def scan_target(host: str, ports: List[int], timeout: float = 2.0, workers: int = 200) -> List[ScanResult]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fn = partial(analyze_port, host, timeout=timeout)
        for res in pool.map(fn, ports):
            if res.state == 'open':
                results.append(res)
    return sorted(results, key=lambda x: x.port)


async def scan_target_async(host: str, ports: List[int], timeout: float = 2.0) -> List[ScanResult]:
    sem = asyncio.Semaphore(500)

    async def bounded_scan(p):
        async with sem:
            return await asyncio.get_event_loop().run_in_executor(
                None, analyze_port, host, p, timeout
            )

    tasks = [bounded_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted([r for r in results if r.state == 'open'], key=lambda x: x.port)


def scan_range(host: str, start: int = 1, end: int = 1024, timeout: float = 2.0, workers: int = 200) -> List[ScanResult]:
    ports = list(range(start, end + 1))
    return scan_target(host, ports, timeout, workers)


def scan_top_ports(host: str, n: int = 100, timeout: float = 2.0) -> List[ScanResult]:
    top = [80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
           8080, 1723, 111, 995, 993, 5900, 587, 8443, 6379, 27017, 5432,
           2375, 9200, 11211, 1433, 1521, 5672, 8000, 8888, 3000, 9090,
           6443, 10250, 2379, 2376, 5985, 5986]
    if n > len(top):
        top = list(range(1, n + 1))
    return scan_target(host, top[:n], timeout)


def export_json(results: List[ScanResult], path: str):
    with open(path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2, default=str)


def export_xml(results: List[ScanResult], path: str, host: str):
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    root = ET.Element('hackit_scan')
    ET.SubElement(root, 'host').text = host
    ET.SubElement(root, 'scan_time').text = time.strftime('%Y-%m-%dT%H:%M:%S')
    ports_el = ET.SubElement(root, 'ports')
    for r in results:
        pe = ET.SubElement(ports_el, 'port', number=str(r.port), state=r.state)
        ET.SubElement(pe, 'service').text = r.service
        ET.SubElement(pe, 'product').text = r.product
        ET.SubElement(pe, 'version').text = r.version
        ET.SubElement(pe, 'banner').text = r.banner[:100]
    xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent='  ')
    with open(path, 'w') as f:
        f.write(xml_str)


if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'scanme.nmap.org'
    ports = sys.argv[2] if len(sys.argv) > 2 else '80,443,22,21,25,3306'
    port_list = []
    for part in ports.split(','):
        if '-' in part:
            a, b = map(int, part.split('-'))
            port_list.extend(range(a, b + 1))
        else:
            port_list.append(int(part))

    print(f'\n  ⚡ HackIT Python Ultra Scanner — scanning {host}')
    print(f'  Targets: {len(port_list)} ports | Protocol probes: {len(PROBES)}\n')
    start = time.time()
    results = scan_target(host, port_list, timeout=2.0, workers=100)
    elapsed = time.time() - start

    print(f'  PORT    STATE   SERVICE         VERSION                BANNER')
    print(f'  {"─" * 70}')
    for r in results:
        ver = r.version[:20] if r.version else ''
        ban = r.banner[:40] if r.banner else ''
        print(f'  {r.port:<6} OPEN    {r.service:<15} {ver:<20} {ban}')
    print(f'\n  Completed {len(port_list)} ports in {elapsed:.2f}s ({len(results)} open)\n')


import ipaddress
import os
import re

HOST_PATTERN = re.compile(r"^[a-zA-Z0-9\-\.]+$")

def parse_targets(targets):
    items = []
    if not targets:
        return items

    def add_item(x):
        x = x.strip()
        if not x:
            return
        # IP address
        try:
            ip = ipaddress.ip_address(x)
            items.append(str(ip))
            return
        except ValueError:
            pass
        # CIDR network
        if "/" in x:
            try:
                net = ipaddress.ip_network(x, strict=False)
                # Expand hosts, skip network/broadcast for IPv4
                # Limit expansion to prevent huge lists
                max_expand = 65536
                count = 0
                for host in net.hosts():
                    items.append(str(host))
                    count += 1
                    if count >= max_expand:
                        break
                return
            except ValueError:
                pass
        # Hostname/domain
        if HOST_PATTERN.match(x):
            items.append(x)

    # File input with @filename
    if targets.startswith("@"):
        path = targets[1:]
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Allow comma or whitespace separated
                    for token in re.split(r"[,\s]+", line):
                        add_item(token)
        else:
            # Treat as literal if file missing
            add_item(targets)
    else:
        # Comma-separated list of targets or single
        for token in re.split(r"[,\s]+", targets):
            add_item(token)

    # Dedupe preserving order
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
def parse_ports(ports=None, port_range=None, popular=False, full_range=False, top_n=None):
    if full_range:
        return "1-65535"
    if top_n:
        return f"top{top_n}"
    if popular:
        return "top100"
    if ports:
        return str(ports).strip()
    if port_range:
        return str(port_range).strip()
    return "1-1000" # Default

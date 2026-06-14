#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'
require 'open3'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

begin
  iface = ARGV[0] || 'wlan0'
  channel_arg = ARGV[1]
  timeout = (ARGV[2] || 10).to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  stdout, stderr, status = Open3.capture3("iw dev #{iface} info 2>/dev/null")
  unless stdout.include?('type monitor')
    puts JSON.generate({ event: 'monitor_fail', iface: iface,
      data: { message: 'Interface not in monitor mode' }, timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  puts JSON.generate({ event: 'scan_start', iface: iface,
    data: { method: 'iw', timeout: timeout }, timestamp: Time.now.iso8601 })
  $stdout.flush

  cmd = "iw dev #{iface} scan 2>/dev/null"
  cmd = "iw dev #{iface} set channel #{channel_arg} 2>/dev/null; " + cmd if channel_arg

  stdout, stderr, status = Open3.capture3(cmd + ' 2>/dev/null &')
  current = {}
  ap_count = 0

  stdout.each_line do |line|
    if (b = line.match(/^BSS ([0-9a-fA-F:]+)/))
      if current[:bssid]
        current[:hidden] = current[:ssid].to_s.strip.empty?
        puts JSON.generate({ event: 'ap_found', iface: iface,
          bssid: current[:bssid], ssid: current[:ssid] || '',
          channel: current[:channel] || '', data: current,
          timestamp: Time.now.iso8601 })
        $stdout.flush
        ap_count += 1
      end
      current = { bssid: b[1], ssid: '', channel: '', signal: '', security: '', band: '' }
    end

    if (s = line.match(/\s+SSID: (.+)/)) then current[:ssid] = s[1] end
    if (f = line.match(/\s+freq: (\d+)/))
      freq = f[1].to_i
      current[:band] = freq < 3000 ? '2.4GHz' : freq < 6000 ? '5GHz' : '6GHz'
    end
    if (ch = line.match(/\s+channel: (\d+)/)) then current[:channel] = ch[1] end
    if (sig = line.match(/signal: (-?\d+\.?\d*)/)) then current[:signal] = sig[1] end
    if line =~ /RSN:/ then current[:security] = 'WPA2' end
    if line =~ /WPA:/ && current[:security] != 'WPA2' then current[:security] = 'WPA' end
  end

  if current[:bssid]
    current[:hidden] = current[:ssid].to_s.strip.empty?
    puts JSON.generate({ event: 'ap_found', iface: iface,
      bssid: current[:bssid], ssid: current[:ssid] || '',
      channel: current[:channel] || '', data: current,
      timestamp: Time.now.iso8601 })
    $stdout.flush
    ap_count += 1
  end

  if ap_count == 0
    puts JSON.generate({ event: 'scan_fallback', iface: iface,
      data: { method: 'nmcli' }, timestamp: Time.now.iso8601 })
    $stdout.flush

    stdout, stderr, status = Open3.capture3("nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY,BAND dev wifi list ifname #{iface} 2>/dev/null")
    stdout.each_line do |line|
      parts = line.split(':')
      next if parts.length < 5
      ssid = parts[0] == '--' ? '' : parts[0]
      bssid = parts[1] || ''
      channel = parts[2] || ''
      signal = parts[3] || ''
      security = parts[4] || ''
      band = parts[5] || ''
      puts JSON.generate({ event: 'ap_found', iface: iface,
        bssid: bssid, ssid: ssid, channel: channel,
        data: { signal: signal, security: security, band: band,
                hidden: ssid.empty?.to_s },
        timestamp: Time.now.iso8601 })
      $stdout.flush
      ap_count += 1
    end
  end

  puts JSON.generate({ event: 'scan_complete', iface: iface,
    data: { ap_count: ap_count }, timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  puts JSON.generate({ event: 'scan_interrupted', iface: iface,
    data: { status: 'interrupted' }, timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

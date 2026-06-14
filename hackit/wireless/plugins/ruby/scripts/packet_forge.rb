#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def mac2bin(s)
  s.split(':').map { |b| b.to_i(16).chr }.join
end

def ip2bin(s)
  s.split('.').map(&:to_i).pack('C*')
end

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def build_auth(da, sa, bssid, seq, algo = 0)
  fc = [0xb0, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  sc = [seq << 4].pack('v')
  body = [algo, 1, 0].pack('vvv')
  fc + dur + da + sa + bssid + sc + body
end

def build_assoc(da, sa, bssid, seq)
  fc = [0x10, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  sc = [seq << 4].pack('v')
  cap = [0x2101].pack('v')
  interval = [0x0064].pack('v')
  fc + dur + da + sa + bssid + sc + cap + interval
end

def build_null(da, sa, bssid, seq)
  fc = [0x48, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  sc = [seq << 4].pack('v')
  fc + dur + da + sa + bssid + sc
end

def build_eth_llc(ethertype)
  "\xaa\xaa\x03\x00\x00\x00" + [ethertype].pack('n')
end

def build_arp(smac, sip, tmac, tip, op)
  hw = [1].pack('n')
  proto = [0x0800].pack('n')
  hw_sz = [6].pack('C')
  proto_sz = [4].pack('C')
  opcode = [op].pack('n')
  hw + proto + hw_sz + proto_sz + opcode + smac + sip + tmac + tip
end

def build_data_arp(da, sa, bssid, seq, smac, sip, tmac, tip, op)
  fc = [0x08, 0x01].pack('C*')
  dur = [0x0000].pack('v')
  sc = [seq << 4].pack('v')
  llc = build_eth_llc(0x0806)
  arp = build_arp(smac, sip, tmac, tip, op)
  fc + dur + da + sa + bssid + sc + llc + arp
end

def build_data_ip(da, sa, bssid, seq, payload)
  fc = [0x08, 0x01].pack('C*')
  dur = [0x0000].pack('v')
  sc = [seq << 4].pack('v')
  llc = build_eth_llc(0x0800)
  fc + dur + da + sa + bssid + sc + llc + payload
end

def build_udp(smac, sip, sport, dip, dport, payload)
  udp_len = 8 + payload.bytesize
  udp_hdr = [sport, dport, udp_len, 0].pack('nnnn')
  pseudo_hdr = ip2bin(sip) + ip2bin(dip) + [0x11, udp_len].pack('C2n')
  udp = udp_hdr + payload
  ip_len = 20 + udp.bytesize
  ip_hdr = [0x45, 0x00, ip_len, rand(0..65535), 0x4000, 0x40, 0x11, 0].pack('C2n2nC2nC')
  ip_hdr[10..11] = [0].pack('n')
  ip_hdr[10..11] = ip_checksum(ip_hdr)
  ip_hdr + udp
end

def ip_checksum(hdr)
  sum = hdr.bytes.each_slice(2).sum { |a, b| (a << 8) | (b || 0) }
  while sum > 0xffff
    sum = (sum & 0xffff) + (sum >> 16)
  end
  [~sum & 0xffff].pack('n')
end

begin
  iface = ARGV[0]
  type = (ARGV[1] || 'auth').downcase
  bssid = mac2bin(ARGV[2] || '00:11:22:33:44:55')
  station = mac2bin(ARGV[3] || '00:11:22:33:44:55')
  ssid = ARGV[4] || ''
  payload_hex = ARGV[5] || ''

  raise 'interface required' unless iface

  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  seq = rand(0..4095)
  frame = nil

  case type
  when 'auth'
    frame = build_auth(station, bssid, bssid, seq, 0)
    puts JSON.generate({ event: 'forge_auth', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq, station: ARGV[3], algo: 0 },
      timestamp: Time.now.iso8601 })
  when 'assoc'
    frame = build_assoc(station, bssid, bssid, seq)
    puts JSON.generate({ event: 'forge_assoc', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq },
      timestamp: Time.now.iso8601 })
  when 'null'
    frame = build_null(station, bssid, bssid, seq)
    puts JSON.generate({ event: 'forge_null', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq },
      timestamp: Time.now.iso8601 })
  when 'arp'
    smac = mac2bin(ARGV[3] || '00:11:22:33:44:55')
    sip = ARGV[4] || '192.168.1.100'
    tip = ARGV[5] || '192.168.1.1'
    frame = build_data_arp(station, bssid, bssid, seq, smac,
                           ip2bin(sip), station, ip2bin(tip), 1)
    puts JSON.generate({ event: 'forge_arp', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq, sender_ip: sip, target_ip: tip, op: 'reply' },
      timestamp: Time.now.iso8601 })
  when 'ip'
    payload = [payload_hex].pack('H*')
    frame = build_data_ip(station, bssid, bssid, seq, payload)
    puts JSON.generate({ event: 'forge_ip', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq, payload_len: payload.bytesize },
      timestamp: Time.now.iso8601 })
  when 'udp'
    sport = (ARGV[4] || 12345).to_i
    dport = (ARGV[5] || 53).to_i
    payload = [payload_hex].pack('H*')
    ip_pkt = build_udp(bssid, '192.168.1.100', sport, '192.168.1.1', dport, payload)
    frame = build_data_ip(station, bssid, bssid, seq, ip_pkt)
    puts JSON.generate({ event: 'forge_udp', iface: iface, bssid: ARGV[2],
      ssid: ssid, channel: 0,
      data: { seq: seq, sport: sport, dport: dport,
              payload_len: payload.bytesize },
      timestamp: Time.now.iso8601 })
  else
    raise "unknown type: #{type} (auth, assoc, null, arp, ip, udp)"
  end

  addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
  sent = sock.send(frame, 0, addr)
  sock.close

  puts JSON.generate({ event: 'forge_sent', iface: iface, bssid: ARGV[2],
    ssid: ssid, channel: 0,
    data: { type: type, bytes: sent, frame_size: frame.bytesize },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

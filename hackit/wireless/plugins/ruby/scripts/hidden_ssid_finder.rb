#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'socket'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def mac_addr(bytes)
  bytes.unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')
end

COMMON_SSIDS = [
  'linksys', 'netgear', 'dlink', 'default', 'attwifi', 'xfinitywifi',
  'Starbucks WiFi', 'McDonalds Free WiFi', 'Guest', 'WiFi',
  'Home', 'Office', 'AP', 'wireless', '2WIRE', 'belkin',
  'TP-LINK', 'DIRECT', 'AndroidAP', 'iPhone'
].freeze

def build_null_probe(client_mac, bssid, seq)
  fc = [0x40, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  addr1 = bssid
  addr2 = client_mac
  addr3 = bssid
  sc = [seq << 4].pack('v')
  fc + dur + addr1 + addr2 + addr3 + sc
end

def build_directed_probe(client_mac, bssid, ssid, seq)
  fc = [0x40, 0x00].pack('C*')
  dur = [0x0000].pack('v')
  addr1 = bssid
  addr2 = client_mac
  addr3 = bssid
  sc = [seq << 4].pack('v')
  body = [0].pack('C') + [ssid.bytesize].pack('C') + ssid +
         [1].pack('C') + [8].pack('C') + [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  fc + dur + addr1 + addr2 + addr3 + sc + body
end

begin
  iface = ARGV[0]
  channel = (ARGV[1] || '6').to_i
  timeout = (ARGV[2] || '30').to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('hidden_ssid_finder_start', iface, '', '', channel, { timeout: timeout })

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 2_097_152)

  client_mac = "\x02\x00\x00\x00\x00\x01"
  broadcast = "\xff\xff\xff\xff\xff\xff"

  hidden_aps = {}
  start_time = Time.now

  emit('hidden_ssid_find_info', iface, '', '', channel, { common_ssids_count: COMMON_SSIDS.size })

  while Time.now - start_time < timeout
    probe_seq = rand(0..4095)

    # Send null probe
    null_frame = build_null_probe(client_mac, broadcast, probe_seq)
    addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
    sock.send(null_frame, 0, addr)

    # Send directed probes for common SSIDs
    COMMON_SSIDS.each do |ssid|
      dir_frame = build_directed_probe(client_mac, broadcast, ssid, rand(0..4095))
      sock.send(dir_frame, 0, addr)
    end

    # Listen for responses
    reads, _, _ = IO.select([sock], nil, nil, 0.2)
    if reads
      reads.each do |s|
        raw = s.recvfrom(4096)[0]
        rt_len = raw[2..3].unpack1('v') rescue 0
        next if rt_len < 4 || rt_len >= raw.size
        frame = raw[rt_len..]
        next if frame.nil? || frame.size < 24

        fc = frame[0..1].unpack1('v')
        frame_type = (fc >> 2) & 0x3
        frame_subtype = (fc >> 4) & 0xF

        next unless frame_type == 0 && (frame_subtype == 5 || frame_subtype == 1)

        bssid = mac_addr(frame[10..15])
        src_mac = mac_addr(frame[10..15])

        pos = 24
        ssid_found = nil
        channel_found = 0
        while pos < frame.size - 2
          tag = frame[pos].ord
          len = frame[pos + 1].ord
          break if pos + 2 + len > frame.size
          val = frame[pos + 2, len]
          if tag == 0
            ssid_found = len > 0 ? val : ''
          elsif tag == 3 && len == 1
            channel_found = val.unpack1('C')
          end
          pos += 2 + len
        end

        is_hidden = ssid_found == '' || ssid_found.nil?
        next unless is_hidden

        unless hidden_aps[bssid]
          hidden_aps[bssid] = { bssid: bssid, channel: channel_found, first_seen: Time.now.iso8601, count: 0 }
        end
        hidden_aps[bssid][:count] += 1
        hidden_aps[bssid][:last_seen] = Time.now.iso8601

        emit('hidden_ssid_found', iface, bssid, '', channel_found, {
          subtype: frame_subtype == 5 ? 'probe_response' : 'beacon',
          times_seen: hidden_aps[bssid][:count]
        })

        # Try to get SSID from associated clients by sending directed probes with common SSIDs
        COMMON_SSIDS.each do |ssid|
          dir_probe = build_directed_probe(client_mac, frame[10..15], ssid, rand(0..4095))
          sock.send(dir_probe, 0, addr)
        end
      end
    end
  end

  sock.close

  emit('hidden_ssid_finder_summary', iface, '', '', channel, {
    hidden_aps_found: hidden_aps.size,
    aps: hidden_aps.values,
    timeout: timeout
  })

  emit('hidden_ssid_finder_complete', iface, '', '', channel, { hidden_aps_found: hidden_aps.size })

rescue Interrupt
  emit('hidden_ssid_finder_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

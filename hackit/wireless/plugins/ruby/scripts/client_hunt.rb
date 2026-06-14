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

def parse_probe_request(frame, data)
  return nil if frame.size < 24
  fc = frame[0..1].unpack1('v')
  frame_type = (fc >> 2) & 0x3
  frame_subtype = (fc >> 4) & 0xF
  return nil unless frame_type == 0 && frame_subtype == 4

  src = mac_addr(frame[10..15])
  dst = mac_addr(frame[4..9])
  bssid_field = mac_addr(frame[16..21])

  pos = 24
  ssid = nil
  rates = nil
  while pos < frame.size - 2
    tag = frame[pos].ord
    len = frame[pos + 1].ord
    break if pos + 2 + len > frame.size
    val = frame[pos + 2, len]
    # rubocop:disable Style/IfUnlessModifier
    if tag == 0 && len > 0
      ssid = val
    end
    if tag == 1 && len > 0
      rates = val.unpack('C*').map { |r| (r & 0x7F) / 2.0 }
    end
    # rubocop:enable Style/IfUnlessModifier
    pos += 2 + len
  end

  { src: src, dst: dst, bssid_from_frame: bssid_field, ssid: ssid, rates: rates, frame_size: frame.size }
end

def parse_data_frame(frame)
  return nil if frame.size < 24
  fc = frame[0..1].unpack1('v')
  frame_type = (fc >> 2) & 0x3
  frame_subtype = (fc >> 4) & 0xF
  return nil unless frame_type == 2

  addr1 = mac_addr(frame[4..9])
  addr2 = mac_addr(frame[10..15])
  addr3 = mac_addr(frame[16..21])
  to_ds = (fc >> 8) & 0x1
  from_ds = (fc >> 9) & 0x1

  bssid = if to_ds == 0 && from_ds == 0
            addr3
          elsif to_ds == 1 && from_ds == 0
            addr1
          elsif to_ds == 0 && from_ds == 1
            addr2
          else
            addr3
          end

  { addr1: addr1, addr2: addr2, addr3: addr3, bssid: bssid, to_ds: to_ds, from_ds: from_ds }
end

begin
  iface = ARGV[0]
  target_bssid = ARGV[1]
  timeout = (ARGV[2] || '30').to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('client_hunt_start', iface, target_bssid || '', '', 0, { timeout: timeout })

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 2_097_152)

  clients = {}
  start_time = Time.now

  while Time.now - start_time < timeout
    raw = sock.recvfrom(8192)[0]
    rt_len = raw[2..3].unpack1('v') rescue 0
    next if rt_len < 4 || rt_len >= raw.size
    frame = raw[rt_len..]
    next if frame.nil? || frame.size < 24

    probe = parse_probe_request(frame, raw)
    if probe
      unless clients[probe[:src]]
        clients[probe[:src]] = { probes: [], data_frames: [], first_seen: Time.now.iso8601, last_seen: Time.now.iso8601 }
      end
      clients[probe[:src]][:probes] << probe
      clients[probe[:src]][:last_seen] = Time.now.iso8601
      clients[probe[:src]][:bssid_probed] = probe[:bssid_from_frame] if probe[:bssid_from_frame] && probe[:bssid_from_frame] != 'FF:FF:FF:FF:FF:FF'

      if !target_bssid || probe[:bssid_from_frame] == target_bssid || probe[:bssid_from_frame] == 'FF:FF:FF:FF:FF:FF'
        emit('probe_request', iface, probe[:bssid_from_frame], probe[:ssid] || '', 0, {
          client: probe[:src], ssid_probed: probe[:ssid],
          rates: probe[:rates], frame_size: probe[:frame_size],
          clients_count: clients.size
        })
      end
    end

    data = parse_data_frame(frame)
    if data
      unless clients[data[:addr2]]
        clients[data[:addr2]] = { probes: [], data_frames: [], first_seen: Time.now.iso8601, last_seen: Time.now.iso8601 }
      end
      clients[data[:addr2]][:data_frames] << data
      clients[data[:addr2]][:last_seen] = Time.now.iso8601

      if !target_bssid || data[:bssid] == target_bssid
        emit('data_frame', iface, data[:bssid], '', 0, {
          client: data[:addr2], destination: data[:addr1],
          to_ds: data[:to_ds], from_ds: data[:from_ds], bssid_from_data: data[:bssid],
          clients_count: clients.size
        })
      end
    end
  end

  sock.close

  emit('client_hunt_summary', iface, target_bssid || '', '', 0, {
    clients_found: clients.size,
    clients: clients.map { |mac, info| { mac: mac, probes: info[:probes].size, data_frames: info[:data_frames].size, first_seen: info[:first_seen], last_seen: info[:last_seen] } },
    timeout: timeout
  })

  emit('client_hunt_complete', iface, target_bssid || '', '', 0, { clients_found: clients.size })

rescue Interrupt
  emit('client_hunt_interrupted', iface || '', target_bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

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

AKM_SAE = 8
AKM_SAE_FT = 24
AKM_PSK = 2
AKM_PSK_FT = 4
AKM_OWE = 18

def parse_rsne(data)
  return nil if data.nil? || data.size < 2
  version = data[0..1].unpack1('v')
  group_cipher = data[2..3].unpack1('v')

  pairwise_offset = 4
  return nil if pairwise_offset + 2 > data.size
  pairwise_count = data[pairwise_offset + 1].ord
  pairwise_end = pairwise_offset + 2 + pairwise_count * 4
  pairwise_ciphers = []
  if pairwise_end <= data.size
    pairwise_count.times do |i|
      pairwise_ciphers << data[pairwise_offset + 2 + i * 4, 4].unpack1('V')
    end
  end

  akm_offset = pairwise_end
  return nil if akm_offset + 2 > data.size
  akm_count = data[akm_offset + 1].ord
  akm_start = akm_offset + 2
  akms = []
  akm_start.step(akm_start + akm_count * 4 - 1, 4) do |i|
    break if i + 4 > data.size
    akms << data[i, 4].unpack1('V')
  end

  rsn_cap_offset = akm_start + akm_count * 4
  rsn_capabilities = nil
  if rsn_cap_offset + 2 <= data.size
    rsn_capabilities = data[rsn_cap_offset, 2].unpack1('v')
  end

  { version: version, group_cipher: group_cipher, pairwise_ciphers: pairwise_ciphers,
    akms: akms, rsn_capabilities: rsn_capabilities }
end

def parse_beacon(frame)
  return nil if frame.size < 36
  fc = frame[0..1].unpack1('v')
  frame_type = (fc >> 2) & 0x3
  frame_subtype = (fc >> 4) & 0xF
  return nil unless frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5)

  bssid = mac_addr(frame[10..15])
  src = mac_addr(frame[10..15])

  pos = 24
  tags = {}
  while pos < frame.size - 2
    tag = frame[pos].ord
    len = frame[pos + 1].ord
    break if pos + 2 + len > frame.size
    val = frame[pos + 2, len]
    tags[tag] = val
    if tag == 48 # RSNE
      rsn = parse_rsne(val)
      tags[:rsn_parsed] = rsn if rsn
    end
    pos += 2 + len
  end

  ssid = tags[0]
  channel_tag = tags[3]

  {
    bssid: bssid, src: src, ssid: ssid, channel: channel_tag&.unpack1('C'),
    has_wpa3: false, has_sae: false, has_owe: false, has_psk: false,
    transition_mode: false, rsn: tags[:rsn_parsed],
    tags: tags.keys
  }
end

def detect_wpa3(ap_info)
  return ap_info unless ap_info[:rsn]

  akms = ap_info[:rsn][:akms] || []
  akms.each do |akm|
    case akm
    when AKM_SAE
      ap_info[:has_sae] = true
      ap_info[:has_wpa3] = true
    when AKM_SAE_FT
      ap_info[:has_sae] = true
      ap_info[:has_wpa3] = true
    when AKM_OWE
      ap_info[:has_owe] = true
      ap_info[:has_wpa3] = true
    when AKM_PSK, AKM_PSK_FT
      ap_info[:has_psk] = true
    end
  end

  # Transition mode: both SAE and PSK AKMs present
  if ap_info[:has_sae] && ap_info[:has_psk]
    ap_info[:transition_mode] = true
  end

  ap_info
end

begin
  iface = ARGV[0]
  channel = (ARGV[1] || '0').to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('wpa3_sae_start', iface, '', '', channel, {})

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 2_097_152)

  aps = {}
  start_time = Time.now

  while Time.now - start_time < 30
    raw = sock.recvfrom(8192)[0]
    rt_len = raw[2..3].unpack1('v') rescue 0
    next if rt_len < 4 || rt_len >= raw.size
    frame = raw[rt_len..]
    next if frame.nil? || frame.size < 36

    ap_info = parse_beacon(frame)
    next unless ap_info

    ap_info = detect_wpa3(ap_info)

    bssid = ap_info[:bssid]
    unless aps[bssid]
      aps[bssid] = ap_info
      emit('wpa3_ap_detected', iface, bssid, ap_info[:ssid] || '', ap_info[:channel] || 0, {
        has_wpa3: ap_info[:has_wpa3], has_sae: ap_info[:has_sae],
        has_owe: ap_info[:has_owe], has_psk: ap_info[:has_psk],
        transition_mode: ap_info[:transition_mode],
        akms: ap_info[:rsn]&.dig(:akms),
        group_cipher: ap_info[:rsn]&.dig(:group_cipher),
        pairwise_ciphers: ap_info[:rsn]&.dig(:pairwise_ciphers)
      })
    end
  end

  sock.close

  wpa3_aps = aps.values.select { |a| a[:has_wpa3] }
  transit_aps = aps.values.select { |a| a[:transition_mode] }

  emit('wpa3_sae_summary', iface, '', '', channel, {
    total_aps: aps.size,
    wpa3_aps: wpa3_aps.size,
    transition_mode_aps: transit_aps.size,
    wpa3_list: wpa3_aps.map { |a| [a[:bssid], a[:ssid], a[:channel]] },
    transition_list: transit_aps.map { |a| [a[:bssid], a[:ssid], a[:channel]] }
  })

  emit('wpa3_sae_complete', iface, '', '', channel, { aps_scanned: aps.size, wpa3_found: wpa3_aps.size })

rescue Interrupt
  emit('wpa3_sae_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

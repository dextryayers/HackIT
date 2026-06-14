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

def mac_addr(bytes)
  bytes.unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')
end

BT_VENDOR_PREFIXES = {
  '00:11:22' => 'Samsung', '00:1A:7D' => 'Samsung', 'AC:5F:3E' => 'Apple',
  'F0:18:98' => 'Apple', '00:23:DF' => 'Apple', '84:38:38' => 'Apple',
  '08:74:02' => 'Apple', '04:F1:3E' => 'Google', 'A4:77:33' => 'Google',
  'BC:8C:CD' => 'Google', '8C:DE:52' => 'Google', '98:5A:EB' => 'Huawei',
  '50:1A:A5' => 'Huawei', '48:0F:CF' => 'Huawei', 'F8:2F:5B' => 'Xiaomi',
  '48:E7:DA' => 'Xiaomi', '50:F5:DA' => 'Xiaomi', '38:BC:1A' => 'OnePlus',
  'E4:8D:8C' => 'OnePlus', 'C4:BE:84' => 'LG', '78:B2:3B' => 'LG',
  'D0:9E:6E' => 'Sony', 'E0:AC:CB' => 'Sony', '24:18:1D' => 'Nokia',
  '30:7C:30' => 'BlackBerry', 'D8:50:E6' => 'HTC', '64:70:02' => 'HTC'
}.freeze

def scan_bluetooth(timeout = 10)
  devices = []

  stdout, _, status = Open3.capture3('bluetoothctl', '--timeout', timeout.to_s, 'scan', 'on')
  return devices unless status.success?

  stdout.each_line do |line|
    if line =~ /Device\s+([A-F0-9:]{17})\s*(.*)/
      mac = $1.upcase
      name = $2.strip
      prefix = mac[0..7]
      vendor = BT_VENDOR_PREFIXES[prefix] || 'Unknown'
      devices << { mac: mac, name: name, vendor: vendor, type: 'BT' }
    end
  end

  devices
end

def scan_bluetooth_le(timeout = 10)
  devices = []
  stdout, _, status = Open3.capture3('bluetoothctl', '--timeout', timeout.to_s, 'scan', 'le')
  return devices unless status.success?

  stdout.each_line do |line|
    if line =~ /Device\s+([A-F0-9:]{17})\s*(.*)/
      mac = $1.upcase
      name = $2.strip
      prefix = mac[0..7]
      vendor = BT_VENDOR_PREFIXES[prefix] || 'Unknown'
      devices << { mac: mac, name: name, vendor: vendor, type: 'BTLE' }
    end
  end

  devices
end

def scan_bluetooth_classic(timeout = 10)
  devices = []
  stdout, _, status = Open3.capture3('hcitool', 'scan', '--flush')
  return devices unless status.success?

  stdout.each_line do |line|
    if line =~ /([A-F0-9:]{17})\s+(.*)/
      mac = $1.upcase
      name = $2.strip
      prefix = mac[0..7]
      vendor = BT_VENDOR_PREFIXES[prefix] || 'Unknown'
      devices << { mac: mac, name: name, vendor: vendor, type: 'BT_CLASSIC' }
    end
  end

  devices
end

def scan_wifi_aps(iface)
  sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
  sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 2_097_152)

  aps = {}
  start = Time.now

  while Time.now - start < 15
    raw = sock.recvfrom(8192)[0]
    rt_len = raw[2..3].unpack1('v') rescue 0
    next if rt_len < 4 || rt_len >= raw.size
    frame = raw[rt_len..]
    next if frame.nil? || frame.size < 24

    fc = frame[0..1].unpack1('v')
    frame_type = (fc >> 2) & 0x3
    frame_subtype = (fc >> 4) & 0xF
    next unless frame_type == 0 && frame_subtype == 8

    bssid = mac_addr(frame[10..15])
    pos = 24
    ssid = nil
    while pos < frame.size - 2
      tag = frame[pos].ord
      len = frame[pos + 1].ord
      break if pos + 2 + len > frame.size
      ssid = frame[pos + 2, len] if tag == 0 && len > 0
      pos += 2 + len
    end

    aps[bssid] = { bssid: bssid, ssid: ssid } unless aps[bssid]
    emit('wifi_ap_seen', iface, bssid, ssid || '', 0, {})
  end

  sock.close
  aps.values
end

def correlate(bt_devices, wifi_aps)
  correlations = []

  bt_devices.each do |bt|
    wifi_aps.each do |wifi|
      bt_prefix = bt[:mac][0..7]
      wifi_prefix = wifi[:bssid][0..7]

      if bt_prefix == wifi_prefix
        correlation = {
          bt_mac: bt[:mac], bt_name: bt[:name], bt_type: bt[:type], bt_vendor: bt[:vendor],
          wifi_bssid: wifi[:bssid], wifi_ssid: wifi[:ssid],
          correlation_type: 'same_prefix'
        }
        correlations << correlation
        emit('bt_wifi_correlation', '', wifi[:bssid], wifi[:ssid] || '', 0, correlation)
      end
    end
  end

  correlations
end

begin
  iface = ARGV[0]
  scan_type = (ARGV[1] || 'both').downcase

  raise 'interface required' unless iface

  emit('bt_wifi_scan_start', iface, '', '', 0, { scan_type: scan_type })

  bt_devices = case scan_type
               when 'bt' then scan_bluetooth(15)
               when 'le' then scan_bluetooth_le(15)
               when 'classic' then scan_bluetooth_classic(15)
               when 'both'
                 scan_bluetooth(15) + scan_bluetooth_le(15) + scan_bluetooth_classic(15)
               else raise "invalid scan_type: #{scan_type}"
               end

  bt_devices.uniq! { |d| d[:mac] }

  emit('bt_devices_found', iface, '', '', 0, { count: bt_devices.size, devices: bt_devices })

  wifi_aps = scan_wifi_aps(iface)
  emit('wifi_aps_found', iface, '', '', 0, { count: wifi_aps.size, aps: wifi_aps })

  correlations = correlate(bt_devices, wifi_aps)

  emit('bt_wifi_summary', iface, '', '', 0, {
    bt_devices: bt_devices.size,
    wifi_aps: wifi_aps.size,
    correlations: correlations.size,
    correlation_details: correlations
  })

  emit('bt_wifi_scan_complete', iface, '', '', 0, {})

rescue Interrupt
  emit('bt_wifi_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end

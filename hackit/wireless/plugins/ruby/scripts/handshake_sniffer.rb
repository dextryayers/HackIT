#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

begin
  iface = ARGV[0]
  bssid = ARGV[1] || ''
  channel = ARGV[2] || ''
  output_dir = ARGV[3] || '/tmp/handshakes'
  timeout = (ARGV[4] || 60).to_i

  raise 'interface required' unless iface

  FileUtils.mkdir_p(output_dir) rescue system("mkdir -p #{output_dir}")

  stdout, stderr, status = Open3.capture3("iw dev #{iface} info 2>/dev/null")
  unless stdout.include?('type monitor')
    puts JSON.generate({ event: 'monitor_fail', iface: iface,
      data: { message: 'Interface not in monitor mode' },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  filter = ''
  filter += " --bssid #{bssid}" unless bssid.empty?
  filter += " -c #{channel}" unless channel.empty?
  capture_path = "#{output_dir}/capture"

  puts JSON.generate({ event: 'sniff_start', iface: iface, bssid: bssid,
    data: { output: output_dir, timeout: timeout, channel: channel },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  airodump_pid = spawn("airodump-ng -w #{capture_path} #{filter} #{iface} 2>/dev/null")
  Process.detach(airodump_pid)

  found = false
  elapsed = 0
  cap_file = "#{capture_path}-01.cap"
  csv_file = "#{capture_path}-01.csv"

  while elapsed < timeout
    sleep(2)
    elapsed += 2

    if File.exist?(csv_file)
      content = File.read(csv_file) rescue ''
      if content.include?('WPA') || content.include?('handshake')
        puts JSON.generate({ event: 'handshake_detected', iface: iface,
          data: { file: cap_file, elapsed: elapsed },
          timestamp: Time.now.iso8601 })
        $stdout.flush
        found = true
        break
      end
    end

    if File.exist?(cap_file)
      size = File.size(cap_file) rescue 0
      puts JSON.generate({ event: 'capture_progress', iface: iface,
        data: { file_size: size, elapsed: elapsed, timeout: timeout },
        timestamp: Time.now.iso8601 })
      $stdout.flush
    end
  end

  system("pkill -f 'airodump-ng.*#{iface}' 2>/dev/null")
  sleep(1)

  if File.exist?(cap_file)
    stdout, stderr, status = Open3.capture3("tshark -r #{cap_file} -Y 'eapol' -T fields -e wlan.sa -e wlan.da 2>/dev/null")
    eapol_count = stdout.each_line.count
    if eapol_count > 0
      puts JSON.generate({ event: 'eapol_frames', iface: iface,
        data: { count: eapol_count, file: cap_file },
        timestamp: Time.now.iso8601 })
      $stdout.flush
    end

    stdout2, stderr2, status2 = Open3.capture3("tshark -r #{cap_file} -Y 'eapol.keydes.key_info' -T fields -e wlan.sa -e wlan.da -e eapol.keydes.key_info 2>/dev/null")
    pmkid_count = stdout2.each_line.count
    if pmkid_count > 0
      puts JSON.generate({ event: 'pmkid_detected', iface: iface,
        data: { count: pmkid_count },
        timestamp: Time.now.iso8601 })
      $stdout.flush
    end
  end

  puts JSON.generate({ event: 'sniff_complete', iface: iface, bssid: bssid,
    data: { handshake_found: found, output_dir: output_dir, elapsed: elapsed,
            pcap: cap_file },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  system("pkill -f 'airodump-ng.*#{iface}' 2>/dev/null") if iface
  puts JSON.generate({ event: 'sniff_interrupted', iface: iface || '',
    data: { status: 'interrupted' }, timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

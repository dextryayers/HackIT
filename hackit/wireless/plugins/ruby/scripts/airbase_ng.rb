#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'
require 'tempfile'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def write_hostapd_conf(path, iface, ssid, passphrase, channel)
  File.write(path, <<~CONF)
    interface=#{iface}
    driver=nl80211
    ssid=#{ssid}
    hw_mode=g
    channel=#{channel}
    wpa=2
    wpa_passphrase=#{passphrase}
    wpa_key_mgmt=WPA-PSK
    wpa_pairwise=TKIP CCMP
    rsn_pairwise=CCMP
    auth_algs=1
    macaddr_acl=0
    logger_stdout=-1
    logger_stdout_level=2
  CONF
end

def write_dnsmasq_conf(path, iface)
  subnet = "10.0.0"
  File.write(path, <<~CONF)
    interface=#{iface}
    dhcp-range=#{subnet}.10,#{subnet}.100,255.255.255.0,12h
    dhcp-option=3,#{subnet}.1
    dhcp-option=6,8.8.8.8,1.1.1.1
    server=8.8.8.8
    server=1.1.1.1
    no-resolv
    log-queries
    log-dhcp
    bind-dynamic
  CONF
end

begin
  iface = ARGV[0]
  ssid = ARGV[1] || 'RogueAP'
  channel = (ARGV[2] || '6').to_i
  passphrase = ARGV[3] || 'roguepass123'

  raise 'interface required' unless iface

  hostapd_conf = Tempfile.new(['hostapd', '.conf'])
  dnsmasq_conf = Tempfile.new(['dnsmasq', '.conf'])

  write_hostapd_conf(hostapd_conf.path, iface, ssid, passphrase, channel)
  write_dnsmasq_conf(dnsmasq_conf.path, iface)

  emit('airbase_start', iface, '', ssid, channel, { passphrase: passphrase })

  airbase = `which airbase-ng 2>/dev/null`.strip
  hostapd_bin = `which hostapd 2>/dev/null`.strip
  dnsmasq_bin = `which dnsmasq 2>/dev/null`.strip

  threads = []

  if airbase.empty? && hostapd_bin.empty?
    raise 'neither airbase-ng nor hostapd found in PATH'
  end

  if !airbase.empty?
    threads << Thread.new do
      cmd = [airbase, '-a', '-e', ssid, '-c', channel.to_s, '-W', '1', iface]
      emit('airbase_launch', iface, '', ssid, channel, { command: cmd.join(' ') })
      Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
        stdin.close
        [stdout, stderr].each do |r|
          Thread.new do
            r.each_line do |line|
              emit('airbase_output', iface, '', ssid, channel, { line: line.strip })
            end
          end
        end
        thread.join
      end
    end
  end

  if !hostapd_bin.empty?
    threads << Thread.new do
      cmd = [hostapd_bin, hostapd_conf.path]
      emit('hostapd_launch', iface, '', ssid, channel, { command: cmd.join(' ') })
      Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
        stdin.close
        [stdout, stderr].each do |r|
          Thread.new do
            r.each_line do |line|
              emit('hostapd_output', iface, '', ssid, channel, { line: line.strip })
            end
          end
        end
        thread.join
      end
    end
  end

  if !dnsmasq_bin.empty?
    threads << Thread.new do
      cmd = [dnsmasq_bin, '-C', dnsmasq_conf.path, '--no-daemon']
      emit('dnsmasq_launch', iface, '', ssid, channel, { command: cmd.join(' ') })
      Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
        stdin.close
        [stdout, stderr].each do |r|
          Thread.new do
            r.each_line do |line|
              emit('dnsmasq_output', iface, '', ssid, channel, { line: line.strip })
            end
          end
        end
        thread.join
      end
    end
  end

  threads.each(&:join)

rescue Interrupt
  emit('airbase_interrupted', iface || '', '', ssid || '', channel || 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
ensure
  hostapd_conf&.unlink
  dnsmasq_conf&.unlink
end
